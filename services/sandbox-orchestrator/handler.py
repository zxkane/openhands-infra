"""Sandbox Orchestrator - FastAPI service implementing the remote runtime HTTP API.

Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations.
Runs as a sidecar container on the EC2 host (Phase 1) or as a standalone Fargate service (Phase 2).
"""

import logging
import os
import uuid
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from dynamodb_store import DynamoDBStore, SandboxRecord
from ecs_manager import EcsManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title='Sandbox Orchestrator', version='1.0.0')

# Configuration from environment
REGISTRY_TABLE_NAME = os.environ.get('REGISTRY_TABLE_NAME', 'openhands-sandbox-registry')
ECS_CLUSTER_ARN = os.environ.get('ECS_CLUSTER_ARN', '')
TASK_DEFINITION_ARN = os.environ.get('TASK_DEFINITION_ARN', '')
SUBNETS = os.environ.get('SUBNETS', '').split(',')
SECURITY_GROUP_ID = os.environ.get('SECURITY_GROUP_ID', '')
ORCHESTRATOR_API_KEY = os.environ.get('ORCHESTRATOR_API_KEY', '')
AWS_REGION = os.environ.get('AWS_REGION_NAME', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
SANDBOX_IMAGE = os.environ.get('SANDBOX_IMAGE', '')

# Initialize services
store = DynamoDBStore(REGISTRY_TABLE_NAME, region=AWS_REGION)
ecs = EcsManager(
    cluster_arn=ECS_CLUSTER_ARN,
    task_definition_arn=TASK_DEFINITION_ARN,
    subnets=[s.strip() for s in SUBNETS if s.strip()],
    security_group_id=SECURITY_GROUP_ID,
    region=AWS_REGION,
)


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    """Verify the API key matches the expected orchestrator key."""
    if ORCHESTRATOR_API_KEY and x_api_key != ORCHESTRATOR_API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')


# ========================================
# Request/Response Models
# ========================================

class StartRequest(BaseModel):
    session_id: str
    image: Optional[str] = None
    environment: Optional[dict[str, str]] = None


class StartResponse(BaseModel):
    session_id: str
    url: str
    session_api_key: str
    status: str


class StopRequest(BaseModel):
    session_id: str


class SessionResponse(BaseModel):
    session_id: str
    url: str
    status: str
    user_id: str
    session_api_key: str


class BatchRequest(BaseModel):
    session_ids: list[str]


class ListResponse(BaseModel):
    sessions: list[SessionResponse]


class ActivityRequest(BaseModel):
    session_id: str


# ========================================
# Helpers
# ========================================


def build_sandbox_url(ip: str, port: int = 8000) -> str:
    """Build the internal HTTP URL for a sandbox task."""
    return f'http://{ip}:{port}'


def record_to_session_response(record: SandboxRecord) -> SessionResponse:
    """Convert a SandboxRecord to a SessionResponse."""
    url = ''
    if record.task_ip and record.status == 'RUNNING':
        url = build_sandbox_url(record.task_ip, record.agent_server_port)
    return SessionResponse(
        session_id=record.conversation_id,
        url=url,
        status=record.status,
        user_id=record.user_id,
        session_api_key=record.session_api_key,
    )


# ========================================
# API Endpoints (Remote Runtime API)
# ========================================

@app.get('/health')
async def health():
    """Health check endpoint."""
    return {'status': 'ok'}


@app.post('/start', response_model=StartResponse)
async def start_sandbox(req: StartRequest, x_api_key: Optional[str] = Header(None)):
    """Start a new sandbox Fargate task for a conversation."""
    verify_api_key(x_api_key)

    session_id = req.session_id
    image = req.image or SANDBOX_IMAGE
    environment = req.environment or {}

    if not image:
        raise HTTPException(status_code=400, detail='No sandbox image specified')

    # Extract user_id from environment (set by RemoteSandboxService)
    user_id = environment.get('USER_ID', '')

    # Generate session API key for agent-server authentication
    session_api_key = str(uuid.uuid4())

    logger.info('Starting sandbox for session=%s, user=%s, image=%s', session_id, user_id, image)

    # Check if sandbox already exists and is running
    existing = store.get_sandbox(session_id)
    if existing and existing.status == 'RUNNING':
        logger.info('Sandbox already running for session=%s', session_id)
        return StartResponse(
            session_id=session_id,
            url=build_sandbox_url(existing.task_ip, existing.agent_server_port),
            session_api_key=existing.session_api_key,
            status='RUNNING',
        )

    def record_error(task_arn: str = '') -> None:
        """Record a sandbox creation failure in DynamoDB."""
        error_record = SandboxRecord({
            'conversation_id': session_id,
            'user_id': user_id,
            'task_arn': task_arn,
            'status': 'ERROR',
            'session_api_key': session_api_key,
            'sandbox_spec_id': image,
        })
        store.put_sandbox(error_record)

    # Start ECS Fargate task
    try:
        result = ecs.run_task(
            conversation_id=session_id,
            user_id=user_id,
            image=image,
            environment=environment,
            session_api_key=session_api_key,
        )
    except RuntimeError as e:
        logger.error('Failed to start sandbox: %s', e)
        record_error()
        raise HTTPException(status_code=503, detail=str(e)) from e

    task_arn = result['task_arn']

    # Wait for task to become RUNNING and get its IP
    task_ip = ecs.wait_for_running(task_arn, timeout_seconds=120)
    if not task_ip:
        logger.error('Sandbox task failed to reach RUNNING state: %s', task_arn)
        try:
            ecs.stop_task(task_arn, reason='Failed to start')
        except RuntimeError:
            pass
        record_error(task_arn)
        raise HTTPException(status_code=503, detail='Sandbox task failed to start')

    # Store in DynamoDB
    record = SandboxRecord({
        'conversation_id': session_id,
        'user_id': user_id,
        'task_arn': task_arn,
        'task_ip': task_ip,
        'status': 'RUNNING',
        'session_api_key': session_api_key,
        'agent_server_port': 8000,
        'sandbox_spec_id': image,
    })
    store.put_sandbox(record)

    url = build_sandbox_url(task_ip)
    logger.info('Sandbox started: session=%s, url=%s', session_id, url)

    return StartResponse(
        session_id=session_id,
        url=url,
        session_api_key=session_api_key,
        status='RUNNING',
    )


@app.post('/stop')
async def stop_sandbox(req: StopRequest, x_api_key: Optional[str] = Header(None)):
    """Stop a running sandbox task."""
    verify_api_key(x_api_key)

    record = store.get_sandbox(req.session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='User requested stop')
        except RuntimeError as e:
            logger.error('Failed to stop task: %s', e)

    store.update_status(req.session_id, 'STOPPED')
    return {'status': 'STOPPED', 'session_id': req.session_id}


@app.post('/pause')
async def pause_sandbox(req: StopRequest, x_api_key: Optional[str] = Header(None)):
    """Pause a sandbox (stops the task but marks as PAUSED for resume)."""
    verify_api_key(x_api_key)

    record = store.get_sandbox(req.session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='Sandbox paused for idle timeout')
        except RuntimeError as e:
            logger.error('Failed to pause task: %s', e)

    store.update_status(req.session_id, 'PAUSED')
    return {'status': 'PAUSED', 'session_id': req.session_id}


@app.post('/resume', response_model=StartResponse)
async def resume_sandbox(req: StartRequest, x_api_key: Optional[str] = Header(None)):
    """Resume a paused sandbox (starts new task, workspace intact on EFS)."""
    verify_api_key(x_api_key)

    record = store.get_sandbox(req.session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING':
        return StartResponse(
            session_id=req.session_id,
            url=build_sandbox_url(record.task_ip, record.agent_server_port),
            session_api_key=record.session_api_key,
            status='RUNNING',
        )

    # Start new task with same configuration
    image = req.image or record.sandbox_spec_id or SANDBOX_IMAGE
    environment = req.environment or {}
    session_api_key = record.session_api_key or str(uuid.uuid4())

    try:
        result = ecs.run_task(
            conversation_id=req.session_id,
            user_id=record.user_id,
            image=image,
            environment=environment,
            session_api_key=session_api_key,
        )
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e

    task_arn = result['task_arn']
    task_ip = ecs.wait_for_running(task_arn, timeout_seconds=120)
    if not task_ip:
        try:
            ecs.stop_task(task_arn, reason='Failed to resume')
        except RuntimeError:
            pass
        raise HTTPException(status_code=503, detail='Sandbox task failed to resume')

    store.update_status(req.session_id, 'RUNNING', task_ip=task_ip, task_arn=task_arn)

    return StartResponse(
        session_id=req.session_id,
        url=build_sandbox_url(task_ip),
        session_api_key=session_api_key,
        status='RUNNING',
    )


@app.get('/sessions/{session_id}', response_model=SessionResponse)
async def get_session(session_id: str, x_api_key: Optional[str] = Header(None)):
    """Get sandbox info by session/conversation ID. Used by OpenResty for discovery."""
    verify_api_key(x_api_key)

    record = store.get_sandbox(session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    return record_to_session_response(record)


@app.post('/sessions/batch')
async def batch_get_sessions(req: BatchRequest, x_api_key: Optional[str] = Header(None)):
    """Batch get sandbox info for multiple sessions."""
    verify_api_key(x_api_key)

    records = store.batch_get_sandboxes(req.session_ids)
    return {'sessions': [record_to_session_response(r) for r in records]}


@app.get('/list', response_model=ListResponse)
async def list_sessions(x_api_key: Optional[str] = Header(None)):
    """List all running sandboxes."""
    verify_api_key(x_api_key)

    records = store.list_running()
    return ListResponse(sessions=[record_to_session_response(r) for r in records])


@app.post('/activity')
async def update_activity(req: ActivityRequest, x_api_key: Optional[str] = Header(None)):
    """Update last_activity_at timestamp (called by OpenResty on each proxied request)."""
    verify_api_key(x_api_key)
    store.update_activity(req.session_id)
    return {'status': 'ok'}
