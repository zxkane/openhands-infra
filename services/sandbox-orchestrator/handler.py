"""Sandbox Orchestrator - FastAPI service implementing the remote runtime HTTP API.

Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations.
API format matches upstream expectations in remote_sandbox_service.py.
Runs as a sidecar container on the EC2 host (Phase 1).
"""

import logging
import os
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
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

# NOTE: No API key auth needed — orchestrator only listens on localhost:8081 (EC2 private).


# ========================================
# Request/Response Models
# ========================================

class StartRequest(BaseModel):
    session_id: str
    image: Optional[str] = None
    environment: Optional[dict[str, str]] = None


class RuntimeIdRequest(BaseModel):
    runtime_id: str


class ActivityRequest(BaseModel):
    session_id: str


# ========================================
# Helpers
# ========================================


def build_sandbox_url(ip: str, port: int = 8000) -> str:
    """Build the internal HTTP URL for a sandbox task."""
    return f'http://{ip}:{port}'


def record_to_runtime(record: SandboxRecord) -> dict:
    """Convert a SandboxRecord to the runtime dict format expected by RemoteSandboxService."""
    url = ''
    if record.task_ip and record.status == 'RUNNING':
        url = build_sandbox_url(record.task_ip, record.agent_server_port)
    return {
        'session_id': record.conversation_id,
        'runtime_id': record.task_arn or record.conversation_id,
        'status': record.status.lower(),  # upstream expects lowercase: running, stopped, etc.
        'url': url,
        'session_api_key': record.session_api_key,
        'image': record.sandbox_spec_id,
        'user_id': record.user_id,
    }


# ========================================
# API Endpoints (Remote Runtime API)
# ========================================

@app.get('/health')
async def health():
    """Health check endpoint."""
    return {'status': 'ok'}


@app.post('/start')
def start_sandbox(req: StartRequest):
    """Start a new sandbox Fargate task for a conversation.

    Returns runtime dict matching upstream RemoteSandboxService expectations.
    """
    session_id = req.session_id
    if not session_id or not session_id.strip():
        raise HTTPException(status_code=400, detail='Invalid session_id')

    image = req.image or SANDBOX_IMAGE
    environment = req.environment or {}

    if not image:
        raise HTTPException(status_code=400, detail='No sandbox image specified')

    # user_id may come from environment vars or be empty
    # DynamoDB GSI key cannot be empty string — use 'anonymous' as fallback
    user_id = environment.get('USER_ID', '') or 'anonymous'
    session_api_key = str(uuid.uuid4())

    logger.info('Starting sandbox for session=%s, user=%s, image=%s', session_id, user_id, image)

    # Check if sandbox already exists and is running
    existing = store.get_sandbox(session_id)
    if existing and existing.status == 'RUNNING':
        logger.info('Sandbox already running for session=%s', session_id)
        return record_to_runtime(existing)

    def record_error(task_arn: str = '') -> None:
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

    logger.info('Sandbox started: session=%s, ip=%s', session_id, task_ip)
    return record_to_runtime(record)


@app.post('/stop')
def stop_sandbox(req: RuntimeIdRequest):
    """Stop a running sandbox task."""
    # runtime_id is the task_arn; find the record by scanning or use session_id
    # The upstream calls stop with runtime_id, but we need to find by task_arn
    record = _find_record_by_runtime_id(req.runtime_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='User requested stop')
        except RuntimeError as e:
            logger.error('Failed to stop task: %s', e)

    store.update_status(record.conversation_id, 'STOPPED')
    return {'status': 'stopped', 'session_id': record.conversation_id}


@app.post('/pause')
def pause_sandbox(req: RuntimeIdRequest):
    """Pause a sandbox (stops the task but marks as PAUSED for resume)."""
    record = _find_record_by_runtime_id(req.runtime_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='Sandbox paused')
        except RuntimeError as e:
            logger.error('Failed to pause task: %s', e)

    store.update_status(record.conversation_id, 'PAUSED')
    return {'status': 'paused', 'session_id': record.conversation_id}


@app.post('/resume')
def resume_sandbox(req: RuntimeIdRequest):
    """Resume a paused sandbox (starts new task, workspace intact on EFS)."""
    record = _find_record_by_runtime_id(req.runtime_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')

    if record.status == 'RUNNING':
        return record_to_runtime(record)

    image = record.sandbox_spec_id or SANDBOX_IMAGE
    session_api_key = record.session_api_key or str(uuid.uuid4())

    try:
        result = ecs.run_task(
            conversation_id=record.conversation_id,
            user_id=record.user_id,
            image=image,
            environment={},
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

    store.update_status(record.conversation_id, 'RUNNING', task_ip=task_ip, task_arn=task_arn)
    updated = store.get_sandbox(record.conversation_id)
    return record_to_runtime(updated) if updated else {'status': 'error'}


@app.get('/sessions/{session_id}')
def get_session(session_id: str):
    """Get runtime info for a single sandbox. Used by RemoteSandboxService._get_runtime()."""
    record = store.get_sandbox(session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')
    return record_to_runtime(record)


@app.get('/sessions/batch')
def batch_get_sessions(ids: list[str] = Query(default=[])):
    """Batch get runtime info. Upstream calls GET /sessions/batch?ids=...&ids=...

    Returns a list of runtime dicts (not wrapped in an object).
    """
    records = store.batch_get_sandboxes(ids)
    return [record_to_runtime(r) for r in records]


@app.get('/list')
def list_sessions():
    """List all running sandboxes.

    Returns {"runtimes": [...]} matching upstream RemoteSandboxService expectations.
    """
    records = store.list_running()
    return {'runtimes': [record_to_runtime(r) for r in records]}


@app.post('/activity')
def update_activity(req: ActivityRequest):
    """Update last_activity_at timestamp (called by OpenResty on each proxied request)."""
    try:
        store.update_activity(req.session_id)
    except Exception as e:
        logger.warning('Failed to update activity for %s: %s', req.session_id, e)
    return {'status': 'ok'}


# ========================================
# Internal helpers
# ========================================

def _find_record_by_runtime_id(runtime_id: str) -> Optional[SandboxRecord]:
    """Find a sandbox record by runtime_id (which is the task_arn or conversation_id)."""
    # First try as conversation_id (most common case)
    record = store.get_sandbox(runtime_id)
    if record:
        return record
    # If runtime_id is a task_arn, we'd need a GSI on task_arn.
    # For now, just return None — upstream typically uses session_id directly.
    return None
