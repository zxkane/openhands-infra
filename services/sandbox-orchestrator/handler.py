"""Sandbox Orchestrator - FastAPI service implementing the remote runtime HTTP API.

Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations.
Uses ECS Service for warm pool — auto-replenishment is handled by ECS, not custom code.
API format matches upstream expectations in remote_sandbox_service.py.
"""

import logging
import os
import threading
import time
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
WARM_POOL_SERVICE_NAME = os.environ.get('WARM_POOL_SERVICE_NAME', '')

# Initialize services
store = DynamoDBStore(REGISTRY_TABLE_NAME, region=AWS_REGION)
ecs = EcsManager(
    cluster_arn=ECS_CLUSTER_ARN,
    task_definition_arn=TASK_DEFINITION_ARN,
    subnets=[s.strip() for s in SUBNETS if s.strip()],
    security_group_id=SECURITY_GROUP_ID,
    region=AWS_REGION,
)


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
    return f'http://{ip}:{port}'


def record_to_runtime(record: SandboxRecord) -> dict:
    """Convert a SandboxRecord to the runtime dict format expected by RemoteSandboxService."""
    url = ''
    if record.task_ip and record.status == 'RUNNING':
        url = build_sandbox_url(record.task_ip, record.agent_server_port)

    status_map = {
        'RUNNING': 'running',
        'STARTING': 'pending',
        'WARM': 'pending',
        'PAUSED': 'stopped',
        'STOPPED': 'stopped',
        'ERROR': 'failed',
    }
    pod_status_map = {
        'RUNNING': 'ready',
        'STARTING': 'pending',
        'WARM': 'pending',
        'PAUSED': 'stopped',
        'STOPPED': 'stopped',
        'ERROR': 'failed',
    }

    return {
        'session_id': record.conversation_id,
        'runtime_id': record.task_arn or record.conversation_id,
        'status': status_map.get(record.status, record.status.lower()),
        'pod_status': pod_status_map.get(record.status, record.status.lower()),
        'url': url,
        'session_api_key': record.session_api_key,
        'image': record.sandbox_spec_id,
        'user_id': record.user_id,
    }


# ========================================
# ECS Service Warm Pool Sync
# ========================================
# ECS Service maintains desiredCount tasks. This sync loop discovers
# Service-managed tasks and registers them in DynamoDB as WARM.
# No RunTask needed — ECS handles all replenishment automatically.

def _sync_warm_pool():
    """Discover ECS Service tasks and sync DynamoDB registry.

    New tasks (not in DynamoDB) get registered as WARM.
    Stopped tasks get cleaned up from DynamoDB.
    """
    if not WARM_POOL_SERVICE_NAME or not ECS_CLUSTER_ARN:
        return

    try:
        # List running tasks in the warm pool Service
        response = ecs._ecs.list_tasks(
            cluster=ECS_CLUSTER_ARN,
            serviceName=WARM_POOL_SERVICE_NAME,
            desiredStatus='RUNNING',
        )
        service_task_arns = response.get('taskArns', [])
        if not service_task_arns:
            return

        # Describe tasks to get IPs
        desc_response = ecs._ecs.describe_tasks(
            cluster=ECS_CLUSTER_ARN,
            tasks=service_task_arns,
        )

        # Get all current DynamoDB WARM records indexed by task_arn
        existing_warm = {r.task_arn: r for r in store.query_by_status('WARM')}
        claimed_records = {r.task_arn: r for r in store.list_running()}
        service_task_arn_set = set(service_task_arns)

        # Clean up stale WARM records (task no longer in Service)
        for task_arn, record in existing_warm.items():
            if task_arn and task_arn not in service_task_arn_set:
                store.update_status(record.conversation_id, 'STOPPED')
                logger.info('Cleaned stale warm record: %s', record.conversation_id)

        for task in desc_response.get('tasks', []):
            task_arn = task['taskArn']
            task_status = task.get('lastStatus', '')

            # Skip tasks that are already claimed (RUNNING in DynamoDB)
            if task_arn in claimed_records:
                continue

            # Skip tasks already registered as WARM
            if task_arn in existing_warm:
                continue

            # New task — register as WARM if it has an IP
            if task_status == 'RUNNING':
                task_ip = EcsManager._extract_task_ip(task)
                if task_ip:
                    pool_id = f'warm-{uuid.uuid4().hex[:12]}'
                    session_api_key = str(uuid.uuid4())
                    record = SandboxRecord({
                        'conversation_id': pool_id,
                        'user_id': 'warm-pool',
                        'task_arn': task_arn,
                        'task_ip': task_ip,
                        'status': 'WARM',
                        'session_api_key': session_api_key,
                        'agent_server_port': 8000,
                        'sandbox_spec_id': SANDBOX_IMAGE,
                    })
                    store.put_sandbox(record)
                    logger.info('Registered warm task: %s, ip=%s', pool_id, task_ip)

    except Exception as e:
        logger.error('Warm pool sync error: %s', e)


def _sync_loop():
    """Background loop to sync ECS Service tasks with DynamoDB."""
    time.sleep(15)  # Initial delay for Service tasks to start
    while True:
        try:
            _sync_warm_pool()
        except Exception as e:
            logger.error('Sync loop error: %s', e)
        time.sleep(15)  # Sync every 15 seconds


# Start sync loop on app startup
if WARM_POOL_SERVICE_NAME and ECS_CLUSTER_ARN:
    threading.Thread(target=_sync_loop, daemon=True).start()
    logger.info('Warm pool sync enabled: service=%s', WARM_POOL_SERVICE_NAME)


# ========================================
# API Endpoints (Remote Runtime API)
# ========================================

@app.get('/health')
async def health():
    return {'status': 'ok'}


@app.post('/start')
def start_sandbox(req: StartRequest):
    """Start a sandbox for a conversation.

    Claims a pre-started warm task from the ECS Service (instant).
    Falls back to launching a new standalone task if no warm task available.
    """
    session_id = req.session_id
    if not session_id or not session_id.strip():
        raise HTTPException(status_code=400, detail='Invalid session_id')

    image = req.image or SANDBOX_IMAGE
    environment = req.environment or {}
    user_id = environment.get('USER_ID', '') or 'anonymous'

    logger.info('Starting sandbox: session=%s, user=%s', session_id, user_id)

    # Check if already running
    existing = store.get_sandbox(session_id)
    if existing and existing.status == 'RUNNING':
        logger.info('Sandbox already running: session=%s', session_id)
        return record_to_runtime(existing)

    # Try to claim a warm task from ECS Service
    # Verify the task is still running in ECS before claiming (prevents stale claims)
    warm_tasks = store.query_by_status('WARM')
    warm = None
    for candidate in warm_tasks:
        if not candidate.task_ip or not candidate.task_arn:
            continue
        task_info = ecs.describe_task(candidate.task_arn)
        if task_info and task_info['last_status'] == 'RUNNING':
            warm = candidate
            break
        else:
            # Task no longer running — clean up stale record
            store.update_status(candidate.conversation_id, 'STOPPED')
            logger.info('Cleaned stale warm task: %s', candidate.conversation_id)

    if warm:
        logger.info('Claimed warm task %s for session=%s (ip=%s)',
                     warm.conversation_id, session_id, warm.task_ip)

        # Mark warm record as claimed
        store.update_status(warm.conversation_id, 'CLAIMED')

        # Create the real conversation record
        record = SandboxRecord({
            'conversation_id': session_id,
            'user_id': user_id,
            'task_arn': warm.task_arn,
            'task_ip': warm.task_ip,
            'status': 'RUNNING',
            'session_api_key': warm.session_api_key,
            'agent_server_port': 8000,
            'sandbox_spec_id': image,
        })
        store.put_sandbox(record)
        return record_to_runtime(record)

    # No warm task available — launch a standalone task (async fallback)
    logger.info('No warm tasks, launching standalone for session=%s', session_id)
    session_api_key = str(uuid.uuid4())

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
        raise HTTPException(status_code=503, detail=str(e)) from e

    task_arn = result['task_arn']

    # Try to get IP quickly (8s, fits within upstream 15s httpx timeout)
    task_ip = ecs.wait_for_running(task_arn, timeout_seconds=8)

    status = 'RUNNING' if task_ip else 'STARTING'
    record = SandboxRecord({
        'conversation_id': session_id,
        'user_id': user_id,
        'task_arn': task_arn,
        'task_ip': task_ip or '',
        'status': status,
        'session_api_key': session_api_key,
        'agent_server_port': 8000,
        'sandbox_spec_id': image,
    })
    store.put_sandbox(record)

    if not task_ip:
        # Background: wait for IP then update
        def _wait_and_update():
            ip = ecs.wait_for_running(task_arn, timeout_seconds=180)
            if ip:
                store.update_status(session_id, 'RUNNING', task_ip=ip)
                logger.info('Sandbox ready (bg): session=%s, ip=%s', session_id, ip)
            else:
                logger.error('Sandbox failed: %s', task_arn)
                try:
                    ecs.stop_task(task_arn, reason='Failed to start')
                except RuntimeError:
                    pass
                store.update_status(session_id, 'ERROR')

        threading.Thread(target=_wait_and_update, daemon=True).start()
        logger.info('Sandbox provisioning: session=%s', session_id)
    else:
        logger.info('Sandbox ready: session=%s, ip=%s', session_id, task_ip)

    return record_to_runtime(record)


@app.post('/stop')
def stop_sandbox(req: RuntimeIdRequest):
    """Stop a sandbox. ECS Service auto-replaces stopped warm pool tasks."""
    record = _find_record_by_runtime_id(req.runtime_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')
    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='User requested stop')
        except RuntimeError as e:
            logger.error('Failed to stop: %s', e)
    store.update_status(record.conversation_id, 'STOPPED')
    return {'status': 'stopped', 'session_id': record.conversation_id}


@app.post('/pause')
def pause_sandbox(req: RuntimeIdRequest):
    """Pause a sandbox. ECS Service auto-replaces the stopped task."""
    record = _find_record_by_runtime_id(req.runtime_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')
    if record.status == 'RUNNING' and record.task_arn:
        try:
            ecs.stop_task(record.task_arn, reason='Sandbox paused')
        except RuntimeError as e:
            logger.error('Failed to pause: %s', e)
    store.update_status(record.conversation_id, 'PAUSED')
    return {'status': 'paused', 'session_id': record.conversation_id}


@app.post('/resume')
def resume_sandbox(req: RuntimeIdRequest):
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


# NOTE: /sessions/batch MUST be declared before /sessions/{session_id}
@app.get('/sessions/batch')
def batch_get_sessions(ids: list[str] = Query(default=[])):
    records = store.batch_get_sandboxes(ids)
    return [record_to_runtime(r) for r in records]


@app.get('/sessions/{session_id}')
def get_session(session_id: str):
    record = store.get_sandbox(session_id)
    if not record:
        raise HTTPException(status_code=404, detail='Sandbox not found')
    return record_to_runtime(record)


@app.get('/list')
def list_sessions():
    """List running sandboxes. Returns {"runtimes": [...]} for upstream compatibility."""
    records = store.list_running()
    return {'runtimes': [record_to_runtime(r) for r in records]}


@app.post('/activity')
def update_activity(req: ActivityRequest):
    try:
        store.update_activity(req.session_id)
    except Exception as e:
        logger.warning('Failed to update activity for %s: %s', req.session_id, e)
    return {'status': 'ok'}


# ========================================
# Internal helpers
# ========================================

def _find_record_by_runtime_id(runtime_id: str) -> Optional[SandboxRecord]:
    record = store.get_sandbox(runtime_id)
    if record:
        return record
    return None
