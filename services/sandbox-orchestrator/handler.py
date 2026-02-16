"""Sandbox Orchestrator - FastAPI service implementing the remote runtime HTTP API.

Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations.
Implements a warm pool of pre-started Fargate tasks for instant sandbox assignment.
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
WARM_POOL_SIZE = int(os.environ.get('WARM_POOL_SIZE', '2'))

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

    # Upstream has two status conventions:
    # - 'status': poll_agent_servers filters by runtime['status'] == 'running'
    # - 'pod_status': _get_sandbox_status_from_runtime uses POD_STATUS_MAPPING
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
# Warm Pool Management
# ========================================

def _claim_warm_task() -> Optional[SandboxRecord]:
    """Try to claim a WARM task from the pool. Returns the record if successful."""
    warm_tasks = store.query_by_status('WARM')
    for task in warm_tasks:
        if task.task_ip:  # Only claim tasks that have an IP (fully ready)
            return task
    return None


def _replenish_warm_pool():
    """Start new Fargate tasks to maintain the warm pool target size."""
    warm_tasks = store.query_by_status('WARM')
    warm_count = len([t for t in warm_tasks if t.task_ip])  # Only count ready ones
    needed = WARM_POOL_SIZE - warm_count

    if needed <= 0:
        return

    logger.info('Replenishing warm pool: %d warm, %d needed', warm_count, needed)
    for _ in range(needed):
        try:
            pool_id = f'warm-{uuid.uuid4().hex[:12]}'
            session_api_key = str(uuid.uuid4())

            result = ecs.run_task(
                conversation_id=pool_id,
                user_id='warm-pool',
                image=SANDBOX_IMAGE,
                environment={},
                session_api_key=session_api_key,
            )
            task_arn = result['task_arn']

            record = SandboxRecord({
                'conversation_id': pool_id,
                'user_id': 'warm-pool',
                'task_arn': task_arn,
                'task_ip': '',
                'status': 'WARM',
                'session_api_key': session_api_key,
                'agent_server_port': 8000,
                'sandbox_spec_id': SANDBOX_IMAGE,
            })
            store.put_sandbox(record)

            # Background: wait for IP then update
            def _wait_for_ip(sid, tarn):
                ip = ecs.wait_for_running(tarn, timeout_seconds=180)
                if ip:
                    store.update_status(sid, 'WARM', task_ip=ip)
                    logger.info('Warm task ready: %s, ip=%s', sid, ip)
                else:
                    logger.error('Warm task failed to start: %s', tarn)
                    store.update_status(sid, 'ERROR')

            threading.Thread(target=_wait_for_ip, args=(pool_id, task_arn), daemon=True).start()
            logger.info('Warm task launched: %s, task=%s', pool_id, task_arn)

        except Exception as e:
            logger.error('Failed to launch warm task: %s', e)


def _warm_pool_maintenance_loop():
    """Background loop to maintain the warm pool."""
    time.sleep(10)  # Initial delay to let services start
    while True:
        try:
            _replenish_warm_pool()
        except Exception as e:
            logger.error('Warm pool maintenance error: %s', e)
        time.sleep(30)  # Check every 30 seconds


# Start warm pool maintenance on app startup
if WARM_POOL_SIZE > 0 and ECS_CLUSTER_ARN:
    threading.Thread(target=_warm_pool_maintenance_loop, daemon=True).start()
    logger.info('Warm pool enabled: target=%d tasks', WARM_POOL_SIZE)


# ========================================
# API Endpoints (Remote Runtime API)
# ========================================

@app.get('/health')
async def health():
    return {'status': 'ok'}


@app.post('/start')
def start_sandbox(req: StartRequest):
    """Start a sandbox for a conversation.

    First tries to claim a pre-started warm task (instant).
    Falls back to launching a new task (async, ~90s).
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

    # Try to claim a warm task (instant assignment)
    warm = _claim_warm_task()
    if warm:
        logger.info('Claimed warm task %s for session=%s (ip=%s)', warm.conversation_id, session_id, warm.task_ip)

        # Delete the warm pool record and create the real one
        store.update_status(warm.conversation_id, 'CLAIMED')

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

        # Trigger replenishment in background
        threading.Thread(target=_replenish_warm_pool, daemon=True).start()

        return record_to_runtime(record)

    # No warm task available — launch a new one (async)
    logger.info('No warm tasks available, launching new task for session=%s', session_id)
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

    if task_ip:
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
        logger.info('Sandbox ready: session=%s, ip=%s', session_id, task_ip)
    else:
        record = SandboxRecord({
            'conversation_id': session_id,
            'user_id': user_id,
            'task_arn': task_arn,
            'task_ip': '',
            'status': 'STARTING',
            'session_api_key': session_api_key,
            'agent_server_port': 8000,
            'sandbox_spec_id': image,
        })
        store.put_sandbox(record)

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

    return record_to_runtime(record)


@app.post('/stop')
def stop_sandbox(req: RuntimeIdRequest):
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
    """Batch get runtime info. Returns a list of runtime dicts."""
    records = store.batch_get_sandboxes(ids)
    return [record_to_runtime(r) for r in records]


@app.get('/sessions/{session_id}')
def get_session(session_id: str):
    """Get runtime info for a single sandbox."""
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
    """Update last_activity_at (non-critical, called by OpenResty on proxied requests)."""
    try:
        store.update_activity(req.session_id)
    except Exception as e:
        logger.warning('Failed to update activity for %s: %s', req.session_id, e)
    return {'status': 'ok'}


# ========================================
# Internal helpers
# ========================================

def _find_record_by_runtime_id(runtime_id: str) -> Optional[SandboxRecord]:
    """Find a sandbox record by runtime_id (task_arn or conversation_id)."""
    record = store.get_sandbox(runtime_id)
    if record:
        return record
    return None
