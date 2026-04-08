/** Sandbox Orchestrator - Fastify service implementing the remote runtime HTTP API.
 *
 * Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations
 * with per-conversation EFS workspace isolation.
 * API format matches upstream expectations in remote_sandbox_service.py.
 */

import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { config } from './config.js';
import { DynamoDBStore } from './dynamodb-store.js';
import { EcsManager } from './ecs-manager.js';
import { EfsManager } from './efs-manager.js';
import type {
  SandboxRecord,
  SandboxStatus,
  RuntimeInfo,
  StartRequest,
  RuntimeIdRequest,
  ActivityRequest,
} from './types.js';

const app = Fastify({ logger: true });

const store = new DynamoDBStore(config.registryTableName, config.region);
const efsManager = config.efsFileSystemId
  ? new EfsManager({ fileSystemId: config.efsFileSystemId, region: config.region })
  : null;
const ecs = new EcsManager({
  clusterArn: config.ecsClusterArn,
  taskDefinitionArn: config.taskDefinitionFamily,
  subnets: config.subnets,
  securityGroupId: config.securityGroupId,
  region: config.region,
});
const lambdaClient = config.deletionLambdaArn
  ? new LambdaClient({ region: config.region })
  : null;

// ========================================
// Helpers
// ========================================

/** Maps SandboxStatus to the API status string returned to callers.
 * Values must match the upstream RemoteSandboxService.STATUS_MAPPING in
 * openhands/app_server/sandbox/remote_sandbox_service.py:
 *   running → RUNNING, starting → STARTING, paused → PAUSED,
 *   stopped → MISSING, error → ERROR
 */
const STATUS_MAP: Record<SandboxStatus, string> = {
  RUNNING: 'running',
  STARTING: 'starting', // upstream expects 'starting', not 'pending'
  WARM: 'starting',
  CLAIMED: 'starting',
  PAUSED: 'paused',    // App maps 'paused' → SandboxStatus.PAUSED → ConversationStatus.STOPPED (resumable)
  STOPPED: 'paused',   // Also resumable — EFS data persists, only the ECS task stopped
  ARCHIVED: 'stopped', // App maps 'stopped' → SandboxStatus.MISSING → ConversationStatus.ARCHIVED (not resumable)
  ERROR: 'error',      // upstream expects 'error', not 'failed'
};

/** Maps SandboxStatus to the pod_status string returned to callers. */
const POD_STATUS_MAP: Record<SandboxStatus, string> = {
  RUNNING: 'ready',
  STARTING: 'pending',
  WARM: 'pending',
  CLAIMED: 'pending',
  PAUSED: 'paused',    // Resumable — sandbox was idle-stopped but can restart
  STOPPED: 'paused',   // Also resumable — EFS data persists, only the ECS task stopped
  ARCHIVED: 'stopped', // Not resumable — archived beyond retention period
  ERROR: 'failed',
};

function buildSandboxUrl(ip: string, port = 8000): string {
  return `http://${ip}:${port}`;
}

/** Max length for session_id / runtime_id to prevent DynamoDB item size abuse. */
const MAX_ID_LENGTH = 256;

/**
 * Verify RUNNING records against ECS — mark stopped tasks as STOPPED in DynamoDB.
 * This prevents the upstream OpenHands app from trying to connect to dead task IPs
 * (which causes 5s httpx timeouts per stale sandbox, accumulating to 15s+ for /api/conversations).
 */
async function verifyRunningRecords(records: SandboxRecord[]): Promise<SandboxRecord[]> {
  const running = records.filter((r) => r.status === 'RUNNING' && r.task_arn);
  if (!running.length) return records;

  // Batch describe all RUNNING tasks in a single ECS API call
  const taskArns = running.map((r) => r.task_arn);
  const tasks = await ecs.describeTasks(taskArns);
  const taskStatusMap = new Map<string, string>();
  for (const task of tasks) {
    if (task.taskArn) {
      taskStatusMap.set(task.taskArn, task.lastStatus ?? 'UNKNOWN');
    }
  }

  // Update stale records in parallel
  const updates: Promise<void>[] = [];
  const result = records.map((record) => {
    if (record.status !== 'RUNNING' || !record.task_arn) return record;

    const ecsStatus = taskStatusMap.get(record.task_arn);
    if (!ecsStatus || ecsStatus === 'STOPPED' || ecsStatus === 'DEPROVISIONING') {
      // Task is gone — mark as STOPPED and return corrected record
      updates.push(
        store.updateStatus(record.conversation_id, 'STOPPED').catch((err) => {
          app.log.warn(`Failed to mark stale record ${record.conversation_id}: ${err}`);
        }),
      );
      return { ...record, status: 'STOPPED' as const, task_ip: '' };
    }
    return record;
  });

  if (updates.length) {
    await Promise.all(updates);
    app.log.info(`Marked ${updates.length} stale RUNNING record(s) as STOPPED`);
  }

  return result;
}

/** Clean up EFS access point and task definition. Silently ignores failures. */
async function cleanupEfsResources(accessPointId?: string, taskDefinitionArn?: string): Promise<void> {
  if (accessPointId && efsManager) {
    await efsManager.deleteAccessPoint(accessPointId).catch((err) => {
      app.log.warn(`Failed to delete access point ${accessPointId}: ${err}`);
    });
  }
  if (taskDefinitionArn) {
    await ecs.deregisterTaskDefinition(taskDefinitionArn).catch((err) => {
      app.log.warn(`Failed to deregister task def ${taskDefinitionArn}: ${err}`);
    });
  }
}

/**
 * Create a per-conversation EFS access point and register a task definition
 * that binds to it. Returns the IDs on success, or cleans up partial resources
 * and returns null on failure.
 */
async function setupEfsIsolation(
  conversationId: string,
  logger: { info: (msg: string) => void; error: (msg: string) => void },
): Promise<{ accessPointId: string; taskDefinitionArn: string } | null> {
  if (!efsManager || !config.efsFileSystemId) return null;

  let accessPointId: string | undefined;
  let taskDefinitionArn: string | undefined;

  try {
    accessPointId = await efsManager.createAccessPoint(conversationId);
    await efsManager.waitForAvailable(accessPointId);
    taskDefinitionArn = await ecs.registerTaskDefinitionWithAccessPoint(
      accessPointId,
      config.efsFileSystemId,
    );
    logger.info(`Created access point ${accessPointId} and task def ${taskDefinitionArn}`);
    return { accessPointId, taskDefinitionArn };
  } catch (err) {
    logger.error(`Failed to set up per-conversation EFS: ${err}`);
    await cleanupEfsResources(accessPointId, taskDefinitionArn);
    return null;
  }
}

function recordToRuntime(record: SandboxRecord): RuntimeInfo {
  const url = record.task_ip && record.status === 'RUNNING'
    ? buildSandboxUrl(record.task_ip, record.agent_server_port)
    : '';

  return {
    session_id: record.conversation_id,
    // Use conversation_id as runtime_id — the upstream RemoteSandboxService
    // sends this value back on /stop, /pause, /resume and we look it up by
    // conversation_id (DynamoDB partition key).
    runtime_id: record.conversation_id,
    status: STATUS_MAP[record.status] ?? record.status.toLowerCase(),
    pod_status: POD_STATUS_MAP[record.status] ?? record.status.toLowerCase(),
    url,
    session_api_key: record.session_api_key,
    image: record.sandbox_spec_id,
    user_id: record.user_id,
  };
}

// ========================================
// API Routes
// ========================================

app.get('/health', async () => {
  return { status: 'ok' };
});

app.post<{ Body: StartRequest }>('/start', async (request, reply) => {
  const { session_id, image, environment } = request.body;
  if (!session_id?.trim() || session_id.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid session_id' });
  }

  const sandboxImage = image || config.sandboxImage;
  const env = environment || {};
  const userId = env.USER_ID || 'anonymous';

  request.log.info(`Starting sandbox: session=${session_id}, user=${userId}`);

  // Check existing record
  const existing = await store.getSandbox(session_id);
  if (existing && existing.status === 'RUNNING') {
    request.log.info(`Sandbox already running: session=${session_id}`);
    return recordToRuntime(existing);
  }
  if (existing && existing.status === 'ARCHIVED') {
    return reply.code(409).send({ detail: 'Conversation is archived and cannot be resumed' });
  }

  // Per-conversation EFS isolation: create access point + register task definition
  request.log.info(`Launching sandbox task for session=${session_id}`);
  const sessionApiKey = randomUUID();

  const timings: Record<string, number> = {};
  const t0 = Date.now();

  const efsSetup = await setupEfsIsolation(session_id, request.log);
  timings.efs_setup_ms = Date.now() - t0;

  if (efsManager && config.efsFileSystemId && !efsSetup) {
    return reply.code(503).send({ detail: 'Failed to start sandbox' });
  }

  let result;
  const tRunTask = Date.now();
  try {
    result = await ecs.runTask({
      conversationId: session_id,
      userId,
      image: sandboxImage,
      environment: env,
      sessionApiKey,
      taskDefinitionOverride: efsSetup?.taskDefinitionArn,
    });
  } catch (err) {
    request.log.error(`Failed to start sandbox: ${err}`);
    await cleanupEfsResources(efsSetup?.accessPointId, efsSetup?.taskDefinitionArn);
    return reply.code(503).send({ detail: 'Failed to start sandbox' });
  }
  timings.run_task_api_ms = Date.now() - tRunTask;

  const taskArn = result.task_arn;

  // Try to get IP quickly (8s, fits within upstream 15s httpx timeout)
  const tWait = Date.now();
  const taskIp = await ecs.waitForRunning(taskArn, 8);
  timings.wait_for_running_ms = Date.now() - tWait;
  timings.total_ms = Date.now() - t0;

  const status: SandboxStatus = taskIp ? 'RUNNING' : 'STARTING';
  const record: SandboxRecord = {
    conversation_id: session_id,
    user_id: userId,
    task_arn: taskArn,
    task_ip: taskIp || '',
    status,
    session_api_key: sessionApiKey,
    agent_server_port: 8000,
    sandbox_spec_id: sandboxImage,
    last_activity_at: 0,
    created_at: 0,
    access_point_id: efsSetup?.accessPointId,
    task_definition_arn: efsSetup?.taskDefinitionArn,
  };
  await store.putSandbox(record);

  if (!taskIp) {
    // Background: wait for IP then update
    const bgStart = Date.now();
    (async () => {
      const ip = await ecs.waitForRunning(taskArn, 180);
      const bgTimings = { ...timings, bg_wait_ms: Date.now() - bgStart, total_ms: Date.now() - t0 };
      if (ip) {
        await store.updateStatus(session_id, 'RUNNING', ip);
        app.log.info({ msg: 'sandbox-startup-timing', route: 'start', session_id, ...bgTimings });
      } else {
        app.log.error(`Sandbox failed: ${taskArn}`);
        app.log.info({ msg: 'sandbox-startup-timing', route: 'start', session_id, failed: true, ...bgTimings });
        try {
          await ecs.stopTask(taskArn, 'Failed to start');
        } catch {
          // ignore
        }
        await cleanupEfsResources(efsSetup?.accessPointId, efsSetup?.taskDefinitionArn);
        await store.updateStatus(session_id, 'ERROR');
      }
    })().catch((err) => app.log.error(`Background sandbox setup failed: ${err}`));
    request.log.info(`Sandbox provisioning: session=${session_id}`);
  } else {
    request.log.info({ msg: 'sandbox-startup-timing', route: 'start', session_id, ...timings });
  }

  return recordToRuntime(record);
});

app.post<{ Body: RuntimeIdRequest }>('/stop', async (request, reply) => {
  const runtimeId = request.body.runtime_id;
  if (!runtimeId?.trim() || runtimeId.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid runtime_id' });
  }
  const record = await store.getSandbox(runtimeId);
  if (!record) {
    return reply.code(404).send({ detail: 'Sandbox not found' });
  }
  if (record.status === 'RUNNING' && record.task_arn) {
    try {
      await ecs.stopTask(record.task_arn, 'User requested stop');
    } catch (err) {
      request.log.error(`Failed to stop: ${err}`);
    }
  }
  await cleanupEfsResources(record.access_point_id, record.task_definition_arn);
  await store.updateStatus(record.conversation_id, 'STOPPED');
  return { status: 'stopped', session_id: record.conversation_id };
});

app.post<{ Body: RuntimeIdRequest }>('/pause', async (request, reply) => {
  const runtimeId = request.body.runtime_id;
  if (!runtimeId?.trim() || runtimeId.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid runtime_id' });
  }
  const record = await store.getSandbox(runtimeId);
  if (!record) {
    return reply.code(404).send({ detail: 'Sandbox not found' });
  }
  if (record.status === 'RUNNING' && record.task_arn) {
    try {
      await ecs.stopTask(record.task_arn, 'Sandbox paused');
    } catch (err) {
      request.log.error(`Failed to pause: ${err}`);
    }
  }
  await cleanupEfsResources(record.access_point_id, record.task_definition_arn);
  await store.updateStatus(record.conversation_id, 'PAUSED');
  return { status: 'paused', session_id: record.conversation_id };
});

app.post<{ Body: RuntimeIdRequest }>('/resume', async (request, reply) => {
  const runtimeId = request.body.runtime_id;
  if (!runtimeId?.trim() || runtimeId.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid runtime_id' });
  }
  const record = await store.getSandbox(runtimeId);
  if (!record) {
    return reply.code(404).send({ detail: 'Sandbox not found' });
  }
  if (record.status === 'ARCHIVED') {
    return reply.code(409).send({ detail: 'Conversation is archived and cannot be resumed' });
  }
  if (record.status === 'RUNNING' || record.status === 'STARTING') {
    return recordToRuntime(record);
  }

  // Immediately mark as STARTING to prevent concurrent resume requests from creating duplicate tasks
  await store.updateStatus(record.conversation_id, 'STARTING');

  const sandboxImage = record.sandbox_spec_id || config.sandboxImage;
  const sessionApiKey = record.session_api_key || randomUUID();

  const timings: Record<string, number> = {};
  const t0 = Date.now();

  // Per-conversation EFS isolation: create new access point for resumed session
  const efsSetup = await setupEfsIsolation(record.conversation_id, request.log);
  timings.efs_setup_ms = Date.now() - t0;

  if (efsManager && config.efsFileSystemId && !efsSetup) {
    await store.updateStatus(record.conversation_id, 'PAUSED').catch(() => {});
    return reply.code(503).send({ detail: 'Failed to start sandbox' });
  }

  let result;
  const tRunTask = Date.now();
  try {
    result = await ecs.runTask({
      conversationId: record.conversation_id,
      userId: record.user_id,
      image: sandboxImage,
      environment: {},
      sessionApiKey,
      taskDefinitionOverride: efsSetup?.taskDefinitionArn,
    });
  } catch (err) {
    await cleanupEfsResources(efsSetup?.accessPointId, efsSetup?.taskDefinitionArn);
    await store.updateStatus(record.conversation_id, 'PAUSED').catch(() => {});
    return reply.code(503).send({ detail: 'Failed to start sandbox' });
  }
  timings.run_task_api_ms = Date.now() - tRunTask;

  const taskArn = result.task_arn;
  const tWait = Date.now();
  const taskIp = await ecs.waitForRunning(taskArn, 120);
  timings.wait_for_running_ms = Date.now() - tWait;
  timings.total_ms = Date.now() - t0;

  if (!taskIp) {
    request.log.info({ msg: 'sandbox-startup-timing', route: 'resume', session_id: runtimeId, failed: true, ...timings });
    try {
      await ecs.stopTask(taskArn, 'Failed to resume');
    } catch {
      // ignore
    }
    await cleanupEfsResources(efsSetup?.accessPointId, efsSetup?.taskDefinitionArn);
    await store.updateStatus(record.conversation_id, 'PAUSED').catch(() => {});
    return reply.code(503).send({ detail: 'Sandbox task failed to resume' });
  }

  request.log.info({ msg: 'sandbox-startup-timing', route: 'resume', session_id: runtimeId, ...timings });

  await store.updateStatus(
    record.conversation_id, 'RUNNING', taskIp, taskArn,
    efsSetup?.accessPointId, efsSetup?.taskDefinitionArn,
  );
  const updated = await store.getSandbox(record.conversation_id);
  return updated ? recordToRuntime(updated) : { status: 'error' };
});

app.post<{ Body: RuntimeIdRequest }>('/delete', async (request, reply) => {
  const runtimeId = request.body.runtime_id;
  if (!runtimeId?.trim() || runtimeId.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid runtime_id' });
  }
  const record = await store.getSandbox(runtimeId);
  if (!record) {
    return reply.code(404).send({ detail: 'Sandbox not found' });
  }

  request.log.info(`Deleting conversation: ${runtimeId}, user=${record.user_id}`);

  // Stop ECS task if running
  if ((record.status === 'RUNNING' || record.status === 'STARTING') && record.task_arn) {
    try {
      await ecs.stopTask(record.task_arn, 'Conversation deleted');
    } catch (err) {
      request.log.error(`Failed to stop task during delete: ${err}`);
    }
  }

  // Clean up EFS access point and task definition
  await cleanupEfsResources(record.access_point_id, record.task_definition_arn);

  // Delete DynamoDB record
  await store.deleteSandbox(record.conversation_id);

  // Async invoke deletion Lambda for full data wipe (S3, EFS workspace, Aurora)
  if (lambdaClient && config.deletionLambdaArn) {
    try {
      await lambdaClient.send(new InvokeCommand({
        FunctionName: config.deletionLambdaArn,
        InvocationType: 'Event', // Async — don't wait for completion
        Payload: Buffer.from(JSON.stringify({
          conversation_id: record.conversation_id,
          user_id: record.user_id,
        })),
      }));
      request.log.info(`Deletion Lambda invoked for ${record.conversation_id}`);
    } catch (err) {
      request.log.error(`Failed to invoke deletion Lambda: ${err}`);
    }
  }

  return { status: 'deleted', session_id: record.conversation_id };
});

// NOTE: /sessions/batch MUST be declared before /sessions/:session_id
app.get<{ Querystring: { ids?: string | string[] } }>(
  '/sessions/batch',
  async (request) => {
    let ids: string[] = [];
    const raw = request.query.ids;
    if (Array.isArray(raw)) {
      ids = raw;
    } else if (typeof raw === 'string') {
      ids = raw.split(',').filter(Boolean);
    }
    const records = await store.batchGetSandboxes(ids);
    // Verify RUNNING records against ECS to prevent stale data causing upstream timeouts
    const verified = await verifyRunningRecords(records);
    return verified.map(recordToRuntime);
  },
);

app.get<{ Params: { session_id: string } }>(
  '/sessions/:session_id',
  async (request, reply) => {
    const record = await store.getSandbox(request.params.session_id);
    if (!record) {
      return reply.code(404).send({ detail: 'Sandbox not found' });
    }
    // Verify single RUNNING record against ECS
    const verified = await verifyRunningRecords([record]);
    return recordToRuntime(verified[0] ?? record);
  },
);

// /runtime/:id — alias for /sessions/:id (used by upstream RemoteSandboxService for VS Code URL)
app.get<{ Params: { id: string } }>(
  '/runtime/:id',
  async (request, reply) => {
    const record = await store.getSandbox(request.params.id);
    if (!record) {
      return reply.code(404).send({ detail: 'Sandbox not found' });
    }
    const verified = await verifyRunningRecords([record]);
    return recordToRuntime(verified[0] ?? record);
  },
);

app.get('/list', async () => {
  const records = await store.listRunning();
  return { runtimes: records.map(recordToRuntime) };
});

app.post<{ Body: ActivityRequest }>('/activity', async (request, reply) => {
  const sessionId = request.body.session_id;
  if (!sessionId?.trim() || sessionId.length > MAX_ID_LENGTH) {
    return reply.code(400).send({ detail: 'Invalid session_id' });
  }
  try {
    await store.updateActivity(sessionId);
  } catch (err) {
    app.log.warn(`Failed to update activity for ${sessionId}: ${err}`);
  }
  return { status: 'ok' };
});

// ========================================
// Start server
// ========================================

async function main(): Promise<void> {
  // Graceful shutdown — ECS sends SIGTERM before killing tasks
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, () => {
      app.log.info(`Received ${signal}, shutting down gracefully`);
      app.close().then(() => process.exit(0)).catch(() => process.exit(1));
    });
  }

  await app.listen({ port: config.port, host: '0.0.0.0' });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

export { app, store, ecs, efsManager };
