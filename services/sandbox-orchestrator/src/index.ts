/** Sandbox Orchestrator - Fastify service implementing the remote runtime HTTP API.
 *
 * Translates OpenHands RemoteSandboxService HTTP calls to ECS Fargate operations.
 * Uses ECS Service for warm pool - auto-replenishment is handled by ECS, not custom code.
 * API format matches upstream expectations in remote_sandbox_service.py.
 */

import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { config } from './config.js';
import { DynamoDBStore } from './dynamodb-store.js';
import { EcsManager } from './ecs-manager.js';
import { startWarmPoolSync } from './warm-pool-sync.js';
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
const ecs = new EcsManager({
  clusterArn: config.ecsClusterArn,
  taskDefinitionArn: config.taskDefinitionFamily,
  subnets: config.subnets,
  securityGroupId: config.securityGroupId,
  region: config.region,
});

// ========================================
// Helpers
// ========================================

/** Maps SandboxStatus to the API status string returned to callers. */
const STATUS_MAP: Record<SandboxStatus, string> = {
  RUNNING: 'running',
  STARTING: 'pending',
  WARM: 'pending',
  CLAIMED: 'pending',
  PAUSED: 'stopped',
  STOPPED: 'stopped',
  ERROR: 'failed',
};

/** Maps SandboxStatus to the pod_status string returned to callers. */
const POD_STATUS_MAP: Record<SandboxStatus, string> = {
  RUNNING: 'ready',
  STARTING: 'pending',
  WARM: 'pending',
  CLAIMED: 'pending',
  PAUSED: 'stopped',
  STOPPED: 'stopped',
  ERROR: 'failed',
};

function buildSandboxUrl(ip: string, port = 8000): string {
  return `http://${ip}:${port}`;
}

/** Max length for session_id / runtime_id to prevent DynamoDB item size abuse. */
const MAX_ID_LENGTH = 256;

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

  // Check if already running
  const existing = await store.getSandbox(session_id);
  if (existing && existing.status === 'RUNNING') {
    request.log.info(`Sandbox already running: session=${session_id}`);
    return recordToRuntime(existing);
  }

  // Try to claim a warm task from ECS Service (atomic conditional update)
  const warmTasks = await store.queryByStatus('WARM');
  let warm: SandboxRecord | null = null;
  for (const candidate of warmTasks) {
    if (!candidate.task_ip || !candidate.task_arn) continue;
    const taskInfo = await ecs.describeTask(candidate.task_arn);
    if (taskInfo && taskInfo.last_status === 'RUNNING') {
      // Atomic claim — prevents two concurrent /start requests from getting the same task
      const claimed = await store.claimWarmTask(candidate.conversation_id);
      if (claimed) {
        warm = candidate;
        break;
      }
      // Another request already claimed it — try next candidate
      request.log.info(`Warm task ${candidate.conversation_id} already claimed, trying next`);
    } else {
      // Task no longer running - clean up stale record
      await store.updateStatus(candidate.conversation_id, 'STOPPED');
      request.log.info(`Cleaned stale warm task: ${candidate.conversation_id}`);
    }
  }

  if (warm) {
    request.log.info(
      `Claimed warm task ${warm.conversation_id} for session=${session_id} (ip=${warm.task_ip})`,
    );

    // Create the real conversation record
    const record: SandboxRecord = {
      conversation_id: session_id,
      user_id: userId,
      task_arn: warm.task_arn,
      task_ip: warm.task_ip,
      status: 'RUNNING',
      session_api_key: warm.session_api_key,
      agent_server_port: 8000,
      sandbox_spec_id: sandboxImage,
      last_activity_at: 0,
      created_at: 0,
    };
    await store.putSandbox(record);
    return recordToRuntime(record);
  }

  // No warm task available - launch a standalone task (async fallback)
  request.log.info(`No warm tasks, launching standalone for session=${session_id}`);
  const sessionApiKey = randomUUID();

  let result;
  try {
    result = await ecs.runTask({
      conversationId: session_id,
      userId,
      image: sandboxImage,
      environment: env,
      sessionApiKey,
    });
  } catch (err) {
    request.log.error(`Failed to start sandbox: ${err}`);
    return reply.code(503).send({ detail: String(err) });
  }

  const taskArn = result.task_arn;

  // Try to get IP quickly (8s, fits within upstream 15s httpx timeout)
  const taskIp = await ecs.waitForRunning(taskArn, 8);

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
  };
  await store.putSandbox(record);

  if (!taskIp) {
    // Background: wait for IP then update
    (async () => {
      const ip = await ecs.waitForRunning(taskArn, 180);
      if (ip) {
        await store.updateStatus(session_id, 'RUNNING', ip);
        app.log.info(`Sandbox ready (bg): session=${session_id}, ip=${ip}`);
      } else {
        app.log.error(`Sandbox failed: ${taskArn}`);
        try {
          await ecs.stopTask(taskArn, 'Failed to start');
        } catch {
          // ignore
        }
        await store.updateStatus(session_id, 'ERROR');
      }
    })().catch((err) => app.log.error(`Background sandbox setup failed: ${err}`));
    request.log.info(`Sandbox provisioning: session=${session_id}`);
  } else {
    request.log.info(`Sandbox ready: session=${session_id}, ip=${taskIp}`);
  }

  return recordToRuntime(record);
});

app.post<{ Body: RuntimeIdRequest }>('/stop', async (request, reply) => {
  const record = await store.getSandbox(request.body.runtime_id);
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
  await store.updateStatus(record.conversation_id, 'STOPPED');
  return { status: 'stopped', session_id: record.conversation_id };
});

app.post<{ Body: RuntimeIdRequest }>('/pause', async (request, reply) => {
  const record = await store.getSandbox(request.body.runtime_id);
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
  await store.updateStatus(record.conversation_id, 'PAUSED');
  return { status: 'paused', session_id: record.conversation_id };
});

app.post<{ Body: RuntimeIdRequest }>('/resume', async (request, reply) => {
  const record = await store.getSandbox(request.body.runtime_id);
  if (!record) {
    return reply.code(404).send({ detail: 'Sandbox not found' });
  }
  if (record.status === 'RUNNING') {
    return recordToRuntime(record);
  }

  const sandboxImage = record.sandbox_spec_id || config.sandboxImage;
  const sessionApiKey = record.session_api_key || randomUUID();

  let result;
  try {
    result = await ecs.runTask({
      conversationId: record.conversation_id,
      userId: record.user_id,
      image: sandboxImage,
      environment: {},
      sessionApiKey,
    });
  } catch (err) {
    return reply.code(503).send({ detail: String(err) });
  }

  const taskArn = result.task_arn;
  const taskIp = await ecs.waitForRunning(taskArn, 120);
  if (!taskIp) {
    try {
      await ecs.stopTask(taskArn, 'Failed to resume');
    } catch {
      // ignore
    }
    return reply.code(503).send({ detail: 'Sandbox task failed to resume' });
  }

  await store.updateStatus(record.conversation_id, 'RUNNING', taskIp, taskArn);
  const updated = await store.getSandbox(record.conversation_id);
  return updated ? recordToRuntime(updated) : { status: 'error' };
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
    return records.map(recordToRuntime);
  },
);

app.get<{ Params: { session_id: string } }>(
  '/sessions/:session_id',
  async (request, reply) => {
    const record = await store.getSandbox(request.params.session_id);
    if (!record) {
      return reply.code(404).send({ detail: 'Sandbox not found' });
    }
    return recordToRuntime(record);
  },
);

app.get('/list', async () => {
  const records = await store.listRunning();
  return { runtimes: records.map(recordToRuntime) };
});

app.post<{ Body: ActivityRequest }>('/activity', async (request) => {
  try {
    await store.updateActivity(request.body.session_id);
  } catch (err) {
    app.log.warn(`Failed to update activity for ${request.body.session_id}: ${err}`);
  }
  return { status: 'ok' };
});

// ========================================
// Start server
// ========================================

let warmPoolTimer: NodeJS.Timeout | undefined;

async function main(): Promise<void> {
  if (config.warmPoolServiceName && config.ecsClusterArn) {
    warmPoolTimer = startWarmPoolSync(ecs, store, config.warmPoolServiceName, config.sandboxImage, (level, msg) => {
      if (level === 'error') app.log.error(msg);
      else app.log.info(msg);
    });
  }

  // Graceful shutdown — ECS sends SIGTERM before killing tasks
  for (const signal of ['SIGTERM', 'SIGINT'] as const) {
    process.on(signal, async () => {
      app.log.info(`Received ${signal}, shutting down gracefully`);
      if (warmPoolTimer) clearInterval(warmPoolTimer);
      await app.close();
      process.exit(0);
    });
  }

  await app.listen({ port: config.port, host: '0.0.0.0' });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

export { app, store, ecs };
