/** Background sync for ECS Service warm pool task discovery. */

import { randomUUID } from 'node:crypto';
import { EcsManager } from './ecs-manager.js';
import { DynamoDBStore } from './dynamodb-store.js';
import type { SandboxRecord } from './types.js';

const SYNC_INTERVAL_MS = 15_000; // 15 seconds

type LogFn = (level: 'info' | 'error', msg: string) => void;

export function startWarmPoolSync(
  ecs: EcsManager,
  store: DynamoDBStore,
  warmPoolServiceName: string,
  sandboxImage: string,
  log: LogFn,
): NodeJS.Timeout {
  async function sync(): Promise<void> {
    try {
      const serviceTaskArns = await ecs.listServiceTasks(warmPoolServiceName);
      if (!serviceTaskArns.length) return;

      const tasks = await ecs.describeTasks(serviceTaskArns);

      // Get all current DynamoDB WARM records indexed by task_arn
      const existingWarm = new Map<string, SandboxRecord>();
      for (const r of await store.queryByStatus('WARM')) {
        if (r.task_arn) existingWarm.set(r.task_arn, r);
      }
      const claimedRecords = new Map<string, SandboxRecord>();
      for (const r of await store.listRunning()) {
        if (r.task_arn) claimedRecords.set(r.task_arn, r);
      }
      const serviceTaskArnSet = new Set(serviceTaskArns);

      // Clean up stale WARM records (task no longer in Service)
      for (const [taskArn, record] of existingWarm) {
        if (taskArn && !serviceTaskArnSet.has(taskArn)) {
          await store.updateStatus(record.conversation_id, 'STOPPED');
          log('info', `Cleaned stale warm record: ${record.conversation_id}`);
        }
      }

      for (const task of tasks) {
        const taskArn = task.taskArn;
        if (!taskArn) continue;
        const taskStatus = task.lastStatus ?? '';

        // Skip tasks that are already claimed (RUNNING in DynamoDB)
        if (claimedRecords.has(taskArn)) continue;
        // Skip tasks already registered as WARM
        if (existingWarm.has(taskArn)) continue;

        // New task - register as WARM if it has an IP
        if (taskStatus === 'RUNNING') {
          const taskIp = EcsManager.extractTaskIp(task);
          if (taskIp) {
            const poolId = `warm-${randomUUID().replace(/-/g, '').slice(0, 12)}`;
            const sessionApiKey = randomUUID();
            const record: SandboxRecord = {
              conversation_id: poolId,
              user_id: 'warm-pool',
              task_arn: taskArn,
              task_ip: taskIp,
              status: 'WARM',
              session_api_key: sessionApiKey,
              agent_server_port: 8000,
              sandbox_spec_id: sandboxImage,
              last_activity_at: 0,
              created_at: 0,
            };
            await store.putSandbox(record);
            log('info', `Registered warm task: ${poolId}, ip=${taskIp}`);
          }
        }
      }
    } catch (err) {
      log('error', `Warm pool sync error: ${err}`);
    }
  }

  // Initial delay for Service tasks to start, then sync every 15 seconds
  const timer = setInterval(sync, SYNC_INTERVAL_MS);
  setTimeout(sync, SYNC_INTERVAL_MS);
  log('info', `Warm pool sync enabled: service=${warmPoolServiceName}`);
  return timer;
}
