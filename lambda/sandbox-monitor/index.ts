/**
 * Sandbox Idle Monitor Lambda
 *
 * Runs on an EventBridge schedule (every 5 minutes) to detect and stop idle sandbox tasks.
 * Idle sandboxes are those with status=RUNNING and last_activity_at older than IDLE_TIMEOUT_MINUTES.
 *
 * Also detects and stops orphan ECS tasks — sandbox tasks that are running but have no
 * corresponding RUNNING/STARTING record in DynamoDB. These orphans can be caused by race
 * conditions during concurrent resume operations on the same conversation.
 */

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, StopTaskCommand, ListTasksCommand, DescribeTasksCommand } from '@aws-sdk/client-ecs';
import { EFSClient, DeleteAccessPointCommand } from '@aws-sdk/client-efs';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME || 'openhands-sandbox-registry';
const ECS_CLUSTER_ARN = process.env.ECS_CLUSTER_ARN || '';
const IDLE_TIMEOUT_MINUTES = parseInt(process.env.IDLE_TIMEOUT_MINUTES || '30', 10);
const SANDBOX_TASK_FAMILY = process.env.SANDBOX_TASK_FAMILY || 'openhands-sandbox';
const REGION = process.env.AWS_REGION_NAME || process.env.AWS_REGION || 'us-east-1';

/** Time-to-live: 7 days from last activity (matches dynamodb_store.py TTL_SECONDS) */
const TTL_SECONDS = 7 * 24 * 3600;

const logger = new Logger({ serviceName: 'sandbox-idle-monitor' });
const dynamodb = new DynamoDBClient({ region: REGION });
const ecs = new ECSClient({ region: REGION });
const cloudwatch = new CloudWatchClient({ region: REGION });
const efsClient = new EFSClient({ region: REGION });

interface SandboxRecord {
  conversation_id: string;
  user_id: string;
  task_arn: string;
  status: string;
  last_activity_at: number;
  access_point_id?: string;
}

async function queryIdleSandboxes(cutoffTimestamp: number): Promise<SandboxRecord[]> {
  const response = await dynamodb.send(new QueryCommand({
    TableName: REGISTRY_TABLE_NAME,
    IndexName: 'status-index',
    KeyConditionExpression: '#status = :running AND last_activity_at < :cutoff',
    ExpressionAttributeValues: {
      ':running': { S: 'RUNNING' },
      ':cutoff': { N: cutoffTimestamp.toString() },
    },
    ExpressionAttributeNames: {
      '#status': 'status',
    },
  }));

  return (response.Items || []).map(item => ({
    conversation_id: item.conversation_id?.S || '',
    user_id: item.user_id?.S || '',
    task_arn: item.task_arn?.S || '',
    status: item.status?.S || '',
    last_activity_at: parseInt(item.last_activity_at?.N || '0', 10),
    access_point_id: item.access_point_id?.S || undefined,
  }));
}

async function stopTask(taskArn: string, reason: string): Promise<void> {
  try {
    await ecs.send(new StopTaskCommand({
      cluster: ECS_CLUSTER_ARN,
      task: taskArn,
      reason,
    }));
  } catch (error) {
    logger.error('Failed to stop task', { taskArn, error: String(error) });
    throw error;
  }
}

async function updateStatus(conversationId: string, status: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await dynamodb.send(new UpdateItemCommand({
    TableName: REGISTRY_TABLE_NAME,
    Key: {
      conversation_id: { S: conversationId },
    },
    UpdateExpression: 'SET #status = :status, last_activity_at = :now, #ttl = :ttl',
    ExpressionAttributeValues: {
      ':status': { S: status },
      ':now': { N: now.toString() },
      ':ttl': { N: (now + TTL_SECONDS).toString() },
    },
    ExpressionAttributeNames: {
      '#status': 'status',
      '#ttl': 'ttl',
    },
  }));
}

/**
 * Detect and stop orphan ECS sandbox tasks.
 *
 * An orphan task is one that is RUNNING in ECS but has no corresponding
 * RUNNING or STARTING record in DynamoDB. This happens when race conditions
 * during concurrent resume operations cause multiple tasks to start for the
 * same conversation — only one gets tracked in DynamoDB, the rest become orphans.
 *
 * Returns the number of orphan tasks stopped.
 */
async function cleanupOrphanTasks(): Promise<number> {
  // 1. List all running sandbox tasks from ECS
  const runningTaskArns: string[] = [];
  let nextToken: string | undefined;
  do {
    const listResponse = await ecs.send(new ListTasksCommand({
      cluster: ECS_CLUSTER_ARN,
      family: SANDBOX_TASK_FAMILY,
      desiredStatus: 'RUNNING',
      nextToken,
    }));
    if (listResponse.taskArns?.length) {
      runningTaskArns.push(...listResponse.taskArns);
    }
    nextToken = listResponse.nextToken;
  } while (nextToken);

  if (runningTaskArns.length === 0) {
    return 0;
  }

  // 2. Collect all task ARNs tracked in DynamoDB with RUNNING or STARTING status
  const trackedTaskArns = new Set<string>();
  for (const status of ['RUNNING', 'STARTING']) {
    let lastEvaluatedKey: Record<string, any> | undefined;
    do {
      const queryResponse = await dynamodb.send(new QueryCommand({
        TableName: REGISTRY_TABLE_NAME,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :status',
        ExpressionAttributeValues: { ':status': { S: status } },
        ExpressionAttributeNames: { '#status': 'status' },
        ProjectionExpression: 'task_arn',
        ExclusiveStartKey: lastEvaluatedKey,
      }));
      for (const item of queryResponse.Items || []) {
        if (item.task_arn?.S) {
          trackedTaskArns.add(item.task_arn.S);
        }
      }
      lastEvaluatedKey = queryResponse.LastEvaluatedKey;
    } while (lastEvaluatedKey);
  }

  // 3. Find candidate orphans: running in ECS but not tracked in DynamoDB
  const candidateOrphanArns = runningTaskArns.filter(arn => !trackedTaskArns.has(arn));

  if (candidateOrphanArns.length === 0) {
    return 0;
  }

  // 4. Apply grace period: skip tasks started less than 5 minutes ago.
  //    There is a brief window between ECS RunTask and the orchestrator writing the
  //    DynamoDB record. Newly-launched tasks could falsely appear as orphans.
  const GRACE_PERIOD_MS = 5 * 60 * 1000;
  const graceCutoff = Date.now() - GRACE_PERIOD_MS;

  // Describe candidate tasks to get their start time (batch in groups of 100 — API limit)
  const DESCRIBE_BATCH_SIZE = 100;
  const allDescribedTasks: Array<{ taskArn?: string; startedAt?: Date; createdAt?: Date }> = [];
  for (let i = 0; i < candidateOrphanArns.length; i += DESCRIBE_BATCH_SIZE) {
    const batch = candidateOrphanArns.slice(i, i + DESCRIBE_BATCH_SIZE);
    const describeResponse = await ecs.send(new DescribeTasksCommand({
      cluster: ECS_CLUSTER_ARN,
      tasks: batch,
    }));
    if (describeResponse.tasks) {
      allDescribedTasks.push(...describeResponse.tasks);
    }
  }

  const orphanTasks = allDescribedTasks.filter(task => {
    const startedAt = task.startedAt ?? task.createdAt;
    if (!startedAt) return true; // If no timestamp, treat as orphan
    return startedAt.getTime() < graceCutoff;
  });

  if (orphanTasks.length === 0) {
    logger.debug('All candidate orphans are within grace period', {
      candidates: candidateOrphanArns.length,
    });
    return 0;
  }

  logger.warn('Orphan sandbox tasks detected', {
    orphanCount: orphanTasks.length,
    trackedCount: trackedTaskArns.size,
    totalRunning: runningTaskArns.length,
  });

  // 5. Stop each orphan task
  let stoppedCount = 0;
  for (const task of orphanTasks) {
    const taskArn = task.taskArn!;
    try {
      logger.info('Stopping orphan sandbox task', { taskArn });
      await ecs.send(new StopTaskCommand({
        cluster: ECS_CLUSTER_ARN,
        task: taskArn,
        reason: 'Orphan task: no DynamoDB record tracking this task',
      }));
      stoppedCount++;
    } catch (error) {
      logger.error('Failed to stop orphan task', { taskArn, error: String(error) });
    }
  }

  return stoppedCount;
}

async function publishMetrics(stoppedCount: number, runningCount: number, orphansStopped: number): Promise<void> {
  await cloudwatch.send(new PutMetricDataCommand({
    Namespace: 'OpenHands/Sandbox',
    MetricData: [
      {
        MetricName: 'IdleSandboxesStopped',
        Value: stoppedCount,
        Unit: 'Count',
        Timestamp: new Date(),
      },
      {
        MetricName: 'RunningSandboxes',
        Value: runningCount,
        Unit: 'Count',
        Timestamp: new Date(),
      },
      {
        MetricName: 'OrphanSandboxesStopped',
        Value: orphansStopped,
        Unit: 'Count',
        Timestamp: new Date(),
      },
    ],
  }));
}

export async function handler(): Promise<{ statusCode: number; body: string }> {
  const now = Math.floor(Date.now() / 1000);
  const cutoff = now - (IDLE_TIMEOUT_MINUTES * 60);

  logger.info('Checking for idle sandboxes', { idleTimeoutMinutes: IDLE_TIMEOUT_MINUTES, cutoff });

  const idleSandboxes = await queryIdleSandboxes(cutoff);
  logger.info('Idle sandboxes found', { count: idleSandboxes.length });

  let stoppedCount = 0;
  const errors: string[] = [];

  for (const sandbox of idleSandboxes) {
    const idleMinutes = Math.round((now - sandbox.last_activity_at) / 60);
    logger.info('Stopping idle sandbox', {
      conversationId: sandbox.conversation_id,
      userId: sandbox.user_id,
      idleMinutes,
      taskArn: sandbox.task_arn,
    });

    try {
      if (sandbox.task_arn) {
        await stopTask(sandbox.task_arn, `Idle timeout (${idleMinutes} minutes)`);
      }
      // Clean up per-conversation EFS access point
      if (sandbox.access_point_id) {
        try {
          await efsClient.send(new DeleteAccessPointCommand({ AccessPointId: sandbox.access_point_id }));
          logger.info('Deleted access point', { accessPointId: sandbox.access_point_id });
        } catch (apErr: any) {
          if (apErr.name !== 'AccessPointNotFound') {
            logger.warn('Failed to delete access point', { accessPointId: sandbox.access_point_id, error: String(apErr) });
          }
        }
      }
      await updateStatus(sandbox.conversation_id, 'PAUSED');
      stoppedCount++;
    } catch (error) {
      const msg = `Failed to stop sandbox ${sandbox.conversation_id}: ${error}`;
      logger.error(msg);
      errors.push(msg);
    }
  }

  let runningCount = 0;
  try {
    const runningResponse = await dynamodb.send(new QueryCommand({
      TableName: REGISTRY_TABLE_NAME,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :running',
      ExpressionAttributeValues: {
        ':running': { S: 'RUNNING' },
      },
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      Select: 'COUNT',
    }));
    runningCount = runningResponse.Count || 0;
  } catch (error) {
    logger.error('Failed to count running sandboxes', { error: String(error) });
  }

  // Orphan task cleanup: stop ECS tasks not tracked in DynamoDB
  let orphansStopped = 0;
  try {
    orphansStopped = await cleanupOrphanTasks();
    if (orphansStopped > 0) {
      logger.warn('Orphan tasks cleaned up', { orphansStopped });
    }
  } catch (error) {
    logger.error('Orphan cleanup failed', { error: String(error) });
  }

  await publishMetrics(stoppedCount, runningCount, orphansStopped);

  const summary = {
    idle_found: idleSandboxes.length,
    stopped: stoppedCount,
    orphans_stopped: orphansStopped,
    running_total: runningCount,
    errors: errors.length,
  };
  logger.info('Idle monitor complete', summary);

  return {
    statusCode: 200,
    body: JSON.stringify(summary),
  };
}
