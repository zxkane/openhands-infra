/**
 * Sandbox Idle Monitor Lambda
 *
 * Runs on an EventBridge schedule (every 5 minutes) to detect and stop idle sandbox tasks.
 * Idle sandboxes are those with status=RUNNING and last_activity_at older than IDLE_TIMEOUT_MINUTES.
 */

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, StopTaskCommand } from '@aws-sdk/client-ecs';
import { EFSClient, DeleteAccessPointCommand } from '@aws-sdk/client-efs';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME || 'openhands-sandbox-registry';
const ECS_CLUSTER_ARN = process.env.ECS_CLUSTER_ARN || '';
const IDLE_TIMEOUT_MINUTES = parseInt(process.env.IDLE_TIMEOUT_MINUTES || '30', 10);
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

async function publishMetrics(stoppedCount: number, runningCount: number): Promise<void> {
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

  await publishMetrics(stoppedCount, runningCount);

  const summary = {
    idle_found: idleSandboxes.length,
    stopped: stoppedCount,
    running_total: runningCount,
    errors: errors.length,
  };
  logger.info('Idle monitor complete', summary);

  return {
    statusCode: 200,
    body: JSON.stringify(summary),
  };
}
