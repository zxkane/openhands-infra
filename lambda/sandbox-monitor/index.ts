/**
 * Sandbox Idle Monitor Lambda
 *
 * Runs on an EventBridge schedule (every 5 minutes) to detect and stop idle sandbox tasks.
 * Idle sandboxes are those with status=RUNNING and last_activity_at older than IDLE_TIMEOUT_MINUTES.
 */

import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, StopTaskCommand } from '@aws-sdk/client-ecs';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME || 'openhands-sandbox-registry';
const ECS_CLUSTER_ARN = process.env.ECS_CLUSTER_ARN || '';
const IDLE_TIMEOUT_MINUTES = parseInt(process.env.IDLE_TIMEOUT_MINUTES || '30', 10);
const REGION = process.env.AWS_REGION_NAME || process.env.AWS_REGION || 'us-east-1';

/** Time-to-live: 7 days from last activity (matches dynamodb_store.py TTL_SECONDS) */
const TTL_SECONDS = 7 * 24 * 3600;

const dynamodb = new DynamoDBClient({ region: REGION });
const ecs = new ECSClient({ region: REGION });
const cloudwatch = new CloudWatchClient({ region: REGION });

interface SandboxRecord {
  conversation_id: string;
  user_id: string;
  task_arn: string;
  status: string;
  last_activity_at: number;
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
    console.error(`Failed to stop task ${taskArn}:`, error);
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

  console.log(`Checking for idle sandboxes (idle > ${IDLE_TIMEOUT_MINUTES} min, cutoff=${cutoff})`);

  // Query idle sandboxes
  const idleSandboxes = await queryIdleSandboxes(cutoff);
  console.log(`Found ${idleSandboxes.length} idle sandbox(es)`);

  let stoppedCount = 0;
  const errors: string[] = [];

  // Stop each idle sandbox
  for (const sandbox of idleSandboxes) {
    const idleMinutes = Math.round((now - sandbox.last_activity_at) / 60);
    console.log(
      `Stopping idle sandbox: conversation=${sandbox.conversation_id}, ` +
      `user=${sandbox.user_id}, idle=${idleMinutes}min, task=${sandbox.task_arn}`
    );

    try {
      if (sandbox.task_arn) {
        await stopTask(sandbox.task_arn, `Idle timeout (${idleMinutes} minutes)`);
      }
      await updateStatus(sandbox.conversation_id, 'PAUSED');
      stoppedCount++;
    } catch (error) {
      const msg = `Failed to stop sandbox ${sandbox.conversation_id}: ${error}`;
      console.error(msg);
      errors.push(msg);
    }
  }

  // Query total running for metrics
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
    console.error('Failed to count running sandboxes:', error);
  }

  // Publish CloudWatch metrics
  await publishMetrics(stoppedCount, runningCount);

  const summary = {
    idle_found: idleSandboxes.length,
    stopped: stoppedCount,
    running_total: runningCount,
    errors: errors.length,
  };
  console.log('Idle monitor complete:', JSON.stringify(summary));

  return {
    statusCode: 200,
    body: JSON.stringify(summary),
  };
}
