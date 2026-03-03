/**
 * Sandbox Task State Change Handler
 *
 * Triggered by EventBridge when an ECS task changes state (RUNNING → STOPPED).
 * Updates the DynamoDB sandbox registry to reflect the actual task state.
 *
 * This prevents stale RUNNING records in DynamoDB that cause the upstream
 * OpenHands app to attempt connections to dead task IPs (5s timeout each).
 *
 * Event pattern: ECS Task State Change where lastStatus=STOPPED and
 * clusterArn matches the sandbox cluster.
 */

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EFSClient, DeleteAccessPointCommand } from '@aws-sdk/client-efs';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME || '';
const REGION = process.env.AWS_REGION_NAME || process.env.AWS_REGION || 'us-east-1';

/** Configurable via CONVERSATION_RETENTION_SECONDS env var (default: 183 days = 180 retention + 3 day buffer) */
const TTL_SECONDS = parseInt(process.env.CONVERSATION_RETENTION_SECONDS || '15811200', 10);

const logger = new Logger({ serviceName: 'sandbox-task-state' });
const dynamodb = new DynamoDBClient({ region: REGION });
const efsClient = new EFSClient({ region: REGION });

/** ECS Task State Change event detail from EventBridge. */
interface EcsTaskStateChangeDetail {
  taskArn: string;
  clusterArn: string;
  lastStatus: string;
  desiredStatus: string;
  stoppedReason?: string;
  group?: string;
}

interface EventBridgeEvent {
  'detail-type': string;
  source: string;
  detail: EcsTaskStateChangeDetail;
}

/**
 * Find DynamoDB records that reference this task ARN.
 * Uses a scan with filter since we don't have a GSI on task_arn.
 * This is acceptable because it's triggered infrequently (only on task stop).
 */
async function findRecordsByTaskArn(taskArn: string): Promise<Array<{ conversation_id: string; status: string; access_point_id?: string }>> {
  // Query RUNNING records and filter by task_arn
  const response = await dynamodb.send(new QueryCommand({
    TableName: REGISTRY_TABLE_NAME,
    IndexName: 'status-index',
    KeyConditionExpression: '#status = :running',
    FilterExpression: 'task_arn = :arn',
    ExpressionAttributeValues: {
      ':running': { S: 'RUNNING' },
      ':arn': { S: taskArn },
    },
    ExpressionAttributeNames: { '#status': 'status' },
  }));

  const records = (response.Items || []).map(item => ({
    conversation_id: item.conversation_id?.S || '',
    status: item.status?.S || '',
    access_point_id: item.access_point_id?.S || undefined,
  }));

  // Also check STARTING status
  const startingResponse = await dynamodb.send(new QueryCommand({
    TableName: REGISTRY_TABLE_NAME,
    IndexName: 'status-index',
    KeyConditionExpression: '#status = :starting',
    FilterExpression: 'task_arn = :arn',
    ExpressionAttributeValues: {
      ':starting': { S: 'STARTING' },
      ':arn': { S: taskArn },
    },
    ExpressionAttributeNames: { '#status': 'status' },
  }));

  for (const item of startingResponse.Items || []) {
    records.push({
      conversation_id: item.conversation_id?.S || '',
      status: item.status?.S || '',
      access_point_id: item.access_point_id?.S || undefined,
    });
  }

  return records;
}

async function updateStatus(conversationId: string, status: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await dynamodb.send(new UpdateItemCommand({
    TableName: REGISTRY_TABLE_NAME,
    Key: { conversation_id: { S: conversationId } },
    UpdateExpression: 'SET #status = :status, last_activity_at = :now, #ttl = :ttl',
    ExpressionAttributeValues: {
      ':status': { S: status },
      ':now': { N: now.toString() },
      ':ttl': { N: (now + TTL_SECONDS).toString() },
    },
    ExpressionAttributeNames: { '#status': 'status', '#ttl': 'ttl' },
  }));
}

export async function handler(event: EventBridgeEvent): Promise<void> {
  const { taskArn, lastStatus, stoppedReason, group } = event.detail;

  logger.info('ECS task state change', { taskArn, lastStatus, stoppedReason, group });

  if (lastStatus !== 'STOPPED') {
    logger.debug('Ignoring non-STOPPED state change', { lastStatus });
    return;
  }

  // Skip warm pool service tasks — they don't have per-conversation records
  if (group?.includes('sandbox-warm-pool')) {
    logger.debug('Skipping warm pool task', { group });
    return;
  }

  // Find DynamoDB records referencing this task and mark as STOPPED
  const records = await findRecordsByTaskArn(taskArn);

  if (!records.length) {
    logger.debug('No DynamoDB records found for task', { taskArn });
    return;
  }

  for (const record of records) {
    logger.info('Marking sandbox as STOPPED', {
      conversationId: record.conversation_id,
      previousStatus: record.status,
      stoppedReason,
    });
    await updateStatus(record.conversation_id, 'STOPPED');

    // Clean up per-conversation EFS access point
    if (record.access_point_id) {
      try {
        await efsClient.send(new DeleteAccessPointCommand({ AccessPointId: record.access_point_id }));
        logger.info('Deleted access point', { accessPointId: record.access_point_id });
      } catch (apErr: any) {
        if (apErr.name !== 'AccessPointNotFound') {
          logger.warn('Failed to delete access point', { accessPointId: record.access_point_id, error: String(apErr) });
        }
      }
    }
  }

  logger.info('Task state change processed', {
    taskArn,
    recordsUpdated: records.length,
  });
}
