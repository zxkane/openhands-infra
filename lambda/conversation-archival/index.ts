/**
 * Conversation Archival Lambda
 *
 * Runs daily on EventBridge schedule to archive inactive conversations.
 * Conversations in STOPPED or PAUSED state beyond the retention period
 * are transitioned to ARCHIVED: EFS workspace is cleaned up, DynamoDB TTL
 * is removed (so ARCHIVED records persist indefinitely for S3 history lookup).
 *
 * S3 conversation history is intentionally preserved — users can still view
 * past conversation events in the UI for ARCHIVED conversations.
 */

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import * as fs from 'node:fs';
import * as path from 'node:path';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME || '';
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || '180', 10);
const EFS_MOUNT_PATH = process.env.EFS_MOUNT_PATH || '/mnt/efs';
const REGION = process.env.AWS_REGION_NAME || process.env.AWS_REGION || 'us-east-1';

const logger = new Logger({ serviceName: 'conversation-archival' });
const dynamodb = new DynamoDBClient({ region: REGION });
const cloudwatch = new CloudWatchClient({ region: REGION });

interface ArchivableRecord {
  conversation_id: string;
  user_id: string;
  status: string;
  last_activity_at: number;
}

async function queryInactiveByStatus(
  status: string,
  cutoffTimestamp: number,
): Promise<ArchivableRecord[]> {
  const records: ArchivableRecord[] = [];
  let lastEvaluatedKey: Record<string, any> | undefined;

  do {
    const response = await dynamodb.send(new QueryCommand({
      TableName: REGISTRY_TABLE_NAME,
      IndexName: 'status-index',
      KeyConditionExpression: '#status = :status AND last_activity_at < :cutoff',
      ExpressionAttributeValues: {
        ':status': { S: status },
        ':cutoff': { N: cutoffTimestamp.toString() },
      },
      ExpressionAttributeNames: {
        '#status': 'status',
      },
      ExclusiveStartKey: lastEvaluatedKey,
    }));

    for (const item of response.Items || []) {
      records.push({
        conversation_id: item.conversation_id?.S || '',
        user_id: item.user_id?.S || '',
        status: item.status?.S || '',
        last_activity_at: parseInt(item.last_activity_at?.N || '0', 10),
      });
    }
    lastEvaluatedKey = response.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return records;
}

async function archiveRecord(conversationId: string): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await dynamodb.send(new UpdateItemCommand({
    TableName: REGISTRY_TABLE_NAME,
    Key: { conversation_id: { S: conversationId } },
    UpdateExpression: 'SET #status = :archived, last_activity_at = :now REMOVE #ttl',
    ExpressionAttributeValues: {
      ':archived': { S: 'ARCHIVED' },
      ':now': { N: now.toString() },
    },
    ExpressionAttributeNames: {
      '#status': 'status',
      '#ttl': 'ttl',
    },
  }));
}

function deleteEfsWorkspace(conversationId: string): void {
  const workspacePath = path.join(EFS_MOUNT_PATH, conversationId);
  try {
    fs.rmSync(workspacePath, { recursive: true, force: true });
    logger.info('Deleted EFS workspace', { conversationId, path: workspacePath });
  } catch (err: any) {
    if (err.code !== 'ENOENT') {
      logger.warn('Failed to delete EFS workspace', {
        conversationId,
        error: String(err),
      });
    }
  }
}

async function publishMetrics(archivedCount: number): Promise<void> {
  await cloudwatch.send(new PutMetricDataCommand({
    Namespace: 'OpenHands/Sandbox',
    MetricData: [
      {
        MetricName: 'ConversationsArchived',
        Value: archivedCount,
        Unit: 'Count',
        Timestamp: new Date(),
      },
    ],
  }));
}

export async function handler(): Promise<{ statusCode: number; body: string }> {
  const now = Math.floor(Date.now() / 1000);
  const cutoff = now - (RETENTION_DAYS * 86400);

  logger.info('Starting conversation archival', { retentionDays: RETENTION_DAYS, cutoff });

  // Query both STOPPED and PAUSED records beyond retention
  const [stoppedRecords, pausedRecords] = await Promise.all([
    queryInactiveByStatus('STOPPED', cutoff),
    queryInactiveByStatus('PAUSED', cutoff),
  ]);

  const allRecords = [...stoppedRecords, ...pausedRecords];
  logger.info('Inactive conversations found', {
    stopped: stoppedRecords.length,
    paused: pausedRecords.length,
    total: allRecords.length,
  });

  let archivedCount = 0;
  const errors: string[] = [];

  for (const record of allRecords) {
    const inactiveDays = Math.round((now - record.last_activity_at) / 86400);
    logger.info('Archiving conversation', {
      conversationId: record.conversation_id,
      userId: record.user_id,
      previousStatus: record.status,
      inactiveDays,
    });

    try {
      // Update DynamoDB first to prevent resume attempts during EFS cleanup
      await archiveRecord(record.conversation_id);

      // Delete EFS workspace (S3 history preserved intentionally)
      deleteEfsWorkspace(record.conversation_id);
      archivedCount++;
    } catch (err) {
      const msg = `Failed to archive ${record.conversation_id}: ${err}`;
      logger.error(msg);
      errors.push(msg);
    }
  }

  await publishMetrics(archivedCount);

  const summary = {
    candidates: allRecords.length,
    archived: archivedCount,
    errors: errors.length,
  };
  logger.info('Archival complete', summary);

  return {
    statusCode: 200,
    body: JSON.stringify(summary),
  };
}
