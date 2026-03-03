/**
 * Conversation Deletion Lambda
 *
 * Invoked asynchronously by the orchestrator to fully delete conversation data
 * across all storage layers: S3, EFS, Aurora PostgreSQL, and DynamoDB.
 *
 * This is a destructive, irreversible operation — all conversation history,
 * workspace files, and metadata are permanently removed.
 */

import { Logger } from '@aws-lambda-powertools/logger';
import { DynamoDBClient, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import {
  S3Client,
  ListObjectsV2Command,
  DeleteObjectsCommand,
  type ObjectIdentifier,
  type _Object,
} from '@aws-sdk/client-s3';
import { RDSDataClient, ExecuteStatementCommand } from '@aws-sdk/client-rds-data';
import * as fs from 'node:fs';
import * as path from 'node:path';

const REGISTRY_TABLE_NAME = process.env.REGISTRY_TABLE_NAME;
if (!REGISTRY_TABLE_NAME) {
  throw new Error('REGISTRY_TABLE_NAME environment variable is required');
}
const DATA_BUCKET = process.env.DATA_BUCKET || '';
const EFS_MOUNT_PATH = process.env.EFS_MOUNT_PATH || '/mnt/efs';
const DB_SECRET_NAME = process.env.DB_SECRET_NAME || '';
const DB_NAME = process.env.DB_NAME || 'openhands';
const REGION = process.env.AWS_REGION_NAME || process.env.AWS_REGION || 'us-east-1';

const logger = new Logger({ serviceName: 'conversation-delete' });
const dynamodb = new DynamoDBClient({ region: REGION });
const s3 = new S3Client({ region: REGION });
const rdsData = new RDSDataClient({ region: REGION });

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
const secretsManager = new SecretsManagerClient({ region: REGION });

/** Cache for resolved database connection info from Secrets Manager */
let dbInfoCache: { clusterArn: string; secretArn: string } | null = null;

async function resolveDbInfo(): Promise<{ clusterArn: string; secretArn: string } | null> {
  if (dbInfoCache) return dbInfoCache;
  if (!DB_SECRET_NAME) return null;

  try {
    const response = await secretsManager.send(new GetSecretValueCommand({ SecretId: DB_SECRET_NAME }));
    const secret = JSON.parse(response.SecretString || '{}');
    // Aurora-generated secrets include dbClusterIdentifier and the full ARN
    const clusterIdentifier = secret.dbClusterIdentifier;
    if (!clusterIdentifier || !response.ARN) {
      logger.warn('Secret missing dbClusterIdentifier or ARN', { secretName: DB_SECRET_NAME });
      return null;
    }
    const clusterArn = `arn:aws:rds:${REGION}:${response.ARN.split(':')[4]}:cluster:${clusterIdentifier}`;
    dbInfoCache = { clusterArn, secretArn: response.ARN };
    return dbInfoCache;
  } catch (err) {
    logger.warn('Failed to resolve database info from secret', { error: String(err) });
    return null;
  }
}

interface DeleteEvent {
  conversation_id: string;
  user_id: string;
}

/**
 * Delete all S3 objects under the conversation prefix.
 * Paginates through ListObjectsV2 and batch-deletes up to 1000 objects per call.
 */
async function deleteS3Objects(conversationId: string): Promise<number> {
  if (!DATA_BUCKET) {
    logger.info('DATA_BUCKET not configured, skipping S3 cleanup');
    return 0;
  }

  const prefix = `conversations/${conversationId}/`;
  let deletedCount = 0;
  let continuationToken: string | undefined;

  do {
    const listResponse = await s3.send(new ListObjectsV2Command({
      Bucket: DATA_BUCKET,
      Prefix: prefix,
      MaxKeys: 1000,
      ContinuationToken: continuationToken,
    }));

    const objects: ObjectIdentifier[] = (listResponse.Contents || [])
      .filter((obj: _Object) => obj.Key)
      .map((obj: _Object) => ({ Key: obj.Key! }));

    if (objects.length > 0) {
      await s3.send(new DeleteObjectsCommand({
        Bucket: DATA_BUCKET,
        Delete: { Objects: objects, Quiet: true },
      }));
      deletedCount += objects.length;
      logger.info('Deleted S3 objects batch', { count: objects.length, total: deletedCount });
    }

    continuationToken = listResponse.NextContinuationToken;
  } while (continuationToken);

  logger.info('S3 cleanup complete', { conversationId, deletedCount });
  return deletedCount;
}

/**
 * Delete the EFS workspace directory for this conversation.
 */
function deleteEfsWorkspace(conversationId: string): void {
  if (!conversationId || conversationId.includes('..') || conversationId.includes('/')) {
    logger.error('Invalid conversationId for EFS deletion', { conversationId });
    return;
  }
  const workspacePath = path.join(EFS_MOUNT_PATH, conversationId);
  // Verify resolved path stays within EFS mount to block path traversal
  const normalized = path.resolve(workspacePath);
  if (!normalized.startsWith(path.resolve(EFS_MOUNT_PATH) + path.sep)) {
    logger.error('Path traversal blocked', { conversationId, workspacePath });
    return;
  }
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

/**
 * Delete the conversation row from Aurora PostgreSQL via RDS Data API.
 */
async function deleteAuroraRecord(conversationId: string): Promise<void> {
  const dbInfo = await resolveDbInfo();
  if (!dbInfo) {
    logger.info('Database config not available, skipping Aurora cleanup');
    return;
  }

  try {
    await rdsData.send(new ExecuteStatementCommand({
      resourceArn: dbInfo.clusterArn,
      secretArn: dbInfo.secretArn,
      database: DB_NAME,
      sql: 'DELETE FROM conversations WHERE id = :id',
      parameters: [
        { name: 'id', value: { stringValue: conversationId } },
      ],
    }));
    logger.info('Deleted Aurora record', { conversationId });
  } catch (err) {
    logger.warn('Failed to delete Aurora record', {
      conversationId,
      error: String(err),
    });
  }
}

/**
 * Delete the DynamoDB record (fallback — orchestrator usually deletes first).
 */
async function deleteDynamoRecord(conversationId: string): Promise<void> {
  try {
    await dynamodb.send(new DeleteItemCommand({
      TableName: REGISTRY_TABLE_NAME,
      Key: { conversation_id: { S: conversationId } },
    }));
    logger.info('Deleted DynamoDB record', { conversationId });
  } catch (err) {
    logger.warn('Failed to delete DynamoDB record', {
      conversationId,
      error: String(err),
    });
  }
}

export async function handler(event: DeleteEvent): Promise<{ statusCode: number; body: string }> {
  if (!event?.conversation_id || !event?.user_id) {
    logger.error('Invalid event payload', { event });
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Missing required fields: conversation_id, user_id' }),
    };
  }

  const { conversation_id, user_id } = event;

  logger.info('Starting conversation deletion', { conversation_id, user_id });

  // Execute all cleanup steps — continue even if individual steps fail
  const [s3Count] = await Promise.all([
    deleteS3Objects(conversation_id),
  ]);

  deleteEfsWorkspace(conversation_id);
  await deleteAuroraRecord(conversation_id);
  await deleteDynamoRecord(conversation_id);

  logger.info('Conversation deletion complete', {
    conversation_id,
    s3_objects_deleted: s3Count,
  });

  return {
    statusCode: 200,
    body: JSON.stringify({
      deleted: true,
      conversation_id,
      s3_objects_deleted: s3Count,
    }),
  };
}
