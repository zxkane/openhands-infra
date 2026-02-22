/** DynamoDB-backed sandbox registry for conversation -> ECS task mapping. */

import {
  DynamoDBClient,
  BatchGetItemCommand,
  type AttributeValue,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  UpdateCommand,
  QueryCommand,
} from '@aws-sdk/lib-dynamodb';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { Agent } from 'node:http';
import type { SandboxRecord, SandboxStatus } from './types.js';

/** Time-to-live: 7 days from last activity. */
const TTL_SECONDS = 7 * 24 * 3600;

export class DynamoDBStore {
  private readonly tableName: string;
  private readonly docClient: DynamoDBDocumentClient;
  private readonly rawClient: DynamoDBClient;

  constructor(tableName: string, region?: string) {
    this.tableName = tableName;
    // Persistent HTTP connections for lower latency
    this.rawClient = new DynamoDBClient({
      region,
      requestHandler: new NodeHttpHandler({
        httpAgent: new Agent({ keepAlive: true, maxSockets: 50 }),
      }),
    });
    this.docClient = DynamoDBDocumentClient.from(this.rawClient, {
      marshallOptions: { removeUndefinedValues: true },
    });
  }

  async putSandbox(record: SandboxRecord): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const item = {
      ...record,
      created_at: record.created_at || now,
      last_activity_at: now,
      ttl: now + TTL_SECONDS,
    };
    await this.docClient.send(
      new PutCommand({ TableName: this.tableName, Item: item }),
    );
  }

  async getSandbox(conversationId: string): Promise<SandboxRecord | null> {
    const result = await this.docClient.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { conversation_id: conversationId },
      }),
    );
    return (result.Item as SandboxRecord) ?? null;
  }

  async batchGetSandboxes(conversationIds: string[]): Promise<SandboxRecord[]> {
    if (!conversationIds.length) return [];

    const records: SandboxRecord[] = [];
    // DynamoDB batch_get_item limit is 100 keys
    for (let i = 0; i < conversationIds.length; i += 100) {
      const batch = conversationIds.slice(i, i + 100);
      let requestItems: Record<string, { Keys: Record<string, { S: string }>[] }> | undefined = {
        [this.tableName]: {
          Keys: batch.map((cid) => ({ conversation_id: { S: cid } })),
        },
      };

      while (requestItems && Object.keys(requestItems).length > 0) {
        const result = await this.rawClient.send(
          new BatchGetItemCommand({ RequestItems: requestItems }),
        );
        const items = result.Responses?.[this.tableName] ?? [];
        for (const item of items) {
          records.push(this.unmarshallRecord(item));
        }
        requestItems = result.UnprocessedKeys as typeof requestItems;
      }
    }
    return records;
  }

  /** Atomically claim a WARM record — returns true if this caller won the race. */
  async claimWarmTask(conversationId: string): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { conversation_id: conversationId },
          UpdateExpression: 'SET #status = :claimed, last_activity_at = :now, #ttl = :ttl',
          ConditionExpression: '#status = :warm',
          ExpressionAttributeValues: {
            ':claimed': 'CLAIMED',
            ':warm': 'WARM',
            ':now': now,
            ':ttl': now + TTL_SECONDS,
          },
          ExpressionAttributeNames: { '#status': 'status', '#ttl': 'ttl' },
        }),
      );
      return true;
    } catch (err: any) {
      if (err.name === 'ConditionalCheckFailedException') return false;
      throw err;
    }
  }

  async updateStatus(
    conversationId: string,
    status: SandboxStatus,
    taskIp?: string,
    taskArn?: string,
  ): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    let updateExpr = 'SET #status = :status, last_activity_at = :now, #ttl = :ttl';
    const exprValues: Record<string, unknown> = {
      ':status': status,
      ':now': now,
      ':ttl': now + TTL_SECONDS,
    };
    const exprNames: Record<string, string> = {
      '#status': 'status',
      '#ttl': 'ttl',
    };

    if (taskIp !== undefined) {
      updateExpr += ', task_ip = :ip';
      exprValues[':ip'] = taskIp;
    }
    if (taskArn !== undefined) {
      updateExpr += ', task_arn = :arn';
      exprValues[':arn'] = taskArn;
    }

    await this.docClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { conversation_id: conversationId },
        UpdateExpression: updateExpr,
        ExpressionAttributeValues: exprValues,
        ExpressionAttributeNames: exprNames,
      }),
    );
  }

  async updateActivity(conversationId: string): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    await this.docClient.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { conversation_id: conversationId },
        UpdateExpression: 'SET last_activity_at = :now, #ttl = :ttl',
        ExpressionAttributeValues: {
          ':now': now,
          ':ttl': now + TTL_SECONDS,
        },
        ExpressionAttributeNames: { '#ttl': 'ttl' },
      }),
    );
  }

  async queryByStatus(status: SandboxStatus): Promise<SandboxRecord[]> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        IndexName: 'status-index',
        KeyConditionExpression: '#status = :s',
        ExpressionAttributeValues: { ':s': status },
        ExpressionAttributeNames: { '#status': 'status' },
      }),
    );
    return (result.Items as SandboxRecord[]) ?? [];
  }

  async listRunning(): Promise<SandboxRecord[]> {
    return this.queryByStatus('RUNNING');
  }

  /** Unmarshall a raw DynamoDB attribute-map into a SandboxRecord. */
  private unmarshallRecord(item: Record<string, AttributeValue>): SandboxRecord {
    return {
      conversation_id: item.conversation_id?.S ?? '',
      user_id: item.user_id?.S ?? '',
      task_arn: item.task_arn?.S ?? '',
      task_ip: item.task_ip?.S ?? '',
      status: (item.status?.S ?? '') as SandboxStatus,
      session_api_key: item.session_api_key?.S ?? '',
      agent_server_port: parseInt(item.agent_server_port?.N ?? '8000', 10),
      sandbox_spec_id: item.sandbox_spec_id?.S ?? '',
      last_activity_at: parseInt(item.last_activity_at?.N ?? '0', 10),
      created_at: parseInt(item.created_at?.N ?? '0', 10),
    };
  }
}
