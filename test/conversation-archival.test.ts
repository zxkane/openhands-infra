import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { mockClient } from 'aws-sdk-client-mock';

// Mock node:fs before importing handler
jest.mock('node:fs', () => ({
  rmSync: jest.fn(),
}));
import * as fs from 'node:fs';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.RETENTION_DAYS = '180';
process.env.EFS_MOUNT_PATH = '/tmp/test-efs';
process.env.AWS_REGION_NAME = 'us-west-2';

const ddbMock = mockClient(DynamoDBClient);
const cwMock = mockClient(CloudWatchClient);

// Import handler after mocks are set up
import { handler } from '../lambda/conversation-archival/index.js';

describe('Conversation Archival Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    cwMock.reset();
    (fs.rmSync as jest.Mock).mockReset();
  });

  test('returns summary when no inactive conversations found', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [] });
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.candidates).toBe(0);
    expect(body.archived).toBe(0);
    expect(body.errors).toBe(0);
  });

  test('archives STOPPED records older than retention period', async () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTimestamp = now - (200 * 86400); // 200 days ago

    ddbMock.on(QueryCommand)
      .resolvesOnce({
        Items: [{
          conversation_id: { S: 'conv-stopped-1' },
          user_id: { S: 'user-1' },
          status: { S: 'STOPPED' },
          last_activity_at: { N: oldTimestamp.toString() },
        }],
      })
      .resolvesOnce({ Items: [] });

    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.candidates).toBe(1);
    expect(body.archived).toBe(1);

    // Verify EFS cleanup was called
    expect(fs.rmSync).toHaveBeenCalledWith(
      expect.stringContaining('conv-stopped-1'),
      expect.objectContaining({ recursive: true, force: true }),
    );
  });

  test('archives PAUSED records older than retention period', async () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTimestamp = now - (200 * 86400);

    ddbMock.on(QueryCommand)
      .resolvesOnce({ Items: [] })
      .resolvesOnce({
        Items: [{
          conversation_id: { S: 'conv-paused-1' },
          user_id: { S: 'user-2' },
          status: { S: 'PAUSED' },
          last_activity_at: { N: oldTimestamp.toString() },
        }],
      });

    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.candidates).toBe(1);
    expect(body.archived).toBe(1);
  });

  test('handles EFS deletion errors gracefully', async () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTimestamp = now - (200 * 86400);

    ddbMock.on(QueryCommand)
      .resolvesOnce({
        Items: [{
          conversation_id: { S: 'conv-efs-error' },
          user_id: { S: 'user-3' },
          status: { S: 'STOPPED' },
          last_activity_at: { N: oldTimestamp.toString() },
        }],
      })
      .resolvesOnce({ Items: [] });

    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    // Simulate EFS permission error
    (fs.rmSync as jest.Mock).mockImplementation(() => {
      const err = new Error('Permission denied') as NodeJS.ErrnoException;
      err.code = 'EPERM';
      throw err;
    });

    // Should still succeed — EFS errors are logged but don't block archival
    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.candidates).toBe(1);
    expect(body.archived).toBe(1);
  });

  test('publishes CloudWatch metrics', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [] });
    cwMock.on(PutMetricDataCommand).resolves({});

    await handler();

    const cwCalls = cwMock.commandCalls(PutMetricDataCommand);
    expect(cwCalls.length).toBe(1);
    expect(cwCalls[0].args[0].input.Namespace).toBe('OpenHands/Sandbox');
    expect(cwCalls[0].args[0].input.MetricData?.[0]?.MetricName).toBe('ConversationsArchived');
  });

  test('DynamoDB update removes TTL for ARCHIVED records', async () => {
    const now = Math.floor(Date.now() / 1000);
    const oldTimestamp = now - (200 * 86400);

    ddbMock.on(QueryCommand)
      .resolvesOnce({
        Items: [{
          conversation_id: { S: 'conv-ttl-check' },
          user_id: { S: 'user-4' },
          status: { S: 'STOPPED' },
          last_activity_at: { N: oldTimestamp.toString() },
        }],
      })
      .resolvesOnce({ Items: [] });

    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    await handler();

    const updateCalls = ddbMock.commandCalls(UpdateItemCommand);
    expect(updateCalls.length).toBe(1);
    const updateExpr = updateCalls[0].args[0].input.UpdateExpression;
    expect(updateExpr).toContain('REMOVE #ttl');
    expect(updateExpr).toContain(':archived');
  });
});
