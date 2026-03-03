import { DynamoDBClient, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, ListObjectsV2Command, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import { RDSDataClient, ExecuteStatementCommand } from '@aws-sdk/client-rds-data';
import { mockClient } from 'aws-sdk-client-mock';

// Mock node:fs before importing handler
jest.mock('node:fs', () => ({
  rmSync: jest.fn(),
}));
import * as fs from 'node:fs';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.DATA_BUCKET = 'test-data-bucket';
process.env.EFS_MOUNT_PATH = '/tmp/test-efs';
process.env.DB_CLUSTER_ARN = 'arn:aws:rds:us-west-2:123456789012:cluster:test-cluster';
process.env.DB_SECRET_ARN = 'arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret';
process.env.DB_NAME = 'openhands';
process.env.AWS_REGION_NAME = 'us-west-2';

const ddbMock = mockClient(DynamoDBClient);
const s3Mock = mockClient(S3Client);
const rdsMock = mockClient(RDSDataClient);

// Import handler after mocks are set up
import { handler } from '../lambda/conversation-delete/index.js';

describe('Conversation Deletion Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    s3Mock.reset();
    rdsMock.reset();
    (fs.rmSync as jest.Mock).mockReset();
  });

  test('deletes conversation data across all storage layers', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [
        { Key: 'conversations/conv-1/event1.json' },
        { Key: 'conversations/conv-1/event2.json' },
      ],
    });
    s3Mock.on(DeleteObjectsCommand).resolves({});
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    const result = await handler({
      conversation_id: 'conv-1',
      user_id: 'user-1',
    });

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.deleted).toBe(true);
    expect(body.conversation_id).toBe('conv-1');
    expect(body.s3_objects_deleted).toBe(2);

    // Verify EFS cleanup was called
    expect(fs.rmSync).toHaveBeenCalledWith(
      expect.stringContaining('conv-1'),
      expect.objectContaining({ recursive: true, force: true }),
    );
  });

  test('handles S3 pagination for large conversations', async () => {
    const page1Contents = Array.from({ length: 1000 }, (_, i) => ({
      Key: `conversations/conv-2/event${i}.json`,
    }));
    s3Mock.on(ListObjectsV2Command)
      .resolvesOnce({
        Contents: page1Contents,
        NextContinuationToken: 'token-1',
      })
      .resolvesOnce({
        Contents: [{ Key: 'conversations/conv-2/event1000.json' }],
      });

    s3Mock.on(DeleteObjectsCommand).resolves({});
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    const result = await handler({
      conversation_id: 'conv-2',
      user_id: 'user-2',
    });

    const body = JSON.parse(result.body);
    expect(body.s3_objects_deleted).toBe(1001);

    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    expect(listCalls.length).toBe(2);
  });

  test('handles empty S3 bucket gracefully', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    const result = await handler({
      conversation_id: 'conv-empty',
      user_id: 'user-3',
    });

    const body = JSON.parse(result.body);
    expect(body.deleted).toBe(true);
    expect(body.s3_objects_deleted).toBe(0);
  });

  test('handles EFS deletion errors gracefully', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    (fs.rmSync as jest.Mock).mockImplementation(() => {
      const err = new Error('ENOENT') as NodeJS.ErrnoException;
      err.code = 'ENOENT';
      throw err;
    });

    const result = await handler({
      conversation_id: 'conv-no-efs',
      user_id: 'user-4',
    });

    expect(result.statusCode).toBe(200);
  });

  test('deletes Aurora record via RDS Data API', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    await handler({
      conversation_id: 'conv-rds',
      user_id: 'user-5',
    });

    const rdsCalls = rdsMock.commandCalls(ExecuteStatementCommand);
    expect(rdsCalls.length).toBe(1);
    expect(rdsCalls[0].args[0].input.sql).toContain('DELETE FROM conversations');
    expect(rdsCalls[0].args[0].input.parameters?.[0]?.value?.stringValue).toBe('conv-rds');
  });

  test('deletes DynamoDB record as fallback', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    await handler({
      conversation_id: 'conv-ddb',
      user_id: 'user-6',
    });

    const ddbCalls = ddbMock.commandCalls(DeleteItemCommand);
    expect(ddbCalls.length).toBe(1);
    expect(ddbCalls[0].args[0].input.Key?.conversation_id?.S).toBe('conv-ddb');
  });
});
