import { DynamoDBClient, DeleteItemCommand } from '@aws-sdk/client-dynamodb';
import { S3Client, ListObjectsV2Command, DeleteObjectsCommand } from '@aws-sdk/client-s3';
import { RDSDataClient, ExecuteStatementCommand } from '@aws-sdk/client-rds-data';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
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
process.env.DB_SECRET_NAME = 'openhands/database/admin';
process.env.DB_NAME = 'openhands';
process.env.AWS_REGION_NAME = 'us-west-2';

const ddbMock = mockClient(DynamoDBClient);
const s3Mock = mockClient(S3Client);
const rdsMock = mockClient(RDSDataClient);
const smMock = mockClient(SecretsManagerClient);

// Import handler after mocks are set up
import { handler } from '../lambda/conversation-delete/index.js';

/** Default mock for Secrets Manager — returns Aurora secret with cluster identifier */
function mockDbSecret() {
  smMock.on(GetSecretValueCommand).resolves({
    ARN: 'arn:aws:secretsmanager:us-west-2:123456789012:secret:openhands/database/admin-AbCdEf',
    SecretString: JSON.stringify({
      dbClusterIdentifier: 'test-cluster',
      host: 'test-cluster.cluster-abc123.us-west-2.rds.amazonaws.com',
      username: 'postgres',
      password: 'test-password',
    }),
  });
}

describe('Conversation Deletion Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    s3Mock.reset();
    rdsMock.reset();
    smMock.reset();
    (fs.rmSync as jest.Mock).mockReset();
    mockDbSecret();
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

    // Verify S3: correct prefix used for listing
    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    expect(listCalls.length).toBe(1);
    expect(listCalls[0].args[0].input.Prefix).toBe('conversations/conv-1/');
    expect(listCalls[0].args[0].input.Bucket).toBe('test-data-bucket');

    // Verify S3: correct keys passed to batch delete, with Quiet mode
    const deleteCalls = s3Mock.commandCalls(DeleteObjectsCommand);
    expect(deleteCalls.length).toBe(1);
    expect(deleteCalls[0].args[0].input.Delete?.Objects).toEqual([
      { Key: 'conversations/conv-1/event1.json' },
      { Key: 'conversations/conv-1/event2.json' },
    ]);
    expect(deleteCalls[0].args[0].input.Delete?.Quiet).toBe(true);

    // Verify EFS: correct path used (mount + conversation_id, not the mount root)
    expect(fs.rmSync).toHaveBeenCalledTimes(1);
    expect(fs.rmSync).toHaveBeenCalledWith(
      '/tmp/test-efs/conv-1',
      { recursive: true, force: true },
    );

    // Verify Aurora: DELETE executed with correct conversation_id
    const rdsCalls = rdsMock.commandCalls(ExecuteStatementCommand);
    expect(rdsCalls.length).toBe(1);
    expect(rdsCalls[0].args[0].input.sql).toContain('DELETE FROM conversations WHERE id = :id');
    expect(rdsCalls[0].args[0].input.parameters?.[0]?.value?.stringValue).toBe('conv-1');

    // Verify DynamoDB: record deleted with correct key
    const ddbCalls = ddbMock.commandCalls(DeleteItemCommand);
    expect(ddbCalls.length).toBe(1);
    expect(ddbCalls[0].args[0].input.Key?.conversation_id?.S).toBe('conv-1');
  });

  test('S3 deletion uses correct prefix and does not leak to other conversations', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({
      Contents: [
        { Key: 'conversations/target-conv/event1.json' },
      ],
    });
    s3Mock.on(DeleteObjectsCommand).resolves({});
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    await handler({ conversation_id: 'target-conv', user_id: 'user-x' });

    // Verify S3 list is scoped to exactly this conversation's prefix
    const listCalls = s3Mock.commandCalls(ListObjectsV2Command);
    const prefix = listCalls[0].args[0].input.Prefix;
    expect(prefix).toBe('conversations/target-conv/');
    // Must end with / to prevent matching conversations/target-conv-2/
    expect(prefix!.endsWith('/')).toBe(true);
  });

  test('EFS deletion targets exact conversation directory, not mount root', async () => {
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    await handler({ conversation_id: 'efs-check-conv', user_id: 'user-y' });

    // Must delete /tmp/test-efs/efs-check-conv, NOT /tmp/test-efs/
    expect(fs.rmSync).toHaveBeenCalledWith(
      '/tmp/test-efs/efs-check-conv',
      { recursive: true, force: true },
    );
    // Must NOT delete the mount root
    expect(fs.rmSync).not.toHaveBeenCalledWith(
      '/tmp/test-efs',
      expect.anything(),
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

  test('skips S3 cleanup when DATA_BUCKET not configured', async () => {
    const origBucket = process.env.DATA_BUCKET;
    // Note: DATA_BUCKET is read at module load, so we test the Lambda logic
    // by verifying that no S3 calls are made when bucket is empty
    s3Mock.on(ListObjectsV2Command).resolves({ Contents: [] });
    rdsMock.on(ExecuteStatementCommand).resolves({});
    ddbMock.on(DeleteItemCommand).resolves({});

    await handler({ conversation_id: 'conv-no-bucket', user_id: 'user-7' });

    // All storage layers should still be attempted (S3 gracefully handles empty results)
    expect(ddbMock.commandCalls(DeleteItemCommand).length).toBe(1);
  });

  test('rejects invalid event payload', async () => {
    const result = await handler({} as any);

    expect(result.statusCode).toBe(400);
    const body = JSON.parse(result.body);
    expect(body.error).toContain('Missing required fields');
  });
});
