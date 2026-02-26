import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { EFSClient, DeleteAccessPointCommand } from '@aws-sdk/client-efs';
import { mockClient } from 'aws-sdk-client-mock';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.AWS_REGION_NAME = 'us-west-2';
process.env.EFS_FILE_SYSTEM_ID = 'fs-test12345';

const ddbMock = mockClient(DynamoDBClient);
const efsMock = mockClient(EFSClient);

// Import handler after mocks are set up
import { handler } from '../lambda/sandbox-task-state/index.js';

describe('Sandbox Task State Change Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    efsMock.reset();
  });

  const makeEvent = (overrides: Record<string, any> = {}) => ({
    'detail-type': 'ECS Task State Change' as const,
    source: 'aws.ecs' as const,
    detail: {
      taskArn: 'arn:aws:ecs:us-west-2:123:task/test/abc123',
      clusterArn: 'arn:aws:ecs:us-west-2:123:cluster/test-sandbox',
      lastStatus: 'STOPPED',
      desiredStatus: 'STOPPED',
      stoppedReason: 'Essential container in task exited',
      ...overrides,
    },
  });

  test('marks RUNNING DynamoDB records as STOPPED when task stops', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-1' },
        status: { S: 'RUNNING' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc123' },
      }],
    } as any).resolvesOnce({ Items: [] } as any);

    ddbMock.on(UpdateItemCommand).resolves({});

    await handler(makeEvent());

    const updateCalls = ddbMock.commandCalls(UpdateItemCommand);
    expect(updateCalls).toHaveLength(1);
    expect(updateCalls[0].args[0].input.Key).toEqual({
      conversation_id: { S: 'conv-1' },
    });
    expect(updateCalls[0].args[0].input.ExpressionAttributeValues![':status']).toEqual({
      S: 'STOPPED',
    });
  });

  test('ignores non-STOPPED state changes', async () => {
    await handler(makeEvent({ lastStatus: 'RUNNING' }));

    const queryCalls = ddbMock.commandCalls(QueryCommand);
    expect(queryCalls).toHaveLength(0);
  });

  test('skips warm pool tasks', async () => {
    await handler(makeEvent({ group: 'service:test-sandbox-warm-pool' }));

    const queryCalls = ddbMock.commandCalls(QueryCommand);
    expect(queryCalls).toHaveLength(0);
  });

  test('handles no matching DynamoDB records gracefully', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [] } as any);

    await handler(makeEvent());

    const updateCalls = ddbMock.commandCalls(UpdateItemCommand);
    expect(updateCalls).toHaveLength(0);
  });

  test('updates both RUNNING and STARTING records', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-running' },
        status: { S: 'RUNNING' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc123' },
      }],
    } as any).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-starting' },
        status: { S: 'STARTING' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc123' },
      }],
    } as any);

    ddbMock.on(UpdateItemCommand).resolves({});

    await handler(makeEvent());

    const updateCalls = ddbMock.commandCalls(UpdateItemCommand);
    expect(updateCalls).toHaveLength(2);
  });

  test('deletes EFS access point when task stops', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-ap-crash' },
        status: { S: 'RUNNING' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc123' },
        access_point_id: { S: 'fsap-crash456' },
      }],
    } as any).resolvesOnce({ Items: [] } as any);

    ddbMock.on(UpdateItemCommand).resolves({});
    efsMock.on(DeleteAccessPointCommand).resolves({});

    await handler(makeEvent());

    const efsCalls = efsMock.commandCalls(DeleteAccessPointCommand);
    expect(efsCalls).toHaveLength(1);
    expect(efsCalls[0].args[0].input.AccessPointId).toBe('fsap-crash456');
  });

  test('skips access point deletion when record has no access_point_id', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-no-ap' },
        status: { S: 'RUNNING' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc123' },
      }],
    } as any).resolvesOnce({ Items: [] } as any);

    ddbMock.on(UpdateItemCommand).resolves({});

    await handler(makeEvent());

    const efsCalls = efsMock.commandCalls(DeleteAccessPointCommand);
    expect(efsCalls).toHaveLength(0);
  });
});
