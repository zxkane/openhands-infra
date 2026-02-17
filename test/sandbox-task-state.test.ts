import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { mockClient } from 'aws-sdk-client-mock';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.AWS_REGION_NAME = 'us-west-2';

const ddbMock = mockClient(DynamoDBClient);

// Import handler after mocks are set up
import { handler } from '../lambda/sandbox-task-state/index.js';

describe('Sandbox Task State Change Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
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
});
