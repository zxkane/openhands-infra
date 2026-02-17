import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, StopTaskCommand } from '@aws-sdk/client-ecs';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { mockClient } from 'aws-sdk-client-mock';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.ECS_CLUSTER_ARN = 'arn:aws:ecs:us-west-2:123456789012:cluster/test-sandbox';
process.env.IDLE_TIMEOUT_MINUTES = '30';
process.env.AWS_REGION_NAME = 'us-west-2';

const ddbMock = mockClient(DynamoDBClient);
const ecsMock = mockClient(ECSClient);
const cwMock = mockClient(CloudWatchClient);

// Import handler after mocks are set up
import { handler } from '../lambda/sandbox-monitor/index.js';

describe('Sandbox Idle Monitor Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    ecsMock.reset();
    cwMock.reset();
  });

  test('returns summary when no idle sandboxes found', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [], Count: 0 } as any);
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.idle_found).toBe(0);
    expect(body.stopped).toBe(0);
  });

  test('stops idle sandbox and updates DynamoDB', async () => {
    const now = Math.floor(Date.now() / 1000);
    const idleTimestamp = now - 3600;

    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-idle-1' },
        user_id: { S: 'user-1' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc' },
        status: { S: 'RUNNING' },
        last_activity_at: { N: idleTimestamp.toString() },
      }],
    } as any).resolvesOnce({ Count: 0 } as any);

    ecsMock.on(StopTaskCommand).resolves({});
    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.idle_found).toBe(1);
    expect(body.stopped).toBe(1);

    const stopCalls = ecsMock.commandCalls(StopTaskCommand);
    expect(stopCalls).toHaveLength(1);
    expect(stopCalls[0].args[0].input.task).toBe('arn:aws:ecs:us-west-2:123:task/test/abc');
  });

  test('handles ECS stop failure gracefully', async () => {
    const now = Math.floor(Date.now() / 1000);
    const idleTimestamp = now - 3600;

    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-fail' },
        user_id: { S: 'user-1' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/fail' },
        status: { S: 'RUNNING' },
        last_activity_at: { N: idleTimestamp.toString() },
      }],
    } as any).resolvesOnce({ Count: 0 } as any);

    ecsMock.on(StopTaskCommand).rejects(new Error('Task not found'));
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.idle_found).toBe(1);
    expect(body.stopped).toBe(0);
    expect(body.errors).toBe(1);
  });

  test('publishes CloudWatch metrics', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any).resolvesOnce({ Count: 5 } as any);
    cwMock.on(PutMetricDataCommand).resolves({});

    await handler();

    const metricCalls = cwMock.commandCalls(PutMetricDataCommand);
    expect(metricCalls).toHaveLength(1);
    const metricData = metricCalls[0].args[0].input.MetricData!;
    expect(metricData).toHaveLength(2);
    expect(metricData[0].MetricName).toBe('IdleSandboxesStopped');
    expect(metricData[1].MetricName).toBe('RunningSandboxes');
    expect(metricData[1].Value).toBe(5);
  });
});
