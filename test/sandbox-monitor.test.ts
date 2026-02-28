import { DynamoDBClient, QueryCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { ECSClient, StopTaskCommand, ListTasksCommand, DescribeTasksCommand } from '@aws-sdk/client-ecs';

/** Timestamp well past the 5-minute grace period */
const OLD_TIMESTAMP = new Date(Date.now() - 10 * 60 * 1000);
/** Timestamp within the 5-minute grace period */
const RECENT_TIMESTAMP = new Date(Date.now() - 60 * 1000);
import { EFSClient, DeleteAccessPointCommand } from '@aws-sdk/client-efs';
import { CloudWatchClient, PutMetricDataCommand } from '@aws-sdk/client-cloudwatch';
import { mockClient } from 'aws-sdk-client-mock';

// Set env vars before importing handler
process.env.REGISTRY_TABLE_NAME = 'test-sandbox-registry';
process.env.ECS_CLUSTER_ARN = 'arn:aws:ecs:us-west-2:123456789012:cluster/test-sandbox';
process.env.IDLE_TIMEOUT_MINUTES = '30';
process.env.SANDBOX_TASK_FAMILY = 'openhands-sandbox';
process.env.AWS_REGION_NAME = 'us-west-2';
process.env.EFS_FILE_SYSTEM_ID = 'fs-test12345';

const ddbMock = mockClient(DynamoDBClient);
const ecsMock = mockClient(ECSClient);
const cwMock = mockClient(CloudWatchClient);
const efsMock = mockClient(EFSClient);

// Import handler after mocks are set up
import { handler } from '../lambda/sandbox-monitor/index.js';

/** Helper to set up default mocks for orphan cleanup (no orphans by default) */
function mockNoOrphans() {
  ecsMock.on(ListTasksCommand).resolves({ taskArns: [] });
}

describe('Sandbox Idle Monitor Lambda', () => {
  beforeEach(() => {
    ddbMock.reset();
    ecsMock.reset();
    efsMock.reset();
    cwMock.reset();
  });

  test('returns summary when no idle sandboxes found', async () => {
    ddbMock.on(QueryCommand).resolves({ Items: [], Count: 0 } as any);
    cwMock.on(PutMetricDataCommand).resolves({});
    mockNoOrphans();

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.idle_found).toBe(0);
    expect(body.stopped).toBe(0);
    expect(body.orphans_stopped).toBe(0);
  });

  test('stops idle sandbox and updates DynamoDB', async () => {
    const now = Math.floor(Date.now() / 1000);
    const idleTimestamp = now - 3600;

    // First QueryCommand call: idle sandboxes query
    // Subsequent calls: running count, then orphan cleanup queries
    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-idle-1' },
        user_id: { S: 'user-1' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/abc' },
        status: { S: 'RUNNING' },
        last_activity_at: { N: idleTimestamp.toString() },
      }],
    } as any).resolves({ Items: [], Count: 0 } as any);

    ecsMock.on(StopTaskCommand).resolves({});
    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});
    mockNoOrphans();

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
    } as any).resolves({ Items: [], Count: 0 } as any);

    ecsMock.on(StopTaskCommand).rejects(new Error('Task not found'));
    cwMock.on(PutMetricDataCommand).resolves({});
    mockNoOrphans();

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.idle_found).toBe(1);
    expect(body.stopped).toBe(0);
    expect(body.errors).toBe(1);
  });

  test('publishes CloudWatch metrics including orphan count', async () => {
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any).resolvesOnce({ Count: 5 } as any)
      .resolves({ Items: [] } as any);
    cwMock.on(PutMetricDataCommand).resolves({});
    mockNoOrphans();

    await handler();

    const metricCalls = cwMock.commandCalls(PutMetricDataCommand);
    expect(metricCalls).toHaveLength(1);
    const metricData = metricCalls[0].args[0].input.MetricData!;
    expect(metricData).toHaveLength(3);
    expect(metricData[0].MetricName).toBe('IdleSandboxesStopped');
    expect(metricData[1].MetricName).toBe('RunningSandboxes');
    expect(metricData[1].Value).toBe(5);
    expect(metricData[2].MetricName).toBe('OrphanSandboxesStopped');
    expect(metricData[2].Value).toBe(0);
  });

  test('deletes EFS access point when stopping idle sandbox', async () => {
    const now = Math.floor(Date.now() / 1000);
    const idleTimestamp = now - 3600;

    ddbMock.on(QueryCommand).resolvesOnce({
      Items: [{
        conversation_id: { S: 'conv-ap-1' },
        user_id: { S: 'user-1' },
        task_arn: { S: 'arn:aws:ecs:us-west-2:123:task/test/ap1' },
        status: { S: 'RUNNING' },
        last_activity_at: { N: idleTimestamp.toString() },
        access_point_id: { S: 'fsap-idle123' },
      }],
    } as any).resolves({ Items: [], Count: 0 } as any);

    ecsMock.on(StopTaskCommand).resolves({});
    efsMock.on(DeleteAccessPointCommand).resolves({});
    ddbMock.on(UpdateItemCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});
    mockNoOrphans();

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.stopped).toBe(1);

    const efsCalls = efsMock.commandCalls(DeleteAccessPointCommand);
    expect(efsCalls).toHaveLength(1);
    expect(efsCalls[0].args[0].input.AccessPointId).toBe('fsap-idle123');
  });
});

describe('Orphan Task Cleanup', () => {
  beforeEach(() => {
    ddbMock.reset();
    ecsMock.reset();
    efsMock.reset();
    cwMock.reset();
  });

  test('stops orphan ECS task not tracked in DynamoDB', async () => {
    const orphanTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/orphan-abc';
    const trackedTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/tracked-def';

    // Idle sandboxes: none
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any)
      // Running count
      .resolvesOnce({ Count: 1 } as any)
      // Orphan cleanup: RUNNING records in DynamoDB (tracked task)
      .resolvesOnce({
        Items: [{ task_arn: { S: trackedTaskArn } }],
      } as any)
      // Orphan cleanup: STARTING records in DynamoDB (none)
      .resolvesOnce({ Items: [] } as any);

    // ECS lists both tasks as running
    ecsMock.on(ListTasksCommand).resolves({
      taskArns: [orphanTaskArn, trackedTaskArn],
    });

    // Orphan task is old enough (past grace period)
    ecsMock.on(DescribeTasksCommand).resolves({
      tasks: [{ taskArn: orphanTaskArn, startedAt: OLD_TIMESTAMP }],
    });

    ecsMock.on(StopTaskCommand).resolves({});
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(1);

    const stopCalls = ecsMock.commandCalls(StopTaskCommand);
    expect(stopCalls).toHaveLength(1);
    expect(stopCalls[0].args[0].input.task).toBe(orphanTaskArn);
    expect(stopCalls[0].args[0].input.reason).toContain('Orphan task');
  });

  test('does not stop tasks that are tracked in DynamoDB', async () => {
    const trackedTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/tracked-abc';

    // No idle sandboxes
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any)
      // Running count
      .resolvesOnce({ Count: 1 } as any)
      // Orphan cleanup: RUNNING records
      .resolvesOnce({
        Items: [{ task_arn: { S: trackedTaskArn } }],
      } as any)
      // STARTING records
      .resolvesOnce({ Items: [] } as any);

    ecsMock.on(ListTasksCommand).resolves({
      taskArns: [trackedTaskArn],
    });

    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(0);

    const stopCalls = ecsMock.commandCalls(StopTaskCommand);
    expect(stopCalls).toHaveLength(0);
  });

  test('skips orphan cleanup when no ECS tasks are running', async () => {
    // No idle sandboxes
    ddbMock.on(QueryCommand).resolves({ Items: [], Count: 0 } as any);

    ecsMock.on(ListTasksCommand).resolves({ taskArns: [] });
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(0);

    // Should not have queried DynamoDB for RUNNING/STARTING status
    // (first call is idle query, second is running count, orphan cleanup skipped)
    const queryCalls = ddbMock.commandCalls(QueryCommand);
    expect(queryCalls).toHaveLength(2); // idle query + running count only
  });

  test('handles orphan stop failure gracefully', async () => {
    const orphanTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/orphan-fail';

    // No idle sandboxes
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any)
      .resolvesOnce({ Count: 0 } as any)
      // RUNNING records
      .resolvesOnce({ Items: [] } as any)
      // STARTING records
      .resolvesOnce({ Items: [] } as any);

    ecsMock.on(ListTasksCommand).resolves({
      taskArns: [orphanTaskArn],
    });

    ecsMock.on(DescribeTasksCommand).resolves({
      tasks: [{ taskArn: orphanTaskArn, startedAt: OLD_TIMESTAMP }],
    });

    ecsMock.on(StopTaskCommand).rejects(new Error('Access denied'));
    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    // Should not crash — error is caught
    expect(result.statusCode).toBe(200);
    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(0);
  });

  test('recognizes STARTING status tasks as tracked (not orphans)', async () => {
    const startingTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/starting-abc';

    // No idle sandboxes
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any)
      .resolvesOnce({ Count: 1 } as any)
      // RUNNING records (none)
      .resolvesOnce({ Items: [] } as any)
      // STARTING records (has the task)
      .resolvesOnce({
        Items: [{ task_arn: { S: startingTaskArn } }],
      } as any);

    ecsMock.on(ListTasksCommand).resolves({
      taskArns: [startingTaskArn],
    });

    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(0);

    const stopCalls = ecsMock.commandCalls(StopTaskCommand);
    expect(stopCalls).toHaveLength(0);
  });

  test('skips orphan task within 5-minute grace period', async () => {
    const newTaskArn = 'arn:aws:ecs:us-west-2:123:task/test/new-task';

    // No idle sandboxes
    ddbMock.on(QueryCommand).resolvesOnce({ Items: [] } as any)
      .resolvesOnce({ Count: 0 } as any)
      // RUNNING records (none — task not yet tracked)
      .resolvesOnce({ Items: [] } as any)
      // STARTING records (none)
      .resolvesOnce({ Items: [] } as any);

    ecsMock.on(ListTasksCommand).resolves({
      taskArns: [newTaskArn],
    });

    // Task was just started (within grace period)
    ecsMock.on(DescribeTasksCommand).resolves({
      tasks: [{ taskArn: newTaskArn, startedAt: RECENT_TIMESTAMP }],
    });

    cwMock.on(PutMetricDataCommand).resolves({});

    const result = await handler();

    const body = JSON.parse(result.body);
    expect(body.orphans_stopped).toBe(0);

    // Should NOT have called StopTask
    const stopCalls = ecsMock.commandCalls(StopTaskCommand);
    expect(stopCalls).toHaveLength(0);
  });
});
