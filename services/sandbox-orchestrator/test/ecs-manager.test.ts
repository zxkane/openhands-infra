import { jest, describe, test, expect, beforeEach } from '@jest/globals';

// Mock AWS SDK before importing the module
const mockSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-ecs', () => ({
  ECSClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  RunTaskCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'RunTaskCommand' })),
  StopTaskCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'StopTaskCommand' })),
  DescribeTasksCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DescribeTasksCommand' })),
  ListTasksCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'ListTasksCommand' })),
}));

jest.unstable_mockModule('@smithy/node-http-handler', () => ({
  NodeHttpHandler: jest.fn(),
}));

const { EcsManager } = await import('../src/ecs-manager.js');

describe('EcsManager', () => {
  let manager: InstanceType<typeof EcsManager>;

  beforeEach(() => {
    jest.clearAllMocks();
    manager = new EcsManager({
      clusterArn: 'arn:aws:ecs:us-west-2:123:cluster/test',
      taskDefinitionArn: 'openhands-sandbox',
      subnets: ['subnet-abc123', 'subnet-def456'],
      securityGroupId: 'sg-12345',
      region: 'us-west-2',
    });
  });

  test('constructor throws with no valid subnets', () => {
    expect(
      () =>
        new EcsManager({
          clusterArn: 'arn:cluster',
          taskDefinitionArn: 'task-def',
          subnets: ['invalid', ''],
          securityGroupId: 'sg-1',
        }),
    ).toThrow('No valid subnets');
  });

  test('runTask sends RunTaskCommand and returns task_arn', async () => {
    mockSend.mockResolvedValueOnce({
      tasks: [
        {
          taskArn: 'arn:aws:ecs:us-west-2:123:task/test/abc123',
          lastStatus: 'PROVISIONING',
        },
      ],
      failures: [],
    });

    const result = await manager.runTask({
      conversationId: 'conv-1',
      userId: 'user-1',
      image: 'img:latest',
      environment: { FOO: 'bar' },
      sessionApiKey: 'key-1',
    });

    expect(result.task_arn).toBe('arn:aws:ecs:us-west-2:123:task/test/abc123');
    expect(result.last_status).toBe('PROVISIONING');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.launchType).toBe('FARGATE');
    const envOverrides = cmd.input.overrides.containerOverrides[0].environment;
    expect(envOverrides).toEqual(
      expect.arrayContaining([
        { name: 'FOO', value: 'bar' },
        { name: 'CONVERSATION_ID', value: 'conv-1' },
        { name: 'USER_ID', value: 'user-1' },
        { name: 'OH_SESSION_API_KEYS_0', value: 'key-1' },
      ]),
    );
  });

  test('runTask throws on failures', async () => {
    mockSend.mockResolvedValueOnce({
      tasks: [],
      failures: [{ reason: 'RESOURCE:MEMORY' }],
    });

    await expect(
      manager.runTask({
        conversationId: 'conv-1',
        userId: 'user-1',
        image: 'img',
        environment: {},
        sessionApiKey: 'key',
      }),
    ).rejects.toThrow('RESOURCE:MEMORY');
  });

  test('runTask throws when no tasks returned', async () => {
    mockSend.mockResolvedValueOnce({
      tasks: [],
      failures: [],
    });

    await expect(
      manager.runTask({
        conversationId: 'conv-1',
        userId: 'user-1',
        image: 'img',
        environment: {},
        sessionApiKey: 'key',
      }),
    ).rejects.toThrow('no tasks');
  });

  test('stopTask sends StopTaskCommand', async () => {
    mockSend.mockResolvedValueOnce({});

    await manager.stopTask('arn:task', 'User requested');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.task).toBe('arn:task');
    expect(cmd.input.reason).toBe('User requested');
  });

  test('describeTask returns TaskInfo', async () => {
    mockSend.mockResolvedValueOnce({
      tasks: [
        {
          taskArn: 'arn:task',
          lastStatus: 'RUNNING',
          desiredStatus: 'RUNNING',
          stoppedReason: '',
          attachments: [
            {
              type: 'ElasticNetworkInterface',
              details: [{ name: 'privateIPv4Address', value: '10.0.0.5' }],
            },
          ],
        },
      ],
    });

    const info = await manager.describeTask('arn:task');
    expect(info).not.toBeNull();
    expect(info!.last_status).toBe('RUNNING');
    expect(info!.task_ip).toBe('10.0.0.5');
  });

  test('describeTask returns null when task not found', async () => {
    mockSend.mockResolvedValueOnce({ tasks: [] });

    const info = await manager.describeTask('arn:nonexistent');
    expect(info).toBeNull();
  });

  test('extractTaskIp extracts IP from ENI attachment', () => {
    const task = {
      attachments: [
        {
          type: 'ElasticNetworkInterface',
          details: [
            { name: 'subnetId', value: 'subnet-123' },
            { name: 'privateIPv4Address', value: '10.0.1.50' },
          ],
        },
      ],
    };
    expect(EcsManager.extractTaskIp(task)).toBe('10.0.1.50');
  });

  test('extractTaskIp returns null when no ENI', () => {
    expect(EcsManager.extractTaskIp({ attachments: [] })).toBeNull();
    expect(EcsManager.extractTaskIp({})).toBeNull();
  });

  test('listServiceTasks returns task ARNs', async () => {
    mockSend.mockResolvedValueOnce({
      taskArns: ['arn:task-1', 'arn:task-2'],
    });

    const arns = await manager.listServiceTasks('my-service');
    expect(arns).toEqual(['arn:task-1', 'arn:task-2']);
  });
});
