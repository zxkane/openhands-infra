import { jest, describe, test, expect, beforeEach } from '@jest/globals';

// Mock AWS SDK before importing the module
const mockSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-ecs', () => ({
  ECSClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  RunTaskCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'RunTaskCommand' })),
  StopTaskCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'StopTaskCommand' })),
  DescribeTasksCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DescribeTasksCommand' })),
  DescribeTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DescribeTaskDefinitionCommand' })),
  RegisterTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'RegisterTaskDefinitionCommand' })),
  DeregisterTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DeregisterTaskDefinitionCommand' })),
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

  test('runTask uses taskDefinitionOverride when provided', async () => {
    mockSend.mockResolvedValueOnce({
      tasks: [
        {
          taskArn: 'arn:aws:ecs:us-west-2:123:task/test/override1',
          lastStatus: 'PROVISIONING',
        },
      ],
      failures: [],
    });

    await manager.runTask({
      conversationId: 'conv-override',
      userId: 'user-1',
      image: 'img:latest',
      environment: {},
      sessionApiKey: 'key-1',
      taskDefinitionOverride: 'arn:aws:ecs:us-west-2:123:task-definition/openhands-sandbox:42',
    });

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.taskDefinition).toBe('arn:aws:ecs:us-west-2:123:task-definition/openhands-sandbox:42');
  });

  test('registerTaskDefinitionWithAccessPoint copies base and replaces AP', async () => {
    // First call: DescribeTaskDefinition
    mockSend.mockResolvedValueOnce({
      taskDefinition: {
        family: 'openhands-sandbox',
        taskRoleArn: 'arn:role/task',
        executionRoleArn: 'arn:role/exec',
        networkMode: 'awsvpc',
        containerDefinitions: [{ name: 'agent-server', image: 'img' }],
        volumes: [
          {
            name: 'workspace',
            efsVolumeConfiguration: {
              fileSystemId: 'fs-old',
              transitEncryption: 'ENABLED',
              authorizationConfig: {
                accessPointId: 'fsap-old',
                iam: 'ENABLED',
              },
            },
          },
        ],
        cpu: '2048',
        memory: '4096',
        requiresCompatibilities: ['FARGATE'],
        runtimePlatform: { cpuArchitecture: 'ARM64' },
      },
    });

    // Second call: RegisterTaskDefinition
    mockSend.mockResolvedValueOnce({
      taskDefinition: {
        taskDefinitionArn: 'arn:aws:ecs:us-west-2:123:task-definition/openhands-sandbox:99',
      },
    });

    const arn = await manager.registerTaskDefinitionWithAccessPoint('fsap-new', 'fs-new');

    expect(arn).toBe('arn:aws:ecs:us-west-2:123:task-definition/openhands-sandbox:99');

    // Verify RegisterTaskDefinition call
    const regCmd = mockSend.mock.calls[1][0] as any;
    expect(regCmd.input.family).toBe('openhands-sandbox');
    expect(regCmd.input.volumes[0].efsVolumeConfiguration.authorizationConfig.accessPointId).toBe('fsap-new');
    expect(regCmd.input.volumes[0].efsVolumeConfiguration.fileSystemId).toBe('fs-new');
  });

  test('registerTaskDefinitionWithAccessPoint throws when base not found', async () => {
    mockSend.mockResolvedValueOnce({ taskDefinition: undefined });

    await expect(
      manager.registerTaskDefinitionWithAccessPoint('fsap-x', 'fs-x'),
    ).rejects.toThrow('Task definition not found');
  });

  test('deregisterTaskDefinition sends command', async () => {
    mockSend.mockResolvedValueOnce({});

    await manager.deregisterTaskDefinition('arn:task-def:1');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.taskDefinition).toBe('arn:task-def:1');
  });

  test('deregisterTaskDefinition handles InvalidParameterException gracefully', async () => {
    const err = new Error('inactive');
    (err as any).name = 'InvalidParameterException';
    mockSend.mockRejectedValueOnce(err);

    await expect(manager.deregisterTaskDefinition('arn:already-inactive')).resolves.toBeUndefined();
  });
});
