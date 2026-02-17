import { jest, describe, test, expect, beforeEach } from '@jest/globals';

// Mock AWS SDK before importing the module
const mockSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  BatchGetItemCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'BatchGetItemCommand' })),
}));

jest.unstable_mockModule('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: jest.fn().mockReturnValue({ send: mockSend }),
  },
  PutCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'PutCommand' })),
  GetCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'GetCommand' })),
  UpdateCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'UpdateCommand' })),
  QueryCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'QueryCommand' })),
}));

jest.unstable_mockModule('@smithy/node-http-handler', () => ({
  NodeHttpHandler: jest.fn(),
}));

const { DynamoDBStore } = await import('../src/dynamodb-store.js');

describe('DynamoDBStore', () => {
  let store: InstanceType<typeof DynamoDBStore>;

  beforeEach(() => {
    jest.clearAllMocks();
    store = new DynamoDBStore('test-table', 'us-west-2');
  });

  test('putSandbox sends PutCommand with TTL', async () => {
    mockSend.mockResolvedValueOnce({});

    await store.putSandbox({
      conversation_id: 'conv-1',
      user_id: 'user-1',
      task_arn: 'arn:aws:ecs:us-west-2:123:task/abc',
      task_ip: '10.0.0.1',
      status: 'RUNNING',
      session_api_key: 'key-1',
      agent_server_port: 8000,
      sandbox_spec_id: 'image:latest',
      last_activity_at: 0,
      created_at: 0,
    });

    expect(mockSend).toHaveBeenCalledTimes(1);
    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.TableName).toBe('test-table');
    expect(cmd.input.Item.conversation_id).toBe('conv-1');
    expect(cmd.input.Item.ttl).toBeGreaterThan(0);
    expect(cmd.input.Item.last_activity_at).toBeGreaterThan(0);
  });

  test('getSandbox returns record when found', async () => {
    mockSend.mockResolvedValueOnce({
      Item: {
        conversation_id: 'conv-1',
        user_id: 'user-1',
        task_arn: 'arn:task',
        task_ip: '10.0.0.1',
        status: 'RUNNING',
        session_api_key: 'key-1',
        agent_server_port: 8000,
        sandbox_spec_id: 'img',
        last_activity_at: 100,
        created_at: 50,
      },
    });

    const record = await store.getSandbox('conv-1');
    expect(record).not.toBeNull();
    expect(record!.conversation_id).toBe('conv-1');
    expect(record!.status).toBe('RUNNING');
  });

  test('getSandbox returns null when not found', async () => {
    mockSend.mockResolvedValueOnce({});
    const record = await store.getSandbox('nonexistent');
    expect(record).toBeNull();
  });

  test('updateStatus sends UpdateCommand with status', async () => {
    mockSend.mockResolvedValueOnce({});

    await store.updateStatus('conv-1', 'STOPPED');

    expect(mockSend).toHaveBeenCalledTimes(1);
    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.Key).toEqual({ conversation_id: 'conv-1' });
    expect(cmd.input.ExpressionAttributeValues[':status']).toBe('STOPPED');
  });

  test('updateStatus includes task_ip when provided', async () => {
    mockSend.mockResolvedValueOnce({});

    await store.updateStatus('conv-1', 'RUNNING', '10.0.0.2');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.UpdateExpression).toContain('task_ip');
    expect(cmd.input.ExpressionAttributeValues[':ip']).toBe('10.0.0.2');
  });

  test('updateActivity sends UpdateCommand', async () => {
    mockSend.mockResolvedValueOnce({});

    await store.updateActivity('conv-1');

    expect(mockSend).toHaveBeenCalledTimes(1);
    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.Key).toEqual({ conversation_id: 'conv-1' });
    expect(cmd.input.UpdateExpression).toContain('last_activity_at');
  });

  test('queryByStatus queries status-index', async () => {
    mockSend.mockResolvedValueOnce({
      Items: [
        {
          conversation_id: 'warm-1',
          user_id: 'warm-pool',
          task_arn: 'arn:task',
          task_ip: '10.0.0.1',
          status: 'WARM',
          session_api_key: 'key',
          agent_server_port: 8000,
          sandbox_spec_id: 'img',
          last_activity_at: 100,
          created_at: 50,
        },
      ],
    });

    const records = await store.queryByStatus('WARM');
    expect(records).toHaveLength(1);
    expect(records[0].status).toBe('WARM');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.IndexName).toBe('status-index');
  });

  test('listRunning queries for RUNNING status', async () => {
    mockSend.mockResolvedValueOnce({ Items: [] });

    const records = await store.listRunning();
    expect(records).toHaveLength(0);

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.ExpressionAttributeValues[':s']).toBe('RUNNING');
  });

  test('batchGetSandboxes returns empty for empty input', async () => {
    const records = await store.batchGetSandboxes([]);
    expect(records).toHaveLength(0);
    expect(mockSend).not.toHaveBeenCalled();
  });

  test('batchGetSandboxes handles results', async () => {
    mockSend.mockResolvedValueOnce({
      Responses: {
        'test-table': [
          {
            conversation_id: { S: 'conv-1' },
            user_id: { S: 'user-1' },
            task_arn: { S: 'arn:task' },
            task_ip: { S: '10.0.0.1' },
            status: { S: 'RUNNING' },
            session_api_key: { S: 'key' },
            agent_server_port: { N: '8000' },
            sandbox_spec_id: { S: 'img' },
            last_activity_at: { N: '100' },
            created_at: { N: '50' },
          },
        ],
      },
      UnprocessedKeys: {},
    });

    const records = await store.batchGetSandboxes(['conv-1']);
    expect(records).toHaveLength(1);
    expect(records[0].conversation_id).toBe('conv-1');
  });
});
