import { jest, describe, test, expect, beforeEach, afterAll } from '@jest/globals';

// Mock AWS SDK modules before importing the app
const mockDocSend = jest.fn<any>();
const mockRawSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: jest.fn().mockImplementation(() => ({ send: mockRawSend })),
  BatchGetItemCommand: jest.fn().mockImplementation((input: any) => ({ input })),
}));

jest.unstable_mockModule('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: jest.fn().mockReturnValue({ send: mockDocSend }),
  },
  PutCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'PutCommand' })),
  GetCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'GetCommand' })),
  UpdateCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'UpdateCommand' })),
  QueryCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'QueryCommand' })),
}));

const mockEcsSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-ecs', () => ({
  ECSClient: jest.fn().mockImplementation(() => ({ send: mockEcsSend })),
  RunTaskCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  StopTaskCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  DescribeTasksCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  DescribeTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  RegisterTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  DeregisterTaskDefinitionCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  ListTasksCommand: jest.fn().mockImplementation((input: any) => ({ input })),
}));

const mockEfsSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-efs', () => ({
  EFSClient: jest.fn().mockImplementation(() => ({ send: mockEfsSend })),
  CreateAccessPointCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  DeleteAccessPointCommand: jest.fn().mockImplementation((input: any) => ({ input })),
  DescribeAccessPointsCommand: jest.fn().mockImplementation((input: any) => ({ input })),
}));

jest.unstable_mockModule('@smithy/node-http-handler', () => ({
  NodeHttpHandler: jest.fn(),
}));

// Set env vars before importing app
process.env.REGISTRY_TABLE_NAME = 'test-table';
process.env.ECS_CLUSTER_ARN = 'arn:aws:ecs:us-west-2:123:cluster/test';
process.env.TASK_DEFINITION_ARN = 'openhands-sandbox';
process.env.SUBNETS = 'subnet-abc123';
process.env.SECURITY_GROUP_ID = 'sg-12345';
process.env.AWS_REGION_NAME = 'us-west-2';
process.env.SANDBOX_IMAGE = 'test-image:latest';

const { app } = await import('../src/index.js');

describe('API Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(async () => {
    await app.close();
  });

  test('GET /health returns ok', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });

  test('POST /start returns 400 for empty session_id', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/start',
      payload: { session_id: '' },
    });

    expect(response.statusCode).toBe(400);
  });

  test('POST /start returns existing running sandbox', async () => {
    mockDocSend.mockResolvedValueOnce({
      Item: {
        conversation_id: 'conv-1',
        user_id: 'user-1',
        task_arn: 'arn:task',
        task_ip: '10.0.0.1',
        status: 'RUNNING',
        session_api_key: 'key-1',
        agent_server_port: 8000,
        sandbox_spec_id: 'img:latest',
        last_activity_at: 100,
        created_at: 50,
      },
    });

    const response = await app.inject({
      method: 'POST',
      url: '/start',
      payload: { session_id: 'conv-1' },
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.session_id).toBe('conv-1');
    expect(body.status).toBe('running');
    expect(body.url).toBe('http://10.0.0.1:8000');
  });

  test('GET /sessions/:session_id returns 404 when not found', async () => {
    mockDocSend.mockResolvedValueOnce({});

    const response = await app.inject({
      method: 'GET',
      url: '/sessions/nonexistent',
    });

    expect(response.statusCode).toBe(404);
  });

  test('GET /sessions/:session_id returns runtime info', async () => {
    mockDocSend.mockResolvedValueOnce({
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

    // verifyRunningRecords calls describeTasks for RUNNING records
    mockEcsSend.mockResolvedValueOnce({
      tasks: [{ taskArn: 'arn:task', lastStatus: 'RUNNING' }],
    });

    const response = await app.inject({
      method: 'GET',
      url: '/sessions/conv-1',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.session_id).toBe('conv-1');
    expect(body.status).toBe('running');
    expect(body.pod_status).toBe('ready');
    expect(body.user_id).toBe('user-1');
  });

  test('GET /sessions/batch returns array of runtimes', async () => {
    mockRawSend.mockResolvedValueOnce({
      Responses: {
        'test-table': [
          {
            conversation_id: { S: 'conv-1' },
            user_id: { S: 'user-1' },
            task_arn: { S: 'arn:task' },
            task_ip: { S: '10.0.0.1' },
            status: { S: 'RUNNING' },
            session_api_key: { S: 'key-1' },
            agent_server_port: { N: '8000' },
            sandbox_spec_id: { S: 'img' },
            last_activity_at: { N: '100' },
            created_at: { N: '50' },
          },
        ],
      },
      UnprocessedKeys: {},
    });

    // verifyRunningRecords calls describeTasks for RUNNING records
    mockEcsSend.mockResolvedValueOnce({
      tasks: [{ taskArn: 'arn:task', lastStatus: 'RUNNING' }],
    });

    const response = await app.inject({
      method: 'GET',
      url: '/sessions/batch?ids=conv-1',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(Array.isArray(body)).toBe(true);
    expect(body).toHaveLength(1);
    expect(body[0].session_id).toBe('conv-1');
  });

  test('GET /list returns runtimes array', async () => {
    mockDocSend.mockResolvedValueOnce({ Items: [] });

    const response = await app.inject({
      method: 'GET',
      url: '/list',
    });

    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.runtimes).toEqual([]);
  });

  test('POST /activity returns ok', async () => {
    mockDocSend.mockResolvedValueOnce({});

    const response = await app.inject({
      method: 'POST',
      url: '/activity',
      payload: { session_id: 'conv-1' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });

  test('POST /stop returns 404 when sandbox not found', async () => {
    mockDocSend.mockResolvedValueOnce({});

    const response = await app.inject({
      method: 'POST',
      url: '/stop',
      payload: { runtime_id: 'nonexistent' },
    });

    expect(response.statusCode).toBe(404);
  });

  test('POST /pause returns 404 when sandbox not found', async () => {
    mockDocSend.mockResolvedValueOnce({});

    const response = await app.inject({
      method: 'POST',
      url: '/pause',
      payload: { runtime_id: 'nonexistent' },
    });

    expect(response.statusCode).toBe(404);
  });

  test('POST /resume returns 404 when sandbox not found', async () => {
    mockDocSend.mockResolvedValueOnce({});

    const response = await app.inject({
      method: 'POST',
      url: '/resume',
      payload: { runtime_id: 'nonexistent' },
    });

    expect(response.statusCode).toBe(404);
  });
});
