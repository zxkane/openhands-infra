import { jest, describe, test, expect, beforeEach } from '@jest/globals';

const mockSend = jest.fn<any>();

jest.unstable_mockModule('@aws-sdk/client-efs', () => ({
  EFSClient: jest.fn().mockImplementation(() => ({ send: mockSend })),
  CreateAccessPointCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'CreateAccessPointCommand' })),
  DeleteAccessPointCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DeleteAccessPointCommand' })),
  DescribeAccessPointsCommand: jest.fn().mockImplementation((input: any) => ({ input, _type: 'DescribeAccessPointsCommand' })),
}));

jest.unstable_mockModule('@smithy/node-http-handler', () => ({
  NodeHttpHandler: jest.fn(),
}));

const { EfsManager } = await import('../src/efs-manager.js');

describe('EfsManager', () => {
  let manager: InstanceType<typeof EfsManager>;

  beforeEach(() => {
    jest.clearAllMocks();
    manager = new EfsManager({
      fileSystemId: 'fs-12345678',
      region: 'us-west-2',
    });
  });

  test('createAccessPoint sends correct command and returns ID', async () => {
    mockSend.mockResolvedValueOnce({
      AccessPointId: 'fsap-abc123',
    });

    const id = await manager.createAccessPoint('conv-123');

    expect(id).toBe('fsap-abc123');
    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.FileSystemId).toBe('fs-12345678');
    expect(cmd.input.RootDirectory.Path).toBe('/sandbox-workspace/conv-123');
    expect(cmd.input.PosixUser.Uid).toBe(1000);
    expect(cmd.input.PosixUser.Gid).toBe(1000);
    expect(cmd.input.RootDirectory.CreationInfo.OwnerUid).toBe(1000);
    expect(cmd.input.RootDirectory.CreationInfo.Permissions).toBe('0755');
    expect(cmd.input.Tags).toEqual(
      expect.arrayContaining([
        { Key: 'conversation_id', Value: 'conv-123' },
        { Key: 'ManagedBy', Value: 'sandbox-orchestrator' },
      ]),
    );
  });

  test('createAccessPoint throws when no ID returned', async () => {
    mockSend.mockResolvedValueOnce({});

    await expect(manager.createAccessPoint('conv-1')).rejects.toThrow('no AccessPointId');
  });

  test('deleteAccessPoint sends correct command', async () => {
    mockSend.mockResolvedValueOnce({});

    await manager.deleteAccessPoint('fsap-abc123');

    const cmd = mockSend.mock.calls[0][0] as any;
    expect(cmd.input.AccessPointId).toBe('fsap-abc123');
  });

  test('deleteAccessPoint handles AccessPointNotFound gracefully', async () => {
    const err = new Error('not found');
    (err as any).name = 'AccessPointNotFound';
    mockSend.mockRejectedValueOnce(err);

    await expect(manager.deleteAccessPoint('fsap-gone')).resolves.toBeUndefined();
  });

  test('deleteAccessPoint handles FileSystemNotFound gracefully', async () => {
    const err = new Error('not found');
    (err as any).name = 'FileSystemNotFound';
    mockSend.mockRejectedValueOnce(err);

    await expect(manager.deleteAccessPoint('fsap-gone')).resolves.toBeUndefined();
  });

  test('deleteAccessPoint rethrows other errors', async () => {
    mockSend.mockRejectedValueOnce(new Error('internal error'));

    await expect(manager.deleteAccessPoint('fsap-x')).rejects.toThrow('internal error');
  });

  test('waitForAvailable resolves when lifecycle is available', async () => {
    mockSend.mockResolvedValueOnce({
      AccessPoints: [{ LifeCycleState: 'available' }],
    });

    await expect(manager.waitForAvailable('fsap-abc', 5000)).resolves.toBeUndefined();
  });

  test('waitForAvailable throws on error state', async () => {
    mockSend.mockResolvedValueOnce({
      AccessPoints: [{ LifeCycleState: 'error' }],
    });

    await expect(manager.waitForAvailable('fsap-err', 5000)).rejects.toThrow('unexpected state: error');
  });

  test('waitForAvailable throws on timeout', async () => {
    // Always return 'creating' state
    mockSend.mockResolvedValue({
      AccessPoints: [{ LifeCycleState: 'creating' }],
    });

    await expect(manager.waitForAvailable('fsap-slow', 100)).rejects.toThrow('did not become available');
  });
});
