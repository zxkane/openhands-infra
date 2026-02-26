/** EFS access point lifecycle manager for per-conversation sandbox isolation. */

import {
  EFSClient,
  CreateAccessPointCommand,
  DeleteAccessPointCommand,
  DescribeAccessPointsCommand,
} from '@aws-sdk/client-efs';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { Agent } from 'node:http';

export class EfsManager {
  private readonly efs: EFSClient;
  private readonly fileSystemId: string;

  constructor(opts: { fileSystemId: string; region?: string }) {
    this.fileSystemId = opts.fileSystemId;
    this.efs = new EFSClient({
      region: opts.region,
      requestHandler: new NodeHttpHandler({
        httpAgent: new Agent({ keepAlive: true, maxSockets: 50 }),
      }),
    });
  }

  /**
   * Create an EFS access point rooted at /sandbox-workspace/<conversationId>.
   * The access point enforces uid/gid 1000 (openhands user) and physically
   * restricts the mount to the conversation directory — the container cannot
   * traverse to parent directories or other conversations.
   */
  async createAccessPoint(conversationId: string): Promise<string> {
    // Defense-in-depth: reject path-unsafe characters to prevent path traversal
    if (!/^[a-zA-Z0-9_-]+$/.test(conversationId)) {
      throw new Error(`Invalid conversation ID for EFS path: ${conversationId}`);
    }

    const response = await this.efs.send(
      new CreateAccessPointCommand({
        FileSystemId: this.fileSystemId,
        PosixUser: { Uid: 1000, Gid: 1000 },
        RootDirectory: {
          Path: `/sandbox-workspace/${conversationId}`,
          CreationInfo: {
            OwnerUid: 1000,
            OwnerGid: 1000,
            Permissions: '0755',
          },
        },
        Tags: [
          { Key: 'conversation_id', Value: conversationId },
          { Key: 'ManagedBy', Value: 'sandbox-orchestrator' },
        ],
      }),
    );

    if (!response.AccessPointId) {
      throw new Error('EFS CreateAccessPoint returned no AccessPointId');
    }
    return response.AccessPointId;
  }

  /**
   * Delete an EFS access point. Handles NotFound gracefully (already deleted).
   */
  async deleteAccessPoint(accessPointId: string): Promise<void> {
    try {
      await this.efs.send(
        new DeleteAccessPointCommand({ AccessPointId: accessPointId }),
      );
    } catch (err: any) {
      if (err.name === 'AccessPointNotFound' || err.name === 'FileSystemNotFound') {
        return; // Already deleted — idempotent
      }
      throw err;
    }
  }

  /**
   * Poll until the access point lifecycle state is 'available'.
   * EFS access points are typically available within a few seconds.
   */
  async waitForAvailable(accessPointId: string, timeoutMs = 15000): Promise<void> {
    const start = Date.now();
    const pollInterval = 500;

    while (Date.now() - start < timeoutMs) {
      const response = await this.efs.send(
        new DescribeAccessPointsCommand({ AccessPointId: accessPointId }),
      );

      const ap = response.AccessPoints?.[0];
      if (ap?.LifeCycleState === 'available') {
        return;
      }
      if (ap?.LifeCycleState === 'error' || ap?.LifeCycleState === 'deleted') {
        throw new Error(`Access point ${accessPointId} in unexpected state: ${ap.LifeCycleState}`);
      }

      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    throw new Error(`Access point ${accessPointId} did not become available within ${timeoutMs}ms`);
  }
}
