/** ECS Fargate task management for sandbox containers. */

import {
  ECSClient,
  RunTaskCommand,
  StopTaskCommand,
  DescribeTasksCommand,
  ListTasksCommand,
} from '@aws-sdk/client-ecs';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { Agent } from 'node:http';
import type { RunTaskResult, TaskInfo, EcsTaskDescription } from './types.js';

export class EcsManager {
  private readonly ecs: ECSClient;
  private readonly clusterArn: string;
  private readonly taskDefinitionArn: string;
  private readonly subnets: string[];
  private readonly securityGroupId: string;

  constructor(opts: {
    clusterArn: string;
    taskDefinitionArn: string;
    subnets: string[];
    securityGroupId: string;
    region?: string;
  }) {
    this.clusterArn = opts.clusterArn;
    this.taskDefinitionArn = opts.taskDefinitionArn;
    this.subnets = opts.subnets.filter((s) => s.startsWith('subnet-'));
    if (!this.subnets.length) {
      throw new Error('No valid subnets configured for ECS tasks');
    }
    this.securityGroupId = opts.securityGroupId;
    this.ecs = new ECSClient({
      region: opts.region,
      requestHandler: new NodeHttpHandler({
        httpAgent: new Agent({ keepAlive: true, maxSockets: 50 }),
      }),
    });
  }

  async runTask(opts: {
    conversationId: string;
    userId: string;
    image: string;
    environment: Record<string, string>;
    sessionApiKey: string;
  }): Promise<RunTaskResult> {
    const envOverrides = Object.entries(opts.environment).map(([name, value]) => ({
      name,
      value,
    }));
    envOverrides.push(
      { name: 'CONVERSATION_ID', value: opts.conversationId },
      { name: 'USER_ID', value: opts.userId },
      { name: 'OH_SESSION_API_KEYS_0', value: opts.sessionApiKey },
    );

    const response = await this.ecs.send(
      new RunTaskCommand({
        cluster: this.clusterArn,
        taskDefinition: this.taskDefinitionArn,
        launchType: 'FARGATE',
        count: 1,
        networkConfiguration: {
          awsvpcConfiguration: {
            subnets: this.subnets,
            securityGroups: [this.securityGroupId],
            assignPublicIp: 'DISABLED',
          },
        },
        overrides: {
          containerOverrides: [
            {
              name: 'agent-server',
              environment: envOverrides,
            },
          ],
        },
        tags: [
          { key: 'conversation_id', value: opts.conversationId },
          { key: 'user_id', value: opts.userId },
          { key: 'ManagedBy', value: 'sandbox-orchestrator' },
        ],
        propagateTags: 'TASK_DEFINITION',
        enableECSManagedTags: true,
        enableExecuteCommand: false,
      }),
    );

    const failures = response.failures ?? [];
    if (failures.length > 0) {
      throw new Error(`ECS RunTask failed: ${failures[0].reason ?? 'Unknown'}`);
    }

    const tasks = response.tasks ?? [];
    if (!tasks.length) {
      throw new Error('ECS RunTask returned no tasks');
    }

    const task = tasks[0];
    return {
      task_arn: task.taskArn!,
      last_status: task.lastStatus ?? 'PROVISIONING',
    };
  }

  async stopTask(taskArn: string, reason = 'Sandbox stopped'): Promise<void> {
    await this.ecs.send(
      new StopTaskCommand({
        cluster: this.clusterArn,
        task: taskArn,
        reason,
      }),
    );
  }

  async describeTask(taskArn: string): Promise<TaskInfo | null> {
    const response = await this.ecs.send(
      new DescribeTasksCommand({
        cluster: this.clusterArn,
        tasks: [taskArn],
      }),
    );

    const tasks = response.tasks ?? [];
    if (!tasks.length) return null;

    const task = tasks[0];
    return {
      task_arn: task.taskArn!,
      last_status: task.lastStatus ?? 'UNKNOWN',
      desired_status: task.desiredStatus ?? 'UNKNOWN',
      task_ip: EcsManager.extractTaskIp(task),
      stopped_reason: task.stoppedReason ?? '',
    };
  }

  async waitForRunning(taskArn: string, timeoutSeconds = 120): Promise<string | null> {
    const start = Date.now();
    const pollInterval = 3000; // 3 seconds

    while (Date.now() - start < timeoutSeconds * 1000) {
      const info = await this.describeTask(taskArn);
      if (!info) return null;

      if (info.last_status === 'RUNNING' && info.task_ip) {
        return info.task_ip;
      }

      if (info.last_status === 'STOPPED' || info.last_status === 'DEPROVISIONING') {
        return null;
      }

      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    return null;
  }

  /** List tasks in a service. */
  async listServiceTasks(serviceName: string): Promise<string[]> {
    const response = await this.ecs.send(
      new ListTasksCommand({
        cluster: this.clusterArn,
        serviceName,
        desiredStatus: 'RUNNING',
      }),
    );
    return response.taskArns ?? [];
  }

  /** Describe multiple tasks at once. */
  async describeTasks(taskArns: string[]): Promise<EcsTaskDescription[]> {
    if (!taskArns.length) return [];
    const response = await this.ecs.send(
      new DescribeTasksCommand({
        cluster: this.clusterArn,
        tasks: taskArns,
      }),
    );
    return (response.tasks ?? []) as EcsTaskDescription[];
  }

  /** Extract private IP from task's ENI attachment. */
  static extractTaskIp(task: EcsTaskDescription): string | null {
    for (const attachment of task.attachments ?? []) {
      if (attachment.type === 'ElasticNetworkInterface') {
        for (const detail of attachment.details ?? []) {
          if (detail.name === 'privateIPv4Address') {
            return detail.value ?? null;
          }
        }
      }
    }
    return null;
  }
}
