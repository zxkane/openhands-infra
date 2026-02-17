import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventsTargets from 'aws-cdk-lib/aws-events-targets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Construct } from 'constructs';
import * as path from 'path';
import {
  OpenHandsConfig,
  NetworkStackOutput,
  MonitoringStackOutput,
  SandboxStackOutput,
} from './interfaces.js';

const WARM_POOL_SIZE_DEFAULT = 2;

export interface SandboxStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
  monitoringOutput: MonitoringStackOutput;
  /** Enable sandbox AWS access — Bedrock and S3 permissions on task role */
  sandboxAwsAccess?: boolean;
  /** EFS file system ID for workspace persistence (from ComputeStack) */
  workspaceFileSystemId?: string;
  /** EFS access point ID for workspace (from ComputeStack) */
  workspaceAccessPointId?: string;
  /** Number of warm pool tasks to keep pre-started (default: 2) */
  warmPoolSize?: number;
}

/**
 * SandboxStack - ECS Fargate Sandbox Infrastructure
 *
 * Creates the infrastructure for running OpenHands sandbox containers on Fargate:
 * - ECS Cluster for sandbox tasks
 * - Fargate Task Definition for sandbox containers
 * - DynamoDB table for sandbox registry (conversation → task mapping)
 * - Sandbox Orchestrator ECR image
 * - Idle Monitor Lambda with EventBridge schedule
 * - Security groups and IAM roles
 */
export class SandboxStack extends cdk.Stack {
  public readonly output: SandboxStackOutput;

  constructor(scope: Construct, id: string, props: SandboxStackProps) {
    super(scope, id, props);

    const { config, networkOutput, monitoringOutput } = props;
    const { vpc } = networkOutput;
    const { alertTopic } = monitoringOutput;

    // Name prefix derived from domain to support multi-environment deployments
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const namePrefix = fullDomain.replace(/\./g, '-');

    // ========================================
    // ECS Cluster
    // ========================================
    const cluster = new ecs.Cluster(this, 'SandboxCluster', {
      vpc,
      clusterName: `${namePrefix}-sandbox`,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });
    // Enable tag propagation: CDK app-level tags (Project, STAGE, Purpose, ManagedBy)
    // are propagated to ECS tasks via the cluster's defaultCloudMapNamespace and task tags
    cdk.Tags.of(cluster).add('Component', 'sandbox');

    // ========================================
    // DynamoDB Sandbox Registry
    // ========================================
    const registryTable = new dynamodb.Table(this, 'SandboxRegistry', {
      tableName: `${namePrefix}-sandbox-registry`,
      partitionKey: {
        name: 'conversation_id',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      timeToLiveAttribute: 'ttl',
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
    });

    // GSI for querying by user_id (multi-tenancy: list my sandboxes)
    registryTable.addGlobalSecondaryIndex({
      indexName: 'user_id-index',
      partitionKey: {
        name: 'user_id',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'created_at',
        type: dynamodb.AttributeType.NUMBER,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // GSI for querying by status (idle detection: find running sandboxes)
    registryTable.addGlobalSecondaryIndex({
      indexName: 'status-index',
      partitionKey: {
        name: 'status',
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: 'last_activity_at',
        type: dynamodb.AttributeType.NUMBER,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // ========================================
    // Security Group for Sandbox Fargate Tasks
    // ========================================
    const sandboxTaskSg = new ec2.SecurityGroup(this, 'SandboxTaskSg', {
      vpc,
      description: 'Security group for sandbox Fargate tasks',
      allowAllOutbound: true,
    });

    // Allow inbound from sandbox tasks to other sandbox tasks (inter-sandbox)
    sandboxTaskSg.addIngressRule(
      sandboxTaskSg,
      ec2.Port.tcpRange(1, 65535),
      'Allow inter-sandbox communication'
    );

    // NOTE: EC2 ↔ sandbox SG rules (ingress + egress) are added in ComputeStack
    // to avoid cyclic cross-stack dependency between SecurityStack and SandboxStack

    // ========================================
    // Sandbox Task IAM Roles
    // ========================================

    // Execution role: used by ECS agent to pull images, write logs, read secrets
    const sandboxExecutionRole = new iam.Role(this, 'SandboxExecutionRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Execution role for sandbox Fargate tasks (image pull, logs)',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    // Grant access to sandbox secret key
    // Reference sandbox secret key by well-known name (avoids cross-stack token reference)
    const sandboxSecretKeyName = 'openhands/sandbox-secret-key';
    const sandboxSecretKey = secretsmanager.Secret.fromSecretNameV2(
      this, 'SandboxSecretKeyRef', sandboxSecretKeyName
    );
    sandboxSecretKey.grantRead(sandboxExecutionRole);

    // Task role: used by the sandbox container itself
    const sandboxTaskRole = new iam.Role(this, 'SandboxTaskRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Task role for sandbox Fargate tasks (runtime permissions)',
    });

    // EFS access for workspace persistence
    if (props.workspaceFileSystemId) {
      sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
        sid: 'EfsWorkspaceAccess',
        effect: iam.Effect.ALLOW,
        actions: [
          'elasticfilesystem:ClientMount',
          'elasticfilesystem:ClientWrite',
          'elasticfilesystem:ClientRootAccess',
        ],
        resources: ['*'],
        conditions: {
          Bool: { 'elasticfilesystem:AccessedViaMountTarget': 'true' },
        },
      }));
    }

    // AWS permissions for sandbox containers (gated by sandboxAwsAccess context flag)
    if (props.sandboxAwsAccess) {
      sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
        sid: 'BedrockAccess',
        effect: iam.Effect.ALLOW,
        actions: [
          'bedrock:InvokeModel',
          'bedrock:InvokeModelWithResponseStream',
        ],
        resources: [
          'arn:aws:bedrock:*::foundation-model/anthropic.claude-*',
          'arn:aws:bedrock:*::foundation-model/us.anthropic.claude-*',
          `arn:aws:bedrock:${config.region}:${this.account}:inference-profile/*anthropic.claude*`,
          `arn:aws:bedrock:*:${this.account}:inference-profile/global.anthropic.claude*`,
        ],
      }));

      sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
        sid: 'S3DataBucketAccess',
        effect: iam.Effect.ALLOW,
        actions: [
          's3:GetObject',
          's3:PutObject',
          's3:DeleteObject',
          's3:ListBucket',
        ],
        resources: [
          monitoringOutput.dataBucket.bucketArn,
          `${monitoringOutput.dataBucket.bucketArn}/*`,
        ],
      }));
    }

    // ========================================
    // Sandbox CloudWatch Log Group
    // ========================================
    const sandboxLogGroup = new logs.LogGroup(this, 'SandboxLogGroup', {
      logGroupName: '/openhands/sandbox',
      retention: logs.RetentionDays.TWO_WEEKS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ========================================
    // Sandbox Fargate Task Definition
    // ========================================
    const sandboxTaskDefinition = new ecs.FargateTaskDefinition(this, 'SandboxTaskDef', {
      family: 'openhands-sandbox',
      cpu: 2048,    // 2 vCPU
      memoryLimitMiB: 4096,  // 4 GB
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
      executionRole: sandboxExecutionRole,
      taskRole: sandboxTaskRole,
    });

    // Mount EFS workspace volume for persistent storage across conversation resume
    // Shares the same EFS as the EC2 host — sandbox tasks can access previous workspace files
    if (props.workspaceFileSystemId && props.workspaceAccessPointId) {
      sandboxTaskDefinition.addVolume({
        name: 'workspace',
        efsVolumeConfiguration: {
          fileSystemId: props.workspaceFileSystemId,
          transitEncryption: 'ENABLED',
          authorizationConfig: {
            accessPointId: props.workspaceAccessPointId,
            iam: 'ENABLED',
          },
        },
      });
    }

    // Agent-server container (main sandbox container)
    const agentServerContainer = sandboxTaskDefinition.addContainer('agent-server', {
      containerName: 'agent-server',
      image: ecs.ContainerImage.fromAsset(path.join(__dirname, '..', 'docker', 'agent-server-custom'), {
        platform: Platform.LINUX_ARM64,
      }),
      essential: true,
      // Override entrypoint: skip /sbin/docker-init (not available in Fargate)
      // Fargate uses initProcessEnabled instead for PID 1 signal handling
      // Init git repo in workspace (required by /api/git/changes endpoint)
      entryPoint: ['/bin/sh', '-c'],
      command: ['git init /workspace/project 2>/dev/null || true; exec /usr/local/bin/openhands-agent-server --port 8000'],
      linuxParameters: new ecs.LinuxParameters(this, 'SandboxLinuxParams', {
        initProcessEnabled: true,  // Replaces Docker's --init flag
      }),
      portMappings: [
        { containerPort: 8000, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'sandbox',
        logGroup: sandboxLogGroup,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:8000/alive || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(10),
        retries: 3,
        startPeriod: cdk.Duration.seconds(60),
      },
      environment: {
        AWS_DEFAULT_REGION: config.region,
      },
      secrets: {
        OH_SECRET_KEY: ecs.Secret.fromSecretsManager(sandboxSecretKey),
      },
    });

    // Mount EFS workspace into the container at /workspace
    if (props.workspaceFileSystemId) {
      agentServerContainer.addMountPoints({
        sourceVolume: 'workspace',
        containerPath: '/workspace',
        readOnly: false,
      });
    }

    // ========================================
    // Warm Pool ECS Service
    // ========================================
    // ECS Service maintains desiredCount of pre-started sandbox tasks.
    // Built-in replenishment: when a task is stopped (conversation ended or idle timeout),
    // ECS automatically starts a replacement — no custom background thread needed.
    const warmPoolSize = props.warmPoolSize ?? WARM_POOL_SIZE_DEFAULT;
    const warmPoolService = new ecs.FargateService(this, 'WarmPoolService', {
      cluster,
      serviceName: `${namePrefix}-sandbox-warm-pool`,
      taskDefinition: sandboxTaskDefinition,
      desiredCount: warmPoolSize,
      minHealthyPercent: 0,    // Allow all tasks to be replaced during deployments
      maxHealthyPercent: 200,  // Allow temporary doubling during rolling update
      vpcSubnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),
      securityGroups: [sandboxTaskSg],
      assignPublicIp: false,
      enableECSManagedTags: true,
      propagateTags: ecs.PropagatedTagSource.TASK_DEFINITION,
    });
    cdk.Tags.of(warmPoolService).add('Component', 'sandbox-warm-pool');

    // NOTE: Orchestrator runs as a docker-compose sidecar on EC2 — it inherits the
    // EC2 instance role. ECS/DynamoDB permissions are added to EC2 role in ComputeStack
    // to avoid cyclic cross-stack references between SecurityStack and SandboxStack.

    // ========================================
    // Sandbox Orchestrator Docker Image
    // ========================================
    const orchestratorImage = new DockerImageAsset(this, 'OrchestratorImage', {
      directory: path.join(__dirname, '..', 'services', 'sandbox-orchestrator'),
      platform: Platform.LINUX_ARM64,
    });

    // NOTE: EC2 role pull access for orchestrator image is granted in ComputeStack
    // to avoid cyclic cross-stack dependency

    // ========================================
    // Idle Monitor Lambda
    // ========================================
    const idleMonitorLambda = new lambda.Function(this, 'IdleMonitorLambda', {
      functionName: 'openhands-sandbox-idle-monitor',
      runtime: lambda.Runtime.NODEJS_22_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda', 'sandbox-monitor')),
      timeout: cdk.Duration.minutes(2),
      memorySize: 256,
      architecture: lambda.Architecture.ARM_64,
      environment: {
        REGISTRY_TABLE_NAME: registryTable.tableName,
        ECS_CLUSTER_ARN: cluster.clusterArn,
        IDLE_TIMEOUT_MINUTES: '30',
        AWS_REGION_NAME: config.region,
        LOG_LEVEL: 'INFO',
        POWERTOOLS_SERVICE_NAME: 'sandbox-idle-monitor',
      },
    });

    // Lambda needs DynamoDB and ECS permissions
    registryTable.grantReadWriteData(idleMonitorLambda);
    idleMonitorLambda.addToRolePolicy(new iam.PolicyStatement({
      sid: 'EcsStopIdleTasks',
      effect: iam.Effect.ALLOW,
      actions: ['ecs:StopTask', 'ecs:DescribeTasks', 'ecs:ListTasks'],
      resources: ['*'],
      conditions: {
        ArnEquals: {
          'ecs:cluster': cluster.clusterArn,
        },
      },
    }));

    // CloudWatch metrics permission for publishing idle stats
    idleMonitorLambda.addToRolePolicy(new iam.PolicyStatement({
      sid: 'CloudWatchMetrics',
      effect: iam.Effect.ALLOW,
      actions: ['cloudwatch:PutMetricData'],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'cloudwatch:namespace': 'OpenHands/Sandbox',
        },
      },
    }));

    // EventBridge rule: run idle monitor every 5 minutes
    new events.Rule(this, 'IdleMonitorSchedule', {
      schedule: events.Schedule.rate(cdk.Duration.minutes(5)),
      targets: [new eventsTargets.LambdaFunction(idleMonitorLambda)],
      description: 'Trigger sandbox idle monitor to stop inactive tasks',
    });

    // ========================================
    // CloudWatch Alarms
    // ========================================
    const sandboxCreationFailureAlarm = new cloudwatch.Alarm(this, 'SandboxCreationFailureAlarm', {
      alarmDescription: 'Sandbox creation failures detected',
      metric: new cloudwatch.Metric({
        namespace: 'OpenHands/Sandbox',
        metricName: 'SandboxCreationFailures',
        statistic: 'Sum',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 3,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    sandboxCreationFailureAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // ========================================
    // Outputs
    // ========================================
    this.output = {
      clusterArn: cluster.clusterArn,
      clusterName: cluster.clusterName,
      registryTableName: registryTable.tableName,
      registryTableArn: registryTable.tableArn,
      taskDefinitionFamily: 'openhands-sandbox',  // Matches family in task definition
      sandboxTaskSecurityGroupId: sandboxTaskSg.securityGroupId,
      // Use Docker Compose service name for inter-container communication
      orchestratorApiUrl: 'http://sandbox-orchestrator:8081',
      sandboxLogGroupName: sandboxLogGroup.logGroupName,
      warmPoolSize: warmPoolSize,
      warmPoolServiceName: warmPoolService.serviceName,
      orchestratorImageUri: orchestratorImage.imageUri,
      sandboxExecutionRoleArn: sandboxExecutionRole.roleArn,
      sandboxTaskRoleArn: sandboxTaskRole.roleArn,
    };

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: cluster.clusterArn,
      description: 'ECS Cluster ARN for sandbox tasks',
    });

    new cdk.CfnOutput(this, 'RegistryTableName', {
      value: registryTable.tableName,
      description: 'DynamoDB table for sandbox registry',
    });

    new cdk.CfnOutput(this, 'TaskDefinitionFamily', {
      value: 'openhands-sandbox',
      description: 'Sandbox Fargate task definition family name',
    });

    new cdk.CfnOutput(this, 'SandboxTaskSecurityGroupId', {
      value: sandboxTaskSg.securityGroupId,
      description: 'Security group ID for sandbox Fargate tasks',
    });

    new cdk.CfnOutput(this, 'OrchestratorImageUri', {
      value: orchestratorImage.imageUri,
      description: 'Sandbox Orchestrator Docker image URI',
    });
  }
}
