import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNode from 'aws-cdk-lib/aws-lambda-nodejs';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventsTargets from 'aws-cdk-lib/aws-events-targets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';
import {
  OpenHandsConfig,
  NetworkStackOutput,
  MonitoringStackOutput,
  ClusterStackOutput,
  SandboxStackOutput,
} from './interfaces.js';

export interface SandboxStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
  monitoringOutput: MonitoringStackOutput;
  /** Shared ECS cluster and Cloud Map namespace from ClusterStack */
  clusterOutput: ClusterStackOutput;
  /** Enable sandbox AWS access — custom IAM policy on task role */
  sandboxAwsAccess?: boolean;
  /** Path to custom policy JSON file for sandbox AWS access (default: config/sandbox-aws-policy.json) */
  sandboxAwsPolicyFile?: string;
  /** Security group for EFS access (from SecurityStack) */
  efsSecurityGroup?: ec2.ISecurityGroup;
  /** Number of warm pool tasks to keep pre-started (default: 2) */
  warmPoolSize?: number;
  /** Idle timeout in minutes before sandbox is stopped (default: 30) */
  idleTimeoutMinutes?: number;
  /** Retention period in days before inactive conversations are archived (default: 180) */
  conversationRetentionDays?: number;
  /** S3 data bucket for conversation events (deletion Lambda needs access) */
  dataBucket?: s3.IBucket;
  /** Secrets Manager secret name for Aurora admin credentials (deletion Lambda) */
  databaseSecretName?: string;
  /** Database name (deletion Lambda) */
  databaseName?: string;
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

    const { config, networkOutput, monitoringOutput, clusterOutput } = props;
    const { vpc } = networkOutput;
    const { alertTopic } = monitoringOutput;
    const { cluster, namespace } = clusterOutput;

    // Name prefix derived from domain to support multi-environment deployments
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const namePrefix = fullDomain.replace(/\./g, '-');

    const retentionDays = props.conversationRetentionDays ?? 180;

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
      // TTL disabled: conversation lifecycle is managed by the archival Lambda,
      // not DynamoDB auto-deletion. Auto-deletion would bypass EFS/S3 cleanup.
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

    // NOTE: No self-referencing ingress rule — sandbox tasks are intentionally
    // isolated from each other. Only the app service (via appServiceSg, added in
    // ComputeStack) can reach sandbox tasks. This prevents cross-sandbox attacks
    // (reading other users' code, accessing other agent-servers, etc.).

    // NOTE: App service ↔ sandbox SG rules (ingress + egress) are added in ComputeStack
    // to avoid cyclic cross-stack dependency between SecurityStack and SandboxStack

    // ========================================
    // Workspace EFS (per-conversation persistence)
    // ========================================
    // Shared by all Fargate sandbox tasks. Each task mounts EFS at /mnt/efs and
    // creates /mnt/efs/<CONVERSATION_ID>/ → symlinked to /workspace in the entrypoint.
    const workspaceEfsSg = new ec2.SecurityGroup(this, 'WorkspaceEfsSg', {
      vpc,
      description: 'Security group for sandbox workspace EFS',
      allowAllOutbound: false,
    });
    // Allow NFS from sandbox tasks
    workspaceEfsSg.addIngressRule(
      sandboxTaskSg,
      ec2.Port.tcp(2049),
      'Allow NFS from sandbox Fargate tasks'
    );

    const workspaceFileSystem = new efs.FileSystem(this, 'WorkspaceEfs', {
      vpc,
      vpcSubnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),
      securityGroup: workspaceEfsSg,
      encrypted: true,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
      throughputMode: efs.ThroughputMode.BURSTING,
      lifecyclePolicy: efs.LifecyclePolicy.AFTER_14_DAYS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    cdk.Tags.of(workspaceFileSystem).add('Component', 'sandbox-workspace');

    const workspaceAccessPoint = new efs.AccessPoint(this, 'WorkspaceAccessPoint', {
      fileSystem: workspaceFileSystem,
      path: '/sandbox-workspace',
      posixUser: { uid: '1000', gid: '1000' },  // openhands user
      createAcl: { ownerUid: '1000', ownerGid: '1000', permissions: '0755' },
    });

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
    sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EfsWorkspaceAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'elasticfilesystem:ClientMount',
        'elasticfilesystem:ClientWrite',
      ],
      resources: [workspaceFileSystem.fileSystemArn],
      conditions: {
        Bool: { 'elasticfilesystem:AccessedViaMountTarget': 'true' },
      },
    }));

    // Bedrock access for LLM inference (ALWAYS granted — required for agent-server LLM calls)
    // Covers 1P (Amazon), Anthropic Claude, and 2P/3P models available on Bedrock.
    // Users can select models via settings; this policy permits all Bedrock models.
    sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BedrockModelAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'bedrock:InvokeModel',
        'bedrock:InvokeModelWithResponseStream',
      ],
      resources: [
        // Foundation models — all providers (1P Amazon, Anthropic, Meta, Mistral, Cohere, AI21, etc.)
        'arn:aws:bedrock:*::foundation-model/*',
        // Cross-region inference profiles (global, us, eu, apac prefixes)
        `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
        // Application inference profiles (for cost tracking per user/team)
        `arn:aws:bedrock:${config.region}:${this.account}:application-inference-profile/*`,
      ],
    }));

    // Bedrock model discovery for agent-server LLM calls
    sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BedrockModelDiscovery',
      effect: iam.Effect.ALLOW,
      actions: [
        'bedrock:ListFoundationModels',
        'bedrock:ListInferenceProfiles',
        'bedrock:GetInferenceProfile',
      ],
      resources: ['*'], // List/Get operations don't support resource-level restrictions
    }));

    // AWS permissions for sandbox containers (gated by sandboxAwsAccess context flag)
    // Loads custom IAM policy from sandbox-aws-policy.json (same policy used by SecurityStack
    // for the STS-assumed sandbox role in Docker-on-EC2 mode)
    if (props.sandboxAwsAccess) {
      // Load custom allow policy (same as SecurityStack's STS-assumed sandbox role)
      const policyFilePath = props.sandboxAwsPolicyFile || path.join(process.cwd(), 'config', 'sandbox-aws-policy.json');
      if (!fs.existsSync(policyFilePath)) {
        throw new Error(`Sandbox AWS policy file not found: ${policyFilePath}`);
      }
      const policyDoc = JSON.parse(fs.readFileSync(policyFilePath, 'utf-8'));
      for (const statement of policyDoc.Statement || []) {
        sandboxTaskRole.addToPolicy(iam.PolicyStatement.fromJson(statement));
      }

      // Explicit deny guardrails (ALWAYS applied, cannot be overridden by allow policy)
      // Mirrors SecurityStack's DenySensitiveOperations for the STS-assumed sandbox role
      sandboxTaskRole.addToPolicy(new iam.PolicyStatement({
        sid: 'DenySensitiveOperations',
        effect: iam.Effect.DENY,
        actions: [
          'iam:CreateUser', 'iam:DeleteUser',
          'iam:CreateAccessKey', 'iam:DeleteAccessKey', 'iam:UpdateAccessKey',
          'iam:AttachUserPolicy', 'iam:DetachUserPolicy', 'iam:PutUserPolicy', 'iam:DeleteUserPolicy',
          'iam:AttachRolePolicy', 'iam:DetachRolePolicy', 'iam:PutRolePolicy', 'iam:DeleteRolePolicy',
          'iam:CreateRole', 'iam:DeleteRole', 'iam:UpdateAssumeRolePolicy',
          'organizations:*', 'account:*', 'billing:*',
          'sts:AssumeRole',
        ],
        resources: ['*'],
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

    // EFS volume for per-conversation workspace persistence across task restarts
    sandboxTaskDefinition.addVolume({
      name: 'workspace',
      efsVolumeConfiguration: {
        fileSystemId: workspaceFileSystem.fileSystemId,
        transitEncryption: 'ENABLED',
        authorizationConfig: {
          accessPointId: workspaceAccessPoint.accessPointId,
          iam: 'ENABLED',
        },
      },
    });

    // Sandbox agent-server image (DockerImageAsset for ECR URI export + SOCI index generation)
    const sandboxImageAsset = new DockerImageAsset(this, 'SandboxAgentServerImage', {
      directory: path.join(__dirname, '..', 'docker', 'agent-server-custom'),
      platform: Platform.LINUX_ARM64,
    });

    // Agent-server container (main sandbox container)
    const agentServerContainer = sandboxTaskDefinition.addContainer('agent-server', {
      containerName: 'agent-server',
      image: ecs.ContainerImage.fromDockerImageAsset(sandboxImageAsset),
      essential: true,
      // Override entrypoint: skip /sbin/docker-init (not available in Fargate)
      // Fargate uses initProcessEnabled instead for PID 1 signal handling
      // Per-conversation EFS isolation via dynamic access points:
      //   1. Orchestrator creates EFS access point at /sandbox-workspace/<CID>
      //   2. Task definition uses per-conversation access point (container sees /mnt/efs as CID root)
      //   3. Symlink /workspace/project → /mnt/efs/project for agent code persistence
      //   4. If EFS not mounted (warm pool fallback), use local workspace
      entryPoint: ['/bin/sh', '-c'],
      command: [
        // Per-conversation EFS isolation via dynamic access points:
        // - Each sandbox mounts an EFS access point rooted at /sandbox-workspace/<CID>
        // - /mnt/efs IS the conversation directory — no traversal to other conversations
        // - Create /mnt/efs/project for agent code persistence on EFS
        // - OH_CONVERSATIONS_PATH=/mnt/efs persists conversation state across restarts
        'if mountpoint -q /mnt/efs 2>/dev/null; then ' +
          'mkdir -p /mnt/efs/project;' +
          'rm -rf /workspace/project;' +
          'ln -s /mnt/efs/project /workspace/project;' +
          'export OH_CONVERSATIONS_PATH=/mnt/efs;' +
        'else ' +
          'mkdir -p /workspace/project;' +
        'fi;' +
        'git init /workspace 2>/dev/null;' +
        'printf "bash_events/\\nconversations/\\n*.pyc\\n__pycache__/\\n" > /workspace/.gitignore;' +
        'cd /workspace && git add .gitignore && git -c user.name=openhands -c user.email=oh@local commit -qm init 2>/dev/null;' +
        'git init /workspace/project 2>/dev/null;' +
        'exec /usr/local/bin/openhands-agent-server --port 8000'
      ],
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

    // Mount EFS at /mnt/efs — per-conversation access point roots to /sandbox-workspace/<CID>
    agentServerContainer.addMountPoints({
      sourceVolume: 'workspace',
      containerPath: '/mnt/efs',
      readOnly: false,
    });

    // ========================================
    // Warm Pool ECS Service (disabled — desiredCount=0)
    // ========================================
    // Warm pool disabled: sandbox tasks now use RunTask with CONVERSATION_ID for
    // per-conversation EFS workspace isolation. Warm pool tasks can't mount the
    // correct workspace because CONVERSATION_ID isn't known at startup.
    // The Service construct is retained (desiredCount=0) to avoid CloudFormation
    // deletion issues with cross-stack exports.
    const warmPoolSize = 0;
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

    // ========================================
    // Sandbox Orchestrator Docker Image
    // ========================================
    const orchestratorImage = new DockerImageAsset(this, 'OrchestratorImage', {
      directory: path.join(__dirname, '..', 'services', 'sandbox-orchestrator'),
      platform: Platform.LINUX_ARM64,
    });

    // ========================================
    // Orchestrator Security Group
    // ========================================
    const orchestratorSg = new ec2.SecurityGroup(this, 'OrchestratorSg', {
      vpc,
      description: 'Security group for sandbox orchestrator Fargate service',
      allowAllOutbound: true,
    });
    // NOTE: Inbound rule from app service SG is added in ComputeStack to avoid cyclic dependency

    // ========================================
    // Orchestrator Fargate Task Definition
    // ========================================
    const orchestratorTaskDef = new ecs.FargateTaskDefinition(this, 'OrchestratorTaskDef', {
      family: 'openhands-sandbox-orchestrator',
      cpu: 512,      // 0.5 vCPU
      memoryLimitMiB: 1024,  // 1 GB
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
    });

    // Orchestrator task role needs ECS + DynamoDB + EFS permissions
    // RunTask scoped to sandbox task definition family (wildcard for dynamic revisions)
    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EcsRunSandboxTask',
      effect: iam.Effect.ALLOW,
      actions: ['ecs:RunTask'],
      resources: [
        `arn:aws:ecs:${this.region}:${this.account}:task-definition/openhands-sandbox:*`,
      ],
    }));

    // EFS access point management for per-conversation isolation
    // CreateAccessPoint + TagResource target the file system ARN;
    // DeleteAccessPoint + DescribeAccessPoints target access point ARNs
    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EfsAccessPointManagement',
      effect: iam.Effect.ALLOW,
      actions: [
        'elasticfilesystem:CreateAccessPoint',
        'elasticfilesystem:DeleteAccessPoint',
        'elasticfilesystem:DescribeAccessPoints',
        'elasticfilesystem:TagResource',
      ],
      resources: [
        workspaceFileSystem.fileSystemArn,
        `arn:aws:elasticfilesystem:${this.region}:${this.account}:access-point/*`,
      ],
    }));

    // ECS task definition management for per-conversation access point binding
    // resources: ['*'] is required — these ECS actions do not support resource-level permissions
    // (AWS limitation). Blast radius is limited by iam:PassRole scoped to sandbox roles only.
    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EcsTaskDefinitionManagement',
      effect: iam.Effect.ALLOW,
      actions: [
        'ecs:RegisterTaskDefinition',
        'ecs:DescribeTaskDefinition',
        'ecs:DeregisterTaskDefinition',
        'ecs:TagResource',
      ],
      resources: ['*'],
    }));

    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EcsSandboxManagement',
      effect: iam.Effect.ALLOW,
      actions: [
        'ecs:StopTask',
        'ecs:DescribeTasks',
        'ecs:ListTasks',
        'ecs:TagResource',
      ],
      resources: ['*'],
      conditions: {
        ArnEquals: {
          'ecs:cluster': cluster.clusterArn,
        },
      },
    }));

    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'PassSandboxRoles',
      effect: iam.Effect.ALLOW,
      actions: ['iam:PassRole'],
      resources: [
        sandboxExecutionRole.roleArn,
        sandboxTaskRole.roleArn,
      ],
    }));

    registryTable.grantReadWriteData(orchestratorTaskDef.taskRole);

    // Orchestrator container
    orchestratorTaskDef.addContainer('orchestrator', {
      containerName: 'orchestrator',
      image: ecs.ContainerImage.fromDockerImageAsset(orchestratorImage),
      essential: true,
      portMappings: [
        { containerPort: 8081, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'orchestrator',
        logGroup: new logs.LogGroup(this, 'OrchestratorLogGroup', {
          logGroupName: '/openhands/sandbox-orchestrator',
          retention: logs.RetentionDays.TWO_WEEKS,
          removalPolicy: cdk.RemovalPolicy.DESTROY,
        }),
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'wget -qO- http://localhost:8081/health || exit 1'],
        interval: cdk.Duration.seconds(15),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(30),
      },
      environment: {
        REGISTRY_TABLE_NAME: registryTable.tableName,
        ECS_CLUSTER_ARN: cluster.clusterArn,
        TASK_DEFINITION_FAMILY: 'openhands-sandbox',
        SUBNETS: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }).subnetIds.join(','),
        SECURITY_GROUP_ID: sandboxTaskSg.securityGroupId,
        AWS_REGION_NAME: config.region,
        AWS_DEFAULT_REGION: config.region,
        SANDBOX_IMAGE: '', // Set by ComputeStack via CDK output
        WARM_POOL_SERVICE_NAME: warmPoolService.serviceName,
        EFS_FILE_SYSTEM_ID: workspaceFileSystem.fileSystemId,
        // DELETION_LAMBDA_ARN is set below after the deletion Lambda is created
      },
    });

    // ========================================
    // Orchestrator Fargate Service (with Cloud Map)
    // ========================================
    const orchestratorDnsName = 'orchestrator';
    const orchestratorService = new ecs.FargateService(this, 'OrchestratorService', {
      cluster,
      serviceName: `${namePrefix}-sandbox-orchestrator`,
      taskDefinition: orchestratorTaskDef,
      desiredCount: 1,
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      vpcSubnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),
      securityGroups: [orchestratorSg],
      assignPublicIp: false,
      enableECSManagedTags: true,
      propagateTags: ecs.PropagatedTagSource.TASK_DEFINITION,
      cloudMapOptions: {
        name: orchestratorDnsName,
        cloudMapNamespace: namespace,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: cdk.Duration.seconds(10),
      },
    });
    cdk.Tags.of(orchestratorService).add('Component', 'sandbox-orchestrator');

    // ========================================
    // Idle Monitor Lambda
    // ========================================
    const idleMonitorLambda = new lambdaNode.NodejsFunction(this, 'IdleMonitorLambda', {
      functionName: 'openhands-sandbox-idle-monitor',
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: path.join(__dirname, '..', 'lambda', 'sandbox-monitor', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.minutes(2),
      memorySize: 256,
      architecture: lambda.Architecture.ARM_64,
      bundling: { minify: true, sourceMap: true },
      environment: {
        REGISTRY_TABLE_NAME: registryTable.tableName,
        ECS_CLUSTER_ARN: cluster.clusterArn,
        IDLE_TIMEOUT_MINUTES: String(props.idleTimeoutMinutes ?? 30),
        SANDBOX_TASK_FAMILY: 'openhands-sandbox',
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

    // EFS access point cleanup for per-conversation isolation
    // DeleteAccessPoint + DescribeAccessPoints target access point ARNs
    idleMonitorLambda.addToRolePolicy(new iam.PolicyStatement({
      sid: 'EfsAccessPointCleanup',
      effect: iam.Effect.ALLOW,
      actions: [
        'elasticfilesystem:DeleteAccessPoint',
        'elasticfilesystem:DescribeAccessPoints',
      ],
      resources: [
        workspaceFileSystem.fileSystemArn,
        `arn:aws:elasticfilesystem:${this.region}:${this.account}:access-point/*`,
      ],
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
    // Task State Change Handler (Event-Driven)
    // ========================================
    // When an ECS task stops (crash, OOM, idle timeout), EventBridge fires an event.
    // This Lambda updates DynamoDB immediately so the orchestrator returns accurate
    // status — preventing the upstream OpenHands app from connecting to dead task IPs.
    const taskStateHandler = new lambdaNode.NodejsFunction(this, 'TaskStateHandler', {
      functionName: 'openhands-sandbox-task-state',
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: path.join(__dirname, '..', 'lambda', 'sandbox-task-state', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.seconds(30),
      memorySize: 128,
      architecture: lambda.Architecture.ARM_64,
      bundling: { minify: true, sourceMap: true },
      environment: {
        REGISTRY_TABLE_NAME: registryTable.tableName,
        AWS_REGION_NAME: config.region,
        LOG_LEVEL: 'INFO',
        POWERTOOLS_SERVICE_NAME: 'sandbox-task-state',
      },
    });

    registryTable.grantReadWriteData(taskStateHandler);

    // EFS access point cleanup for per-conversation isolation
    taskStateHandler.addToRolePolicy(new iam.PolicyStatement({
      sid: 'EfsAccessPointCleanup',
      effect: iam.Effect.ALLOW,
      actions: ['elasticfilesystem:DeleteAccessPoint'],
      resources: [
        workspaceFileSystem.fileSystemArn,
        `arn:aws:elasticfilesystem:${this.region}:${this.account}:access-point/*`,
      ],
    }));

    // EventBridge rule: ECS task stopped in sandbox cluster
    new events.Rule(this, 'TaskStateChangeRule', {
      eventPattern: {
        source: ['aws.ecs'],
        detailType: ['ECS Task State Change'],
        detail: {
          clusterArn: [cluster.clusterArn],
          lastStatus: ['STOPPED'],
        },
      },
      targets: [new eventsTargets.LambdaFunction(taskStateHandler)],
      description: 'Update DynamoDB when sandbox ECS tasks stop',
    });

    // ========================================
    // Conversation Lifecycle Lambdas (Archival + Deletion)
    // ========================================

    // Shared security group for lifecycle Lambdas that need EFS access
    const lifecycleLambdaSg = new ec2.SecurityGroup(this, 'LifecycleLambdaSg', {
      vpc,
      description: 'Security group for conversation lifecycle Lambdas (archival/deletion)',
      allowAllOutbound: true,
    });
    // Allow NFS from lifecycle Lambdas to EFS
    workspaceEfsSg.addIngressRule(
      lifecycleLambdaSg,
      ec2.Port.tcp(2049),
      'Allow NFS from lifecycle Lambdas'
    );

    // Lambda EFS mount via existing workspace access point
    const lambdaEfsMount = lambda.FileSystem.fromEfsAccessPoint(
      workspaceAccessPoint, '/mnt/efs'
    );

    // --- Conversation Archival Lambda (daily) ---
    const archivalLambda = new lambdaNode.NodejsFunction(this, 'ArchivalLambda', {
      functionName: 'openhands-conversation-archival',
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: path.join(__dirname, '..', 'lambda', 'conversation-archival', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      architecture: lambda.Architecture.ARM_64,
      bundling: { minify: true, sourceMap: true },
      vpc,
      vpcSubnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),
      securityGroups: [lifecycleLambdaSg],
      filesystem: lambdaEfsMount,
      environment: {
        REGISTRY_TABLE_NAME: registryTable.tableName,
        RETENTION_DAYS: String(retentionDays),
        EFS_MOUNT_PATH: '/mnt/efs',
        AWS_REGION_NAME: config.region,
        LOG_LEVEL: 'INFO',
        POWERTOOLS_SERVICE_NAME: 'conversation-archival',
      },
    });

    registryTable.grantReadWriteData(archivalLambda);

    // CloudWatch metrics for archival stats
    archivalLambda.addToRolePolicy(new iam.PolicyStatement({
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

    // EventBridge rule: run archival daily
    new events.Rule(this, 'ArchivalSchedule', {
      schedule: events.Schedule.rate(cdk.Duration.days(1)),
      targets: [new eventsTargets.LambdaFunction(archivalLambda)],
      description: 'Archive inactive conversations (STOPPED/PAUSED beyond retention period)',
    });

    // --- Conversation Deletion Lambda (on-demand) ---
    const deletionLambdaEnv: Record<string, string> = {
      REGISTRY_TABLE_NAME: registryTable.tableName,
      EFS_MOUNT_PATH: '/mnt/efs',
      AWS_REGION_NAME: config.region,
      LOG_LEVEL: 'INFO',
      POWERTOOLS_SERVICE_NAME: 'conversation-delete',
    };

    // Add optional database and S3 config for full data wipe
    if (props.dataBucket) {
      deletionLambdaEnv.DATA_BUCKET = props.dataBucket.bucketName;
    }
    // Database secret name for RDS Data API auth — Lambda resolves ARNs at runtime
    // to avoid cyclic CDK dependency (Sandbox → Database → Security → Sandbox)
    if (props.databaseSecretName) {
      deletionLambdaEnv.DB_SECRET_NAME = props.databaseSecretName;
    }
    if (props.databaseName) {
      deletionLambdaEnv.DB_NAME = props.databaseName;
    }

    const deletionLambda = new lambdaNode.NodejsFunction(this, 'DeletionLambda', {
      functionName: 'openhands-conversation-delete',
      runtime: lambda.Runtime.NODEJS_24_X,
      entry: path.join(__dirname, '..', 'lambda', 'conversation-delete', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      architecture: lambda.Architecture.ARM_64,
      bundling: { minify: true, sourceMap: true },
      vpc,
      vpcSubnets: vpc.selectSubnets({ subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS }),
      securityGroups: [lifecycleLambdaSg],
      filesystem: lambdaEfsMount,
      environment: deletionLambdaEnv,
    });

    registryTable.grantReadWriteData(deletionLambda);

    // S3 permissions for conversation data cleanup
    if (props.dataBucket) {
      props.dataBucket.grantRead(deletionLambda, 'conversations/*');
      props.dataBucket.grantDelete(deletionLambda, 'conversations/*');
    }

    // RDS Data API + Secrets Manager for Aurora conversation cleanup
    // Uses well-known secret name to avoid cyclic CDK dependency
    if (props.databaseSecretName) {
      const dbSecret = secretsmanager.Secret.fromSecretNameV2(
        this, 'DeletionLambdaDbSecret', props.databaseSecretName
      );
      dbSecret.grantRead(deletionLambda);

      // RDS Data API — scoped to all clusters in this account/region
      // (narrower scoping requires cluster ARN which creates cyclic dependency)
      deletionLambda.addToRolePolicy(new iam.PolicyStatement({
        sid: 'RdsDataApi',
        effect: iam.Effect.ALLOW,
        actions: ['rds-data:ExecuteStatement'],
        resources: [`arn:aws:rds:${this.region}:${this.account}:cluster:*`],
      }));
    }

    // Grant orchestrator permission to invoke deletion Lambda
    orchestratorTaskDef.taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'InvokeDeletionLambda',
      effect: iam.Effect.ALLOW,
      actions: ['lambda:InvokeFunction'],
      resources: [deletionLambda.functionArn],
    }));

    // Add DELETION_LAMBDA_ARN to orchestrator container environment
    // (Orchestrator container is the first container added to orchestratorTaskDef)
    const orchestratorContainer = orchestratorTaskDef.defaultContainer!;
    orchestratorContainer.addEnvironment('DELETION_LAMBDA_ARN', deletionLambda.functionArn);

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
    const orchestratorFqdn = `${orchestratorDnsName}.openhands.local`;
    this.output = {
      clusterArn: cluster.clusterArn,
      clusterName: cluster.clusterName,
      registryTableName: registryTable.tableName,
      registryTableArn: registryTable.tableArn,
      taskDefinitionFamily: 'openhands-sandbox',  // Matches family in task definition
      sandboxTaskSecurityGroupId: sandboxTaskSg.securityGroupId,
      // Cloud Map private DNS for orchestrator Fargate service
      orchestratorApiUrl: `http://${orchestratorFqdn}:8081`,
      orchestratorDnsName: orchestratorFqdn,
      orchestratorSecurityGroupId: orchestratorSg.securityGroupId,
      sandboxLogGroupName: sandboxLogGroup.logGroupName,
      warmPoolSize,
      warmPoolServiceName: warmPoolService.serviceName,
      orchestratorImageUri: orchestratorImage.imageUri,
      sandboxExecutionRoleArn: sandboxExecutionRole.roleArn,
      sandboxTaskRoleArn: sandboxTaskRole.roleArn,
      efsFileSystemId: workspaceFileSystem.fileSystemId,
      deletionLambdaArn: deletionLambda.functionArn,
      sandboxImageUri: sandboxImageAsset.imageUri,
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

    new cdk.CfnOutput(this, 'SandboxImageUri', {
      value: sandboxImageAsset.imageUri,
      description: 'Sandbox agent-server image URI (ECR) for SOCI index generation',
    });
  }
}
