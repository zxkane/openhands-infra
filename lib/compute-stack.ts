import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as efs from 'aws-cdk-lib/aws-efs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import { DockerImageAsset, Platform } from 'aws-cdk-lib/aws-ecr-assets';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';
import {
  OpenHandsConfig,
  NetworkStackOutput,
  SecurityStackOutput,
  MonitoringStackOutput,
  ComputeStackOutput,
  DatabaseStackOutput,
  ClusterStackOutput,
  SandboxStackOutput,
} from './interfaces.js';

/**
 * Default Docker image versions - update these when new stable versions are released.
 * Latest release: https://github.com/OpenHands/OpenHands/releases
 */
const DEFAULT_OPENHANDS_VERSION = '1.6.0';
const DEFAULT_RUNTIME_VERSION = '1.6-nikolaik';

/**
 * Read OpenHands config.toml from the config directory.
 * Replaces all placeholders with actual values at CDK synth time
 * (no shell expansion available in Fargate).
 */
function readOpenHandsConfig(s3BucketName: string, agentServerImageUri: string, region: string): string {
  const projectRoot = process.cwd();
  const configPath = path.resolve(projectRoot, 'config', 'config.toml');

  const expectedDir = path.resolve(projectRoot, 'config');
  if (!configPath.startsWith(expectedDir)) {
    throw new Error(`Security Error: Config path must be within ${expectedDir}`);
  }

  if (!fs.existsSync(configPath)) {
    throw new Error(
      `Configuration file not found: ${configPath}\n` +
      `Please ensure config/config.toml exists in the project root.`
    );
  }

  let content: string;
  try {
    content = fs.readFileSync(configPath, 'utf-8');
  } catch (error) {
    const err = error as NodeJS.ErrnoException;
    throw new Error(`Failed to read config file: ${err.message}`);
  }

  if (!content.includes('[core]') || !content.includes('[llm]')) {
    throw new Error(
      'Invalid config.toml: Missing required sections [core] and/or [llm]'
    );
  }

  // Replace ${AWS_REGION} with the actual region value (no shell expansion in Fargate)
  content = content.replace(/\$\{AWS_REGION\}/g, region);

  // Replace ${AWS_S3_BUCKET} with actual bucket name
  content = content.replace(/\$\{AWS_S3_BUCKET\}/g, s3BucketName);

  // Replace ${AGENT_SERVER_IMAGE} with the provided image URI
  content = content.replace(/\$\{AGENT_SERVER_IMAGE\}/g, agentServerImageUri);

  // Remove comments and empty lines for cleaner embedded config
  const lines = content.split('\n').filter(line => {
    const trimmed = line.trim();
    return trimmed && !trimmed.startsWith('#');
  });

  return lines.join('\n');
}

export interface ComputeStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
  securityOutput: SecurityStackOutput;
  monitoringOutput: MonitoringStackOutput;
  /** Shared ECS cluster and Cloud Map namespace from ClusterStack */
  clusterOutput: ClusterStackOutput;
  /**
   * Database configuration for Aurora Serverless PostgreSQL.
   * Optional: When provided, enables self-healing architecture that persists
   * conversation history across task replacements.
   */
  databaseOutput?: DatabaseStackOutput;
  /**
   * Enable sandbox AWS access (default: false).
   */
  sandboxAwsAccess?: boolean;
  /**
   * User Config API Lambda function (optional).
   * When provided, creates ALB target group and listener rule for /api/v1/user-config/*
   */
  userConfigFunction?: lambda.IFunction;
  /**
   * Sandbox infrastructure output (required).
   * Enables Fargate sandbox mode with RUNTIME=remote env vars.
   */
  sandboxOutput: SandboxStackOutput;
}

/**
 * ComputeStack - Creates Fargate services, ALB, and EFS configuration
 *
 * This stack deploys:
 * - OpenHands App Fargate Service (1 vCPU, 2 GB, auto-scales 1-3) with Cloud Map DNS
 * - OpenResty Proxy Fargate Service (0.25 vCPU, 512 MB, auto-scales 1-3)
 * - Internet-facing Application Load Balancer
 * - IP-type Target Groups with health checks
 * - EFS for persistent workspace storage
 * - CloudWatch alarms for ECS service health
 */
export class ComputeStack extends cdk.Stack {
  public readonly output: ComputeStackOutput;
  public readonly alb: elbv2.IApplicationLoadBalancer;

  constructor(scope: Construct, id: string, props: ComputeStackProps) {
    super(scope, id, props);

    const { config, networkOutput, securityOutput, monitoringOutput, databaseOutput, sandboxOutput, clusterOutput } = props;
    const { vpc } = networkOutput;
    const { albSecurityGroup, appServiceSecurityGroup, efsSecurityGroup, appTaskRole, appExecutionRole, sandboxSecretKeyName, sandboxRoleArn } = securityOutput;
    const { alertTopic, dataBucket, openrestyLogGroup } = monitoringOutput;
    const { cluster, namespace } = clusterOutput;

    // Full domain for runtime URL pattern
    const fullDomain = `${config.subDomain}.${config.domainName}`;

    // ========================================
    // App ↔ Sandbox Fargate Networking
    // ========================================
    const sandboxTaskSg = ec2.SecurityGroup.fromSecurityGroupId(
      this, 'ImportedSandboxTaskSg', sandboxOutput.sandboxTaskSecurityGroupId
    );
    // App → sandbox (outbound)
    appServiceSecurityGroup.addEgressRule(
      sandboxTaskSg,
      ec2.Port.tcpRange(1, 65535),
      'Allow app service to reach sandbox Fargate tasks'
    );
    // sandbox → app (inbound to sandbox SG from app SG)
    new ec2.CfnSecurityGroupIngress(this, 'SandboxIngressFromApp', {
      groupId: sandboxOutput.sandboxTaskSecurityGroupId,
      sourceSecurityGroupId: appServiceSecurityGroup.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 1,
      toPort: 65535,
      description: 'Allow all TCP from app service (OpenResty routes to sandbox ports)',
    });

    // App ↔ orchestrator Fargate service (port 8081 for sandbox API)
    appServiceSecurityGroup.addEgressRule(
      ec2.SecurityGroup.fromSecurityGroupId(this, 'ImportedOrchestratorSg', sandboxOutput.orchestratorSecurityGroupId),
      ec2.Port.tcp(8081),
      'Allow app service to reach sandbox orchestrator'
    );
    new ec2.CfnSecurityGroupIngress(this, 'OrchestratorIngressFromApp', {
      groupId: sandboxOutput.orchestratorSecurityGroupId,
      sourceSecurityGroupId: appServiceSecurityGroup.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 8081,
      toPort: 8081,
      description: 'Allow app service to reach sandbox orchestrator',
    });

    // Preserve cross-stack exports to avoid CloudFormation "Cannot delete export"
    // errors during migration from EC2 to Fargate. These were previously referenced
    // by docker-compose env vars and IAM policies. Can be removed after successful
    // migration when no deployed stack imports them.
    new cdk.CfnOutput(this, 'SandboxClusterArn', {
      value: sandboxOutput.clusterArn,
    });
    new cdk.CfnOutput(this, 'SandboxRegistryTableName', {
      value: sandboxOutput.registryTableName,
    });
    new cdk.CfnOutput(this, 'SandboxRegistryTableArn', {
      value: sandboxOutput.registryTableArn,
    });
    new cdk.CfnOutput(this, 'SandboxWarmPoolServiceName', {
      value: sandboxOutput.warmPoolServiceName,
    });
    new cdk.CfnOutput(this, 'SandboxExecutionRoleArn', {
      value: sandboxOutput.sandboxExecutionRoleArn,
    });
    new cdk.CfnOutput(this, 'SandboxTaskRoleArn', {
      value: sandboxOutput.sandboxTaskRoleArn,
    });
    // Preserve cross-stack exports for SecurityStack's role references.
    // Uses SSM parameters (not CfnOutput) to force CDK to generate the cross-stack imports.
    // These are needed during migration to prevent "Cannot delete export" errors.
    // Can be removed in a follow-up deployment after migration completes.
    new ssm.StringParameter(this, 'MigrationAppTaskRoleName', {
      parameterName: '/openhands/migration/app-task-role-name',
      stringValue: appTaskRole.roleName,  // Forces Ref export
      description: 'Temporary: preserves SecurityStack Ref export during migration',
      tier: ssm.ParameterTier.STANDARD,
    });
    if (sandboxRoleArn) {
      new ssm.StringParameter(this, 'MigrationSandboxRoleArn', {
        parameterName: '/openhands/migration/sandbox-role-arn',
        stringValue: sandboxRoleArn,
        description: 'Temporary: preserves SecurityStack sandbox role export during migration',
        tier: ssm.ParameterTier.STANDARD,
      });
    }

    // App ↔ app internal communication (OpenResty → app on port 3000)
    // Uses CfnSecurityGroupIngress/Egress to avoid CDK creating rules with
    // auto-generated descriptions in SecurityStack (cross-stack SG)
    new ec2.CfnSecurityGroupIngress(this, 'AppIngressFromApp', {
      groupId: appServiceSecurityGroup.securityGroupId,
      sourceSecurityGroupId: appServiceSecurityGroup.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 3000,
      toPort: 3000,
      description: 'Allow OpenResty to reach app on port 3000',
    });
    new ec2.CfnSecurityGroupEgress(this, 'AppEgressToApp', {
      groupId: appServiceSecurityGroup.securityGroupId,
      destinationSecurityGroupId: appServiceSecurityGroup.securityGroupId,
      ipProtocol: 'tcp',
      fromPort: 3000,
      toPort: 3000,
      description: 'Allow outbound to app on port 3000',
    });

    // ========================================
    // Persistent Workspace EFS
    // ========================================
    const privateSubnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    });

    const workspaceFileSystem = new efs.FileSystem(this, 'WorkspaceFileSystem', {
      vpc,
      vpcSubnets: privateSubnets,
      securityGroup: efsSecurityGroup,
      encrypted: true,
      performanceMode: efs.PerformanceMode.GENERAL_PURPOSE,
      throughputMode: efs.ThroughputMode.BURSTING,
      lifecyclePolicy: efs.LifecyclePolicy.AFTER_14_DAYS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    cdk.Tags.of(workspaceFileSystem).add('backup', 'true');

    // EFS resource policy: allow mounting from Fargate app task role only
    workspaceFileSystem.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowClientMountViaMountTarget',
      effect: iam.Effect.ALLOW,
      principals: [appTaskRole],
      actions: [
        'elasticfilesystem:ClientMount',
        'elasticfilesystem:ClientWrite',
        'elasticfilesystem:ClientRootAccess',
      ],
      resources: ['*'],
      conditions: {
        Bool: {
          'elasticfilesystem:AccessedViaMountTarget': 'true',
        },
      },
    }));

    const workspaceAccessPoint = new efs.AccessPoint(this, 'WorkspaceAccessPoint', {
      fileSystem: workspaceFileSystem,
      path: '/openhands',
      posixUser: { uid: '0', gid: '0' },
      createAcl: { ownerUid: '0', ownerGid: '0', permissions: '0777' },
    });

    // Grant app task role permission to access EFS
    appTaskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      sid: 'EfsClientAccess',
      actions: [
        'elasticfilesystem:ClientMount',
        'elasticfilesystem:ClientWrite',
        'elasticfilesystem:ClientRootAccess',
      ],
      resources: ['*'],
      conditions: {
        Bool: {
          'elasticfilesystem:AccessedViaMountTarget': 'true',
        },
      },
    }));

    // ========================================
    // Log Groups
    // ========================================
    // The app log group is created by MonitoringStack but referenced by name here
    // to avoid cyclic dependencies with SecurityStack (which owns the roles).
    // The openresty log group is passed via monitoringOutput (no cycle risk).
    const appLogGroup = logs.LogGroup.fromLogGroupName(this, 'AppLogGroupRef', '/openhands/application');

    // ========================================
    // Docker Image Builds
    // ========================================
    const customOpenhandsImage = new DockerImageAsset(this, 'CustomOpenHandsImage', {
      directory: path.join(__dirname, '..', 'docker'),
      platform: Platform.LINUX_ARM64,
      buildArgs: {
        OPENHANDS_VERSION: DEFAULT_OPENHANDS_VERSION,
      },
      exclude: [
        'agent-server',
        'agent-server-custom',
        '**/__pycache__',
        '**/*.pyc',
        '**/.pytest_cache',
      ],
    });

    const customAgentServerImage = new DockerImageAsset(this, 'CustomAgentServerImage', {
      directory: path.join(__dirname, '..', 'docker', 'agent-server-custom'),
      platform: Platform.LINUX_ARM64,
    });

    const openrestyImage = new DockerImageAsset(this, 'OpenRestyImage', {
      directory: path.join(__dirname, '..', 'docker', 'openresty'),
      platform: Platform.LINUX_ARM64,
    });

    const customRuntimeImage = new DockerImageAsset(this, 'CustomRuntimeImage', {
      directory: path.join(__dirname, '..', 'docker', 'runtime-custom'),
      platform: Platform.LINUX_ARM64,
      buildArgs: {
        RUNTIME_VERSION: DEFAULT_RUNTIME_VERSION,
      },
    });

    // Grant execution role permission to pull from CDK-managed ECR repositories
    customOpenhandsImage.repository.grantPull(appExecutionRole);
    openrestyImage.repository.grantPull(appExecutionRole);

    // ========================================
    // Origin Verification Secret
    // ========================================
    const originVerifySecret = cdk.Names.uniqueId(this).substring(0, 32);

    new ssm.StringParameter(this, 'OriginVerifyParam', {
      parameterName: '/openhands/cloudfront/origin-verify-secret',
      stringValue: originVerifySecret,
      description: 'Secret header value for CloudFront origin verification',
      tier: ssm.ParameterTier.STANDARD,
    });

    // SSM Parameters for Docker image versions
    new ssm.StringParameter(this, 'OpenHandsVersionParam', {
      parameterName: '/openhands/docker/openhands-version',
      stringValue: DEFAULT_OPENHANDS_VERSION,
      description: 'OpenHands Docker image version tag',
      tier: ssm.ParameterTier.STANDARD,
    });

    new ssm.StringParameter(this, 'RuntimeVersionParam', {
      parameterName: '/openhands/docker/runtime-version',
      stringValue: DEFAULT_RUNTIME_VERSION,
      description: 'OpenHands Runtime Docker image version tag',
      tier: ssm.ParameterTier.STANDARD,
    });

    // ========================================
    // Secrets Manager References (for ECS native secret injection)
    // ========================================
    const sandboxSecretKey = secretsmanager.Secret.fromSecretNameV2(
      this, 'SandboxSecretKeyRef', sandboxSecretKeyName
    );

    const proxyUserSecret = secretsmanager.Secret.fromSecretNameV2(
      this, 'ProxyUserSecretRef', 'openhands/database/proxy-user'
    );

    // ========================================
    // App Fargate Task Definition (1 vCPU / 2 GB)
    // Control plane only — actual compute runs in sandbox containers.
    // Rightsized based on CloudWatch metrics: avg CPU <1%, avg memory ~580 MB.
    // ========================================
    const appTaskDefinition = new ecs.FargateTaskDefinition(this, 'AppTaskDef', {
      family: 'openhands-app',
      cpu: 1024,      // 1 vCPU
      memoryLimitMiB: 2048,  // 2 GB
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
      executionRole: appExecutionRole,
      taskRole: appTaskRole,
    });

    // EFS volume for persistent workspace
    appTaskDefinition.addVolume({
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

    // Config file content (embedded at synth time, written to /app/config.toml at container start)
    const agentServerImageUri = customAgentServerImage.imageUri;
    const configContent = readOpenHandsConfig(dataBucket.bucketName, agentServerImageUri, config.region);

    // Build environment variables for the app container
    const appEnvironment: Record<string, string> = {
      SANDBOX_USER_ID: '0',
      SANDBOX_RUNTIME_CONTAINER_IMAGE: customRuntimeImage.imageUri,
      WORKSPACE_MOUNT_PATH: '/data/openhands/workspace',
      WORKSPACE_BASE: '/data/openhands/workspace',
      LOG_ALL_EVENTS: 'true',
      HIDE_LLM_SETTINGS: 'false',
      USER_AUTH_CLASS: 'openhands.server.user_auth.cognito_user_auth.CognitoUserAuth',
      // LLM_MODEL removed — model is configured via config.toml [llm].model
      // and overridden per-user via Settings.llm_model (saved in S3).
      // Hardcoding LLM_MODEL env var would override user's model selection.
      LLM_AWS_REGION_NAME: config.region,
      AWS_REGION: config.region,
      AWS_DEFAULT_REGION: config.region,
      AWS_S3_BUCKET: dataBucket.bucketName,
      FILE_STORE: 's3',
      FILE_STORE_PATH: dataBucket.bucketName,
      AGENT_SERVER_IMAGE_REPOSITORY: customAgentServerImage.repository.repositoryUri,
      AGENT_SERVER_IMAGE_TAG: customAgentServerImage.imageTag,
      AGENT_ENABLE_BROWSING: 'false',
      AGENT_ENABLE_MCP: 'true',
      // Fargate sandbox mode
      RUNTIME: 'remote',
      SANDBOX_REMOTE_RUNTIME_API_URL: sandboxOutput.orchestratorApiUrl,
      SANDBOX_API_KEY: 'local',
      SANDBOX_START_TIMEOUT: '300',
      // Sandbox runtime env vars injected into sandbox containers at startup.
      // OH_SECRET_KEY enables secret persistence across sandbox restarts (required for conversation resume).
      // The $OH_SECRET_KEY reference is resolved at runtime from the ECS-injected env var.
      // Fargate sandboxes use native ECS task role for AWS credentials, not STS.
      SANDBOX_RUNTIME_STARTUP_ENV_VARS: `{"OH_PRELOAD_TOOLS":"false","AWS_DEFAULT_REGION":"${config.region}","OH_SECRET_KEY":"$OH_SECRET_KEY"}`,
    };

    // User Config feature flag
    if (securityOutput.userSecretsKmsKeyId) {
      appEnvironment['USER_CONFIG_ENABLED'] = 'true';
      appEnvironment['USER_SECRETS_KMS_KEY_ID'] = securityOutput.userSecretsKmsKeyId;
    } else {
      appEnvironment['USER_CONFIG_ENABLED'] = 'false';
    }

    // Database env vars
    if (databaseOutput) {
      appEnvironment['DB_HOST'] = databaseOutput.proxyEndpoint;
      appEnvironment['DB_PORT'] = databaseOutput.clusterPort;
      appEnvironment['DB_NAME'] = databaseOutput.databaseName;
      appEnvironment['DB_USER'] = databaseOutput.databaseUser;
      appEnvironment['DB_SSL'] = 'require';
      appEnvironment['DB_CLUSTER_ENDPOINT'] = databaseOutput.clusterEndpoint;
    }

    // ECS native secrets injection
    const appSecrets: Record<string, ecs.Secret> = {
      OH_SECRET_KEY: ecs.Secret.fromSecretsManager(sandboxSecretKey),
    };

    // Inject DB password from Secrets Manager (password JSON key)
    if (databaseOutput) {
      appSecrets['DB_PASS'] = ecs.Secret.fromSecretsManager(proxyUserSecret, 'password');
    }

    // Inject config.toml content as environment variable
    // Written to /app/config.toml at container startup via entrypoint command
    appEnvironment['OPENHANDS_CONFIG_TOML'] = configContent;

    // App container
    // Overrides entrypoint to write config.toml from env var before starting the app.
    // The base image's CMD is the app startup; we prepend config file creation.
    const appContainer = appTaskDefinition.addContainer('openhands-app', {
      containerName: 'openhands-app',
      image: ecs.ContainerImage.fromDockerImageAsset(customOpenhandsImage),
      essential: true,
      entryPoint: ['/bin/bash', '-c'],
      command: [
        // Write config.toml from env var, then exec the original entrypoint + CMD
        'echo "$OPENHANDS_CONFIG_TOML" > /app/config.toml && exec /bin/sh /opt/apply-startup.sh uvicorn openhands.server.listen:app --host 0.0.0.0 --port 3000',
      ],
      portMappings: [
        { containerPort: 3000, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'app',
        logGroup: appLogGroup,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:3000/api/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(10),
        retries: 3,
        startPeriod: cdk.Duration.seconds(120),
      },
      environment: appEnvironment,
      secrets: appSecrets,
    });

    // Mount EFS at /data/openhands
    appContainer.addMountPoints({
      sourceVolume: 'workspace',
      containerPath: '/data/openhands',
      readOnly: false,
    });

    // ========================================
    // App Fargate Service (with Cloud Map DNS)
    // ========================================
    const appService = new ecs.FargateService(this, 'AppService', {
      cluster,
      serviceName: 'openhands-app',
      taskDefinition: appTaskDefinition,
      desiredCount: 1,
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      vpcSubnets: privateSubnets,
      securityGroups: [appServiceSecurityGroup],
      assignPublicIp: false,
      enableECSManagedTags: true,
      enableExecuteCommand: true,
      propagateTags: ecs.PropagatedTagSource.TASK_DEFINITION,
      cloudMapOptions: {
        name: 'app',
        cloudMapNamespace: namespace,
        dnsRecordType: servicediscovery.DnsRecordType.A,
        dnsTtl: cdk.Duration.seconds(10),
      },
    });
    cdk.Tags.of(appService).add('Component', 'openhands-app');

    // ========================================
    // App Service Auto Scaling
    // ========================================
    const appScaling = appService.autoScaleTaskCount({
      minCapacity: 1,
      maxCapacity: 3,
    });

    appScaling.scaleOnCpuUtilization('AppCpuScaling', {
      targetUtilizationPercent: 60,
      scaleInCooldown: cdk.Duration.seconds(300),
      scaleOutCooldown: cdk.Duration.seconds(60),
    });

    appScaling.scaleOnMemoryUtilization('AppMemoryScaling', {
      targetUtilizationPercent: 70,
      scaleInCooldown: cdk.Duration.seconds(300),
      scaleOutCooldown: cdk.Duration.seconds(60),
    });

    // ========================================
    // OpenResty Fargate Task Definition (0.25 vCPU / 512 MB)
    // ========================================
    const openrestyTaskDefinition = new ecs.FargateTaskDefinition(this, 'OpenRestyTaskDef', {
      family: 'openhands-openresty',
      cpu: 256,       // 0.25 vCPU
      memoryLimitMiB: 512,  // 512 MB
      runtimePlatform: {
        cpuArchitecture: ecs.CpuArchitecture.ARM64,
        operatingSystemFamily: ecs.OperatingSystemFamily.LINUX,
      },
      executionRole: appExecutionRole,
      taskRole: appTaskRole,
    });

    openrestyTaskDefinition.addContainer('openresty-proxy', {
      containerName: 'openresty-proxy',
      image: ecs.ContainerImage.fromDockerImageAsset(openrestyImage),
      essential: true,
      portMappings: [
        { containerPort: 8080, protocol: ecs.Protocol.TCP },
      ],
      logging: ecs.LogDrivers.awsLogs({
        streamPrefix: 'openresty',
        logGroup: openrestyLogGroup,
      }),
      healthCheck: {
        command: ['CMD-SHELL', 'curl -f http://localhost:8080/health || exit 1'],
        interval: cdk.Duration.seconds(30),
        timeout: cdk.Duration.seconds(5),
        retries: 3,
        startPeriod: cdk.Duration.seconds(30),
      },
      environment: {
        ORCHESTRATOR_URL: sandboxOutput.orchestratorApiUrl,
        APP_URL: 'http://app.openhands.local:3000',
      },
    });

    // ========================================
    // OpenResty Fargate Service
    // ========================================
    const openrestyService = new ecs.FargateService(this, 'OpenRestyService', {
      cluster,
      serviceName: 'openhands-openresty',
      taskDefinition: openrestyTaskDefinition,
      desiredCount: 1,
      minHealthyPercent: 100,
      maxHealthyPercent: 200,
      vpcSubnets: privateSubnets,
      securityGroups: [appServiceSecurityGroup],
      assignPublicIp: false,
      enableECSManagedTags: true,
      enableExecuteCommand: true,
      propagateTags: ecs.PropagatedTagSource.TASK_DEFINITION,
    });
    cdk.Tags.of(openrestyService).add('Component', 'openresty-proxy');

    // ========================================
    // OpenResty Service Auto Scaling
    // ========================================
    const openrestyScaling = openrestyService.autoScaleTaskCount({
      minCapacity: 1,
      maxCapacity: 3,
    });

    openrestyScaling.scaleOnCpuUtilization('OpenRestyCpuScaling', {
      targetUtilizationPercent: 60,
      scaleInCooldown: cdk.Duration.seconds(300),
      scaleOutCooldown: cdk.Duration.seconds(60),
    });

    // ========================================
    // Internet-facing ALB
    // ========================================
    const alb = new elbv2.ApplicationLoadBalancer(this, 'OpenHandsAlb', {
      vpc,
      internetFacing: true,
      securityGroup: albSecurityGroup,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PUBLIC,
      },
    });

    // App Target Group (IP type for Fargate)
    const targetGroup = new elbv2.ApplicationTargetGroup(this, 'AppTargetGroup', {
      vpc,
      port: 3000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        path: '/api/health',
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        timeout: cdk.Duration.seconds(5),
        interval: cdk.Duration.seconds(30),
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // Attach app Fargate service to target group
    appService.attachToApplicationTargetGroup(targetGroup);

    // Runtime Proxy Target Group (IP type for Fargate, OpenResty on port 8080)
    const runtimeTargetGroup = new elbv2.ApplicationTargetGroup(this, 'RuntimeTargetGroup', {
      vpc,
      port: 8080,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.IP,
      healthCheck: {
        path: '/health',
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        timeout: cdk.Duration.seconds(5),
        interval: cdk.Duration.seconds(30),
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // Attach openresty Fargate service to runtime target group
    openrestyService.attachToApplicationTargetGroup(runtimeTargetGroup);

    // HTTP Listener with origin verification
    const listener = alb.addListener('HttpListener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      defaultAction: elbv2.ListenerAction.fixedResponse(403, {
        contentType: 'text/plain',
        messageBody: 'Access Denied - Invalid Origin',
      }),
    });

    // Rule: Forward requests with valid origin verification header to main target group
    listener.addTargetGroups('VerifiedMainRule', {
      priority: 20,
      conditions: [
        elbv2.ListenerCondition.httpHeader('X-Origin-Verify', [originVerifySecret]),
      ],
      targetGroups: [targetGroup],
    });

    // Rule: Forward /runtime/* requests with valid origin verification header
    listener.addTargetGroups('VerifiedRuntimeRule', {
      priority: 10,
      conditions: [
        elbv2.ListenerCondition.pathPatterns(['/runtime/*']),
        elbv2.ListenerCondition.httpHeader('X-Origin-Verify', [originVerifySecret]),
      ],
      targetGroups: [runtimeTargetGroup],
    });

    // ========================================
    // User Config API Lambda Target Group (optional)
    // ========================================
    if (props.userConfigFunction) {
      const userConfigTargetGroup = new elbv2.ApplicationTargetGroup(this, 'UserConfigTargetGroup', {
        targetType: elbv2.TargetType.LAMBDA,
        targets: [new targets.LambdaTarget(props.userConfigFunction)],
        healthCheck: {
          enabled: false,
        },
      });

      listener.addTargetGroups('VerifiedUserConfigRule', {
        priority: 5,
        conditions: [
          elbv2.ListenerCondition.pathPatterns(['/api/v1/user-config/*']),
          elbv2.ListenerCondition.httpHeader('X-Origin-Verify', [originVerifySecret]),
        ],
        targetGroups: [userConfigTargetGroup],
      });
    }

    // Store outputs
    this.output = {
      targetGroup,
      originVerifySecret,
      computeRegion: this.region,
    };
    this.alb = alb;

    // ========================================
    // CloudWatch Alarms (ECS Service Metrics)
    // ========================================
    const appCpuAlarm = new cloudwatch.Alarm(this, 'AppCpuAlarm', {
      alarmDescription: 'App service CPU utilization exceeds 80%',
      metric: appService.metricCpuUtilization({
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    appCpuAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    const appMemoryAlarm = new cloudwatch.Alarm(this, 'AppMemoryAlarm', {
      alarmDescription: 'App service memory utilization exceeds 85%',
      metric: appService.metricMemoryUtilization({
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 85,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    appMemoryAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // ========================================
    // SSM Parameters (for EdgeStack in us-east-1)
    // ========================================
    const ssmPathPrefix = `/openhands/compute/${this.region}`;

    new cr.AwsCustomResource(this, 'SsmUsEast1Writer', {
      onCreate: {
        service: 'SSM',
        action: 'putParameter',
        parameters: {
          Name: `${ssmPathPrefix}/alb-dns-name`,
          Value: alb.loadBalancerDnsName,
          Type: 'String',
          Overwrite: true,
          Description: `ALB DNS name for CloudFront origin (${this.region})`,
        },
        region: 'us-east-1',
        physicalResourceId: cr.PhysicalResourceId.of(`openhands-ssm-alb-dns-${this.region}`),
      },
      onUpdate: {
        service: 'SSM',
        action: 'putParameter',
        parameters: {
          Name: `${ssmPathPrefix}/alb-dns-name`,
          Value: alb.loadBalancerDnsName,
          Type: 'String',
          Overwrite: true,
          Description: `ALB DNS name for CloudFront origin (${this.region})`,
        },
        region: 'us-east-1',
        physicalResourceId: cr.PhysicalResourceId.of(`openhands-ssm-alb-dns-${this.region}`),
      },
      onDelete: {
        service: 'SSM',
        action: 'deleteParameter',
        parameters: {
          Name: `${ssmPathPrefix}/alb-dns-name`,
        },
        region: 'us-east-1',
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:aws:ssm:us-east-1:${this.account}:parameter/openhands/compute/${this.region}/*`],
        }),
      ]),
    });

    new cr.AwsCustomResource(this, 'SsmUsEast1SecretWriter', {
      onCreate: {
        service: 'SSM',
        action: 'putParameter',
        parameters: {
          Name: `${ssmPathPrefix}/origin-verify-secret`,
          Value: originVerifySecret,
          Type: 'String',
          Overwrite: true,
          Description: `Origin verification secret for CloudFront-to-ALB authentication (${this.region})`,
        },
        region: 'us-east-1',
        physicalResourceId: cr.PhysicalResourceId.of(`openhands-ssm-origin-secret-${this.region}`),
      },
      onUpdate: {
        service: 'SSM',
        action: 'putParameter',
        parameters: {
          Name: `${ssmPathPrefix}/origin-verify-secret`,
          Value: originVerifySecret,
          Type: 'String',
          Overwrite: true,
          Description: `Origin verification secret for CloudFront-to-ALB authentication (${this.region})`,
        },
        region: 'us-east-1',
        physicalResourceId: cr.PhysicalResourceId.of(`openhands-ssm-origin-secret-${this.region}`),
      },
      onDelete: {
        service: 'SSM',
        action: 'deleteParameter',
        parameters: {
          Name: `${ssmPathPrefix}/origin-verify-secret`,
        },
        region: 'us-east-1',
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['ssm:PutParameter', 'ssm:DeleteParameter'],
          resources: [`arn:aws:ssm:us-east-1:${this.account}:parameter/openhands/compute/${this.region}/*`],
        }),
      ]),
    });

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'AlbDnsName', {
      value: alb.loadBalancerDnsName,
      description: 'ALB DNS Name',
    });

    new cdk.CfnOutput(this, 'AlbArn', {
      value: alb.loadBalancerArn,
      description: 'ALB ARN',
    });

    new cdk.CfnOutput(this, 'AppServiceName', {
      value: appService.serviceName,
      description: 'App Fargate Service Name',
    });

    new cdk.CfnOutput(this, 'OpenRestyServiceName', {
      value: openrestyService.serviceName,
      description: 'OpenResty Fargate Service Name',
    });

    new cdk.CfnOutput(this, 'WorkspaceEfsFileSystemId', {
      value: workspaceFileSystem.fileSystemId,
      description: 'EFS file system ID for persistent OpenHands workspaces',
    });
  }
}
