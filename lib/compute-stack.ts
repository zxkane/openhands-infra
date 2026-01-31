import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as efs from 'aws-cdk-lib/aws-efs';
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
} from './interfaces.js';

/**
 * Default Docker image versions - update these when new stable versions are released.
 * Latest release: https://github.com/OpenHands/OpenHands/releases
 *
 * NOTE: Using CDK DockerImageAsset to build and push images during deployment.
 * Images are built for ARM64 (Graviton) architecture using Docker buildx.
 * See docker/ directory for Dockerfile contents.
 */
const DEFAULT_OPENHANDS_VERSION = '1.2.1';
// Runtime version matching OpenHands 1.2.x - see docker-compose.yml in OpenHands repo
const DEFAULT_RUNTIME_VERSION = '1.2-nikolaik';

/**
 * Read OpenHands config.toml from the config directory.
 * The config file uses ${AWS_REGION} placeholder which will be replaced at runtime,
 * and ${AWS_S3_BUCKET} placeholder which is replaced at CDK synth time.
 *
 * @param s3BucketName - The S3 bucket name to substitute for ${AWS_S3_BUCKET}
 * @param agentServerImageUri - The full agent server image URI to substitute for ${AGENT_SERVER_IMAGE}
 * @throws Error if config file is not found or contains invalid content
 */
function readOpenHandsConfig(s3BucketName: string, agentServerImageUri: string): string {
  const projectRoot = process.cwd();
  const configPath = path.resolve(projectRoot, 'config', 'config.toml');

  // Security: Validate path is within expected directory (prevent path traversal)
  const expectedDir = path.resolve(projectRoot, 'config');
  if (!configPath.startsWith(expectedDir)) {
    throw new Error(`Security Error: Config path must be within ${expectedDir}`);
  }

  // Check file exists before reading
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

  // Validate config has required sections
  if (!content.includes('[core]') || !content.includes('[llm]')) {
    throw new Error(
      'Invalid config.toml: Missing required sections [core] and/or [llm]'
    );
  }

  // Replace ${AWS_REGION} with ${REGION} for shell variable substitution in user data
  content = content.replace(/\$\{AWS_REGION\}/g, '${REGION}');

  // Replace ${AWS_S3_BUCKET} with actual bucket name at CDK synth time
  content = content.replace(/\$\{AWS_S3_BUCKET\}/g, s3BucketName);

  // Replace ${AGENT_SERVER_IMAGE} with the provided image URI at CDK synth time
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
  /**
   * Database configuration for Aurora Serverless PostgreSQL.
   * Optional: When provided, enables self-healing architecture that persists
   * conversation history across EC2 instance replacements.
   * When omitted, the app uses SQLite on the EBS volume (data persists within instance lifecycle).
   * The EC2 instance uses IAM role authentication (no passwords).
   */
  databaseOutput?: DatabaseStackOutput;
  /**
   * Enable sandbox AWS access (default: false).
   * When enabled, sandbox containers receive scoped AWS credentials.
   */
  sandboxAwsAccess?: boolean;
  /**
   * User Config API Lambda function (optional).
   * When provided, creates ALB target group and listener rule for /api/v1/user-config/*
   * to route requests to this Lambda function.
   */
  userConfigFunction?: lambda.IFunction;
}

/**
 * ComputeStack - Creates ASG, Launch Template, ALB, and EBS configuration
 *
 * This stack deploys:
 * - Launch Template with Graviton (ARM64) instance
 * - Auto Scaling Group for self-healing
 * - Internal Application Load Balancer
 * - Target Group with health checks
 */
export class ComputeStack extends cdk.Stack {
  public readonly output: ComputeStackOutput;
  public readonly alb: elbv2.IApplicationLoadBalancer;

  constructor(scope: Construct, id: string, props: ComputeStackProps) {
    super(scope, id, props);

    const { config, networkOutput, securityOutput, monitoringOutput, databaseOutput, sandboxAwsAccess } = props;
    const { vpc } = networkOutput;
    const { albSecurityGroup, ec2SecurityGroup, efsSecurityGroup, ec2Role, ec2InstanceProfile, sandboxRoleArn } = securityOutput;
    const { alertTopic, dataBucket } = monitoringOutput;

    // Full domain for runtime URL pattern
    const fullDomain = `${config.subDomain}.${config.domainName}`;

    // Get private subnets for EC2 and internal ALB
    const privateSubnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    });

    // Persistent workspace storage
    // Mounting /data/openhands from EFS allows conversations to be resumed after EC2 replacement.
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

    // Ensure the EFS file system policy allows mounting from EC2 instances only.
    // Restrict access to the specific EC2 role to prevent unauthorized access.
    workspaceFileSystem.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowClientMountViaMountTarget',
      effect: iam.Effect.ALLOW,
      principals: [ec2Role],
      actions: [
        'elasticfilesystem:ClientMount',
        'elasticfilesystem:ClientWrite',
        'elasticfilesystem:ClientRootAccess',
      ],
      // IMPORTANT: Use Resource="*" to avoid a self-dependency cycle in CloudFormation when
      // embedding FileSystemPolicy directly on AWS::EFS::FileSystem.
      resources: ['*'],
      conditions: {
        Bool: {
          'elasticfilesystem:AccessedViaMountTarget': 'true',
        },
      },
    }));

    // Access Point uses root (uid=0) because OpenHands sandbox containers run as root
    // and need full access to workspace files for Docker operations and code execution.
    // The EFS policy above restricts access to only the EC2 role via mount targets.
    const workspaceAccessPoint = new efs.AccessPoint(this, 'WorkspaceAccessPoint', {
      fileSystem: workspaceFileSystem,
      path: '/openhands',
      posixUser: {
        uid: '0',
        gid: '0',
      },
      createAcl: {
        ownerUid: '0',
        ownerGid: '0',
        permissions: '0777',
      },
    });

    // Grant EC2 role permission to access EFS (required for IAM-authenticated mount)
    // Use Resource='*' to avoid circular dependency between SecurityStack and ComputeStack.
    // The EFS resource policy above restricts access to only this specific role.
    ec2Role.addToPrincipalPolicy(new iam.PolicyStatement({
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

    // SSM Parameters for Docker image versions (allows runtime updates without redeploying)
    const openhandsVersionParam = new ssm.StringParameter(this, 'OpenHandsVersionParam', {
      parameterName: '/openhands/docker/openhands-version',
      stringValue: DEFAULT_OPENHANDS_VERSION,
      description: 'OpenHands Docker image version tag',
      tier: ssm.ParameterTier.STANDARD,
    });

    const runtimeVersionParam = new ssm.StringParameter(this, 'RuntimeVersionParam', {
      parameterName: '/openhands/docker/runtime-version',
      stringValue: DEFAULT_RUNTIME_VERSION,
      description: 'OpenHands Runtime Docker image version tag',
      tier: ssm.ParameterTier.STANDARD,
    });

    // Origin verification secret for CloudFront-to-ALB authentication
    // This secret is shared with EdgeStack via cross-stack reference
    // CloudFront sends this in X-Origin-Verify header, ALB validates it
    // Use uniqueId which generates a stable hash based on construct path (works across stacks)
    const originVerifySecret = cdk.Names.uniqueId(this).substring(0, 32);

    // Store in local region for ALB listener rules
    const originVerifyParam = new ssm.StringParameter(this, 'OriginVerifyParam', {
      parameterName: '/openhands/cloudfront/origin-verify-secret',
      stringValue: originVerifySecret,
      description: 'Secret header value for CloudFront origin verification',
      tier: ssm.ParameterTier.STANDARD,
    });

    // Build custom Docker images using CDK DockerImageAsset
    // Images are built for ARM64 (Graviton) architecture during CDK deployment
    // and automatically pushed to CDK-managed ECR repositories
    const customOpenhandsImage = new DockerImageAsset(this, 'CustomOpenHandsImage', {
      directory: path.join(__dirname, '..', 'docker'),
      platform: Platform.LINUX_ARM64,
      buildArgs: {
        OPENHANDS_VERSION: DEFAULT_OPENHANDS_VERSION,
      },
      // Exclude agent-server subdirectories from the build context
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

    // Build OpenResty Docker image for runtime proxy
    // Runs as a container on the same bridge network as sandbox containers
    // enabling direct routing to any port without Docker port mappings
    const openrestyImage = new DockerImageAsset(this, 'OpenRestyImage', {
      directory: path.join(__dirname, '..', 'docker', 'openresty'),
      platform: Platform.LINUX_ARM64,
    });

    // Build custom runtime Docker image with Chromium for browser automation (MCP chrome-devtools)
    // This runtime image is used as the sandbox container where agent code executes
    const customRuntimeImage = new DockerImageAsset(this, 'CustomRuntimeImage', {
      directory: path.join(__dirname, '..', 'docker', 'runtime-custom'),
      platform: Platform.LINUX_ARM64,
      buildArgs: {
        RUNTIME_VERSION: DEFAULT_RUNTIME_VERSION,
      },
    });

    // Grant EC2 role permission to pull from CDK-managed ECR repositories
    customOpenhandsImage.repository.grantPull(ec2Role);
    customAgentServerImage.repository.grantPull(ec2Role);
    openrestyImage.repository.grantPull(ec2Role);
    customRuntimeImage.repository.grantPull(ec2Role);

    // Note: IAM authentication permission for Aurora PostgreSQL is granted in DatabaseStack
    // using the EC2 role ARN to avoid cyclic cross-stack dependencies

    // Extract repository URI and image tag for user data
    // DockerImageAsset.imageUri format: <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
    const openhandsImageUri = customOpenhandsImage.imageUri;
    const agentServerImageUri = customAgentServerImage.imageUri;
    const openrestyImageUri = openrestyImage.imageUri;

    // Use DockerImageAsset properties to get repository URI and tag
    // Note: imageUri is a CDK token (CloudFormation intrinsic), so string operations don't work.
    // DockerImageAsset exposes repositoryUri and imageTag properties for this purpose.
    const agentServerRepo = customAgentServerImage.repository.repositoryUri;
    const agentServerTag = customAgentServerImage.imageTag;

    // User Data script for EC2 instance (compact version to stay under 16KB)
    const userData = ec2.UserData.forLinux();
    userData.addCommands(
      '#!/bin/bash',
      'set -ex',
      'exec > >(tee /var/log/user-data.log) 2>&1',
      'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")',
      'INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)',
      'REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)',
      `error_handler() { aws sns publish --topic-arn "${alertTopic.topicArn}" --region "$REGION" --subject "OpenHands EC2 Failed" --message "Instance: $INSTANCE_ID, Line: $1" || true; exit 1; }`,
      'trap \'error_handler $LINENO\' ERR',
      'retry() { for i in 1 2 3; do "$@" && return 0; sleep 10; done; return 1; }',
      'retry dnf install -y docker',
      'retry dnf install -y amazon-efs-utils',
      'mkdir -p /etc/docker',
      'echo \'{"default-address-pools":[{"base":"172.17.0.0/12","size":24}],"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"3"}}\' > /etc/docker/daemon.json',
      'systemctl enable --now docker',
      'usermod -aG docker ec2-user',
      'chmod 666 /var/run/docker.sock',
      'curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-Linux-aarch64" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose',
      'retry dnf install -y amazon-cloudwatch-agent',
      // CloudWatch Agent configuration
      'echo \'{"agent":{"metrics_collection_interval":60,"run_as_user":"root"},"metrics":{"namespace":"CWAgent","metrics_collected":{"cpu":{"measurement":["cpu_usage_idle","cpu_usage_user"],"metrics_collection_interval":60,"totalcpu":true},"mem":{"measurement":["mem_used_percent"],"metrics_collection_interval":60},"disk":{"measurement":["disk_used_percent"],"metrics_collection_interval":60,"resources":["/","/data"]}},"append_dimensions":{"AutoScalingGroupName":"${aws:AutoScalingGroupName}","InstanceId":"${aws:InstanceId}"}}}\' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json',
      '/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json',
      'for i in {1..60}; do [ -e /dev/nvme1n1 ] && break; sleep 5; done; [ -e /dev/nvme1n1 ] || exit 1',
      'blkid /dev/nvme1n1 || mkfs -t xfs /dev/nvme1n1',
      'mkdir -p /data && mount /dev/nvme1n1 /data && echo "/dev/nvme1n1 /data xfs defaults,nofail 0 2" >> /etc/fstab',
      '# Mount EFS at /data/openhands (persists workspaces across EC2 replacement)',
      'mkdir -p /data/openhands',
      `echo "${workspaceFileSystem.fileSystemId}:/ /data/openhands efs _netdev,tls,iam,accesspoint=${workspaceAccessPoint.accessPointId} 0 0" >> /etc/fstab`,
      'retry mount -a',
      'mountpoint -q /data/openhands || exit 1',
      'mkdir -p /data/openhands/{config,workspace,.openhands} && chown -R ec2-user:ec2-user /data/openhands',
      // Generate or retrieve OH_SECRET_KEY from Secrets Manager (persists across EC2 replacement)
      // This key encrypts secrets in conversation state, enabling resume after sandbox restart
      `OH_SECRET_KEY=$(aws secretsmanager get-secret-value --secret-id openhands/sandbox-secret-key --region "$REGION" --query SecretString --output text 2>/dev/null || (SK=$(openssl rand -base64 32) && aws secretsmanager create-secret --name openhands/sandbox-secret-key --secret-string "$SK" --region "$REGION" >/dev/null && echo "$SK"))`,
      'export OH_SECRET_KEY',
      'cat > /data/openhands/docker-compose.yml << EOF',
      'services:',
      // OpenResty reverse proxy - runs as container on Docker bridge network
      // Enables direct routing to sandbox container IPs on any port
      '  openresty:',
      `    image: ${openrestyImageUri}`,
      '    container_name: openresty-proxy',
      '    restart: always',
      '    ports:',
      '      - "8080:8080"',  // ALB connects to this port for runtime traffic
      '    volumes:',
      '      # SECURITY: Docker socket access required for container discovery (read-only)',
      '      # OpenResty queries /containers/json to find sandbox container IPs for routing',
      '      # Mitigations: mounted :ro, only GET requests, no container modifications',
      '      - /var/run/docker.sock:/var/run/docker.sock:ro',
      '    depends_on:',
      '      - openhands',
      '    logging:',
      '      driver: json-file',
      '      options:',
      '        max-size: "100m"',
      '        max-file: "3"',
      '',
      '  openhands:',
      `    image: ${openhandsImageUri}`,
      '    container_name: openhands-app',
      '    restart: unless-stopped',
      '    environment:',
      '      - SANDBOX_USER_ID=0',
      `      - SANDBOX_RUNTIME_CONTAINER_IMAGE=${customRuntimeImage.imageUri}`,
      // Ensure agent-server containers bind-mount the host workspace into /workspace.
      // The host path (/data/openhands/workspace) is backed by EFS so it persists across EC2 replacement.
      // When sandboxAwsAccess is enabled, also mount the credentials file (read-only).
      sandboxAwsAccess && sandboxRoleArn
        ? '      - SANDBOX_VOLUMES=/data/openhands/workspace:/workspace:rw,/data/openhands/config/sandbox-credentials:/data/sandbox-credentials:ro'
        : '      - SANDBOX_VOLUMES=/data/openhands/workspace:/workspace:rw',
      '      - WORKSPACE_MOUNT_PATH=/data/openhands/workspace',
      // OpenHands config uses WORKSPACE_BASE for workspace root (and derives legacy mounts from it).
      // This must be a host path understood by the Docker daemon to ensure nested runtimes get a real bind mount.
      '      - WORKSPACE_BASE=/data/openhands/workspace',
      '      - LOG_ALL_EVENTS=true',
      '      - HIDE_LLM_SETTINGS=true',
      '      - USER_AUTH_CLASS=openhands.server.user_auth.cognito_user_auth.CognitoUserAuth',
      '      - LLM_MODEL=bedrock/us.anthropic.claude-opus-4-5-20251101-v1:0',
      '      - LLM_AWS_REGION_NAME=us-west-2',
      // Ensure AWS SDKs inside the container have a default region for signing/endpoint resolution
      '      - AWS_REGION=$REGION',
      '      - AWS_DEFAULT_REGION=$REGION',
      `      - AWS_S3_BUCKET=${dataBucket.bucketName}`,
      '      - FILE_STORE=s3',
      `      - FILE_STORE_PATH=${dataBucket.bucketName}`,
      // User Config feature flag and KMS key for secrets encryption
      // When USER_CONFIG_ENABLED=true, user-specific MCP configs are loaded from S3
      ...(securityOutput.userSecretsKmsKeyId ? [
        '      - USER_CONFIG_ENABLED=true',
        `      - USER_SECRETS_KMS_KEY_ID=${securityOutput.userSecretsKmsKeyId}`,
      ] : [
        '      - USER_CONFIG_ENABLED=false',
      ]),
      // OH_SECRET_KEY encrypts/decrypts secrets in conversation state (uses shell var from user-data)
      // Required by both main app (load/save conversations) and sandbox containers (runtime access)
      '      - OH_SECRET_KEY=$OH_SECRET_KEY',
      // Note: network_mode should NOT be set here as OpenHands sets it internally
      // Only set extra_hosts for MCP connection support (PR #12236)
      // When sandboxAwsAccess is enabled, also set environment variables for AWS credentials
      // OH_SECRET_KEY is dynamically injected via $OH_SECRET_KEY shell variable (set in user-data)
      sandboxAwsAccess && sandboxRoleArn
        ? '      - SANDBOX_DOCKER_RUNTIME_KWARGS={"extra_hosts":{"host.docker.internal":"host-gateway"},"environment":{"AWS_SHARED_CREDENTIALS_FILE":"/data/sandbox-credentials","AWS_DEFAULT_REGION":"$REGION","OH_SECRET_KEY":"$OH_SECRET_KEY"}}'
        : '      - SANDBOX_DOCKER_RUNTIME_KWARGS={"extra_hosts":{"host.docker.internal":"host-gateway"},"environment":{"OH_SECRET_KEY":"$OH_SECRET_KEY"}}',
      `      - AGENT_SERVER_IMAGE_REPOSITORY=${agentServerRepo}`,
      `      - AGENT_SERVER_IMAGE_TAG=${agentServerTag}`,
      '      - AGENT_ENABLE_BROWSING=false',
      '      - AGENT_ENABLE_MCP=true',
      // Environment variables injected into sandbox containers at startup
      // When sandboxAwsAccess is enabled, include AWS_SHARED_CREDENTIALS_FILE to use scoped credentials
      // OH_SECRET_KEY enables secret persistence across sandbox restarts (required for conversation resume)
      sandboxAwsAccess && sandboxRoleArn
        ? '      - SANDBOX_RUNTIME_STARTUP_ENV_VARS={"OH_PRELOAD_TOOLS":"false","AWS_SHARED_CREDENTIALS_FILE":"/data/sandbox-credentials","AWS_DEFAULT_REGION":"$REGION","OH_SECRET_KEY":"$OH_SECRET_KEY"}'
        : '      - SANDBOX_RUNTIME_STARTUP_ENV_VARS={"OH_PRELOAD_TOOLS":"false","OH_SECRET_KEY":"$OH_SECRET_KEY"}',
      // DB_* env vars enable PostgreSQL mode in OpenHands V1 (DbSessionInjector checks DB_HOST)
      // DB_SSL=require is essential for Aurora IAM auth (asyncpg requires explicit SSL)
      // Use RDS Proxy endpoint for automatic IAM token management and connection pooling
      // Note: clusterEndpoint reference kept for CloudFormation export compatibility during migration
      ...(databaseOutput ? [
        `      - DB_HOST=${databaseOutput.proxyEndpoint}`,
        `      - DB_PORT=${databaseOutput.clusterPort}`,
        `      - DB_NAME=${databaseOutput.databaseName}`,
        `      - DB_USER=${databaseOutput.databaseUser}`,
        '      - DB_SSL=require',
        `      - DB_CLUSTER_ENDPOINT=${databaseOutput.clusterEndpoint}`,
      ] : []),
      '    volumes:',
      '      - /var/run/docker.sock:/var/run/docker.sock',
      '      - /root/.docker:/root/.docker:ro',  // ECR credentials for Docker API
      '      - /data/openhands/.openhands:/root/.openhands',
      // IMPORTANT: workspace_base in config.toml is a host-path used by the Docker daemon.
      // Mount the EFS-backed host path into the container at the same absolute path so
      // the nested agent-server runtime gets a real bind mount (persists across EC2 replacement).
      '      - /data/openhands/workspace:/data/openhands/workspace',
      '      - /data/openhands/config/config.toml:/app/config.toml:ro',
      ...(databaseOutput ? ['      - /data/openhands/config/database.env:/app/database.env:ro'] : []),
      // Mount sandbox credentials file (read-only) when sandboxAwsAccess is enabled
      // OpenHands container needs this to pass credentials to sandbox containers via SANDBOX_VOLUMES
      ...(sandboxAwsAccess && sandboxRoleArn ? ['      - /data/openhands/config/sandbox-credentials:/data/openhands/config/sandbox-credentials:ro'] : []),
      '    ports:',
      '      - "3000:3000"',  // OpenHands app port (direct access from ALB for main app)
      ...(databaseOutput ? [
        '    env_file:',
        '      - /data/openhands/config/database.env',
      ] : []),
      '    extra_hosts:',
      '      - "host.docker.internal:host-gateway"',
      '',
      '  watchtower:',
      '    image: containrrr/watchtower:1.7.1',
      '    restart: unless-stopped',
      '    volumes:',
      '      - /var/run/docker.sock:/var/run/docker.sock',
      '    environment:',
      '      - WATCHTOWER_CLEANUP=true',
      '      - WATCHTOWER_POLL_INTERVAL=86400',
      '    command: openhands-app openresty-proxy',  // Watch both containers
      'EOF',
      '',
      '# Create config.toml (loaded from config/config.toml at CDK synth time)',
      'cat > /data/openhands/config/config.toml << CONFIG',
      readOpenHandsConfig(dataBucket.bucketName, agentServerImageUri),
      'CONFIG',
      '',
      // Aurora database setup via RDS Proxy with password from Secrets Manager
      // No token refresh needed - password is stable and proxy handles connection pooling
      ...(databaseOutput ? [
        `cat > /usr/local/bin/setup-db-credentials.sh << 'DBSCRIPT'\n#!/bin/bash\nset -e\nDB_HOST="${databaseOutput.proxyEndpoint}"\nDB_PORT="${databaseOutput.clusterPort}"\nDB_USER="${databaseOutput.databaseUser}"\nDB_NAME="${databaseOutput.databaseName}"\nTOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")\nREGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)\n# Get password from Secrets Manager\nSECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id openhands/database/proxy-user --region "$REGION" --query SecretString --output text 2>/dev/null || echo "")\nif [ -z "$SECRET_VALUE" ]; then echo "ERROR: Failed to retrieve database secret"; exit 1; fi\nDB_PASS=$(echo "$SECRET_VALUE" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")\nENCODED_PASS=$(python3 -c "import urllib.parse; print(urllib.parse.quote(\\"$DB_PASS\\", safe=\\"\\"))")\nmkdir -p /data/openhands/config\necho "DB_HOST=$DB_HOST" > /data/openhands/config/database.env\necho "DB_PORT=$DB_PORT" >> /data/openhands/config/database.env\necho "DB_NAME=$DB_NAME" >> /data/openhands/config/database.env\necho "DB_USER=$DB_USER" >> /data/openhands/config/database.env\necho "DB_PASS=$DB_PASS" >> /data/openhands/config/database.env\necho "DB_SSL=require" >> /data/openhands/config/database.env\necho "DATABASE_URL=postgresql://\${DB_USER}:\${ENCODED_PASS}@\${DB_HOST}:\${DB_PORT}/\${DB_NAME}?sslmode=require" >> /data/openhands/config/database.env\nchmod 600 /data/openhands/config/database.env\necho "Database credentials configured successfully"\nDBSCRIPT`,
        'chmod +x /usr/local/bin/setup-db-credentials.sh',
        '/usr/local/bin/setup-db-credentials.sh',
      ] : []),
      // Sandbox AWS credentials refresh - assumes sandboxRole and writes credentials file
      // Credentials have 15-minute lifetime, refreshed every 10 minutes via systemd timer
      ...(sandboxAwsAccess && sandboxRoleArn ? [
        `cat > /usr/local/bin/refresh-sandbox-creds.sh << 'SANDBOXSCRIPT'\n#!/bin/bash\nset -e\nROLE_ARN="${sandboxRoleArn}"\nCREDS_FILE="/data/openhands/config/sandbox-credentials"\nTOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")\nREGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)\nif [ -z "$ROLE_ARN" ]; then echo "ROLE_ARN not set, skipping credential refresh"; exit 0; fi\nCREDENTIALS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "sandbox-$(date +%s)" --external-id "openhands-sandbox" --duration-seconds 900 --output json 2>/dev/null)\nif [ $? -ne 0 ]; then echo "Failed to assume role $ROLE_ARN"; exit 1; fi\nmkdir -p "$(dirname $CREDS_FILE)"\ncat > "$CREDS_FILE" << EOF\n[default]\naws_access_key_id=$(echo $CREDENTIALS | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['AccessKeyId'])")\naws_secret_access_key=$(echo $CREDENTIALS | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['SecretAccessKey'])")\naws_session_token=$(echo $CREDENTIALS | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['SessionToken'])")\nregion=$REGION\nEOF\nchmod 600 "$CREDS_FILE"\necho "Sandbox credentials refreshed at $(date)"\nSANDBOXSCRIPT`,
        'chmod +x /usr/local/bin/refresh-sandbox-creds.sh',
        // Create systemd service and timer for credential refresh
        `cat > /etc/systemd/system/refresh-sandbox-credentials.service << 'SVCFILE'\n[Unit]\nDescription=Refresh Sandbox AWS Credentials\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/refresh-sandbox-creds.sh\nSVCFILE`,
        `cat > /etc/systemd/system/refresh-sandbox-credentials.timer << 'TIMERFILE'\n[Unit]\nDescription=Refresh Sandbox AWS Credentials Timer\n[Timer]\nOnBootSec=30sec\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\nTIMERFILE`,
        // Initial credential refresh and enable timer
        '/usr/local/bin/refresh-sandbox-creds.sh',
        'systemctl daemon-reload && systemctl enable refresh-sandbox-credentials.timer && systemctl start refresh-sandbox-credentials.timer',
      ] : []),
      `cat > /etc/systemd/system/openhands.service << SERVICE\n[Unit]\nDescription=OpenHands\nAfter=docker.service\nRequires=docker.service\n[Service]\nType=simple\nWorkingDirectory=/data/openhands\nExecStart=/usr/local/bin/docker-compose up\nExecStop=/usr/local/bin/docker-compose down\nRestart=always\nUser=root\n[Install]\nWantedBy=multi-user.target\nSERVICE`,
      `aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${cdk.Aws.ACCOUNT_ID}.dkr.ecr.$REGION.amazonaws.com`,
      'pull_with_retry() { local img=$1; for i in 1 2 3; do docker pull "$img" && return 0; sleep 15; done; return 1; }',
      `pull_with_retry "${openhandsImageUri}"`,
      `pull_with_retry "${openrestyImageUri}"`,  // OpenResty runtime proxy
      `pull_with_retry "${customRuntimeImage.imageUri}"`,  // Custom runtime with Chromium for MCP
      `pull_with_retry "${agentServerImageUri}"`,
      'set +e; trap - ERR; pull_with_retry "containrrr/watchtower:1.7.1" || echo "Watchtower pull failed, auto-updates disabled"; set -e; trap \'error_handler $LINENO\' ERR',
      'systemctl daemon-reload && systemctl enable openhands && systemctl start openhands',
      // Connect OpenResty to the Docker bridge network for sandbox container access
      // Sandbox containers use default bridge, compose network doesn't support external bridge directly
      'for i in {1..30}; do docker inspect openresty-proxy >/dev/null 2>&1 && break; sleep 2; done',
      'docker network connect bridge openresty-proxy 2>/dev/null || echo "Already connected to bridge network"',
      'echo "OpenHands setup complete!"',
    );

    // Launch Template for Graviton instances
    // Note: Let CDK generate the name to support multiple deployments in same account/region
    const launchTemplate = new ec2.LaunchTemplate(this, 'OpenHandsLaunchTemplate', {
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.M7G, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
      }),
      securityGroup: ec2SecurityGroup,
      role: ec2Role,
      userData,
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(30, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            iops: 3000,
            throughput: 125,
            encrypted: true,
          }),
        },
        {
          deviceName: '/dev/sdf',  // Will appear as /dev/nvme1n1 on Nitro instances
          volume: ec2.BlockDeviceVolume.ebs(100, {
            volumeType: ec2.EbsDeviceVolumeType.GP3,
            iops: 3000,
            throughput: 125,
            encrypted: true,
            deleteOnTermination: false,  // Preserve data on instance termination
          }),
        },
      ],
      requireImdsv2: true,
    });

    // Auto Scaling Group - let CDK generate the name to support multiple deployments
    const asg = new autoscaling.AutoScalingGroup(this, 'OpenHandsAsg', {
      vpc,
      vpcSubnets: privateSubnets,
      launchTemplate,
      minCapacity: 1,
      maxCapacity: 1,
      healthChecks: autoscaling.HealthChecks.withAdditionalChecks({
        gracePeriod: cdk.Duration.seconds(600),  // Allow time for Docker images to pull
        additionalTypes: [
          autoscaling.AdditionalHealthCheckType.ELB,
        ],
      }),
      updatePolicy: autoscaling.UpdatePolicy.rollingUpdate(),
      newInstancesProtectedFromScaleIn: false,
    });

    // Add data volume via Block Device Mapping in Launch Template
    // Note: Additional EBS volume needs to be added separately
    const cfnAsg = asg.node.defaultChild as autoscaling.CfnAutoScalingGroup;

    // Internet-facing Application Load Balancer (required for WebSocket support)
    // CloudFront VPC Origin does NOT support WebSocket connections, so we use
    // internet-facing ALB with CloudFront HttpOrigin instead.
    // Security: ALB is protected by custom origin header verification (see listener rules below)
    const alb = new elbv2.ApplicationLoadBalancer(this, 'OpenHandsAlb', {
      vpc,
      internetFacing: true,
      securityGroup: albSecurityGroup,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PUBLIC,
      },
    });

    // Target Group
    const targetGroup = new elbv2.ApplicationTargetGroup(this, 'OpenHandsTargetGroup', {
      vpc,
      port: 3000,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.INSTANCE,
      healthCheck: {
        path: '/api/health',
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        timeout: cdk.Duration.seconds(5),
        interval: cdk.Duration.seconds(30),
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // Attach ASG to Target Group
    asg.attachToApplicationTargetGroup(targetGroup);

    // Runtime Proxy Target Group (nginx on port 8080)
    // Routes /runtime/* requests to nginx which proxies to runtime containers
    const runtimeTargetGroup = new elbv2.ApplicationTargetGroup(this, 'RuntimeTargetGroup', {
      vpc,
      port: 8080,
      protocol: elbv2.ApplicationProtocol.HTTP,
      targetType: elbv2.TargetType.INSTANCE,
      healthCheck: {
        path: '/health',
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 3,
        timeout: cdk.Duration.seconds(5),
        interval: cdk.Duration.seconds(30),
      },
      deregistrationDelay: cdk.Duration.seconds(30),
    });

    // Attach ASG to Runtime Target Group
    asg.attachToApplicationTargetGroup(runtimeTargetGroup);

    // HTTP Listener with origin verification (CloudFront connects via HTTP to internet-facing ALB)
    // Default action returns 403 - only requests with valid X-Origin-Verify header are allowed
    const listener = alb.addListener('HttpListener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      defaultAction: elbv2.ListenerAction.fixedResponse(403, {
        contentType: 'text/plain',
        messageBody: 'Access Denied - Invalid Origin',
      }),
    });

    // Rule: Forward requests with valid origin verification header to main target group
    // Priority 20 (lower priority than runtime rule)
    listener.addTargetGroups('VerifiedMainRule', {
      priority: 20,
      conditions: [
        elbv2.ListenerCondition.httpHeader('X-Origin-Verify', [originVerifySecret]),
      ],
      targetGroups: [targetGroup],
    });

    // Rule: Forward /runtime/* requests with valid origin verification header
    // Priority 10 (higher priority - more specific path match)
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
    // When userConfigFunction is provided, route /api/v1/user-config/* to Lambda
    // This eliminates the need for a separate API Gateway, reducing latency and cost
    if (props.userConfigFunction) {
      // Create Lambda target group
      const userConfigTargetGroup = new elbv2.ApplicationTargetGroup(this, 'UserConfigTargetGroup', {
        targetType: elbv2.TargetType.LAMBDA,
        targets: [new targets.LambdaTarget(props.userConfigFunction)],
        healthCheck: {
          enabled: false,  // Lambda targets don't support health checks in the traditional sense
        },
      });

      // Rule: Forward /api/v1/user-config/* requests with valid origin verification header
      // Priority 5 (highest priority - most specific path match)
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

    // CloudWatch Alarms for ASG - using CDK-generated ASG name reference
    const cpuAlarm = new cloudwatch.Alarm(this, 'CpuAlarm', {
      alarmDescription: 'CPU utilization exceeds 80%',
      metric: new cloudwatch.Metric({
        namespace: 'AWS/EC2',
        metricName: 'CPUUtilization',
        dimensionsMap: {
          AutoScalingGroupName: asg.autoScalingGroupName,
        },
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 80,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    cpuAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // Memory Utilization Alarm (requires CloudWatch Agent)
    const memoryAlarm = new cloudwatch.Alarm(this, 'MemoryAlarm', {
      alarmDescription: 'Memory utilization exceeds 85%',
      metric: new cloudwatch.Metric({
        namespace: 'CWAgent',
        metricName: 'mem_used_percent',
        dimensionsMap: {
          AutoScalingGroupName: asg.autoScalingGroupName,
        },
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 85,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    memoryAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // Disk Usage Alarm
    const diskAlarm = new cloudwatch.Alarm(this, 'DiskAlarm', {
      alarmDescription: 'Disk usage exceeds 85%',
      metric: new cloudwatch.Metric({
        namespace: 'CWAgent',
        metricName: 'disk_used_percent',
        dimensionsMap: {
          AutoScalingGroupName: asg.autoScalingGroupName,
          path: '/data',
        },
        statistic: 'Average',
        period: cdk.Duration.minutes(5),
      }),
      threshold: 85,
      evaluationPeriods: 2,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    diskAlarm.addAlarmAction(new cloudwatchActions.SnsAction(alertTopic));

    // Write ALB DNS name and origin secret to SSM in us-east-1 for EdgeStack consumption
    // SSM parameter path includes the Compute stack's region to support multi-region deployments
    // Each Compute stack in a different region gets its own SSM namespace: /openhands/compute/{region}/*
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

    new cdk.CfnOutput(this, 'AsgName', {
      value: asg.autoScalingGroupName,
      description: 'Auto Scaling Group Name',
    });

    new cdk.CfnOutput(this, 'WorkspaceEfsFileSystemId', {
      value: workspaceFileSystem.fileSystemId,
      description: 'EFS file system ID for persistent OpenHands workspaces',
    });
  }
}
