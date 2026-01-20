import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as autoscaling from 'aws-cdk-lib/aws-autoscaling';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
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
}

/**
 * OpenResty configuration for runtime WebSocket proxy with dynamic container routing.
 * Routes /runtime/{conversation_id}/{port}/... to container_ip:{port}/...
 * Uses Lua to discover container IPs via Docker API based on conversation_id label.
 */
const OPENRESTY_CONFIG = `worker_processes auto;
error_log /var/log/openresty/error.log warn;
pid /usr/local/openresty/nginx/logs/nginx.pid;
events { worker_connections 1024; use epoll; multi_accept on; }
http {
  lua_package_path "/usr/local/openresty/lualib/?.lua;;";
  default_type application/octet-stream;
  access_log /var/log/openresty/access.log;
  server_tokens off;
  more_clear_headers Server;
  sendfile on; tcp_nopush on; tcp_nodelay on; keepalive_timeout 65;
  server {
    listen 8080; server_name _;
    location /health { return 200 'OK'; add_header Content-Type text/plain; }
    location ~ ^/runtime/(?<conv_id>[a-f0-9]+)/(?<target_port>\\d+)(?<remaining_path>/.*)?$ {
      set $container_ip "";
      set $internal_port "";
      set $proxy_path $remaining_path;
      if ($proxy_path = "") { set $proxy_path "/"; }
      access_by_lua_block {
        local discovery = require "docker_discovery"
        local ip,port = discovery.find_container(ngx.var.conv_id, ngx.var.target_port)
        if ip and port then
          ngx.var.container_ip = ip
          ngx.var.internal_port = port
          ngx.log(ngx.INFO, "Routing /runtime/", ngx.var.conv_id, "/", ngx.var.target_port, " to ", ip, ":", port)
        else
          ngx.log(ngx.WARN, "No container found for conversation: ", ngx.var.conv_id)
          ngx.status = 502
          ngx.say("No container found for conversation " .. ngx.var.conv_id)
          return ngx.exit(502)
        end
      }
      proxy_pass http://$container_ip:$internal_port$proxy_path$is_args$args;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_connect_timeout 60s; proxy_send_timeout 300s; proxy_read_timeout 300s;
      proxy_buffering off;
    }
    location / {
      proxy_pass http://127.0.0.1:3000;
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_connect_timeout 60s; proxy_send_timeout 300s; proxy_read_timeout 300s;
      proxy_buffering off;
    }
  }
}`;

// Lua script for Docker container discovery - minified to fit 16KB user data limit
// Maps PublicPort (host port) to container IP + PrivatePort (container internal port).
// For system ports with PublicPort mappings, returns the matching PrivatePort.
// For user app ports (not in port mappings), returns the requested port directly since
// user apps run inside the container and listen on that port.
const LUA_DOCKER_DISCOVERY = `local http=require"resty.http" local cjson=require"cjson" local _M={}
function _M.find_container(cid,hp)
local h=http.new() local ok,e=h:connect("unix:/var/run/docker.sock") if not ok then return nil,nil end
local r,e=h:request({path="/containers/json",headers={["Host"]="localhost"}}) if not r then return nil,nil end
local b=r:read_body() local ok2,cs=pcall(cjson.decode,b) if not ok2 then return nil,nil end
for _,c in ipairs(cs) do local lb=c.Labels or {} if lb["conversation_id"]==cid then
local ip=nil local ns=c.NetworkSettings and c.NetworkSettings.Networks
if ns then for _,n in pairs(ns) do if n.IPAddress and n.IPAddress~="" then ip=n.IPAddress break end end end
if ip then
local pts=c.Ports or {} for _,p in ipairs(pts) do if p.PublicPort and tostring(p.PublicPort)==hp then return ip,tostring(p.PrivatePort) end end
return ip,hp end
end end
return nil,nil
end
return _M`;

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

    const { config, networkOutput, securityOutput, monitoringOutput, databaseOutput } = props;
    const { vpc } = networkOutput;
    const { albSecurityGroup, ec2SecurityGroup, ec2Role, ec2InstanceProfile } = securityOutput;
    const { alertTopic, dataBucket } = monitoringOutput;

    // Full domain for runtime URL pattern
    const fullDomain = `${config.subDomain}.${config.domainName}`;

    // Get private subnets for EC2 and internal ALB
    const privateSubnets = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    });

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
      exclude: ['agent-server', 'agent-server-custom'],
    });

    const customAgentServerImage = new DockerImageAsset(this, 'CustomAgentServerImage', {
      directory: path.join(__dirname, '..', 'docker', 'agent-server-custom'),
      platform: Platform.LINUX_ARM64,
    });

    // Grant EC2 role permission to pull from CDK-managed ECR repositories
    customOpenhandsImage.repository.grantPull(ec2Role);
    customAgentServerImage.repository.grantPull(ec2Role);

    // Note: IAM authentication permission for Aurora PostgreSQL is granted in DatabaseStack
    // using the EC2 role ARN to avoid cyclic cross-stack dependencies

    // Extract repository URI and image tag for user data
    // DockerImageAsset.imageUri format: <account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>
    const openhandsImageUri = customOpenhandsImage.imageUri;
    const agentServerImageUri = customAgentServerImage.imageUri;

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
      'mkdir -p /etc/docker',
      'echo \'{"default-address-pools":[{"base":"172.17.0.0/12","size":24}],"log-driver":"json-file","log-opts":{"max-size":"100m","max-file":"3"}}\' > /etc/docker/daemon.json',
      'systemctl enable --now docker',
      'usermod -aG docker ec2-user',
      'chmod 666 /var/run/docker.sock',
      'curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-Linux-aarch64" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose',
      'retry dnf install -y amazon-cloudwatch-agent',
      // Install OpenResty for dynamic container routing via Lua
      'wget -q https://openresty.org/package/amazon/openresty.repo -O /etc/yum.repos.d/openresty.repo',
      'dnf check-update || true',  // check-update returns 100 when updates available, not an error
      'retry dnf install -y openresty openresty-opm openresty-resty',
      'HOME=/root /usr/local/openresty/bin/opm get ledgetech/lua-resty-http',  // opm requires HOME
      'mkdir -p /var/log/openresty',
      'echo \'{"agent":{"metrics_collection_interval":60,"run_as_user":"root"},"metrics":{"namespace":"CWAgent","metrics_collected":{"cpu":{"measurement":["cpu_usage_idle","cpu_usage_user"],"metrics_collection_interval":60,"totalcpu":true},"mem":{"measurement":["mem_used_percent"],"metrics_collection_interval":60},"disk":{"measurement":["disk_used_percent"],"metrics_collection_interval":60,"resources":["/","/data"]}},"append_dimensions":{"AutoScalingGroupName":"${aws:AutoScalingGroupName}","InstanceId":"${aws:InstanceId}"}}}\' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json',
      '/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json',
      `cat > /usr/local/openresty/nginx/conf/nginx.conf << 'EOF'\n${OPENRESTY_CONFIG}\nEOF`,
      `cat > /usr/local/openresty/lualib/docker_discovery.lua << 'LUA'\n${LUA_DOCKER_DISCOVERY}\nLUA`,
      'systemctl enable --now openresty',
      'for i in {1..60}; do [ -e /dev/nvme1n1 ] && break; sleep 5; done; [ -e /dev/nvme1n1 ] || exit 1',
      'blkid /dev/nvme1n1 || mkfs -t xfs /dev/nvme1n1',
      'mkdir -p /data && mount /dev/nvme1n1 /data && echo "/dev/nvme1n1 /data xfs defaults,nofail 0 2" >> /etc/fstab',
      'mkdir -p /data/openhands/{config,workspace,.openhands} && chown -R ec2-user:ec2-user /data/openhands',
      `RUNTIME_VERSION=$(aws ssm get-parameter --name "${runtimeVersionParam.parameterName}" --region $REGION --query "Parameter.Value" --output text 2>/dev/null || echo "${DEFAULT_RUNTIME_VERSION}")`,
      'cat > /data/openhands/docker-compose.yml << EOF',
      'services:',
      '  openhands:',
      `    image: ${openhandsImageUri}`,
      '    container_name: openhands-app',
      '    restart: unless-stopped',
      '    environment:',
      '      - SANDBOX_USER_ID=0',
      '      - SANDBOX_RUNTIME_CONTAINER_IMAGE=docker.openhands.dev/openhands/runtime:$RUNTIME_VERSION',
      '      - WORKSPACE_MOUNT_PATH=/data/openhands/workspace',
      '      - LOG_ALL_EVENTS=true',
      '      - HIDE_LLM_SETTINGS=true',
      '      - USER_AUTH_CLASS=openhands.server.user_auth.cognito_user_auth.CognitoUserAuth',
      '      - LLM_MODEL=bedrock/us.anthropic.claude-opus-4-5-20251101-v1:0',
      '      - LLM_AWS_REGION_NAME=us-west-2',
      `      - AWS_S3_BUCKET=${dataBucket.bucketName}`,
      '      - FILE_STORE=s3',
      `      - FILE_STORE_PATH=${dataBucket.bucketName}`,
      // Note: network_mode should NOT be set here as OpenHands sets it internally
      // Only set extra_hosts for MCP connection support (PR #12236)
      '      - SANDBOX_DOCKER_RUNTIME_KWARGS={"extra_hosts":{"host.docker.internal":"host-gateway"}}',
      `      - AGENT_SERVER_IMAGE_REPOSITORY=${agentServerRepo}`,
      `      - AGENT_SERVER_IMAGE_TAG=${agentServerTag}`,
      '      - AGENT_ENABLE_BROWSING=false',
      '      - AGENT_ENABLE_MCP=false',
      '      - SANDBOX_RUNTIME_STARTUP_ENV_VARS={"OH_PRELOAD_TOOLS":"false"}',
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
      '      - /data/openhands/workspace:/opt/workspace_base',
      '      - /data/openhands/config/config.toml:/app/config.toml:ro',
      ...(databaseOutput ? ['      - /data/openhands/config/database.env:/app/database.env:ro'] : []),
      '    ports:',
      '      - "3000:3000"',
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
      '    command: openhands-app',
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
      `cat > /etc/systemd/system/openhands.service << SERVICE\n[Unit]\nDescription=OpenHands\nAfter=docker.service\nRequires=docker.service\n[Service]\nType=simple\nWorkingDirectory=/data/openhands\nExecStart=/usr/local/bin/docker-compose up\nExecStop=/usr/local/bin/docker-compose down\nRestart=always\nUser=root\n[Install]\nWantedBy=multi-user.target\nSERVICE`,
      `aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin ${cdk.Aws.ACCOUNT_ID}.dkr.ecr.$REGION.amazonaws.com`,
      'pull_with_retry() { local img=$1; for i in 1 2 3; do docker pull "$img" && return 0; sleep 15; done; return 1; }',
      `pull_with_retry "${openhandsImageUri}"`,
      'pull_with_retry "docker.openhands.dev/openhands/runtime:$RUNTIME_VERSION"',
      `pull_with_retry "${agentServerImageUri}"`,
      'set +e; trap - ERR; pull_with_retry "containrrr/watchtower:1.7.1" || echo "Watchtower pull failed, auto-updates disabled"; set -e; trap \'error_handler $LINENO\' ERR',
      'systemctl daemon-reload && systemctl enable openhands && systemctl start openhands',
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

    // Internet-facing Application Load Balancer
    // Note: CloudFront VPC Origin does NOT support WebSocket connections.
    // We use internet-facing ALB with CloudFront HttpOrigin instead.
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

    // HTTP Listener (CloudFront connects via HTTP to internet-facing ALB)
    const listener = alb.addListener('HttpListener', {
      port: 80,
      protocol: elbv2.ApplicationProtocol.HTTP,
      defaultTargetGroups: [targetGroup],
    });

    // Add listener rule for runtime proxy paths (/runtime/*)
    listener.addTargetGroups('RuntimeRule', {
      priority: 10,
      conditions: [
        elbv2.ListenerCondition.pathPatterns(['/runtime/*']),
      ],
      targetGroups: [runtimeTargetGroup],
    });

    // Store outputs
    this.output = {
      targetGroup,
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
  }
}
