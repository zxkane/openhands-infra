import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';
import { OpenHandsConfig, NetworkStackOutput, SecurityStackOutput } from './interfaces.js';

export interface SecurityStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
  dataBucket: s3.IBucket;
  /** Enable sandbox AWS access (default: false) */
  sandboxAwsAccess?: boolean;
  /** Path to custom policy JSON file (default: config/sandbox-aws-policy.json) */
  sandboxAwsPolicyFile?: string;
}

/**
 * SecurityStack - Creates IAM Roles and Security Groups for Fargate services
 *
 * This stack implements the principle of least privilege for all IAM policies
 * and creates security groups with minimal required access.
 */
export class SecurityStack extends cdk.Stack {
  public readonly output: SecurityStackOutput;

  constructor(scope: Construct, id: string, props: SecurityStackProps) {
    super(scope, id, props);

    const { config, networkOutput, dataBucket, sandboxAwsAccess, sandboxAwsPolicyFile } = props;
    const { vpc, vpcEndpointSecurityGroup } = networkOutput;

    // Security Group for ALB
    const albSecurityGroup = new ec2.SecurityGroup(this, 'AlbSecurityGroup', {
      vpc,
      description: 'Security group for Application Load Balancer',
      allowAllOutbound: false,
    });

    // CloudFront Origin-Facing Managed Prefix List IDs per region
    // These are AWS-managed prefix lists for CloudFront origin-facing IPs
    const cloudfrontPrefixListIds: Record<string, string> = {
      'us-east-1': 'pl-3b927c52',
      'us-east-2': 'pl-b6a144df',
      'us-west-1': 'pl-4ea04527',
      'us-west-2': 'pl-82a045eb',
      'ap-northeast-1': 'pl-58a04531',
      'ap-northeast-2': 'pl-22a6434b',
      'ap-southeast-1': 'pl-31a34658',
      'ap-southeast-2': 'pl-b8a742d1',
      'eu-west-1': 'pl-4fa04526',
      'eu-central-1': 'pl-a3a144ca',
    };

    const cloudfrontPrefixListId = cloudfrontPrefixListIds[config.region];
    if (!cloudfrontPrefixListId) {
      throw new Error(`CloudFront prefix list ID not found for region: ${config.region}`);
    }

    // Allow inbound from CloudFront Managed Prefix List
    albSecurityGroup.addIngressRule(
      ec2.Peer.prefixList(cloudfrontPrefixListId),
      ec2.Port.tcp(80),
      'Allow HTTP from CloudFront'
    );

    // Security Group for Fargate app and openresty services
    // Note: Construct ID kept as 'Ec2SecurityGroup' for CloudFormation export compatibility
    // with existing Compute/Database stacks that reference this export.
    const appServiceSecurityGroup = new ec2.SecurityGroup(this, 'Ec2SecurityGroup', {
      vpc,
      description: 'Security group for OpenHands Fargate app and openresty services',
      allowAllOutbound: false,
    });

    // Security Group for EFS (OpenHands workspaces)
    const efsSecurityGroup = new ec2.SecurityGroup(this, 'EfsSecurityGroup', {
      vpc,
      description: 'Security group for OpenHands EFS (NFS)',
      allowAllOutbound: false,
    });

    // Allow NFS from Fargate app service to EFS
    efsSecurityGroup.addIngressRule(
      appServiceSecurityGroup,
      ec2.Port.tcp(2049),
      'Allow NFS from OpenHands Fargate app service'
    );

    // Allow inbound from ALB on port 3000 (OpenHands app)
    appServiceSecurityGroup.addIngressRule(
      albSecurityGroup,
      ec2.Port.tcp(3000),
      'Allow traffic from ALB to OpenHands app'
    );

    // Allow inbound from ALB on port 8080 (OpenResty runtime proxy)
    appServiceSecurityGroup.addIngressRule(
      albSecurityGroup,
      ec2.Port.tcp(8080),
      'Allow traffic from ALB to OpenResty runtime proxy'
    );

    // Allow outbound to VPC Endpoints (HTTPS)
    appServiceSecurityGroup.addEgressRule(
      vpcEndpointSecurityGroup,
      ec2.Port.tcp(443),
      'Allow HTTPS to VPC Endpoints'
    );

    // Allow outbound to NAT Gateway for external registries and services
    appServiceSecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS outbound for external services'
    );

    // Allow outbound NFS to EFS
    appServiceSecurityGroup.addEgressRule(
      efsSecurityGroup,
      ec2.Port.tcp(2049),
      'Allow NFS to OpenHands EFS'
    );

    // ALB outbound to Fargate app service (OpenHands app)
    albSecurityGroup.addEgressRule(
      appServiceSecurityGroup,
      ec2.Port.tcp(3000),
      'Allow traffic to OpenHands app'
    );

    // ALB outbound to Fargate openresty service (runtime proxy)
    albSecurityGroup.addEgressRule(
      appServiceSecurityGroup,
      ec2.Port.tcp(8080),
      'Allow traffic to OpenResty runtime proxy'
    );

    // ========================================
    // IAM Task Role for Fargate App Service
    // ========================================
    // Note: Construct ID kept as 'OpenHandsEc2Role' for CloudFormation export compatibility
    // with existing Compute/Database stacks that reference this export. The role principal
    // is changed from ec2.amazonaws.com to ecs-tasks.amazonaws.com (in-place update, no replacement).
    const appTaskRole = new iam.Role(this, 'OpenHandsEc2Role', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'IAM task role for OpenHands Fargate app service',
    });

    // Custom policy for Bedrock access
    // Supports both foundation models (Claude 3.x) and inference profiles (Claude 4.x)
    appTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'BedrockAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'bedrock:InvokeModel',
        'bedrock:InvokeModelWithResponseStream',
      ],
      resources: [
        // Foundation models (Claude 3.x and earlier)
        'arn:aws:bedrock:*::foundation-model/anthropic.claude-*',
        'arn:aws:bedrock:*::foundation-model/us.anthropic.claude-*',
        // Inference profiles (Claude 4.x - Opus 4.5, Sonnet 4, etc.)
        `arn:aws:bedrock:${config.region}:${this.account}:inference-profile/*anthropic.claude*`,
        // Cross-region inference profiles (global prefix)
        `arn:aws:bedrock:*:${this.account}:inference-profile/global.anthropic.claude*`,
      ],
    }));

    // ECS Execute Command requires SSM Messages permissions on the task role
    appTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EcsExecAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'ssmmessages:CreateControlChannel',
        'ssmmessages:CreateDataChannel',
        'ssmmessages:OpenControlChannel',
        'ssmmessages:OpenDataChannel',
      ],
      resources: ['*'],
    }));

    // ========================================
    // Sandbox Secret Key (for session encryption)
    // ========================================
    const sandboxSecretKeyName = 'openhands/sandbox-secret-key';
    const sandboxSecretKey = secretsmanager.Secret.fromSecretNameV2(
      this,
      'SandboxSecretKey',
      sandboxSecretKeyName
    );

    // Custom policy for CloudWatch Logs
    appTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'CloudWatchLogsAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogGroup',
        'logs:CreateLogStream',
        'logs:PutLogEvents',
        'logs:DescribeLogStreams',
      ],
      resources: [
        `arn:aws:logs:${config.region}:${this.account}:log-group:/openhands/*`,
      ],
    }));

    // Custom policy for S3 data bucket access (OpenHands file store)
    appTaskRole.addToPolicy(new iam.PolicyStatement({
      sid: 'S3DataBucketAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        's3:GetObject',
        's3:PutObject',
        's3:DeleteObject',
        's3:ListBucket',
      ],
      resources: [
        dataBucket.bucketArn,
        `${dataBucket.bucketArn}/*`,
      ],
    }));

    // ========================================
    // IAM Execution Role for Fargate Tasks
    // ========================================
    // Used by ECS agent to pull images, write logs, and read secrets
    const appExecutionRole = new iam.Role(this, 'AppExecutionRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      description: 'Execution role for OpenHands Fargate tasks (image pull, logs, secrets)',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AmazonECSTaskExecutionRolePolicy'),
      ],
    });

    // Grant execution role read access to sandbox secret key (for ECS secret injection)
    sandboxSecretKey.grantRead(appExecutionRole);

    // Grant execution role read access to proxy user secret (for DB_PASS injection)
    const proxyUserSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      'ProxyUserSecretRef',
      'openhands/database/proxy-user'
    );
    proxyUserSecret.grantRead(appExecutionRole);

    // Optional: Sandbox IAM Role for container AWS access
    let sandboxRoleArn: string | undefined;

    if (sandboxAwsAccess) {
      // Load user-defined policy from file
      const policyFilePath = sandboxAwsPolicyFile || path.join(process.cwd(), 'config', 'sandbox-aws-policy.json');
      if (!fs.existsSync(policyFilePath)) {
        throw new Error(`Sandbox AWS policy file not found: ${policyFilePath}`);
      }
      const policyDocument = JSON.parse(fs.readFileSync(policyFilePath, 'utf-8'));

      // Create sandbox role — Fargate sandboxes use native ECS task role, not STS
      // This role is kept for backward compatibility with EC2-based sandbox mode
      const sandboxRole = new iam.Role(this, 'OpenHandsSandboxRole', {
        assumedBy: new iam.ArnPrincipal(appTaskRole.roleArn),
        externalIds: ['openhands-sandbox'],
        description: 'IAM role for OpenHands sandbox containers with scoped AWS access',
      });

      for (const statement of policyDocument.Statement) {
        sandboxRole.addToPolicy(iam.PolicyStatement.fromJson(statement));
      }

      // Explicit deny policy (ALWAYS applied, cannot be overridden)
      sandboxRole.addToPolicy(new iam.PolicyStatement({
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

      // Grant app task role permission to assume sandbox role
      appTaskRole.addToPolicy(new iam.PolicyStatement({
        sid: 'AssumeSandboxRole',
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: [sandboxRole.roleArn],
        conditions: {
          StringEquals: {
            'sts:ExternalId': 'openhands-sandbox',
          },
        },
      }));

      sandboxRoleArn = sandboxRole.roleArn;

      new cdk.CfnOutput(this, 'SandboxRoleArn', {
        value: sandboxRole.roleArn,
        description: 'Sandbox IAM Role ARN for container AWS access',
      });
    }

    // ========================================
    // KMS Key for User Secrets Encryption
    // ========================================
    const userSecretsKmsKey = new kms.Key(this, 'UserSecretsKmsKey', {
      alias: 'alias/openhands-user-secrets',
      description: 'KMS key for encrypting OpenHands user secrets (API keys, tokens)',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            sid: 'EnableRootAccess',
            effect: iam.Effect.ALLOW,
            principals: [new iam.AccountRootPrincipal()],
            actions: ['kms:*'],
            resources: ['*'],
          }),
          new iam.PolicyStatement({
            sid: 'DenySensitiveOperations',
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: [
              'kms:CreateGrant',
              'kms:RetireGrant',
              'kms:RevokeGrant',
              'kms:ScheduleKeyDeletion',
              'kms:CancelKeyDeletion',
            ],
            resources: ['*'],
            conditions: {
              StringNotEquals: {
                'aws:PrincipalType': 'Root',
              },
            },
          }),
        ],
      }),
    });

    // Grant app task role permission to use the KMS key for decrypt and generate data keys
    userSecretsKmsKey.grantDecrypt(appTaskRole);
    userSecretsKmsKey.grant(appTaskRole, 'kms:GenerateDataKey', 'kms:GenerateDataKeyWithoutPlaintext');

    new cdk.CfnOutput(this, 'UserSecretsKmsKeyArn', {
      value: userSecretsKmsKey.keyArn,
      description: 'KMS Key ARN for user secrets encryption',
    });

    new cdk.CfnOutput(this, 'UserSecretsKmsKeyId', {
      value: userSecretsKmsKey.keyId,
      description: 'KMS Key ID for user secrets encryption',
    });

    // Store outputs
    this.output = {
      albSecurityGroup,
      appServiceSecurityGroup,
      appServiceSecurityGroupId: appServiceSecurityGroup.securityGroupId,
      efsSecurityGroup,
      efsSecurityGroupId: efsSecurityGroup.securityGroupId,
      appTaskRole,
      appExecutionRole,
      sandboxRoleArn,
      userSecretsKmsKeyArn: userSecretsKmsKey.keyArn,
      userSecretsKmsKeyId: userSecretsKmsKey.keyId,
      sandboxSecretKeyName: sandboxSecretKey.secretName,
    };

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'AppTaskRoleArn', {
      value: appTaskRole.roleArn,
      description: 'Fargate App Task Role ARN',
    });

    new cdk.CfnOutput(this, 'AppExecutionRoleArn', {
      value: appExecutionRole.roleArn,
      description: 'Fargate App Execution Role ARN',
    });
  }
}
