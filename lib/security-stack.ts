import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
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
 * SecurityStack - Creates IAM Roles and Security Groups
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
    // Note: CloudFront connects via HTTP to internet-facing ALB (HttpOrigin)
    albSecurityGroup.addIngressRule(
      ec2.Peer.prefixList(cloudfrontPrefixListId),
      ec2.Port.tcp(80),
      'Allow HTTP from CloudFront'
    );

    // Security Group for EC2 (OpenHands)
    const ec2SecurityGroup = new ec2.SecurityGroup(this, 'Ec2SecurityGroup', {
      vpc,
      description: 'Security group for OpenHands EC2 instances',
      allowAllOutbound: false,
    });

    // Security Group for EFS (OpenHands workspaces)
    const efsSecurityGroup = new ec2.SecurityGroup(this, 'EfsSecurityGroup', {
      vpc,
      description: 'Security group for OpenHands EFS (NFS)',
      allowAllOutbound: false,
    });

    // Allow NFS from EC2 instances to EFS
    efsSecurityGroup.addIngressRule(
      ec2SecurityGroup,
      ec2.Port.tcp(2049),
      'Allow NFS from OpenHands EC2 instances'
    );

    // Allow inbound from ALB on port 3000 (OpenHands app)
    ec2SecurityGroup.addIngressRule(
      albSecurityGroup,
      ec2.Port.tcp(3000),
      'Allow traffic from ALB to OpenHands app'
    );

    // Allow inbound from ALB on port 8080 (nginx runtime proxy)
    ec2SecurityGroup.addIngressRule(
      albSecurityGroup,
      ec2.Port.tcp(8080),
      'Allow traffic from ALB to nginx runtime proxy'
    );

    // Allow outbound to VPC Endpoints (HTTPS)
    ec2SecurityGroup.addEgressRule(
      vpcEndpointSecurityGroup,
      ec2.Port.tcp(443),
      'Allow HTTPS to VPC Endpoints'
    );

    // Allow outbound to NAT Gateway for Docker Hub / external registries
    ec2SecurityGroup.addEgressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS outbound for Docker registry'
    );

    // Allow outbound NFS to EFS (EC2 SG has allowAllOutbound=false)
    ec2SecurityGroup.addEgressRule(
      efsSecurityGroup,
      ec2.Port.tcp(2049),
      'Allow NFS to OpenHands EFS'
    );

    // ALB outbound to EC2 (OpenHands app)
    albSecurityGroup.addEgressRule(
      ec2SecurityGroup,
      ec2.Port.tcp(3000),
      'Allow traffic to OpenHands app'
    );

    // ALB outbound to EC2 (nginx runtime proxy)
    albSecurityGroup.addEgressRule(
      ec2SecurityGroup,
      ec2.Port.tcp(8080),
      'Allow traffic to nginx runtime proxy'
    );

    // Note: VPC Endpoint SG already allows inbound from VPC CIDR in NetworkStack
    // No additional rule needed here to avoid cyclic dependency

    // IAM Role for EC2 Instance Profile
    const ec2Role = new iam.Role(this, 'OpenHandsEc2Role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      description: 'IAM role for OpenHands EC2 instances',
    });

    // Attach AWS managed policies
    ec2Role.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore')
    );
    ec2Role.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName('CloudWatchAgentServerPolicy')
    );

    // Custom policy for Bedrock access
    // Supports both foundation models (Claude 3.x) and inference profiles (Claude 4.x)
    ec2Role.addToPolicy(new iam.PolicyStatement({
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

    // Custom policy for Secrets Manager (for optional secrets)
    ec2Role.addToPolicy(new iam.PolicyStatement({
      sid: 'SecretsManagerAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'secretsmanager:GetSecretValue',
      ],
      resources: [
        `arn:aws:secretsmanager:${config.region}:${this.account}:secret:openhands/*`,
      ],
    }));

    // ECR authorization token - required for docker login to any ECR repository
    // Note: GetAuthorizationToken is a service-level action that requires resource: '*'
    // Repository-specific permissions (BatchGetImage, etc.) are granted by
    // DockerImageAsset.repository.grantPull() in compute-stack.ts
    ec2Role.addToPolicy(new iam.PolicyStatement({
      sid: 'EcrAuthorizationToken',
      effect: iam.Effect.ALLOW,
      actions: [
        'ecr:GetAuthorizationToken',
      ],
      resources: ['*'],
    }));

    // Custom policy for CloudWatch Logs
    ec2Role.addToPolicy(new iam.PolicyStatement({
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
    ec2Role.addToPolicy(new iam.PolicyStatement({
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

    // Create Instance Profile
    const ec2InstanceProfile = new iam.CfnInstanceProfile(this, 'OpenHandsInstanceProfile', {
      roles: [ec2Role.roleName],
    });

    // Optional: Sandbox IAM Role for container AWS access
    // This role is assumed by sandbox containers to access AWS services
    // with explicit deny on sensitive operations
    let sandboxRoleArn: string | undefined;

    if (sandboxAwsAccess) {
      // Load user-defined policy from file
      const policyFilePath = sandboxAwsPolicyFile || path.join(process.cwd(), 'config', 'sandbox-aws-policy.json');
      if (!fs.existsSync(policyFilePath)) {
        throw new Error(`Sandbox AWS policy file not found: ${policyFilePath}`);
      }
      const policyDocument = JSON.parse(fs.readFileSync(policyFilePath, 'utf-8'));

      // Create sandbox role with trust policy allowing EC2 role to assume it
      const sandboxRole = new iam.Role(this, 'OpenHandsSandboxRole', {
        assumedBy: new iam.ArnPrincipal(ec2Role.roleArn),
        externalIds: ['openhands-sandbox'],
        description: 'IAM role for OpenHands sandbox containers with scoped AWS access',
      });

      // Attach user-defined policy statements
      for (const statement of policyDocument.Statement) {
        sandboxRole.addToPolicy(iam.PolicyStatement.fromJson(statement));
      }

      // Attach explicit deny policy (ALWAYS applied, cannot be overridden)
      // These actions are denied regardless of the user-defined policy
      sandboxRole.addToPolicy(new iam.PolicyStatement({
        sid: 'DenySensitiveOperations',
        effect: iam.Effect.DENY,
        actions: [
          // IAM User Management
          'iam:CreateUser',
          'iam:DeleteUser',
          'iam:CreateAccessKey',
          'iam:DeleteAccessKey',
          'iam:UpdateAccessKey',
          // IAM Policy Management
          'iam:AttachUserPolicy',
          'iam:DetachUserPolicy',
          'iam:PutUserPolicy',
          'iam:DeleteUserPolicy',
          'iam:AttachRolePolicy',
          'iam:DetachRolePolicy',
          'iam:PutRolePolicy',
          'iam:DeleteRolePolicy',
          // IAM Role Management
          'iam:CreateRole',
          'iam:DeleteRole',
          'iam:UpdateAssumeRolePolicy',
          // Account-level Operations
          'organizations:*',
          'account:*',
          'billing:*',
          // Prevent lateral movement
          'sts:AssumeRole',
        ],
        resources: ['*'],
      }));

      // Grant EC2 role permission to assume sandbox role with external ID
      ec2Role.addToPolicy(new iam.PolicyStatement({
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

      // CloudFormation output for sandbox role
      new cdk.CfnOutput(this, 'SandboxRoleArn', {
        value: sandboxRole.roleArn,
        description: 'Sandbox IAM Role ARN for container AWS access',
      });
    }

    // ========================================
    // KMS Key for User Secrets Encryption
    // ========================================
    // Creates a KMS key for encrypting user-specific secrets (API keys, tokens)
    // stored in S3. Uses envelope encryption: KMS encrypts data keys, data keys encrypt secrets.

    const userSecretsKmsKey = new kms.Key(this, 'UserSecretsKmsKey', {
      alias: 'alias/openhands-user-secrets',
      description: 'KMS key for encrypting OpenHands user secrets (API keys, tokens)',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      // Restrict key usage to encrypt/decrypt only (no sign/verify)
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
    });

    // Grant EC2 role permission to use the KMS key for decrypt and generate data keys
    // Required for the OpenHands app to decrypt user secrets during conversation creation
    userSecretsKmsKey.grantDecrypt(ec2Role);
    userSecretsKmsKey.grant(ec2Role, 'kms:GenerateDataKey', 'kms:GenerateDataKeyWithoutPlaintext');

    // CloudFormation output for KMS key
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
      ec2SecurityGroup,
      ec2SecurityGroupId: ec2SecurityGroup.securityGroupId,
      efsSecurityGroup,
      efsSecurityGroupId: efsSecurityGroup.securityGroupId,
      ec2Role,
      ec2InstanceProfile,
      sandboxRoleArn,
      userSecretsKmsKeyArn: userSecretsKmsKey.keyArn,
      userSecretsKmsKeyId: userSecretsKmsKey.keyId,
    };

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'Ec2RoleArn', {
      value: ec2Role.roleArn,
      description: 'EC2 Instance Role ARN',
    });
  }
}
