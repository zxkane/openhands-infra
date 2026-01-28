import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as s3 from 'aws-cdk-lib/aws-s3';

/**
 * Configuration for the OpenHands infrastructure deployment
 */
export interface OpenHandsConfig {
  /** Existing VPC ID to deploy into */
  vpcId: string;
  /** Existing Route 53 Hosted Zone ID */
  hostedZoneId: string;
  /** Domain name (e.g., example.com) */
  domainName: string;
  /** Subdomain for OpenHands (e.g., openhands -> openhands.example.com) */
  subDomain: string;
  /** AWS Region for deployment */
  region: string;
  /** Display name used by the Cognito hosted authentication pages (managed login) */
  siteName?: string;
}

/**
 * Output from AuthStack (Cognito)
 */
export interface AuthStackOutput {
  userPoolId: string;
  userPoolDomainPrefix: string;
  userPoolClientId: string;
  /** Secrets Manager secret name that holds the Cognito app client secret */
  clientSecretName: string;
  /** Region where the user pool (and domain) exist */
  region: string;
}

/**
 * Output from NetworkStack
 */
export interface NetworkStackOutput {
  vpc: ec2.IVpc;
  vpcId: string;
  vpcEndpointSecurityGroup: ec2.ISecurityGroup;
}

/**
 * Output from SecurityStack
 */
export interface SecurityStackOutput {
  albSecurityGroup: ec2.ISecurityGroup;
  ec2SecurityGroup: ec2.ISecurityGroup;
  ec2SecurityGroupId: string;
  /** Security group for EFS (NFS) used to persist workspaces */
  efsSecurityGroup: ec2.ISecurityGroup;
  efsSecurityGroupId: string;
  ec2Role: iam.IRole;
  ec2InstanceProfile: iam.CfnInstanceProfile;
  /** IAM role ARN for sandbox containers (optional, only when sandboxAwsAccess is enabled) */
  sandboxRoleArn?: string;
  /** KMS key ARN for user secrets encryption (optional, only when user config enabled) */
  userSecretsKmsKeyArn?: string;
  /** KMS key ID for user secrets encryption (optional, only when user config enabled) */
  userSecretsKmsKeyId?: string;
}

/**
 * Output from MonitoringStack
 */
export interface MonitoringStackOutput {
  appLogGroup: logs.ILogGroup;
  alertTopic: sns.ITopic;
  dataBucket: s3.IBucket;
}

/**
 * Output from ComputeStack
 */
export interface ComputeStackOutput {
  targetGroup: elbv2.IApplicationTargetGroup;
  /** Secret value for CloudFront origin verification header (X-Origin-Verify) */
  originVerifySecret: string;
  /** Region where the Compute stack is deployed (for SSM parameter path) */
  computeRegion: string;
}

/**
 * Output from DatabaseStack (Aurora Serverless v2 with IAM Authentication)
 */
export interface DatabaseStackOutput {
  clusterEndpoint: string;
  clusterPort: string;
  clusterResourceId: string;
  databaseName: string;
  databaseUser: string;
  securityGroupId: string;
  /** RDS Proxy endpoint for connection pooling and IAM auth management */
  proxyEndpoint: string;
}

/**
 * Output from UserConfigStack (User Configuration API)
 */
export interface UserConfigStackOutput {
  /** Lambda function ARN for user config API */
  lambdaFunctionArn: string;
  /** Lambda function name for user config API */
  lambdaFunctionName: string;
  /** KMS key ARN for user secrets encryption */
  kmsKeyArn: string;
  /** KMS key ID for user secrets encryption */
  kmsKeyId: string;
}
