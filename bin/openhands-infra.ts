#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/network-stack.js';
import { SecurityStack } from '../lib/security-stack.js';
import { MonitoringStack } from '../lib/monitoring-stack.js';
import { DatabaseStack } from '../lib/database-stack.js';
import { ComputeStack } from '../lib/compute-stack.js';
import { AuthStack } from '../lib/auth-stack.js';
import { EdgeStack } from '../lib/edge-stack.js';
import { OpenHandsConfig } from '../lib/interfaces.js';

const app = new cdk.App();

// Get configuration from context
const vpcId = app.node.tryGetContext('vpcId');
const hostedZoneId = app.node.tryGetContext('hostedZoneId');
const domainName = app.node.tryGetContext('domainName');
const subDomain = app.node.tryGetContext('subDomain') || 'openhands';
const region = app.node.tryGetContext('region') || process.env.CDK_DEFAULT_REGION || 'us-east-1';
const siteName = app.node.tryGetContext('siteName') || 'Openhands on AWS';

// Validate required context
if (!vpcId) {
  throw new Error('Missing required context: vpcId. Use --context vpcId=vpc-xxxxxxxx');
}
if (!hostedZoneId) {
  throw new Error('Missing required context: hostedZoneId. Use --context hostedZoneId=Z0123456789ABC');
}
if (!domainName) {
  throw new Error('Missing required context: domainName. Use --context domainName=example.com');
}

const config: OpenHandsConfig = {
  vpcId,
  hostedZoneId,
  domainName,
  subDomain,
  region,
  siteName,
};

// Stack naming prefix
const prefix = 'OpenHands';

const fullDomain = `${config.subDomain}.${config.domainName}`;

/**
 * Normalizes an array of strings by trimming whitespace and filtering empty values.
 */
function normalizeStringArray(arr: unknown[]): string[] {
  return arr.map(v => String(v).trim()).filter(Boolean);
}

/**
 * Parses domain list from CDK context, supporting multiple input formats:
 * - Native array: ["domain1.com", "domain2.com"]
 * - JSON string: '["domain1.com", "domain2.com"]'
 * - Comma-separated string: "domain1.com, domain2.com"
 * @param value - The raw context value (unknown type from CDK context)
 * @param fallback - Default value if parsing fails or value is empty
 * @returns Array of trimmed, non-empty domain strings
 */
function parseDomainList(value: unknown, fallback: string[]): string[] {
  if (Array.isArray(value)) {
    return normalizeStringArray(value);
  }
  if (typeof value === 'string' && value.trim() !== '') {
    const trimmed = value.trim();
    if (trimmed.startsWith('[')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return normalizeStringArray(parsed);
        }
      } catch (error) {
        console.warn(`Failed to parse authCallbackDomains as JSON: ${error instanceof Error ? error.message : 'Unknown error'}. Falling back to comma-separated parsing.`);
        // fall through to comma-separated parsing
      }
    }
    return trimmed.split(',').map(v => v.trim()).filter(Boolean);
  }
  return fallback;
}

/**
 * Gets a trimmed string from CDK context, returning fallback if empty or not a string.
 */
function getContextString(key: string, fallback: string | undefined): string | undefined {
  const raw = app.node.tryGetContext(key);
  if (typeof raw === 'string' && raw.trim() !== '') {
    return raw.trim();
  }
  return fallback;
}

const authCallbackDomains = parseDomainList(
  app.node.tryGetContext('authCallbackDomains'),
  [fullDomain]
);

const authDomainPrefixSuffix = getContextString('authDomainPrefixSuffix', 'shared') as string;
const edgeStackSuffix = getContextString('edgeStackSuffix', undefined);

// Backwards-compatible default: if no suffix is provided, keep the legacy stack name `OpenHands-Edge`
// so existing deployments can be updated in-place without Route 53 record conflicts.
const edgeStackId = edgeStackSuffix
  ? `${prefix}-Edge-${edgeStackSuffix}`
  : `${prefix}-Edge`;

const skipS3Endpoint = app.node.tryGetContext('skipS3Endpoint') === 'true' ||
  app.node.tryGetContext('skipS3Endpoint') === true;

// Environment configuration
const mainEnv = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: config.region,
};

// us-east-1 environment for Lambda@Edge and CloudFront resources
const usEast1Env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: 'us-east-1',
};

// Create stacks in dependency order

// 0. Auth Stack (us-east-1) - Shared Cognito resources (reused across multiple Edge stacks)
const authStack = new AuthStack(app, `${prefix}-Auth`, {
  env: usEast1Env,
  config,
  callbackDomains: authCallbackDomains,
  domainPrefixSuffix: authDomainPrefixSuffix,
  description: 'OpenHands Auth Infrastructure - Cognito User Pool and managed login branding',
  crossRegionReferences: true,
});

// 1. Network Stack - Import VPC, create VPC Endpoints
const networkStack = new NetworkStack(app, `${prefix}-Network`, {
  env: mainEnv,
  config,
  skipS3Endpoint,  // Skip if VPC already has S3 endpoint
  description: 'OpenHands Network Infrastructure - VPC Endpoints',
  crossRegionReferences: true,
});

// 2. Monitoring Stack - CloudWatch Logs, Alarms, Backup, S3 Data Bucket
const monitoringStack = new MonitoringStack(app, `${prefix}-Monitoring`, {
  env: mainEnv,
  config,
  description: 'OpenHands Monitoring Infrastructure - CloudWatch, Backup, and S3 Data Store',
  crossRegionReferences: true,
});

// 3. Security Stack - IAM Roles, Security Groups (depends on MonitoringStack for S3 bucket)
const securityStack = new SecurityStack(app, `${prefix}-Security`, {
  env: mainEnv,
  config,
  networkOutput: networkStack.output,
  dataBucket: monitoringStack.output.dataBucket,
  description: 'OpenHands Security Infrastructure - IAM and Security Groups',
  crossRegionReferences: true,
});
securityStack.addDependency(networkStack);
securityStack.addDependency(monitoringStack);

// 4. Database Stack - Aurora Serverless v2 PostgreSQL with IAM Auth (REQUIRED)
//    Provides self-healing architecture - persists conversation history across EC2 replacements
//    CRITICAL: Database is mandatory for production ASG deployments to prevent data loss
const databaseStack = new DatabaseStack(app, `${prefix}-Database`, {
  env: mainEnv,
  networkOutput: networkStack.output,
  securityOutput: securityStack.output,
  ec2RoleArn: securityStack.output.ec2Role.roleArn,  // Pass ARN for IAM auth grant (avoids cyclic deps)
  description: 'OpenHands Database Infrastructure - Aurora Serverless v2 PostgreSQL',
  crossRegionReferences: true,
});
databaseStack.addDependency(networkStack);
databaseStack.addDependency(securityStack);

// 5. Compute Stack - ASG, Launch Template, ALB (Internal)
const computeStack = new ComputeStack(app, `${prefix}-Compute`, {
  env: mainEnv,
  config,
  networkOutput: networkStack.output,
  securityOutput: securityStack.output,
  monitoringOutput: monitoringStack.output,
  databaseOutput: databaseStack.output,
  description: 'OpenHands Compute Infrastructure - EC2 ASG and Internal ALB',
  crossRegionReferences: true,
});
computeStack.addDependency(networkStack);
computeStack.addDependency(securityStack);
computeStack.addDependency(monitoringStack);
computeStack.addDependency(databaseStack);

// 6. Edge Stack (us-east-1) - Cognito, Lambda@Edge, CloudFront, WAF, Route 53
//    This merged stack combines Auth and CDN to avoid cross-stack reference issues
//    ALB DNS name and origin secret are read from SSM parameters in us-east-1 (written by ComputeStack)
//    This enables multiple Edge stacks to share the same Compute stack without cross-region export conflicts.
const edgeStack = new EdgeStack(app, edgeStackId, {
  env: usEast1Env,
  config,
  alb: computeStack.alb,
  computeOutput: computeStack.output,
  authOutput: authStack.output,
  description: 'OpenHands Edge Infrastructure - Lambda@Edge, CloudFront, WAF, Route 53',
  crossRegionReferences: true,
});
edgeStack.addDependency(computeStack);
edgeStack.addDependency(authStack);

// Add tags to all stacks
cdk.Tags.of(app).add('Project', 'OpenHands');
cdk.Tags.of(app).add('Environment', 'Production');
cdk.Tags.of(app).add('ManagedBy', 'CDK');

app.synth();
