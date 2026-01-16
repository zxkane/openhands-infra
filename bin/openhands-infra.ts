#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkStack } from '../lib/network-stack.js';
import { SecurityStack } from '../lib/security-stack.js';
import { MonitoringStack } from '../lib/monitoring-stack.js';
import { DatabaseStack } from '../lib/database-stack.js';
import { ComputeStack } from '../lib/compute-stack.js';
import { EdgeStack } from '../lib/edge-stack.js';
import { OpenHandsConfig } from '../lib/interfaces.js';

const app = new cdk.App();

// Get configuration from context
const vpcId = app.node.tryGetContext('vpcId');
const hostedZoneId = app.node.tryGetContext('hostedZoneId');
const domainName = app.node.tryGetContext('domainName');
const subDomain = app.node.tryGetContext('subDomain') || 'openhands';
const region = app.node.tryGetContext('region') || process.env.CDK_DEFAULT_REGION || 'us-east-1';

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
};

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

// Stack naming prefix
const prefix = 'OpenHands';

// Create stacks in dependency order

// 1. Network Stack - Import VPC, create VPC Endpoints
const networkStack = new NetworkStack(app, `${prefix}-Network`, {
  env: mainEnv,
  config,
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
const edgeStack = new EdgeStack(app, `${prefix}-Edge`, {
  env: usEast1Env,
  config,
  computeOutput: computeStack.output,
  alb: computeStack.alb,
  description: 'OpenHands Edge Infrastructure - Cognito, Lambda@Edge, CloudFront, WAF, Route 53',
  crossRegionReferences: true,
});
edgeStack.addDependency(computeStack);

// Add tags to all stacks
cdk.Tags.of(app).add('Project', 'OpenHands');
cdk.Tags.of(app).add('Environment', 'Production');
cdk.Tags.of(app).add('ManagedBy', 'CDK');

app.synth();
