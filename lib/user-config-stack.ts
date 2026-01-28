import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as pythonLambda from '@aws-cdk/aws-lambda-python-alpha';
import { Construct } from 'constructs';
import * as path from 'path';
import { OpenHandsConfig, UserConfigStackOutput } from './interfaces.js';

export interface UserConfigStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  /** S3 bucket for user data storage (from MonitoringStack) */
  dataBucket: s3.IBucket;
  /** KMS key ARN for user secrets encryption */
  kmsKeyArn: string;
}

/**
 * UserConfigStack - User Configuration API Infrastructure
 *
 * This stack creates:
 * - Lambda function for user configuration management (MCP, secrets, integrations)
 *
 * The Lambda is integrated with ALB in ComputeStack for routing.
 * API endpoints handled:
 * - MCP server configuration (add/remove/enable/disable)
 * - Encrypted secrets storage (API keys, tokens)
 * - Third-party integrations (GitHub, Slack)
 * - Configuration merging (user + global config)
 *
 * Architecture:
 * CloudFront → Lambda@Edge (JWT) → ALB → Lambda Target Group → This Lambda
 */
export class UserConfigStack extends cdk.Stack {
  public readonly output: UserConfigStackOutput;
  public readonly userConfigFunction: lambda.Function;

  constructor(scope: Construct, id: string, props: UserConfigStackProps) {
    super(scope, id, props);

    const { dataBucket, kmsKeyArn } = props;

    // Import the KMS key
    const kmsKey = kms.Key.fromKeyArn(this, 'UserSecretsKmsKey', kmsKeyArn);

    // ========================================
    // Lambda Function for User Config API
    // ========================================

    // Lambda code path - dependencies managed by uv (pyproject.toml + uv.lock)
    const lambdaCodePath = path.join(__dirname, '..', 'lambda', 'user-config');

    // Create Lambda function with Python dependencies bundled via uv
    // PythonFunction automatically handles pyproject.toml and uv.lock
    // CI uses QEMU for ARM64 Docker builds (see .github/workflows/ci.yml)
    this.userConfigFunction = new pythonLambda.PythonFunction(this, 'UserConfigFunction', {
      functionName: 'openhands-user-config-api',
      description: 'Handles user configuration management for OpenHands (MCP, secrets, integrations)',
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,  // Cost-effective Graviton
      entry: lambdaCodePath,
      index: 'handler.py',
      handler: 'handler',
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      environment: {
        DATA_BUCKET: dataBucket.bucketName,
        KMS_KEY_ID: kmsKey.keyId,
        LOG_LEVEL: 'INFO',
      },
      bundling: {
        // Use uv for dependency management (reads pyproject.toml + uv.lock)
        assetExcludes: ['.venv', '__pycache__', '*.pyc', 'test_*.py', '.pytest_cache'],
        // Use SOURCE hash to ensure consistent asset hash across environments
        assetHashType: cdk.AssetHashType.SOURCE,
      },
    });

    // Grant S3 read/write access for user config storage
    dataBucket.grantReadWrite(this.userConfigFunction, 'users/*');

    // Grant KMS encrypt/decrypt for secrets
    kmsKey.grantEncryptDecrypt(this.userConfigFunction);
    kmsKey.grant(this.userConfigFunction, 'kms:GenerateDataKey', 'kms:GenerateDataKeyWithoutPlaintext');

    // Store outputs
    this.output = {
      lambdaFunctionArn: this.userConfigFunction.functionArn,
      lambdaFunctionName: this.userConfigFunction.functionName,
      kmsKeyArn: kmsKey.keyArn,
      kmsKeyId: kmsKey.keyId,
    };

    // ========================================
    // CloudFormation Outputs
    // ========================================

    new cdk.CfnOutput(this, 'LambdaFunctionArn', {
      value: this.userConfigFunction.functionArn,
      description: 'User Config Lambda Function ARN',
    });

    new cdk.CfnOutput(this, 'LambdaFunctionName', {
      value: this.userConfigFunction.functionName,
      description: 'User Config Lambda Function Name',
    });
  }
}
