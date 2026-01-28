import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
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

    // Lambda code path - dependencies are bundled via requirements.txt
    // The Lambda layer approach avoids Docker bundling issues in CI
    const lambdaCodePath = path.join(__dirname, '..', 'lambda', 'user-config');

    // Create Lambda function with Python dependencies bundled
    // Uses Docker bundling to install requirements.txt dependencies
    this.userConfigFunction = new lambda.Function(this, 'UserConfigFunction', {
      functionName: 'openhands-user-config-api',
      description: 'Handles user configuration management for OpenHands (MCP, secrets, integrations)',
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,  // Cost-effective Graviton
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(lambdaCodePath, {
        // Exclude test files and dev artifacts from Lambda package
        exclude: ['.venv', '__pycache__', '*.pyc', 'test_*.py', '.pytest_cache', 'uv.lock'],
        // Bundle Python dependencies using Docker
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          platform: 'linux/arm64',
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -r . /asset-output/ && rm -rf /asset-output/__pycache__ /asset-output/test_*.py /asset-output/.pytest_cache',
          ],
        },
      }),
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      environment: {
        DATA_BUCKET: dataBucket.bucketName,
        KMS_KEY_ID: kmsKey.keyId,
        LOG_LEVEL: 'INFO',
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
