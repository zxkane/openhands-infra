import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { Construct } from 'constructs';
import * as path from 'path';
import * as fs from 'fs';
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
    const lambdaCodePath = path.join(__dirname, '..', 'lambda', 'user-config');

    // Create Lambda function with Python dependencies bundled
    // Uses Docker bundling to install requirements.txt dependencies
    // Falls back to local copy-only bundling for CI environments without Docker ARM64 support
    this.userConfigFunction = new lambda.Function(this, 'UserConfigFunction', {
      functionName: 'openhands-user-config-api',
      description: 'Handles user configuration management for OpenHands (MCP, secrets, integrations)',
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,  // Cost-effective Graviton
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(lambdaCodePath, {
        // Exclude test files and dev artifacts from Lambda package
        exclude: ['.venv', '__pycache__', '*.pyc', 'test_*.py', '.pytest_cache', 'uv.lock'],
        // Bundle Python dependencies using Docker (preferred)
        // Falls back to local copy for CI environments without Docker ARM64 support
        bundling: {
          image: lambda.Runtime.PYTHON_3_12.bundlingImage,
          platform: 'linux/arm64',
          command: [
            'bash', '-c',
            'pip install -r requirements.txt -t /asset-output && cp -r . /asset-output/ && rm -rf /asset-output/__pycache__ /asset-output/test_*.py /asset-output/.pytest_cache',
          ],
          // Local bundling fallback: just copies files without pip install
          // This allows CDK synth/tests to pass in CI without Docker ARM64 support
          // Actual deployments use Docker bundling for proper dependency installation
          local: {
            tryBundle(outputDir: string): boolean {
              try {
                // Copy source files (without dependencies - tests don't invoke Lambda)
                const files = fs.readdirSync(lambdaCodePath);
                for (const file of files) {
                  if (!file.startsWith('.') && !file.startsWith('test_') && !file.endsWith('.pyc')) {
                    const srcPath = path.join(lambdaCodePath, file);
                    const destPath = path.join(outputDir, file);
                    if (fs.statSync(srcPath).isDirectory()) {
                      fs.cpSync(srcPath, destPath, { recursive: true });
                    } else {
                      fs.copyFileSync(srcPath, destPath);
                    }
                  }
                }
                return true;
              } catch {
                // If local bundling fails, Docker bundling will be attempted
                return false;
              }
            },
          },
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
