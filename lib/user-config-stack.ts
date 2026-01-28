import * as cdk from 'aws-cdk-lib';
import * as apigateway from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigatewayIntegrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
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
 * - HTTP API Gateway for the /api/v1/user-config/* endpoints
 *
 * The API endpoints handle:
 * - MCP server configuration (add/remove/enable/disable)
 * - Encrypted secrets storage (API keys, tokens)
 * - Third-party integrations (GitHub, Slack)
 * - Configuration merging (user + global config)
 */
export class UserConfigStack extends cdk.Stack {
  public readonly output: UserConfigStackOutput;
  public readonly httpApi: apigateway.HttpApi;

  constructor(scope: Construct, id: string, props: UserConfigStackProps) {
    super(scope, id, props);

    const { config, dataBucket, kmsKeyArn } = props;

    // Import the KMS key
    const kmsKey = kms.Key.fromKeyArn(this, 'UserSecretsKmsKey', kmsKeyArn);

    // ========================================
    // Lambda Function for User Config API
    // ========================================

    // Lambda code path - dependencies are bundled via requirements.txt
    // The Lambda layer approach avoids Docker bundling issues in CI
    const lambdaCodePath = path.join(__dirname, '..', 'lambda', 'user-config');

    // Create Lambda function with standard Python runtime
    // Note: Dependencies (boto3, pydantic, cryptography) are bundled via Lambda layer
    // or pre-installed in the Lambda runtime
    const userConfigFunction = new lambda.Function(this, 'UserConfigFunction', {
      functionName: 'openhands-user-config-api',
      description: 'Handles user configuration management for OpenHands (MCP, secrets, integrations)',
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.ARM_64,  // Cost-effective Graviton
      handler: 'handler.handler',
      code: lambda.Code.fromAsset(lambdaCodePath, {
        // Exclude test files and dev artifacts from Lambda package
        exclude: ['.venv', '__pycache__', '*.pyc', 'test_*.py', '.pytest_cache', 'uv.lock', 'pyproject.toml'],
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
    dataBucket.grantReadWrite(userConfigFunction, 'users/*');

    // Grant KMS encrypt/decrypt for secrets
    kmsKey.grantEncryptDecrypt(userConfigFunction);
    kmsKey.grant(userConfigFunction, 'kms:GenerateDataKey', 'kms:GenerateDataKeyWithoutPlaintext');

    // ========================================
    // HTTP API Gateway
    // ========================================

    // Create HTTP API (v2) - faster and cheaper than REST API
    this.httpApi = new apigateway.HttpApi(this, 'UserConfigApi', {
      apiName: 'openhands-user-config',
      description: 'OpenHands User Configuration API',
      corsPreflight: {
        allowOrigins: ['*'],  // Will be restricted by CloudFront
        allowMethods: [
          apigateway.CorsHttpMethod.GET,
          apigateway.CorsHttpMethod.PUT,
          apigateway.CorsHttpMethod.POST,
          apigateway.CorsHttpMethod.DELETE,
          apigateway.CorsHttpMethod.OPTIONS,
        ],
        allowHeaders: [
          'Content-Type',
          'Authorization',
          'X-Cognito-User-Id',
          'X-Cognito-Email',
        ],
        maxAge: cdk.Duration.hours(24),
      },
    });

    // Lambda integration
    const lambdaIntegration = new apigatewayIntegrations.HttpLambdaIntegration(
      'UserConfigIntegration',
      userConfigFunction
    );

    // Add routes for user config API
    // All routes use the same Lambda, which routes internally based on path and method
    const routes = [
      { path: '/api/v1/user-config/mcp', methods: ['GET', 'PUT'] },
      { path: '/api/v1/user-config/mcp/servers', methods: ['POST'] },
      { path: '/api/v1/user-config/mcp/servers/{serverId}', methods: ['DELETE', 'PUT'] },
      { path: '/api/v1/user-config/secrets', methods: ['GET'] },
      { path: '/api/v1/user-config/secrets/{secretId}', methods: ['PUT', 'DELETE'] },
      { path: '/api/v1/user-config/integrations', methods: ['GET'] },
      { path: '/api/v1/user-config/integrations/{provider}', methods: ['PUT', 'DELETE'] },
      { path: '/api/v1/user-config/merged', methods: ['GET'] },
    ];

    for (const { path, methods } of routes) {
      for (const method of methods) {
        this.httpApi.addRoutes({
          path,
          methods: [method as apigateway.HttpMethod],
          integration: lambdaIntegration,
        });
      }
    }

    // Store outputs
    this.output = {
      apiEndpoint: this.httpApi.apiEndpoint,
      kmsKeyArn: kmsKey.keyArn,
      kmsKeyId: kmsKey.keyId,
    };

    // ========================================
    // CloudFormation Outputs
    // ========================================

    new cdk.CfnOutput(this, 'ApiEndpoint', {
      value: this.httpApi.apiEndpoint,
      description: 'User Config API Endpoint',
    });

    new cdk.CfnOutput(this, 'ApiId', {
      value: this.httpApi.httpApiId,
      description: 'User Config API ID',
    });
  }
}
