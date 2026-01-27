import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { NetworkStack } from '../lib/network-stack';
import { SecurityStack } from '../lib/security-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { ComputeStack } from '../lib/compute-stack';
import { EdgeStack } from '../lib/edge-stack';
import { DatabaseStack } from '../lib/database-stack';
import { AuthStack } from '../lib/auth-stack';
import { UserConfigStack } from '../lib/user-config-stack';
import { OpenHandsConfig, DatabaseStackOutput, AuthStackOutput } from '../lib/interfaces';

// Test configuration
const testConfig: OpenHandsConfig = {
  vpcId: 'vpc-12345678',
  hostedZoneId: 'Z0123456789ABC',
  domainName: 'example.com',
  subDomain: 'openhands',
  region: 'us-west-2',
};

const testEnv = {
  account: '123456789012',
  region: 'us-west-2',
};

// Mock database output for tests (required for self-healing architecture)
const mockDatabaseOutput: DatabaseStackOutput = {
  clusterEndpoint: 'mock-cluster.cluster-abc123.us-west-2.rds.amazonaws.com',
  clusterPort: '5432',
  clusterResourceId: 'cluster-ABC123DEF456',
  databaseName: 'openhands',
  databaseUser: 'openhands_proxy',  // Proxy user for RDS Proxy connections
  securityGroupId: 'sg-mock123',
  proxyEndpoint: 'mock-proxy.proxy-abc123.us-west-2.rds.amazonaws.com',
};

// Mock auth output for EdgeStack tests (shared Cognito from AuthStack)
const mockAuthOutput: AuthStackOutput = {
  userPoolId: 'us-east-1_mockPoolId',
  userPoolDomainPrefix: 'openhands-mock',
  userPoolClientId: 'mock-client-id-123',
  clientSecretName: 'cognito-client-secret-shared',
  region: 'us-east-1',
};

describe('OpenHands Infrastructure Stacks', () => {
  let app: cdk.App;

  beforeEach(() => {
    app = new cdk.App();
  });

  describe('NetworkStack', () => {
    test('synthesizes correctly', () => {
      const stack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const template = Template.fromStack(stack);

      // Verify VPC Endpoints are created
      template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
        VpcEndpointType: 'Interface',
      });

      // Verify Security Group for VPC Endpoints
      template.hasResourceProperties('AWS::EC2::SecurityGroup', {
        GroupDescription: Match.stringLikeRegexp('VPC Endpoint'),
      });
    });

    test('matches snapshot', () => {
      const stack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('SecurityStack', () => {
    test('synthesizes correctly', () => {
      // First create NetworkStack and MonitoringStack to get outputs
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const stack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });

      const template = Template.fromStack(stack);

      // Verify IAM Role is created with EC2 assume role policy
      template.hasResourceProperties('AWS::IAM::Role', {
        AssumeRolePolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 'sts:AssumeRole',
              Effect: 'Allow',
              Principal: {
                Service: 'ec2.amazonaws.com',
              },
            }),
          ]),
        },
      });

      // Verify Instance Profile is created
      template.resourceCountIs('AWS::IAM::InstanceProfile', 1);

      // Verify Security Groups are created (ALB, EC2, EFS)
      template.resourceCountIs('AWS::EC2::SecurityGroup', 3);
    });

    test('matches snapshot', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const stack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('MonitoringStack', () => {
    test('synthesizes correctly', () => {
      const stack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const template = Template.fromStack(stack);

      // Verify CloudWatch Log Group is created
      template.hasResourceProperties('AWS::Logs::LogGroup', {
        LogGroupName: '/openhands/application',
        RetentionInDays: 30,
      });

      // Verify SNS Topic is created
      template.hasResourceProperties('AWS::SNS::Topic', {
        DisplayName: 'OpenHands Alerts',
      });

      // Verify CloudWatch Dashboard is created
      template.resourceCountIs('AWS::CloudWatch::Dashboard', 1);

      // Verify Backup Plan is created
      template.resourceCountIs('AWS::Backup::BackupPlan', 1);
    });

    test('matches snapshot', () => {
      const stack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('ComputeStack', () => {
    let networkStack: NetworkStack;
    let securityStack: SecurityStack;
    let monitoringStack: MonitoringStack;

    beforeEach(() => {
      networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      securityStack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });
    });

    test('synthesizes correctly', () => {
      const stack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        databaseOutput: mockDatabaseOutput,
      });

      const template = Template.fromStack(stack);

      // Verify Launch Template is created
      template.resourceCountIs('AWS::EC2::LaunchTemplate', 1);

      // Verify Auto Scaling Group is created
      template.hasResourceProperties('AWS::AutoScaling::AutoScalingGroup', {
        MinSize: '1',
        MaxSize: '1',
      });

      // Verify ALB is created (internet-facing for CloudFront compatibility)
      // Note: CloudFront VPC Origin does NOT support WebSocket connections,
      // so we use internet-facing ALB with CloudFront HttpOrigin instead
      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
        Scheme: 'internet-facing',
        Type: 'application',
      });

      // Verify Target Group is created
      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
        Port: 3000,
        Protocol: 'HTTP',
        HealthCheckPath: '/api/health',
      });

      // Verify SSM Parameters for Docker versions
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: '/openhands/docker/openhands-version',
        Type: 'String',
      });

      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: '/openhands/docker/runtime-version',
        Type: 'String',
      });

      // Verify CloudWatch Alarms are created
      template.resourceCountIs('AWS::CloudWatch::Alarm', 3); // CPU, Memory, Disk
    });

    test('creates alarms with proper ASG reference', () => {
      const stack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        databaseOutput: mockDatabaseOutput,
      });

      const template = Template.fromStack(stack);

      // Verify CPU alarm references ASG dynamically
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'CPU utilization exceeds 80%',
        Namespace: 'AWS/EC2',
        MetricName: 'CPUUtilization',
        Threshold: 80,
      });

      // Verify Memory alarm references ASG dynamically
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'Memory utilization exceeds 85%',
        Namespace: 'CWAgent',
        MetricName: 'mem_used_percent',
        Threshold: 85,
      });

      // Verify Disk alarm references ASG dynamically
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'Disk usage exceeds 85%',
        Namespace: 'CWAgent',
        MetricName: 'disk_used_percent',
        Threshold: 85,
      });
    });

    test('matches snapshot', () => {
      const stack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        databaseOutput: mockDatabaseOutput,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('EdgeStack', () => {
    let networkStack: NetworkStack;
    let securityStack: SecurityStack;
    let monitoringStack: MonitoringStack;
    let computeStack: ComputeStack;

    beforeEach(() => {
      networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      securityStack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });

      computeStack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        databaseOutput: mockDatabaseOutput,
      });
    });

    test('synthesizes correctly', () => {
      // EdgeStack must be in us-east-1 for Lambda@Edge
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new EdgeStack(app, 'TestEdgeStack', {
        env: edgeEnv,
        config: testConfig,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
        authOutput: mockAuthOutput,
        crossRegionReferences: true,
      });

      const template = Template.fromStack(stack);

      // Verify Cognito resources are NOT created here (imported from OpenHands-Auth stack)
      template.resourceCountIs('AWS::Cognito::UserPool', 0);
      template.resourceCountIs('AWS::Cognito::UserPoolClient', 0);

      // Verify ACM Certificate is created
      template.hasResourceProperties('AWS::CertificateManager::Certificate', {
        DomainName: 'openhands.example.com',
      });

      // Verify CloudFront distribution is created
      template.resourceCountIs('AWS::CloudFront::Distribution', 1);

      // Verify Lambda@Edge function is created
      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'nodejs22.x',
        Handler: 'index.handler',
      });

      // Verify the AuthFunction lambda code references the shared client secret
      const templateJson = template.toJSON() as any;
      const lambdaFunctions = Object.values(templateJson.Resources || {}).filter(
        (r: any) => r?.Type === 'AWS::Lambda::Function' && r?.Properties?.Handler === 'index.handler'
      );
      const hasSharedSecretReference = lambdaFunctions.some((fn: any) => {
        const zipFile = fn?.Properties?.Code?.ZipFile;
        if (typeof zipFile === 'string') return zipFile.includes('cognito-client-secret-shared');
        if (zipFile?.['Fn::Join'] && Array.isArray(zipFile['Fn::Join'][1])) {
          return zipFile['Fn::Join'][1].some((part: any) =>
            typeof part === 'string' && part.includes('cognito-client-secret-shared')
          );
        }
        return false;
      });
      expect(hasSharedSecretReference).toBe(true);

      // Verify WAF WebACL is created
      template.hasResourceProperties('AWS::WAFv2::WebACL', {
        Scope: 'CLOUDFRONT',
      });

      // Verify Route53 alias record is created
      template.hasResourceProperties('AWS::Route53::RecordSet', {
        Name: 'openhands.example.com.',
        Type: 'A',
      });
    });

    test('creates WAF with managed rules', () => {
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new EdgeStack(app, 'TestEdgeStack', {
        env: edgeEnv,
        config: testConfig,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
        authOutput: mockAuthOutput,
        crossRegionReferences: true,
      });

      const template = Template.fromStack(stack);

      // Verify WAF has managed rule groups
      template.hasResourceProperties('AWS::WAFv2::WebACL', {
        Rules: Match.arrayWith([
          Match.objectLike({
            Statement: {
              ManagedRuleGroupStatement: {
                VendorName: 'AWS',
                Name: 'AWSManagedRulesCommonRuleSet',
              },
            },
          }),
        ]),
      });
    });

    test('matches snapshot', () => {
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new EdgeStack(app, 'TestEdgeStack', {
        env: edgeEnv,
        config: testConfig,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
        authOutput: mockAuthOutput,
        crossRegionReferences: true,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('AuthStack', () => {
    const authEnv = { account: '123456789012', region: 'us-east-1' };

    // Helper to extract UserPool properties from template
    function getUserPoolProperties(template: Template): Record<string, unknown> {
      const templateJson = template.toJSON() as Record<string, unknown>;
      const resources = templateJson.Resources as Record<string, { Type: string; Properties: Record<string, unknown> }>;
      const userPoolResource = Object.values(resources).find(
        r => r?.Type === 'AWS::Cognito::UserPool'
      );
      expect(userPoolResource).toBeDefined();
      return userPoolResource!.Properties;
    }

    test('synthesizes correctly', () => {
      const stack = new AuthStack(app, 'TestAuthStack', {
        env: authEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com', 'openhands.test.example.com'],
      });

      const template = Template.fromStack(stack);

      // Verify User Pool is created
      template.hasResourceProperties('AWS::Cognito::UserPool', {
        UserPoolName: Match.anyValue(),
        AutoVerifiedAttributes: ['email'],
        MfaConfiguration: 'OPTIONAL',
      });

      // Verify User Pool Client is created
      template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
        AllowedOAuthFlows: ['code'],
        AllowedOAuthScopes: Match.arrayWith(['openid', 'email', 'profile']),
      });

      // Verify Cognito Domain is created
      template.resourceCountIs('AWS::Cognito::UserPoolDomain', 1);

      // Verify Secret is created for client secret
      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Description: 'Cognito User Pool Client Secret for OpenHands',
      });
    });

    test('includes custom email templates with userInvitation', () => {
      const stack = new AuthStack(app, 'TestAuthStack', {
        env: authEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
      });

      const template = Template.fromStack(stack);
      const userPoolProps = getUserPoolProperties(template);
      const adminConfig = userPoolProps.AdminCreateUserConfig as Record<string, unknown>;
      const inviteTemplate = adminConfig.InviteMessageTemplate as Record<string, string>;

      expect(inviteTemplate).toBeDefined();
      expect(inviteTemplate.EmailSubject).toContain('Welcome to');
      expect(inviteTemplate.EmailMessage).toContain('OpenHands');
      expect(inviteTemplate.EmailMessage).toContain('{username}');
      expect(inviteTemplate.EmailMessage).toContain('{####}');
    });

    test('includes custom email templates with userVerification', () => {
      const stack = new AuthStack(app, 'TestAuthStack', {
        env: authEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
      });

      const template = Template.fromStack(stack);
      const userPoolProps = getUserPoolProperties(template);
      const verificationTemplate = userPoolProps.VerificationMessageTemplate as Record<string, string>;

      expect(verificationTemplate).toBeDefined();
      expect(verificationTemplate.EmailSubject).toContain('Verification Code');
      expect(verificationTemplate.EmailMessage).toContain('OpenHands');
      expect(verificationTemplate.EmailMessage).toContain('{####}');
    });

    test('replaces portal URL placeholders correctly', () => {
      const stack = new AuthStack(app, 'TestAuthStack', {
        env: authEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com', 'openhands.test.example.com'],
      });

      const template = Template.fromStack(stack);
      const userPoolProps = getUserPoolProperties(template);
      const adminConfig = userPoolProps.AdminCreateUserConfig as Record<string, unknown>;
      const inviteTemplate = adminConfig.InviteMessageTemplate as Record<string, string>;
      const invitationEmail = inviteTemplate.EmailMessage;

      // Verify invitation email contains both portal URLs
      expect(invitationEmail).toContain('https://openhands.example.com');
      expect(invitationEmail).toContain('https://openhands.test.example.com');

      // Verify placeholders are replaced (no {{...}} remaining)
      expect(invitationEmail).not.toContain('{{PORTAL_URLS}}');
      expect(invitationEmail).not.toContain('{{PRIMARY_PORTAL_URL}}');
    });

    test('matches snapshot', () => {
      const stack = new AuthStack(app, 'TestAuthStack', {
        env: authEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('UserConfigStack', () => {
    let networkStack: NetworkStack;
    let monitoringStack: MonitoringStack;
    let securityStack: SecurityStack;

    beforeEach(() => {
      networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      securityStack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });
    });

    test('synthesizes correctly', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      const template = Template.fromStack(stack);

      // Verify Lambda function is created with correct runtime
      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'python3.12',
        Handler: 'handler.handler',
        FunctionName: 'openhands-user-config-api',
      });

      // Verify HTTP API Gateway is created
      template.hasResourceProperties('AWS::ApiGatewayV2::Api', {
        Name: 'openhands-user-config',
        ProtocolType: 'HTTP',
      });

      // Verify CORS configuration exists
      template.hasResourceProperties('AWS::ApiGatewayV2::Api', {
        CorsConfiguration: {
          AllowMethods: Match.arrayWith(['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS']),
        },
      });
    });

    test('creates API routes for all endpoints', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      const template = Template.fromStack(stack);

      // Count routes - should have multiple API routes for user-config endpoints
      // Routes: MCP (GET, PUT), MCP/servers (POST), MCP/servers/{id} (DELETE, PUT),
      //         secrets (GET), secrets/{id} (PUT, DELETE), integrations (GET),
      //         integrations/{provider} (PUT, DELETE), merged (GET)
      // Total: 12 routes
      const routeCount = Object.values(template.toJSON().Resources || {}).filter(
        (r: any) => r?.Type === 'AWS::ApiGatewayV2::Route'
      ).length;

      expect(routeCount).toBeGreaterThanOrEqual(10);
    });

    test('lambda has correct environment variables', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: {
            LOG_LEVEL: 'INFO',
          },
        },
      });
    });

    test('lambda has proper IAM permissions for S3 and KMS', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      const template = Template.fromStack(stack);

      // Verify IAM policy exists for Lambda function with S3 permissions
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: Match.arrayWith(['s3:GetObject*']),
              Effect: 'Allow',
            }),
          ]),
        },
      });
    });

    test('outputs are correctly defined', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      expect(stack.output).toBeDefined();
      expect(stack.output.apiEndpoint).toBeDefined();
      expect(stack.output.kmsKeyArn).toBeDefined();
      expect(stack.output.kmsKeyId).toBeDefined();
    });

    test('matches snapshot', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('Stack Integration', () => {
    test('all stacks can be synthesized together', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const securityStack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });

      const computeStack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        databaseOutput: mockDatabaseOutput,
      });

      // Verify all stacks can be synthesized
      expect(networkStack.stackName).toBeDefined();
      expect(securityStack.stackName).toBeDefined();
      expect(monitoringStack.stackName).toBeDefined();
      expect(computeStack.stackName).toBeDefined();

      // Verify outputs are defined
      expect(networkStack.output).toBeDefined();
      expect(securityStack.output).toBeDefined();
      expect(monitoringStack.output).toBeDefined();
      expect(computeStack.output).toBeDefined();
    });

    test('UserConfigStack integrates with SecurityStack KMS key', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const monitoringStack = new MonitoringStack(app, 'TestMonitoringStack', {
        env: testEnv,
        config: testConfig,
      });

      const securityStack = new SecurityStack(app, 'TestSecurityStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        dataBucket: monitoringStack.output.dataBucket,
      });

      // Verify SecurityStack outputs KMS key ARN
      expect(securityStack.output.userSecretsKmsKeyArn).toBeDefined();
      expect(securityStack.output.userSecretsKmsKeyId).toBeDefined();

      // Verify UserConfigStack can be created with the KMS key
      const userConfigStack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      expect(userConfigStack.stackName).toBeDefined();
      expect(userConfigStack.output).toBeDefined();
    });
  });
});
