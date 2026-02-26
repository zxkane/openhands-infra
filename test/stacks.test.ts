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
import { ClusterStack } from '../lib/cluster-stack';
import { SandboxStack } from '../lib/sandbox-stack';
import { OpenHandsConfig, DatabaseStackOutput, AuthStackOutput, SandboxStackOutput, ClusterStackOutput } from '../lib/interfaces';

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
  databaseUser: 'openhands_proxy',
  securityGroupId: 'sg-mock123',
  proxyEndpoint: 'mock-proxy.proxy-abc123.us-west-2.rds.amazonaws.com',
};

// Mock sandbox output for ComputeStack tests (ECS Fargate sandbox)
const mockSandboxOutput: SandboxStackOutput = {
  clusterArn: 'arn:aws:ecs:us-west-2:123456789012:cluster/openhands-sandbox',
  clusterName: 'openhands-sandbox',
  registryTableName: 'openhands-sandbox-registry',
  registryTableArn: 'arn:aws:dynamodb:us-west-2:123456789012:table/openhands-sandbox-registry',
  taskDefinitionFamily: 'openhands-sandbox',
  sandboxTaskSecurityGroupId: 'sg-sandbox123',
  orchestratorApiUrl: 'http://orchestrator.openhands.local:8081',
  orchestratorDnsName: 'orchestrator.openhands.local',
  orchestratorSecurityGroupId: 'sg-orchestrator123',
  sandboxLogGroupName: '/openhands/sandbox',
  warmPoolSize: 2,
  warmPoolServiceName: 'openhands-example-com-sandbox-warm-pool',
  orchestratorImageUri: '123456789012.dkr.ecr.us-west-2.amazonaws.com/mock-orchestrator:latest',
  sandboxExecutionRoleArn: 'arn:aws:iam::123456789012:role/mock-execution-role',
  sandboxTaskRoleArn: 'arn:aws:iam::123456789012:role/mock-task-role',
  efsFileSystemId: 'fs-mock12345',
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

      // Verify IAM Role is created with ECS tasks assume role policy
      template.hasResourceProperties('AWS::IAM::Role', {
        AssumeRolePolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Action: 'sts:AssumeRole',
              Effect: 'Allow',
              Principal: {
                Service: 'ecs-tasks.amazonaws.com',
              },
            }),
          ]),
        },
      });

      // Verify no Instance Profile (Fargate doesn't use instance profiles)
      template.resourceCountIs('AWS::IAM::InstanceProfile', 0);

      // Verify Security Groups are created (ALB, App Service, EFS)
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

  describe('ClusterStack', () => {
    test('synthesizes correctly', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const stack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });

      const template = Template.fromStack(stack);

      // Verify ECS Cluster is created
      template.hasResourceProperties('AWS::ECS::Cluster', {
        ClusterName: 'openhands-example-com',
      });

      // Verify Cloud Map namespace is created
      template.hasResourceProperties('AWS::ServiceDiscovery::PrivateDnsNamespace', {
        Name: 'openhands.local',
      });
    });

    test('outputs are correctly defined', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const stack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });

      expect(stack.output).toBeDefined();
      expect(stack.output.cluster).toBeDefined();
      expect(stack.output.clusterArn).toBeDefined();
      expect(stack.output.namespace).toBeDefined();
      expect(stack.output.namespaceName).toBe('openhands.local');
    });

    test('matches snapshot', () => {
      const networkStack = new NetworkStack(app, 'TestNetworkStack', {
        env: testEnv,
        config: testConfig,
      });

      const stack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('ComputeStack', () => {
    let networkStack: NetworkStack;
    let securityStack: SecurityStack;
    let monitoringStack: MonitoringStack;
    let clusterStack: ClusterStack;

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

      clusterStack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });
    });

    test('synthesizes correctly', () => {
      const stack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
        databaseOutput: mockDatabaseOutput,
        sandboxOutput: mockSandboxOutput,
      });

      const template = Template.fromStack(stack);

      // Verify NO EC2 resources (Launch Template, ASG)
      template.resourceCountIs('AWS::EC2::LaunchTemplate', 0);
      template.resourceCountIs('AWS::AutoScaling::AutoScalingGroup', 0);

      // Verify Fargate task definitions are created
      template.hasResourceProperties('AWS::ECS::TaskDefinition', {
        Family: 'openhands-app',
        Cpu: '4096',
        Memory: '8192',
        RequiresCompatibilities: ['FARGATE'],
        NetworkMode: 'awsvpc',
      });

      template.hasResourceProperties('AWS::ECS::TaskDefinition', {
        Family: 'openhands-openresty',
        Cpu: '256',
        Memory: '512',
        RequiresCompatibilities: ['FARGATE'],
        NetworkMode: 'awsvpc',
      });

      // Verify ALB is created (internet-facing for CloudFront compatibility)
      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
        Scheme: 'internet-facing',
        Type: 'application',
      });

      // Verify IP-type Target Groups are created
      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
        Port: 3000,
        Protocol: 'HTTP',
        TargetType: 'ip',
        HealthCheckPath: '/api/health',
      });

      template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
        Port: 8080,
        Protocol: 'HTTP',
        TargetType: 'ip',
        HealthCheckPath: '/health',
      });

      // Verify SSM Parameters for Docker versions
      template.hasResourceProperties('AWS::SSM::Parameter', {
        Name: '/openhands/docker/openhands-version',
        Type: 'String',
      });

      // Verify CloudWatch Alarms are created (CPU + Memory for ECS)
      template.resourceCountIs('AWS::CloudWatch::Alarm', 2);
    });

    test('creates ECS service alarms', () => {
      const stack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
        databaseOutput: mockDatabaseOutput,
        sandboxOutput: mockSandboxOutput,
      });

      const template = Template.fromStack(stack);

      // Verify CPU alarm for ECS service
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'App service CPU utilization exceeds 80%',
        Namespace: 'AWS/ECS',
        MetricName: 'CPUUtilization',
        Threshold: 80,
      });

      // Verify Memory alarm for ECS service
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'App service memory utilization exceeds 85%',
        Namespace: 'AWS/ECS',
        MetricName: 'MemoryUtilization',
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
        clusterOutput: clusterStack.output,
        databaseOutput: mockDatabaseOutput,
        sandboxOutput: mockSandboxOutput,
      });

      const template = Template.fromStack(stack);
      expect(template.toJSON()).toMatchSnapshot();
    });
  });

  describe('EdgeStack', () => {
    let networkStack: NetworkStack;
    let securityStack: SecurityStack;
    let monitoringStack: MonitoringStack;
    let clusterStack: ClusterStack;
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

      clusterStack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });

      computeStack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
        databaseOutput: mockDatabaseOutput,
        sandboxOutput: mockSandboxOutput,
      });
    });

    test('synthesizes correctly', () => {
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

      template.hasResourceProperties('AWS::Cognito::UserPool', {
        UserPoolName: Match.anyValue(),
        AutoVerifiedAttributes: ['email'],
        MfaConfiguration: 'OPTIONAL',
      });

      template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
        AllowedOAuthFlows: ['code'],
        AllowedOAuthScopes: Match.arrayWith(['openid', 'email', 'profile']),
      });

      template.resourceCountIs('AWS::Cognito::UserPoolDomain', 1);

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

      expect(invitationEmail).toContain('https://openhands.example.com');
      expect(invitationEmail).toContain('https://openhands.test.example.com');

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

      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'python3.12',
        Handler: 'handler.handler',
        FunctionName: 'openhands-user-config-api',
      });
    });

    test('lambda function is exported for ALB integration', () => {
      const stack = new UserConfigStack(app, 'TestUserConfigStack', {
        env: testEnv,
        config: testConfig,
        dataBucket: monitoringStack.output.dataBucket,
        kmsKeyArn: securityStack.output.userSecretsKmsKeyArn!,
      });

      expect(stack.userConfigFunction).toBeDefined();
      expect(stack.userConfigFunction.functionArn).toBeDefined();
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
      expect(stack.output.lambdaFunctionArn).toBeDefined();
      expect(stack.output.lambdaFunctionName).toBeDefined();
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
      const templateJson = template.toJSON();

      const resources = templateJson.Resources || {};
      for (const [, resource] of Object.entries(resources)) {
        const res = resource as { Type?: string; Properties?: { Code?: { S3Key?: string } } };
        if (res.Type === 'AWS::Lambda::Function' && res.Properties?.Code?.S3Key) {
          res.Properties.Code.S3Key = '<ASSET_HASH>.zip';
        }
      }

      expect(templateJson).toMatchSnapshot();
    });
  });

  describe('SandboxStack', () => {
    let networkStack: NetworkStack;
    let securityStack: SecurityStack;
    let monitoringStack: MonitoringStack;
    let clusterStack: ClusterStack;

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

      clusterStack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });
    });

    test('synthesizes correctly', () => {
      const stack = new SandboxStack(app, 'TestSandboxStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      // Verify no ECS Cluster is created in SandboxStack (it comes from ClusterStack)
      template.resourceCountIs('AWS::ECS::Cluster', 0);

      // Verify DynamoDB table is created
      template.hasResourceProperties('AWS::DynamoDB::Table', {
        TableName: 'openhands-example-com-sandbox-registry',
        KeySchema: Match.arrayWith([
          Match.objectLike({
            AttributeName: 'conversation_id',
            KeyType: 'HASH',
          }),
        ]),
      });

      // Verify Fargate task definition is created
      template.hasResourceProperties('AWS::ECS::TaskDefinition', {
        Family: 'openhands-sandbox',
        Cpu: '2048',
        Memory: '4096',
        RequiresCompatibilities: ['FARGATE'],
        NetworkMode: 'awsvpc',
      });

      // Verify security group for sandbox tasks
      template.hasResourceProperties('AWS::EC2::SecurityGroup', {
        GroupDescription: Match.stringLikeRegexp('sandbox Fargate'),
      });

      // Verify Idle Monitor Lambda
      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'openhands-sandbox-idle-monitor',
        Runtime: 'nodejs22.x',
      });

      // Verify EventBridge rule for idle monitor
      template.hasResourceProperties('AWS::Events::Rule', {
        ScheduleExpression: 'rate(5 minutes)',
      });

      // Verify CloudWatch alarm for sandbox creation failures
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        AlarmDescription: 'Sandbox creation failures detected',
        Namespace: 'OpenHands/Sandbox',
        MetricName: 'SandboxCreationFailures',
      });
    });

    test('sandbox task SG has no self-referencing ingress rule', () => {
      const stack = new SandboxStack(app, 'TestSandboxSgIsolation', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);
      const templateJson = template.toJSON() as Record<string, unknown>;
      const resources = templateJson.Resources as Record<string, { Type: string; Properties: Record<string, unknown> }>;

      // Find the sandbox task security group
      const sgEntries = Object.entries(resources).filter(
        ([, r]) => r.Type === 'AWS::EC2::SecurityGroup' &&
          (r.Properties?.GroupDescription as string)?.includes('sandbox Fargate')
      );
      expect(sgEntries.length).toBe(1);
      const [sandboxSgLogicalId] = sgEntries[0];

      // Check for SecurityGroupIngress resources that reference the sandbox SG as both source and target
      const selfRefIngress = Object.entries(resources).filter(([, r]) => {
        if (r.Type !== 'AWS::EC2::SecurityGroupIngress') return false;
        const props = r.Properties;
        // Both GroupId and SourceSecurityGroupId reference the same SG
        const groupId = JSON.stringify(props?.GroupId ?? '');
        const sourceGroupId = JSON.stringify(props?.SourceSecurityGroupId ?? '');
        return groupId.includes(sandboxSgLogicalId) && sourceGroupId.includes(sandboxSgLogicalId);
      });
      expect(selfRefIngress.length).toBe(0);

      // Also check inline SecurityGroupIngress in the SG resource itself
      const sgResource = resources[sandboxSgLogicalId];
      const inlineIngress = (sgResource.Properties?.SecurityGroupIngress ?? []) as Array<Record<string, unknown>>;
      const selfRefInline = inlineIngress.filter((rule) => {
        const sourceGroupId = JSON.stringify(rule.SourceSecurityGroupId ?? '');
        return sourceGroupId.includes(sandboxSgLogicalId);
      });
      expect(selfRefInline.length).toBe(0);
    });

    test('outputs are correctly defined', () => {
      const stack = new SandboxStack(app, 'TestSandboxStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      expect(stack.output).toBeDefined();
      expect(stack.output.clusterArn).toBeDefined();
      expect(stack.output.registryTableName).toBeDefined();
      expect(stack.output.taskDefinitionFamily).toBeDefined();
      expect(stack.output.sandboxTaskSecurityGroupId).toBeDefined();
      expect(stack.output.orchestratorApiUrl).toBeDefined();
      expect(stack.output.orchestratorDnsName).toContain('openhands.local');
    });

    test('idle timeout is configurable', () => {
      const stack = new SandboxStack(app, 'TestSandboxCustomTimeout', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
        idleTimeoutMinutes: 10,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'openhands-sandbox-idle-monitor',
        Environment: {
          Variables: Match.objectLike({
            IDLE_TIMEOUT_MINUTES: '10',
          }),
        },
      });
    });

    test('idle timeout defaults to 30 minutes', () => {
      const stack = new SandboxStack(app, 'TestSandboxDefaultTimeout', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'openhands-sandbox-idle-monitor',
        Environment: {
          Variables: Match.objectLike({
            IDLE_TIMEOUT_MINUTES: '30',
          }),
        },
      });
    });

    test('orchestrator has EFS access point management permissions', () => {
      const stack = new SandboxStack(app, 'TestSandboxEfs', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'EfsAccessPointManagement',
              Effect: 'Allow',
              Action: [
                'elasticfilesystem:CreateAccessPoint',
                'elasticfilesystem:DeleteAccessPoint',
                'elasticfilesystem:DescribeAccessPoints',
                'elasticfilesystem:TagResource',
              ],
            }),
          ]),
        },
      });
    });

    test('orchestrator has ECS task definition management permissions', () => {
      const stack = new SandboxStack(app, 'TestSandboxTaskDef', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'EcsTaskDefinitionManagement',
              Effect: 'Allow',
              Action: [
                'ecs:RegisterTaskDefinition',
                'ecs:DescribeTaskDefinition',
                'ecs:DeregisterTaskDefinition',
              ],
            }),
          ]),
        },
      });
    });

    test('orchestrator environment includes EFS_FILE_SYSTEM_ID', () => {
      const stack = new SandboxStack(app, 'TestSandboxEfsEnv', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      // Orchestrator container should have EFS_FILE_SYSTEM_ID env var
      template.hasResourceProperties('AWS::ECS::TaskDefinition', Match.objectLike({
        Family: 'openhands-sandbox-orchestrator',
        ContainerDefinitions: Match.arrayWith([
          Match.objectLike({
            Name: 'orchestrator',
            Environment: Match.arrayWith([
              Match.objectLike({ Name: 'EFS_FILE_SYSTEM_ID' }),
            ]),
          }),
        ]),
      }));
    });

    test('idle monitor Lambda has EFS cleanup permissions', () => {
      const stack = new SandboxStack(app, 'TestSandboxIdleEfs', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Sid: 'EfsAccessPointCleanup',
              Effect: 'Allow',
              Action: Match.arrayWith([
                'elasticfilesystem:DeleteAccessPoint',
              ]),
            }),
          ]),
        },
      });
    });

    test('task state handler Lambda has EFS cleanup permissions', () => {
      const stack = new SandboxStack(app, 'TestSandboxTaskStateEfs', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      const template = Template.fromStack(stack);

      // Should have at least 2 policies with EFS cleanup (idle monitor + task state handler)
      const templateJson = template.toJSON() as Record<string, unknown>;
      const resources = templateJson.Resources as Record<string, { Type: string; Properties: Record<string, unknown> }>;
      const efsCleanupPolicies = Object.entries(resources).filter(([, r]) => {
        if (r.Type !== 'AWS::IAM::Policy') return false;
        const stmts = (r.Properties?.PolicyDocument as any)?.Statement ?? [];
        return stmts.some((s: any) => s.Sid === 'EfsAccessPointCleanup');
      });
      expect(efsCleanupPolicies.length).toBeGreaterThanOrEqual(2);
    });

    test('efsFileSystemId is in stack output', () => {
      const stack = new SandboxStack(app, 'TestSandboxEfsOutput', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
      });

      expect(stack.output.efsFileSystemId).toBeDefined();
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

      const clusterStack = new ClusterStack(app, 'TestClusterStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
      });

      const computeStack = new ComputeStack(app, 'TestComputeStack', {
        env: testEnv,
        config: testConfig,
        networkOutput: networkStack.output,
        securityOutput: securityStack.output,
        monitoringOutput: monitoringStack.output,
        clusterOutput: clusterStack.output,
        databaseOutput: mockDatabaseOutput,
        sandboxOutput: mockSandboxOutput,
      });

      // Verify all stacks can be synthesized
      expect(networkStack.stackName).toBeDefined();
      expect(securityStack.stackName).toBeDefined();
      expect(monitoringStack.stackName).toBeDefined();
      expect(clusterStack.stackName).toBeDefined();
      expect(computeStack.stackName).toBeDefined();

      // Verify outputs are defined
      expect(networkStack.output).toBeDefined();
      expect(securityStack.output).toBeDefined();
      expect(monitoringStack.output).toBeDefined();
      expect(clusterStack.output).toBeDefined();
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

      expect(securityStack.output.userSecretsKmsKeyArn).toBeDefined();
      expect(securityStack.output.userSecretsKmsKeyId).toBeDefined();

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
