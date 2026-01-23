import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { NetworkStack } from '../lib/network-stack';
import { SecurityStack } from '../lib/security-stack';
import { MonitoringStack } from '../lib/monitoring-stack';
import { ComputeStack } from '../lib/compute-stack';
import { AuthStack } from '../lib/auth-stack';
import { EdgeStack } from '../lib/edge-stack';
import { DatabaseStack } from '../lib/database-stack';
import { OpenHandsConfig, DatabaseStackOutput } from '../lib/interfaces';

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

      // Verify Security Groups are created (ALB and EC2)
      template.resourceCountIs('AWS::EC2::SecurityGroup', 2);
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

  describe('AuthStack', () => {
    test('synthesizes correctly', () => {
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new AuthStack(app, 'TestAuthStack', {
        env: edgeEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com', 'openhands.test.example.com'],
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Cognito::UserPool', {
        AutoVerifiedAttributes: ['email'],
        UsernameAttributes: ['email'],
      });

      template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
        ClientName: 'Openhands on AWS',
        CallbackURLs: Match.arrayWith([
          'https://openhands.example.com/_callback',
          'https://openhands.test.example.com/_callback',
        ]),
      });

      template.hasResourceProperties('AWS::Cognito::UserPoolDomain', {
        ManagedLoginVersion: 2,
      });

      template.resourceCountIs('AWS::Cognito::ManagedLoginBranding', 1);

      template.hasResourceProperties('AWS::SecretsManager::Secret', {
        Name: 'openhands/cognito-client-secret-shared',
      });
    });

    test('creates user pool with secure password policy', () => {
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new AuthStack(app, 'TestAuthStack', {
        env: edgeEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
      });

      const template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Cognito::UserPool', {
        Policies: {
          PasswordPolicy: {
            MinimumLength: 8,
            RequireLowercase: true,
            RequireUppercase: true,
            RequireNumbers: true,
            RequireSymbols: true,
          },
        },
      });
    });

    test('matches snapshot', () => {
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new AuthStack(app, 'TestAuthStack', {
        env: edgeEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
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
    let authStack: AuthStack;

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

      const edgeEnv = { account: '123456789012', region: 'us-east-1' };
      authStack = new AuthStack(app, 'TestAuthStack', {
        env: edgeEnv,
        config: testConfig,
        callbackDomains: ['openhands.example.com'],
      });
    });

    test('synthesizes correctly', () => {
      // EdgeStack must be in us-east-1 for Lambda@Edge
      const edgeEnv = { account: '123456789012', region: 'us-east-1' };

      const stack = new EdgeStack(app, 'TestEdgeStack', {
        env: edgeEnv,
        config: testConfig,
        authOutput: authStack.output,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
        crossRegionReferences: true,
      });

      const template = Template.fromStack(stack);

      // Verify ACM Certificate is created
      template.hasResourceProperties('AWS::CertificateManager::Certificate', {
        DomainName: 'openhands.example.com',
      });

      // Verify CloudFront distribution is created
      template.resourceCountIs('AWS::CloudFront::Distribution', 1);

      // Verify Lambda@Edge function is created
      template.hasResourceProperties('AWS::Lambda::Function', {
        Runtime: 'nodejs20.x',
        Handler: 'index.handler',
      });

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
        authOutput: authStack.output,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
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
        authOutput: authStack.output,
        computeOutput: computeStack.output,
        alb: computeStack.alb,
        crossRegionReferences: true,
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
  });
});
