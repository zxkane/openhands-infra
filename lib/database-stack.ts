import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import { Construct } from 'constructs';
import * as path from 'node:path';
import { NetworkStackOutput, SecurityStackOutput, DatabaseStackOutput } from './interfaces.js';

export interface DatabaseStackProps extends cdk.StackProps {
  networkOutput: NetworkStackOutput;
  securityOutput: SecurityStackOutput;
  /**
   * EC2 role ARN to grant RDS IAM authentication permission.
   * Uses string ARN to avoid cross-stack L2 construct token references that cause cyclic dependencies.
   */
  ec2RoleArn: string;
}

export { DatabaseStackOutput };

/**
 * DatabaseStack - Aurora Serverless v2 PostgreSQL with IAM Authentication
 *
 * Uses IAM role-based authentication instead of username/password:
 * - No secrets to manage or rotate
 * - EC2 instance uses its IAM role to authenticate
 * - Connection token generated dynamically via AWS SDK
 */
export class DatabaseStack extends cdk.Stack {
  public readonly output: DatabaseStackOutput;
  public readonly cluster: rds.DatabaseCluster;

  constructor(scope: Construct, id: string, props: DatabaseStackProps) {
    super(scope, id, props);

    const vpc = ec2.Vpc.fromLookup(this, 'Vpc', {
      vpcId: props.networkOutput.vpcId,
    });

    // Security group for Aurora
    const dbSecurityGroup = new ec2.SecurityGroup(this, 'AuroraSecurityGroup', {
      vpc,
      description: 'Security group for Aurora Serverless PostgreSQL',
      allowAllOutbound: false,
    });

    // Import EC2 security group
    const ec2Sg = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      'Ec2Sg',
      props.securityOutput.ec2SecurityGroupId,
      { mutable: true, allowAllOutbound: false }
    );

    // Allow inbound from EC2 security group
    dbSecurityGroup.addIngressRule(
      ec2Sg,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL from EC2'
    );

    // Allow EC2 security group egress to Aurora
    // Note: Must be added here (not in SecurityStack) to avoid cyclic dependency
    ec2Sg.addEgressRule(
      dbSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL to Aurora'
    );

    // Database configuration
    const databaseName = 'openhands';
    // IAM user for direct cluster connections (backup)
    const iamDatabaseUser = 'openhands_iam';
    // Password-based user for RDS Proxy connections (primary)
    const proxyDatabaseUser = 'openhands_proxy';

    // Create secret for the proxy user (RDS Proxy requires password-based auth to backend)
    const proxyUserSecret = new secretsmanager.Secret(this, 'ProxyUserSecret', {
      secretName: 'openhands/database/proxy-user',
      description: 'Credentials for OpenHands RDS Proxy user',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          username: proxyDatabaseUser,
        }),
        generateStringKey: 'password',
        excludePunctuation: true,
        passwordLength: 32,
      },
    });

    // Aurora Serverless v2 cluster with IAM authentication
    this.cluster = new rds.DatabaseCluster(this, 'AuroraCluster', {
      engine: rds.DatabaseClusterEngine.auroraPostgres({
        version: rds.AuroraPostgresEngineVersion.VER_15_8,  // Use stable available version
      }),
      // Use admin credentials only for initial setup (create IAM user)
      credentials: rds.Credentials.fromGeneratedSecret('postgres', {
        secretName: 'openhands/database/admin',
      }),
      defaultDatabaseName: databaseName,
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      securityGroups: [dbSecurityGroup],

      // Enable IAM authentication
      iamAuthentication: true,

      // Serverless v2 configuration
      serverlessV2MinCapacity: 0.5,  // Minimum 0.5 ACU (~$43/month if always on)
      serverlessV2MaxCapacity: 4,    // Maximum 4 ACU

      writer: rds.ClusterInstance.serverlessV2('writer', {
        publiclyAccessible: false,
      }),

      // Backup configuration
      backup: {
        retention: cdk.Duration.days(35),
        preferredWindow: '03:00-04:00',  // UTC
      },

      // Maintenance window
      preferredMaintenanceWindow: 'Sun:04:00-Sun:05:00',

      // Storage encryption
      storageEncrypted: true,

      // CloudWatch logs export
      cloudwatchLogsExports: ['postgresql'],

      // Deletion protection (enable for production)
      deletionProtection: false,
      removalPolicy: cdk.RemovalPolicy.SNAPSHOT,

      // Enable Data API for SQL execution via Custom Resource
      enableDataApi: true,

      // Parameter group for performance tuning
      parameterGroup: new rds.ParameterGroup(this, 'ParameterGroup', {
        engine: rds.DatabaseClusterEngine.auroraPostgres({
          version: rds.AuroraPostgresEngineVersion.VER_15_8,
        }),
        parameters: {
          'log_statement': 'ddl',
          'log_min_duration_statement': '1000',  // Log queries > 1s
        },
      }),
    });

    // Note: IAM authentication permissions are granted in ComputeStack
    // using the clusterResourceId exported from this stack.
    // This avoids cyclic dependencies between SecurityStack and DatabaseStack.

    // Database bootstrap (idempotent):
    // - Create required DB users
    // - Ensure the RDS Proxy backend user's password matches the secret used by the proxy
    // - Apply compatibility shim(s) needed by OpenHands migrations
    //
    // Implemented as a Lambda-backed Custom Resource so secrets never appear in CloudFormation
    // resource properties, and so the same IaC works across accounts/regions without manual steps.

    // Build ARN manually to avoid cross-stack reference issues
    const clusterArn = `arn:aws:rds:${cdk.Aws.REGION}:${cdk.Aws.ACCOUNT_ID}:cluster:${this.cluster.clusterIdentifier}`;

    const dbBootstrapSecurityGroup = new ec2.SecurityGroup(this, 'DbBootstrapSecurityGroup', {
      vpc,
      description: 'Security group for database bootstrap Lambda',
      allowAllOutbound: true,
    });

    // Allow the bootstrap Lambda to connect to Aurora for one-time/idempotent initialization.
    dbSecurityGroup.addIngressRule(
      dbBootstrapSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL from DB bootstrap Lambda'
    );

    const dbBootstrapHandler = new lambdaNodejs.NodejsFunction(this, 'DbBootstrapHandler', {
      runtime: lambda.Runtime.NODEJS_20_X,
      entry: path.join(__dirname, '..', 'lambda', 'db-bootstrap', 'index.ts'),
      handler: 'handler',
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [dbBootstrapSecurityGroup],
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
    });

    // Needs to read DB admin + proxy user secrets to connect and sync credentials.
    this.cluster.secret!.grantRead(dbBootstrapHandler);
    proxyUserSecret.grantRead(dbBootstrapHandler);

    const dbBootstrapProvider = new cr.Provider(this, 'DbBootstrapProvider', {
      onEventHandler: dbBootstrapHandler,
    });

    const dbBootstrap = new cdk.CustomResource(this, 'DbBootstrap', {
      serviceToken: dbBootstrapProvider.serviceToken,
      properties: {
        clusterArn,
        adminSecretArn: this.cluster.secret!.secretArn,
        host: this.cluster.clusterEndpoint.hostname,
        port: this.cluster.clusterEndpoint.port.toString(),
        database: databaseName,
        iamDatabaseUser,
        proxyDatabaseUser,
        proxySecretArn: proxyUserSecret.secretArn,
      },
      resourceType: 'Custom::OpenHandsDbBootstrap',
    });

    dbBootstrap.node.addDependency(this.cluster);
    dbBootstrap.node.addDependency(proxyUserSecret);

    // Grant IAM authentication permission to EC2 role for direct cluster access (backup)
    // Import role by ARN (using string) to avoid cross-stack token references
    const ec2RoleFromArn = iam.Role.fromRoleArn(this, 'Ec2RoleRef', props.ec2RoleArn, {
      mutable: true,  // Allow policy attachment
    });
    ec2RoleFromArn.addToPrincipalPolicy(new iam.PolicyStatement({
      actions: ['rds-db:connect'],
      resources: [
        `arn:aws:rds-db:${cdk.Aws.REGION}:${cdk.Aws.ACCOUNT_ID}:dbuser:${this.cluster.clusterResourceIdentifier}/${iamDatabaseUser}`,
      ],
    }));

    // RDS Proxy for connection pooling
    // Uses password-based authentication to connect to Aurora (via proxyUserSecret)
    // Application connects using the proxy user credentials stored in Secrets Manager
    const proxySecurityGroup = new ec2.SecurityGroup(this, 'ProxySecurityGroup', {
      vpc,
      description: 'Security group for RDS Proxy',
      allowAllOutbound: false,
    });

    // Allow EC2 to connect to proxy
    proxySecurityGroup.addIngressRule(
      ec2Sg,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL from EC2'
    );

    // Allow EC2 security group egress to RDS Proxy
    // Note: Must be added here (not in SecurityStack) because the proxy SG is created in this stack.
    ec2Sg.addEgressRule(
      proxySecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL to RDS Proxy'
    );

    // Allow proxy to connect to Aurora
    proxySecurityGroup.addEgressRule(
      dbSecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL to Aurora'
    );

    // Allow Aurora to accept connections from proxy
    dbSecurityGroup.addIngressRule(
      proxySecurityGroup,
      ec2.Port.tcp(5432),
      'Allow PostgreSQL from RDS Proxy'
    );

    // Create RDS Proxy with password-based authentication
    // The proxy uses the proxyUserSecret to authenticate to Aurora
    // Application connects using the same credentials (no IAM tokens needed)
    const proxy = new rds.DatabaseProxy(this, 'Proxy', {
      proxyTarget: rds.ProxyTarget.fromCluster(this.cluster),
      // Include both admin secret and proxy user secret
      // Admin secret is used to create the user, proxy user secret is used for connections
      secrets: [this.cluster.secret!, proxyUserSecret],
      vpc,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
      securityGroups: [proxySecurityGroup],
      requireTLS: true,
      // Disable IAM auth - use password-based auth instead
      // This eliminates the need for token refresh entirely
      iamAuth: false,
      dbProxyName: 'openhands-proxy',
      idleClientTimeout: cdk.Duration.minutes(30),
      maxConnectionsPercent: 100,
      maxIdleConnectionsPercent: 50,
    });

    // Grant EC2 role permission to read proxy user secret
    proxyUserSecret.grantRead(ec2RoleFromArn);

    // Outputs - use proxy user for connections
    this.output = {
      clusterEndpoint: this.cluster.clusterEndpoint.hostname,
      clusterPort: this.cluster.clusterEndpoint.port.toString(),
      clusterResourceId: this.cluster.clusterResourceIdentifier,
      databaseName,
      databaseUser: proxyDatabaseUser,  // Use proxy user for connections
      securityGroupId: dbSecurityGroup.securityGroupId,
      proxyEndpoint: proxy.endpoint,
    };

    // Stack outputs
    new cdk.CfnOutput(this, 'ClusterEndpoint', {
      value: this.cluster.clusterEndpoint.hostname,
      description: 'Aurora cluster endpoint',
    });

    new cdk.CfnOutput(this, 'ClusterPort', {
      value: this.cluster.clusterEndpoint.port.toString(),
      description: 'Aurora cluster port',
    });

    new cdk.CfnOutput(this, 'ClusterResourceId', {
      value: this.cluster.clusterResourceIdentifier,
      description: 'Aurora cluster resource ID (for IAM auth)',
    });

    new cdk.CfnOutput(this, 'DatabaseUser', {
      value: proxyDatabaseUser,
      description: 'Database user for proxy connections',
    });

    new cdk.CfnOutput(this, 'DatabaseName', {
      value: databaseName,
      description: 'Database name',
    });

    new cdk.CfnOutput(this, 'ProxyEndpoint', {
      value: proxy.endpoint,
      description: 'RDS Proxy endpoint (recommended for connections)',
    });

    new cdk.CfnOutput(this, 'ProxyUserSecretArn', {
      value: proxyUserSecret.secretArn,
      description: 'ARN of the secret containing proxy user credentials',
    });

    // Output connection command for reference (using proxy with password from secret)
    new cdk.CfnOutput(this, 'ProxyConnectionExample', {
      value: `export PGPASSWORD=$(aws secretsmanager get-secret-value --secret-id openhands/database/proxy-user --query SecretString --output text | jq -r .password) && psql "host=${proxy.endpoint} port=5432 dbname=${databaseName} user=${proxyDatabaseUser} sslmode=require"`,
      description: 'Example command to connect via RDS Proxy using password from Secrets Manager',
    });

    // Keep direct cluster connection command for admin tasks (IAM auth)
    new cdk.CfnOutput(this, 'ClusterConnectionExample', {
      value: `export PGPASSWORD=$(aws rds generate-db-auth-token --hostname ${this.cluster.clusterEndpoint.hostname} --port 5432 --username ${iamDatabaseUser} --region ${this.region}) && psql "host=${this.cluster.clusterEndpoint.hostname} port=5432 dbname=${databaseName} user=${iamDatabaseUser} sslmode=require"`,
      description: 'Example command to connect directly to cluster using IAM auth (for admin tasks)',
    });

    // Post-deployment setup instructions
  }
}
