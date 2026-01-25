import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';
import { OpenHandsConfig, NetworkStackOutput } from './interfaces.js';

export interface NetworkStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  /**
   * Skip creating S3 VPC Gateway Endpoint if one already exists in the VPC.
   * Set to true when deploying to a VPC that already has an S3 endpoint.
   */
  skipS3Endpoint?: boolean;
}

/**
 * NetworkStack - Imports existing VPC and creates VPC Endpoints
 *
 * VPC Endpoints provide private connectivity to AWS services without
 * traversing the public internet, improving security and reducing costs.
 */
export class NetworkStack extends cdk.Stack {
  public readonly output: NetworkStackOutput;

  constructor(scope: Construct, id: string, props: NetworkStackProps) {
    super(scope, id, props);

    const { config } = props;

    // Import existing VPC
    const vpc = ec2.Vpc.fromLookup(this, 'ExistingVpc', {
      vpcId: config.vpcId,
    });

    // Security group for VPC Endpoints
    const vpcEndpointSecurityGroup = new ec2.SecurityGroup(this, 'VpcEndpointSg', {
      vpc,
      description: 'Security group for VPC Endpoints',
      allowAllOutbound: false,
    });

    // Allow inbound HTTPS from within VPC
    vpcEndpointSecurityGroup.addIngressRule(
      ec2.Peer.ipv4(vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      'Allow HTTPS from VPC'
    );

    // Create Interface VPC Endpoints
    const interfaceEndpoints = [
      { id: 'BedrockRuntime', service: ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME },
      { id: 'SecretsManager', service: ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER },
      { id: 'EcrApi', service: ec2.InterfaceVpcEndpointAwsService.ECR },
      { id: 'EcrDkr', service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER },
      { id: 'CloudWatchLogs', service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS },
      { id: 'Ssm', service: ec2.InterfaceVpcEndpointAwsService.SSM },
      { id: 'SsmMessages', service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES },
      { id: 'Ec2Messages', service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES },
    ];

    for (const endpoint of interfaceEndpoints) {
      new ec2.InterfaceVpcEndpoint(this, `${endpoint.id}Endpoint`, {
        vpc,
        service: endpoint.service,
        securityGroups: [vpcEndpointSecurityGroup],
        privateDnsEnabled: true,
      });
    }

    // Create Gateway VPC Endpoint for S3 (unless already exists)
    if (!props.skipS3Endpoint) {
      new ec2.GatewayVpcEndpoint(this, 'S3Endpoint', {
        vpc,
        service: ec2.GatewayVpcEndpointAwsService.S3,
      });
    }

    // Store outputs
    this.output = {
      vpc,
      vpcId: config.vpcId,
      vpcEndpointSecurityGroup,
    };

    // CloudFormation outputs
    new cdk.CfnOutput(this, 'VpcId', {
      value: vpc.vpcId,
      description: 'VPC ID',
    });
  }
}
