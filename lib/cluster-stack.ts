import * as cdk from 'aws-cdk-lib';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import { Construct } from 'constructs';
import { OpenHandsConfig, NetworkStackOutput, ClusterStackOutput } from './interfaces.js';

export interface ClusterStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
}

/**
 * ClusterStack - Shared ECS Cluster and Cloud Map Namespace
 *
 * Provides the shared ECS cluster and Cloud Map private DNS namespace
 * used by both the main application services (ComputeStack) and
 * sandbox containers (SandboxStack).
 *
 * Resources:
 * - ECS Cluster with Container Insights enabled
 * - Cloud Map private DNS namespace (openhands.local)
 */
export class ClusterStack extends cdk.Stack {
  public readonly output: ClusterStackOutput;

  constructor(scope: Construct, id: string, props: ClusterStackProps) {
    super(scope, id, props);

    const { config, networkOutput } = props;
    const { vpc } = networkOutput;

    // Name prefix derived from domain to support multi-environment deployments
    const fullDomain = `${config.subDomain}.${config.domainName}`;
    const namePrefix = fullDomain.replace(/\./g, '-');

    // ========================================
    // ECS Cluster (shared by app + sandbox)
    // ========================================
    const cluster = new ecs.Cluster(this, 'Cluster', {
      vpc,
      clusterName: namePrefix,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });
    cdk.Tags.of(cluster).add('Component', 'ecs-cluster');

    // ========================================
    // Cloud Map Private DNS Namespace
    // ========================================
    const namespace = new servicediscovery.PrivateDnsNamespace(this, 'Namespace', {
      name: 'openhands.local',
      vpc,
      description: 'Private DNS for OpenHands services (app, orchestrator)',
    });

    // ========================================
    // Outputs
    // ========================================
    this.output = {
      cluster,
      clusterArn: cluster.clusterArn,
      clusterName: cluster.clusterName,
      namespace,
      namespaceName: 'openhands.local',
    };

    new cdk.CfnOutput(this, 'ClusterArn', {
      value: cluster.clusterArn,
      description: 'Shared ECS Cluster ARN',
    });

    new cdk.CfnOutput(this, 'ClusterName', {
      value: cluster.clusterName,
      description: 'Shared ECS Cluster name',
    });

    new cdk.CfnOutput(this, 'NamespaceName', {
      value: 'openhands.local',
      description: 'Cloud Map private DNS namespace',
    });
  }
}
