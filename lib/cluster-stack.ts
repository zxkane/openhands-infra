import * as cdk from 'aws-cdk-lib';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as servicediscovery from 'aws-cdk-lib/aws-servicediscovery';
import { Construct } from 'constructs';
import { OpenHandsConfig, NetworkStackOutput, ClusterStackOutput } from './interfaces.js';

export interface ClusterStackProps extends cdk.StackProps {
  config: OpenHandsConfig;
  networkOutput: NetworkStackOutput;
  /**
   * Existing Cloud Map namespace ARN to import instead of creating a new one.
   * Used during migration when the namespace was previously owned by SandboxStack.
   * Once migration is complete and the old namespace resource is removed from
   * SandboxStack's CloudFormation template, this can be omitted to create a new one.
   */
  existingNamespaceArn?: string;
  /**
   * Existing Cloud Map namespace name (required when existingNamespaceArn is provided).
   */
  existingNamespaceName?: string;
  /**
   * Existing Cloud Map namespace ID (required when existingNamespaceArn is provided).
   */
  existingNamespaceId?: string;
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
    // During migration from SandboxStack-owned namespace, import the existing one.
    // For fresh deployments, create a new namespace.
    let namespace: servicediscovery.IPrivateDnsNamespace;
    let namespaceName: string;

    if (props.existingNamespaceArn && props.existingNamespaceId && props.existingNamespaceName) {
      namespace = servicediscovery.PrivateDnsNamespace.fromPrivateDnsNamespaceAttributes(this, 'Namespace', {
        namespaceArn: props.existingNamespaceArn,
        namespaceId: props.existingNamespaceId,
        namespaceName: props.existingNamespaceName,
      });
      namespaceName = props.existingNamespaceName;
    } else {
      namespace = new servicediscovery.PrivateDnsNamespace(this, 'Namespace', {
        name: 'openhands.local',
        vpc,
        description: 'Private DNS for OpenHands services (app, orchestrator)',
      });
      namespaceName = 'openhands.local';
    }

    // ========================================
    // Outputs
    // ========================================
    this.output = {
      cluster,
      clusterArn: cluster.clusterArn,
      clusterName: cluster.clusterName,
      namespace,
      namespaceName,
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
      value: namespaceName,
      description: 'Cloud Map private DNS namespace',
    });
  }
}
