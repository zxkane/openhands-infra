/** Environment variable configuration for the Sandbox Orchestrator. */

export const config = {
  registryTableName: process.env.REGISTRY_TABLE_NAME || 'openhands-sandbox-registry',
  ecsClusterArn: process.env.ECS_CLUSTER_ARN || '',
  taskDefinitionArn: process.env.TASK_DEFINITION_ARN || '',
  subnets: (process.env.SUBNETS || '').split(',').filter((s) => s.trim()),
  securityGroupId: process.env.SECURITY_GROUP_ID || '',
  region: process.env.AWS_REGION_NAME || process.env.AWS_DEFAULT_REGION || 'us-east-1',
  sandboxImage: process.env.SANDBOX_IMAGE || '',
  warmPoolServiceName: process.env.WARM_POOL_SERVICE_NAME || '',
  port: parseInt(process.env.PORT || '8081', 10),
} as const;
