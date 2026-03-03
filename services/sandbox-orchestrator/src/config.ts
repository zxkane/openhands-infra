/** Environment variable configuration for the Sandbox Orchestrator. */

export const config = {
  registryTableName: process.env.REGISTRY_TABLE_NAME || 'openhands-sandbox-registry',
  ecsClusterArn: process.env.ECS_CLUSTER_ARN || '',
  taskDefinitionFamily: process.env.TASK_DEFINITION_FAMILY || process.env.TASK_DEFINITION_ARN || '',
  subnets: (process.env.SUBNETS || '').split(',').filter((s) => s.trim()),
  securityGroupId: process.env.SECURITY_GROUP_ID || '',
  region: process.env.AWS_REGION_NAME || process.env.AWS_DEFAULT_REGION || 'us-east-1',
  sandboxImage: process.env.SANDBOX_IMAGE || '',
  warmPoolServiceName: process.env.WARM_POOL_SERVICE_NAME || '',
  efsFileSystemId: process.env.EFS_FILE_SYSTEM_ID || '',
  port: parseInt(process.env.PORT || '8081', 10),
  /** Lambda ARN for async conversation deletion (full data wipe) */
  deletionLambdaArn: process.env.DELETION_LAMBDA_ARN || '',
  /** Conversation retention TTL in seconds (default: 183 days = 180 retention + 3 day buffer) */
  conversationRetentionSeconds: parseInt(process.env.CONVERSATION_RETENTION_SECONDS || '15811200', 10),
} as const;
