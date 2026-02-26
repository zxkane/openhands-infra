/** Shared TypeScript interfaces for the Sandbox Orchestrator. */

/** Sandbox record as stored in DynamoDB. */
export interface SandboxRecord {
  conversation_id: string;
  user_id: string;
  task_arn: string;
  task_ip: string;
  status: SandboxStatus;
  session_api_key: string;
  agent_server_port: number;
  sandbox_spec_id: string;
  last_activity_at: number;
  created_at: number;
  ttl?: number;
  /** EFS access point ID for per-conversation isolation (created at sandbox start) */
  access_point_id?: string;
  /** Task definition ARN with per-conversation access point (registered at sandbox start) */
  task_definition_arn?: string;
}

export type SandboxStatus =
  | 'RUNNING'
  | 'STARTING'
  | 'WARM'
  | 'CLAIMED'
  | 'PAUSED'
  | 'STOPPED'
  | 'ERROR';

/** Runtime info returned to the OpenHands RemoteSandboxService. */
export interface RuntimeInfo {
  session_id: string;
  runtime_id: string;
  status: string;
  pod_status: string;
  url: string;
  session_api_key: string;
  image: string;
  user_id: string;
}

/** Request body for POST /start */
export interface StartRequest {
  session_id: string;
  image?: string;
  environment?: Record<string, string>;
}

/** Request body for POST /stop, /pause, /resume */
export interface RuntimeIdRequest {
  runtime_id: string;
}

/** Request body for POST /activity */
export interface ActivityRequest {
  session_id: string;
}

/** Result from ECS RunTask. */
export interface RunTaskResult {
  task_arn: string;
  last_status: string;
}

/** Result from ECS DescribeTasks. */
export interface TaskInfo {
  task_arn: string;
  last_status: string;
  desired_status: string;
  task_ip: string | null;
  stopped_reason: string;
}

/** Minimal shape of an ECS Task from DescribeTasks, used for IP extraction. */
export interface EcsTaskDescription {
  taskArn?: string;
  lastStatus?: string;
  desiredStatus?: string;
  stoppedReason?: string;
  attachments?: Array<{
    type?: string;
    details?: Array<{ name?: string; value?: string }>;
  }>;
}
