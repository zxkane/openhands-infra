"""ECS Fargate task management for sandbox containers."""

import logging
import time
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class EcsManager:
    """Manages ECS Fargate tasks for sandbox containers."""

    def __init__(
        self,
        cluster_arn: str,
        task_definition_arn: str,
        subnets: list[str],
        security_group_id: str,
        region: Optional[str] = None,
    ):
        self._cluster_arn = cluster_arn
        self._task_definition_arn = task_definition_arn
        self._subnets = [s for s in subnets if s.startswith('subnet-')]
        if not self._subnets:
            raise ValueError('No valid subnets configured for ECS tasks')
        self._security_group_id = security_group_id
        session = boto3.Session(region_name=region) if region else boto3.Session()
        self._ecs = session.client('ecs')

    def run_task(
        self,
        conversation_id: str,
        user_id: str,
        image: str,
        environment: dict[str, str],
        session_api_key: str,
    ) -> dict:
        """Start a new Fargate task for a sandbox.

        Returns dict with task_arn and task info on success.
        Raises RuntimeError on failure.
        """
        # Build container overrides with environment variables
        env_overrides = [
            {'name': k, 'value': v}
            for k, v in environment.items()
        ]
        # Inject standard vars
        env_overrides.extend([
            {'name': 'CONVERSATION_ID', 'value': conversation_id},
            {'name': 'USER_ID', 'value': user_id},
            {'name': 'OH_SESSION_API_KEYS_0', 'value': session_api_key},
        ])

        # Note: 'image' is not a valid containerOverride field.
        # The sandbox image is set in the task definition. If a different image is needed,
        # a new task definition revision must be registered.
        container_overrides = [{
            'name': 'agent-server',
            'environment': env_overrides,
        }]

        tags = [
            {'key': 'conversation_id', 'value': conversation_id},
            {'key': 'user_id', 'value': user_id},
            {'key': 'ManagedBy', 'value': 'sandbox-orchestrator'},
        ]

        try:
            response = self._ecs.run_task(
                cluster=self._cluster_arn,
                taskDefinition=self._task_definition_arn,
                launchType='FARGATE',
                count=1,
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': self._subnets,
                        'securityGroups': [self._security_group_id],
                        'assignPublicIp': 'DISABLED',
                    }
                },
                overrides={
                    'containerOverrides': container_overrides,
                },
                tags=tags,
                propagateTags='TASK_DEFINITION',
                enableECSManagedTags=True,
                enableExecuteCommand=False,
            )
        except ClientError as e:
            raise RuntimeError(f'Failed to run ECS task: {e}') from e

        failures = response.get('failures', [])
        if failures:
            reason = failures[0].get('reason', 'Unknown')
            raise RuntimeError(f'ECS RunTask failed: {reason}')

        tasks = response.get('tasks', [])
        if not tasks:
            raise RuntimeError('ECS RunTask returned no tasks')

        task = tasks[0]
        task_arn = task['taskArn']
        logger.info('Started sandbox task %s for conversation %s', task_arn, conversation_id)

        return {
            'task_arn': task_arn,
            'last_status': task.get('lastStatus', 'PROVISIONING'),
        }

    def stop_task(self, task_arn: str, reason: str = 'Sandbox stopped') -> None:
        """Stop a running Fargate task."""
        try:
            self._ecs.stop_task(
                cluster=self._cluster_arn,
                task=task_arn,
                reason=reason,
            )
            logger.info('Stopped task %s: %s', task_arn, reason)
        except ClientError as e:
            logger.error('Failed to stop task %s: %s', task_arn, e)
            raise RuntimeError(f'Failed to stop task: {e}') from e

    def describe_task(self, task_arn: str) -> Optional[dict]:
        """Get current state of a task including ENI IP."""
        try:
            response = self._ecs.describe_tasks(
                cluster=self._cluster_arn,
                tasks=[task_arn],
            )
        except ClientError as e:
            logger.error('Failed to describe task %s: %s', task_arn, e)
            return None

        tasks = response.get('tasks', [])
        if not tasks:
            return None

        task = tasks[0]
        return {
            'task_arn': task['taskArn'],
            'last_status': task.get('lastStatus', 'UNKNOWN'),
            'desired_status': task.get('desiredStatus', 'UNKNOWN'),
            'task_ip': self._extract_task_ip(task),
            'stopped_reason': task.get('stoppedReason', ''),
        }

    def wait_for_running(self, task_arn: str, timeout_seconds: int = 120) -> Optional[str]:
        """Poll until task reaches RUNNING state and return its ENI IP.

        Returns the task's private IP address or None on timeout/failure.
        """
        start = time.time()
        poll_interval = 3  # seconds

        while time.time() - start < timeout_seconds:
            info = self.describe_task(task_arn)
            if not info:
                logger.warning('Task %s not found during wait', task_arn)
                return None

            status = info['last_status']
            if status == 'RUNNING':
                task_ip = info.get('task_ip')
                if task_ip:
                    logger.info('Task %s is RUNNING with IP %s', task_arn, task_ip)
                    return task_ip
                logger.warning('Task %s is RUNNING but has no IP', task_arn)

            if status in ('STOPPED', 'DEPROVISIONING'):
                reason = info.get('stopped_reason', 'Unknown')
                logger.error('Task %s stopped before becoming ready: %s', task_arn, reason)
                return None

            time.sleep(poll_interval)

        logger.error('Timed out waiting for task %s to become RUNNING', task_arn)
        return None

    @staticmethod
    def _extract_task_ip(task: dict) -> Optional[str]:
        """Extract private IP from task's ENI attachment."""
        for attachment in task.get('attachments', []):
            if attachment.get('type') == 'ElasticNetworkInterface':
                for detail in attachment.get('details', []):
                    if detail.get('name') == 'privateIPv4Address':
                        return detail.get('value')
        return None
