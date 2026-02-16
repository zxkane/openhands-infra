"""DynamoDB-backed sandbox registry for conversation → ECS task mapping."""

import time
import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Time-to-live: 7 days from last activity
TTL_SECONDS = 7 * 24 * 3600


class SandboxRecord:
    """Represents a sandbox entry in the registry."""

    def __init__(self, data: dict):
        self.conversation_id: str = data.get('conversation_id', '')
        self.user_id: str = data.get('user_id', '')
        self.task_arn: str = data.get('task_arn', '')
        self.task_ip: str = data.get('task_ip', '')
        self.status: str = data.get('status', '')
        self.session_api_key: str = data.get('session_api_key', '')
        self.agent_server_port: int = int(data.get('agent_server_port', 8000))
        self.sandbox_spec_id: str = data.get('sandbox_spec_id', '')
        self.last_activity_at: int = int(data.get('last_activity_at', 0))
        self.created_at: int = int(data.get('created_at', 0))

    def to_dict(self) -> dict:
        return {
            'conversation_id': self.conversation_id,
            'user_id': self.user_id,
            'task_arn': self.task_arn,
            'task_ip': self.task_ip,
            'status': self.status,
            'session_api_key': self.session_api_key,
            'agent_server_port': self.agent_server_port,
            'sandbox_spec_id': self.sandbox_spec_id,
            'last_activity_at': self.last_activity_at,
            'created_at': self.created_at,
        }


class DynamoDBStore:
    """DynamoDB operations for sandbox registry."""

    def __init__(self, table_name: str, region: Optional[str] = None):
        self._table_name = table_name
        session = boto3.Session(region_name=region) if region else boto3.Session()
        self._dynamodb = session.resource('dynamodb')
        self._table = self._dynamodb.Table(table_name)

    def put_sandbox(self, record: SandboxRecord) -> None:
        """Create or update a sandbox record."""
        now = int(time.time())
        item = record.to_dict()
        if not item.get('created_at'):
            item['created_at'] = now
        item['last_activity_at'] = now
        item['ttl'] = now + TTL_SECONDS

        self._table.put_item(Item=item)
        logger.info('Put sandbox record: %s', record.conversation_id)

    def get_sandbox(self, conversation_id: str) -> Optional[SandboxRecord]:
        """Get a sandbox record by conversation_id."""
        try:
            response = self._table.get_item(
                Key={'conversation_id': conversation_id}
            )
            item = response.get('Item')
            if item:
                return SandboxRecord(item)
            return None
        except ClientError as e:
            logger.error('Failed to get sandbox %s: %s', conversation_id, e)
            return None

    def batch_get_sandboxes(self, conversation_ids: list[str]) -> list[SandboxRecord]:
        """Batch get sandbox records."""
        if not conversation_ids:
            return []

        records = []
        # DynamoDB batch_get_item limit is 100 keys
        for i in range(0, len(conversation_ids), 100):
            batch = conversation_ids[i:i + 100]
            request_items = {
                self._table_name: {
                    'Keys': [{'conversation_id': cid} for cid in batch]
                }
            }
            # Retry loop for UnprocessedKeys
            while request_items:
                response = self._dynamodb.batch_get_item(RequestItems=request_items)
                items = response.get('Responses', {}).get(self._table_name, [])
                records.extend(SandboxRecord(item) for item in items)
                request_items = response.get('UnprocessedKeys', {})

        return records

    def update_status(self, conversation_id: str, status: str,
                      task_ip: Optional[str] = None,
                      task_arn: Optional[str] = None) -> None:
        """Update sandbox status and optionally task IP/ARN."""
        now = int(time.time())
        update_expr = 'SET #status = :status, last_activity_at = :now, #ttl = :ttl'
        expr_values: dict = {
            ':status': status,
            ':now': now,
            ':ttl': now + TTL_SECONDS,
        }
        expr_names: dict = {
            '#status': 'status',
            '#ttl': 'ttl',
        }

        if task_ip is not None:
            update_expr += ', task_ip = :ip'
            expr_values[':ip'] = task_ip

        if task_arn is not None:
            update_expr += ', task_arn = :arn'
            expr_values[':arn'] = task_arn

        self._table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names,
        )
        logger.info('Updated sandbox %s status to %s', conversation_id, status)

    def update_activity(self, conversation_id: str) -> None:
        """Update last_activity_at timestamp (called on each proxied request)."""
        now = int(time.time())
        self._table.update_item(
            Key={'conversation_id': conversation_id},
            UpdateExpression='SET last_activity_at = :now, #ttl = :ttl',
            ExpressionAttributeValues={
                ':now': now,
                ':ttl': now + TTL_SECONDS,
            },
            ExpressionAttributeNames={'#ttl': 'ttl'},
        )

    def query_by_status(self, status: str) -> list[SandboxRecord]:
        """Query sandboxes by status (via status GSI)."""
        response = self._table.query(
            IndexName='status-index',
            KeyConditionExpression='#status = :s',
            ExpressionAttributeValues={':s': status},
            ExpressionAttributeNames={'#status': 'status'},
        )
        return [SandboxRecord(item) for item in response.get('Items', [])]

    def list_running(self) -> list[SandboxRecord]:
        """List all running sandboxes (via status GSI)."""
        response = self._table.query(
            IndexName='status-index',
            KeyConditionExpression='#status = :running',
            ExpressionAttributeValues={':running': 'RUNNING'},
            ExpressionAttributeNames={'#status': 'status'},
        )
        return [SandboxRecord(item) for item in response.get('Items', [])]

    def list_by_user(self, user_id: str) -> list[SandboxRecord]:
        """List sandboxes for a specific user (via user_id GSI)."""
        response = self._table.query(
            IndexName='user_id-index',
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id},
        )
        return [SandboxRecord(item) for item in response.get('Items', [])]

    def query_idle(self, idle_before: int) -> list[SandboxRecord]:
        """Query running sandboxes that have been idle since before the given timestamp."""
        response = self._table.query(
            IndexName='status-index',
            KeyConditionExpression='#status = :running AND last_activity_at < :cutoff',
            ExpressionAttributeValues={
                ':running': 'RUNNING',
                ':cutoff': idle_before,
            },
            ExpressionAttributeNames={'#status': 'status'},
        )
        # Note: DynamoDB supports <, >, <=, >=, BETWEEN, begins_with on sort keys
        # in KeyConditionExpression. This is valid since last_activity_at is the sort key.
        return [SandboxRecord(item) for item in response.get('Items', [])]
