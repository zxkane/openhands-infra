"""
User-scoped secrets storage for multi-tenancy.

This module provides a SecretsStore implementation that stores secrets
under user-specific paths in S3: users/{user_id}/secrets.json

This enables per-user secrets isolation when using Cognito authentication.
Without this, all users would share a global secrets.json file at the bucket root,
which is a CRITICAL SECURITY VULNERABILITY.

Path Format:
- Authenticated users: users/{user_id}/secrets.json
- Anonymous users: NOT SUPPORTED (raises ValueError)

Design Decisions:
- No anonymous users: System requires login, all users must have user_id
- No global secrets file: User secrets stored only in user-scoped paths
- Secrets structure follows OpenHands format: {"custom_secrets": {...}}
"""

import json
import logging
from dataclasses import dataclass

from openhands.core.config.openhands_config import OpenHandsConfig
from openhands.storage import get_file_store
from openhands.storage.files import FileStore
from openhands.storage.secrets.secrets_store import SecretsStore
from openhands.utils.async_utils import call_sync_from_async

logger = logging.getLogger(__name__)


@dataclass
class S3SecretsStore(SecretsStore):
    """Secrets store with user-scoped paths for multi-tenancy.

    When a user_id is provided, secrets are stored under:
        users/{user_id}/secrets.json

    Anonymous users are NOT supported - this store requires authentication.

    Secrets Format (OpenHands standard):
    {
        "custom_secrets": {
            "SECRET_NAME": {
                "secret": "secret_value",
                "description": "optional description"
            }
        }
    }

    Attributes:
        file_store: The underlying file store (S3, local, etc.)
        user_id: The authenticated user's ID (Cognito sub)
    """

    file_store: FileStore
    user_id: str

    def _get_path(self) -> str:
        """Get the user-specific secrets path.

        Returns:
            Path in format: users/{user_id}/secrets.json
        """
        return f'users/{self.user_id}/secrets.json'

    async def load(self) -> dict | None:
        """Load secrets from the user-specific path.

        Returns:
            Dict containing secrets if found, None if not found.
            Format: {"custom_secrets": {...}}
        """
        path = self._get_path()
        logger.debug(f"S3SecretsStore.load: Loading secrets from {path}")
        try:
            json_str = await call_sync_from_async(self.file_store.read, path)
            data = json.loads(json_str)
            logger.info(f"S3SecretsStore: Loaded secrets for user {self.user_id}")
            return data
        except FileNotFoundError:
            logger.debug(f"S3SecretsStore: No secrets found at {path}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"S3SecretsStore: Invalid JSON in secrets file {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"S3SecretsStore: Failed to load secrets from {path}: {e}")
            return None

    async def store(self, data: dict) -> None:
        """Store secrets to the user-specific path.

        Args:
            data: Dict containing secrets in OpenHands format.
        """
        path = self._get_path()
        logger.debug(f"S3SecretsStore.store: Storing secrets to {path}")
        try:
            json_str = json.dumps(data)
            await call_sync_from_async(self.file_store.write, path, json_str)
            logger.info(f"S3SecretsStore: Stored secrets for user {self.user_id}")
        except Exception as e:
            logger.error(f"S3SecretsStore: Failed to store secrets to {path}: {e}")
            raise

    async def get_secret(self, name: str) -> str | None:
        """Get a specific secret by name.

        Args:
            name: The name of the secret.

        Returns:
            The secret value if found, None otherwise.
        """
        data = await self.load()
        if data is None:
            return None

        custom_secrets = data.get('custom_secrets', {})
        secret_entry = custom_secrets.get(name)

        if secret_entry is None:
            return None

        # Handle both dict format {"secret": "value"} and direct string value
        if isinstance(secret_entry, dict):
            return secret_entry.get('secret')
        return secret_entry

    async def set_secret(self, name: str, value: str, description: str | None = None) -> None:
        """Set a specific secret.

        Args:
            name: The name of the secret.
            value: The secret value.
            description: Optional description of the secret.
        """
        data = await self.load() or {'custom_secrets': {}}
        custom_secrets = data.setdefault('custom_secrets', {})

        secret_entry = {'secret': value}
        if description:
            secret_entry['description'] = description

        custom_secrets[name] = secret_entry
        await self.store(data)

    async def delete_secret(self, name: str) -> bool:
        """Delete a specific secret.

        Args:
            name: The name of the secret to delete.

        Returns:
            True if the secret was deleted, False if it didn't exist.
        """
        data = await self.load()
        if data is None:
            return False

        custom_secrets = data.get('custom_secrets', {})
        if name not in custom_secrets:
            return False

        del custom_secrets[name]
        await self.store(data)
        return True

    async def list_secrets(self) -> list[str]:
        """List all secret names.

        Returns:
            List of secret names (values are not exposed).
        """
        data = await self.load()
        if data is None:
            return []

        custom_secrets = data.get('custom_secrets', {})
        return list(custom_secrets.keys())

    @classmethod
    async def get_instance(
        cls, config: OpenHandsConfig, user_id: str | None
    ) -> 'S3SecretsStore':
        """Create a secrets store instance for the given user.

        Args:
            config: OpenHands configuration.
            user_id: The authenticated user's ID (Cognito sub).

        Returns:
            An S3SecretsStore instance configured for the user.

        Raises:
            ValueError: If user_id is None or empty (anonymous users not supported).
        """
        if not user_id:
            raise ValueError(
                'user_id is required for multi-tenant secrets. '
                'Anonymous users are not supported in this deployment.'
            )

        logger.info(f"S3SecretsStore.get_instance: Creating store for user {user_id}")

        file_store = get_file_store(
            file_store_type=config.file_store,
            file_store_path=config.file_store_path,
            file_store_web_hook_url=config.file_store_web_hook_url,
            file_store_web_hook_headers=config.file_store_web_hook_headers,
            file_store_web_hook_batch=config.file_store_web_hook_batch,
        )

        return cls(file_store=file_store, user_id=user_id)
