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
- Secrets structure follows OpenHands Secrets Pydantic model
"""

import json
import logging
from dataclasses import dataclass

from openhands.core.config.openhands_config import OpenHandsConfig
from openhands.storage import get_file_store
from openhands.storage.data_models.secrets import Secrets
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

    async def load(self) -> Secrets | None:
        """Load secrets from the user-specific path.

        Returns:
            Secrets object if found, None if not found.
        """
        path = self._get_path()
        logger.debug(f"S3SecretsStore.load: Loading secrets from {path}")
        try:
            json_str = await call_sync_from_async(self.file_store.read, path)
            data = json.loads(json_str)
            # Create Secrets model from the loaded data
            secrets = Secrets(**data)
            logger.info(f"S3SecretsStore: Loaded secrets for user {self.user_id}")
            return secrets
        except FileNotFoundError:
            logger.debug(f"S3SecretsStore: No secrets found at {path}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"S3SecretsStore: Invalid JSON in secrets file {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"S3SecretsStore: Failed to load secrets from {path}: {e}")
            return None

    async def store(self, secrets: Secrets) -> None:
        """Store secrets to the user-specific path.

        Args:
            secrets: Secrets Pydantic model to store.
        """
        path = self._get_path()
        logger.debug(f"S3SecretsStore.store: Storing secrets to {path}")
        try:
            # Use Pydantic's model_dump_json with expose_secrets context
            json_str = secrets.model_dump_json(context={'expose_secrets': True})
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
        secrets = await self.load()
        if secrets is None:
            return None

        custom_secret = secrets.custom_secrets.get(name)
        if custom_secret is None:
            return None

        return custom_secret.secret.get_secret_value()

    async def set_secret(self, name: str, value: str, description: str | None = None) -> None:
        """Set a specific secret.

        Args:
            name: The name of the secret.
            value: The secret value.
            description: Optional description of the secret.
        """
        secrets = await self.load()

        # Get current custom_secrets as dict
        current_secrets = {}
        if secrets is not None:
            # Export current secrets to dict
            for secret_name, secret_value in secrets.custom_secrets.items():
                current_secrets[secret_name] = {
                    'secret': secret_value.secret.get_secret_value(),
                    'description': secret_value.description,
                }

        # Add/update the new secret
        secret_entry = {'secret': value, 'description': description or ''}
        current_secrets[name] = secret_entry

        # Create new Secrets model
        new_secrets = Secrets(custom_secrets=current_secrets)
        await self.store(new_secrets)

    async def delete_secret(self, name: str) -> bool:
        """Delete a specific secret.

        Args:
            name: The name of the secret to delete.

        Returns:
            True if the secret was deleted, False if it didn't exist.
        """
        secrets = await self.load()
        if secrets is None:
            return False

        if name not in secrets.custom_secrets:
            return False

        # Get current custom_secrets as dict, excluding the one to delete
        current_secrets = {}
        for secret_name, secret_value in secrets.custom_secrets.items():
            if secret_name != name:
                current_secrets[secret_name] = {
                    'secret': secret_value.secret.get_secret_value(),
                    'description': secret_value.description,
                }

        # Create new Secrets model without the deleted secret
        new_secrets = Secrets(custom_secrets=current_secrets)
        await self.store(new_secrets)
        return True

    async def list_secrets(self) -> list[str]:
        """List all secret names.

        Returns:
            List of secret names (values are not exposed).
        """
        secrets = await self.load()
        if secrets is None:
            return []

        return list(secrets.custom_secrets.keys())

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
