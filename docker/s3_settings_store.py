"""
User-scoped settings storage for multi-tenancy.

This module provides a SettingsStore implementation that stores settings
under user-specific paths in S3: users/{user_id}/settings.json

This enables per-user settings isolation when using Cognito authentication.
Without this, all users would share a global settings.json file at the bucket root,
which is a critical security vulnerability.

Path Format:
- Authenticated users: users/{user_id}/settings.json
- Anonymous users: NOT SUPPORTED (raises ValueError)

Design Decisions:
- No anonymous users: System requires login, all users must have user_id
- No global settings file: User settings stored only in user-scoped paths
- Global config: Provided via config.toml (LLM model, etc.), not settings.json
"""

import json
import logging
from dataclasses import dataclass

from openhands.core.config.openhands_config import OpenHandsConfig
from openhands.storage import get_file_store
from openhands.storage.data_models.settings import Settings
from openhands.storage.files import FileStore
from openhands.storage.settings.settings_store import SettingsStore
from openhands.utils.async_utils import call_sync_from_async

logger = logging.getLogger(__name__)


@dataclass
class S3SettingsStore(SettingsStore):
    """Settings store with user-scoped paths for multi-tenancy.

    When a user_id is provided, settings are stored under:
        users/{user_id}/settings.json

    Anonymous users are NOT supported - this store requires authentication.

    Attributes:
        file_store: The underlying file store (S3, local, etc.)
        user_id: The authenticated user's ID (Cognito sub)
    """

    file_store: FileStore
    user_id: str

    def _get_path(self) -> str:
        """Get the user-specific settings path.

        Returns:
            Path in format: users/{user_id}/settings.json
        """
        return f'users/{self.user_id}/settings.json'

    async def load(self) -> Settings | None:
        """Load settings from the user-specific path.

        Returns:
            Settings object if found, None if not found.
        """
        path = self._get_path()
        logger.debug(f"S3SettingsStore.load: Loading settings from {path}")
        try:
            json_str = await call_sync_from_async(self.file_store.read, path)
            kwargs = json.loads(json_str)
            settings = Settings(**kwargs)
            # Ensure v1 is enabled (required for V1 app server)
            settings.v1_enabled = True
            logger.info(f"S3SettingsStore: Loaded settings for user {self.user_id}")
            return settings
        except FileNotFoundError:
            logger.debug(f"S3SettingsStore: No settings found at {path}")
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"S3SettingsStore: Invalid JSON in settings file {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"S3SettingsStore: Failed to load settings from {path}: {e}")
            return None

    async def store(self, settings: Settings) -> None:
        """Store settings to the user-specific path.

        Args:
            settings: The Settings object to store.
        """
        path = self._get_path()
        logger.debug(f"S3SettingsStore.store: Storing settings to {path}")
        try:
            json_str = settings.model_dump_json(context={'expose_secrets': True})
            await call_sync_from_async(self.file_store.write, path, json_str)
            logger.info(f"S3SettingsStore: Stored settings for user {self.user_id}")
        except Exception as e:
            logger.error(f"S3SettingsStore: Failed to store settings to {path}: {e}")
            raise

    @classmethod
    async def get_instance(
        cls, config: OpenHandsConfig, user_id: str | None
    ) -> 'S3SettingsStore':
        """Create a settings store instance for the given user.

        Args:
            config: OpenHands configuration.
            user_id: The authenticated user's ID (Cognito sub).

        Returns:
            An S3SettingsStore instance configured for the user.

        Raises:
            ValueError: If user_id is None or empty (anonymous users not supported).
        """
        if not user_id:
            raise ValueError(
                'user_id is required for multi-tenant settings. '
                'Anonymous users are not supported in this deployment.'
            )

        logger.info(f"S3SettingsStore.get_instance: Creating store for user {user_id}")

        file_store = get_file_store(
            file_store_type=config.file_store,
            file_store_path=config.file_store_path,
            file_store_web_hook_url=config.file_store_web_hook_url,
            file_store_web_hook_headers=config.file_store_web_hook_headers,
            file_store_web_hook_batch=config.file_store_web_hook_batch,
        )

        return cls(file_store=file_store, user_id=user_id)
