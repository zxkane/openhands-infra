"""
User-scoped settings storage for multi-tenancy (V1 OpenHands).

This module provides a SettingsStore implementation that stores settings
under user-specific paths in S3: users/{user_id}/settings.json

This enables per-user settings isolation when using Cognito authentication.
Without this, all users would share a global settings.json file at the
bucket root, which is a critical security vulnerability.

Path Format:
- Authenticated users: users/{user_id}/settings.json
- Anonymous users: NOT SUPPORTED (raises ValueError)

V1 NOTES (PR #81 / OpenHands v1.7.0):
- Imports moved from openhands.storage.* to openhands.app_server.* —
  upstream deleted the V0 storage subpackages in 1.7.0.
- get_file_store no longer accepts file_store_web_hook_* args; webhook
  support was removed alongside the V0 collapse.
- Settings model moved to openhands.app_server.settings.settings_models.
"""

import json
import logging
from dataclasses import dataclass

from openhands.app_server.file_store import get_file_store
from openhands.app_server.file_store.files import FileStore
from openhands.app_server.settings.settings_models import Settings
from openhands.app_server.settings.settings_store import SettingsStore
from openhands.app_server.utils.async_utils import call_sync_from_async
from openhands.core.config.openhands_config import OpenHandsConfig

logger = logging.getLogger(__name__)


@dataclass
class CognitoS3SettingsStore(SettingsStore):
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
        return f'users/{self.user_id}/settings.json'

    async def load(self) -> Settings | None:
        path = self._get_path()
        try:
            json_str = await call_sync_from_async(self.file_store.read, path)
            kwargs = json.loads(json_str)
            settings = Settings(**kwargs)
            # Ensure v1 is enabled — preserved from V0; harmless on v1.7.0
            # but defensive against settings files written by v1.6.0.
            settings.v1_enabled = True
            logger.info(f"CognitoS3SettingsStore: Loaded settings for user {self.user_id}")
            return settings
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"CognitoS3SettingsStore: Invalid JSON in {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"CognitoS3SettingsStore: Failed to load {path}: {e}")
            return None

    async def store(self, settings: Settings) -> None:
        path = self._get_path()
        try:
            json_str = settings.model_dump_json(
                context={'expose_secrets': True, 'persist_settings': True}
            )
            await call_sync_from_async(self.file_store.write, path, json_str)
            logger.info(f"CognitoS3SettingsStore: Stored settings for user {self.user_id}")
        except Exception as e:
            logger.error(f"CognitoS3SettingsStore: Failed to store {path}: {e}")
            raise

    @classmethod
    async def get_instance(
        cls, config: OpenHandsConfig, user_id: str | None
    ) -> 'CognitoS3SettingsStore':
        if not user_id:
            raise ValueError(
                'user_id is required for multi-tenant settings. '
                'Anonymous users are not supported in this deployment.'
            )

        file_store = get_file_store(
            file_store_type=config.file_store,
            file_store_path=config.file_store_path,
        )

        return cls(file_store=file_store, user_id=user_id)
