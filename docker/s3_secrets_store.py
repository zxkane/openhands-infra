"""
User-scoped secrets storage for multi-tenancy (V1 OpenHands).

This module provides a SecretsStore implementation that stores secrets
under user-specific paths in S3: users/{user_id}/secrets.json

Without this, all users would share a global secrets.json file at the
bucket root, which is a CRITICAL SECURITY VULNERABILITY.

Path Format:
- Authenticated users: users/{user_id}/secrets.json
- Anonymous users: NOT SUPPORTED (raises ValueError)

V1 NOTES (PR #81 / OpenHands v1.7.0):
- Imports moved from openhands.storage.* to openhands.app_server.* —
  upstream deleted the V0 storage subpackages in 1.7.0.
- get_file_store no longer accepts file_store_web_hook_* args.
- Secrets model moved to openhands.app_server.secrets.secrets_models.
- The V0 helper methods (get_secret / set_secret / delete_secret /
  list_secrets) are dropped — they were not part of the SecretsStore
  ABC and had no callers in the upstream V1 codebase.
"""

import json
import logging
from dataclasses import dataclass

from openhands.app_server.file_store import get_file_store
from openhands.app_server.file_store.files import FileStore
from openhands.app_server.secrets.secrets_models import Secrets
from openhands.app_server.secrets.secrets_store import SecretsStore
from openhands.app_server.utils.async_utils import call_sync_from_async
from openhands.core.config.openhands_config import OpenHandsConfig

logger = logging.getLogger(__name__)


@dataclass
class CognitoS3SecretsStore(SecretsStore):
    """Secrets store with user-scoped paths for multi-tenancy.

    When a user_id is provided, secrets are stored under:
        users/{user_id}/secrets.json

    Anonymous users are NOT supported - this store requires authentication.

    Attributes:
        file_store: The underlying file store (S3, local, etc.)
        user_id: The authenticated user's ID (Cognito sub)
    """

    file_store: FileStore
    user_id: str

    def _get_path(self) -> str:
        return f'users/{self.user_id}/secrets.json'

    async def load(self) -> Secrets | None:
        path = self._get_path()
        try:
            json_str = await call_sync_from_async(self.file_store.read, path)
            data = json.loads(json_str)
            # Mirror upstream FileSecretsStore: filter out provider_tokens
            # entries with no token (left behind after rotation/revoke).
            provider_tokens = {
                k: v
                for k, v in (data.get('provider_tokens') or {}).items()
                if v.get('token')
            }
            data['provider_tokens'] = provider_tokens
            secrets = Secrets(**data)
            logger.info(f"CognitoS3SecretsStore: Loaded secrets for user {self.user_id}")
            return secrets
        except FileNotFoundError:
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"CognitoS3SecretsStore: Invalid JSON in {path}: {e}")
            return None
        except Exception as e:
            logger.warning(f"CognitoS3SecretsStore: Failed to load {path}: {e}")
            return None

    async def store(self, secrets: Secrets) -> None:
        path = self._get_path()
        try:
            json_str = secrets.model_dump_json(context={'expose_secrets': True})
            await call_sync_from_async(self.file_store.write, path, json_str)
            logger.info(f"CognitoS3SecretsStore: Stored secrets for user {self.user_id}")
        except Exception as e:
            logger.error(f"CognitoS3SecretsStore: Failed to store {path}: {e}")
            raise

    @classmethod
    async def get_instance(
        cls, config: OpenHandsConfig, user_id: str | None
    ) -> 'CognitoS3SecretsStore':
        if not user_id:
            raise ValueError(
                'user_id is required for multi-tenant secrets. '
                'Anonymous users are not supported in this deployment.'
            )

        file_store = get_file_store(
            file_store_type=config.file_store,
            file_store_path=config.file_store_path,
        )

        return cls(file_store=file_store, user_id=user_id)
