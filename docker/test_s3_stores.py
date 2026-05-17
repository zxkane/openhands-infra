"""
Unit tests for CognitoS3SettingsStore and CognitoS3SecretsStore.

These tests verify the user-scoped storage functionality including:
- User-specific path generation (users/{user_id}/settings.json, users/{user_id}/secrets.json)
- Load and store operations with mocked file_store
- User isolation (different users have different paths)
- Error handling (user_id required, file not found)

Note: Tests mock file_store to avoid actual S3 calls.

Run with: pytest docker/test_s3_stores.py -v
"""

import json
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import sys
from dataclasses import dataclass


# Mock OpenHands modules before importing the modules under test.
# v1.7.0 dropped the file_store_web_hook_* fields from OpenHandsConfig (and the
# matching kwargs from get_file_store), so they're not part of the mock.
@dataclass
class MockOpenHandsConfig:
    """Mock OpenHands configuration."""
    file_store: str = 's3'
    file_store_path: str = 'test-bucket'


@dataclass
class MockSettings:
    """Mock Settings class from OpenHands."""
    llm_model: str = 'test-model'
    language: str = 'en'
    v1_enabled: bool = True

    def model_dump_json(self, context=None):
        return json.dumps({
            'llm_model': self.llm_model,
            'language': self.language,
            'v1_enabled': self.v1_enabled
        })


class MockSecretValue:
    """Mock SecretStr-like class."""
    def __init__(self, value: str):
        self._value = value

    def get_secret_value(self):
        return self._value


class MockCustomSecret:
    """Mock CustomSecret class."""
    def __init__(self, secret: str, description: str = ''):
        self.secret = MockSecretValue(secret)
        self.description = description


class MockSecrets:
    """Mock Secrets Pydantic model."""
    def __init__(self, custom_secrets=None, provider_tokens=None):
        # Convert dict to MockCustomSecret objects
        self._custom_secrets = {}
        if custom_secrets:
            for name, value in custom_secrets.items():
                if isinstance(value, dict):
                    self._custom_secrets[name] = MockCustomSecret(
                        secret=value.get('secret', ''),
                        description=value.get('description', '')
                    )
                else:
                    self._custom_secrets[name] = value

    @property
    def custom_secrets(self):
        return self._custom_secrets

    def model_dump_json(self, context=None):
        result = {'custom_secrets': {}, 'provider_tokens': {}}
        for name, secret in self._custom_secrets.items():
            result['custom_secrets'][name] = {
                'secret': secret.secret.get_secret_value(),
                'description': secret.description
            }
        return json.dumps(result)


# Set up mock modules.
# v1.7.0 collapsed the V0 openhands.storage.* and openhands.utils.* surfaces
# into openhands.app_server.{settings,secrets,file_store,utils}.* — mocks
# follow.
sys.modules['openhands'] = MagicMock()
sys.modules['openhands.core'] = MagicMock()
sys.modules['openhands.core.config'] = MagicMock()
sys.modules['openhands.core.config.openhands_config'] = MagicMock()
sys.modules['openhands.core.config.openhands_config'].OpenHandsConfig = MockOpenHandsConfig
sys.modules['openhands.app_server'] = MagicMock()
sys.modules['openhands.app_server.file_store'] = MagicMock()
sys.modules['openhands.app_server.file_store.files'] = MagicMock()
sys.modules['openhands.app_server.settings'] = MagicMock()
sys.modules['openhands.app_server.settings.settings_models'] = MagicMock()
sys.modules['openhands.app_server.settings.settings_models'].Settings = MockSettings
sys.modules['openhands.app_server.settings.settings_store'] = MagicMock()
sys.modules['openhands.app_server.secrets'] = MagicMock()
sys.modules['openhands.app_server.secrets.secrets_models'] = MagicMock()
sys.modules['openhands.app_server.secrets.secrets_models'].Secrets = MockSecrets
sys.modules['openhands.app_server.secrets.secrets_store'] = MagicMock()
sys.modules['openhands.app_server.utils'] = MagicMock()
sys.modules['openhands.app_server.utils.async_utils'] = MagicMock()

# Create mock base classes
class MockSettingsStore:
    """Mock base SettingsStore class."""
    pass


class MockSecretsStore:
    """Mock base SecretsStore class."""
    pass


sys.modules['openhands.app_server.settings.settings_store'].SettingsStore = MockSettingsStore
sys.modules['openhands.app_server.secrets.secrets_store'].SecretsStore = MockSecretsStore


# Now import the modules under test (renamed in v1.7.0:
# CognitoS3SettingsStore -> CognitoS3SettingsStore, CognitoS3SecretsStore -> CognitoS3SecretsStore)
from s3_settings_store import CognitoS3SettingsStore
from s3_secrets_store import CognitoS3SecretsStore


class TestCognitoS3SettingsStorePathGeneration:
    """Tests for CognitoS3SettingsStore path generation."""

    def test_get_path_returns_user_scoped_path(self):
        """Should return users/{user_id}/settings.json."""
        store = CognitoS3SettingsStore(file_store=MagicMock(), user_id="user-123")
        assert store._get_path() == "users/user-123/settings.json"

    def test_different_users_have_different_paths(self):
        """Different user_ids should produce different paths."""
        store_a = CognitoS3SettingsStore(file_store=MagicMock(), user_id="user-aaa")
        store_b = CognitoS3SettingsStore(file_store=MagicMock(), user_id="user-bbb")
        assert store_a._get_path() != store_b._get_path()
        assert "user-aaa" in store_a._get_path()
        assert "user-bbb" in store_b._get_path()

    def test_path_format_matches_conversation_store_pattern(self):
        """Path should follow same pattern as CognitoFileConversationStore."""
        store = CognitoS3SettingsStore(file_store=MagicMock(), user_id="cognito-sub-uuid")
        path = store._get_path()
        # Should be: users/{user_id}/settings.json
        assert path.startswith("users/")
        assert path.endswith("/settings.json")
        assert "cognito-sub-uuid" in path

    def test_path_with_complex_user_id(self):
        """Should handle complex user IDs (UUID format from Cognito)."""
        user_id = "abc12345-def6-7890-ghij-klmnopqrstuv"
        store = CognitoS3SettingsStore(file_store=MagicMock(), user_id=user_id)
        path = store._get_path()
        assert path == f"users/{user_id}/settings.json"


class TestCognitoS3SettingsStoreGetInstance:
    """Tests for CognitoS3SettingsStore.get_instance class method."""

    @pytest.mark.asyncio
    async def test_get_instance_requires_user_id(self):
        """Should raise ValueError when user_id is None."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError, match="user_id is required"):
            await CognitoS3SettingsStore.get_instance(mock_config, None)

    @pytest.mark.asyncio
    async def test_get_instance_requires_user_id_empty_string(self):
        """Should raise ValueError when user_id is empty string."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError, match="user_id is required"):
            await CognitoS3SettingsStore.get_instance(mock_config, "")

    @pytest.mark.asyncio
    @patch('s3_settings_store.get_file_store')
    async def test_get_instance_creates_store_with_user_id(self, mock_get_file_store):
        """Should create store instance with correct user_id."""
        mock_file_store = MagicMock()
        mock_get_file_store.return_value = mock_file_store
        mock_config = MockOpenHandsConfig()

        store = await CognitoS3SettingsStore.get_instance(mock_config, "user-xyz")

        assert store.user_id == "user-xyz"
        assert store.file_store == mock_file_store

    @pytest.mark.asyncio
    @patch('s3_settings_store.get_file_store')
    async def test_get_instance_passes_config_to_file_store(self, mock_get_file_store):
        """Should pass config parameters to get_file_store."""
        mock_file_store = MagicMock()
        mock_get_file_store.return_value = mock_file_store
        mock_config = MockOpenHandsConfig(
            file_store='s3',
            file_store_path='my-bucket'
        )

        await CognitoS3SettingsStore.get_instance(mock_config, "user-xyz")

        mock_get_file_store.assert_called_once()
        call_kwargs = mock_get_file_store.call_args
        assert call_kwargs[1]['file_store_type'] == 's3'
        assert call_kwargs[1]['file_store_path'] == 'my-bucket'


class TestCognitoS3SettingsStoreLoad:
    """Tests for CognitoS3SettingsStore.load method."""

    @pytest.mark.asyncio
    @patch('s3_settings_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_reads_from_user_path(self, mock_call_sync):
        """Should read settings from users/{user_id}/settings.json."""
        mock_file_store = MagicMock()
        settings_data = {"llm_model": "gpt-4", "language": "en", "v1_enabled": True}
        mock_call_sync.return_value = json.dumps(settings_data)

        store = CognitoS3SettingsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        mock_call_sync.assert_called_once()
        call_args = mock_call_sync.call_args[0]
        assert call_args[1] == "users/user-123/settings.json"

    @pytest.mark.asyncio
    @patch('s3_settings_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_returns_none_when_file_not_found(self, mock_call_sync):
        """Should return None when settings file doesn't exist."""
        mock_file_store = MagicMock()
        mock_call_sync.side_effect = FileNotFoundError("Not found")

        store = CognitoS3SettingsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        assert result is None

    @pytest.mark.asyncio
    @patch('s3_settings_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_returns_none_on_invalid_json(self, mock_call_sync):
        """Should return None when settings file contains invalid JSON."""
        mock_file_store = MagicMock()
        mock_call_sync.return_value = "not valid json {"

        store = CognitoS3SettingsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        assert result is None


class TestCognitoS3SettingsStoreStore:
    """Tests for CognitoS3SettingsStore.store method."""

    @pytest.mark.asyncio
    @patch('s3_settings_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_store_writes_to_user_path(self, mock_call_sync):
        """Should write settings to users/{user_id}/settings.json."""
        mock_file_store = MagicMock()
        mock_settings = MockSettings()

        store = CognitoS3SettingsStore(file_store=mock_file_store, user_id="user-456")
        await store.store(mock_settings)

        mock_call_sync.assert_called_once()
        call_args = mock_call_sync.call_args[0]
        assert call_args[1] == "users/user-456/settings.json"


class TestCognitoS3SecretsStorePathGeneration:
    """Tests for CognitoS3SecretsStore path generation."""

    def test_get_path_returns_user_scoped_path(self):
        """Should return users/{user_id}/secrets.json."""
        store = CognitoS3SecretsStore(file_store=MagicMock(), user_id="user-789")
        assert store._get_path() == "users/user-789/secrets.json"

    def test_different_users_have_different_paths(self):
        """Different user_ids should produce different paths."""
        store_a = CognitoS3SecretsStore(file_store=MagicMock(), user_id="user-a")
        store_b = CognitoS3SecretsStore(file_store=MagicMock(), user_id="user-b")
        assert store_a._get_path() != store_b._get_path()

    def test_path_format_is_consistent(self):
        """Path should follow consistent format."""
        store = CognitoS3SecretsStore(file_store=MagicMock(), user_id="cognito-sub-uuid")
        path = store._get_path()
        assert path.startswith("users/")
        assert path.endswith("/secrets.json")
        assert "cognito-sub-uuid" in path


class TestCognitoS3SecretsStoreGetInstance:
    """Tests for CognitoS3SecretsStore.get_instance class method."""

    @pytest.mark.asyncio
    async def test_get_instance_requires_user_id(self):
        """Should raise ValueError when user_id is None."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError, match="user_id is required"):
            await CognitoS3SecretsStore.get_instance(mock_config, None)

    @pytest.mark.asyncio
    async def test_get_instance_requires_user_id_empty_string(self):
        """Should raise ValueError when user_id is empty string."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError, match="user_id is required"):
            await CognitoS3SecretsStore.get_instance(mock_config, "")

    @pytest.mark.asyncio
    @patch('s3_secrets_store.get_file_store')
    async def test_get_instance_creates_store_with_user_id(self, mock_get_file_store):
        """Should create store instance with correct user_id."""
        mock_file_store = MagicMock()
        mock_get_file_store.return_value = mock_file_store
        mock_config = MockOpenHandsConfig()

        store = await CognitoS3SecretsStore.get_instance(mock_config, "user-xyz")

        assert store.user_id == "user-xyz"
        assert store.file_store == mock_file_store


class TestCognitoS3SecretsStoreLoad:
    """Tests for CognitoS3SecretsStore.load method."""

    @pytest.mark.asyncio
    @patch('s3_secrets_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_reads_from_user_path(self, mock_call_sync):
        """Should read secrets from users/{user_id}/secrets.json."""
        mock_file_store = MagicMock()
        secrets_data = {"custom_secrets": {"api_key": {"secret": "xxx"}}}
        mock_call_sync.return_value = json.dumps(secrets_data)

        store = CognitoS3SecretsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        mock_call_sync.assert_called_once()
        call_args = mock_call_sync.call_args[0]
        assert call_args[1] == "users/user-123/secrets.json"

    @pytest.mark.asyncio
    @patch('s3_secrets_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_returns_none_when_file_not_found(self, mock_call_sync):
        """Should return None when secrets file doesn't exist."""
        mock_file_store = MagicMock()
        mock_call_sync.side_effect = FileNotFoundError("Not found")

        store = CognitoS3SecretsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        assert result is None

    @pytest.mark.asyncio
    @patch('s3_secrets_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_load_returns_none_on_invalid_json(self, mock_call_sync):
        """Should return None when secrets file contains invalid JSON."""
        mock_file_store = MagicMock()
        mock_call_sync.return_value = "invalid json"

        store = CognitoS3SecretsStore(file_store=mock_file_store, user_id="user-123")
        result = await store.load()

        assert result is None


class TestCognitoS3SecretsStoreStore:
    """Tests for CognitoS3SecretsStore.store method."""

    @pytest.mark.asyncio
    @patch('s3_secrets_store.call_sync_from_async', new_callable=AsyncMock)
    async def test_store_writes_to_user_path(self, mock_call_sync):
        """Should write secrets to users/{user_id}/secrets.json."""
        mock_file_store = MagicMock()
        # Create a MockSecrets object instead of dict
        mock_secrets = MockSecrets(custom_secrets={"my_key": {"secret": "value", "description": ""}})

        store = CognitoS3SecretsStore(file_store=mock_file_store, user_id="user-456")
        await store.store(mock_secrets)

        mock_call_sync.assert_called_once()
        call_args = mock_call_sync.call_args[0]
        assert call_args[1] == "users/user-456/secrets.json"


# V0 helper methods (get_secret / set_secret / delete_secret / list_secrets)
# were dropped in v1.7.0 along with the V0 storage package collapse — they were
# never part of the SecretsStore ABC and had no callers. Their tests went with
# them. The load/store path coverage above is sufficient.


class TestUserIsolation:
    """Tests verifying user isolation between different users."""

    def test_user_a_cannot_access_user_b_settings_path(self):
        """User A's path should never include User B's user_id."""
        user_a_id = "user-a-cognito-sub"
        user_b_id = "user-b-cognito-sub"

        store_a = CognitoS3SettingsStore(file_store=MagicMock(), user_id=user_a_id)
        store_b = CognitoS3SettingsStore(file_store=MagicMock(), user_id=user_b_id)

        assert user_a_id in store_a._get_path()
        assert user_b_id not in store_a._get_path()
        assert user_b_id in store_b._get_path()
        assert user_a_id not in store_b._get_path()

    def test_user_a_cannot_access_user_b_secrets_path(self):
        """User A's secrets path should never include User B's user_id."""
        user_a_id = "user-a-cognito-sub"
        user_b_id = "user-b-cognito-sub"

        store_a = CognitoS3SecretsStore(file_store=MagicMock(), user_id=user_a_id)
        store_b = CognitoS3SecretsStore(file_store=MagicMock(), user_id=user_b_id)

        assert user_a_id in store_a._get_path()
        assert user_b_id not in store_a._get_path()
        assert user_b_id in store_b._get_path()
        assert user_a_id not in store_b._get_path()

    def test_settings_and_secrets_paths_are_isolated(self):
        """Settings and secrets should have different but consistent paths."""
        user_id = "test-user-123"

        settings_store = CognitoS3SettingsStore(file_store=MagicMock(), user_id=user_id)
        secrets_store = CognitoS3SecretsStore(file_store=MagicMock(), user_id=user_id)

        settings_path = settings_store._get_path()
        secrets_path = secrets_store._get_path()

        # Both should contain user_id
        assert user_id in settings_path
        assert user_id in secrets_path

        # But they should be different files
        assert settings_path != secrets_path
        assert settings_path.endswith("settings.json")
        assert secrets_path.endswith("secrets.json")


class TestPathConsistencyWithConversationStore:
    """Tests ensuring path consistency with CognitoFileConversationStore."""

    def test_settings_path_uses_same_user_prefix(self):
        """Settings path should use same 'users/{user_id}/' prefix as conversations."""
        user_id = "cognito-abc-123"
        store = CognitoS3SettingsStore(file_store=MagicMock(), user_id=user_id)
        path = store._get_path()

        # Should match pattern: users/{user_id}/settings.json
        assert path == f"users/{user_id}/settings.json"

    def test_secrets_path_uses_same_user_prefix(self):
        """Secrets path should use same 'users/{user_id}/' prefix as conversations."""
        user_id = "cognito-abc-123"
        store = CognitoS3SecretsStore(file_store=MagicMock(), user_id=user_id)
        path = store._get_path()

        # Should match pattern: users/{user_id}/secrets.json
        assert path == f"users/{user_id}/secrets.json"


class TestErrorMessages:
    """Tests for clear error messages."""

    @pytest.mark.asyncio
    async def test_settings_store_error_message_is_descriptive(self):
        """Error message should explain why user_id is required."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError) as exc_info:
            await CognitoS3SettingsStore.get_instance(mock_config, None)

        error_msg = str(exc_info.value)
        assert "user_id is required" in error_msg
        assert "multi-tenant" in error_msg

    @pytest.mark.asyncio
    async def test_secrets_store_error_message_is_descriptive(self):
        """Error message should explain why user_id is required."""
        mock_config = MockOpenHandsConfig()
        with pytest.raises(ValueError) as exc_info:
            await CognitoS3SecretsStore.get_instance(mock_config, None)

        error_msg = str(exc_info.value)
        assert "user_id is required" in error_msg
        assert "multi-tenant" in error_msg


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
