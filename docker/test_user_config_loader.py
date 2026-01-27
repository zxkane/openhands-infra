"""
Unit tests for UserConfigLoader module.

These tests verify the user configuration loading functionality including:
- S3 configuration reading
- MCP config loading
- Integration config loading
- Secret reference resolution
- INTEGRATION_MCP_MAP structure

Note: Tests mock boto3 clients to avoid actual AWS calls.
"""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


class TestUserConfigLoaderInit:
    """Tests for UserConfigLoader initialization."""

    @patch('user_config_loader.boto3')
    def test_init_reads_bucket_from_aws_s3_bucket(self, mock_boto3):
        """Should use AWS_S3_BUCKET environment variable."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'
        os.environ.pop('FILE_STORE_PATH', None)
        os.environ.pop('USER_SECRETS_KMS_KEY_ID', None)

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            assert loader.bucket_name == 'test-bucket'
            assert loader.user_id == 'user-123'
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_init_reads_bucket_from_file_store_path(self, mock_boto3):
        """Should fall back to FILE_STORE_PATH if AWS_S3_BUCKET not set."""
        os.environ.pop('AWS_S3_BUCKET', None)
        os.environ['FILE_STORE_PATH'] = 'fallback-bucket'
        os.environ.pop('USER_SECRETS_KMS_KEY_ID', None)

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-456')

            assert loader.bucket_name == 'fallback-bucket'
        finally:
            del os.environ['FILE_STORE_PATH']

    @patch('user_config_loader.boto3')
    def test_init_creates_kms_client_when_key_configured(self, mock_boto3):
        """Should create KMS client when USER_SECRETS_KMS_KEY_ID is set."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'
        os.environ['USER_SECRETS_KMS_KEY_ID'] = 'alias/test-key'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-789')

            assert loader.kms_key_id == 'alias/test-key'
            mock_boto3.client.assert_any_call('kms', region_name='us-west-2')
        finally:
            del os.environ['AWS_S3_BUCKET']
            del os.environ['USER_SECRETS_KMS_KEY_ID']

    @patch('user_config_loader.boto3')
    def test_init_sets_correct_s3_paths(self, mock_boto3):
        """Should set config and secrets prefixes based on user_id."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'
        os.environ.pop('USER_SECRETS_KMS_KEY_ID', None)

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('test-user-123')

            assert loader.config_prefix == 'users/test-user-123/config'
            assert loader.secrets_prefix == 'users/test-user-123/secrets'
        finally:
            del os.environ['AWS_S3_BUCKET']


class TestUserConfigLoaderReadJson:
    """Tests for UserConfigLoader._read_json method."""

    @patch('user_config_loader.boto3')
    def test_read_json_returns_none_when_no_bucket(self, mock_boto3):
        """Should return None when bucket is not configured."""
        os.environ.pop('AWS_S3_BUCKET', None)
        os.environ.pop('FILE_STORE_PATH', None)

        from user_config_loader import UserConfigLoader
        loader = UserConfigLoader('user-123')

        result = loader._read_json('some/key')
        assert result is None

    @patch('user_config_loader.boto3')
    def test_read_json_returns_none_when_key_not_found(self, mock_boto3):
        """Should return None when S3 key doesn't exist."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_s3 = MagicMock()
            mock_s3.get_object.side_effect = ClientError(
                {'Error': {'Code': 'NoSuchKey', 'Message': 'Not found'}},
                'GetObject'
            )
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')
            loader.s3 = mock_s3

            result = loader._read_json('nonexistent/key')
            assert result is None
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_read_json_parses_json_content(self, mock_boto3):
        """Should parse and return JSON content from S3."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_body = MagicMock()
            mock_body.read.return_value = b'{"key": "value", "number": 42}'

            mock_s3 = MagicMock()
            mock_s3.get_object.return_value = {'Body': mock_body}
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')
            loader.s3 = mock_s3

            result = loader._read_json('test/key.json')

            assert result == {'key': 'value', 'number': 42}
            mock_s3.get_object.assert_called_once_with(Bucket='test-bucket', Key='test/key.json')
        finally:
            del os.environ['AWS_S3_BUCKET']


class TestUserConfigLoaderGetMcpConfig:
    """Tests for UserConfigLoader.get_mcp_config method."""

    @patch('user_config_loader.boto3')
    def test_get_mcp_config_reads_correct_s3_path(self, mock_boto3):
        """Should read from users/{user_id}/config/mcp-config.json."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_body = MagicMock()
            mock_body.read.return_value = b'{"version": "1.0", "shttp_servers": []}'

            mock_s3 = MagicMock()
            mock_s3.get_object.return_value = {'Body': mock_body}
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-abc')
            loader.s3 = mock_s3

            result = loader.get_mcp_config()

            mock_s3.get_object.assert_called_once_with(
                Bucket='test-bucket',
                Key='users/user-abc/config/mcp-config.json'
            )
            assert result == {'version': '1.0', 'shttp_servers': []}
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_get_mcp_config_returns_none_when_not_found(self, mock_boto3):
        """Should return None when MCP config doesn't exist."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_s3 = MagicMock()
            mock_s3.get_object.side_effect = ClientError(
                {'Error': {'Code': 'NoSuchKey', 'Message': 'Not found'}},
                'GetObject'
            )
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')
            loader.s3 = mock_s3

            result = loader.get_mcp_config()
            assert result is None
        finally:
            del os.environ['AWS_S3_BUCKET']


class TestUserConfigLoaderGetIntegrations:
    """Tests for UserConfigLoader.get_integrations method."""

    @patch('user_config_loader.boto3')
    def test_get_integrations_reads_correct_s3_path(self, mock_boto3):
        """Should read from users/{user_id}/config/integrations.json."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_body = MagicMock()
            mock_body.read.return_value = b'{"github": {"enabled": true}}'

            mock_s3 = MagicMock()
            mock_s3.get_object.return_value = {'Body': mock_body}
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-xyz')
            loader.s3 = mock_s3

            result = loader.get_integrations()

            mock_s3.get_object.assert_called_once_with(
                Bucket='test-bucket',
                Key='users/user-xyz/config/integrations.json'
            )
            assert result == {'github': {'enabled': True}}
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_get_integrations_returns_empty_dict_when_not_found(self, mock_boto3):
        """Should return empty dict when integrations file doesn't exist."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            mock_s3 = MagicMock()
            mock_s3.get_object.side_effect = ClientError(
                {'Error': {'Code': 'NoSuchKey', 'Message': 'Not found'}},
                'GetObject'
            )
            mock_boto3.client.return_value = mock_s3

            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')
            loader.s3 = mock_s3

            result = loader.get_integrations()
            assert result == {}
        finally:
            del os.environ['AWS_S3_BUCKET']


class TestUserConfigLoaderResolveSecretRefs:
    """Tests for UserConfigLoader.resolve_secret_refs method."""

    @patch('user_config_loader.boto3')
    def test_resolve_secret_refs_passes_through_non_secret_values(self, mock_boto3):
        """Should pass through values that don't start with 'secrets/'."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            env_vars = {
                'NORMAL_VAR': 'some-value',
                'API_URL': 'https://api.example.com',
                'PORT': '8080',
            }

            result = loader.resolve_secret_refs(env_vars)

            assert result == env_vars
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_resolve_secret_refs_removes_ref_suffix(self, mock_boto3):
        """Should remove _REF suffix when resolving secrets."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            # Mock get_secret to return a test value
            loader.get_secret = MagicMock(return_value='secret-value-123')

            env_vars = {
                'GITHUB_TOKEN_REF': 'secrets/github-token',
                'NORMAL_VAR': 'normal-value',
            }

            result = loader.resolve_secret_refs(env_vars)

            assert 'GITHUB_TOKEN_REF' not in result
            assert result['GITHUB_TOKEN'] == 'secret-value-123'
            assert result['NORMAL_VAR'] == 'normal-value'
            loader.get_secret.assert_called_once_with('github-token')
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_resolve_secret_refs_handles_missing_secrets(self, mock_boto3):
        """Should exclude secret refs when secret is not found."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            # Mock get_secret to return None (secret not found)
            loader.get_secret = MagicMock(return_value=None)

            env_vars = {
                'MISSING_SECRET_REF': 'secrets/nonexistent',
                'NORMAL_VAR': 'normal-value',
            }

            result = loader.resolve_secret_refs(env_vars)

            # Secret ref should not be in result
            assert 'MISSING_SECRET_REF' not in result
            assert 'MISSING_SECRET' not in result
            assert result['NORMAL_VAR'] == 'normal-value'
        finally:
            del os.environ['AWS_S3_BUCKET']

    @patch('user_config_loader.boto3')
    def test_resolve_secret_refs_handles_key_without_ref_suffix(self, mock_boto3):
        """Should work with keys that don't have _REF suffix."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            loader.get_secret = MagicMock(return_value='my-api-key')

            env_vars = {
                'API_KEY': 'secrets/api-key',  # No _REF suffix
            }

            result = loader.resolve_secret_refs(env_vars)

            # Key stays the same since it doesn't end with _REF
            assert result['API_KEY'] == 'my-api-key'
        finally:
            del os.environ['AWS_S3_BUCKET']


class TestIntegrationMcpMap:
    """Tests for INTEGRATION_MCP_MAP constant."""

    def test_github_integration_mapping(self):
        """Should have correct GitHub MCP mapping."""
        from user_config_loader import INTEGRATION_MCP_MAP

        assert 'github' in INTEGRATION_MCP_MAP
        github = INTEGRATION_MCP_MAP['github']

        assert github['name'] == 'github-mcp'
        assert github['command'] == 'npx'
        assert '-y' in github['args']
        assert '@modelcontextprotocol/server-github' in github['args']
        assert github['env_key'] == 'GITHUB_TOKEN'

    def test_slack_integration_mapping(self):
        """Should have correct Slack MCP mapping."""
        from user_config_loader import INTEGRATION_MCP_MAP

        assert 'slack' in INTEGRATION_MCP_MAP
        slack = INTEGRATION_MCP_MAP['slack']

        assert slack['name'] == 'slack-mcp'
        assert slack['command'] == 'npx'
        assert '-y' in slack['args']
        assert '@modelcontextprotocol/server-slack' in slack['args']
        assert slack['env_key'] == 'SLACK_BOT_TOKEN'

    def test_integration_map_has_required_keys(self):
        """All integrations should have required keys."""
        from user_config_loader import INTEGRATION_MCP_MAP

        required_keys = {'name', 'command', 'args', 'env_key'}

        for provider, config in INTEGRATION_MCP_MAP.items():
            for key in required_keys:
                assert key in config, f'{provider} missing required key: {key}'


class TestUserConfigLoaderGetSecret:
    """Tests for UserConfigLoader.get_secret method."""

    @patch('user_config_loader.boto3')
    def test_get_secret_returns_none_when_not_found(self, mock_boto3):
        """Should return None when secret doesn't exist."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'
        os.environ['USER_SECRETS_KMS_KEY_ID'] = 'alias/test-key'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            # Mock _get_secrets_data to return empty secrets
            loader._get_secrets_data = MagicMock(return_value={
                'version': '1.0',
                'secrets': {}
            })

            result = loader.get_secret('nonexistent-secret')
            assert result is None
        finally:
            del os.environ['AWS_S3_BUCKET']
            del os.environ['USER_SECRETS_KMS_KEY_ID']

    @patch('user_config_loader.boto3')
    def test_get_secret_returns_value_when_found(self, mock_boto3):
        """Should return secret value when it exists."""
        os.environ['AWS_S3_BUCKET'] = 'test-bucket'
        os.environ['USER_SECRETS_KMS_KEY_ID'] = 'alias/test-key'

        try:
            from user_config_loader import UserConfigLoader
            loader = UserConfigLoader('user-123')

            # Mock _get_secrets_data to return a secret
            loader._get_secrets_data = MagicMock(return_value={
                'version': '1.0',
                'secrets': {
                    'my-token': {
                        'type': 'api_key',
                        'value': 'super-secret-value',
                    }
                }
            })

            result = loader.get_secret('my-token')
            assert result == 'super-secret-value'
        finally:
            del os.environ['AWS_S3_BUCKET']
            del os.environ['USER_SECRETS_KMS_KEY_ID']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
