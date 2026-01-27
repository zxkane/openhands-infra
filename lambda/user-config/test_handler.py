"""
Unit tests for User Configuration API Lambda Handler

Tests cover:
- Request routing
- MCP configuration CRUD
- Secrets management (metadata only, values never exposed)
- Integration configuration
- Authentication (user ID from headers)
"""

import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set environment variables before importing handler
os.environ['DATA_BUCKET'] = 'test-bucket'
os.environ['KMS_KEY_ID'] = 'test-kms-key-id'
os.environ['LOG_LEVEL'] = 'DEBUG'

# Import modules after setting env vars
from handler import (
    create_response,
    get_path_parameter,
    get_user_id,
    handler,
    parse_json_body,
    route_request,
)
from schemas import IntegrationConfig, MCPConfig, MCPServerConfig, SecretMetadata


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_create_response_with_body(self):
        response = create_response(200, {'message': 'success'})
        assert response['statusCode'] == 200
        assert response['headers']['Content-Type'] == 'application/json'
        assert 'success' in response['body']

    def test_create_response_without_body(self):
        response = create_response(204, None)
        assert response['statusCode'] == 204
        assert response['body'] == ''

    def test_get_user_id_lowercase_header(self):
        event = {'headers': {'x-cognito-user-id': 'user-123'}}
        assert get_user_id(event) == 'user-123'

    def test_get_user_id_mixed_case_header(self):
        event = {'headers': {'X-Cognito-User-Id': 'user-456'}}
        assert get_user_id(event) == 'user-456'

    def test_get_user_id_missing(self):
        event = {'headers': {}}
        assert get_user_id(event) is None

    def test_get_path_parameter(self):
        event = {'pathParameters': {'serverId': 'server-123'}}
        assert get_path_parameter(event, 'serverId') == 'server-123'

    def test_get_path_parameter_missing(self):
        event = {'pathParameters': None}
        assert get_path_parameter(event, 'serverId') is None

    def test_parse_json_body_valid(self):
        event = {'body': '{"key": "value"}'}
        assert parse_json_body(event) == {'key': 'value'}

    def test_parse_json_body_invalid(self):
        event = {'body': 'not-json'}
        assert parse_json_body(event) is None

    def test_parse_json_body_empty(self):
        event = {'body': None}
        assert parse_json_body(event) is None


class TestHandler:
    """Tests for Lambda handler entry point."""

    def test_handler_missing_user_id(self):
        event = {'headers': {}, 'rawPath': '/api/v1/user-config/mcp'}
        response = handler(event, None)
        assert response['statusCode'] == 401
        assert 'Unauthorized' in response['body']

    @patch('handler.UserConfigStore')
    def test_handler_missing_bucket_env(self, mock_store):
        # Temporarily remove environment variable
        original_bucket = os.environ.get('DATA_BUCKET')
        del os.environ['DATA_BUCKET']

        try:
            event = {
                'headers': {'x-cognito-user-id': 'user-123'},
                'rawPath': '/api/v1/user-config/mcp',
                'requestContext': {'http': {'method': 'GET'}},
            }
            response = handler(event, None)
            assert response['statusCode'] == 500
            assert 'configuration error' in response['body']
        finally:
            # Restore environment variable
            if original_bucket:
                os.environ['DATA_BUCKET'] = original_bucket


class TestRouting:
    """Tests for request routing."""

    @pytest.mark.asyncio
    async def test_route_mcp_get(self):
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=MCPConfig())

        event = {
            'rawPath': '/api/v1/user-config/mcp',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.get_mcp_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_mcp_put(self):
        mock_store = MagicMock()
        mock_store.save_mcp_config = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/mcp',
            'requestContext': {'http': {'method': 'PUT'}},
            'body': json.dumps({'version': '1.0', 'shttp_servers': [], 'stdio_servers': []}),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.save_mcp_config.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_secrets_get(self):
        mock_store = MagicMock()
        mock_store.list_secrets = AsyncMock(return_value=[])

        event = {
            'rawPath': '/api/v1/user-config/secrets',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.list_secrets.assert_called_once()

    @pytest.mark.asyncio
    async def test_route_not_found(self):
        mock_store = MagicMock()

        event = {
            'rawPath': '/api/v1/user-config/invalid',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 404


class TestMCPConfiguration:
    """Tests for MCP configuration endpoints."""

    @pytest.mark.asyncio
    async def test_get_mcp_config_empty(self):
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=None)

        event = {
            'rawPath': '/api/v1/user-config/mcp',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['version'] == '1.0'
        assert body['shttp_servers'] == []

    @pytest.mark.asyncio
    async def test_add_mcp_server(self):
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=MCPConfig())
        mock_store.save_mcp_config = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/mcp/servers',
            'requestContext': {'http': {'method': 'POST'}},
            'body': json.dumps({
                'id': 'my-server',
                'type': 'shttp',
                'url': 'https://example.com/mcp',
                'enabled': True,
            }),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 201
        body = json.loads(response['body'])
        assert body['server_id'] == 'my-server'

    @pytest.mark.asyncio
    async def test_add_duplicate_mcp_server(self):
        existing_config = MCPConfig(
            shttp_servers=[MCPServerConfig(id='my-server', type='shttp', url='https://old.com')]
        )
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=existing_config)

        event = {
            'rawPath': '/api/v1/user-config/mcp/servers',
            'requestContext': {'http': {'method': 'POST'}},
            'body': json.dumps({
                'id': 'my-server',
                'type': 'shttp',
                'url': 'https://new.com/mcp',
            }),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 409
        assert 'already exists' in response['body']

    @pytest.mark.asyncio
    async def test_delete_mcp_server(self):
        existing_config = MCPConfig(
            shttp_servers=[MCPServerConfig(id='to-delete', type='shttp', url='https://example.com')]
        )
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=existing_config)
        mock_store.save_mcp_config = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/mcp/servers/to-delete',
            'requestContext': {'http': {'method': 'DELETE'}},
            'pathParameters': {'serverId': 'to-delete'},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200

    @pytest.mark.asyncio
    async def test_delete_nonexistent_server(self):
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=MCPConfig())

        event = {
            'rawPath': '/api/v1/user-config/mcp/servers/not-found',
            'requestContext': {'http': {'method': 'DELETE'}},
            'pathParameters': {'serverId': 'not-found'},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 404


class TestSecrets:
    """Tests for secrets management (metadata only, values never exposed)."""

    @pytest.mark.asyncio
    async def test_list_secrets_returns_metadata_only(self):
        mock_secrets = [
            SecretMetadata(
                id='github-token',
                type='api_key',
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                notes='GitHub PAT',
            )
        ]
        mock_store = MagicMock()
        mock_store.list_secrets = AsyncMock(return_value=mock_secrets)

        event = {
            'rawPath': '/api/v1/user-config/secrets',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        body = json.loads(response['body'])

        # Verify only metadata is returned, NOT the actual value
        assert len(body['secrets']) == 1
        secret = body['secrets'][0]
        assert secret['id'] == 'github-token'
        assert secret['type'] == 'api_key'
        assert 'value' not in secret  # Value must never be exposed

    @pytest.mark.asyncio
    async def test_save_secret(self):
        mock_store = MagicMock()
        mock_store.save_secret = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/secrets/github-token',
            'requestContext': {'http': {'method': 'PUT'}},
            'pathParameters': {'secretId': 'github-token'},
            'body': json.dumps({
                'value': 'ghp_secret123',
                'type': 'api_key',
                'notes': 'My GitHub token',
            }),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.save_secret.assert_called_once_with(
            'github-token',
            'ghp_secret123',
            'api_key',
            'My GitHub token',
        )

    @pytest.mark.asyncio
    async def test_save_secret_missing_value(self):
        mock_store = MagicMock()

        event = {
            'rawPath': '/api/v1/user-config/secrets/github-token',
            'requestContext': {'http': {'method': 'PUT'}},
            'pathParameters': {'secretId': 'github-token'},
            'body': json.dumps({'notes': 'No value provided'}),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 400
        assert 'Missing required field: value' in response['body']

    @pytest.mark.asyncio
    async def test_delete_secret(self):
        mock_store = MagicMock()
        mock_store.delete_secret = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/secrets/github-token',
            'requestContext': {'http': {'method': 'DELETE'}},
            'pathParameters': {'secretId': 'github-token'},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.delete_secret.assert_called_once_with('github-token')


class TestIntegrations:
    """Tests for third-party integration configuration."""

    @pytest.mark.asyncio
    async def test_get_integrations_empty(self):
        mock_store = MagicMock()
        mock_store.get_integrations = AsyncMock(return_value={})

        event = {
            'rawPath': '/api/v1/user-config/integrations',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        assert json.loads(response['body']) == {}

    @pytest.mark.asyncio
    async def test_get_integrations_with_data(self):
        mock_integrations = {
            'github': IntegrationConfig(
                enabled=True,
                token_ref='secrets/github-token',
                auto_mcp=True,
            )
        }
        mock_store = MagicMock()
        mock_store.get_integrations = AsyncMock(return_value=mock_integrations)

        event = {
            'rawPath': '/api/v1/user-config/integrations',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'github' in body
        assert body['github']['enabled'] is True
        assert body['github']['auto_mcp'] is True

    @pytest.mark.asyncio
    async def test_save_integration(self):
        mock_store = MagicMock()
        mock_store.save_integration = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/integrations/github',
            'requestContext': {'http': {'method': 'PUT'}},
            'pathParameters': {'provider': 'github'},
            'body': json.dumps({
                'enabled': True,
                'token_ref': 'secrets/github-token',
                'auto_mcp': True,
            }),
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.save_integration.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_integration(self):
        mock_store = MagicMock()
        mock_store.delete_integration = AsyncMock()

        event = {
            'rawPath': '/api/v1/user-config/integrations/github',
            'requestContext': {'http': {'method': 'DELETE'}},
            'pathParameters': {'provider': 'github'},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        mock_store.delete_integration.assert_called_once_with('github')


class TestMergedConfig:
    """Tests for merged configuration endpoint."""

    @pytest.mark.asyncio
    async def test_get_merged_config(self):
        mock_store = MagicMock()
        mock_store.get_mcp_config = AsyncMock(return_value=MCPConfig())
        mock_store.get_integrations = AsyncMock(return_value={})
        mock_store.list_secrets = AsyncMock(return_value=[])

        event = {
            'rawPath': '/api/v1/user-config/merged',
            'requestContext': {'http': {'method': 'GET'}},
        }
        response = await route_request(event, mock_store)
        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert 'mcp' in body
        assert 'integrations' in body
        assert 'secrets' in body


class TestSchemas:
    """Tests for Pydantic schemas."""

    def test_mcp_server_config_shttp(self):
        config = MCPServerConfig(
            id='aws-docs',
            type='shttp',
            url='https://awsdocs.mcp.example.com',
            enabled=True,
        )
        assert config.id == 'aws-docs'
        assert config.type == 'shttp'
        assert config.url == 'https://awsdocs.mcp.example.com'

    def test_mcp_server_config_stdio(self):
        config = MCPServerConfig(
            id='github-mcp',
            type='stdio',
            name='github-mcp',
            command='npx',
            args=['-y', '@modelcontextprotocol/server-github'],
            env={'GITHUB_TOKEN_REF': 'secrets/github-token'},
            runtime='sandbox',
        )
        assert config.type == 'stdio'
        assert config.command == 'npx'
        assert 'GITHUB_TOKEN_REF' in config.env

    def test_mcp_config_default(self):
        config = MCPConfig()
        assert config.version == '1.0'
        assert config.shttp_servers == []
        assert config.stdio_servers == []
        assert config.disabled_global_servers == []

    def test_integration_config_defaults(self):
        config = IntegrationConfig()
        assert config.enabled is False
        assert config.auto_mcp is True
        assert config.token_ref is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
