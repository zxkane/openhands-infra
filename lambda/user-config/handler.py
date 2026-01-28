"""
OpenHands User Configuration API Lambda Handler

This Lambda handles all user configuration management:
- MCP server configuration (add/remove/enable/disable)
- Encrypted secrets storage (API keys, tokens)
- Third-party integrations (GitHub, Slack)
- Configuration merging (user + global config)

Authentication & Security:
- Users are identified by X-Cognito-User-Id header (injected by Lambda@Edge)
- All operations are scoped to the authenticated user
- This API is only accessible via CloudFront (not directly via API Gateway execute-api URL)
  because CloudFront routes /api/v1/user-config/* to this Lambda, and Lambda@Edge validates
  JWT tokens before forwarding requests. Direct API Gateway access would bypass JWT validation.
- The API Gateway does NOT have a separate authorizer because authentication is handled
  by the Lambda@Edge function in CloudFront which validates JWT and injects user headers.
"""

import json
import logging
import os
from typing import Any

from config_store import UserConfigStore
from schemas import IntegrationConfig, MCPConfig, MCPServerConfig

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(level=getattr(logging, log_level))
logger = logging.getLogger(__name__)


def create_response(status_code: int, body: Any) -> dict:
    """Create an API Gateway response with proper headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
        },
        'body': json.dumps(body, default=str) if body is not None else '',
    }


def get_user_id(event: dict) -> str | None:
    """Extract user ID from request headers (injected by Lambda@Edge)."""
    headers = event.get('headers', {})
    # API Gateway v2 lowercases all header keys
    return headers.get('x-cognito-user-id') or headers.get('X-Cognito-User-Id')


def get_path_parameter(event: dict, name: str) -> str | None:
    """Extract a path parameter from the event."""
    params = event.get('pathParameters', {})
    return params.get(name) if params else None


def parse_json_body(event: dict) -> dict | None:
    """Parse JSON body from request."""
    body = event.get('body')
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


async def handle_get_mcp_config(store: UserConfigStore) -> dict:
    """GET /api/v1/user-config/mcp - Get user MCP configuration."""
    config = await store.get_mcp_config()
    return create_response(200, config.model_dump() if config else MCPConfig().model_dump())


async def handle_put_mcp_config(store: UserConfigStore, body: dict) -> dict:
    """PUT /api/v1/user-config/mcp - Update complete MCP configuration."""
    try:
        config = MCPConfig.model_validate(body)
        await store.save_mcp_config(config)
        return create_response(200, {'message': 'MCP configuration updated'})
    except Exception as e:
        logger.error(f'Failed to update MCP config: {e}')
        return create_response(400, {'error': str(e)})


async def handle_add_mcp_server(store: UserConfigStore, body: dict) -> dict:
    """POST /api/v1/user-config/mcp/servers - Add a new MCP server."""
    try:
        server = MCPServerConfig.model_validate(body)
        config = await store.get_mcp_config() or MCPConfig()

        # Check for duplicate ID
        existing_ids = {s.id for s in config.shttp_servers + config.stdio_servers}
        if server.id in existing_ids:
            return create_response(409, {'error': f'Server with ID {server.id} already exists'})

        # Add to appropriate list based on server type
        if server.type == 'shttp':
            config.shttp_servers.append(server)
        else:
            config.stdio_servers.append(server)

        await store.save_mcp_config(config)
        return create_response(201, {'message': 'MCP server added', 'server_id': server.id})
    except Exception as e:
        logger.error(f'Failed to add MCP server: {e}')
        return create_response(400, {'error': str(e)})


async def handle_update_mcp_server(store: UserConfigStore, server_id: str, body: dict) -> dict:
    """PUT /api/v1/user-config/mcp/servers/{serverId} - Update an MCP server."""
    try:
        config = await store.get_mcp_config()
        if not config:
            return create_response(404, {'error': 'No MCP configuration found'})

        # Find and update the server
        found = False
        for i, server in enumerate(config.shttp_servers):
            if server.id == server_id:
                config.shttp_servers[i] = MCPServerConfig.model_validate({**server.model_dump(), **body})
                found = True
                break

        if not found:
            for i, server in enumerate(config.stdio_servers):
                if server.id == server_id:
                    config.stdio_servers[i] = MCPServerConfig.model_validate({**server.model_dump(), **body})
                    found = True
                    break

        if not found:
            return create_response(404, {'error': f'Server {server_id} not found'})

        await store.save_mcp_config(config)
        return create_response(200, {'message': 'MCP server updated'})
    except Exception as e:
        logger.error(f'Failed to update MCP server: {e}')
        return create_response(400, {'error': str(e)})


async def handle_delete_mcp_server(store: UserConfigStore, server_id: str) -> dict:
    """DELETE /api/v1/user-config/mcp/servers/{serverId} - Delete an MCP server."""
    config = await store.get_mcp_config()
    if not config:
        return create_response(404, {'error': 'No MCP configuration found'})

    # Remove from shttp_servers
    original_len = len(config.shttp_servers)
    config.shttp_servers = [s for s in config.shttp_servers if s.id != server_id]

    # If not found in shttp, try stdio
    if len(config.shttp_servers) == original_len:
        original_len = len(config.stdio_servers)
        config.stdio_servers = [s for s in config.stdio_servers if s.id != server_id]
        if len(config.stdio_servers) == original_len:
            return create_response(404, {'error': f'Server {server_id} not found'})

    await store.save_mcp_config(config)
    return create_response(200, {'message': 'MCP server deleted'})


async def handle_get_secrets(store: UserConfigStore) -> dict:
    """GET /api/v1/user-config/secrets - List secret metadata (not values)."""
    secrets = await store.list_secrets()
    return create_response(200, {'secrets': [s.model_dump() for s in secrets]})


async def handle_put_secret(store: UserConfigStore, secret_id: str, body: dict) -> dict:
    """PUT /api/v1/user-config/secrets/{secretId} - Create or update a secret."""
    value = body.get('value')
    if not value:
        return create_response(400, {'error': 'Missing required field: value'})

    secret_type = body.get('type', 'api_key')
    notes = body.get('notes', '')

    try:
        await store.save_secret(secret_id, value, secret_type, notes)
        return create_response(200, {'message': f'Secret {secret_id} saved'})
    except Exception as e:
        logger.error(f'Failed to save secret: {e}')
        return create_response(500, {'error': 'Failed to save secret'})


async def handle_delete_secret(store: UserConfigStore, secret_id: str) -> dict:
    """DELETE /api/v1/user-config/secrets/{secretId} - Delete a secret."""
    try:
        await store.delete_secret(secret_id)
        return create_response(200, {'message': f'Secret {secret_id} deleted'})
    except Exception as e:
        logger.error(f'Failed to delete secret: {e}')
        return create_response(500, {'error': 'Failed to delete secret'})


async def handle_get_integrations(store: UserConfigStore) -> dict:
    """GET /api/v1/user-config/integrations - Get all integration configurations."""
    integrations = await store.get_integrations()
    return create_response(200, {k: v.model_dump() for k, v in integrations.items()})


async def handle_put_integration(store: UserConfigStore, provider: str, body: dict) -> dict:
    """PUT /api/v1/user-config/integrations/{provider} - Configure an integration."""
    try:
        config = IntegrationConfig.model_validate(body)
        await store.save_integration(provider, config)
        return create_response(200, {'message': f'Integration {provider} configured'})
    except Exception as e:
        logger.error(f'Failed to configure integration: {e}')
        return create_response(400, {'error': str(e)})


async def handle_delete_integration(store: UserConfigStore, provider: str) -> dict:
    """DELETE /api/v1/user-config/integrations/{provider} - Remove an integration."""
    try:
        await store.delete_integration(provider)
        return create_response(200, {'message': f'Integration {provider} removed'})
    except Exception as e:
        logger.error(f'Failed to remove integration: {e}')
        return create_response(500, {'error': 'Failed to remove integration'})


async def handle_get_merged_config(store: UserConfigStore) -> dict:
    """GET /api/v1/user-config/merged - Get merged configuration (global + user)."""
    # Note: Global config merging happens in the OpenHands app, not here
    # This endpoint returns the user's config that will be merged with global
    mcp_config = await store.get_mcp_config()
    integrations = await store.get_integrations()
    secrets_metadata = await store.list_secrets()

    return create_response(200, {
        'mcp': mcp_config.model_dump() if mcp_config else None,
        'integrations': {k: v.model_dump() for k, v in integrations.items()},
        'secrets': [s.model_dump() for s in secrets_metadata],  # Metadata only, no values
    })


async def route_request(event: dict, store: UserConfigStore) -> dict:
    """Route the request to the appropriate handler."""
    path = event.get('rawPath', '')
    method = event.get('requestContext', {}).get('http', {}).get('method', '')

    logger.info(f'Routing {method} {path}')

    # MCP Configuration
    if path == '/api/v1/user-config/mcp':
        if method == 'GET':
            return await handle_get_mcp_config(store)
        elif method == 'PUT':
            body = parse_json_body(event)
            if not body:
                return create_response(400, {'error': 'Invalid JSON body'})
            return await handle_put_mcp_config(store, body)

    # MCP Servers
    elif path == '/api/v1/user-config/mcp/servers':
        if method == 'POST':
            body = parse_json_body(event)
            if not body:
                return create_response(400, {'error': 'Invalid JSON body'})
            return await handle_add_mcp_server(store, body)

    elif path.startswith('/api/v1/user-config/mcp/servers/'):
        server_id = get_path_parameter(event, 'serverId')
        if not server_id:
            return create_response(400, {'error': 'Missing server ID'})

        if method == 'PUT':
            body = parse_json_body(event)
            if not body:
                return create_response(400, {'error': 'Invalid JSON body'})
            return await handle_update_mcp_server(store, server_id, body)
        elif method == 'DELETE':
            return await handle_delete_mcp_server(store, server_id)

    # Secrets
    elif path == '/api/v1/user-config/secrets':
        if method == 'GET':
            return await handle_get_secrets(store)

    elif path.startswith('/api/v1/user-config/secrets/'):
        secret_id = get_path_parameter(event, 'secretId')
        if not secret_id:
            return create_response(400, {'error': 'Missing secret ID'})

        if method == 'PUT':
            body = parse_json_body(event)
            if not body:
                return create_response(400, {'error': 'Invalid JSON body'})
            return await handle_put_secret(store, secret_id, body)
        elif method == 'DELETE':
            return await handle_delete_secret(store, secret_id)

    # Integrations
    elif path == '/api/v1/user-config/integrations':
        if method == 'GET':
            return await handle_get_integrations(store)

    elif path.startswith('/api/v1/user-config/integrations/'):
        provider = get_path_parameter(event, 'provider')
        if not provider:
            return create_response(400, {'error': 'Missing provider'})

        if method == 'PUT':
            body = parse_json_body(event)
            if not body:
                return create_response(400, {'error': 'Invalid JSON body'})
            return await handle_put_integration(store, provider, body)
        elif method == 'DELETE':
            return await handle_delete_integration(store, provider)

    # Merged Config
    elif path == '/api/v1/user-config/merged':
        if method == 'GET':
            return await handle_get_merged_config(store)

    return create_response(404, {'error': 'Not found'})


def handler(event: dict, context: Any) -> dict:
    """Lambda handler entry point."""
    import asyncio

    logger.debug(f'Received event: {json.dumps(event, default=str)}')

    # Extract user ID from headers (injected by Lambda@Edge)
    user_id = get_user_id(event)
    if not user_id:
        return create_response(401, {'error': 'Unauthorized: Missing user ID'})

    # Create user-scoped config store
    bucket = os.environ.get('DATA_BUCKET')
    kms_key_id = os.environ.get('KMS_KEY_ID')

    if not bucket:
        logger.error('DATA_BUCKET environment variable not set')
        return create_response(500, {'error': 'Server configuration error'})

    store = UserConfigStore(
        bucket_name=bucket,
        user_id=user_id,
        kms_key_id=kms_key_id,
    )

    # Route and handle the request
    return asyncio.get_event_loop().run_until_complete(route_request(event, store))
