"""
Cognito User Authentication for OpenHands

This module provides user authentication via AWS Cognito, integrating with
Lambda@Edge which injects verified user information as HTTP headers.

Security Note:
    The x-cognito-* headers are set by Lambda@Edge after JWT verification.
    CloudFront VPC Origin ensures only Lambda@Edge processed requests reach
    the ALB, preventing header spoofing from external sources.

User Configuration:
    This module also handles loading user-specific MCP configurations from S3,
    merging them with global config.toml settings. User configs can:
    - Add custom MCP servers (shttp or stdio)
    - Disable specific global MCP servers
    - Configure third-party integrations with auto_mcp support
"""

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Request

from openhands.server.user_auth.default_user_auth import DefaultUserAuth
from openhands.server.user_auth.user_auth import UserAuth

if TYPE_CHECKING:
    from openhands.storage.data_models.settings import Settings

logger = logging.getLogger(__name__)

# Feature flag for user config loading
USER_CONFIG_ENABLED = os.environ.get('USER_CONFIG_ENABLED', 'false').lower() == 'true'


@dataclass
class CognitoUserAuth(DefaultUserAuth):
    """Cognito user authentication via Lambda@Edge injected headers.

    This class extends DefaultUserAuth to provide user identity from
    Cognito JWT tokens, which are validated by Lambda@Edge and injected
    as HTTP headers (x-cognito-user-id, x-cognito-email).
    """

    _user_id: str | None = None
    _email: str | None = None

    async def get_user_id(self) -> str | None:
        """Return the Cognito user ID (sub claim from JWT).

        Returns:
            The user's Cognito sub (unique identifier) or None if not authenticated.
        """
        return self._user_id

    async def get_user_email(self) -> str | None:
        """Return the user's email from Cognito.

        Returns:
            The user's email address or None if not available.
        """
        return self._email

    @classmethod
    async def get_instance(cls, request: Request) -> UserAuth:
        """Create an instance from the incoming request.

        Extracts user information from headers set by Lambda@Edge:
        - x-cognito-user-id: The user's Cognito sub (unique identifier)
        - x-cognito-email: The user's email address

        Args:
            request: The FastAPI request object.

        Returns:
            A CognitoUserAuth instance with user info, or DefaultUserAuth
            if no valid Cognito headers are present.
        """
        user_id = request.headers.get('x-cognito-user-id')
        email = request.headers.get('x-cognito-email')

        logger.info(f"CognitoUserAuth.get_instance: user_id={user_id}, email={email}")

        if not user_id:
            # No Cognito user info, fall back to default behavior
            logger.info("CognitoUserAuth: No user_id in headers, using DefaultUserAuth")
            return DefaultUserAuth()

        instance = cls()
        instance._user_id = user_id
        instance._email = email if email else None
        logger.info(f"CognitoUserAuth: Created instance for user {user_id}")
        return instance

    @classmethod
    async def get_for_user(cls, user_id: str) -> UserAuth:
        """Create an instance for a specific user ID.

        Used internally when user context is needed without a request.

        Args:
            user_id: The Cognito user ID (sub).

        Returns:
            A CognitoUserAuth instance with the specified user ID.
        """
        instance = cls()
        instance._user_id = user_id
        return instance

    async def get_user_settings(self) -> 'Settings | None':
        """Get user settings with merged MCP configuration.

        This method extends the parent's settings loading to include
        user-specific MCP configuration from S3. The merge process:
        1. Load base settings (with config.toml merge) from parent
        2. Load user MCP config from S3
        3. Remove disabled global servers
        4. Add user custom servers
        5. Add auto_mcp servers from integrations

        Returns:
            Settings with merged MCP configuration, or None if not found.
        """
        from openhands.storage.data_models.settings import Settings

        # Get base settings from parent (includes config.toml merge)
        settings = await super().get_user_settings()

        # Check if user config loading is enabled
        if not USER_CONFIG_ENABLED:
            return settings

        user_id = await self.get_user_id()
        if not user_id:
            return settings

        try:
            # Import here to avoid circular imports
            from user_config_loader import UserConfigLoader
            try:
                from user_config_loader import INTEGRATION_MCP_MAP
            except ImportError:
                logger.warning('INTEGRATION_MCP_MAP not available in user_config_loader')
                INTEGRATION_MCP_MAP = {}

            loader = UserConfigLoader(user_id)

            # Load user MCP configuration
            user_mcp = loader.get_mcp_config()
            if user_mcp and settings and settings.mcp_config:
                # Remove user-disabled global servers
                disabled = set(user_mcp.get('disabled_global_servers', []))
                if disabled:
                    logger.info(f'User {user_id} disabled global MCP servers: {disabled}')

                    # Filter out disabled servers by URL (for shttp) or name (for stdio)
                    settings.mcp_config.shttp_servers = [
                        s for s in settings.mcp_config.shttp_servers
                        if getattr(s, 'url', '') not in disabled
                    ]
                    settings.mcp_config.stdio_servers = [
                        s for s in settings.mcp_config.stdio_servers
                        if getattr(s, 'name', '') not in disabled
                    ]

                # Add user custom shttp servers
                for server in user_mcp.get('shttp_servers', []):
                    if server.get('enabled', True):
                        from openhands.core.config.mcp_config import MCPSSEServerConfig
                        settings.mcp_config.sse_servers = list(settings.mcp_config.sse_servers) + [
                            MCPSSEServerConfig(url=server['url'])
                        ]
                        logger.info(f'Added user shttp MCP server: {server.get("id")}')

                # Add user custom stdio servers
                for server in user_mcp.get('stdio_servers', []):
                    if server.get('enabled', True):
                        from openhands.core.config.mcp_config import MCPStdioServerConfig
                        settings.mcp_config.stdio_servers = list(settings.mcp_config.stdio_servers) + [
                            MCPStdioServerConfig(
                                name=server.get('name', server.get('id')),
                                command=server.get('command', ''),
                                args=server.get('args', []),
                                env=server.get('env', {}),
                            )
                        ]
                        logger.info(f'Added user stdio MCP server: {server.get("id")}')

            # Load integrations and add auto_mcp servers
            integrations = loader.get_integrations()
            for provider, config in integrations.items():
                if config.get('enabled') and config.get('auto_mcp', True):
                    mcp_template = INTEGRATION_MCP_MAP.get(provider)
                    if mcp_template and settings and settings.mcp_config:
                        from openhands.core.config.mcp_config import MCPStdioServerConfig
                        settings.mcp_config.stdio_servers = list(settings.mcp_config.stdio_servers) + [
                            MCPStdioServerConfig(
                                name=mcp_template['name'],
                                command=mcp_template['command'],
                                args=mcp_template['args'],
                                env={
                                    f"{mcp_template['env_key']}_REF": config.get('token_ref', '')
                                },
                            )
                        ]
                        logger.info(f'Added auto_mcp server for integration: {provider}')

        except ImportError as e:
            logger.warning(f'User config loader not available: {e}')
        except Exception as e:
            logger.error(f'Failed to load user MCP config: {e}')

        return settings
