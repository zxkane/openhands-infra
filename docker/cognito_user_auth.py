"""
Cognito User Authentication for OpenHands (V1).

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

V1 NOTES (PR #81 / OpenHands v1.7.0):
- Imports moved from openhands.server.user_auth.* to
  openhands.app_server.user_auth.* — V0 paths are scheduled for removal
  but the V1 application server still routes auth through these
  Legacy-V0-tagged files (see openhands/app_server/user/auth_user_context.py
  which wraps UserAuth as the V1 UserContext).
- Settings model moved to openhands.app_server.settings.settings_models.
- MCPSSEServerConfig / MCPStdioServerConfig live in openhands.core.config
  in v1.7.0 (unchanged from v1.6.0).
"""

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Request

from openhands.app_server.user_auth.default_user_auth import DefaultUserAuth
from openhands.app_server.user_auth.user_auth import UserAuth

if TYPE_CHECKING:
    from openhands.app_server.settings.settings_models import Settings

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
        return self._user_id

    async def get_user_email(self) -> str | None:
        return self._email

    @classmethod
    async def get_instance(cls, request: Request) -> UserAuth:
        """Create an instance from the incoming request.

        Extracts user information from headers set by Lambda@Edge:
        - x-cognito-user-id: The user's Cognito sub (unique identifier)
        - x-cognito-email: The user's email address
        """
        user_id = request.headers.get('x-cognito-user-id')
        email = request.headers.get('x-cognito-email')

        logger.info(f"CognitoUserAuth.get_instance: user_id={user_id}, email={email}")

        if not user_id:
            logger.info("CognitoUserAuth: No user_id in headers, using DefaultUserAuth")
            return DefaultUserAuth()

        instance = cls()
        instance._user_id = user_id
        instance._email = email if email else None
        return instance

    @classmethod
    async def get_for_user(cls, user_id: str) -> UserAuth:
        instance = cls()
        instance._user_id = user_id
        return instance

    async def get_user_settings(self) -> 'Settings | None':
        """Get user settings with user-specific MCP configuration merged in.

        Loads base settings via the parent (which already merges config.toml),
        then applies the per-user MCP overlay from S3: removes globally
        configured servers the user has disabled, appends the user's custom
        shttp/stdio servers, and registers any auto_mcp servers configured by
        third-party integrations.
        """
        # Get base settings from parent (includes config.toml merge)
        settings = await super().get_user_settings()

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

        except ImportError as e:
            logger.warning(f'User config loader not available: {e}')
        except Exception as e:
            logger.error(f'Failed to load user MCP config: {e}')

        return settings
