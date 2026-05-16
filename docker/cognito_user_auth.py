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
- MCP config moved from Settings.mcp_config (V0) to
  Settings.agent_settings.mcp_config (V1) using fastmcp's MCPConfig shape:
  ``{'mcpServers': {'name': {'url': ...}|{'command':..., 'args': [...]}}}``
- V1's app_server does NOT parse config.toml's [mcp] section. We load it
  here at user-settings time and inject into agent_settings.mcp_config so
  global servers (knowledge-mcp, chrome-devtools-mcp) reach the agent.
"""

import logging
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Request

from openhands.app_server.user_auth.default_user_auth import DefaultUserAuth
from openhands.app_server.user_auth.user_auth import UserAuth

if TYPE_CHECKING:
    from openhands.app_server.settings.settings_models import Settings

logger = logging.getLogger(__name__)

# Feature flag for user config loading
USER_CONFIG_ENABLED = os.environ.get('USER_CONFIG_ENABLED', 'false').lower() == 'true'

# Path to the global app config.toml. The compute-stack writes config.toml content
# from the OPENHANDS_CONFIG_TOML env var into /app/config.toml at container start.
GLOBAL_CONFIG_TOML_PATH = Path(os.environ.get('OPENHANDS_CONFIG_PATH', '/app/config.toml'))


def _load_global_mcp_servers() -> dict[str, dict[str, Any]]:
    """Parse [mcp] from the global config.toml into fastmcp mcpServers shape.

    Returns a dict of ``{name: server_dict}`` ready to merge into
    ``Settings.agent_settings.mcp_config.mcpServers``. Each server_dict is
    either ``{'url': '...'}`` (HTTP) or ``{'command': '...', 'args': [...]}``
    (stdio), matching fastmcp's MCPConfig schema.

    Returns an empty dict if the file is missing, unreadable, or has no [mcp]
    section. Reading config.toml is best-effort; failures are logged but
    must not block user settings load.
    """
    try:
        if not GLOBAL_CONFIG_TOML_PATH.exists():
            return {}
        with GLOBAL_CONFIG_TOML_PATH.open('rb') as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.warning(f'Failed to read global config.toml at {GLOBAL_CONFIG_TOML_PATH}: {e}')
        return {}

    mcp_section = data.get('mcp') or {}
    servers: dict[str, dict[str, Any]] = {}

    # HTTP/SSE servers — config.toml uses `shttp_servers = [{ url = "..." }]`.
    # fastmcp keys each server by name; derive a stable name from the URL host
    # when one isn't provided, since shttp entries typically lack a name field.
    for entry in mcp_section.get('shttp_servers') or []:
        url = entry.get('url')
        if not url:
            continue
        name = entry.get('name') or _name_from_url(url)
        servers[name] = {'url': url}

    # stdio servers — `[{ name, command, args, env }]`
    for entry in mcp_section.get('stdio_servers') or []:
        name = entry.get('name')
        command = entry.get('command')
        if not name or not command:
            continue
        server_dict: dict[str, Any] = {'command': command, 'args': list(entry.get('args') or [])}
        env = entry.get('env')
        if env:
            server_dict['env'] = dict(env)
        servers[name] = server_dict

    return servers


def _name_from_url(url: str) -> str:
    """Derive a stable MCP server name from a URL when none is given.

    Uses the host's first label, e.g. ``https://knowledge-mcp.global.api.aws``
    -> ``knowledge-mcp``. Falls back to the full URL if parsing fails.
    """
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        return host.split('.')[0] or url
    except Exception:
        return url


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
        """Get user settings with global + per-user MCP servers merged in.

        V1 architecture: MCP config lives at
        ``settings.agent_settings.mcp_config`` (fastmcp's MCPConfig with
        ``mcpServers: dict[str, MCPServer]``). The V1 app_server does NOT
        load config.toml's [mcp] section, so we do it here ourselves and
        merge it with per-user S3 overlays.

        Merge order (later wins on name collision):
          1. Global ``[mcp]`` from ``/app/config.toml``
          2. User-disabled global servers are removed
          3. Per-user custom servers from S3
          4. auto_mcp servers from user integrations
        """
        # Get base settings from parent
        settings = await super().get_user_settings()

        # Load global config.toml [mcp] for every authenticated user
        # (V1 doesn't do this automatically — see module docstring).
        global_servers = _load_global_mcp_servers()
        if global_servers:
            settings = self._ensure_mcp_servers(settings, global_servers)

        if not USER_CONFIG_ENABLED:
            return settings

        user_id = await self.get_user_id()
        if not user_id:
            return settings

        try:
            from user_config_loader import UserConfigLoader
            try:
                from user_config_loader import INTEGRATION_MCP_MAP
            except ImportError:
                logger.warning('INTEGRATION_MCP_MAP not available in user_config_loader')
                INTEGRATION_MCP_MAP = {}

            loader = UserConfigLoader(user_id)
            user_mcp = loader.get_mcp_config() or {}

            # Apply per-user disable list (drops names from the merged map)
            disabled = set(user_mcp.get('disabled_global_servers') or [])
            if disabled:
                self._remove_mcp_servers(settings, disabled)
                logger.info(f'User {user_id} disabled global MCP servers: {disabled}')

            # Per-user custom shttp servers
            user_servers: dict[str, dict[str, Any]] = {}
            for server in user_mcp.get('shttp_servers') or []:
                if not server.get('enabled', True):
                    continue
                url = server.get('url')
                if not url:
                    continue
                name = server.get('name') or server.get('id') or _name_from_url(url)
                user_servers[name] = {'url': url}

            # Per-user custom stdio servers
            for server in user_mcp.get('stdio_servers') or []:
                if not server.get('enabled', True):
                    continue
                name = server.get('name') or server.get('id')
                command = server.get('command')
                if not name or not command:
                    continue
                server_dict: dict[str, Any] = {
                    'command': command,
                    'args': list(server.get('args') or []),
                }
                if server.get('env'):
                    server_dict['env'] = dict(server['env'])
                user_servers[name] = server_dict

            # auto_mcp servers from user integrations
            integrations = loader.get_integrations()
            for provider, config in integrations.items():
                if not (config.get('enabled') and config.get('auto_mcp', True)):
                    continue
                template = INTEGRATION_MCP_MAP.get(provider)
                if not template:
                    continue
                user_servers[template['name']] = {
                    'command': template['command'],
                    'args': list(template['args']),
                    'env': {
                        f"{template['env_key']}_REF": config.get('token_ref', '')
                    },
                }

            if user_servers:
                settings = self._ensure_mcp_servers(settings, user_servers)

        except ImportError as e:
            logger.warning(f'User config loader not available: {e}')
        except Exception as e:
            logger.error(f'Failed to load user MCP config: {e}')

        return settings

    @staticmethod
    def _ensure_mcp_servers(
        settings: 'Settings | None', servers: dict[str, dict[str, Any]]
    ) -> 'Settings | None':
        """Merge ``servers`` into ``settings.agent_settings.mcp_config.mcpServers``.

        Creates the ``mcp_config`` if it's missing. Existing servers with the
        same name are overwritten — caller orders the merge accordingly.
        """
        if settings is None or settings.agent_settings is None:
            return settings
        from fastmcp.mcp_config import MCPConfig

        agent_settings = settings.agent_settings
        existing = agent_settings.mcp_config
        existing_dict = existing.model_dump(exclude_none=True) if existing else {}
        existing_servers = dict(existing_dict.get('mcpServers') or {})
        existing_servers.update(servers)
        existing_dict['mcpServers'] = existing_servers
        agent_settings.mcp_config = MCPConfig.from_dict(existing_dict)
        return settings

    @staticmethod
    def _remove_mcp_servers(
        settings: 'Settings | None', names: set[str]
    ) -> None:
        """Remove named servers from ``settings.agent_settings.mcp_config.mcpServers``."""
        if (
            settings is None
            or settings.agent_settings is None
            or settings.agent_settings.mcp_config is None
        ):
            return
        mcp = settings.agent_settings.mcp_config
        if not mcp.mcpServers:
            return
        for name in names:
            mcp.mcpServers.pop(name, None)
