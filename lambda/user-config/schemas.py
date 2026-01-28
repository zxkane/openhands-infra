"""
Pydantic schemas for User Configuration API

These schemas define the structure of user configuration data:
- MCP server configuration
- Encrypted secrets metadata
- Third-party integrations
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class MCPServerConfig(BaseModel):
    """Configuration for a single MCP server."""

    id: str = Field(..., description='Unique identifier for the server')
    type: Literal['shttp', 'stdio'] = Field('shttp', description='Server type')
    enabled: bool = Field(True, description='Whether the server is enabled')
    notes: str = Field('', description='User notes about this server')

    # SHTTP server fields
    url: str | None = Field(None, description='URL for SHTTP servers')

    # STDIO server fields
    name: str | None = Field(None, description='Name for STDIO servers')
    command: str | None = Field(None, description='Command to run for STDIO servers')
    args: list[str] = Field(default_factory=list, description='Arguments for STDIO server command')
    env: dict[str, str] = Field(default_factory=dict, description='Environment variables (may include secret refs)')
    runtime: str = Field('sandbox', description='Where to run: sandbox or host')


class MCPConfig(BaseModel):
    """Complete MCP configuration for a user."""

    version: str = Field('1.0', description='Configuration schema version')
    updated_at: datetime | None = Field(None, description='Last update timestamp')
    shttp_servers: list[MCPServerConfig] = Field(default_factory=list, description='SHTTP MCP servers')
    stdio_servers: list[MCPServerConfig] = Field(default_factory=list, description='STDIO MCP servers')
    disabled_global_servers: list[str] = Field(
        default_factory=list,
        description='IDs of global servers to disable for this user'
    )


class SecretMetadata(BaseModel):
    """Metadata about a stored secret (value is never returned)."""

    id: str = Field(..., description='Secret identifier')
    type: str = Field('api_key', description='Type of secret: api_key, token, credential')
    created_at: datetime = Field(..., description='When the secret was created')
    updated_at: datetime = Field(..., description='When the secret was last updated')
    notes: str = Field('', description='User notes about this secret')


class IntegrationConfig(BaseModel):
    """Configuration for a third-party integration."""

    enabled: bool = Field(False, description='Whether the integration is enabled')
    token_ref: str | None = Field(
        None,
        description='Reference to secret (e.g., secrets/github-token)'
    )
    connected_at: datetime | None = Field(None, description='When the integration was configured')
    notes: str = Field('', description='User notes about this integration')
    auto_mcp: bool = Field(
        True,
        description='Automatically add MCP server for this integration'
    )
