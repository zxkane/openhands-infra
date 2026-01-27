"""
User Configuration Store

Handles storage and retrieval of user configuration from S3,
with KMS envelope encryption for secrets.

Storage Structure:
    users/{user_id}/
    ├── config/
    │   ├── mcp-config.json         # MCP server configuration
    │   └── integrations.json       # Third-party integration config
    └── secrets/
        └── credentials.json.enc    # KMS-encrypted secrets

Security:
- Secrets are encrypted using KMS envelope encryption
- KMS key is used to encrypt a data key (DEK)
- DEK encrypts the actual secret values
- Only metadata is returned via API (never the actual values)
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from schemas import IntegrationConfig, MCPConfig, SecretMetadata

logger = logging.getLogger(__name__)


class UserConfigStore:
    """Store for user-scoped configuration in S3 with KMS encryption."""

    def __init__(self, bucket_name: str, user_id: str, kms_key_id: str | None = None):
        """Initialize the store for a specific user.

        Args:
            bucket_name: S3 bucket for data storage
            user_id: Cognito user ID
            kms_key_id: KMS key ID for secrets encryption
        """
        self.bucket_name = bucket_name
        self.user_id = user_id
        self.kms_key_id = kms_key_id
        self.s3 = boto3.client('s3')
        self.kms = boto3.client('kms') if kms_key_id else None

        # S3 paths for this user
        self.config_prefix = f'users/{user_id}/config'
        self.secrets_prefix = f'users/{user_id}/secrets'

    def _get_s3_key(self, *parts: str) -> str:
        """Construct S3 key from parts."""
        return '/'.join(parts)

    async def _read_json(self, key: str) -> dict | None:
        """Read and parse JSON from S3."""
        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            content = response['Body'].read().decode('utf-8')
            return json.loads(content)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return None
            raise

    async def _write_json(self, key: str, data: dict) -> None:
        """Write JSON to S3."""
        self.s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=json.dumps(data, default=str),
            ContentType='application/json',
        )

    async def _delete_object(self, key: str) -> None:
        """Delete an object from S3."""
        try:
            self.s3.delete_object(Bucket=self.bucket_name, Key=key)
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchKey':
                raise

    # ========================================
    # MCP Configuration
    # ========================================

    async def get_mcp_config(self) -> MCPConfig | None:
        """Get user MCP configuration."""
        key = self._get_s3_key(self.config_prefix, 'mcp-config.json')
        data = await self._read_json(key)
        if data:
            return MCPConfig.model_validate(data)
        return None

    async def save_mcp_config(self, config: MCPConfig) -> None:
        """Save user MCP configuration."""
        config.updated_at = datetime.now(timezone.utc)
        key = self._get_s3_key(self.config_prefix, 'mcp-config.json')
        await self._write_json(key, config.model_dump())

    # ========================================
    # Secrets (KMS Envelope Encryption)
    # ========================================

    async def _encrypt_secrets(self, secrets: dict[str, Any]) -> str:
        """Encrypt secrets using KMS envelope encryption.

        1. Generate a data key using KMS
        2. Encrypt the secrets JSON with the data key (AES-256-GCM)
        3. Store both the encrypted data key and ciphertext
        """
        if not self.kms or not self.kms_key_id:
            raise ValueError('KMS key not configured for secrets encryption')

        # Generate data key
        response = self.kms.generate_data_key(
            KeyId=self.kms_key_id,
            KeySpec='AES_256',
        )
        plaintext_key = response['Plaintext']
        encrypted_key = response['CiphertextBlob']

        # Encrypt the secrets
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os as crypto_os

        nonce = crypto_os.urandom(12)
        aesgcm = AESGCM(plaintext_key)
        ciphertext = aesgcm.encrypt(nonce, json.dumps(secrets).encode('utf-8'), None)

        # Package encrypted key + nonce + ciphertext
        envelope = {
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        }

        return json.dumps(envelope)

    async def _decrypt_secrets(self, encrypted_data: str) -> dict[str, Any]:
        """Decrypt secrets using KMS envelope encryption."""
        if not self.kms:
            raise ValueError('KMS key not configured for secrets decryption')

        envelope = json.loads(encrypted_data)
        encrypted_key = base64.b64decode(envelope['encrypted_key'])
        nonce = base64.b64decode(envelope['nonce'])
        ciphertext = base64.b64decode(envelope['ciphertext'])

        # Decrypt the data key using KMS
        response = self.kms.decrypt(CiphertextBlob=encrypted_key)
        plaintext_key = response['Plaintext']

        # Decrypt the secrets
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(plaintext_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode('utf-8'))

    async def _get_secrets_data(self) -> dict:
        """Get the raw secrets data structure."""
        key = self._get_s3_key(self.secrets_prefix, 'credentials.json.enc')
        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            encrypted_data = response['Body'].read().decode('utf-8')
            return await self._decrypt_secrets(encrypted_data)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return {'version': '1.0', 'secrets': {}}
            raise

    async def _save_secrets_data(self, data: dict) -> None:
        """Save the secrets data structure."""
        key = self._get_s3_key(self.secrets_prefix, 'credentials.json.enc')
        encrypted_data = await self._encrypt_secrets(data)
        self.s3.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=encrypted_data,
            ContentType='application/octet-stream',
        )

    async def list_secrets(self) -> list[SecretMetadata]:
        """List all secrets (metadata only, not values)."""
        data = await self._get_secrets_data()
        secrets = []
        for secret_id, secret_data in data.get('secrets', {}).items():
            secrets.append(SecretMetadata(
                id=secret_id,
                type=secret_data.get('type', 'api_key'),
                created_at=datetime.fromisoformat(secret_data['created_at']),
                updated_at=datetime.fromisoformat(secret_data['updated_at']),
                notes=secret_data.get('notes', ''),
            ))
        return secrets

    async def get_secret(self, secret_id: str) -> str | None:
        """Get a secret value by ID (for internal use only).

        WARNING: This method returns the actual secret value.
        It should only be called during conversation creation
        to inject secrets into sandbox environment variables.
        """
        data = await self._get_secrets_data()
        secret_data = data.get('secrets', {}).get(secret_id)
        if secret_data:
            return secret_data.get('value')
        return None

    async def save_secret(
        self,
        secret_id: str,
        value: str,
        secret_type: str = 'api_key',
        notes: str = '',
    ) -> None:
        """Save a secret with KMS encryption."""
        data = await self._get_secrets_data()
        now = datetime.now(timezone.utc).isoformat()

        existing = data.get('secrets', {}).get(secret_id, {})
        data.setdefault('secrets', {})[secret_id] = {
            'type': secret_type,
            'value': value,  # This gets encrypted
            'created_at': existing.get('created_at', now),
            'updated_at': now,
            'notes': notes,
        }

        await self._save_secrets_data(data)
        logger.info(f'Saved secret: {secret_id} (type: {secret_type})')

    async def delete_secret(self, secret_id: str) -> None:
        """Delete a secret."""
        data = await self._get_secrets_data()
        if secret_id in data.get('secrets', {}):
            del data['secrets'][secret_id]
            await self._save_secrets_data(data)
            logger.info(f'Deleted secret: {secret_id}')

    # ========================================
    # Integrations
    # ========================================

    async def get_integrations(self) -> dict[str, IntegrationConfig]:
        """Get all integration configurations."""
        key = self._get_s3_key(self.config_prefix, 'integrations.json')
        data = await self._read_json(key)
        if not data:
            return {}
        return {k: IntegrationConfig.model_validate(v) for k, v in data.items()}

    async def save_integration(self, provider: str, config: IntegrationConfig) -> None:
        """Save an integration configuration."""
        integrations = await self.get_integrations()
        config.connected_at = datetime.now(timezone.utc)
        integrations[provider] = config

        key = self._get_s3_key(self.config_prefix, 'integrations.json')
        await self._write_json(key, {k: v.model_dump() for k, v in integrations.items()})
        logger.info(f'Saved integration: {provider}')

    async def delete_integration(self, provider: str) -> None:
        """Delete an integration configuration."""
        integrations = await self.get_integrations()
        if provider in integrations:
            del integrations[provider]
            key = self._get_s3_key(self.config_prefix, 'integrations.json')
            await self._write_json(key, {k: v.model_dump() for k, v in integrations.items()})
            logger.info(f'Deleted integration: {provider}')

    # ========================================
    # Secret Resolution (for Sandbox Injection)
    # ========================================

    async def resolve_secret_refs(self, env_vars: dict[str, str]) -> dict[str, str]:
        """Resolve secret references in environment variables.

        Replaces env vars like GITHUB_TOKEN_REF='secrets/github-token'
        with GITHUB_TOKEN=<actual_secret_value>

        Args:
            env_vars: Dictionary of environment variables, some may have _REF suffix

        Returns:
            Dictionary with resolved values (no _REF suffix)
        """
        resolved = {}
        for key, value in env_vars.items():
            if isinstance(value, str) and value.startswith('secrets/'):
                secret_id = value.replace('secrets/', '')
                secret_value = await self.get_secret(secret_id)
                if secret_value:
                    # Remove _REF suffix from key
                    resolved_key = key[:-4] if key.endswith('_REF') else key
                    resolved[resolved_key] = secret_value
                else:
                    logger.warning(f'Secret not found: {secret_id}')
            else:
                resolved[key] = value
        return resolved
