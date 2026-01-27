"""
User Configuration Loader for OpenHands

This module loads user-specific configurations from S3, including:
- MCP server configurations
- Integration settings
- Encrypted secrets (decrypted at runtime)

This runs inside the OpenHands container and is used by CognitoUserAuth
to merge user-specific configs with global config.toml settings.

Security Notes:
- Secrets are only decrypted when needed (at conversation creation)
- Decrypted values are held in memory only, never written to disk
- Secret values are never logged
"""

import base64
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class UserConfigLoader:
    """Loads user configuration from S3 with KMS encryption support.

    This class is designed for use inside the OpenHands container to load
    user-specific MCP configurations and secrets for sandbox injection.
    """

    def __init__(self, user_id: str):
        """Initialize the loader for a specific user.

        Args:
            user_id: Cognito user ID
        """
        self.user_id = user_id
        self.bucket_name = os.environ.get('AWS_S3_BUCKET') or os.environ.get('FILE_STORE_PATH')
        self.kms_key_id = os.environ.get('USER_SECRETS_KMS_KEY_ID')

        if not self.bucket_name:
            logger.warning('No S3 bucket configured for user config storage')

        # Initialize AWS clients
        # Uses EC2 instance role for credentials (no explicit key needed)
        region = os.environ.get('AWS_REGION', 'us-west-2')
        self.s3 = boto3.client('s3', region_name=region)
        self.kms = boto3.client('kms', region_name=region) if self.kms_key_id else None

        # S3 paths
        self.config_prefix = f'users/{user_id}/config'
        self.secrets_prefix = f'users/{user_id}/secrets'

    def _read_json(self, key: str) -> dict | None:
        """Read and parse JSON from S3.

        Args:
            key: S3 object key

        Returns:
            Parsed JSON dict or None if not found
        """
        if not self.bucket_name:
            return None

        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            content = response['Body'].read().decode('utf-8')
            return json.loads(content)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return None
            logger.error(f'Failed to read S3 object {key}: {e}')
            raise
        except Exception as e:
            logger.error(f'Failed to parse JSON from {key}: {e}')
            return None

    def get_mcp_config(self) -> dict | None:
        """Get user MCP configuration.

        Returns:
            MCP config dict with shttp_servers, stdio_servers, disabled_global_servers
            or None if no config exists
        """
        key = f'{self.config_prefix}/mcp-config.json'
        config = self._read_json(key)
        if config:
            logger.info(f'Loaded MCP config for user {self.user_id}')
        return config

    def get_integrations(self) -> dict:
        """Get user integration configurations.

        Returns:
            Dict of provider -> config, e.g., {'github': {...}, 'slack': {...}}
        """
        key = f'{self.config_prefix}/integrations.json'
        integrations = self._read_json(key)
        return integrations or {}

    # ========================================
    # Secrets Handling (KMS Envelope Encryption)
    # ========================================

    def _get_secrets_data(self) -> dict:
        """Get the raw secrets data structure (decrypted).

        Returns:
            Dict with 'secrets' key containing secret id -> data mapping
        """
        if not self.bucket_name:
            return {'version': '1.0', 'secrets': {}}

        key = f'{self.secrets_prefix}/credentials.json.enc'
        try:
            response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
            encrypted_data = response['Body'].read().decode('utf-8')
            return self._decrypt_secrets(encrypted_data)
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchKey':
                return {'version': '1.0', 'secrets': {}}
            logger.error(f'Failed to read secrets from S3: {e}')
            raise

    def _decrypt_secrets(self, encrypted_data: str) -> dict:
        """Decrypt secrets using KMS envelope encryption.

        Args:
            encrypted_data: JSON string with encrypted_key, nonce, ciphertext

        Returns:
            Decrypted secrets dict
        """
        if not self.kms:
            raise ValueError('KMS client not configured for secrets decryption')

        try:
            envelope = json.loads(encrypted_data)
            encrypted_key = base64.b64decode(envelope['encrypted_key'])
            nonce = base64.b64decode(envelope['nonce'])
            ciphertext = base64.b64decode(envelope['ciphertext'])

            # Decrypt the data key using KMS
            response = self.kms.decrypt(CiphertextBlob=encrypted_key)
            plaintext_key = response['Plaintext']

            # Decrypt the secrets using AES-256-GCM
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(plaintext_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            logger.error(f'Failed to decrypt secrets: {e}')
            raise

    def get_secret(self, secret_id: str) -> str | None:
        """Get a specific secret value.

        WARNING: This returns the plaintext secret value.
        Use only during conversation creation for sandbox injection.

        Args:
            secret_id: The secret identifier (e.g., 'github-token')

        Returns:
            The decrypted secret value or None if not found
        """
        try:
            data = self._get_secrets_data()
            secret_data = data.get('secrets', {}).get(secret_id)
            if secret_data:
                # SECURITY: Never log the actual secret value
                logger.info(f'Retrieved secret: {secret_id}')
                return secret_data.get('value')
            return None
        except Exception as e:
            logger.error(f'Failed to get secret {secret_id}: {e}')
            return None

    def resolve_secret_refs(self, env_vars: dict[str, str]) -> dict[str, str]:
        """Resolve secret references in environment variables.

        Replaces env vars like GITHUB_TOKEN_REF='secrets/github-token'
        with GITHUB_TOKEN=<actual_secret_value>

        Args:
            env_vars: Dictionary of environment variables

        Returns:
            Dictionary with resolved values
        """
        resolved = {}
        for key, value in env_vars.items():
            if isinstance(value, str) and value.startswith('secrets/'):
                secret_id = value.replace('secrets/', '')
                secret_value = self.get_secret(secret_id)
                if secret_value:
                    # Remove _REF suffix from key
                    resolved_key = key[:-4] if key.endswith('_REF') else key
                    resolved[resolved_key] = secret_value
                    # SECURITY: Log key name but never the value
                    logger.info(f'Resolved secret ref: {key} -> {resolved_key}')
                else:
                    logger.warning(f'Secret not found: {secret_id}')
            else:
                resolved[key] = value
        return resolved


# Integration -> MCP Server mapping for auto_mcp feature
INTEGRATION_MCP_MAP = {
    'github': {
        'name': 'github-mcp',
        'command': 'npx',
        'args': ['-y', '@modelcontextprotocol/server-github'],
        'env_key': 'GITHUB_TOKEN',
    },
    'slack': {
        'name': 'slack-mcp',
        'command': 'npx',
        'args': ['-y', '@modelcontextprotocol/server-slack'],
        'env_key': 'SLACK_BOT_TOKEN',
    },
    # Add more integrations as needed
}
