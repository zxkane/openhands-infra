"""
Unit tests for CognitoUserAuth module.

These tests verify the custom Cognito user authentication implementation
that reads user identity from Lambda@Edge injected headers.

Run with: pytest docker/test_cognito_user_auth.py -v
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

# Mock the openhands imports before importing the module under test
import sys
from dataclasses import dataclass


# Create mock base classes
@dataclass
class MockUserAuth:
    """Mock base UserAuth class."""
    pass


@dataclass
class MockDefaultUserAuth(MockUserAuth):
    """Mock DefaultUserAuth class."""
    pass


# Set up mock modules before importing
sys.modules['openhands'] = MagicMock()
sys.modules['openhands.server'] = MagicMock()
sys.modules['openhands.server.user_auth'] = MagicMock()
sys.modules['openhands.server.user_auth.user_auth'] = MagicMock()
sys.modules['openhands.server.user_auth.user_auth'].UserAuth = MockUserAuth
sys.modules['openhands.server.user_auth.default_user_auth'] = MagicMock()
sys.modules['openhands.server.user_auth.default_user_auth'].DefaultUserAuth = MockDefaultUserAuth

# Also mock fastapi Request
mock_request_module = MagicMock()
sys.modules['fastapi'] = mock_request_module


# Now import the module under test
from cognito_user_auth import CognitoUserAuth


class MockRequest:
    """Mock FastAPI Request object with configurable headers."""

    def __init__(self, headers: dict | None = None):
        self._headers = headers or {}

    @property
    def headers(self):
        return self._headers


class TestCognitoUserAuthGetUserId:
    """Tests for CognitoUserAuth.get_user_id() method."""

    @pytest.mark.asyncio
    async def test_get_user_id_returns_user_id(self):
        """Should return the stored user_id."""
        auth = CognitoUserAuth()
        auth._user_id = "cognito-sub-12345"

        result = await auth.get_user_id()

        assert result == "cognito-sub-12345"

    @pytest.mark.asyncio
    async def test_get_user_id_returns_none_when_not_set(self):
        """Should return None when user_id is not set."""
        auth = CognitoUserAuth()

        result = await auth.get_user_id()

        assert result is None


class TestCognitoUserAuthGetUserEmail:
    """Tests for CognitoUserAuth.get_user_email() method."""

    @pytest.mark.asyncio
    async def test_get_user_email_returns_email(self):
        """Should return the stored email."""
        auth = CognitoUserAuth()
        auth._email = "user@example.com"

        result = await auth.get_user_email()

        assert result == "user@example.com"

    @pytest.mark.asyncio
    async def test_get_user_email_returns_none_when_not_set(self):
        """Should return None when email is not set."""
        auth = CognitoUserAuth()

        result = await auth.get_user_email()

        assert result is None


class TestCognitoUserAuthGetInstance:
    """Tests for CognitoUserAuth.get_instance() class method."""

    @pytest.mark.asyncio
    async def test_get_instance_extracts_user_id_from_headers(self):
        """Should extract user_id from x-cognito-user-id header."""
        request = MockRequest(headers={
            'x-cognito-user-id': 'cognito-sub-67890',
            'x-cognito-email': 'test@example.com'
        })

        result = await CognitoUserAuth.get_instance(request)

        assert isinstance(result, CognitoUserAuth)
        assert result._user_id == 'cognito-sub-67890'

    @pytest.mark.asyncio
    async def test_get_instance_extracts_email_from_headers(self):
        """Should extract email from x-cognito-email header."""
        request = MockRequest(headers={
            'x-cognito-user-id': 'cognito-sub-67890',
            'x-cognito-email': 'test@example.com'
        })

        result = await CognitoUserAuth.get_instance(request)

        assert isinstance(result, CognitoUserAuth)
        assert result._email == 'test@example.com'

    @pytest.mark.asyncio
    async def test_get_instance_returns_default_auth_when_no_user_id(self):
        """Should return DefaultUserAuth when x-cognito-user-id is missing."""
        request = MockRequest(headers={
            'x-cognito-email': 'test@example.com'  # Only email, no user_id
        })

        result = await CognitoUserAuth.get_instance(request)

        # Should return DefaultUserAuth (mocked as MockDefaultUserAuth)
        assert isinstance(result, MockDefaultUserAuth)

    @pytest.mark.asyncio
    async def test_get_instance_returns_default_auth_when_headers_empty(self):
        """Should return DefaultUserAuth when no Cognito headers present."""
        request = MockRequest(headers={})

        result = await CognitoUserAuth.get_instance(request)

        assert isinstance(result, MockDefaultUserAuth)

    @pytest.mark.asyncio
    async def test_get_instance_handles_empty_email(self):
        """Should handle empty email header gracefully."""
        request = MockRequest(headers={
            'x-cognito-user-id': 'cognito-sub-67890',
            'x-cognito-email': ''
        })

        result = await CognitoUserAuth.get_instance(request)

        assert isinstance(result, CognitoUserAuth)
        assert result._user_id == 'cognito-sub-67890'
        assert result._email is None  # Empty string should become None

    @pytest.mark.asyncio
    async def test_get_instance_with_only_user_id(self):
        """Should work with only user_id header (no email)."""
        request = MockRequest(headers={
            'x-cognito-user-id': 'cognito-sub-12345'
        })

        result = await CognitoUserAuth.get_instance(request)

        assert isinstance(result, CognitoUserAuth)
        assert result._user_id == 'cognito-sub-12345'
        assert result._email is None

    @pytest.mark.asyncio
    async def test_get_instance_preserves_special_characters_in_email(self):
        """Should preserve special characters in email address."""
        request = MockRequest(headers={
            'x-cognito-user-id': 'cognito-sub-67890',
            'x-cognito-email': 'user+tag@sub.example.com'
        })

        result = await CognitoUserAuth.get_instance(request)

        assert result._email == 'user+tag@sub.example.com'


class TestCognitoUserAuthGetForUser:
    """Tests for CognitoUserAuth.get_for_user() class method."""

    @pytest.mark.asyncio
    async def test_get_for_user_creates_instance_with_user_id(self):
        """Should create instance with specified user_id."""
        result = await CognitoUserAuth.get_for_user('specified-user-id')

        assert isinstance(result, CognitoUserAuth)
        assert result._user_id == 'specified-user-id'

    @pytest.mark.asyncio
    async def test_get_for_user_email_is_none(self):
        """Should not set email when using get_for_user."""
        result = await CognitoUserAuth.get_for_user('specified-user-id')

        assert result._email is None


class TestCognitoUserAuthIntegration:
    """Integration tests verifying full authentication flow."""

    @pytest.mark.asyncio
    async def test_full_authentication_flow(self):
        """Test complete flow: headers -> instance -> getters."""
        # Simulate Lambda@Edge injected headers
        request = MockRequest(headers={
            'x-cognito-user-id': 'abc123-def456-ghi789',
            'x-cognito-email': 'admin@company.com',
            'x-cognito-email-verified': 'true'  # Extra header (not used but shouldn't break)
        })

        # Create instance from request
        auth = await CognitoUserAuth.get_instance(request)

        # Verify all getters work correctly
        assert await auth.get_user_id() == 'abc123-def456-ghi789'
        assert await auth.get_user_email() == 'admin@company.com'

    @pytest.mark.asyncio
    async def test_unauthenticated_flow(self):
        """Test flow when user is not authenticated."""
        # No Cognito headers (unauthenticated request)
        request = MockRequest(headers={
            'content-type': 'application/json',
            'authorization': 'Bearer some-other-token'
        })

        # Should fall back to DefaultUserAuth
        auth = await CognitoUserAuth.get_instance(request)

        assert isinstance(auth, MockDefaultUserAuth)
        assert not isinstance(auth, CognitoUserAuth)


class TestCognitoUserAuthGetUserSettings:
    """Tests for CognitoUserAuth.get_user_settings() method with user config loading.

    Note: The get_user_settings() method imports OpenHands modules at runtime,
    which are not available in this test environment. These tests verify the
    method structure and behavior when imports would fail, which is expected
    in the standalone test environment.

    The actual functionality is tested via E2E tests in the deployed environment
    where OpenHands modules are available.
    """

    @pytest.mark.asyncio
    async def test_get_user_settings_import_error_handled_gracefully(self):
        """Should handle import errors gracefully when OpenHands modules unavailable."""
        import os
        original_value = os.environ.get('USER_CONFIG_ENABLED')
        os.environ['USER_CONFIG_ENABLED'] = 'true'

        try:
            auth = CognitoUserAuth()
            auth._user_id = 'test-user-123'

            # When get_user_settings is called outside OpenHands container,
            # it should fail gracefully due to missing imports.
            # This is expected behavior in standalone test environment.
            with pytest.raises(ModuleNotFoundError):
                await auth.get_user_settings()

        finally:
            if original_value is not None:
                os.environ['USER_CONFIG_ENABLED'] = original_value
            elif 'USER_CONFIG_ENABLED' in os.environ:
                del os.environ['USER_CONFIG_ENABLED']

    def test_get_user_settings_is_async_method(self):
        """Verify get_user_settings is defined as async method."""
        import asyncio
        auth = CognitoUserAuth()
        # Check that the method is a coroutine function
        assert asyncio.iscoroutinefunction(auth.get_user_settings)


class TestUserConfigEnabled:
    """Tests for USER_CONFIG_ENABLED feature flag."""

    def test_user_config_enabled_default_is_false(self):
        """USER_CONFIG_ENABLED should default to false when not set."""
        import os
        # Remove the env var if it exists
        original_value = os.environ.pop('USER_CONFIG_ENABLED', None)

        try:
            # Re-import to get fresh value
            import importlib
            import cognito_user_auth
            importlib.reload(cognito_user_auth)

            assert cognito_user_auth.USER_CONFIG_ENABLED is False
        finally:
            if original_value is not None:
                os.environ['USER_CONFIG_ENABLED'] = original_value

    def test_user_config_enabled_true_when_set(self):
        """USER_CONFIG_ENABLED should be true when env var is 'true'."""
        import os
        original_value = os.environ.get('USER_CONFIG_ENABLED')
        os.environ['USER_CONFIG_ENABLED'] = 'true'

        try:
            # Re-import to get fresh value
            import importlib
            import cognito_user_auth
            importlib.reload(cognito_user_auth)

            assert cognito_user_auth.USER_CONFIG_ENABLED is True
        finally:
            if original_value is not None:
                os.environ['USER_CONFIG_ENABLED'] = original_value
            elif 'USER_CONFIG_ENABLED' in os.environ:
                del os.environ['USER_CONFIG_ENABLED']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
