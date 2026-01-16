"""
Cognito User Authentication for OpenHands

This module provides user authentication via AWS Cognito, integrating with
Lambda@Edge which injects verified user information as HTTP headers.

Security Note:
    The x-cognito-* headers are set by Lambda@Edge after JWT verification.
    CloudFront VPC Origin ensures only Lambda@Edge processed requests reach
    the ALB, preventing header spoofing from external sources.
"""

import logging
from dataclasses import dataclass

from fastapi import Request

from openhands.server.user_auth.default_user_auth import DefaultUserAuth
from openhands.server.user_auth.user_auth import UserAuth

logger = logging.getLogger(__name__)


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
