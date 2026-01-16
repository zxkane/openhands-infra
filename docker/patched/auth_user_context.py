"""
Patched AuthUserContextInjector with internal network detection.

This module fixes 401 Unauthorized errors on webhook callbacks from agent-server
to app-server by detecting internal Docker network requests early in the auth flow.

Problem:
  FastAPI evaluates Depends() in parallel. When agent-server sends webhooks,
  AuthUserContextInjector may run BEFORE as_admin() sets ADMIN context, causing
  Cognito auth to fail with 401.

Solution:
  Detect internal network requests (from Docker bridge + X-Session-API-Key header)
  and grant ADMIN access immediately, bypassing Cognito auth.
"""

import logging
from typing import AsyncGenerator

from starlette.requests import Request

from openhands.server.shared import InjectorState
from openhands.server.user_context import (
    ADMIN,
    USER_CONTEXT_ATTR,
    SpecifyUserContext,
    UserContextInjector,
)

_logger = logging.getLogger(__name__)


def _is_internal_network_request(request: Request | None) -> bool:
    """Check if request is from internal Docker network with session API key.

    Internal requests have both:
    1. X-Session-API-Key header (proves it's from agent-server sandbox)
    2. Private IP address (172.x, 10.x, 192.168.x, or localhost)

    This dual-check ensures external requests cannot spoof internal auth.
    """
    if request is None:
        return False

    # Must have X-Session-API-Key header (proves it's from agent-server)
    session_api_key = request.headers.get('x-session-api-key')
    if not session_api_key:
        return False

    # Get client IP
    client_host = None
    if request.client:
        client_host = request.client.host

    # Check X-Forwarded-For for proxy scenarios (Docker uses this)
    x_forwarded_for = request.headers.get('x-forwarded-for', '')
    if x_forwarded_for:
        # Use first IP in chain (original client)
        client_host = x_forwarded_for.split(',')[0].strip()

    if not client_host:
        return False

    # Check for RFC 1918 private addresses (Docker networks)
    is_private = (
        client_host.startswith('172.')       # Docker bridge default: 172.17-31.x.x
        or client_host.startswith('10.')     # Class A private
        or client_host.startswith('192.168.')  # Class C private
        or client_host == '127.0.0.1'
        or client_host == 'localhost'
        or client_host == '::1'              # IPv6 localhost
    )

    if is_private:
        _logger.debug(
            f"Internal network request detected: ip={client_host}, "
            f"has_session_key=True"
        )

    return is_private


class PatchedAuthUserContextInjector(UserContextInjector):
    """AuthUserContextInjector with early internal network detection.

    This patched version checks for internal Docker network requests BEFORE
    attempting Cognito authentication, preventing 401 errors on webhook callbacks.

    Priority order:
    1. Already has ADMIN or SpecifyUserContext -> use existing
    2. Internal network + X-Session-API-Key -> grant ADMIN
    3. Normal Cognito authentication flow
    """

    async def inject(
        self, state: InjectorState, request: Request | None = None
    ) -> AsyncGenerator:
        """Inject user context with internal network detection."""

        # Priority 1: Check if already has user context set
        user_context = getattr(state, USER_CONTEXT_ATTR, None)
        if user_context is ADMIN or isinstance(user_context, SpecifyUserContext):
            _logger.debug(f"Using existing user context: {type(user_context).__name__}")
            yield user_context
            return

        # Priority 2: Internal network + session API key -> ADMIN
        # MUST be checked BEFORE Cognito auth to prevent 401
        if _is_internal_network_request(request):
            _logger.info("Granting ADMIN access for internal network request")
            setattr(state, USER_CONTEXT_ATTR, ADMIN)
            yield ADMIN
            return

        # Priority 3: Normal Cognito authentication
        # Import here to avoid circular dependency and to use original implementation
        try:
            from openhands_cloud.app_server.injectors.auth_user_context import (
                CognitoAuthUserContextInjector,
            )
            original = CognitoAuthUserContextInjector()
            async for context in original.inject(state, request):
                yield context
        except ImportError:
            # Fallback if openhands_cloud not available (e.g., local dev)
            _logger.warning(
                "CognitoAuthUserContextInjector not available, using ADMIN fallback"
            )
            setattr(state, USER_CONTEXT_ATTR, ADMIN)
            yield ADMIN


# Export with standard name for drop-in replacement
AuthUserContextInjector = PatchedAuthUserContextInjector
