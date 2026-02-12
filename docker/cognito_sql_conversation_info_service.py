"""
Cognito-aware SQL Conversation Info Service for OpenHands Multi-Tenant Isolation

This module extends SQLAppConversationInfoService to add user_id filtering for
multi-tenant conversation isolation. In the OSS v1.3.0, conversation metadata is
stored in PostgreSQL but without user_id scoping. This means all users see all
conversations.

This custom service:
  - Dynamically adds a user_id column to StoredConversationMetadata (idempotent)
  - Overrides _secure_select() to filter by user_id
  - Overrides save_app_conversation_info() to persist user_id
  - Overrides _to_info() to return the real created_by_user_id
  - Overrides count_app_conversation_info() and delete_app_conversation_info()
    to scope operations to the current user

Follows the same pattern as cognito_user_auth.py, s3_settings_store.py, and
s3_secrets_store.py - a custom module wired in via sed in apply-patch.sh.

If upstream ever adds user_id to StoredConversationMetadata, the hasattr check
makes this a no-op.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import AsyncGenerator
from uuid import UUID

from fastapi import Request
from sqlalchemy import Column, String, func, select, delete as sa_delete

from openhands.app_server.app_conversation.app_conversation_info_service import (
    AppConversationInfoService,
    AppConversationInfoServiceInjector,
)
from openhands.app_server.app_conversation.app_conversation_models import (
    AppConversationInfo,
)
from openhands.app_server.app_conversation.sql_app_conversation_info_service import (
    SQLAppConversationInfoService,
    SQLAppConversationInfoServiceInjector,
    StoredConversationMetadata,
)
from openhands.app_server.services.injector import InjectorState
from openhands.app_server.user.user_context import UserContext

logger = logging.getLogger(__name__)

# Dynamically add user_id column to StoredConversationMetadata if not present.
# This is a standard SQLAlchemy pattern for extending models without forking.
# If upstream ever adds user_id, the hasattr check makes this a no-op.
if not hasattr(StoredConversationMetadata, 'user_id'):
    StoredConversationMetadata.user_id = Column(
        'user_id', String, nullable=True, index=True
    )
    logger.info(
        'CognitoSQL: Added user_id column to StoredConversationMetadata model'
    )


@dataclass
class CognitoSQLAppConversationInfoService(SQLAppConversationInfoService):
    """SQL conversation info service with user_id-based multi-tenant isolation.

    Extends SQLAppConversationInfoService to:
    - Filter conversations by user_id in all queries
    - Persist user_id when saving conversation info
    - Return real created_by_user_id from database
    """

    async def _secure_select(self):
        """Override to add user_id filter for multi-tenant isolation.

        When a user_id is available from user_context, adds WHERE user_id = ?
        to scope all queries to the current user's conversations.

        When user_id is None (internal/admin calls), returns all V1 conversations
        (same behavior as upstream).
        """
        query = select(StoredConversationMetadata).where(
            StoredConversationMetadata.conversation_version == 'V1'
        )

        try:
            user_id = await self.user_context.get_user_id()
        except Exception:
            user_id = None

        if user_id:
            query = query.where(StoredConversationMetadata.user_id == user_id)

        return query

    async def save_app_conversation_info(
        self, info: AppConversationInfo
    ) -> AppConversationInfo:
        """Override to persist user_id in conversation metadata.

        Calls the parent save method, then updates the stored record with user_id
        from the AppConversationInfo.created_by_user_id field.
        """
        # Let parent handle the core save logic
        result = await super().save_app_conversation_info(info)

        # Update user_id if available
        user_id = info.created_by_user_id
        if user_id:
            try:
                query = select(StoredConversationMetadata).where(
                    StoredConversationMetadata.conversation_id == str(info.id)
                )
                db_result = await self.db_session.execute(query)
                stored = db_result.scalar_one_or_none()
                if stored:
                    stored.user_id = user_id
                    await self.db_session.commit()
                    logger.debug(
                        'CognitoSQL: Saved user_id=%s for conversation %s',
                        user_id,
                        info.id,
                    )
            except Exception:
                logger.exception(
                    'CognitoSQL: Failed to update user_id for conversation %s',
                    info.id,
                )

        return result

    def _to_info(
        self,
        stored: StoredConversationMetadata,
        sub_conversation_ids: list[UUID] | None = None,
    ) -> AppConversationInfo:
        """Override to return real created_by_user_id from database.

        The upstream implementation returns created_by_user_id=None because
        user_id is delegated to SaaS-only ConversationMetadataSaas layer.
        We read the user_id column we added to the model.
        """
        info = super()._to_info(stored, sub_conversation_ids=sub_conversation_ids)

        # Override the created_by_user_id with the actual value from database
        user_id = getattr(stored, 'user_id', None)
        if user_id:
            info.created_by_user_id = user_id

        return info

    async def count_app_conversation_info(
        self,
        title__contains: str | None = None,
        created_at__gte=None,
        created_at__lt=None,
        updated_at__gte=None,
        updated_at__lt=None,
    ) -> int:
        """Override to scope count to current user's conversations."""
        query = select(
            func.count(StoredConversationMetadata.conversation_id)
        ).where(StoredConversationMetadata.conversation_version == 'V1')

        # Add user_id filter
        try:
            user_id = await self.user_context.get_user_id()
        except Exception:
            user_id = None

        if user_id:
            query = query.where(StoredConversationMetadata.user_id == user_id)

        query = self._apply_filters(
            query=query,
            title__contains=title__contains,
            created_at__gte=created_at__gte,
            created_at__lt=created_at__lt,
            updated_at__gte=updated_at__gte,
            updated_at__lt=updated_at__lt,
        )

        result = await self.db_session.execute(query)
        count = result.scalar()
        return count or 0

    async def delete_app_conversation_info(self, conversation_id: UUID) -> bool:
        """Override to scope deletion to current user's conversations.

        Prevents cross-user deletion by adding user_id filter to the DELETE query.
        """
        delete_query = sa_delete(StoredConversationMetadata).where(
            StoredConversationMetadata.conversation_id == str(conversation_id)
        )

        # Add user_id filter for safety
        try:
            user_id = await self.user_context.get_user_id()
        except Exception:
            user_id = None

        if user_id:
            delete_query = delete_query.where(
                StoredConversationMetadata.user_id == user_id
            )

        result = await self.db_session.execute(delete_query)
        return result.rowcount > 0


class CognitoSQLAppConversationInfoServiceInjector(
    AppConversationInfoServiceInjector
):
    """Dependency injection resolver that creates CognitoSQLAppConversationInfoService.

    Identical to SQLAppConversationInfoServiceInjector but instantiates the
    Cognito-aware service class for multi-tenant isolation.
    """

    async def inject(
        self, state: InjectorState, request: Request | None = None
    ) -> AsyncGenerator[AppConversationInfoService, None]:
        # Define inline to prevent circular lookup (same pattern as upstream)
        from openhands.app_server.config import (
            get_db_session,
            get_user_context,
        )

        async with (
            get_user_context(state, request) as user_context,
            get_db_session(state, request) as db_session,
        ):
            service = CognitoSQLAppConversationInfoService(
                db_session=db_session, user_context=user_context
            )
            yield service
