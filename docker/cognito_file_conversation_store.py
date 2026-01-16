"""
Cognito-aware File Conversation Store for OpenHands

This module extends FileConversationStore to store conversations under
user-specific paths in S3: users/{user_id}/conversations/{conversation_id}/

This enables per-user conversation persistence when using Cognito authentication.
"""

import logging
from dataclasses import dataclass, field

from openhands.core.config.openhands_config import OpenHandsConfig
from openhands.storage import get_file_store
from openhands.storage.conversation.file_conversation_store import FileConversationStore
from openhands.storage.data_models.conversation_metadata import ConversationMetadata
from openhands.storage.data_models.conversation_metadata_result_set import (
    ConversationMetadataResultSet,
)
from openhands.storage.files import FileStore
from openhands.storage.locations import (
    get_conversation_metadata_filename,
)
from openhands.utils.async_utils import call_sync_from_async
from openhands.utils.search_utils import offset_to_page_id, page_id_to_offset

logger = logging.getLogger(__name__)


@dataclass
class CognitoFileConversationStore(FileConversationStore):
    """File-based conversation store with user-specific storage paths.

    When a user_id is provided, conversations are stored under:
        users/{user_id}/conversations/{conversation_id}/

    When no user_id is provided (anonymous), falls back to:
        sessions/{conversation_id}/
    """

    file_store: FileStore
    user_id: str | None = field(default=None)

    def get_conversation_metadata_dir(self) -> str:
        """Get the directory containing all conversations for this user.

        Returns:
            For authenticated users: 'users/{user_id}/conversations'
            For anonymous users: 'sessions'
        """
        if self.user_id:
            return f'users/{self.user_id}/conversations'
        return 'sessions'

    def get_conversation_metadata_filename(self, conversation_id: str) -> str:
        """Get the full path to a conversation's metadata file.

        Args:
            conversation_id: The unique conversation identifier.

        Returns:
            Full path to metadata.json file.
        """
        return get_conversation_metadata_filename(conversation_id, self.user_id)

    async def search(
        self,
        page_id: str | None = None,
        limit: int = 20,
    ) -> ConversationMetadataResultSet:
        """Search conversations for the current user.

        Args:
            page_id: Pagination cursor.
            limit: Maximum results to return.

        Returns:
            ConversationMetadataResultSet with matching conversations.
        """
        conversations: list[ConversationMetadata] = []
        metadata_dir = self.get_conversation_metadata_dir()

        logger.info(f"CognitoFileConversationStore.search: dir={metadata_dir}, user_id={self.user_id}")

        try:
            # List all conversation directories
            paths = self.file_store.list(metadata_dir)
            conversation_ids = [
                path.rstrip('/').split('/')[-1]
                for path in paths
                if not path.split('/')[-1].startswith('.') and path.rstrip('/') != metadata_dir
            ]
            logger.info(f"CognitoFileConversationStore: found {len(conversation_ids)} conversations")
        except FileNotFoundError:
            logger.info(f"CognitoFileConversationStore: no conversations found at {metadata_dir}")
            return ConversationMetadataResultSet([])

        num_conversations = len(conversation_ids)
        start = page_id_to_offset(page_id)
        end = min(limit + start, num_conversations)

        for conversation_id in conversation_ids:
            try:
                conversations.append(await self.get_metadata(conversation_id))
            except Exception as e:
                logger.warning(f'Could not load conversation metadata: {conversation_id}: {e}')

        # Sort by created_at descending
        conversations.sort(key=lambda c: c.created_at or '', reverse=True)
        conversations = conversations[start:end]
        next_page_id = offset_to_page_id(end, end < num_conversations)

        return ConversationMetadataResultSet(conversations, next_page_id)

    @classmethod
    async def get_instance(
        cls, config: OpenHandsConfig, user_id: str | None
    ) -> 'CognitoFileConversationStore':
        """Create a conversation store instance for the given user.

        Args:
            config: OpenHands configuration.
            user_id: The authenticated user's ID (Cognito sub).

        Returns:
            A CognitoFileConversationStore instance configured for the user.
        """
        logger.info(f"CognitoFileConversationStore.get_instance: user_id={user_id}")

        file_store = get_file_store(
            file_store_type=config.file_store,
            file_store_path=config.file_store_path,
            file_store_web_hook_url=config.file_store_web_hook_url,
            file_store_web_hook_headers=config.file_store_web_hook_headers,
            file_store_web_hook_batch=config.file_store_web_hook_batch,
        )

        store = cls(file_store=file_store, user_id=user_id)
        logger.info(f"CognitoFileConversationStore: Created store for user {user_id}")
        return store
