"""
S3-backed EventService for V1 conversation event persistence.

This module provides an EventService implementation that stores conversation events
in S3 instead of the container's ephemeral filesystem. This solves:

1. ARCHIVED conversations losing history (S3 persists after EFS cleanup)
2. Resumed conversations losing events after app task replacement
3. Events unavailable when sandbox is stopped

S3 Path Structure:
    users/{user_id}/v1_conversations/{conv_id_hex}/{event_id_hex}.json

This follows the same path convention as FilesystemEventServiceBase.get_conversation_path()
and is consistent with other user-scoped S3 stores (settings, secrets, conversations).

Design:
- Follows GoogleCloudEventService pattern exactly (same base class, same injector pattern)
- Uses OpenHands FileStore abstraction (already configured for S3 via FILE_STORE=s3)
- No direct boto3 usage — delegates to FileStore.read/write/list
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncGenerator

from fastapi import Request

from openhands.app_server.config import get_app_conversation_info_service
from openhands.app_server.event.event_service import EventService, EventServiceInjector
from openhands.app_server.event.event_service_base import EventServiceBase
from openhands.app_server.services.injector import InjectorState
from openhands.sdk import Event
from openhands.storage import get_file_store
from openhands.storage.files import FileStore

_logger = logging.getLogger(__name__)


@dataclass
class S3EventService(EventServiceBase):
    """S3-backed implementation of EventService using OpenHands FileStore."""

    file_store: FileStore

    def _load_event(self, path: Path) -> Event | None:
        try:
            return Event.model_validate_json(self.file_store.read(str(path)))
        except FileNotFoundError:
            return None
        except Exception:
            _logger.exception('Error reading event from %s', path)
            return None

    def _store_event(self, path: Path, event: Event):
        try:
            data = event.model_dump(mode='json')
            self.file_store.write(str(path), json.dumps(data, indent=2))
        except Exception:
            _logger.exception('Error writing event to %s', path)
            raise

    def _search_paths(self, prefix: Path, _page_id: str | None = None) -> list[Path]:
        try:
            keys = self.file_store.list(str(prefix))
            return [Path(key) for key in keys]
        except FileNotFoundError:
            return []
        except Exception:
            _logger.exception('Error listing events under %s', prefix)
            return []


class S3EventServiceInjector(EventServiceInjector):
    bucket_name: str
    prefix: Path = Path('users')

    async def inject(
        self, state: InjectorState, request: Request | None = None
    ) -> AsyncGenerator[EventService, None]:
        from openhands.app_server.config import get_user_context

        async with (
            get_user_context(state, request) as user_context,
            get_app_conversation_info_service(
                state, request
            ) as app_conversation_info_service,
        ):
            user_id = await user_context.get_user_id()

            file_store = get_file_store(
                file_store_type='s3',
                file_store_path=self.bucket_name,
            )

            yield S3EventService(
                prefix=self.prefix,
                user_id=user_id,
                app_conversation_info_service=app_conversation_info_service,
                file_store=file_store,
                app_conversation_info_load_tasks={},
            )
