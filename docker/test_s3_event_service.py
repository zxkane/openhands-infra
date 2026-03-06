"""
Unit tests for S3EventService.

Tests verify:
- Event loading from S3 via FileStore
- Event storing to S3 via FileStore
- Path listing (search_paths)
- Error handling (FileNotFoundError, invalid JSON, exceptions)
- S3EventServiceInjector wiring

Run with: pytest docker/test_s3_event_service.py -v
"""

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# --- Mock OpenHands modules before importing module under test ---

class MockEvent:
    """Mock Event class that mimics Pydantic model behavior."""
    def __init__(self, id='abc123', kind='message', timestamp=None, **kwargs):
        self.id = id
        self.kind = kind
        self.timestamp = timestamp
        self._data = {'id': id, 'kind': kind, 'timestamp': timestamp, **kwargs}

    @classmethod
    def model_validate_json(cls, json_str):
        data = json.loads(json_str)
        return cls(**data)

    def model_dump(self, mode=None):
        return self._data


# Create proper dataclass base so @dataclass inheritance works
@dataclass
class MockEventServiceBase:
    prefix: Path
    user_id: str | None
    app_conversation_info_service: object
    app_conversation_info_load_tasks: dict


class MockEventService:
    pass


class MockFileStoreBase:
    pass


# Use Pydantic-like base for injector
class MockEventServiceInjector:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# Wire up all mock modules
sys.modules.setdefault('openhands', MagicMock())
sys.modules.setdefault('openhands.sdk', MagicMock())
sys.modules['openhands.sdk'].Event = MockEvent
sys.modules.setdefault('openhands.sdk.utils', MagicMock())
sys.modules.setdefault('openhands.sdk.utils.models', MagicMock())
sys.modules.setdefault('openhands.agent_server', MagicMock())
sys.modules.setdefault('openhands.agent_server.models', MagicMock())
sys.modules.setdefault('openhands.agent_server.sockets', MagicMock())
sys.modules.setdefault('openhands.app_server', MagicMock())
sys.modules.setdefault('openhands.app_server.config', MagicMock())
sys.modules.setdefault('openhands.app_server.event', MagicMock())

# Critical: set up event_service mock with proper base classes
event_service_mock = MagicMock()
event_service_mock.EventService = MockEventService
event_service_mock.EventServiceInjector = MockEventServiceInjector
sys.modules['openhands.app_server.event.event_service'] = event_service_mock

event_service_base_mock = MagicMock()
event_service_base_mock.EventServiceBase = MockEventServiceBase
sys.modules['openhands.app_server.event.event_service_base'] = event_service_base_mock

sys.modules.setdefault('openhands.app_server.event_callback', MagicMock())
sys.modules.setdefault('openhands.app_server.event_callback.event_callback_models', MagicMock())
sys.modules.setdefault('openhands.app_server.app_conversation', MagicMock())
sys.modules.setdefault('openhands.app_server.app_conversation.app_conversation_info_service', MagicMock())
sys.modules.setdefault('openhands.app_server.services', MagicMock())
sys.modules.setdefault('openhands.app_server.services.injector', MagicMock())
sys.modules.setdefault('openhands.app_server.user', MagicMock())
sys.modules.setdefault('openhands.app_server.user.user_context', MagicMock())

storage_mock = MagicMock()
sys.modules['openhands.storage'] = storage_mock

storage_files_mock = MagicMock()
storage_files_mock.FileStore = MockFileStoreBase
sys.modules['openhands.storage.files'] = storage_files_mock

sys.modules.setdefault('fastapi', MagicMock())

# Now import the module under test
from s3_event_service import S3EventService, S3EventServiceInjector


@dataclass
class MockFileStore:
    """Mock FileStore for testing S3EventService."""
    _files: dict = field(default_factory=dict)

    def read(self, path: str) -> str:
        if path not in self._files:
            raise FileNotFoundError(f'Not found: {path}')
        return self._files[path]

    def write(self, path: str, contents: str) -> None:
        self._files[path] = contents

    def list(self, path: str) -> list[str]:
        if not path.endswith('/'):
            path += '/'
        return [k for k in self._files if k.startswith(path)]


def _make_service(file_store, user_id='u1'):
    return S3EventService(
        prefix=Path('users'), user_id=user_id,
        app_conversation_info_service=None,
        app_conversation_info_load_tasks={},
        file_store=file_store,
    )


class TestS3EventServiceLoadEvent:
    """Tests for S3EventService._load_event."""

    def test_load_event_returns_event(self):
        """Should deserialize event JSON from S3."""
        event_data = json.dumps({'id': 'event-1', 'kind': 'message'})
        file_store = MockFileStore(_files={
            'users/u1/v1_conversations/abc/event1.json': event_data
        })
        service = _make_service(file_store)
        event = service._load_event(Path('users/u1/v1_conversations/abc/event1.json'))
        assert event is not None
        assert event.id == 'event-1'
        assert event.kind == 'message'

    def test_load_event_returns_none_when_not_found(self):
        """Should return None when S3 object doesn't exist."""
        service = _make_service(MockFileStore())
        event = service._load_event(Path('users/u1/v1_conversations/abc/missing.json'))
        assert event is None

    def test_load_event_returns_none_on_invalid_json(self):
        """Should return None when S3 object contains invalid JSON."""
        file_store = MockFileStore(_files={'bad.json': 'not valid json {'})
        service = _make_service(file_store)
        event = service._load_event(Path('bad.json'))
        assert event is None


class TestS3EventServiceStoreEvent:
    """Tests for S3EventService._store_event."""

    def test_store_event_writes_json(self):
        """Should serialize event to JSON and write to S3."""
        file_store = MockFileStore()
        service = _make_service(file_store)
        event = MockEvent(id='evt-1', kind='action')
        path = Path('users/u1/v1_conversations/abc/evt1.json')
        service._store_event(path, event)

        assert str(path) in file_store._files
        stored_data = json.loads(file_store._files[str(path)])
        assert stored_data['id'] == 'evt-1'
        assert stored_data['kind'] == 'action'

    def test_store_event_overwrites_existing(self):
        """Should overwrite existing event at the same path."""
        file_store = MockFileStore(_files={'path.json': '{"id": "old"}'})
        service = _make_service(file_store)
        event = MockEvent(id='new')
        service._store_event(Path('path.json'), event)

        stored_data = json.loads(file_store._files['path.json'])
        assert stored_data['id'] == 'new'

    def test_store_event_raises_on_write_failure(self):
        """Should re-raise exceptions from file_store.write."""
        file_store = MagicMock()
        file_store.write.side_effect = RuntimeError('S3 write error')
        service = _make_service(file_store)
        event = MockEvent(id='fail')
        with pytest.raises(RuntimeError, match='S3 write error'):
            service._store_event(Path('fail.json'), event)


class TestS3EventServiceSearchPaths:
    """Tests for S3EventService._search_paths."""

    def test_search_paths_returns_matching_keys(self):
        """Should list all objects under the prefix."""
        file_store = MockFileStore(_files={
            'users/u1/v1_conversations/abc/e1.json': '{}',
            'users/u1/v1_conversations/abc/e2.json': '{}',
            'users/u1/v1_conversations/def/e3.json': '{}',
        })
        service = _make_service(file_store)
        paths = service._search_paths(Path('users/u1/v1_conversations/abc'))
        assert len(paths) == 2
        assert all(str(p).startswith('users/u1/v1_conversations/abc/') for p in paths)

    def test_search_paths_returns_empty_when_no_events(self):
        """Should return empty list when no events exist."""
        service = _make_service(MockFileStore())
        paths = service._search_paths(Path('users/u1/v1_conversations/abc'))
        assert paths == []

    def test_search_paths_handles_file_not_found(self):
        """Should return empty list on FileNotFoundError."""
        file_store = MagicMock()
        file_store.list.side_effect = FileNotFoundError('No such prefix')
        service = _make_service(file_store)
        paths = service._search_paths(Path('nonexistent'))
        assert paths == []

    def test_search_paths_handles_generic_exception(self):
        """Should return empty list on unexpected errors."""
        file_store = MagicMock()
        file_store.list.side_effect = RuntimeError('S3 error')
        service = _make_service(file_store)
        paths = service._search_paths(Path('prefix'))
        assert paths == []


class TestS3EventServiceIsolation:
    """Tests verifying user isolation in event storage paths."""

    def test_different_users_have_different_prefixes(self):
        """Events for different users should be stored under different prefixes."""
        file_store = MockFileStore()
        service_a = _make_service(file_store, user_id='user-a')
        service_b = _make_service(file_store, user_id='user-b')

        event_a = MockEvent(id='a')
        event_b = MockEvent(id='b')
        service_a._store_event(Path('users/user-a/v1_conversations/conv1/e1.json'), event_a)
        service_b._store_event(Path('users/user-b/v1_conversations/conv1/e1.json'), event_b)

        assert 'users/user-a/v1_conversations/conv1/e1.json' in file_store._files
        assert 'users/user-b/v1_conversations/conv1/e1.json' in file_store._files
        data_a = json.loads(file_store._files['users/user-a/v1_conversations/conv1/e1.json'])
        data_b = json.loads(file_store._files['users/user-b/v1_conversations/conv1/e1.json'])
        assert data_a['id'] == 'a'
        assert data_b['id'] == 'b'


class TestS3EventServiceInjector:
    """Tests for S3EventServiceInjector configuration."""

    def test_injector_has_bucket_name(self):
        """Should accept bucket_name parameter."""
        injector = S3EventServiceInjector(bucket_name='my-bucket')
        assert injector.bucket_name == 'my-bucket'

    def test_injector_default_prefix(self):
        """Should default prefix to 'users'."""
        injector = S3EventServiceInjector(bucket_name='my-bucket')
        assert injector.prefix == Path('users')

    def test_injector_custom_prefix(self):
        """Should accept custom prefix."""
        injector = S3EventServiceInjector(bucket_name='my-bucket', prefix=Path('custom'))
        assert injector.prefix == Path('custom')


class TestRoundTrip:
    """Tests for store-then-load round-trip."""

    def test_store_then_load_preserves_event(self):
        """Storing and loading an event should preserve its data."""
        file_store = MockFileStore()
        service = _make_service(file_store)
        original = MockEvent(id='round-trip', kind='observation')
        path = Path('users/u1/v1_conversations/c1/rt.json')

        service._store_event(path, original)
        loaded = service._load_event(path)

        assert loaded is not None
        assert loaded.id == 'round-trip'
        assert loaded.kind == 'observation'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
