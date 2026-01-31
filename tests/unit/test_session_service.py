"""
Unit tests for session service.

Tests JWT session creation, revocation, listing, checking, and cleanup.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.session_service import SessionService


class TestSessionCreation:
    """Test session creation."""

    @pytest.mark.asyncio
    async def test_create_session_calls_insert(self):
        """Verify db.insert called with correct fields."""
        mock_db = MagicMock()
        mock_db.insert = AsyncMock(return_value="session-id")

        expires = datetime.utcnow() + timedelta(hours=1)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            await service.create_session(jti="jti-abc", user_id="user-1", expires_at=expires)

        mock_db.insert.assert_called_once()
        call_args = mock_db.insert.call_args
        assert call_args[0][0] == "sessions"
        record = call_args[0][1]
        assert record["id"] == "jti-abc"
        assert record["user_id"] == "user-1"
        assert record["expires_at"] == expires.isoformat()
        assert record["is_revoked"] is False
        assert record["revoked_at"] is None
        assert record["ip_address"] is None
        assert record["user_agent"] is None

    @pytest.mark.asyncio
    async def test_create_session_with_optional_fields(self):
        """ip_address and user_agent are stored when provided."""
        mock_db = MagicMock()
        mock_db.insert = AsyncMock(return_value="session-id")

        expires = datetime.utcnow() + timedelta(hours=1)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            await service.create_session(
                jti="jti-xyz",
                user_id="user-2",
                expires_at=expires,
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
            )

        record = mock_db.insert.call_args[0][1]
        assert record["ip_address"] == "192.168.1.100"
        assert record["user_agent"] == "Mozilla/5.0"


class TestSessionRevocation:
    """Test session revocation."""

    @pytest.mark.asyncio
    async def test_revoke_session(self):
        """db.update called with is_revoked=True."""
        mock_db = MagicMock()
        mock_db.update = AsyncMock(return_value=True)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.revoke_session("jti-revoke")

        assert result is True
        mock_db.update.assert_called_once()
        call_args = mock_db.update.call_args[0]
        assert call_args[0] == "sessions"
        assert call_args[1] == "jti-revoke"
        update_fields = call_args[2]
        assert update_fields["is_revoked"] is True
        assert "revoked_at" in update_fields

    @pytest.mark.asyncio
    async def test_revoke_all_user_sessions(self):
        """Mock db.connection + cursor.execute, verify UPDATE query."""
        mock_db = MagicMock()
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 3
        mock_conn.execute = AsyncMock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()

        @asynccontextmanager
        async def _mock_connection():
            yield mock_conn

        mock_db.connection = _mock_connection

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            count = await service.revoke_all_user_sessions("user-1")

        assert count == 3
        mock_conn.execute.assert_called_once()
        query = mock_conn.execute.call_args[0][0]
        assert "UPDATE sessions SET is_revoked = 1" in query
        assert "WHERE user_id = ?" in query
        assert "id != ?" not in query
        mock_conn.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_all_except_current(self):
        """Verify query includes 'AND id != ?' when except_jti is provided."""
        mock_db = MagicMock()
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 5
        mock_conn.execute = AsyncMock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()

        @asynccontextmanager
        async def _mock_connection():
            yield mock_conn

        mock_db.connection = _mock_connection

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            count = await service.revoke_all_user_sessions("user-1", except_jti="jti-keep")

        assert count == 5
        query = mock_conn.execute.call_args[0][0]
        params = mock_conn.execute.call_args[0][1]
        assert "AND id != ?" in query
        assert "jti-keep" in params


class TestSessionListing:
    """Test session listing."""

    @pytest.mark.asyncio
    async def test_list_active_sessions(self):
        """Mock db.fetch_all returns sessions, verify result."""
        mock_db = MagicMock()
        mock_rows = [
            {"id": "jti-1", "user_id": "user-1", "is_revoked": 0, "expires_at": "2099-01-01T00:00:00"},
            {"id": "jti-2", "user_id": "user-1", "is_revoked": 0, "expires_at": "2099-01-01T00:00:00"},
        ]
        mock_db.fetch_all = AsyncMock(return_value=mock_rows)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            sessions = await service.list_user_sessions("user-1")

        assert len(sessions) == 2
        assert sessions[0]["id"] == "jti-1"
        assert sessions[1]["id"] == "jti-2"
        mock_db.fetch_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_excludes_expired_and_revoked(self):
        """The SQL query filters out expired and revoked sessions."""
        mock_db = MagicMock()
        mock_db.fetch_all = AsyncMock(return_value=[])

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            await service.list_user_sessions("user-1")

        query = mock_db.fetch_all.call_args[0][0]
        assert "is_revoked = 0" in query
        assert "expires_at > ?" in query


class TestSessionChecks:
    """Test session checking methods."""

    @pytest.mark.asyncio
    async def test_is_revoked_true(self):
        """db.fetch_one returns is_revoked=1, should return True."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"is_revoked": 1})

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.is_session_revoked("jti-revoked")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_revoked_false(self):
        """db.fetch_one returns is_revoked=0, should return False."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"is_revoked": 0})

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.is_session_revoked("jti-active")

        assert result is False

    @pytest.mark.asyncio
    async def test_is_revoked_unknown_session(self):
        """db.fetch_one returns None for unknown session, should return False (fail-open)."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value=None)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.is_session_revoked("jti-unknown")

        assert result is False

    @pytest.mark.asyncio
    async def test_get_session_found(self):
        """get_session returns dict when session exists."""
        mock_db = MagicMock()
        session_data = {
            "id": "jti-found",
            "user_id": "user-1",
            "is_revoked": 0,
            "expires_at": "2099-01-01T00:00:00",
        }
        mock_db.fetch_one = AsyncMock(return_value=session_data)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.get_session("jti-found")

        assert result is not None
        assert result["id"] == "jti-found"
        assert result["user_id"] == "user-1"

    @pytest.mark.asyncio
    async def test_get_session_not_found(self):
        """get_session returns None when session does not exist."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value=None)

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            result = await service.get_session("jti-missing")

        assert result is None


class TestSessionCleanup:
    """Test expired session cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self):
        """Mock db.connection, verify DELETE query and return count."""
        mock_db = MagicMock()
        mock_conn = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.rowcount = 7
        mock_conn.execute = AsyncMock(return_value=mock_cursor)
        mock_conn.commit = AsyncMock()

        @asynccontextmanager
        async def _mock_connection():
            yield mock_conn

        mock_db.connection = _mock_connection

        with patch("core.session_service.get_database", return_value=mock_db):
            service = SessionService()
            count = await service.cleanup_expired_sessions()

        assert count == 7
        query = mock_conn.execute.call_args[0][0]
        assert "DELETE FROM sessions" in query
        assert "expires_at < ?" in query
        mock_conn.commit.assert_called_once()
