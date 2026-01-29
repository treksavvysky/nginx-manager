"""
Unit tests for rate limiting configuration.

Tests rate limiter key generation and configuration.
"""

from unittest.mock import MagicMock

import pytest


class TestRateLimiterKeyGeneration:
    """Test rate limit key generation."""

    def test_key_from_ip_only(self):
        """Unauthenticated request uses IP as key."""
        from core.rate_limiter import _get_client_key

        mock_request = MagicMock()
        mock_request.client.host = "192.168.1.1"
        mock_request.headers = {}

        key = _get_client_key(mock_request)
        assert key == "192.168.1.1"

    def test_key_includes_api_key_prefix(self):
        """API key request includes key prefix in bucket."""
        from core.rate_limiter import _get_client_key

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"X-API-Key": "ngx_abcdef123456789012345"}

        key = _get_client_key(mock_request)
        assert key == "10.0.0.1:ngx_abcdef12"

    def test_key_for_jwt_bearer(self):
        """JWT bearer request uses jwt tag."""
        from core.rate_limiter import _get_client_key

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.2"
        mock_request.headers = {
            "X-API-Key": "",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.test",
        }

        key = _get_client_key(mock_request)
        assert key == "10.0.0.2:jwt"

    def test_different_ips_different_keys(self):
        """Different client IPs produce different keys."""
        from core.rate_limiter import _get_client_key

        req1 = MagicMock()
        req1.client.host = "10.0.0.1"
        req1.headers = {}

        req2 = MagicMock()
        req2.client.host = "10.0.0.2"
        req2.headers = {}

        assert _get_client_key(req1) != _get_client_key(req2)

    def test_same_ip_different_keys_with_api_key(self):
        """Same IP but different API keys produce different keys."""
        from core.rate_limiter import _get_client_key

        req1 = MagicMock()
        req1.client.host = "10.0.0.1"
        req1.headers = {"X-API-Key": "ngx_aaaaaaaaaaaa"}

        req2 = MagicMock()
        req2.client.host = "10.0.0.1"
        req2.headers = {"X-API-Key": "ngx_bbbbbbbbbbbb"}

        assert _get_client_key(req1) != _get_client_key(req2)


class TestRateLimiterInstance:
    """Test limiter instance configuration."""

    def test_limiter_exists(self):
        """Global limiter instance is available."""
        from core.rate_limiter import limiter

        assert limiter is not None

    def test_default_limits_set(self):
        """Default rate limits are configured."""
        from core.rate_limiter import (
            DEFAULT_RATE_AUTH,
            DEFAULT_RATE_MUTATION,
            DEFAULT_RATE_READ,
            DEFAULT_RATE_UNAUTH,
        )

        assert "60" in DEFAULT_RATE_AUTH
        assert "10" in DEFAULT_RATE_UNAUTH
        assert "30" in DEFAULT_RATE_MUTATION
        assert "120" in DEFAULT_RATE_READ


class TestEventAuditFields:
    """Test event model audit fields."""

    def test_event_with_audit_fields(self):
        """Event model accepts audit fields."""
        from models.event import Event

        event = Event(
            category="config",
            action="created",
            message="Site created",
            client_ip="192.168.1.1",
            user_id="user-123",
            api_key_id="key-456",
        )
        assert event.client_ip == "192.168.1.1"
        assert event.user_id == "user-123"
        assert event.api_key_id == "key-456"

    def test_event_audit_fields_optional(self):
        """Audit fields default to None."""
        from models.event import Event

        event = Event(
            category="system",
            action="startup",
            message="System started",
        )
        assert event.client_ip is None
        assert event.user_id is None
        assert event.api_key_id is None


class TestEventStoreAudit:
    """Test event store audit recording."""

    @pytest.mark.asyncio
    async def test_record_event_with_audit_fields(self):
        """record_event stores audit fields."""
        from unittest.mock import AsyncMock, patch

        from core.event_store import EventStore

        mock_db = MagicMock()
        mock_db.insert = AsyncMock()

        with patch("core.event_store.get_database", return_value=mock_db):
            store = EventStore()
            event = await store.record_event(
                category="config",
                action="created",
                message="Site created",
                client_ip="10.0.0.1",
                api_key_id="key-abc",
            )

        assert event.client_ip == "10.0.0.1"
        assert event.api_key_id == "key-abc"

        # Verify the data passed to db.insert includes audit fields
        insert_data = mock_db.insert.call_args[0][1]
        assert insert_data["client_ip"] == "10.0.0.1"
        assert insert_data["api_key_id"] == "key-abc"

    @pytest.mark.asyncio
    async def test_record_api_event_extracts_context(self):
        """record_api_event extracts fields from AuthContext."""
        from unittest.mock import AsyncMock, patch

        from core.event_store import EventStore
        from models.auth import AuthContext, Role

        mock_db = MagicMock()
        mock_db.insert = AsyncMock()

        auth_ctx = AuthContext(
            api_key_id="key-test",
            role=Role.OPERATOR,
            auth_method="api_key",
            client_ip="192.168.1.100",
        )

        with patch("core.event_store.get_database", return_value=mock_db):
            store = EventStore()
            event = await store.record_api_event(
                category="config",
                action="updated",
                message="Site updated",
                auth_context=auth_ctx,
            )

        assert event.client_ip == "192.168.1.100"
        assert event.api_key_id == "key-test"
