"""
Unit tests for auth service.

Tests API key creation, validation, and revocation.
"""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timedelta

from core.auth_service import AuthService, KEY_PREFIX
from models.auth import Role, AuthContext


class TestAuthServiceKeyGeneration:
    """Test API key generation."""

    def test_generate_key_format(self):
        """Generated keys have correct prefix and length."""
        key = AuthService._generate_key()
        assert key.startswith(KEY_PREFIX)
        assert len(key) == len(KEY_PREFIX) + 64  # 32 bytes = 64 hex chars

    def test_generate_key_unique(self):
        """Each generated key is unique."""
        keys = {AuthService._generate_key() for _ in range(100)}
        assert len(keys) == 100

    def test_hash_key_deterministic(self):
        """Same key always produces same hash."""
        key = "ngx_test123"
        h1 = AuthService._hash_key(key)
        h2 = AuthService._hash_key(key)
        assert h1 == h2

    def test_hash_key_different_for_different_keys(self):
        """Different keys produce different hashes."""
        h1 = AuthService._hash_key("ngx_key1")
        h2 = AuthService._hash_key("ngx_key2")
        assert h1 != h2


class TestAuthServiceCRUD:
    """Test API key CRUD operations."""

    @pytest.mark.asyncio
    async def test_create_api_key(self):
        """Test creating an API key."""
        mock_db = MagicMock()
        mock_db.insert = AsyncMock(return_value="key-123")

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            api_key, plaintext = await service.create_api_key(
                name="test-key",
                role=Role.OPERATOR,
            )

        assert api_key.name == "test-key"
        assert api_key.role == Role.OPERATOR
        assert api_key.is_active is True
        assert plaintext.startswith(KEY_PREFIX)
        mock_db.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_validate_api_key_valid(self):
        """Test validating a valid API key."""
        plaintext = AuthService._generate_key()
        key_hash = AuthService._hash_key(plaintext)

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={
            "id": "key-123",
            "key_hash": key_hash,
            "role": "operator",
            "is_active": True,
            "expires_at": None,
        })
        mock_db.execute = AsyncMock()

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            ctx = await service.validate_api_key(plaintext)

        assert ctx is not None
        assert ctx.api_key_id == "key-123"
        assert ctx.role == Role.OPERATOR
        assert ctx.auth_method == "api_key"

    @pytest.mark.asyncio
    async def test_validate_api_key_invalid(self):
        """Test validating an invalid API key returns None."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value=None)

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            ctx = await service.validate_api_key("ngx_invalid_key")

        assert ctx is None

    @pytest.mark.asyncio
    async def test_validate_api_key_no_prefix(self):
        """Test validating a key without prefix returns None."""
        mock_db = MagicMock()

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            ctx = await service.validate_api_key("no_prefix_key")

        assert ctx is None
        mock_db.fetch_one.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_api_key_inactive(self):
        """Test validating an inactive key returns None."""
        plaintext = AuthService._generate_key()
        key_hash = AuthService._hash_key(plaintext)

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={
            "id": "key-123",
            "key_hash": key_hash,
            "role": "operator",
            "is_active": False,
            "expires_at": None,
        })

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            ctx = await service.validate_api_key(plaintext)

        assert ctx is None

    @pytest.mark.asyncio
    async def test_validate_api_key_expired(self):
        """Test validating an expired key returns None."""
        plaintext = AuthService._generate_key()
        key_hash = AuthService._hash_key(plaintext)

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={
            "id": "key-123",
            "key_hash": key_hash,
            "role": "operator",
            "is_active": True,
            "expires_at": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
        })

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            ctx = await service.validate_api_key(plaintext)

        assert ctx is None

    @pytest.mark.asyncio
    async def test_revoke_api_key(self):
        """Test revoking an API key."""
        mock_db = MagicMock()
        mock_db.update = AsyncMock(return_value=True)

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            result = await service.revoke_api_key("key-123")

        assert result is True
        mock_db.update.assert_called_once_with(
            "api_keys", "key-123", {"is_active": False}
        )

    @pytest.mark.asyncio
    async def test_has_any_keys_empty(self):
        """Test has_any_keys returns False when no keys exist."""
        mock_db = MagicMock()
        mock_db.count = AsyncMock(return_value=0)

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            assert await service.has_any_keys() is False

    @pytest.mark.asyncio
    async def test_has_any_keys_present(self):
        """Test has_any_keys returns True when keys exist."""
        mock_db = MagicMock()
        mock_db.count = AsyncMock(return_value=3)

        with patch('core.auth_service.get_database', return_value=mock_db):
            service = AuthService()
            assert await service.has_any_keys() is True
