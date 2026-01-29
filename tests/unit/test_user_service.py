"""
Unit tests for user management service.

Tests user creation, authentication, password management,
and account lockout behavior.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

# --- Password Hashing Tests ---


class TestPasswordHashing:
    """Test bcrypt password hashing."""

    def test_hash_password_produces_bcrypt_hash(self):
        from core.user_service import UserService

        hashed = UserService._hash_password("TestPassword1!")
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
        assert len(hashed) == 60

    def test_verify_correct_password(self):
        from core.user_service import UserService

        hashed = UserService._hash_password("TestPassword1!")
        assert UserService._verify_password("TestPassword1!", hashed) is True

    def test_verify_wrong_password(self):
        from core.user_service import UserService

        hashed = UserService._hash_password("TestPassword1!")
        assert UserService._verify_password("WrongPassword1!", hashed) is False

    def test_different_hashes_for_same_password(self):
        """bcrypt generates unique salts each time."""
        from core.user_service import UserService

        h1 = UserService._hash_password("TestPassword1!")
        h2 = UserService._hash_password("TestPassword1!")
        assert h1 != h2


# --- User Creation Tests ---


class TestUserCreation:
    """Test user account creation."""

    @pytest.mark.asyncio
    async def test_create_user_success(self):
        from core.user_service import UserService
        from models.auth import Role

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=None)
        service.db.insert = AsyncMock()

        user = await service.create_user(
            username="testuser",
            password="SecurePass123!",
            role=Role.OPERATOR,
            email="test@example.com",
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.failed_login_attempts == 0
        service.db.insert.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self):
        from core.user_service import UserService, UserServiceError

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value={"id": "existing"})

        with pytest.raises(UserServiceError, match="already exists"):
            await service.create_user(
                username="duplicate",
                password="SecurePass123!",
            )

    @pytest.mark.asyncio
    async def test_create_user_generates_id(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=None)
        service.db.insert = AsyncMock()

        user = await service.create_user(
            username="newuser",
            password="SecurePass123!",
        )

        assert user.id.startswith("usr-")
        assert len(user.id) > 4


# --- Authentication Tests ---


class TestAuthentication:
    """Test user authentication with lockout."""

    def _make_user_row(self, **overrides):
        from core.user_service import UserService

        defaults = {
            "id": "usr-test123",
            "username": "testuser",
            "email": None,
            "password_hash": UserService._hash_password("SecurePass123!"),
            "role": "operator",
            "is_active": True,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "password_changed_at": None,
            "failed_login_attempts": 0,
            "locked_until": None,
        }
        defaults.update(overrides)
        return defaults

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row())
        service.db.update = AsyncMock(return_value=True)

        auth_ctx = await service.authenticate("testuser", "SecurePass123!")
        assert auth_ctx is not None
        assert auth_ctx.user_id == "usr-test123"
        assert auth_ctx.auth_method == "user"

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row())
        service.db.update = AsyncMock(return_value=True)

        auth_ctx = await service.authenticate("testuser", "WrongPassword1!")
        assert auth_ctx is None

    @pytest.mark.asyncio
    async def test_authenticate_increments_failed_attempts(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row())
        service.db.update = AsyncMock(return_value=True)

        await service.authenticate("testuser", "WrongPassword1!")

        # Check that update was called with incremented failed_login_attempts
        call_args = service.db.update.call_args
        assert call_args[0][0] == "users"  # table
        update_data = call_args[0][2]  # data dict
        assert update_data["failed_login_attempts"] == 1

    @pytest.mark.asyncio
    async def test_authenticate_lockout_after_max_failures(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row(failed_login_attempts=4))
        service.db.update = AsyncMock(return_value=True)

        await service.authenticate("testuser", "WrongPassword1!")

        call_args = service.db.update.call_args
        update_data = call_args[0][2]
        assert update_data["failed_login_attempts"] == 5
        assert "locked_until" in update_data

    @pytest.mark.asyncio
    async def test_authenticate_rejected_when_locked(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        locked_until = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row(locked_until=locked_until))

        auth_ctx = await service.authenticate("testuser", "SecurePass123!")
        assert auth_ctx is None

    @pytest.mark.asyncio
    async def test_authenticate_expired_lockout_resets(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        expired_lockout = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
        service.db.fetch_one = AsyncMock(
            return_value=self._make_user_row(
                locked_until=expired_lockout,
                failed_login_attempts=5,
            )
        )
        service.db.update = AsyncMock(return_value=True)
        service.db.execute = AsyncMock()

        auth_ctx = await service.authenticate("testuser", "SecurePass123!")
        assert auth_ctx is not None

    @pytest.mark.asyncio
    async def test_authenticate_inactive_user(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=self._make_user_row(is_active=False))

        auth_ctx = await service.authenticate("testuser", "SecurePass123!")
        assert auth_ctx is None

    @pytest.mark.asyncio
    async def test_authenticate_nonexistent_user(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=None)

        auth_ctx = await service.authenticate("noone", "SecurePass123!")
        assert auth_ctx is None


# --- Password Change Tests ---


class TestPasswordChange:
    """Test password change functionality."""

    @pytest.mark.asyncio
    async def test_change_password_success(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        password_hash = UserService._hash_password("OldPassword123!")
        service.db.fetch_one = AsyncMock(
            return_value={
                "id": "usr-1",
                "password_hash": password_hash,
            }
        )
        service.db.update = AsyncMock(return_value=True)

        result = await service.change_password("usr-1", "OldPassword123!", "NewPassword456!")
        assert result is True

    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        password_hash = UserService._hash_password("OldPassword123!")
        service.db.fetch_one = AsyncMock(
            return_value={
                "id": "usr-1",
                "password_hash": password_hash,
            }
        )

        result = await service.change_password("usr-1", "WrongCurrent1!", "NewPassword456!")
        assert result is False

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(self):
        from core.user_service import UserService, UserServiceError

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=None)

        with pytest.raises(UserServiceError, match="not found"):
            await service.change_password("usr-nonexistent", "Old1!", "New1!")


# --- User CRUD Tests ---


class TestUserCRUD:
    """Test user list, get, update, delete operations."""

    @pytest.mark.asyncio
    async def test_list_users(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_all = AsyncMock(
            return_value=[
                {
                    "id": "usr-1",
                    "username": "admin",
                    "email": None,
                    "role": "admin",
                    "is_active": True,
                    "created_at": datetime.utcnow().isoformat(),
                    "last_login": None,
                    "password_changed_at": None,
                    "failed_login_attempts": 0,
                    "locked_until": None,
                },
            ]
        )

        users = await service.list_users()
        assert len(users) == 1
        assert users[0].username == "admin"

    @pytest.mark.asyncio
    async def test_get_user_by_id(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(
            return_value={
                "id": "usr-1",
                "username": "testuser",
                "email": "test@test.com",
                "role": "operator",
                "is_active": True,
                "created_at": datetime.utcnow().isoformat(),
                "last_login": None,
                "password_changed_at": None,
                "failed_login_attempts": 0,
                "locked_until": None,
            }
        )

        user = await service.get_user("usr-1")
        assert user is not None
        assert user.username == "testuser"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.fetch_one = AsyncMock(return_value=None)

        user = await service.get_user("usr-nonexistent")
        assert user is None

    @pytest.mark.asyncio
    async def test_delete_user(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.delete = AsyncMock(return_value=True)

        result = await service.delete_user("usr-1")
        assert result is True
        service.db.delete.assert_called_once_with("users", "usr-1")

    @pytest.mark.asyncio
    async def test_has_any_users_empty(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.count = AsyncMock(return_value=0)

        result = await service.has_any_users()
        assert result is False

    @pytest.mark.asyncio
    async def test_has_any_users_populated(self):
        from core.user_service import UserService

        service = UserService()
        service.db = MagicMock()
        service.db.count = AsyncMock(return_value=3)

        result = await service.has_any_users()
        assert result is True
