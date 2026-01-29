"""
Unit tests for user management endpoints.

Tests login, user CRUD, and password change endpoints.
"""

from datetime import datetime

import pytest

# --- Model Validation Tests ---


class TestUserCreateValidation:
    """Test UserCreateRequest validation."""

    def test_valid_user_create(self):
        from models.auth import UserCreateRequest

        req = UserCreateRequest(
            username="validuser",
            password="SecurePass123!",
            email="user@example.com",
        )
        assert req.username == "validuser"

    def test_username_too_short(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="ab", password="SecurePass123!")

    def test_username_invalid_chars(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="user name", password="SecurePass123!")

    def test_username_special_chars_allowed(self):
        from models.auth import UserCreateRequest

        req = UserCreateRequest(
            username="user.name-1_test",
            password="SecurePass123!",
        )
        assert req.username == "user.name-1_test"

    def test_password_too_short(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="validuser", password="Short1!")

    def test_password_no_uppercase(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="validuser", password="nouppercase123!")

    def test_password_no_lowercase(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="validuser", password="NOLOWERCASE123!")

    def test_password_no_digit(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(username="validuser", password="NoDigitsHere!!")

    def test_valid_email(self):
        from models.auth import UserCreateRequest

        req = UserCreateRequest(
            username="validuser",
            password="SecurePass123!",
            email="valid@example.com",
        )
        assert req.email == "valid@example.com"

    def test_invalid_email(self):
        from models.auth import UserCreateRequest

        with pytest.raises(Exception):
            UserCreateRequest(
                username="validuser",
                password="SecurePass123!",
                email="not-an-email",
            )

    def test_empty_email_becomes_none(self):
        from models.auth import UserCreateRequest

        req = UserCreateRequest(
            username="validuser",
            password="SecurePass123!",
            email="",
        )
        assert req.email is None


class TestPasswordChangeValidation:
    """Test PasswordChangeRequest validation."""

    def test_valid_password_change(self):
        from models.auth import PasswordChangeRequest

        req = PasswordChangeRequest(
            current_password="OldPassword123!",
            new_password="NewPassword456!",
        )
        assert req.new_password == "NewPassword456!"

    def test_new_password_too_short(self):
        from models.auth import PasswordChangeRequest

        with pytest.raises(Exception):
            PasswordChangeRequest(
                current_password="OldPassword123!",
                new_password="Short1!",
            )

    def test_new_password_no_uppercase(self):
        from models.auth import PasswordChangeRequest

        with pytest.raises(Exception):
            PasswordChangeRequest(
                current_password="OldPassword123!",
                new_password="nouppercase123!",
            )


class TestLoginRequestModel:
    """Test LoginRequest model."""

    def test_valid_login(self):
        from models.auth import LoginRequest

        req = LoginRequest(username="admin", password="test")
        assert req.username == "admin"


# --- User Model Tests ---


class TestUserModel:
    """Test User model properties."""

    def test_user_not_locked(self):
        from models.auth import User

        user = User(username="test")
        assert user.is_locked is False

    def test_user_locked(self):
        from datetime import timedelta

        from models.auth import User

        user = User(
            username="test",
            locked_until=datetime.utcnow() + timedelta(minutes=10),
        )
        assert user.is_locked is True

    def test_user_lockout_expired(self):
        from datetime import timedelta

        from models.auth import User

        user = User(
            username="test",
            locked_until=datetime.utcnow() - timedelta(minutes=1),
        )
        assert user.is_locked is False

    def test_user_id_prefix(self):
        from models.auth import User

        user = User(username="test")
        assert user.id.startswith("usr-")


# --- Role Hierarchy Tests (with users) ---


class TestRoleWithUsers:
    """Test that role hierarchy works for user-related auth."""

    def test_admin_can_manage_users(self):
        from models.auth import Role

        assert Role.ADMIN.has_permission(Role.ADMIN) is True

    def test_operator_cannot_manage_users(self):
        from models.auth import Role

        assert Role.OPERATOR.has_permission(Role.ADMIN) is False

    def test_viewer_cannot_manage_users(self):
        from models.auth import Role

        assert Role.VIEWER.has_permission(Role.ADMIN) is False


# --- Login Response Tests ---


class TestLoginResponse:
    """Test LoginResponse model."""

    def test_login_response_has_suggestions(self):
        from models.auth import LoginResponse, Role, User

        resp = LoginResponse(
            access_token="tok",
            expires_in=3600,
            role=Role.ADMIN,
            user=User(username="admin"),
        )
        assert len(resp.suggestions) > 0
        assert any("Bearer" in s["action"] for s in resp.suggestions)


# --- UserListResponse Tests ---


class TestUserListResponse:
    """Test UserListResponse model."""

    def test_empty_list(self):
        from models.auth import UserListResponse

        resp = UserListResponse(users=[], total=0)
        assert resp.total == 0

    def test_with_users(self):
        from models.auth import User, UserListResponse

        users = [User(username="a"), User(username="b")]
        resp = UserListResponse(users=users, total=2)
        assert resp.total == 2
        assert len(resp.users) == 2
