"""
Unit tests for TOTP two-factor authentication endpoints.

Tests enrollment, confirmation, disable, status, and backup code regeneration.
Uses httpx AsyncClient with ASGITransport to test FastAPI endpoints.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from httpx import ASGITransport, AsyncClient

from core.auth_dependency import get_current_auth
from core.totp_service import TOTPServiceError
from main import app
from models.auth import AuthContext, Role, User

# Auth context with a user_id for endpoints that require a user account
MOCK_AUTH_WITH_USER = AuthContext(user_id="usr-test123", role=Role.ADMIN, auth_method="jwt")

# Auth context without a user_id (e.g. API key only auth)
MOCK_AUTH_NO_USER = AuthContext(user_id=None, role=Role.ADMIN, auth_method="api_key")


@pytest.fixture(autouse=True)
def _override_auth():
    """Override get_current_auth to return an admin context with user_id for all tests by default."""
    app.dependency_overrides[get_current_auth] = lambda: MOCK_AUTH_WITH_USER
    yield
    app.dependency_overrides.clear()


class TestEnrollment:
    """Tests for POST /auth/2fa/enroll endpoint."""

    @pytest.mark.asyncio
    async def test_enroll_returns_qr_and_backup_codes(self):
        """Successful enrollment returns secret, QR code, and backup codes."""
        mock_user = User(id="usr-test123", username="testuser", role=Role.ADMIN)
        mock_enroll_result = {
            "secret": "JBSWY3DPEHPK3PXP",
            "provisioning_uri": "otpauth://totp/NGINX%20Manager:testuser?secret=JBSWY3DPEHPK3PXP&issuer=NGINX+Manager",
            "qr_code_data_uri": "data:image/png;base64,iVBORw0KGgo=",
            "backup_codes": ["abc12345", "def67890", "ghi11111"],
        }

        mock_totp = MagicMock()
        mock_totp.enroll = AsyncMock(return_value=mock_enroll_result)

        mock_user_svc = MagicMock()
        mock_user_svc.get_user = AsyncMock(return_value=mock_user)

        with (
            patch("endpoints.totp.get_totp_service", return_value=mock_totp),
            patch("endpoints.totp.get_user_service", return_value=mock_user_svc),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/enroll")

        assert response.status_code == 200
        data = response.json()
        assert data["secret"] == "JBSWY3DPEHPK3PXP"
        assert data["qr_code_data_uri"] == "data:image/png;base64,iVBORw0KGgo="
        assert data["backup_codes"] == ["abc12345", "def67890", "ghi11111"]
        assert "message" in data

    @pytest.mark.asyncio
    async def test_enroll_already_enabled_returns_400(self):
        """Enrollment fails with 400 when 2FA is already enabled."""
        mock_user = User(id="usr-test123", username="testuser", role=Role.ADMIN)

        mock_totp = MagicMock()
        mock_totp.enroll = AsyncMock(side_effect=TOTPServiceError("2FA is already enabled for this user"))

        mock_user_svc = MagicMock()
        mock_user_svc.get_user = AsyncMock(return_value=mock_user)

        with (
            patch("endpoints.totp.get_totp_service", return_value=mock_totp),
            patch("endpoints.totp.get_user_service", return_value=mock_user_svc),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/enroll")

        assert response.status_code == 400
        assert "already enabled" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_enroll_requires_user_account(self):
        """Enrollment fails with 400 when auth context has no user_id."""
        app.dependency_overrides[get_current_auth] = lambda: MOCK_AUTH_NO_USER

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/auth/2fa/enroll")

        assert response.status_code == 400
        assert "user account" in response.json()["detail"].lower()


class TestConfirmation:
    """Tests for POST /auth/2fa/confirm endpoint."""

    @pytest.mark.asyncio
    async def test_confirm_valid_code(self):
        """Confirmation succeeds with a valid TOTP code."""
        mock_totp = MagicMock()
        mock_totp.confirm = AsyncMock(return_value=True)

        with patch("endpoints.totp.get_totp_service", return_value=mock_totp):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/confirm", json={"totp_code": "123456"})

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "active" in data["message"].lower()
        assert len(data["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_confirm_invalid_code_returns_400(self):
        """Confirmation fails with 400 when TOTP code is invalid."""
        mock_totp = MagicMock()
        mock_totp.confirm = AsyncMock(side_effect=TOTPServiceError("Invalid TOTP code. Please try again."))

        with patch("endpoints.totp.get_totp_service", return_value=mock_totp):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/confirm", json={"totp_code": "000000"})

        assert response.status_code == 400
        assert "invalid totp code" in response.json()["detail"].lower()


class TestDisable:
    """Tests for POST /auth/2fa/disable endpoint."""

    @pytest.mark.asyncio
    async def test_disable_success(self):
        """Disable succeeds with correct password when 2FA is enabled."""
        mock_db_row = {"password_hash": "hashed_pw", "totp_enabled": True}

        mock_user_svc = MagicMock()
        mock_user_svc.db = MagicMock()
        mock_user_svc.db.fetch_one = AsyncMock(return_value=mock_db_row)
        mock_user_svc._verify_password = MagicMock(return_value=True)

        mock_totp = MagicMock()
        mock_totp.disable = AsyncMock(return_value=True)

        with (
            patch("endpoints.totp.get_totp_service", return_value=mock_totp),
            patch("endpoints.totp.get_user_service", return_value=mock_user_svc),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/disable", json={"password": "TestPassword1"})

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "disabled" in data["message"].lower()
        mock_totp.disable.assert_awaited_once_with("usr-test123")

    @pytest.mark.asyncio
    async def test_disable_wrong_password_returns_400(self):
        """Disable fails with 400 when password is incorrect."""
        mock_db_row = {"password_hash": "hashed_pw", "totp_enabled": True}

        mock_user_svc = MagicMock()
        mock_user_svc.db = MagicMock()
        mock_user_svc.db.fetch_one = AsyncMock(return_value=mock_db_row)
        mock_user_svc._verify_password = MagicMock(return_value=False)

        with patch("endpoints.totp.get_user_service", return_value=mock_user_svc):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/disable", json={"password": "WrongPassword1"})

        assert response.status_code == 400
        assert "incorrect password" in response.json()["detail"].lower()


class TestStatus:
    """Tests for GET /auth/2fa/status endpoint."""

    @pytest.mark.asyncio
    async def test_status_returns_totp_state(self):
        """Status endpoint returns current TOTP state."""
        mock_status = {
            "enabled": True,
            "confirmed_at": "2026-01-15T10:30:00",
            "enforcement": "optional",
            "backup_codes_remaining": 8,
        }

        mock_totp = MagicMock()
        mock_totp.get_status = AsyncMock(return_value=mock_status)

        with patch("endpoints.totp.get_totp_service", return_value=mock_totp):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get("/auth/2fa/status")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is True
        assert data["enforcement"] == "optional"
        assert data["backup_codes_remaining"] == 8
        assert data["confirmed_at"] is not None

    @pytest.mark.asyncio
    async def test_status_no_user_returns_disabled(self):
        """Status endpoint returns disabled state when auth has no user_id."""
        app.dependency_overrides[get_current_auth] = lambda: MOCK_AUTH_NO_USER

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.get("/auth/2fa/status")

        assert response.status_code == 200
        data = response.json()
        assert data["enabled"] is False
        assert data["enforcement"] == "n/a"
        assert data["backup_codes_remaining"] == 0


class TestBackupCodeRegeneration:
    """Tests for POST /auth/2fa/backup-codes/regenerate endpoint."""

    @pytest.mark.asyncio
    async def test_regenerate_success(self):
        """Backup code regeneration succeeds with valid TOTP code."""
        new_codes = ["newcode01", "newcode02", "newcode03", "newcode04", "newcode05"]

        mock_totp = MagicMock()
        mock_totp.verify_totp = AsyncMock(return_value=True)
        mock_totp.regenerate_backup_codes = AsyncMock(return_value=new_codes)

        with patch("endpoints.totp.get_totp_service", return_value=mock_totp):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/backup-codes/regenerate", json={"totp_code": "123456"})

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["backup_codes"] == new_codes
        assert len(data["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_regenerate_invalid_code_returns_400(self):
        """Backup code regeneration fails with 400 when TOTP code is invalid."""
        mock_totp = MagicMock()
        mock_totp.verify_totp = AsyncMock(return_value=False)

        with patch("endpoints.totp.get_totp_service", return_value=mock_totp):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/auth/2fa/backup-codes/regenerate", json={"totp_code": "000000"})

        assert response.status_code == 400
        assert "invalid totp code" in response.json()["detail"].lower()
