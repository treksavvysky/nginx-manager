"""
Unit tests for the two-step login flow with TOTP 2FA.

Tests the login endpoint (POST /auth/login) which returns either a session
token or a 2FA challenge, and the verify-2fa endpoint (POST /auth/verify-2fa)
which completes the 2FA handshake.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from httpx import ASGITransport, AsyncClient

from main import app
from models.auth import AuthContext, Role, User

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MOCK_USER = User(id="usr-123", username="testuser", role=Role.ADMIN)
MOCK_OPERATOR_USER = User(id="usr-456", username="opsuser", role=Role.OPERATOR)


def _make_auth_ctx(role: Role = Role.ADMIN, user_id: str = "usr-123") -> AuthContext:
    return AuthContext(user_id=user_id, role=role, auth_method="user")


def _make_user_service(*, auth_ctx: AuthContext | None = None, totp_enabled: bool = False, user: User = MOCK_USER):
    svc = MagicMock()
    if auth_ctx is not None:
        svc.authenticate = AsyncMock(return_value=(auth_ctx, totp_enabled))
    else:
        svc.authenticate = AsyncMock(return_value=None)
    svc.get_user = AsyncMock(return_value=user)
    return svc


def _make_auth_service(
    *,
    jwt_token: tuple[str, int] = ("session-token-abc", 3600),
    challenge_token: tuple[str, int] = ("challenge-tok-xyz", 300),
    decode_result: dict | None = None,
):
    svc = MagicMock()
    svc.create_jwt_token = MagicMock(return_value=jwt_token)
    svc.create_challenge_token = MagicMock(return_value=challenge_token)
    svc.decode_token_payload = MagicMock(return_value=decode_result)
    return svc


def _make_session_service():
    svc = MagicMock()
    svc.create_session = AsyncMock()
    return svc


def _make_totp_service(*, verified: bool = True):
    svc = MagicMock()
    svc.verify_totp = AsyncMock(return_value=verified)
    return svc


def _make_settings(**overrides):
    defaults = {
        "totp_enforce_admin": True,
        "totp_enforce_operator": False,
    }
    defaults.update(overrides)
    s = MagicMock(**defaults)
    return s


# ---------------------------------------------------------------------------
# TestTwoStepLogin
# ---------------------------------------------------------------------------


class TestTwoStepLogin:
    """Tests for the POST /auth/login and POST /auth/verify-2fa endpoints."""

    @pytest.mark.asyncio
    async def test_login_no_2fa_returns_session_token(self):
        """When 2FA is not enabled, login returns a session token directly."""
        auth_ctx = _make_auth_ctx()
        mock_user_svc = _make_user_service(auth_ctx=auth_ctx, totp_enabled=False)
        mock_auth_svc = _make_auth_service(
            jwt_token=("session-token-abc", 3600),
            decode_result={"jti": "abc", "purpose": "session"},
        )
        mock_session_svc = _make_session_service()

        with (
            patch("endpoints.users.get_user_service", return_value=mock_user_svc),
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
            patch("core.session_service.get_session_service", return_value=mock_session_svc),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/auth/login", json={"username": "testuser", "password": "secret"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["requires_2fa"] is False
        assert data["access_token"] == "session-token-abc"
        assert data["challenge_token"] is None
        assert data["expires_in"] == 3600

    @pytest.mark.asyncio
    async def test_login_with_2fa_returns_challenge_token(self):
        """When 2FA is enabled, login returns a challenge token with requires_2fa=True."""
        auth_ctx = _make_auth_ctx()
        mock_user_svc = _make_user_service(auth_ctx=auth_ctx, totp_enabled=True)
        mock_auth_svc = _make_auth_service(challenge_token=("challenge-tok-xyz", 300))

        with (
            patch("endpoints.users.get_user_service", return_value=mock_user_svc),
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/auth/login", json={"username": "testuser", "password": "secret"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["requires_2fa"] is True
        assert data["challenge_token"] == "challenge-tok-xyz"
        assert data["expires_in"] == 300

    @pytest.mark.asyncio
    async def test_login_invalid_credentials_returns_401(self):
        """Invalid credentials yield a 401 response."""
        mock_user_svc = _make_user_service(auth_ctx=None)

        with patch("endpoints.users.get_user_service", return_value=mock_user_svc):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/auth/login", json={"username": "bad", "password": "wrong"})

        assert resp.status_code == 401
        assert "Invalid" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_verify_2fa_valid_code(self):
        """A valid TOTP code after a challenge token returns a session token."""
        mock_auth_svc = _make_auth_service(
            jwt_token=("final-session-token", 3600),
            decode_result={"purpose": "2fa_challenge", "user_id": "usr-123", "role": "admin"},
        )
        mock_totp_svc = _make_totp_service(verified=True)
        mock_session_svc = _make_session_service()
        mock_user_svc = _make_user_service(auth_ctx=_make_auth_ctx())

        with (
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
            patch("core.totp_service.get_totp_service", return_value=mock_totp_svc),
            patch("core.session_service.get_session_service", return_value=mock_session_svc),
            patch("endpoints.users.get_user_service", return_value=mock_user_svc),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/auth/verify-2fa",
                    json={"challenge_token": "some-challenge-token", "totp_code": "123456"},
                )

        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "final-session-token"
        assert data["expires_in"] == 3600
        assert data.get("requires_2fa", False) is False

    @pytest.mark.asyncio
    async def test_verify_2fa_invalid_code_returns_401(self):
        """An invalid TOTP code returns a 401 response."""
        mock_auth_svc = _make_auth_service(
            decode_result={"purpose": "2fa_challenge", "user_id": "usr-123", "role": "admin"},
        )
        mock_totp_svc = _make_totp_service(verified=False)

        with (
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
            patch("core.totp_service.get_totp_service", return_value=mock_totp_svc),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/auth/verify-2fa",
                    json={"challenge_token": "some-challenge-token", "totp_code": "000000"},
                )

        assert resp.status_code == 401
        assert "Invalid TOTP" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_verify_2fa_expired_challenge_returns_401(self):
        """An expired / invalid challenge token returns a 401 response."""
        mock_auth_svc = _make_auth_service(decode_result=None)

        with patch("endpoints.users.get_auth_service", return_value=mock_auth_svc):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/auth/verify-2fa",
                    json={"challenge_token": "expired-token", "totp_code": "123456"},
                )

        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower() or "Invalid" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# TestEnforcementWarnings
# ---------------------------------------------------------------------------


class TestEnforcementWarnings:
    """Tests for soft 2FA enforcement warnings in the login response."""

    @pytest.mark.asyncio
    async def test_admin_without_2fa_gets_warning(self):
        """An admin user without 2FA gets totp_setup_required=True when enforcement is on."""
        auth_ctx = _make_auth_ctx(role=Role.ADMIN)
        mock_user_svc = _make_user_service(auth_ctx=auth_ctx, totp_enabled=False, user=MOCK_USER)
        mock_auth_svc = _make_auth_service(
            jwt_token=("admin-session-tok", 3600),
            decode_result={"jti": "jti-admin", "purpose": "session"},
        )
        mock_session_svc = _make_session_service()
        mock_settings = _make_settings(totp_enforce_admin=True, totp_enforce_operator=False)

        with (
            patch("endpoints.users.get_user_service", return_value=mock_user_svc),
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
            patch("core.session_service.get_session_service", return_value=mock_session_svc),
            patch("config.settings", mock_settings),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/auth/login", json={"username": "testuser", "password": "secret"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["totp_setup_required"] is True

    @pytest.mark.asyncio
    async def test_operator_no_enforcement_no_warning(self):
        """An operator user with enforcement disabled gets totp_setup_required=False."""
        auth_ctx = _make_auth_ctx(role=Role.OPERATOR, user_id="usr-456")
        mock_user_svc = _make_user_service(auth_ctx=auth_ctx, totp_enabled=False, user=MOCK_OPERATOR_USER)
        mock_auth_svc = _make_auth_service(
            jwt_token=("ops-session-tok", 3600),
            decode_result={"jti": "jti-ops", "purpose": "session"},
        )
        mock_session_svc = _make_session_service()
        mock_settings = _make_settings(totp_enforce_admin=True, totp_enforce_operator=False)

        with (
            patch("endpoints.users.get_user_service", return_value=mock_user_svc),
            patch("endpoints.users.get_auth_service", return_value=mock_auth_svc),
            patch("core.session_service.get_session_service", return_value=mock_session_svc),
            patch("config.settings", mock_settings),
        ):
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/auth/login", json={"username": "opsuser", "password": "secret"})

        assert resp.status_code == 200
        data = resp.json()
        assert data["totp_setup_required"] is False
