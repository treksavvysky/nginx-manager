"""
Unit tests for JWT token authentication.

Tests JWT creation, validation, expiration, and token refresh flow.
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from core.auth_service import AuthService
from models.auth import AuthContext, Role


class TestJWTTokenCreation:
    """Test JWT token creation."""

    def test_create_token_returns_string_and_expiry(self):
        """create_jwt_token returns a token string and expiry seconds."""
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = "test-secret-key-for-jwt"
            mock_settings.jwt_algorithm = "HS256"
            mock_settings.jwt_expiry_minutes = 60

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = AuthContext(
                api_key_id="key-123",
                role=Role.OPERATOR,
                auth_method="api_key",
            )
            token, expires_in = service.create_jwt_token(ctx)

        assert isinstance(token, str)
        assert len(token) > 0
        assert expires_in == 3600  # 60 minutes

    def test_create_token_encodes_role(self):
        """Token payload contains the correct role."""
        secret = "test-secret"
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = secret
            mock_settings.jwt_algorithm = "HS256"
            mock_settings.jwt_expiry_minutes = 30

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = AuthContext(
                api_key_id="key-abc",
                role=Role.ADMIN,
                auth_method="api_key",
            )
            token, _ = service.create_jwt_token(ctx)

        payload = jwt.decode(token, secret, algorithms=["HS256"])
        assert payload["role"] == "admin"
        assert payload["api_key_id"] == "key-abc"
        assert payload["sub"] == "key-abc"

    def test_create_token_includes_user_id(self):
        """Token includes user_id when present."""
        secret = "test-secret"
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = secret
            mock_settings.jwt_algorithm = "HS256"
            mock_settings.jwt_expiry_minutes = 60

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = AuthContext(
                user_id="user-456",
                role=Role.VIEWER,
                auth_method="user",
            )
            token, _ = service.create_jwt_token(ctx)

        payload = jwt.decode(token, secret, algorithms=["HS256"])
        assert payload["user_id"] == "user-456"
        assert payload["sub"] == "user-456"
        assert "api_key_id" not in payload

    def test_create_token_raises_without_secret(self):
        """Raises ValueError if JWT_SECRET_KEY is not configured."""
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = None

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = AuthContext(role=Role.VIEWER, auth_method="api_key")

            with pytest.raises(ValueError, match="JWT_SECRET_KEY"):
                service.create_jwt_token(ctx)


class TestJWTTokenValidation:
    """Test JWT token validation."""

    def _make_token(self, secret, payload_overrides=None, algorithm="HS256"):
        """Helper to create a test JWT token."""
        payload = {
            "sub": "key-123",
            "role": "operator",
            "auth_method": "api_key",
            "api_key_id": "key-123",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1),
        }
        if payload_overrides:
            payload.update(payload_overrides)
        return jwt.encode(payload, secret, algorithm=algorithm)

    def test_validate_valid_token(self):
        """Valid token returns correct AuthContext."""
        secret = "test-validation-secret"
        token = self._make_token(secret)

        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = secret
            mock_settings.jwt_algorithm = "HS256"

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token(token)

        assert ctx is not None
        assert ctx.api_key_id == "key-123"
        assert ctx.role == Role.OPERATOR
        assert ctx.auth_method == "jwt"

    def test_validate_expired_token(self):
        """Expired token returns None."""
        secret = "test-secret"
        token = self._make_token(
            secret,
            {
                "exp": datetime.utcnow() - timedelta(hours=1),
            },
        )

        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = secret
            mock_settings.jwt_algorithm = "HS256"

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token(token)

        assert ctx is None

    def test_validate_wrong_secret(self):
        """Token signed with wrong secret returns None."""
        token = self._make_token("correct-secret")

        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = "wrong-secret"
            mock_settings.jwt_algorithm = "HS256"

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token(token)

        assert ctx is None

    def test_validate_malformed_token(self):
        """Malformed token string returns None."""
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = "test-secret"
            mock_settings.jwt_algorithm = "HS256"

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token("not.a.valid.jwt")

        assert ctx is None

    def test_validate_returns_none_without_secret(self):
        """Returns None if JWT_SECRET_KEY not configured."""
        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = None

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token("some.token.here")

        assert ctx is None

    def test_validate_token_with_user_id(self):
        """Token with user_id returns correct context."""
        secret = "test-secret"
        token = self._make_token(
            secret,
            {
                "sub": "user-789",
                "user_id": "user-789",
                "role": "admin",
                "auth_method": "user",
            },
        )

        with patch("core.auth_service.settings") as mock_settings:
            mock_settings.jwt_secret_key = secret
            mock_settings.jwt_algorithm = "HS256"

            mock_db = MagicMock()
            with patch("core.auth_service.get_database", return_value=mock_db):
                service = AuthService()

            ctx = service.validate_jwt_token(token)

        assert ctx is not None
        assert ctx.user_id == "user-789"
        assert ctx.role == Role.ADMIN


class TestBearerTokenExtraction:
    """Test bearer token extraction from auth dependency."""

    def test_extract_bearer_token(self):
        """Extracts Bearer token from Authorization header."""
        from core.auth_dependency import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "Bearer eyJtest"}
        assert _extract_bearer_token(mock_request) == "eyJtest"

    def test_extract_bearer_case_insensitive(self):
        """Bearer prefix is case-insensitive."""
        from core.auth_dependency import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "bearer eyJtest"}
        assert _extract_bearer_token(mock_request) == "eyJtest"

    def test_extract_no_auth_header(self):
        """Returns None when no Authorization header."""
        from core.auth_dependency import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers = {}
        assert _extract_bearer_token(mock_request) is None

    def test_extract_non_bearer_scheme(self):
        """Returns None for non-Bearer auth schemes."""
        from core.auth_dependency import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "Basic dXNlcjpwYXNz"}
        assert _extract_bearer_token(mock_request) is None

    def test_extract_malformed_header(self):
        """Returns None for malformed Authorization header."""
        from core.auth_dependency import _extract_bearer_token

        mock_request = MagicMock()
        mock_request.headers = {"Authorization": "JustAToken"}
        assert _extract_bearer_token(mock_request) is None


class TestAuthDependencyJWT:
    """Test get_current_auth with JWT tokens."""

    @pytest.mark.asyncio
    async def test_jwt_auth_succeeds(self):
        """Valid JWT Bearer token authenticates successfully."""
        from core.auth_dependency import get_current_auth

        expected_ctx = AuthContext(
            api_key_id="key-123",
            role=Role.OPERATOR,
            auth_method="jwt",
        )

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"Authorization": "Bearer valid.jwt.token"}

        mock_auth_service = MagicMock()
        mock_auth_service.validate_jwt_token = MagicMock(return_value=expected_ctx)

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with patch("core.auth_service.get_auth_service", return_value=mock_auth_service):
                ctx = await get_current_auth(mock_request, api_key=None)

        assert ctx.role == Role.OPERATOR
        assert ctx.auth_method == "jwt"
        assert ctx.client_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_invalid_jwt_raises_401(self):
        """Invalid JWT token raises 401."""
        from fastapi import HTTPException

        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {"Authorization": "Bearer invalid.token"}

        mock_auth_service = MagicMock()
        mock_auth_service.validate_jwt_token = MagicMock(return_value=None)

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with patch("core.auth_service.get_auth_service", return_value=mock_auth_service):
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_auth(mock_request, api_key=None)
                assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_no_credentials_raises_401(self):
        """No Bearer token and no API key raises 401."""
        from fastapi import HTTPException

        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {}

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with pytest.raises(HTTPException) as exc_info:
                await get_current_auth(mock_request, api_key=None)
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_api_key_fallback_when_no_bearer(self):
        """Falls back to API key when no Bearer token present."""
        from core.auth_dependency import get_current_auth

        expected_ctx = AuthContext(
            api_key_id="key-456",
            role=Role.ADMIN,
            auth_method="api_key",
        )

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"
        mock_request.headers = {}

        mock_auth_service = MagicMock()
        mock_auth_service.validate_api_key = AsyncMock(return_value=expected_ctx)

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with patch("core.auth_service.get_auth_service", return_value=mock_auth_service):
                ctx = await get_current_auth(mock_request, api_key="ngx_validkey")

        assert ctx.role == Role.ADMIN
        assert ctx.auth_method == "api_key"
