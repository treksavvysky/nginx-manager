"""
Unit tests for auth dependency.

Tests authentication bypass, API key validation, and role enforcement.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.auth import AuthContext, Role


class TestRoleHierarchy:
    """Test role permission hierarchy."""

    def test_admin_has_all_permissions(self):
        """Admin role has permission for all roles."""
        assert Role.ADMIN.has_permission(Role.ADMIN) is True
        assert Role.ADMIN.has_permission(Role.OPERATOR) is True
        assert Role.ADMIN.has_permission(Role.VIEWER) is True

    def test_operator_permissions(self):
        """Operator has permission for operator and viewer."""
        assert Role.OPERATOR.has_permission(Role.ADMIN) is False
        assert Role.OPERATOR.has_permission(Role.OPERATOR) is True
        assert Role.OPERATOR.has_permission(Role.VIEWER) is True

    def test_viewer_permissions(self):
        """Viewer only has viewer permission."""
        assert Role.VIEWER.has_permission(Role.ADMIN) is False
        assert Role.VIEWER.has_permission(Role.OPERATOR) is False
        assert Role.VIEWER.has_permission(Role.VIEWER) is True


class TestAuthContext:
    """Test AuthContext model."""

    def test_default_context(self):
        """Default auth context has viewer role and no auth method."""
        ctx = AuthContext()
        assert ctx.role == Role.VIEWER
        assert ctx.auth_method == "none"
        assert ctx.api_key_id is None
        assert ctx.user_id is None

    def test_context_with_api_key(self):
        """Auth context from API key validation."""
        ctx = AuthContext(
            api_key_id="key-123",
            role=Role.OPERATOR,
            auth_method="api_key",
            client_ip="192.168.1.1",
        )
        assert ctx.api_key_id == "key-123"
        assert ctx.role == Role.OPERATOR
        assert ctx.auth_method == "api_key"


class TestGetCurrentAuth:
    """Test the get_current_auth dependency."""

    @pytest.mark.asyncio
    async def test_bypass_when_auth_disabled(self):
        """Returns admin context when AUTH_ENABLED=false."""
        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = False
            ctx = await get_current_auth(mock_request, api_key=None)

        assert ctx.role == Role.ADMIN
        assert ctx.auth_method == "none"

    @pytest.mark.asyncio
    async def test_requires_key_when_auth_enabled(self):
        """Raises 401 when auth enabled and no key provided."""
        from fastapi import HTTPException

        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with pytest.raises(HTTPException) as exc_info:
                await get_current_auth(mock_request, api_key=None)
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_key_returns_401(self):
        """Raises 401 for invalid API key."""
        from fastapi import HTTPException

        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_auth_service = MagicMock()
        mock_auth_service.validate_api_key = AsyncMock(return_value=None)

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with patch("core.auth_service.get_auth_service", return_value=mock_auth_service):
                with pytest.raises(HTTPException) as exc_info:
                    await get_current_auth(mock_request, api_key="ngx_invalid")
                assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_key_returns_context(self):
        """Returns auth context for valid API key."""
        from core.auth_dependency import get_current_auth

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"

        expected_ctx = AuthContext(
            api_key_id="key-123",
            role=Role.OPERATOR,
            auth_method="api_key",
        )

        mock_auth_service = MagicMock()
        mock_auth_service.validate_api_key = AsyncMock(return_value=expected_ctx)

        with patch("core.auth_dependency.settings") as mock_settings:
            mock_settings.auth_enabled = True
            with patch("core.auth_service.get_auth_service", return_value=mock_auth_service):
                ctx = await get_current_auth(mock_request, api_key="ngx_validkey")

        assert ctx.api_key_id == "key-123"
        assert ctx.role == Role.OPERATOR
        assert ctx.client_ip == "10.0.0.1"


class TestRequireRole:
    """Test role enforcement dependency."""

    @pytest.mark.asyncio
    async def test_sufficient_role_passes(self):
        """Passes when user has sufficient role."""
        from core.auth_dependency import require_role

        checker = require_role(Role.VIEWER)
        ctx = AuthContext(role=Role.ADMIN, auth_method="api_key")
        result = await checker(auth=ctx)
        assert result.role == Role.ADMIN

    @pytest.mark.asyncio
    async def test_insufficient_role_raises_403(self):
        """Raises 403 when user lacks required role."""
        from fastapi import HTTPException

        from core.auth_dependency import require_role

        checker = require_role(Role.ADMIN)
        ctx = AuthContext(role=Role.VIEWER, auth_method="api_key")

        with pytest.raises(HTTPException) as exc_info:
            await checker(auth=ctx)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_exact_role_passes(self):
        """Passes when user has exactly the required role."""
        from core.auth_dependency import require_role

        checker = require_role(Role.OPERATOR)
        ctx = AuthContext(role=Role.OPERATOR, auth_method="api_key")
        result = await checker(auth=ctx)
        assert result.role == Role.OPERATOR
