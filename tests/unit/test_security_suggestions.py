"""
Unit tests for security suggestions and warnings.

Tests that security misconfigurations generate appropriate warnings.
"""

import pytest
from unittest.mock import patch, MagicMock


def _make_mock_settings(**overrides):
    """Create a mock settings object with defaults."""
    defaults = {
        "auth_enabled": True,
        "api_debug": False,
        "jwt_secret_key": "a-long-enough-secret-key-for-jwt-auth",
        "cors_allowed_origins": "https://app.example.com",
        "encrypt_private_keys": True,
    }
    defaults.update(overrides)
    mock = MagicMock()
    for k, v in defaults.items():
        setattr(mock, k, v)
    return mock


class TestSecurityWarnings:
    """Test get_security_warnings() output."""

    def test_warns_when_auth_disabled(self):
        """Warns when AUTH_ENABLED=false."""
        mock_settings = _make_mock_settings(auth_enabled=False)
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "auth_disabled" in codes

    def test_warns_when_debug_enabled(self):
        """Warns when API_DEBUG=true."""
        mock_settings = _make_mock_settings(api_debug=True, cors_allowed_origins="")
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "debug_mode" in codes

    def test_warns_no_jwt_secret(self):
        """Warns when auth enabled but no JWT_SECRET_KEY."""
        mock_settings = _make_mock_settings(jwt_secret_key=None)
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "no_jwt_secret" in codes

    def test_warns_weak_jwt_secret(self):
        """Warns when JWT secret is too short."""
        mock_settings = _make_mock_settings(jwt_secret_key="short")
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "weak_jwt_secret" in codes

    def test_warns_cors_wildcard(self):
        """Warns when CORS allows any origin."""
        mock_settings = _make_mock_settings(api_debug=True, cors_allowed_origins="")
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "cors_wildcard" in codes

    def test_warns_encryption_disabled(self):
        """Warns when private key encryption is disabled."""
        mock_settings = _make_mock_settings(encrypt_private_keys=False)
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        codes = [w["code"] for w in warnings]
        assert "encryption_disabled" in codes

    def test_no_warnings_when_fully_configured(self):
        """No warnings when all security settings are properly configured."""
        mock_settings = _make_mock_settings()
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        assert len(warnings) == 0

    def test_each_warning_has_required_fields(self):
        """Each warning has code, message, and suggestion fields."""
        mock_settings = _make_mock_settings(
            auth_enabled=False, api_debug=True,
            jwt_secret_key=None, cors_allowed_origins="",
            encrypt_private_keys=False,
        )
        with patch("config.settings", mock_settings):
            from core.context_helpers import get_security_warnings
            warnings = get_security_warnings()

        assert len(warnings) > 0
        for w in warnings:
            assert "code" in w
            assert "message" in w
            assert "suggestion" in w


class TestMCPAuth:
    """Test MCP server authentication validation."""

    def test_auth_disabled_allows_startup(self):
        """MCP starts when MCP_REQUIRE_AUTH=false."""
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = False
        with patch("config.settings", mock_settings):
            from mcp_server.server import _validate_mcp_auth
            assert _validate_mcp_auth("stdio") is True

    def test_no_key_configured_allows_startup(self):
        """MCP starts when no MCP_API_KEY is configured (backward compat)."""
        import os

        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = None
        with patch("config.settings", mock_settings):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MCP_API_KEY", None)
                from mcp_server.server import _validate_mcp_auth
                assert _validate_mcp_auth("stdio") is True

    def test_matching_key_allows_startup(self):
        """MCP starts when env MCP_API_KEY matches configured key."""
        import os

        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "ngx_test_mcp_key"
        with patch("config.settings", mock_settings):
            with patch.dict(os.environ, {"MCP_API_KEY": "ngx_test_mcp_key"}):
                from mcp_server.server import _validate_mcp_auth
                assert _validate_mcp_auth("stdio") is True

    def test_mismatched_key_blocks_startup(self):
        """MCP refuses to start when env key doesn't match."""
        import os

        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "ngx_correct_key"
        with patch("config.settings", mock_settings):
            with patch.dict(os.environ, {"MCP_API_KEY": "ngx_wrong_key"}):
                from mcp_server.server import _validate_mcp_auth
                assert _validate_mcp_auth("stdio") is False

    def test_missing_env_key_blocks_startup(self):
        """MCP refuses to start when key configured but env var missing."""
        import os

        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "ngx_configured_key"
        with patch("config.settings", mock_settings):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MCP_API_KEY", None)
                from mcp_server.server import _validate_mcp_auth
                assert _validate_mcp_auth("stdio") is False

    def test_http_transport_always_passes(self):
        """HTTP transport delegates auth to per-request middleware."""
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        with patch("config.settings", mock_settings):
            from mcp_server.server import _validate_mcp_auth
            assert _validate_mcp_auth("streamable-http") is True
