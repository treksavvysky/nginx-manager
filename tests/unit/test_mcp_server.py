"""
Unit tests for MCP server setup, authentication, and transport.

Tests create_mcp_server(), _validate_mcp_auth(), and run_mcp_server().
"""

import os
from unittest.mock import MagicMock, patch

from mcp_server.server import _validate_mcp_auth, create_mcp_server, run_mcp_server


class TestCreateMcpServer:
    """Tests for the create_mcp_server factory."""

    def test_returns_none_when_mcp_unavailable(self):
        with patch("mcp_server.server.MCP_AVAILABLE", False):
            result = create_mcp_server()
            assert result is None

    def test_creates_server_when_mcp_available(self):
        mock_fastmcp_instance = MagicMock()
        mock_fastmcp_class = MagicMock(return_value=mock_fastmcp_instance)

        with (
            patch("mcp_server.server.MCP_AVAILABLE", True),
            patch("mcp_server.server.FastMCP", mock_fastmcp_class),
        ):
            result = create_mcp_server("test-server")
            assert result is not None
            mock_fastmcp_class.assert_called_once_with("test-server")

    def test_registers_resources(self):
        mock_fastmcp_instance = MagicMock()
        mock_fastmcp_class = MagicMock(return_value=mock_fastmcp_instance)

        with (
            patch("mcp_server.server.MCP_AVAILABLE", True),
            patch("mcp_server.server.FastMCP", mock_fastmcp_class),
        ):
            create_mcp_server()
            assert mock_fastmcp_instance.resource.call_count == 8

    def test_registers_tools(self):
        mock_fastmcp_instance = MagicMock()
        mock_fastmcp_class = MagicMock(return_value=mock_fastmcp_instance)

        with (
            patch("mcp_server.server.MCP_AVAILABLE", True),
            patch("mcp_server.server.FastMCP", mock_fastmcp_class),
        ):
            create_mcp_server()
            assert mock_fastmcp_instance.tool.call_count >= 15

    def test_registers_prompts(self):
        mock_fastmcp_instance = MagicMock()
        mock_fastmcp_class = MagicMock(return_value=mock_fastmcp_instance)

        with (
            patch("mcp_server.server.MCP_AVAILABLE", True),
            patch("mcp_server.server.FastMCP", mock_fastmcp_class),
        ):
            create_mcp_server()
            assert mock_fastmcp_instance.prompt.call_count == 5


class TestValidateMcpAuth:
    """Tests for _validate_mcp_auth."""

    def test_auth_disabled_returns_true(self):
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = False

        with patch("config.settings", mock_settings):
            assert _validate_mcp_auth("stdio") is True

    def test_stdio_matching_key_returns_true(self):
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "test-key-123"

        with (
            patch("config.settings", mock_settings),
            patch.dict(os.environ, {"MCP_API_KEY": "test-key-123"}),
        ):
            assert _validate_mcp_auth("stdio") is True

    def test_stdio_mismatched_key_returns_false(self):
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "correct-key"

        with (
            patch("config.settings", mock_settings),
            patch.dict(os.environ, {"MCP_API_KEY": "wrong-key"}),
        ):
            assert _validate_mcp_auth("stdio") is False

    def test_stdio_missing_env_key_returns_false(self):
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = "configured-key"

        env = os.environ.copy()
        env.pop("MCP_API_KEY", None)
        with (
            patch("config.settings", mock_settings),
            patch.dict(os.environ, env, clear=True),
        ):
            assert _validate_mcp_auth("stdio") is False

    def test_stdio_no_key_configured_returns_true(self):
        """Backward compatible: no key configured means allow access."""
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True
        mock_settings.mcp_api_key = None

        env = os.environ.copy()
        env.pop("MCP_API_KEY", None)
        with (
            patch("config.settings", mock_settings),
            patch.dict(os.environ, env, clear=True),
        ):
            assert _validate_mcp_auth("stdio") is True

    def test_http_transport_returns_true(self):
        """HTTP transport delegates auth to API middleware."""
        mock_settings = MagicMock()
        mock_settings.mcp_require_auth = True

        with patch("config.settings", mock_settings):
            assert _validate_mcp_auth("streamable-http") is True


class TestRunMcpServer:
    """Tests for run_mcp_server."""

    def test_run_fails_when_server_creation_fails(self):
        with patch("mcp_server.server.create_mcp_server", return_value=None):
            run_mcp_server()

    def test_run_fails_when_auth_fails(self):
        mock_mcp = MagicMock()
        with (
            patch("mcp_server.server.create_mcp_server", return_value=mock_mcp),
            patch("mcp_server.server._validate_mcp_auth", return_value=False),
        ):
            run_mcp_server()
            mock_mcp.run.assert_not_called()

    def test_run_stdio_transport(self):
        mock_mcp = MagicMock()
        with (
            patch("mcp_server.server.create_mcp_server", return_value=mock_mcp),
            patch("mcp_server.server._validate_mcp_auth", return_value=True),
        ):
            run_mcp_server(transport="stdio")
            mock_mcp.run.assert_called_once_with()

    def test_run_http_transport(self):
        mock_mcp = MagicMock()
        with (
            patch("mcp_server.server.create_mcp_server", return_value=mock_mcp),
            patch("mcp_server.server._validate_mcp_auth", return_value=True),
        ):
            run_mcp_server(transport="streamable-http", host="0.0.0.0", port=9090)
            mock_mcp.run.assert_called_once_with(transport="streamable-http", host="0.0.0.0", port=9090)
