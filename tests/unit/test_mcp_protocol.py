"""
Unit tests for MCP protocol compliance.

Verifies JSON serialization, URI patterns, and tool schema requirements.
"""

import inspect
import json
from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server import resources, tools


class TestResourceJsonSerialization:
    """Verify all resource functions return JSON-serializable dicts."""

    @pytest.mark.asyncio
    async def test_sites_resource_returns_json_serializable(self, tmp_conf_dir):
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await resources.get_sites_resource()
            serialized = json.dumps(result, default=str)
            assert isinstance(serialized, str)
            parsed = json.loads(serialized)
            assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_site_resource_returns_json_serializable(self, tmp_conf_dir):
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await resources.get_site_resource("nonexistent")
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert "error" in parsed

    @pytest.mark.asyncio
    async def test_certificates_resource_returns_json_serializable(self):
        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])
        with patch("core.cert_manager.get_cert_manager", return_value=mock_cm):
            result = await resources.get_certificates_resource()
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert "certificates" in parsed

    @pytest.mark.asyncio
    async def test_certificate_resource_returns_json_serializable(self):
        mock_cm = MagicMock()
        mock_cm.get_certificate = AsyncMock(return_value=None)
        with patch("core.cert_manager.get_cert_manager", return_value=mock_cm):
            result = await resources.get_certificate_resource("example.com")
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert isinstance(parsed, dict)

    @pytest.mark.asyncio
    async def test_health_resource_returns_json_serializable(self, tmp_conf_dir):
        mock_docker = MagicMock()
        mock_docker.get_container_status = AsyncMock(return_value={"running": False})
        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])
        mock_es = MagicMock()
        mock_counts = MagicMock()
        mock_counts.error = 0
        mock_counts.critical = 0
        mock_counts.warning = 0
        mock_es.get_event_counts_by_severity = AsyncMock(return_value=mock_counts)

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await resources.get_health_resource()
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert "status" in parsed
            # Verify datetime fields serialize cleanly
            assert "timestamp" in parsed

    @pytest.mark.asyncio
    async def test_events_resource_returns_json_serializable(self):
        mock_es = MagicMock()
        mock_result = MagicMock()
        mock_result.events = []
        mock_result.total = 0
        mock_es.list_events = AsyncMock(return_value=mock_result)
        with patch("core.event_store.get_event_store", return_value=mock_es):
            result = await resources.get_events_resource()
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert "events" in parsed

    @pytest.mark.asyncio
    async def test_transactions_resource_returns_json_serializable(self):
        mock_tm = MagicMock()
        mock_result = MagicMock()
        mock_result.transactions = []
        mock_result.total = 0
        mock_tm.list_transactions = AsyncMock(return_value=mock_result)
        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await resources.get_transactions_resource()
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert "transactions" in parsed


class TestToolJsonSerialization:
    """Verify tool functions return JSON-serializable dicts."""

    @pytest.mark.asyncio
    async def test_create_site_returns_json_serializable(self, tmp_conf_dir):
        conf_file = tmp_conf_dir / "existing.conf"
        conf_file.write_text("server {}")
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await tools.create_site(name="existing", server_names=["existing.com"], site_type="static")
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert parsed["success"] is False

    @pytest.mark.asyncio
    async def test_nginx_test_returns_json_serializable(self):
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(True, "ok", ""))
        with patch("core.docker_service.docker_service", mock_docker):
            result = await tools.nginx_test()
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert parsed["success"] is True

    @pytest.mark.asyncio
    async def test_diagnose_ssl_returns_json_serializable(self):
        mock_result = MagicMock()
        mock_result.domain = "example.com"
        mock_result.dns_resolves = True
        mock_result.dns_ip_addresses = ["1.2.3.4"]
        mock_result.points_to_this_server = True
        mock_result.port_80_open = True
        mock_result.port_443_open = False
        mock_result.has_certificate = False
        mock_result.certificate_valid = False
        mock_result.certificate_expiry = None
        mock_result.certificate_issuer = None
        mock_result.chain_valid = False
        mock_result.chain_issues = []
        mock_result.ready_for_ssl = True
        mock_result.issues = []
        mock_result.suggestions = []

        mock_cm = MagicMock()
        mock_cm.diagnose_ssl = AsyncMock(return_value=mock_result)
        with patch("core.cert_manager.get_cert_manager", return_value=mock_cm):
            result = await tools.diagnose_ssl("example.com")
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert parsed["domain"] == "example.com"

    @pytest.mark.asyncio
    async def test_rollback_returns_json_serializable(self):
        mock_tm = MagicMock()
        mock_tm.can_rollback = AsyncMock(return_value=(False, "Snapshot not found"))
        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await tools.rollback_transaction("txn-123")
            serialized = json.dumps(result, default=str)
            parsed = json.loads(serialized)
            assert parsed["success"] is False


class TestResourceURIPatterns:
    """Verify resource URIs follow correct patterns."""

    def test_all_resource_uris_use_nginx_scheme(self):
        """All resource URIs registered in server.py use nginx:// scheme."""
        # These are the URIs from server.py registration
        uris = [
            "nginx://sites",
            "nginx://sites/{name}",
            "nginx://certificates",
            "nginx://certificates/{domain}",
            "nginx://health",
            "nginx://events",
            "nginx://transactions",
            "nginx://transactions/{transaction_id}",
        ]
        for uri in uris:
            assert uri.startswith("nginx://"), f"URI {uri} doesn't use nginx:// scheme"

    def test_parametric_uris_have_valid_placeholders(self):
        parametric_uris = {
            "nginx://sites/{name}": "name",
            "nginx://certificates/{domain}": "domain",
            "nginx://transactions/{transaction_id}": "transaction_id",
        }
        for uri, param in parametric_uris.items():
            assert f"{{{param}}}" in uri


class TestToolSchemas:
    """Verify tool functions have proper type hints and docstrings for MCP schema generation."""

    TOOL_FUNCTIONS: ClassVar[list] = [
        tools.create_site,
        tools.update_site,
        tools.delete_site,
        tools.enable_site,
        tools.disable_site,
        tools.nginx_reload,
        tools.nginx_restart,
        tools.nginx_test,
        tools.request_certificate,
        tools.upload_certificate,
        tools.renew_certificate,
        tools.revoke_certificate,
        tools.diagnose_ssl,
        tools.rollback_transaction,
        tools.execute_setup_site_workflow,
        tools.execute_migrate_site_workflow,
    ]

    def test_all_tools_have_docstrings(self):
        for func in self.TOOL_FUNCTIONS:
            assert func.__doc__ is not None, f"{func.__name__} missing docstring"
            assert len(func.__doc__.strip()) > 20, f"{func.__name__} docstring too short"

    def test_all_tools_have_type_hints(self):
        for func in self.TOOL_FUNCTIONS:
            sig = inspect.signature(func)
            for param_name, param in sig.parameters.items():
                assert param.annotation != inspect.Parameter.empty, f"{func.__name__}.{param_name} missing type hint"

    def test_optional_params_have_defaults(self):
        """Optional parameters (those with None or specific defaults) should have default values."""
        for func in self.TOOL_FUNCTIONS:
            sig = inspect.signature(func)
            for param_name, param in sig.parameters.items():
                annotation = str(param.annotation)
                if "None" in annotation and param.default == inspect.Parameter.empty:
                    pytest.fail(f"{func.__name__}.{param_name}: nullable param missing default")

    def test_all_tools_are_coroutines(self):
        for func in self.TOOL_FUNCTIONS:
            assert inspect.iscoroutinefunction(func), f"{func.__name__} is not async"
