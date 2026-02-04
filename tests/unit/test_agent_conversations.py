"""
Unit tests for simulated multi-turn agent conversation flows.

Tests realistic sequences of MCP tool and resource calls that an AI agent
would make, verifying state consistency across turns.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class MockTransactionContext:
    """Local copy — avoids cross-directory import of conftest."""

    def __init__(self, transaction_id: str = "txn-test-123"):
        self.id = transaction_id


class _MockState:
    """Shared mock state that persists across calls in a conversation."""

    def __init__(self, tmp_dir):
        self.tmp_dir = tmp_dir
        self.sites = {}
        self.certs = {}
        self.health_status = "running"

    def site_exists(self, name):
        return (self.tmp_dir / f"{name}.conf").exists()

    def create_site(self, name, content="server { listen 80; }"):
        (self.tmp_dir / f"{name}.conf").write_text(content)
        self.sites[name] = content


class TestHappyPathConversation:
    """Test successful multi-turn agent interactions."""

    @pytest.mark.asyncio
    async def test_create_site_then_verify_listed(self, tmp_conf_dir, mock_transaction_ctx):
        """Agent creates a site, then checks it appears in the sites list."""
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; server_name test.com; }")
        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))
        mock_docker.get_container_status = AsyncMock(return_value={"running": True})
        mock_docker.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            # Turn 1: Create site
            from mcp_server.tools import create_site

            result = await create_site(
                name="test-conv", server_names=["test.com"], site_type="static", root_path="/var/www/test"
            )
            assert result["success"] is True
            assert "transaction_id" in result

            # Turn 2: Verify site file exists (simulating get_sites_resource reading the dir)
            assert (tmp_conf_dir / "test-conv.conf").exists()

    @pytest.mark.asyncio
    async def test_create_then_update(self, tmp_conf_dir, mock_transaction_ctx):
        """Agent creates a site, then updates it."""
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")
        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        mock_parsed = MagicMock()
        mock_rich = {
            "name": "app",
            "server_names": ["app.com"],
            "listen_ports": [80],
            "proxy_pass": "http://localhost:3000",
            "root_path": None,
        }

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_site_update_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=mock_parsed),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=mock_rich),
        ):
            from mcp_server.tools import create_site, update_site

            # Turn 1: Create
            result1 = await create_site(
                name="app", server_names=["app.com"], site_type="reverse_proxy", proxy_pass="http://localhost:3000"
            )
            assert result1["success"] is True

            # Turn 2: Update
            result2 = await update_site(name="app", proxy_pass="http://localhost:4000")
            assert result2["success"] is True


class TestFailureRecoveryConversation:
    """Test failure and recovery interaction patterns."""

    @pytest.mark.asyncio
    async def test_create_fails_then_retry_succeeds(self, tmp_conf_dir, mock_transaction_ctx):
        """Agent's first attempt fails, second succeeds."""
        mock_generator = MagicMock()
        from core.config_generator import ConfigGeneratorError

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        # First call: generator fails. Second call: succeeds.
        error = ConfigGeneratorError("Missing root_path for static site")
        mock_generator.generate = MagicMock(side_effect=[error, "server { listen 80; }"])

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            from mcp_server.tools import create_site

            # Turn 1: Fail (generator error)
            result1 = await create_site(
                name="retry-site", server_names=["retry.com"], site_type="static", root_path="/var/www/retry"
            )
            assert result1["success"] is False

            # Turn 2: Succeed (with proper params)
            result2 = await create_site(
                name="retry-site", server_names=["retry.com"], site_type="static", root_path="/var/www/retry"
            )
            assert result2["success"] is True

    @pytest.mark.asyncio
    async def test_rollback_after_update_failure(self, tmp_conf_dir):
        """Agent updates a site, config validation fails, then rolls back."""
        mock_tm = MagicMock()
        mock_tm.can_rollback = AsyncMock(return_value=(True, None))
        mock_rb_result = MagicMock()
        mock_rb_result.success = True
        mock_rb_result.rollback_transaction_id = "txn-rb-456"
        mock_rb_result.original_transaction_id = "txn-update-123"
        mock_rb_result.message = "Rolled back"
        mock_rb_result.warnings = []
        mock_tm.rollback_transaction = AsyncMock(return_value=mock_rb_result)

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            from mcp_server.tools import rollback_transaction

            result = await rollback_transaction("txn-update-123", reason="Config broke")
            assert result["success"] is True
            assert result["rollback_transaction_id"] == "txn-rb-456"


class TestDiagnosticConversation:
    """Test diagnostic and healing interaction patterns."""

    @pytest.mark.asyncio
    async def test_health_check_then_diagnose(self, tmp_conf_dir):
        """Agent checks health (degraded), then runs diagnostics."""
        # Turn 1: Health check shows degraded
        mock_docker = MagicMock()
        mock_docker.get_container_status = AsyncMock(return_value={"running": True, "container_id": "abc123"})
        mock_docker.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_expired_cert = MagicMock()
        mock_expired_cert.status = MagicMock()
        mock_expired_cert.status.value = "expired"
        mock_expired_cert.domain = "expired.com"

        from models.certificate import CertificateStatus

        mock_expired_cert.status = CertificateStatus.EXPIRED

        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[mock_expired_cert])

        mock_es = MagicMock()
        mock_counts = MagicMock()
        mock_counts.error = 0
        mock_counts.critical = 0
        mock_counts.warning = 1
        mock_es.get_event_counts_by_severity = AsyncMock(return_value=mock_counts)

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            from mcp_server.resources import get_health_resource

            health = await get_health_resource()
            assert health["status"] == "degraded"
            assert health["certificates"]["expired"] == 1

        # Turn 2: Diagnose the expired domain
        mock_diag = MagicMock()
        mock_diag.domain = "expired.com"
        mock_diag.dns_resolves = True
        mock_diag.dns_ip_addresses = ["1.2.3.4"]
        mock_diag.points_to_this_server = True
        mock_diag.port_80_open = True
        mock_diag.port_443_open = True
        mock_diag.has_certificate = True
        mock_diag.certificate_valid = False
        mock_diag.certificate_expiry = None
        mock_diag.certificate_issuer = "Let's Encrypt"
        mock_diag.chain_valid = True
        mock_diag.chain_issues = []
        mock_diag.ready_for_ssl = True
        mock_diag.issues = ["Certificate expired"]
        mock_diag.suggestions = ["Renew certificate"]

        mock_cm2 = MagicMock()
        mock_cm2.diagnose_ssl = AsyncMock(return_value=mock_diag)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_cm2):
            from mcp_server.tools import diagnose_ssl

            diag_result = await diagnose_ssl("expired.com")
            assert diag_result["ready_for_ssl"] is True
            assert "Certificate expired" in diag_result["issues"]


class TestWorkflowConversation:
    """Test workflow-based agent interactions."""

    @pytest.mark.asyncio
    async def test_dry_run_then_execute_setup(self):
        """Agent previews a workflow (dry-run), then executes it."""
        from mcp_server.tools import execute_setup_site_workflow

        # Turn 1: Dry-run
        with patch("endpoints.workflows._dry_run_setup_site") as mock_dry:
            mock_response = MagicMock()
            mock_response.model_dump.return_value = {
                "workflow_type": "setup_site",
                "total_steps": 3,
                "would_succeed": True,
                "steps": [
                    {"name": "check_prerequisites", "description": "Check NGINX running"},
                    {"name": "create_site", "description": "Create config"},
                    {"name": "verify_site", "description": "Validate config"},
                ],
            }
            mock_dry.return_value = mock_response

            preview = await execute_setup_site_workflow(
                name="new-site",
                server_names=["new.com"],
                site_type="static",
                root_path="/var/www/new",
                dry_run=True,
            )

            assert preview["would_succeed"] is True
            assert preview["total_steps"] == 3

        # Turn 2: Execute (mocked)
        with patch("core.workflow_definitions.build_setup_site_workflow") as mock_build:
            mock_engine = MagicMock()
            mock_result = MagicMock()
            mock_result.model_dump.return_value = {
                "workflow_type": "setup_site",
                "status": "completed",
                "total_steps": 3,
                "completed_steps": 3,
            }
            mock_engine.execute = AsyncMock(return_value=mock_result)
            mock_build.return_value = mock_engine

            result = await execute_setup_site_workflow(
                name="new-site",
                server_names=["new.com"],
                site_type="static",
                root_path="/var/www/new",
                dry_run=False,
            )

            assert result["status"] == "completed"
            assert result["completed_steps"] == 3
