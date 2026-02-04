"""
Unit tests for workflow integration.

Tests build_setup_site_workflow and build_migrate_site_workflow
with mocked tool functions, verifying step sequencing, context passing,
rollback, and partial completion.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.workflow import WorkflowStatus


def _mock_settings():
    """Create mock settings for workflow factory functions."""
    s = MagicMock()
    s.workflow_step_timeout = 120
    s.workflow_auto_rollback = True
    return s


class TestSetupSiteWorkflowIntegration:
    """Tests for the setup-site workflow with concrete step implementations."""

    @pytest.mark.asyncio
    async def test_full_setup_without_ssl(self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx):
        """Setup-site without SSL: 3 steps, all succeed."""
        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            from core.workflow_definitions import build_setup_site_workflow

            context = {
                "name": "test-site",
                "server_names": ["test-site.com"],
                "site_type": "static",
                "root_path": "/var/www/test",
                "request_ssl": False,
            }
            engine = build_setup_site_workflow(context)
            result = await engine.execute(context)

            assert result.status == WorkflowStatus.COMPLETED
            assert result.total_steps == 3
            assert result.completed_steps == 3

    @pytest.mark.asyncio
    async def test_full_setup_with_ssl(self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx):
        """Setup-site with SSL: 6 steps total."""
        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        mock_diag_result = MagicMock()
        mock_diag_result.domain = "test-site.com"
        mock_diag_result.dns_resolves = True
        mock_diag_result.dns_ip_addresses = ["1.2.3.4"]
        mock_diag_result.points_to_this_server = True
        mock_diag_result.port_80_open = True
        mock_diag_result.port_443_open = False
        mock_diag_result.has_certificate = False
        mock_diag_result.certificate_valid = False
        mock_diag_result.certificate_expiry = None
        mock_diag_result.certificate_issuer = None
        mock_diag_result.chain_valid = False
        mock_diag_result.chain_issues = []
        mock_diag_result.ready_for_ssl = True
        mock_diag_result.issues = []
        mock_diag_result.suggestions = []

        mock_cert_result = MagicMock()
        mock_cert_result.success = True
        mock_cert_result.message = "Certificate issued"
        mock_cert_result.domain = "test-site.com"
        mock_cert_result.transaction_id = "cert-txn-123"
        mock_cert_result.certificate = None
        mock_cert_result.reload_required = False
        mock_cert_result.reloaded = True
        mock_cert_result.suggestions = []
        mock_cert_result.warnings = []

        mock_cm = MagicMock()
        mock_cm.diagnose_ssl = AsyncMock(return_value=mock_diag_result)
        mock_cm.request_certificate = AsyncMock(return_value=mock_cert_result)

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
        ):
            from core.workflow_definitions import build_setup_site_workflow

            context = {
                "name": "test-site",
                "server_names": ["test-site.com"],
                "site_type": "static",
                "root_path": "/var/www/test",
                "request_ssl": True,
            }
            engine = build_setup_site_workflow(context)
            result = await engine.execute(context)

            assert result.total_steps == 6
            assert result.status in (WorkflowStatus.COMPLETED, WorkflowStatus.PARTIALLY_COMPLETED)

    @pytest.mark.asyncio
    async def test_prerequisites_fail_stops_workflow(self, tmp_conf_dir, mock_docker_service):
        """When NGINX is not running, workflow fails at step 1."""
        mock_docker_service.get_container_status = AsyncMock(return_value={"running": False})

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
        ):
            from core.workflow_definitions import build_setup_site_workflow

            context = {
                "name": "test-site",
                "server_names": ["test-site.com"],
                "site_type": "static",
                "request_ssl": False,
            }
            engine = build_setup_site_workflow(context)
            result = await engine.execute(context)

            assert result.status == WorkflowStatus.FAILED
            assert result.completed_steps == 0
            assert result.failed_step == "check_prerequisites"

    @pytest.mark.asyncio
    async def test_ssl_diagnose_fail_partial_completion(self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx):
        """SSL diagnose failure doesn't rollback site creation (non-critical)."""
        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        mock_diag_result = MagicMock()
        mock_diag_result.domain = "test.com"
        mock_diag_result.dns_resolves = False
        mock_diag_result.dns_ip_addresses = []
        mock_diag_result.points_to_this_server = False
        mock_diag_result.port_80_open = False
        mock_diag_result.port_443_open = False
        mock_diag_result.has_certificate = False
        mock_diag_result.certificate_valid = False
        mock_diag_result.certificate_expiry = None
        mock_diag_result.certificate_issuer = None
        mock_diag_result.chain_valid = False
        mock_diag_result.chain_issues = []
        mock_diag_result.ready_for_ssl = False
        mock_diag_result.issues = ["DNS not resolving"]
        mock_diag_result.suggestions = []

        mock_cm = MagicMock()
        mock_cm.diagnose_ssl = AsyncMock(return_value=mock_diag_result)

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
        ):
            from core.workflow_definitions import build_setup_site_workflow

            context = {
                "name": "test-site",
                "server_names": ["test.com"],
                "site_type": "static",
                "root_path": "/var/www/test",
                "request_ssl": True,
            }
            engine = build_setup_site_workflow(context)
            result = await engine.execute(context)

            # SSL failure is non-critical, site should still be created
            assert result.status == WorkflowStatus.PARTIALLY_COMPLETED
            assert result.completed_steps >= 3

    @pytest.mark.asyncio
    async def test_progress_events_emitted(self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx):
        """Progress callback events emitted for all steps."""
        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        progress_events = []

        async def capture_progress(event):
            progress_events.append(event)

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            from core.workflow_definitions import build_setup_site_workflow

            context = {
                "name": "test-site",
                "server_names": ["test.com"],
                "site_type": "static",
                "root_path": "/var/www/test",
                "request_ssl": False,
            }
            engine = build_setup_site_workflow(context)
            engine.on_progress(capture_progress)
            await engine.execute(context)

            # Should have workflow_started, step_started/completed for each step, workflow_completed
            event_types = [e.event_type for e in progress_events]
            assert "workflow_started" in event_types
            assert "workflow_completed" in event_types or "workflow_failed" in event_types
            assert event_types.count("step_started") >= 3


class TestMigrateSiteWorkflowIntegration:
    """Tests for the migrate-site workflow."""

    @pytest.mark.asyncio
    async def test_full_migration_success(self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx):
        """All 3 migration steps succeed."""
        # Create existing site config
        conf_file = tmp_conf_dir / "migrate-site.conf"
        conf_file.write_text("server { listen 80; server_name migrate-site.com; }")

        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_parsed = MagicMock()
        mock_rich_dict = {
            "name": "migrate-site",
            "server_names": ["migrate-site.com"],
            "listen_ports": [80],
            "proxy_pass": None,
            "root_path": "/var/www/migrate",
        }

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=mock_parsed),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=mock_rich_dict),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_update_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            from core.workflow_definitions import build_migrate_site_workflow

            context = {
                "name": "migrate-site",
                "proxy_pass": "http://localhost:4000",
            }
            engine = build_migrate_site_workflow(context)
            result = await engine.execute(context)

            assert result.status == WorkflowStatus.COMPLETED
            assert result.total_steps == 3

    @pytest.mark.asyncio
    async def test_site_not_found_fails(self, tmp_conf_dir):
        """Migration fails if site doesn't exist."""
        with (
            patch("config.settings", _mock_settings()),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
        ):
            from core.workflow_definitions import build_migrate_site_workflow

            context = {"name": "nonexistent"}
            engine = build_migrate_site_workflow(context)
            result = await engine.execute(context)

            assert result.status == WorkflowStatus.FAILED
            assert result.failed_step == "verify_exists"


class TestWorkflowDryRunIntegration:
    """Tests for workflow dry-run via MCP tools."""

    @pytest.mark.asyncio
    async def test_setup_site_dry_run_without_ssl(self):
        """Dry-run of setup-site without SSL returns 3 steps."""
        from mcp_server.tools import execute_setup_site_workflow

        with patch("endpoints.workflows._dry_run_setup_site") as mock_dry:
            mock_response = MagicMock()
            mock_response.model_dump.return_value = {
                "workflow_type": "setup_site",
                "steps": [
                    {"name": "check_prerequisites"},
                    {"name": "create_site"},
                    {"name": "verify_site"},
                ],
                "total_steps": 3,
                "would_succeed": True,
            }
            mock_dry.return_value = mock_response

            result = await execute_setup_site_workflow(
                name="test",
                server_names=["test.com"],
                site_type="static",
                root_path="/var/www/test",
                request_ssl=False,
                dry_run=True,
            )

            assert result["total_steps"] == 3
            assert result["would_succeed"] is True

    @pytest.mark.asyncio
    async def test_setup_site_dry_run_with_ssl(self):
        """Dry-run of setup-site with SSL returns 6 steps."""
        from mcp_server.tools import execute_setup_site_workflow

        with patch("endpoints.workflows._dry_run_setup_site") as mock_dry:
            mock_response = MagicMock()
            mock_response.model_dump.return_value = {
                "workflow_type": "setup_site",
                "steps": [{"name": f"step_{i}"} for i in range(6)],
                "total_steps": 6,
                "would_succeed": True,
            }
            mock_dry.return_value = mock_response

            result = await execute_setup_site_workflow(
                name="test",
                server_names=["test.com"],
                site_type="static",
                root_path="/var/www/test",
                request_ssl=True,
                dry_run=True,
            )

            assert result["total_steps"] == 6

    @pytest.mark.asyncio
    async def test_migrate_site_dry_run_no_changes(self):
        """Dry-run of migrate with no changes warns."""
        from mcp_server.tools import execute_migrate_site_workflow

        with patch("endpoints.workflows._dry_run_migrate_site") as mock_dry:
            mock_response = MagicMock()
            mock_response.model_dump.return_value = {
                "workflow_type": "migrate_site",
                "would_succeed": False,
                "warnings": [{"message": "No changes specified"}],
            }
            mock_dry.return_value = mock_response

            result = await execute_migrate_site_workflow(
                name="test",
                dry_run=True,
            )

            assert result["would_succeed"] is False
