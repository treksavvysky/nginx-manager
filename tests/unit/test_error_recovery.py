"""
Unit tests for error recovery scenarios.

Tests Docker failures, health check failures, config validation failures,
cascade failures in workflows, partial failure handling, and transaction rollback.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from models.workflow import WorkflowStatus


class MockTransactionContext:
    """Local copy — avoids cross-directory import of conftest."""

    def __init__(self, transaction_id: str = "txn-test-123"):
        self.id = transaction_id


class TestDockerServiceFailures:
    """Test error handling when Docker service fails."""

    @pytest.mark.asyncio
    async def test_nginx_reload_docker_unavailable(self, mock_transaction_ctx):
        """DockerServiceError during reload returns structured error."""
        from core.docker_service import DockerServiceError

        mock_docker = MagicMock()
        error = DockerServiceError("Container not found", "container_error", suggestion="Check container name")
        mock_docker.reload_nginx = AsyncMock(side_effect=error)

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            from mcp_server.tools import nginx_reload

            result = await nginx_reload(dry_run=False)
            assert result["success"] is False
            assert "Container not found" in result["message"]

    @pytest.mark.asyncio
    async def test_nginx_test_docker_unavailable(self):
        """DockerServiceError during config test returns structured error."""
        from core.docker_service import DockerServiceError

        mock_docker = MagicMock()
        error = DockerServiceError("Connection refused", "docker_error", suggestion="Start Docker daemon")
        mock_docker.test_config = AsyncMock(side_effect=error)

        with patch("core.docker_service.docker_service", mock_docker):
            from mcp_server.tools import nginx_test

            result = await nginx_test()
            assert result["success"] is False
            assert "Connection refused" in result["message"]

    @pytest.mark.asyncio
    async def test_nginx_reload_dry_run_docker_error(self):
        """DockerServiceError during dry-run reload returns would_succeed=False."""
        from core.docker_service import DockerServiceError

        mock_docker = MagicMock()
        error = DockerServiceError("Not running", "container_error", suggestion="Start container")
        mock_docker.get_container_status = AsyncMock(side_effect=error)

        with patch("core.docker_service.docker_service", mock_docker):
            from mcp_server.tools import nginx_reload

            result = await nginx_reload(dry_run=True)
            assert result["dry_run"] is True
            assert result["would_succeed"] is False


class TestHealthCheckFailures:
    """Test behavior when health checks fail after operations."""

    @pytest.mark.asyncio
    async def test_reload_succeeds_but_health_check_fails(self, mock_transaction_ctx):
        """Reload succeeds but health verification fails — still returns success."""
        from core.health_checker import HealthCheckError

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        mock_health = MagicMock()
        mock_health.verify_health = AsyncMock(side_effect=HealthCheckError("Health check timed out", attempts=3))

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.health_checker.health_checker", mock_health),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            from mcp_server.tools import nginx_reload

            result = await nginx_reload(dry_run=False)
            assert result["success"] is True
            assert result["health_verified"] is False

    @pytest.mark.asyncio
    async def test_restart_succeeds_but_health_check_fails(self, mock_transaction_ctx):
        """Restart succeeds but health verification fails."""
        from core.health_checker import HealthCheckError

        mock_docker = MagicMock()
        mock_docker.restart_container = AsyncMock(return_value=True)

        mock_health = MagicMock()
        mock_health.verify_health = AsyncMock(side_effect=HealthCheckError("Timeout", attempts=3))

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.health_checker.health_checker", mock_health),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            from mcp_server.tools import nginx_restart

            result = await nginx_restart(dry_run=False)
            assert result["success"] is True
            assert result["health_verified"] is False


class TestConfigValidationFailures:
    """Test handling when NGINX config validation fails."""

    @pytest.mark.asyncio
    async def test_create_site_validation_fails_cleanup(self, tmp_conf_dir):
        """When config validation fails during create, temp file is cleaned up."""
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(False, "", "syntax error"))

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = True

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { bad config }")

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.docker_service.docker_service", mock_docker),
        ):
            from mcp_server.tools import create_site

            result = await create_site(
                name="bad-site", server_names=["bad.com"], site_type="static", root_path="/var/www/bad", dry_run=False
            )

            assert result["success"] is False
            assert "validation failed" in result["message"].lower()
            # Config file should not remain
            assert not (tmp_conf_dir / "bad-site.conf").exists()

    @pytest.mark.asyncio
    async def test_create_site_validation_fails_dry_run(self, tmp_conf_dir):
        """Dry-run with validation failure returns would_succeed=False."""
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(False, "", "syntax error"))

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = True

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { bad config }")

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.docker_service.docker_service", mock_docker),
        ):
            from mcp_server.tools import create_site

            result = await create_site(
                name="bad-site", server_names=["bad.com"], site_type="static", root_path="/var/www/bad", dry_run=True
            )

            assert result["dry_run"] is True
            assert result["would_succeed"] is False
            assert result["validation_passed"] is False


class TestCascadeFailures:
    """Test cascade failure scenarios in workflows."""

    @pytest.mark.asyncio
    async def test_workflow_step_failure_triggers_rollback(
        self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx
    ):
        """When a critical step fails, checkpoint transactions are rolled back."""
        # Step 1 (check prereqs): success
        # Step 2 (create site): success with transaction
        # Step 3 (verify site): fail → triggers rollback

        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        call_count = 0

        async def test_config_sequence():
            nonlocal call_count
            call_count += 1
            # First call (during create validation) succeeds
            # Second call (during verify) fails
            if call_count <= 1:
                return (True, "ok", "")
            return (False, "", "config error after create")

        mock_docker_service.test_config = AsyncMock(side_effect=test_config_sequence)

        mock_txn_manager = MagicMock()
        mock_txn_manager.can_rollback = AsyncMock(return_value=(True, None))
        mock_rb_result = MagicMock()
        mock_rb_result.success = True
        mock_txn_manager.rollback_transaction = AsyncMock(return_value=mock_rb_result)

        mock_settings = MagicMock()
        mock_settings.workflow_step_timeout = 120
        mock_settings.workflow_auto_rollback = True

        with (
            patch("config.settings", mock_settings),
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
            patch("core.transaction_manager.get_transaction_manager", return_value=mock_txn_manager),
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
            result = await engine.execute(context)

            assert result.status in (WorkflowStatus.ROLLED_BACK, WorkflowStatus.FAILED)
            assert result.failed_step == "verify_site"


class TestPartialFailureHandling:
    """Test non-critical step failures that should not trigger rollback."""

    @pytest.mark.asyncio
    async def test_non_critical_ssl_failure_preserves_site(
        self, tmp_conf_dir, mock_docker_service, mock_transaction_ctx
    ):
        """SSL diagnosis failure with rollback_on_failure=False preserves site."""
        mock_docker_service.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        # diagnose_ssl raises exception (non-critical step)
        mock_cm = MagicMock()
        mock_diag_result = MagicMock()
        mock_diag_result.ready_for_ssl = False
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
        mock_diag_result.issues = ["DNS not resolving"]
        mock_diag_result.suggestions = []
        mock_cm.diagnose_ssl = AsyncMock(return_value=mock_diag_result)

        with (
            patch("config.settings", MagicMock(workflow_step_timeout=120, workflow_auto_rollback=True)),
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

            # Site created (steps 1-3), SSL failed (step 4), partial completion
            assert result.status == WorkflowStatus.PARTIALLY_COMPLETED
            assert not result.rolled_back


class TestTransactionRollbackVerification:
    """Test the rollback_transaction tool error paths."""

    @pytest.mark.asyncio
    async def test_rollback_not_possible(self):
        """Rollback fails when can_rollback returns False."""
        mock_tm = MagicMock()
        mock_tm.can_rollback = AsyncMock(return_value=(False, "Snapshot expired"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            from mcp_server.tools import rollback_transaction

            result = await rollback_transaction("txn-old")
            assert result["success"] is False
            assert "Snapshot expired" in result["message"]

    @pytest.mark.asyncio
    async def test_rollback_success(self):
        """Successful rollback returns rollback_transaction_id."""
        mock_rb_result = MagicMock()
        mock_rb_result.success = True
        mock_rb_result.rollback_transaction_id = "txn-rb-456"
        mock_rb_result.original_transaction_id = "txn-orig-123"
        mock_rb_result.message = "Rolled back successfully"
        mock_rb_result.warnings = []

        mock_tm = MagicMock()
        mock_tm.can_rollback = AsyncMock(return_value=(True, None))
        mock_tm.rollback_transaction = AsyncMock(return_value=mock_rb_result)

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            from mcp_server.tools import rollback_transaction

            result = await rollback_transaction("txn-orig-123", reason="Test rollback")
            assert result["success"] is True
            assert result["rollback_transaction_id"] == "txn-rb-456"

    @pytest.mark.asyncio
    async def test_rollback_exception(self):
        """Exception during rollback returns structured error."""
        mock_tm = MagicMock()
        mock_tm.can_rollback = AsyncMock(return_value=(True, None))
        mock_tm.rollback_transaction = AsyncMock(side_effect=RuntimeError("DB error"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            from mcp_server.tools import rollback_transaction

            result = await rollback_transaction("txn-err")
            assert result["success"] is False
            assert "DB error" in result["message"]
