"""
Unit tests for MCP tool handler functions.

Tests all tool functions in mcp_server/tools.py, covering success paths,
error paths, dry-run modes, and edge cases.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.tools import (
    create_site,
    delete_site,
    diagnose_ssl,
    disable_site,
    enable_site,
    nginx_reload,
    nginx_restart,
    nginx_test,
    request_certificate,
    rollback_transaction,
    update_site,
)

# =============================================================================
# Site Creation Tests
# =============================================================================


class TestCreateSiteTool:
    """Tests for the create_site tool function."""

    @pytest.mark.asyncio
    async def test_create_site_already_exists(self, tmp_conf_dir):
        """If the .conf file already exists, return success=False."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server { }")

        with patch("mcp_server.tools.create_site.__module__", "mcp_server.tools"):
            with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
                result = await create_site(
                    name="example.com",
                    server_names=["example.com"],
                    site_type="static",
                )

        assert result["success"] is False
        assert "already exists" in result["message"]
        assert len(result["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_create_site_disabled_exists(self, tmp_conf_dir):
        """If a .conf.disabled file exists, return success=False with enable suggestion."""
        disabled_file = tmp_conf_dir / "example.com.conf.disabled"
        disabled_file.write_text("server { }")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await create_site(
                name="example.com",
                server_names=["example.com"],
                site_type="static",
            )

        assert result["success"] is False
        assert "disabled" in result["message"]
        assert any("enable" in s.lower() or "Enable" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_create_site_invalid_site_type(self, tmp_conf_dir):
        """Invalid site_type returns success=False with helpful message."""
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await create_site(
                name="example.com",
                server_names=["example.com"],
                site_type="invalid_type",
            )

        assert result["success"] is False
        assert "Invalid site_type" in result["message"]
        assert len(result["suggestions"]) == 2

    @pytest.mark.asyncio
    async def test_create_site_dry_run_success(self, tmp_conf_dir):
        """Dry run returns preview with generated config content."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = "server {\n    listen 80;\n}"

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
        ):
            result = await create_site(
                name="example.com",
                server_names=["example.com"],
                site_type="static",
                root_path="/var/www/example",
                dry_run=True,
            )

        assert result["dry_run"] is True
        assert result["would_succeed"] is True
        assert result["operation"] == "create_site"
        assert "generated_config" in result
        assert result["generated_config"] == "server {\n    listen 80;\n}"
        assert result["reload_required"] is True

    @pytest.mark.asyncio
    async def test_create_site_success(self, tmp_conf_dir, mock_transaction_ctx):
        """Full create returns success=True with transaction_id."""
        mock_generator = MagicMock()
        mock_generator.generate.return_value = "server {\n    listen 80;\n    server_name example.com;\n}"

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.context_helpers.get_site_create_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            result = await create_site(
                name="example.com",
                server_names=["example.com"],
                site_type="static",
                root_path="/var/www/example",
                auto_reload=True,
            )

        assert result["success"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert result["site_name"] == "example.com"
        assert result["reloaded"] is True
        assert result["enabled"] is True
        # Verify the conf file was actually written
        assert (tmp_conf_dir / "example.com.conf").exists()

    @pytest.mark.asyncio
    async def test_create_site_config_generation_error(self, tmp_conf_dir):
        """ConfigGeneratorError is caught and returns success=False."""
        from core.config_generator import ConfigGeneratorError

        mock_generator = MagicMock()
        mock_generator.generate.side_effect = ConfigGeneratorError(
            message="Template rendering failed", site_name="example.com"
        )

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
        ):
            result = await create_site(
                name="example.com",
                server_names=["example.com"],
                site_type="static",
                root_path="/var/www/example",
            )

        assert result["success"] is False
        assert "Template rendering failed" in result["message"]
        assert len(result["suggestions"]) > 0


# =============================================================================
# Site Update Tests
# =============================================================================


class TestUpdateSiteTool:
    """Tests for the update_site tool function."""

    @pytest.mark.asyncio
    async def test_update_site_not_found(self, tmp_conf_dir):
        """Updating a non-existent site returns success=False."""
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await update_site(name="nonexistent.com")

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_update_site_disabled(self, tmp_conf_dir):
        """Updating a disabled site returns success=False with enable suggestion."""
        disabled_file = tmp_conf_dir / "example.com.conf.disabled"
        disabled_file.write_text("server { listen 80; }")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await update_site(name="example.com")

        assert result["success"] is False
        assert "disabled" in result["message"].lower() or "Enable" in result["message"]
        assert any("enable" in s.lower() for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_update_site_dry_run(self, tmp_conf_dir):
        """Dry run returns preview with current_content and new_content."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server {\n    listen 80;\n    server_name example.com;\n}")

        mock_parser = MagicMock()
        mock_parser.parse_config_file.return_value = {"parsed": True}

        mock_adapter = MagicMock()
        mock_adapter.to_rich_dict.return_value = {
            "server_names": ["example.com"],
            "listen_ports": [80],
            "root_path": "/var/www/example",
            "proxy_pass": None,
        }

        mock_generator = MagicMock()
        mock_generator.generate.return_value = "server {\n    listen 8080;\n    server_name example.com;\n}"

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_manager.nginx_parser", mock_parser),
            patch("core.config_manager.ConfigAdapter", mock_adapter),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
        ):
            result = await update_site(
                name="example.com",
                listen_port=8080,
                dry_run=True,
            )

        assert result["dry_run"] is True
        assert result["would_succeed"] is True
        assert result["operation"] == "update_site"
        assert "current_content" in result
        assert "new_content" in result
        assert result["reload_required"] is True

    @pytest.mark.asyncio
    async def test_update_site_success(self, tmp_conf_dir, mock_transaction_ctx):
        """Full update returns success=True with transaction_id."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server {\n    listen 80;\n    server_name example.com;\n}")

        mock_parser = MagicMock()
        mock_parser.parse_config_file.return_value = {"parsed": True}

        mock_adapter = MagicMock()
        mock_adapter.to_rich_dict.return_value = {
            "server_names": ["example.com"],
            "listen_ports": [80],
            "root_path": "/var/www/example",
            "proxy_pass": None,
        }

        mock_generator = MagicMock()
        mock_generator.generate.return_value = "server {\n    listen 8080;\n    server_name example.com;\n}"

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.config_manager.nginx_parser", mock_parser),
            patch("core.config_manager.ConfigAdapter", mock_adapter),
            patch("core.config_generator.get_config_generator", return_value=mock_generator),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.context_helpers.get_site_update_suggestions", return_value=[]),
            patch("core.context_helpers.get_config_warnings", return_value=[]),
        ):
            result = await update_site(
                name="example.com",
                listen_port=8080,
                auto_reload=True,
            )

        assert result["success"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert result["site_name"] == "example.com"
        assert result["reloaded"] is True


# =============================================================================
# Site Delete Tests
# =============================================================================


class TestDeleteSiteTool:
    """Tests for the delete_site tool function."""

    @pytest.mark.asyncio
    async def test_delete_site_not_found(self, tmp_conf_dir):
        """Deleting a non-existent site returns success=False."""
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await delete_site(name="nonexistent.com")

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_delete_site_dry_run(self, tmp_conf_dir):
        """Dry run returns preview with file_path and reload_required."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server {\n    listen 80;\n}")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await delete_site(name="example.com", dry_run=True)

        assert result["dry_run"] is True
        assert result["would_succeed"] is True
        assert result["operation"] == "delete_site"
        assert result["reload_required"] is True
        assert "file_path" in result
        # File should still exist after dry run
        assert conf_file.exists()

    @pytest.mark.asyncio
    async def test_delete_site_success(self, tmp_conf_dir, mock_transaction_ctx):
        """Full delete returns success=True and removes the file."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server { listen 80; }")

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.context_helpers.get_site_delete_suggestions", return_value=[]),
        ):
            result = await delete_site(name="example.com", auto_reload=True)

        assert result["success"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert result["site_name"] == "example.com"
        assert not conf_file.exists()


# =============================================================================
# Enable / Disable Site Tests
# =============================================================================


class TestEnableDisableSiteTools:
    """Tests for the enable_site and disable_site tool functions."""

    @pytest.mark.asyncio
    async def test_enable_already_enabled(self, tmp_conf_dir):
        """Enabling an already enabled site returns success=False."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server { listen 80; }")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await enable_site(name="example.com")

        assert result["success"] is False
        assert "already enabled" in result["message"]

    @pytest.mark.asyncio
    async def test_enable_not_found(self, tmp_conf_dir):
        """Enabling a non-existent site returns success=False."""
        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await enable_site(name="nonexistent.com")

        assert result["success"] is False
        assert "not found" in result["message"]

    @pytest.mark.asyncio
    async def test_enable_site_success(self, tmp_conf_dir, mock_transaction_ctx):
        """Enabling a disabled site renames the file and returns success=True."""
        disabled_file = tmp_conf_dir / "example.com.conf.disabled"
        disabled_file.write_text("server { listen 80; }")

        mock_settings = MagicMock()
        mock_settings.validate_before_deploy = False

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("config.settings", mock_settings),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.context_helpers.get_site_enable_suggestions", return_value=[]),
        ):
            result = await enable_site(name="example.com", auto_reload=True)

        assert result["success"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert result["enabled"] is True
        # .conf should now exist, .disabled should not
        assert (tmp_conf_dir / "example.com.conf").exists()
        assert not disabled_file.exists()

    @pytest.mark.asyncio
    async def test_disable_already_disabled(self, tmp_conf_dir):
        """Disabling an already disabled site returns success=False."""
        disabled_file = tmp_conf_dir / "example.com.conf.disabled"
        disabled_file.write_text("server { listen 80; }")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await disable_site(name="example.com")

        assert result["success"] is False
        assert "already disabled" in result["message"]

    @pytest.mark.asyncio
    async def test_disable_dry_run(self, tmp_conf_dir):
        """Dry run for disable returns preview without modifying files."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server { listen 80; }")

        with patch("config.get_nginx_conf_path", return_value=tmp_conf_dir):
            result = await disable_site(name="example.com", dry_run=True)

        assert result["dry_run"] is True
        assert result["would_succeed"] is True
        assert result["operation"] == "disable_site"
        assert result["reload_required"] is True
        # File should still exist after dry run
        assert conf_file.exists()

    @pytest.mark.asyncio
    async def test_disable_site_success(self, tmp_conf_dir, mock_transaction_ctx):
        """Disabling a site renames the file and returns success=True."""
        conf_file = tmp_conf_dir / "example.com.conf"
        conf_file.write_text("server { listen 80; }")

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("config.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.context_helpers.get_site_disable_suggestions", return_value=[]),
        ):
            result = await disable_site(name="example.com", auto_reload=True)

        assert result["success"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert result["enabled"] is False
        assert not conf_file.exists()
        assert (tmp_conf_dir / "example.com.conf.disabled").exists()


# =============================================================================
# NGINX Control Tests
# =============================================================================


class TestNginxControlTools:
    """Tests for nginx_reload, nginx_restart, and nginx_test tool functions."""

    @pytest.mark.asyncio
    async def test_nginx_reload_dry_run(self, mock_docker_service):
        """Dry run returns container status and config validation result."""
        with patch("core.docker_service.docker_service", mock_docker_service):
            result = await nginx_reload(dry_run=True)

        assert result["dry_run"] is True
        assert result["operation"] == "nginx_reload"
        assert result["config_valid"] is True
        assert result["container_running"] is True
        assert result["would_drop_connections"] is False
        assert result["would_succeed"] is True

    @pytest.mark.asyncio
    async def test_nginx_reload_success(self, mock_docker_service, mock_transaction_ctx):
        """Successful reload returns success=True with health info."""
        mock_health = MagicMock()
        mock_health.verify_health = AsyncMock(return_value=True)

        with (
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.health_checker.health_checker", mock_health),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            result = await nginx_reload(dry_run=False)

        assert result["success"] is True
        assert result["operation"] == "reload"
        assert result["health_verified"] is True
        assert result["transaction_id"] == "txn-test-123"
        assert "timestamp" in result
        assert "duration_ms" in result

    @pytest.mark.asyncio
    async def test_nginx_reload_docker_error(self, mock_transaction_ctx):
        """DockerServiceError during reload returns success=False."""
        from core.docker_service import DockerServiceError

        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(
            side_effect=DockerServiceError(
                message="Container not running",
                error_type="container_error",
                suggestion="Start the NGINX container",
            )
        )

        with (
            patch("core.docker_service.docker_service", mock_docker),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            result = await nginx_reload(dry_run=False)

        assert result["success"] is False
        assert result["message"] == "Container not running"
        assert result["suggestion"] == "Start the NGINX container"
        assert result["transaction_id"] == "txn-test-123"

    @pytest.mark.asyncio
    async def test_nginx_restart_dry_run(self, mock_docker_service):
        """Dry run for restart shows would_drop_connections=True."""
        with patch("core.docker_service.docker_service", mock_docker_service):
            result = await nginx_restart(dry_run=True)

        assert result["dry_run"] is True
        assert result["operation"] == "nginx_restart"
        assert result["would_drop_connections"] is True
        assert result["would_succeed"] is True
        assert result["container_running"] is True
        assert "estimated_downtime_ms" in result

    @pytest.mark.asyncio
    async def test_nginx_restart_success(self, mock_docker_service, mock_transaction_ctx):
        """Successful restart returns success=True."""
        mock_health = MagicMock()
        mock_health.verify_health = AsyncMock(return_value=True)

        with (
            patch("core.docker_service.docker_service", mock_docker_service),
            patch("core.health_checker.health_checker", mock_health),
            patch("core.transaction_context.transactional_operation", mock_transaction_ctx),
        ):
            result = await nginx_restart(dry_run=False)

        assert result["success"] is True
        assert result["operation"] == "restart"
        assert result["health_verified"] is True
        assert result["transaction_id"] == "txn-test-123"

    @pytest.mark.asyncio
    async def test_nginx_test_success(self):
        """Successful config test returns success=True."""
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(True, "nginx: configuration ok", ""))

        with patch("core.docker_service.docker_service", mock_docker):
            result = await nginx_test()

        assert result["success"] is True
        assert result["message"] == "Configuration is valid"
        assert result["stdout"] == "nginx: configuration ok"
        assert "tested_at" in result
        assert result["suggestions"] == []

    @pytest.mark.asyncio
    async def test_nginx_test_failure(self):
        """Failed config test returns success=False with error details."""
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(False, "", "nginx: [emerg] unknown directive"))

        with patch("core.docker_service.docker_service", mock_docker):
            result = await nginx_test()

        assert result["success"] is False
        assert result["message"] == "Configuration has errors"
        assert result["stderr"] == "nginx: [emerg] unknown directive"
        assert len(result["suggestions"]) > 0

    @pytest.mark.asyncio
    async def test_nginx_test_docker_error(self):
        """DockerServiceError during test returns success=False."""
        from core.docker_service import DockerServiceError

        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(
            side_effect=DockerServiceError(
                message="Docker daemon unavailable",
                error_type="docker_error",
                suggestion="Check Docker is running",
            )
        )

        with patch("core.docker_service.docker_service", mock_docker):
            result = await nginx_test()

        assert result["success"] is False
        assert result["message"] == "Docker daemon unavailable"
        assert result["suggestion"] == "Check Docker is running"


# =============================================================================
# Certificate Tests
# =============================================================================


class TestCertificateTools:
    """Tests for certificate tool functions."""

    @pytest.mark.asyncio
    async def test_request_certificate_dry_run(self):
        """Dry run returns prerequisite check results."""
        mock_dry_run_result = MagicMock()
        mock_dry_run_result.would_succeed = True
        mock_dry_run_result.message = "Domain is ready for certificate"
        mock_dry_run_result.domain_resolves = True
        mock_dry_run_result.domain_points_to_server = True
        mock_dry_run_result.port_80_accessible = True
        mock_dry_run_result.warnings = []
        mock_dry_run_result.suggestions = []

        mock_cert_manager = MagicMock()
        mock_cert_manager.request_certificate = AsyncMock(return_value=mock_dry_run_result)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_cert_manager):
            result = await request_certificate(
                domain="example.com",
                alt_names=["www.example.com"],
                dry_run=True,
            )

        assert result["dry_run"] is True
        assert result["would_succeed"] is True
        assert result["domain"] == "example.com"
        assert result["domain_resolves"] is True
        assert result["port_80_accessible"] is True
        assert result["operation"] == "request_certificate"

    @pytest.mark.asyncio
    async def test_request_certificate_success(self):
        """Successful certificate request returns cert details."""
        mock_cert = MagicMock()
        mock_cert.domain = "example.com"
        mock_cert.status.value = "valid"
        mock_cert.not_after.isoformat.return_value = "2027-01-29T00:00:00"
        mock_cert.days_until_expiry = 365

        mock_cert_manager = MagicMock()
        mock_cert_manager.request_certificate = AsyncMock(return_value=mock_cert)

        with (
            patch("core.cert_manager.get_cert_manager", return_value=mock_cert_manager),
            patch("core.docker_service.docker_service.reload_nginx", new_callable=AsyncMock),
        ):
            result = await request_certificate(
                domain="example.com",
                dry_run=False,
            )

        assert result["success"] is True
        assert result["domain"] == "example.com"
        assert result["certificate"]["domain"] == "example.com"
        assert result["certificate"]["status"] == "valid"

    @pytest.mark.asyncio
    async def test_request_certificate_error(self):
        """CertificateError returns structured error response."""
        from core.cert_manager import CertificateError

        mock_cert_manager = MagicMock()
        mock_cert_manager.request_certificate = AsyncMock(
            side_effect=CertificateError(
                message="DNS resolution failed",
                domain="example.com",
                suggestion="Check DNS configuration",
            )
        )

        with patch("core.cert_manager.get_cert_manager", return_value=mock_cert_manager):
            result = await request_certificate(domain="example.com")

        assert result["success"] is False
        assert result["message"] == "DNS resolution failed"
        assert result["domain"] == "example.com"
        assert result["suggestion"] == "Check DNS configuration"

    @pytest.mark.asyncio
    async def test_diagnose_ssl_success(self):
        """Successful SSL diagnostic returns comprehensive results."""
        mock_result = MagicMock()
        mock_result.domain = "example.com"
        mock_result.dns_resolves = True
        mock_result.dns_ip_addresses = ["93.184.216.34"]
        mock_result.points_to_this_server = True
        mock_result.port_80_open = True
        mock_result.port_443_open = True
        mock_result.has_certificate = True
        mock_result.certificate_valid = True
        mock_result.certificate_expiry = None
        mock_result.certificate_issuer = "Let's Encrypt"
        mock_result.chain_valid = True
        mock_result.chain_issues = []
        mock_result.ready_for_ssl = True
        mock_result.issues = []
        mock_result.suggestions = []

        mock_cert_manager = MagicMock()
        mock_cert_manager.diagnose_ssl = AsyncMock(return_value=mock_result)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_cert_manager):
            result = await diagnose_ssl(domain="example.com")

        assert result["domain"] == "example.com"
        assert result["dns_resolves"] is True
        assert result["dns_ip_addresses"] == ["93.184.216.34"]
        assert result["points_to_this_server"] is True
        assert result["port_80_open"] is True
        assert result["port_443_open"] is True
        assert result["has_certificate"] is True
        assert result["certificate_valid"] is True
        assert result["certificate_issuer"] == "Let's Encrypt"
        assert result["chain_valid"] is True
        assert result["ready_for_ssl"] is True

    @pytest.mark.asyncio
    async def test_diagnose_ssl_exception(self):
        """Exception during diagnosis returns error response."""
        mock_cert_manager = MagicMock()
        mock_cert_manager.diagnose_ssl = AsyncMock(side_effect=RuntimeError("Network timeout"))

        with patch("core.cert_manager.get_cert_manager", return_value=mock_cert_manager):
            result = await diagnose_ssl(domain="example.com")

        assert result["domain"] == "example.com"
        assert result["ready_for_ssl"] is False
        assert any("Network timeout" in issue for issue in result["issues"])
        assert len(result["suggestions"]) > 0


# =============================================================================
# Rollback Transaction Tests
# =============================================================================


class TestRollbackTransactionTool:
    """Tests for the rollback_transaction tool function."""

    @pytest.mark.asyncio
    async def test_rollback_success(self):
        """Successful rollback returns success=True with IDs."""
        mock_rollback_result = MagicMock()
        mock_rollback_result.success = True
        mock_rollback_result.rollback_transaction_id = "txn-rollback-789"
        mock_rollback_result.original_transaction_id = "txn-original-123"
        mock_rollback_result.message = "Rollback completed"
        mock_rollback_result.warnings = []

        mock_txn_manager = MagicMock()
        mock_txn_manager.can_rollback = AsyncMock(return_value=(True, None))
        mock_txn_manager.rollback_transaction = AsyncMock(return_value=mock_rollback_result)

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_txn_manager):
            result = await rollback_transaction(
                transaction_id="txn-original-123",
                reason="Bad deployment",
            )

        assert result["success"] is True
        assert result["rollback_transaction_id"] == "txn-rollback-789"
        assert result["original_transaction_id"] == "txn-original-123"
        assert result["message"] == "Rollback completed"
        mock_txn_manager.rollback_transaction.assert_called_once_with(
            transaction_id="txn-original-123", reason="Bad deployment"
        )

    @pytest.mark.asyncio
    async def test_rollback_not_possible(self):
        """When can_rollback=False, return success=False with reason."""
        mock_txn_manager = MagicMock()
        mock_txn_manager.can_rollback = AsyncMock(return_value=(False, "Transaction already rolled back"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_txn_manager):
            result = await rollback_transaction(transaction_id="txn-old-456")

        assert result["success"] is False
        assert "already rolled back" in result["message"]
        assert result["original_transaction_id"] == "txn-old-456"

    @pytest.mark.asyncio
    async def test_rollback_exception(self):
        """Exception during rollback returns success=False."""
        mock_txn_manager = MagicMock()
        mock_txn_manager.can_rollback = AsyncMock(return_value=(True, None))
        mock_txn_manager.rollback_transaction = AsyncMock(side_effect=RuntimeError("Database error"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_txn_manager):
            result = await rollback_transaction(transaction_id="txn-fail-789")

        assert result["success"] is False
        assert "Database error" in result["message"]
        assert result["original_transaction_id"] == "txn-fail-789"
