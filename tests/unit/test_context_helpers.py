"""
Unit tests for context helpers module.

Tests the suggestion and warning generation functions for rich API responses.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from core.context_helpers import (
    get_site_create_suggestions,
    get_site_update_suggestions,
    get_site_delete_suggestions,
    get_site_enable_suggestions,
    get_site_disable_suggestions,
    get_nginx_reload_suggestions,
    get_nginx_restart_suggestions,
    get_config_warnings,
    get_system_state_summary,
    get_error_context,
    Suggestion,
    Warning,
    SuggestionPriority,
)


class TestSiteCreateSuggestions:
    """Tests for site creation suggestions."""

    def test_suggestions_when_not_reloaded(self):
        """Test high priority reload suggestion when not auto-reloaded."""
        suggestions = get_site_create_suggestions(
            site_name="test.local",
            site_type="static",
            reloaded=False,
            enabled=True
        )

        # Should have reload suggestion as high priority
        reload_suggestion = next(
            (s for s in suggestions if "reload" in s["action"].lower()),
            None
        )
        assert reload_suggestion is not None
        assert reload_suggestion["priority"] == "high"
        assert "POST /nginx/reload" in reload_suggestion["endpoint"]

    def test_no_reload_suggestion_when_reloaded(self):
        """Test no reload suggestion when auto-reloaded."""
        suggestions = get_site_create_suggestions(
            site_name="test.local",
            site_type="static",
            reloaded=True,
            enabled=True
        )

        # Should not have reload suggestion
        reload_suggestion = next(
            (s for s in suggestions if "reload nginx" in s["action"].lower()),
            None
        )
        assert reload_suggestion is None

    def test_static_site_suggestions(self):
        """Test suggestions specific to static sites."""
        suggestions = get_site_create_suggestions(
            site_name="test.local",
            site_type="static",
            reloaded=False,
            enabled=True
        )

        # Should have document root verification suggestion
        root_suggestion = next(
            (s for s in suggestions if "root" in s["action"].lower()),
            None
        )
        assert root_suggestion is not None

    def test_reverse_proxy_suggestions(self):
        """Test suggestions specific to reverse proxy sites."""
        suggestions = get_site_create_suggestions(
            site_name="api.local",
            site_type="reverse_proxy",
            reloaded=False,
            enabled=True
        )

        # Should have upstream verification suggestion
        upstream_suggestion = next(
            (s for s in suggestions if "upstream" in s["action"].lower()),
            None
        )
        assert upstream_suggestion is not None


class TestSiteDeleteSuggestions:
    """Tests for site deletion suggestions."""

    def test_reload_suggestion_when_was_enabled(self):
        """Test reload suggestion when deleting an enabled site."""
        suggestions = get_site_delete_suggestions(
            site_name="test.local",
            reloaded=False,
            was_enabled=True
        )

        reload_suggestion = next(
            (s for s in suggestions if "reload" in s["action"].lower()),
            None
        )
        assert reload_suggestion is not None
        assert reload_suggestion["priority"] == "high"

    def test_no_reload_for_disabled_site(self):
        """Test no reload needed when deleting a disabled site."""
        suggestions = get_site_delete_suggestions(
            site_name="test.local",
            reloaded=False,
            was_enabled=False
        )

        # Should not have high priority reload suggestion
        reload_suggestion = next(
            (s for s in suggestions if "reload nginx" in s["action"].lower() and s["priority"] == "high"),
            None
        )
        assert reload_suggestion is None


class TestConfigWarnings:
    """Tests for configuration warnings."""

    def test_localhost_proxy_warning(self):
        """Test warning for proxying to localhost."""
        warnings = get_config_warnings(
            proxy_pass="http://localhost:3000"
        )

        localhost_warning = next(
            (w for w in warnings if w["code"] == "localhost_proxy"),
            None
        )
        assert localhost_warning is not None
        assert "container" in localhost_warning["suggestion"].lower()

    def test_port_443_without_ssl_warning(self):
        """Test warning for port 443 without SSL."""
        warnings = get_config_warnings(
            ssl_enabled=False,
            listen_ports=[443]
        )

        ssl_warning = next(
            (w for w in warnings if w["code"] == "port_443_no_ssl"),
            None
        )
        assert ssl_warning is not None

    def test_ssl_without_cert_warning(self):
        """Test warning for SSL enabled without certificate."""
        warnings = get_config_warnings(
            ssl_enabled=True,
            has_ssl_cert=False
        )

        cert_warning = next(
            (w for w in warnings if w["code"] == "ssl_no_cert"),
            None
        )
        assert cert_warning is not None

    def test_no_warnings_for_valid_config(self):
        """Test no warnings for a properly configured site."""
        warnings = get_config_warnings(
            ssl_enabled=False,
            listen_ports=[80],
            root_path="/var/www/html"
        )

        assert len(warnings) == 0


class TestNginxReloadSuggestions:
    """Tests for NGINX reload suggestions."""

    def test_success_suggestions(self):
        """Test suggestions after successful reload."""
        suggestions = get_nginx_reload_suggestions(
            success=True,
            health_verified=True,
            auto_rolled_back=False
        )

        # Should have verification suggestion
        assert len(suggestions) > 0
        assert suggestions[0]["priority"] == "low"

    def test_rolled_back_suggestions(self):
        """Test suggestions after auto-rollback."""
        suggestions = get_nginx_reload_suggestions(
            success=False,
            health_verified=False,
            auto_rolled_back=True
        )

        # Should have high priority review suggestions
        high_priority = [s for s in suggestions if s["priority"] == "high"]
        assert len(high_priority) >= 1


class TestNginxRestartSuggestions:
    """Tests for NGINX restart suggestions."""

    def test_success_suggestions(self):
        """Test suggestions after successful restart."""
        suggestions = get_nginx_restart_suggestions(
            success=True,
            health_verified=True
        )

        # Should mention connections were reset
        assert len(suggestions) > 0
        assert "reset" in suggestions[0]["reason"].lower()

    def test_failed_health_check_suggestions(self):
        """Test suggestions when health check fails after restart."""
        suggestions = get_nginx_restart_suggestions(
            success=True,
            health_verified=False
        )

        # Should have high priority check suggestions
        high_priority = [s for s in suggestions if s["priority"] == "high"]
        assert len(high_priority) >= 1


class TestSystemStateSummary:
    """Tests for system state summary."""

    def test_healthy_system(self):
        """Test summary for a healthy system."""
        summary = get_system_state_summary(
            nginx_running=True,
            nginx_healthy=True,
            total_sites=5,
            enabled_sites=4,
            disabled_sites=1
        )

        assert summary["nginx"]["running"] is True
        assert summary["nginx"]["healthy"] is True
        assert summary["nginx"]["status"] == "healthy"
        assert summary["sites"]["total"] == 5
        assert summary["sites"]["enabled"] == 4
        assert summary["sites"]["disabled"] == 1

    def test_degraded_system(self):
        """Test summary for a running but unhealthy system."""
        summary = get_system_state_summary(
            nginx_running=True,
            nginx_healthy=False,
            total_sites=2,
            enabled_sites=2,
            disabled_sites=0
        )

        assert summary["nginx"]["running"] is True
        assert summary["nginx"]["healthy"] is False
        assert summary["nginx"]["status"] == "running"

    def test_down_system(self):
        """Test summary for a down system."""
        summary = get_system_state_summary(
            nginx_running=False,
            nginx_healthy=False,
            total_sites=2,
            enabled_sites=2,
            disabled_sites=0
        )

        assert summary["nginx"]["running"] is False
        assert summary["nginx"]["status"] == "down"


class TestErrorContext:
    """Tests for error context generation."""

    def test_site_not_found_context(self):
        """Test error context for site not found."""
        context = get_error_context(
            error_type="site_not_found",
            error_message="Site 'test.local' not found",
            operation="get",
            resource="test.local"
        )

        assert context["error_type"] == "site_not_found"
        assert "how_to_fix" in context
        assert len(context["how_to_fix"]) > 0
        assert any("GET /sites/" in fix for fix in context["how_to_fix"])

    def test_config_validation_failed_context(self):
        """Test error context for config validation failure."""
        context = get_error_context(
            error_type="config_validation_failed",
            error_message="nginx: configuration test failed",
            operation="create",
            resource="test.local"
        )

        assert "dry_run" in str(context["how_to_fix"]).lower()

    def test_docker_unavailable_context(self):
        """Test error context for Docker unavailable."""
        context = get_error_context(
            error_type="docker_unavailable",
            error_message="Cannot connect to Docker daemon",
            operation="reload"
        )

        assert any("docker" in fix.lower() for fix in context["how_to_fix"])


class TestSuggestionAndWarningModels:
    """Tests for Suggestion and Warning dataclasses."""

    def test_suggestion_to_dict(self):
        """Test Suggestion conversion to dict."""
        suggestion = Suggestion(
            action="Test action",
            reason="Test reason",
            endpoint="/test",
            priority=SuggestionPriority.HIGH
        )

        result = suggestion.to_dict()
        assert result["action"] == "Test action"
        assert result["reason"] == "Test reason"
        assert result["endpoint"] == "/test"
        assert result["priority"] == "high"

    def test_suggestion_without_endpoint(self):
        """Test Suggestion without endpoint."""
        suggestion = Suggestion(
            action="Test action",
            reason="Test reason"
        )

        result = suggestion.to_dict()
        assert "endpoint" not in result

    def test_warning_to_dict(self):
        """Test Warning conversion to dict."""
        warning = Warning(
            code="test_warning",
            message="Test message",
            suggestion="Fix it"
        )

        result = warning.to_dict()
        assert result["code"] == "test_warning"
        assert result["message"] == "Test message"
        assert result["suggestion"] == "Fix it"

    def test_warning_without_suggestion(self):
        """Test Warning without suggestion."""
        warning = Warning(
            code="test_warning",
            message="Test message"
        )

        result = warning.to_dict()
        assert "suggestion" not in result
