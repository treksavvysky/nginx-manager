"""
Context helpers for generating rich AI-friendly responses.

This module provides functions to generate contextual suggestions,
warnings, and guidance for API responses. Designed to help AI agents
understand what happened and what to do next.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class SuggestionPriority(str, Enum):
    """Priority level for suggestions."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Suggestion:
    """A contextual suggestion for the AI agent."""
    action: str
    reason: str
    endpoint: Optional[str] = None
    priority: SuggestionPriority = SuggestionPriority.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "action": self.action,
            "reason": self.reason,
            "priority": self.priority.value
        }
        if self.endpoint:
            result["endpoint"] = self.endpoint
        return result


@dataclass
class Warning:
    """A non-blocking warning about the current state."""
    code: str
    message: str
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "code": self.code,
            "message": self.message
        }
        if self.suggestion:
            result["suggestion"] = self.suggestion
        return result


def get_site_create_suggestions(
    site_name: str,
    site_type: str,
    reloaded: bool,
    enabled: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after creating a site."""
    suggestions = []

    if not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to activate the new site",
            reason="The site configuration has been created but NGINX hasn't loaded it yet",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    if site_type == "static":
        suggestions.append(Suggestion(
            action="Verify the document root directory exists and has correct permissions",
            reason="Static sites require the root directory to be accessible by NGINX",
            priority=SuggestionPriority.MEDIUM
        ).to_dict())
    elif site_type == "reverse_proxy":
        suggestions.append(Suggestion(
            action="Verify the upstream service is running and accessible",
            reason="Reverse proxy requires the backend service to be available",
            priority=SuggestionPriority.MEDIUM
        ).to_dict())

    suggestions.append(Suggestion(
        action="Test the site by accessing it in a browser or with curl",
        reason="Verify the configuration works as expected",
        priority=SuggestionPriority.LOW
    ).to_dict())

    return suggestions


def get_site_update_suggestions(
    site_name: str,
    reloaded: bool,
    changes_made: List[str]
) -> List[Dict[str, Any]]:
    """Generate suggestions after updating a site."""
    suggestions = []

    if not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to apply the changes",
            reason=f"Site '{site_name}' was updated but NGINX hasn't reloaded yet",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    suggestions.append(Suggestion(
        action="Test the site to verify changes work correctly",
        reason="Configuration changes should be validated in practice",
        priority=SuggestionPriority.MEDIUM
    ).to_dict())

    return suggestions


def get_site_delete_suggestions(
    site_name: str,
    reloaded: bool,
    was_enabled: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after deleting a site."""
    suggestions = []

    if was_enabled and not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to remove the site from active configuration",
            reason=f"Site '{site_name}' was deleted but NGINX still has the old config in memory",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    suggestions.append(Suggestion(
        action="Verify the site is no longer accessible",
        reason="Confirm the deletion took effect",
        priority=SuggestionPriority.LOW
    ).to_dict())

    return suggestions


def get_site_enable_suggestions(
    site_name: str,
    reloaded: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after enabling a site."""
    suggestions = []

    if not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to activate the enabled site",
            reason=f"Site '{site_name}' is enabled but NGINX hasn't loaded it yet",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    suggestions.append(Suggestion(
        action="Test the site to verify it's working",
        reason="Confirm the site is accessible after enabling",
        priority=SuggestionPriority.MEDIUM
    ).to_dict())

    return suggestions


def get_site_disable_suggestions(
    site_name: str,
    reloaded: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after disabling a site."""
    suggestions = []

    if not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to deactivate the disabled site",
            reason=f"Site '{site_name}' is disabled but NGINX still has it in memory",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    suggestions.append(Suggestion(
        action="Verify the site is no longer accessible",
        reason="Confirm the site has been deactivated",
        priority=SuggestionPriority.LOW
    ).to_dict())

    suggestions.append(Suggestion(
        action="Re-enable the site when ready",
        reason="The configuration is preserved and can be re-enabled later",
        endpoint=f"POST /sites/{site_name}/enable",
        priority=SuggestionPriority.LOW
    ).to_dict())

    return suggestions


def get_nginx_reload_suggestions(
    success: bool,
    health_verified: bool,
    auto_rolled_back: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after NGINX reload."""
    suggestions = []

    if success and health_verified:
        suggestions.append(Suggestion(
            action="Verify your sites are working correctly",
            reason="NGINX reloaded successfully - test your applications",
            priority=SuggestionPriority.LOW
        ).to_dict())
    elif not success and auto_rolled_back:
        suggestions.append(Suggestion(
            action="Review the configuration that caused the failure",
            reason="The reload failed and was automatically rolled back",
            endpoint="GET /transactions/",
            priority=SuggestionPriority.HIGH
        ).to_dict())
        suggestions.append(Suggestion(
            action="Check the NGINX error logs for details",
            reason="Logs may contain specific error information",
            priority=SuggestionPriority.HIGH
        ).to_dict())
    elif not health_verified:
        suggestions.append(Suggestion(
            action="Check if NGINX is responding to requests",
            reason="Health check failed after reload",
            endpoint="GET /nginx/status",
            priority=SuggestionPriority.HIGH
        ).to_dict())
        suggestions.append(Suggestion(
            action="Review recent configuration changes",
            reason="A recent change may have caused the issue",
            endpoint="GET /transactions/",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    return suggestions


def get_nginx_restart_suggestions(
    success: bool,
    health_verified: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions after NGINX restart."""
    suggestions = []

    if success and health_verified:
        suggestions.append(Suggestion(
            action="Verify your sites are working correctly",
            reason="NGINX restarted successfully - all connections were reset",
            priority=SuggestionPriority.MEDIUM
        ).to_dict())
    elif not health_verified:
        suggestions.append(Suggestion(
            action="Check NGINX container status",
            reason="Health check failed after restart",
            endpoint="GET /nginx/status",
            priority=SuggestionPriority.HIGH
        ).to_dict())
        suggestions.append(Suggestion(
            action="Check NGINX error logs",
            reason="Container may have failed to start properly",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    return suggestions


def get_config_warnings(
    ssl_enabled: bool = False,
    has_ssl_cert: bool = False,
    listen_ports: List[int] = None,
    proxy_pass: Optional[str] = None,
    root_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Generate warnings about the current configuration."""
    warnings = []
    listen_ports = listen_ports or []

    # SSL warnings
    if ssl_enabled and not has_ssl_cert:
        warnings.append(Warning(
            code="ssl_no_cert",
            message="SSL is enabled but no certificate is configured",
            suggestion="Add SSL certificate or disable SSL"
        ).to_dict())

    if 443 in listen_ports and not ssl_enabled:
        warnings.append(Warning(
            code="port_443_no_ssl",
            message="Listening on port 443 without SSL enabled",
            suggestion="Enable SSL for HTTPS traffic"
        ).to_dict())

    # Proxy warnings
    if proxy_pass and proxy_pass.startswith("http://localhost"):
        warnings.append(Warning(
            code="localhost_proxy",
            message="Proxying to localhost - ensure the backend is accessible from the NGINX container",
            suggestion="Use container name or host.docker.internal instead of localhost"
        ).to_dict())

    return warnings


def get_system_state_summary(
    nginx_running: bool,
    nginx_healthy: bool,
    total_sites: int,
    enabled_sites: int,
    disabled_sites: int
) -> Dict[str, Any]:
    """Generate a summary of the current system state."""
    return {
        "nginx": {
            "running": nginx_running,
            "healthy": nginx_healthy,
            "status": "healthy" if nginx_healthy else ("running" if nginx_running else "down")
        },
        "sites": {
            "total": total_sites,
            "enabled": enabled_sites,
            "disabled": disabled_sites
        }
    }


# SSL Certificate Helpers

def get_cert_request_suggestions(
    domain: str,
    reloaded: bool,
    sites_using_cert: List[str]
) -> List[Dict[str, Any]]:
    """Generate suggestions after certificate issuance."""
    suggestions = []

    if not reloaded:
        suggestions.append(Suggestion(
            action="Reload NGINX to apply SSL configuration",
            reason="Certificate installed but NGINX hasn't loaded it yet",
            endpoint="POST /nginx/reload",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    if not sites_using_cert:
        suggestions.append(Suggestion(
            action="Update site configuration to use SSL",
            reason="Certificate is ready but no sites are configured to use it",
            endpoint=f"PUT /sites/{domain}",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    suggestions.append(Suggestion(
        action="Test HTTPS connectivity",
        reason="Verify SSL is working correctly",
        priority=SuggestionPriority.MEDIUM
    ).to_dict())

    suggestions.append(Suggestion(
        action="Consider enabling HSTS",
        reason="HTTP Strict Transport Security improves security",
        priority=SuggestionPriority.LOW
    ).to_dict())

    return suggestions


def get_cert_renewal_suggestions(domain: str) -> List[Dict[str, Any]]:
    """Generate suggestions after certificate renewal."""
    suggestions = []

    suggestions.append(Suggestion(
        action="Verify HTTPS is still working",
        reason="Confirm the renewed certificate is serving correctly",
        priority=SuggestionPriority.MEDIUM
    ).to_dict())

    suggestions.append(Suggestion(
        action="Check certificate expiry date",
        reason="Confirm the renewal extended the certificate validity",
        endpoint=f"GET /certificates/{domain}",
        priority=SuggestionPriority.LOW
    ).to_dict())

    return suggestions


def get_cert_expiry_warnings(cert) -> List[Dict[str, Any]]:
    """Generate warnings for certificate expiry."""
    from datetime import datetime
    warnings = []

    if not cert.not_after:
        return warnings

    days_left = (cert.not_after - datetime.utcnow()).days

    if days_left < 0:
        warnings.append(Warning(
            code="cert_expired",
            message=f"Certificate expired {abs(days_left)} days ago",
            suggestion="Request a new certificate immediately"
        ).to_dict())
    elif days_left < 7:
        warnings.append(Warning(
            code="cert_expiring_critical",
            message=f"Certificate expires in {days_left} days (CRITICAL)",
            suggestion="Renew certificate immediately"
        ).to_dict())
    elif days_left < 14:
        warnings.append(Warning(
            code="cert_expiring_soon",
            message=f"Certificate expires in {days_left} days",
            suggestion="Consider renewing soon"
        ).to_dict())
    elif days_left < 30:
        warnings.append(Warning(
            code="cert_expiring_warning",
            message=f"Certificate expires in {days_left} days",
            suggestion="Certificate will be auto-renewed if enabled"
        ).to_dict())

    if not cert.auto_renew and cert.certificate_type.value == "letsencrypt":
        warnings.append(Warning(
            code="auto_renew_disabled",
            message="Auto-renewal is disabled for this Let's Encrypt certificate",
            suggestion="Enable auto_renew or manually renew before expiry"
        ).to_dict())

    return warnings


def get_cert_diagnostic_suggestions(
    domain: str,
    dns_ok: bool,
    port_80_ok: bool,
    has_cert: bool
) -> List[Dict[str, Any]]:
    """Generate suggestions based on SSL diagnostic results."""
    suggestions = []

    if not dns_ok:
        suggestions.append(Suggestion(
            action="Configure DNS A record",
            reason="Domain must resolve to this server for certificate validation",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    if dns_ok and not port_80_ok:
        suggestions.append(Suggestion(
            action="Open port 80 in firewall",
            reason="Let's Encrypt requires port 80 for HTTP-01 challenge",
            priority=SuggestionPriority.HIGH
        ).to_dict())

    if dns_ok and port_80_ok and not has_cert:
        suggestions.append(Suggestion(
            action="Request SSL certificate",
            reason="Domain is ready for SSL certificate",
            endpoint="POST /certificates/",
            priority=SuggestionPriority.MEDIUM
        ).to_dict())

    if has_cert:
        suggestions.append(Suggestion(
            action="Update site to use HTTPS",
            reason="SSL certificate is available for this domain",
            priority=SuggestionPriority.MEDIUM
        ).to_dict())

    return suggestions


def get_error_context(
    error_type: str,
    error_message: str,
    operation: str,
    resource: Optional[str] = None
) -> Dict[str, Any]:
    """Generate rich error context for AI agents."""
    context = {
        "error_type": error_type,
        "message": error_message,
        "operation": operation
    }

    if resource:
        context["resource"] = resource

    # Add fix suggestions based on error type
    fix_suggestions = []

    if error_type == "site_not_found":
        fix_suggestions.append("Check the site name spelling")
        fix_suggestions.append("Use GET /sites/ to list available sites")
    elif error_type == "site_already_exists":
        fix_suggestions.append("Use PUT to update the existing site")
        fix_suggestions.append("Delete the existing site first if you want to recreate it")
    elif error_type == "config_validation_failed":
        fix_suggestions.append("Review the NGINX error message for syntax issues")
        fix_suggestions.append("Use dry_run=true to preview the config before applying")
    elif error_type == "container_not_found":
        fix_suggestions.append("Ensure the NGINX container is running")
        fix_suggestions.append("Check docker compose status")
    elif error_type == "docker_unavailable":
        fix_suggestions.append("Verify Docker daemon is running")
        fix_suggestions.append("Check Docker socket permissions")

    context["how_to_fix"] = fix_suggestions

    return context
