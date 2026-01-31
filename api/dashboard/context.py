"""
Shared template context builders for dashboard pages.
"""

import logging
from datetime import datetime

from fastapi import Request

from config import get_nginx_conf_path, settings
from models.auth import AuthContext

logger = logging.getLogger(__name__)


async def base_context(request: Request, auth: AuthContext) -> dict:
    """
    Build the base template context shared by all pages.

    Includes auth state, system health summary, and navigation state.
    """
    ctx = {
        "request": request,
        "auth": auth,
        "auth_enabled": settings.auth_enabled,
        "current_path": request.url.path,
        "now": datetime.now(),
    }

    # Lightweight health summary for the status indicator
    ctx["health"] = await _get_health_summary()

    return ctx


async def _get_health_summary() -> dict:
    """Get a lightweight health summary for the nav status indicator."""
    summary = {
        "status": "unknown",
        "nginx_running": False,
        "total_sites": 0,
        "enabled_sites": 0,
        "disabled_sites": 0,
        "ssl_warnings": 0,
    }

    # Count sites
    try:
        conf_dir = get_nginx_conf_path()
        if conf_dir.exists():
            summary["enabled_sites"] = len(list(conf_dir.glob("*.conf")))
            summary["disabled_sites"] = len(list(conf_dir.glob("*.conf.disabled")))
            summary["total_sites"] = summary["enabled_sites"] + summary["disabled_sites"]
    except Exception as e:
        logger.warning(f"Failed to count sites: {e}")

    # Check NGINX status
    try:
        from core.docker_service import docker_service

        container_status = await docker_service.get_container_status()
        summary["nginx_running"] = container_status.get("running", False)
        health = container_status.get("health_status", "unknown")
        if summary["nginx_running"] and health == "healthy":
            summary["status"] = "healthy"
        elif summary["nginx_running"]:
            summary["status"] = "degraded"
        else:
            summary["status"] = "unhealthy"
    except Exception as e:
        logger.warning(f"Failed to get NGINX status: {e}")
        summary["status"] = "error"

    # SSL warnings count
    try:
        from core.cert_manager import get_cert_manager
        from models.certificate import CertificateStatus

        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates()
        summary["ssl_warnings"] = len(
            [c for c in certs if c.status in (CertificateStatus.EXPIRING_SOON, CertificateStatus.EXPIRED)]
        )
    except Exception:
        pass

    return summary
