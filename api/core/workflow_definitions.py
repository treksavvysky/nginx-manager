"""
Concrete workflow step definitions.

Each function implements a single workflow step and returns
a result dict with at minimum {"success": bool, "message": str}.
Step functions receive a shared context dict for inter-step communication.
"""

import logging
from typing import Dict, Any

from core.workflow_engine import WorkflowEngine, WorkflowStep
from models.workflow import WorkflowType

logger = logging.getLogger(__name__)


# =============================================================================
# Setup Site Workflow Steps
# =============================================================================

async def step_check_prerequisites(context: Dict[str, Any]) -> Dict[str, Any]:
    """Check that NGINX is running and the site doesn't already exist."""
    from core.docker_service import docker_service, DockerServiceError
    from config import get_nginx_conf_path

    name = context["name"]
    conf_dir = get_nginx_conf_path()

    # Check NGINX is running
    try:
        status = await docker_service.get_container_status()
        if not status.get("running"):
            return {
                "success": False,
                "message": "NGINX container is not running. Start it before creating a site."
            }
    except DockerServiceError as e:
        return {
            "success": False,
            "message": f"Cannot connect to NGINX container: {e.message}"
        }

    # Check site doesn't already exist
    conf_file = conf_dir / f"{name}.conf"
    disabled_file = conf_dir / f"{name}.conf.disabled"

    if conf_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' already exists"
        }

    if disabled_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' exists but is disabled. Enable or delete it first."
        }

    return {
        "success": True,
        "message": "Prerequisites satisfied: NGINX running, site name available"
    }


async def step_create_site(context: Dict[str, Any]) -> Dict[str, Any]:
    """Create the NGINX site configuration."""
    from mcp_server.tools import create_site

    result = await create_site(
        name=context["name"],
        server_names=context["server_names"],
        site_type=context["site_type"],
        listen_port=context.get("listen_port", 80),
        root_path=context.get("root_path"),
        proxy_pass=context.get("proxy_pass"),
        auto_reload=True,
        dry_run=False
    )
    return result


async def step_verify_site(context: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the site configuration is valid after creation."""
    from mcp_server.tools import nginx_test

    result = await nginx_test()
    if result.get("success"):
        return {
            "success": True,
            "message": f"Site '{context['name']}' is configured and NGINX config is valid"
        }
    return {
        "success": False,
        "message": f"NGINX config validation failed after site creation: {result.get('stderr', 'unknown error')}"
    }


async def step_diagnose_ssl(context: Dict[str, Any]) -> Dict[str, Any]:
    """Check SSL prerequisites before requesting certificate."""
    from mcp_server.tools import diagnose_ssl

    domain = context["server_names"][0]
    result = await diagnose_ssl(domain=domain)

    if not result.get("ready_for_ssl"):
        issues = result.get("issues", [])
        return {
            "success": False,
            "message": f"SSL prerequisites not met for {domain}: {'; '.join(issues)}",
            "data": result
        }

    return {
        "success": True,
        "message": f"SSL prerequisites verified for {domain}",
        "data": result
    }


async def step_request_certificate(context: Dict[str, Any]) -> Dict[str, Any]:
    """Request Let's Encrypt SSL certificate."""
    from mcp_server.tools import request_certificate

    domain = context["server_names"][0]
    alt_names = context.get("ssl_alt_names") or []

    result = await request_certificate(
        domain=domain,
        alt_names=alt_names,
        auto_renew=context.get("auto_renew", True),
        auto_reload=True,
        dry_run=False
    )
    return result


async def step_verify_ssl(context: Dict[str, Any]) -> Dict[str, Any]:
    """Verify SSL certificate is installed and NGINX config is valid."""
    from mcp_server.tools import nginx_test

    result = await nginx_test()
    if result.get("success"):
        return {
            "success": True,
            "message": "SSL certificate installed and NGINX config valid"
        }
    return {
        "success": False,
        "message": f"NGINX config invalid after SSL install: {result.get('stderr', 'unknown error')}"
    }


# =============================================================================
# Migrate Site Workflow Steps
# =============================================================================

async def step_verify_site_exists(context: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the site to migrate exists."""
    from config import get_nginx_conf_path

    name = context["name"]
    conf_dir = get_nginx_conf_path()
    conf_file = conf_dir / f"{name}.conf"

    if not conf_file.exists():
        return {
            "success": False,
            "message": f"Site '{name}' not found. Cannot migrate a non-existent site."
        }

    return {
        "success": True,
        "message": f"Site '{name}' found and ready for migration"
    }


async def step_update_site(context: Dict[str, Any]) -> Dict[str, Any]:
    """Update the site configuration."""
    from mcp_server.tools import update_site

    result = await update_site(
        name=context["name"],
        server_names=context.get("server_names"),
        listen_port=context.get("listen_port"),
        root_path=context.get("root_path"),
        proxy_pass=context.get("proxy_pass"),
        auto_reload=True,
        dry_run=False
    )
    return result


async def step_test_config_after_update(context: Dict[str, Any]) -> Dict[str, Any]:
    """Validate NGINX configuration after update."""
    from mcp_server.tools import nginx_test

    result = await nginx_test()
    if result.get("success"):
        return {
            "success": True,
            "message": "NGINX configuration valid after migration"
        }
    return {
        "success": False,
        "message": f"Config validation failed after migration: {result.get('stderr', 'unknown error')}"
    }


# =============================================================================
# Workflow Factories
# =============================================================================

def build_setup_site_workflow(context: Dict[str, Any]) -> WorkflowEngine:
    """Build the setup-site workflow with all steps."""
    from config import settings

    engine = WorkflowEngine(
        workflow_type=WorkflowType.SETUP_SITE,
        step_timeout=settings.workflow_step_timeout,
        auto_rollback=settings.workflow_auto_rollback,
    )

    engine.add_step(WorkflowStep(
        name="check_prerequisites",
        description="Verify NGINX is running and site name is available",
        execute=step_check_prerequisites,
        is_checkpoint=False,
    ))

    engine.add_step(WorkflowStep(
        name="create_site",
        description="Create NGINX site configuration",
        execute=step_create_site,
        is_checkpoint=True,
    ))

    engine.add_step(WorkflowStep(
        name="verify_site",
        description="Verify site is configured correctly",
        execute=step_verify_site,
        is_checkpoint=False,
    ))

    request_ssl = context.get("request_ssl", False)
    if request_ssl:
        engine.add_step(WorkflowStep(
            name="diagnose_ssl",
            description="Check SSL prerequisites (DNS, port accessibility)",
            execute=step_diagnose_ssl,
            is_checkpoint=False,
            rollback_on_failure=False,
        ))

        engine.add_step(WorkflowStep(
            name="request_certificate",
            description="Request Let's Encrypt SSL certificate",
            execute=step_request_certificate,
            is_checkpoint=True,
            rollback_on_failure=False,
        ))

        engine.add_step(WorkflowStep(
            name="verify_ssl",
            description="Verify SSL certificate installation",
            execute=step_verify_ssl,
            is_checkpoint=False,
            rollback_on_failure=False,
        ))

    return engine


def build_migrate_site_workflow(context: Dict[str, Any]) -> WorkflowEngine:
    """Build the migrate-site workflow with all steps."""
    from config import settings

    engine = WorkflowEngine(
        workflow_type=WorkflowType.MIGRATE_SITE,
        step_timeout=settings.workflow_step_timeout,
        auto_rollback=settings.workflow_auto_rollback,
    )

    engine.add_step(WorkflowStep(
        name="verify_exists",
        description="Verify site exists and is eligible for migration",
        execute=step_verify_site_exists,
        is_checkpoint=False,
    ))

    engine.add_step(WorkflowStep(
        name="update_site",
        description="Update site configuration",
        execute=step_update_site,
        is_checkpoint=True,
    ))

    engine.add_step(WorkflowStep(
        name="test_config",
        description="Validate NGINX configuration after update",
        execute=step_test_config_after_update,
        is_checkpoint=False,
    ))

    return engine
