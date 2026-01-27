"""
NGINX control endpoints.

REST API endpoints for managing NGINX container lifecycle including
reload, restart, status checks, and configuration testing.
"""

import logging
import time
from datetime import datetime

from fastapi import APIRouter, HTTPException

from config import settings
from core.docker_service import (
    docker_service,
    DockerServiceError,
    ContainerNotFoundError,
    DockerUnavailableError,
)
from core.health_checker import health_checker, HealthCheckError
from models.nginx import (
    NginxOperationResult,
    NginxStatusResponse,
    NginxConfigTestResult,
    NginxProcessStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/nginx", tags=["NGINX Control"])


def _handle_docker_error(e: DockerServiceError) -> HTTPException:
    """Convert Docker errors to appropriate HTTP exceptions."""
    if isinstance(e, ContainerNotFoundError):
        return HTTPException(
            status_code=503,
            detail={
                "error": e.error_type,
                "message": e.message,
                "suggestion": e.suggestion
            }
        )
    if isinstance(e, DockerUnavailableError):
        return HTTPException(
            status_code=503,
            detail={
                "error": e.error_type,
                "message": e.message,
                "suggestion": e.suggestion
            }
        )
    return HTTPException(
        status_code=500,
        detail={
            "error": e.error_type,
            "message": e.message,
            "suggestion": e.suggestion
        }
    )


@router.post(
    "/reload",
    response_model=NginxOperationResult,
    summary="Reload NGINX Configuration",
    description="""
Perform a graceful NGINX reload (nginx -s reload).

This sends a signal to NGINX to gracefully reload its configuration without
dropping existing connections. Perfect for applying configuration changes.

**What happens:**
1. NGINX master process receives reload signal
2. Master process verifies new configuration
3. If valid, starts new workers with new config
4. Old workers gracefully finish existing requests
5. Health check verifies NGINX is responding

**Safe Operation:** Existing connections are preserved during reload.
If configuration is invalid, NGINX continues with old config.

**AI Agent Usage:** Call this after modifying site configurations to apply changes.
""",
    responses={
        200: {"description": "Reload completed (check 'success' field for result)"},
        503: {"description": "NGINX container not available"}
    }
)
async def reload_nginx() -> NginxOperationResult:
    """Gracefully reload NGINX configuration."""
    start_time = time.time()

    try:
        # Get current state
        status = await docker_service.get_container_status()
        previous_state = status.get("status", "unknown")

        # Perform reload
        success, stdout, stderr = await docker_service.reload_nginx()

        if not success:
            logger.error(f"NGINX reload failed: {stderr}")
            return NginxOperationResult(
                success=False,
                operation="reload",
                message=f"Reload failed: {stderr.strip()}",
                duration_ms=int((time.time() - start_time) * 1000),
                health_verified=False,
                previous_state=previous_state,
                current_state=previous_state
            )

        # Verify health after reload
        health_verified = False
        try:
            await health_checker.verify_health()
            health_verified = True
        except HealthCheckError as e:
            logger.warning(f"Health check failed after reload: {e}")

        # Get new state
        new_status = await docker_service.get_container_status()

        duration_ms = int((time.time() - start_time) * 1000)

        return NginxOperationResult(
            success=True,
            operation="reload",
            message="NGINX configuration reloaded successfully",
            duration_ms=duration_ms,
            health_verified=health_verified,
            previous_state=previous_state,
            current_state=new_status.get("status", "unknown")
        )

    except DockerServiceError as e:
        raise _handle_docker_error(e)


@router.post(
    "/restart",
    response_model=NginxOperationResult,
    summary="Restart NGINX Container",
    description="""
Perform a full NGINX container restart.

**WARNING:** This is a disruptive operation that will:
- Stop the NGINX container
- Drop all active connections
- Start the container fresh

Use this only when a reload is insufficient (e.g., after binary updates
or when NGINX is in an inconsistent state).

**For configuration changes, prefer `/nginx/reload` instead.**

**AI Agent Usage:** Only use when reload fails or NGINX needs a full restart.
""",
    responses={
        200: {"description": "Restart completed (check 'success' field for result)"},
        503: {"description": "NGINX container not available"}
    }
)
async def restart_nginx() -> NginxOperationResult:
    """Full restart of NGINX container."""
    start_time = time.time()

    try:
        # Get current state
        status = await docker_service.get_container_status()
        previous_state = status.get("status", "unknown")

        # Perform restart
        await docker_service.restart_container(timeout=10)

        # Wait for container to stabilize
        import asyncio
        await asyncio.sleep(2)

        # Verify health with more retries for restart
        health_verified = False
        try:
            await health_checker.verify_health(retries=10, interval=1.0)
            health_verified = True
        except HealthCheckError as e:
            logger.warning(f"Health check failed after restart: {e}")

        # Get new state
        new_status = await docker_service.get_container_status()

        duration_ms = int((time.time() - start_time) * 1000)

        return NginxOperationResult(
            success=True,
            operation="restart",
            message="NGINX container restarted successfully",
            duration_ms=duration_ms,
            health_verified=health_verified,
            previous_state=previous_state,
            current_state=new_status.get("status", "unknown")
        )

    except DockerServiceError as e:
        raise _handle_docker_error(e)


@router.get(
    "/status",
    response_model=NginxStatusResponse,
    summary="Get NGINX Status",
    description="""
Get detailed NGINX process and container status.

Returns comprehensive information about:
- Container state (running, stopped, etc.)
- Uptime and start time
- Health check status
- Process ID

**AI Agent Use Cases:**
- Verify NGINX is running before making changes
- Diagnose issues when sites are unreachable
- Check uptime after operations
""",
    responses={
        200: {"description": "Status retrieved successfully"},
        503: {"description": "NGINX container not available"}
    }
)
async def get_nginx_status() -> NginxStatusResponse:
    """Get detailed NGINX status information."""
    try:
        status = await docker_service.get_container_status()

        # Map Docker status to our enum
        process_status = NginxProcessStatus.UNKNOWN
        if status.get("running"):
            process_status = NginxProcessStatus.RUNNING
        elif status.get("status") == "exited":
            process_status = NginxProcessStatus.STOPPED
        elif status.get("status") == "restarting":
            process_status = NginxProcessStatus.RESTARTING

        return NginxStatusResponse(
            status=process_status,
            container_id=status.get("container_id"),
            container_name=status.get("container_name", settings.nginx_container_name),
            uptime_seconds=status.get("uptime_seconds"),
            started_at=status.get("started_at"),
            master_pid=status.get("pid"),
            health_status=status.get("health_status", "unknown"),
            last_health_check=datetime.now()
        )

    except DockerServiceError as e:
        raise _handle_docker_error(e)


@router.post(
    "/test",
    response_model=NginxConfigTestResult,
    summary="Test NGINX Configuration",
    description="""
Validate all NGINX configuration files (nginx -t).

This runs `nginx -t` inside the container to verify:
- Syntax is correct
- All included files exist
- SSL certificates are accessible
- Upstream servers are defined

**Always run this before reload** to catch errors early.

**AI Agent Usage:** Call this after modifying configurations but before reload
to verify changes are valid.

**Returns:**
- success: Whether config is valid
- message: Summary of result
- stderr: Full nginx -t output for debugging
""",
    responses={
        200: {"description": "Test completed (check 'success' field for result)"},
        503: {"description": "NGINX container not available"}
    }
)
async def test_nginx_config() -> NginxConfigTestResult:
    """Test NGINX configuration validity."""
    try:
        success, stdout, stderr = await docker_service.test_config()

        # nginx -t outputs to stderr even on success
        output = stderr.strip() if stderr else stdout.strip()

        return NginxConfigTestResult(
            success=success,
            message="Configuration is valid" if success else "Configuration test failed",
            stdout=stdout if stdout else None,
            stderr=stderr if stderr else None
        )

    except DockerServiceError as e:
        raise _handle_docker_error(e)
