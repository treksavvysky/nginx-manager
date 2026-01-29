"""
NGINX control endpoints.

REST API endpoints for managing NGINX container lifecycle including
reload, restart, status checks, and configuration testing.

All mutation operations (reload, restart) are wrapped in transactions
for audit logging and rollback capability.
"""

import logging
import time
from datetime import datetime
from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth_dependency import get_current_auth, require_role
from models.auth import AuthContext, Role

from config import settings
from core.docker_service import (
    docker_service,
    DockerServiceError,
    ContainerNotFoundError,
    DockerUnavailableError,
)
from core.health_checker import health_checker, HealthCheckError
from core.transaction_context import transactional_operation
from core.transaction_manager import get_transaction_manager
from core.context_helpers import (
    get_nginx_reload_suggestions,
    get_nginx_restart_suggestions,
)
from models.nginx import (
    NginxOperationResult,
    NginxStatusResponse,
    NginxConfigTestResult,
    NginxProcessStatus,
    NginxDryRunResult,
)
from models.transaction import OperationType

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
    response_model=Union[NginxOperationResult, NginxDryRunResult],
    summary="Reload NGINX Configuration",
    description="""
Perform a graceful NGINX reload (nginx -s reload).

This sends a signal to NGINX to gracefully reload its configuration without
dropping existing connections. Perfect for applying configuration changes.

**Dry Run Mode:**
Add `?dry_run=true` to validate configuration and preview the operation
without actually reloading NGINX.

**What happens:**
1. NGINX master process receives reload signal
2. Master process verifies new configuration
3. If valid, starts new workers with new config
4. Old workers gracefully finish existing requests
5. Health check verifies NGINX is responding
6. **If health check fails, configuration is automatically rolled back**

**Safe Operation:** Existing connections are preserved during reload.
If configuration is invalid, NGINX continues with old config.
If health check fails after reload, previous configuration is restored.

**AI Agent Usage:** Call this after modifying site configurations to apply changes.
""",
    responses={
        200: {"description": "Reload completed or dry run result"},
        503: {"description": "NGINX container not available"}
    }
)
async def reload_nginx(
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[NginxOperationResult, NginxDryRunResult]:
    """Gracefully reload NGINX configuration."""
    start_time = time.time()

    try:
        # Get current state for dry run check
        status = await docker_service.get_container_status()
        current_state = status.get("status", "unknown")
        container_running = status.get("running", False)

        # Dry run mode: validate config and return preview
        if dry_run:
            # Test configuration
            config_valid = True
            config_test_output = None
            warnings = []

            try:
                success, stdout, stderr = await docker_service.test_config()
                config_valid = success
                config_test_output = stderr or stdout
            except DockerServiceError as e:
                config_valid = False
                config_test_output = e.message
                warnings.append(f"Cannot test config: {e.message}")

            if not container_running:
                warnings.append("NGINX container is not running")

            return NginxDryRunResult(
                would_succeed=config_valid and container_running,
                operation="reload",
                message="Would perform graceful NGINX reload" if config_valid else "Reload would fail due to invalid configuration",
                current_state=current_state,
                container_running=container_running,
                config_valid=config_valid,
                config_test_output=config_test_output,
                would_drop_connections=False,
                estimated_downtime_ms=0,
                warnings=warnings
            )

        async with transactional_operation(
            operation=OperationType.NGINX_RELOAD,
            resource_type="nginx",
            resource_id="nginx",
            auto_rollback_on_failure=False  # We handle rollback manually for health failures
        ) as ctx:
            # Get current state
            status = await docker_service.get_container_status()
            previous_state = status.get("status", "unknown")

            # Perform reload
            success, stdout, stderr = await docker_service.reload_nginx()

            if not success:
                logger.error(f"NGINX reload failed: {stderr}")
                # Raise to trigger transaction failure
                raise Exception(f"Reload failed: {stderr.strip()}")

            # Verify health after reload
            health_verified = False
            health_error = None
            try:
                await health_checker.verify_health()
                health_verified = True
                ctx.set_health_verified(True)
            except HealthCheckError as e:
                logger.warning(f"Health check failed after reload: {e}")
                health_error = str(e)

            # Auto-rollback if health check failed and auto-rollback is enabled
            auto_rolled_back = False
            rollback_reason = None
            rollback_transaction_id = None

            if not health_verified and settings.auto_rollback_on_failure:
                logger.info(f"Auto-rolling back transaction {ctx.id} due to health check failure")
                rollback_reason = f"Health check failed: {health_error}"

                try:
                    # Get transaction manager and perform rollback
                    transaction_manager = get_transaction_manager()

                    # Complete current transaction first (mark as needing rollback)
                    ctx.set_result({
                        "success": False,
                        "operation": "reload",
                        "health_verified": False,
                        "auto_rollback_triggered": True
                    })

                    # We need to complete the transaction context before rollback
                    # The rollback will be done after the context exits

                except Exception as rollback_error:
                    logger.error(f"Failed to prepare auto-rollback: {rollback_error}")

            # Get new state
            new_status = await docker_service.get_container_status()
            duration_ms = int((time.time() - start_time) * 1000)

            # Set transaction context data
            ctx.set_nginx_validated(True)
            ctx.set_result({
                "success": health_verified,
                "operation": "reload",
                "duration_ms": duration_ms,
                "health_verified": health_verified
            })

            # Store transaction ID for potential rollback after context exits
            transaction_id = ctx.id

        # After transaction context exits, perform rollback if needed
        if not health_verified and settings.auto_rollback_on_failure:
            try:
                transaction_manager = get_transaction_manager()
                rollback_result = await transaction_manager.rollback_transaction(
                    transaction_id,
                    reason=rollback_reason
                )

                if rollback_result.success:
                    auto_rolled_back = True
                    rollback_transaction_id = rollback_result.rollback_transaction_id
                    logger.info(f"Auto-rollback successful: {rollback_transaction_id}")
                else:
                    logger.error(f"Auto-rollback failed: {rollback_result.message}")
                    rollback_reason = f"Rollback failed: {rollback_result.message}"

            except Exception as rollback_error:
                logger.error(f"Auto-rollback error: {rollback_error}")
                rollback_reason = f"Rollback error: {rollback_error}"

        # Build response message
        if auto_rolled_back:
            message = "NGINX reload succeeded but health check failed. Configuration automatically rolled back."
        elif not health_verified:
            message = "NGINX reload succeeded but health check failed. Auto-rollback disabled or failed."
        else:
            message = "NGINX configuration reloaded successfully"

        # Generate suggestions
        suggestions = get_nginx_reload_suggestions(
            success=health_verified,
            health_verified=health_verified,
            auto_rolled_back=auto_rolled_back
        )

        return NginxOperationResult(
            success=health_verified,
            operation="reload",
            message=message,
            duration_ms=duration_ms,
            health_verified=health_verified,
            previous_state=previous_state,
            current_state=new_status.get("status", "unknown"),
            transaction_id=transaction_id,
            auto_rolled_back=auto_rolled_back,
            rollback_reason=rollback_reason if auto_rolled_back else None,
            rollback_transaction_id=rollback_transaction_id,
            suggestions=suggestions
        )

    except DockerServiceError as e:
        raise _handle_docker_error(e)
    except Exception as e:
        # Handle reload failure (non-Docker errors)
        duration_ms = int((time.time() - start_time) * 1000)
        return NginxOperationResult(
            success=False,
            operation="reload",
            message=str(e),
            duration_ms=duration_ms,
            health_verified=False
        )


@router.post(
    "/restart",
    response_model=Union[NginxOperationResult, NginxDryRunResult],
    summary="Restart NGINX Container",
    description="""
Perform a full NGINX container restart.

**Dry Run Mode:**
Add `?dry_run=true` to preview the operation without actually restarting.

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
        200: {"description": "Restart completed or dry run result"},
        503: {"description": "NGINX container not available"}
    }
)
async def restart_nginx(
    dry_run: bool = Query(default=False, description="Preview the operation without making changes"),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[NginxOperationResult, NginxDryRunResult]:
    """Full restart of NGINX container."""
    start_time = time.time()

    try:
        # Get current state
        status = await docker_service.get_container_status()
        current_state = status.get("status", "unknown")
        container_running = status.get("running", False)

        # Dry run mode: validate config and return preview
        if dry_run:
            # Test configuration
            config_valid = True
            config_test_output = None
            warnings = [
                "This operation will drop all active connections",
                "Consider using /nginx/reload for configuration changes"
            ]

            try:
                success, stdout, stderr = await docker_service.test_config()
                config_valid = success
                config_test_output = stderr or stdout
                if not success:
                    warnings.append("Configuration is invalid - container may fail to start")
            except DockerServiceError as e:
                config_valid = False
                config_test_output = e.message
                warnings.append(f"Cannot test config: {e.message}")

            return NginxDryRunResult(
                would_succeed=container_running,  # Can only restart if container exists
                operation="restart",
                message="Would perform full NGINX container restart (DISRUPTIVE)",
                current_state=current_state,
                container_running=container_running,
                config_valid=config_valid,
                config_test_output=config_test_output,
                would_drop_connections=True,
                estimated_downtime_ms=3000,  # Estimate ~3 seconds for restart
                warnings=warnings
            )

        async with transactional_operation(
            operation=OperationType.NGINX_RESTART,
            resource_type="nginx",
            resource_id="nginx"
        ) as ctx:
            previous_state = current_state

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
                ctx.set_health_verified(True)
            except HealthCheckError as e:
                logger.warning(f"Health check failed after restart: {e}")

            # Get new state
            new_status = await docker_service.get_container_status()

            duration_ms = int((time.time() - start_time) * 1000)

            # Set transaction context data
            ctx.set_nginx_validated(True)
            ctx.set_result({
                "success": True,
                "operation": "restart",
                "duration_ms": duration_ms,
                "health_verified": health_verified
            })

            # Generate suggestions
            suggestions = get_nginx_restart_suggestions(
                success=True,
                health_verified=health_verified
            )

            return NginxOperationResult(
                success=True,
                operation="restart",
                message="NGINX container restarted successfully",
                duration_ms=duration_ms,
                health_verified=health_verified,
                previous_state=previous_state,
                current_state=new_status.get("status", "unknown"),
                transaction_id=ctx.id,
                suggestions=suggestions
            )

    except DockerServiceError as e:
        raise _handle_docker_error(e)
    except Exception as e:
        # Handle restart failure (non-Docker errors)
        duration_ms = int((time.time() - start_time) * 1000)
        return NginxOperationResult(
            success=False,
            operation="restart",
            message=str(e),
            duration_ms=duration_ms,
            health_verified=False
        )


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
async def get_nginx_status(
    auth: AuthContext = Depends(require_role(Role.VIEWER)),
) -> NginxStatusResponse:
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
async def test_nginx_config(
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> NginxConfigTestResult:
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
