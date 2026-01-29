"""
Docker service for NGINX container management.

Provides async-safe wrapper around Docker SDK for container operations
including reload, restart, status checks, and config testing.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

import docker
from docker.errors import APIError, NotFound

from config import settings

logger = logging.getLogger(__name__)


class DockerServiceError(Exception):
    """Base exception for Docker service errors."""

    def __init__(self, message: str, error_type: str, suggestion: str | None = None):
        self.message = message
        self.error_type = error_type
        self.suggestion = suggestion
        super().__init__(message)


class ContainerNotFoundError(DockerServiceError):
    """Container not found."""

    pass


class ContainerOperationError(DockerServiceError):
    """Error during container operation."""

    pass


class DockerUnavailableError(DockerServiceError):
    """Docker daemon not available."""

    pass


class DockerService:
    """Service for managing Docker containers."""

    def __init__(self):
        self._client: docker.DockerClient | None = None

    @property
    def client(self) -> docker.DockerClient:
        """Lazy-load Docker client."""
        if self._client is None:
            try:
                self._client = docker.from_env()
            except docker.errors.DockerException as e:
                raise DockerUnavailableError(
                    f"Cannot connect to Docker daemon: {e}",
                    error_type="docker_unavailable",
                    suggestion="Ensure Docker daemon is running and socket is accessible",
                )
        return self._client

    def _get_container(self):
        """Get the NGINX container by name."""
        try:
            return self.client.containers.get(settings.nginx_container_name)
        except NotFound:
            raise ContainerNotFoundError(
                f"Container '{settings.nginx_container_name}' not found",
                error_type="container_not_found",
                suggestion="Ensure NGINX container is running with 'docker compose up -d'",
            )
        except APIError as e:
            raise ContainerOperationError(
                f"Docker API error: {e}",
                error_type="docker_api_error",
                suggestion="Check Docker daemon status and permissions",
            )

    async def get_container_status(self) -> dict[str, Any]:
        """Get detailed container status."""
        return await asyncio.to_thread(self._get_container_status_sync)

    def _get_container_status_sync(self) -> dict[str, Any]:
        """Synchronous container status retrieval."""
        container = self._get_container()
        container.reload()  # Refresh container data

        attrs = container.attrs
        state = attrs.get("State", {})

        # Parse started_at timestamp
        started_at = None
        if state.get("StartedAt"):
            try:
                # Docker returns ISO format with nanoseconds
                started_str = state["StartedAt"].split(".")[0]
                started_at = datetime.fromisoformat(started_str.replace("Z", ""))
            except (ValueError, IndexError):
                pass

        # Calculate uptime
        uptime_seconds = None
        if started_at:
            uptime_seconds = int((datetime.utcnow() - started_at).total_seconds())

        return {
            "container_id": container.short_id,
            "container_name": container.name,
            "status": state.get("Status", "unknown"),
            "running": state.get("Running", False),
            "started_at": started_at,
            "uptime_seconds": uptime_seconds,
            "health_status": state.get("Health", {}).get("Status", "unknown"),
            "exit_code": state.get("ExitCode"),
            "pid": state.get("Pid"),
        }

    async def exec_in_container(self, command: list[str], timeout: int = None) -> tuple[int, str, str]:
        """
        Execute command in NGINX container.

        Args:
            command: Command and arguments as list
            timeout: Operation timeout in seconds

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        timeout = timeout or settings.nginx_operation_timeout
        return await asyncio.to_thread(self._exec_in_container_sync, command, timeout)

    def _exec_in_container_sync(self, command: list[str], timeout: int) -> tuple[int, str, str]:
        """Synchronous command execution."""
        container = self._get_container()

        # Execute command
        exec_result = container.exec_run(
            cmd=command,
            demux=True,  # Separate stdout/stderr
        )

        exit_code = exec_result.exit_code
        stdout = exec_result.output[0].decode() if exec_result.output[0] else ""
        stderr = exec_result.output[1].decode() if exec_result.output[1] else ""

        return exit_code, stdout, stderr

    async def reload_nginx(self) -> tuple[bool, str, str]:
        """
        Send reload signal to NGINX (graceful reload).

        Returns:
            Tuple of (success, stdout, stderr)
        """
        logger.info("Sending reload signal to NGINX")
        exit_code, stdout, stderr = await self.exec_in_container(["nginx", "-s", "reload"])
        success = exit_code == 0

        if success:
            logger.info("NGINX reload signal sent successfully")
        else:
            logger.error(f"NGINX reload failed: {stderr}")

        return success, stdout, stderr

    async def restart_container(self, timeout: int = 10) -> bool:
        """
        Restart the NGINX container.

        Args:
            timeout: Seconds to wait for graceful stop before killing

        Returns:
            True if restart initiated successfully
        """
        logger.info(f"Restarting NGINX container with {timeout}s timeout")
        return await asyncio.to_thread(self._restart_container_sync, timeout)

    def _restart_container_sync(self, timeout: int) -> bool:
        """Synchronous container restart."""
        container = self._get_container()
        container.restart(timeout=timeout)
        logger.info("NGINX container restart completed")
        return True

    async def test_config(self) -> tuple[bool, str, str]:
        """
        Test NGINX configuration (nginx -t).

        Returns:
            Tuple of (success, stdout, stderr)
        """
        logger.info("Testing NGINX configuration")
        exit_code, stdout, stderr = await self.exec_in_container(["nginx", "-t"])
        success = exit_code == 0

        if success:
            logger.info("NGINX configuration test passed")
        else:
            logger.warning(f"NGINX configuration test failed: {stderr}")

        return success, stdout, stderr

    async def get_nginx_version(self) -> dict[str, Any]:
        """
        Get NGINX version information.

        Returns:
            Dict with version info
        """
        exit_code, stdout, stderr = await self.exec_in_container(["nginx", "-v"])
        # nginx -v outputs to stderr
        return {
            "exit_code": exit_code,
            "version": stderr.strip() if stderr else stdout.strip(),
        }

    async def get_container_logs(self, tail: int = 50) -> str:
        """
        Get recent container logs.

        Args:
            tail: Number of lines to retrieve

        Returns:
            Log output as string
        """
        return await asyncio.to_thread(self._get_container_logs_sync, tail)

    def _get_container_logs_sync(self, tail: int) -> str:
        """Synchronous log retrieval."""
        container = self._get_container()
        logs = container.logs(tail=tail, timestamps=True)
        return logs.decode() if logs else ""

    async def is_container_running(self) -> bool:
        """Check if NGINX container is running."""
        try:
            status = await self.get_container_status()
            return status.get("running", False)
        except DockerServiceError:
            return False


# Singleton instance
docker_service = DockerService()
