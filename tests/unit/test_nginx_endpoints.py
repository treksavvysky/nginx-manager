"""
Unit tests for NGINX control endpoints.

These tests mock the Docker service, health checker, and transaction context to test
endpoint logic without requiring actual Docker connectivity or database.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from contextlib import asynccontextmanager

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from main import app
from core.docker_service import (
    DockerServiceError,
    ContainerNotFoundError,
    DockerUnavailableError,
)
from core.health_checker import HealthCheckError


class MockTransactionContext:
    """Mock transaction context for testing."""

    def __init__(self, transaction_id: str = "test-txn-123"):
        self.id = transaction_id
        self.result_data = None
        self.after_state = None
        self.nginx_validated = False
        self.health_verified = False

    def set_result(self, result):
        self.result_data = result

    def set_after_state(self, state):
        self.after_state = state

    def set_nginx_validated(self, validated=True):
        self.nginx_validated = validated

    def set_health_verified(self, verified=True):
        self.health_verified = verified


@asynccontextmanager
async def mock_transactional_operation(*args, **kwargs):
    """Mock transactional_operation context manager."""
    yield MockTransactionContext()


class TestNginxStatus:
    """Tests for GET /nginx/status endpoint."""

    @pytest.fixture
    def mock_container_status(self):
        """Standard mock container status."""
        return {
            "container_id": "abc123",
            "container_name": "nginx-manager-nginx",
            "status": "running",
            "running": True,
            "started_at": datetime(2026, 1, 27, 10, 0, 0),
            "uptime_seconds": 3600,
            "health_status": "healthy",
            "pid": 1234,
        }

    @pytest.mark.asyncio
    async def test_status_running_container(self, mock_container_status):
        """Test status endpoint with running container."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_container_status)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/nginx/status")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "running"
            assert data["container_id"] == "abc123"
            assert data["uptime_seconds"] == 3600
            assert data["health_status"] == "healthy"

    @pytest.mark.asyncio
    async def test_status_stopped_container(self):
        """Test status endpoint with stopped container."""
        stopped_status = {
            "container_id": "abc123",
            "container_name": "nginx-manager-nginx",
            "status": "exited",
            "running": False,
            "started_at": None,
            "uptime_seconds": None,
            "health_status": "unhealthy",
            "pid": None,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=stopped_status)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/nginx/status")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "stopped"

    @pytest.mark.asyncio
    async def test_status_container_not_found(self):
        """Test status endpoint when container doesn't exist."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(
                side_effect=ContainerNotFoundError(
                    "Container 'nginx-manager-nginx' not found",
                    error_type="container_not_found",
                    suggestion="Ensure NGINX container is running"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/nginx/status")

            assert response.status_code == 503
            data = response.json()
            assert data["detail"]["error"] == "container_not_found"

    @pytest.mark.asyncio
    async def test_status_docker_unavailable(self):
        """Test status endpoint when Docker is unavailable."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(
                side_effect=DockerUnavailableError(
                    "Cannot connect to Docker daemon",
                    error_type="docker_unavailable",
                    suggestion="Ensure Docker daemon is running"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/nginx/status")

            assert response.status_code == 503


class TestNginxReload:
    """Tests for POST /nginx/reload endpoint."""

    @pytest.mark.asyncio
    async def test_reload_success(self):
        """Test successful reload operation."""
        mock_status = {
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.health_checker") as mock_health, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation):

            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))
            mock_health.verify_health = AsyncMock(return_value=True)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["operation"] == "reload"
            assert data["health_verified"] is True
            assert data["transaction_id"] == "test-txn-123"

    @pytest.mark.asyncio
    async def test_reload_failure(self):
        """Test failed reload operation."""
        mock_status = {
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation):
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.reload_nginx = AsyncMock(
                return_value=(False, "", "nginx: configuration file test failed")
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "failed" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_reload_health_check_fails_with_auto_rollback(self):
        """Test reload success but health check fails triggers auto-rollback."""
        mock_status = {
            "status": "running",
            "running": True,
        }

        # Mock rollback result
        mock_rollback_result = MagicMock()
        mock_rollback_result.success = True
        mock_rollback_result.rollback_transaction_id = "rollback-txn-456"
        mock_rollback_result.message = "Rollback successful"

        mock_txn_manager = MagicMock()
        mock_txn_manager.rollback_transaction = AsyncMock(return_value=mock_rollback_result)

        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.health_checker") as mock_health, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation), \
             patch("endpoints.nginx.get_transaction_manager", return_value=mock_txn_manager), \
             patch("endpoints.nginx.settings") as mock_settings:

            mock_settings.auto_rollback_on_failure = True
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))
            mock_health.verify_health = AsyncMock(
                side_effect=HealthCheckError("Health check failed", attempts=5)
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert data["health_verified"] is False
            assert data["auto_rolled_back"] is True
            assert data["rollback_transaction_id"] == "rollback-txn-456"
            assert "rolled back" in data["message"].lower()

    @pytest.mark.asyncio
    async def test_reload_health_check_fails_auto_rollback_disabled(self):
        """Test reload with health check failure when auto-rollback is disabled."""
        mock_status = {
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.health_checker") as mock_health, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation), \
             patch("endpoints.nginx.settings") as mock_settings:

            mock_settings.auto_rollback_on_failure = False
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))
            mock_health.verify_health = AsyncMock(
                side_effect=HealthCheckError("Health check failed", attempts=5)
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert data["health_verified"] is False
            assert data["auto_rolled_back"] is False
            assert data.get("rollback_transaction_id") is None


class TestNginxRestart:
    """Tests for POST /nginx/restart endpoint."""

    @pytest.mark.asyncio
    async def test_restart_success(self):
        """Test successful restart operation."""
        mock_status = {
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.health_checker") as mock_health, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation), \
             patch("asyncio.sleep", new_callable=AsyncMock):

            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.restart_container = AsyncMock(return_value=True)
            mock_health.verify_health = AsyncMock(return_value=True)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/restart")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["operation"] == "restart"
            assert data["transaction_id"] == "test-txn-123"

    @pytest.mark.asyncio
    async def test_restart_container_not_found(self):
        """Test restart when container doesn't exist."""
        with patch("endpoints.nginx.docker_service") as mock_docker, \
             patch("endpoints.nginx.transactional_operation", mock_transactional_operation):
            mock_docker.get_container_status = AsyncMock(
                side_effect=ContainerNotFoundError(
                    "Container not found",
                    error_type="container_not_found",
                    suggestion="Start the container first"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/restart")

            assert response.status_code == 503


class TestNginxConfigTest:
    """Tests for POST /nginx/test endpoint."""

    @pytest.mark.asyncio
    async def test_config_test_success(self):
        """Test successful config validation."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.test_config = AsyncMock(
                return_value=(
                    True,
                    "",
                    "nginx: configuration file /etc/nginx/nginx.conf test is successful"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/test")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Configuration is valid"

    @pytest.mark.asyncio
    async def test_config_test_failure(self):
        """Test failed config validation."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.test_config = AsyncMock(
                return_value=(
                    False,
                    "",
                    "nginx: [emerg] unknown directive \"invalid\" in /etc/nginx/conf.d/test.conf:1"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/test")

            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert data["message"] == "Configuration test failed"
            assert "unknown directive" in data["stderr"]

    @pytest.mark.asyncio
    async def test_config_test_container_not_found(self):
        """Test config validation when container doesn't exist."""
        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.test_config = AsyncMock(
                side_effect=ContainerNotFoundError(
                    "Container not found",
                    error_type="container_not_found",
                    suggestion="Start the container"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/test")

            assert response.status_code == 503


class TestHealthEndpoint:
    """Tests for GET /health endpoint with NGINX status."""

    @pytest.mark.asyncio
    async def test_health_with_running_nginx(self):
        """Test health endpoint shows running NGINX."""
        mock_status = {
            "container_id": "abc123",
            "status": "running",
            "running": True,
            "uptime_seconds": 3600,
            "health_status": "healthy",
        }

        with patch("core.docker_service.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["nginx"]["status"] == "running"
            assert data["nginx"]["container_id"] == "abc123"

    @pytest.mark.asyncio
    async def test_health_with_stopped_nginx(self):
        """Test health endpoint shows stopped NGINX."""
        mock_status = {
            "container_id": "abc123",
            "status": "exited",
            "running": False,
        }

        with patch("core.docker_service.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["nginx"]["status"] == "exited"
            assert "not running" in data["nginx"]["message"]

    @pytest.mark.asyncio
    async def test_health_with_docker_error(self):
        """Test health endpoint handles Docker errors gracefully."""
        with patch("core.docker_service.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(
                side_effect=DockerUnavailableError(
                    "Docker daemon not running",
                    error_type="docker_unavailable",
                    suggestion="Start Docker"
                )
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
            assert data["nginx"]["status"] == "error"
            assert "suggestion" in data["nginx"]
