"""
Unit tests for dry-run mode on mutation endpoints.

Tests that dry_run=true returns preview responses without making changes.
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from contextlib import asynccontextmanager
import tempfile
import shutil

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from httpx import ASGITransport, AsyncClient

from main import app


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


class TestSiteCreateDryRun:
    """Tests for dry-run mode on POST /sites/."""

    @pytest.mark.asyncio
    async def test_create_site_dry_run_success(self, tmp_path):
        """Test dry-run create returns preview without creating file."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir), \
             patch("endpoints.sites.docker_service") as mock_docker, \
             patch("endpoints.sites.settings") as mock_settings:

            mock_settings.validate_before_deploy = False

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post(
                    "/sites/?dry_run=true",
                    json={
                        "name": "test-site",
                        "server_names": ["test.local"],
                        "site_type": "static",
                        "root_path": "/var/www/test"
                    }
                )

            assert response.status_code == 201
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "create"
            assert "generated_config" in data
            assert data["generated_config"] is not None
            assert "test.local" in data["generated_config"]

            # Verify file was NOT created
            assert not (conf_dir / "test-site.conf").exists()

    @pytest.mark.asyncio
    async def test_create_site_dry_run_already_exists(self, tmp_path):
        """Test dry-run create detects existing site."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "existing.conf").write_text("# existing config")

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post(
                    "/sites/?dry_run=true",
                    json={
                        "name": "existing",
                        "server_names": ["existing.local"],
                        "site_type": "static",
                        "root_path": "/var/www/test"
                    }
                )

            assert response.status_code == 201
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is False
            assert "already exists" in data["message"]


class TestSiteUpdateDryRun:
    """Tests for dry-run mode on PUT /sites/{name}."""

    @pytest.mark.asyncio
    async def test_update_site_dry_run_success(self, tmp_path):
        """Test dry-run update returns preview without modifying file."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        original_content = """server {
    listen 80;
    server_name test.local;
    root /var/www/test;
}"""
        (conf_dir / "test-site.conf").write_text(original_content)

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir), \
             patch("endpoints.sites.docker_service") as mock_docker, \
             patch("endpoints.sites.settings") as mock_settings:

            mock_settings.validate_before_deploy = False

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.put(
                    "/sites/test-site?dry_run=true",
                    json={
                        "listen_port": 8080
                    }
                )

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "update"
            assert data["diff"] is not None
            assert data["diff"]["current_content"] == original_content

            # Verify file was NOT modified
            assert (conf_dir / "test-site.conf").read_text() == original_content

    @pytest.mark.asyncio
    async def test_update_site_dry_run_not_found(self, tmp_path):
        """Test dry-run update detects missing site."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.put(
                    "/sites/nonexistent?dry_run=true",
                    json={"listen_port": 8080}
                )

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is False
            assert "not found" in data["message"]


class TestSiteDeleteDryRun:
    """Tests for dry-run mode on DELETE /sites/{name}."""

    @pytest.mark.asyncio
    async def test_delete_site_dry_run_success(self, tmp_path):
        """Test dry-run delete returns preview without deleting file."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        content = "server { listen 80; }"
        (conf_dir / "test-site.conf").write_text(content)

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.delete("/sites/test-site?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "delete"
            assert data["diff"]["current_content"] == content
            assert data["reload_required"] is True

            # Verify file was NOT deleted
            assert (conf_dir / "test-site.conf").exists()

    @pytest.mark.asyncio
    async def test_delete_site_dry_run_not_found(self, tmp_path):
        """Test dry-run delete detects missing site."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.delete("/sites/nonexistent?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is False
            assert "not found" in data["message"]


class TestSiteEnableDisableDryRun:
    """Tests for dry-run mode on enable/disable endpoints."""

    @pytest.mark.asyncio
    async def test_enable_site_dry_run_success(self, tmp_path):
        """Test dry-run enable returns preview without enabling."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        content = "server { listen 80; }"
        (conf_dir / "test-site.conf.disabled").write_text(content)

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir), \
             patch("endpoints.sites.docker_service") as mock_docker, \
             patch("endpoints.sites.settings") as mock_settings:

            mock_settings.validate_before_deploy = False

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/sites/test-site/enable?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "enable"

            # Verify file was NOT renamed
            assert (conf_dir / "test-site.conf.disabled").exists()
            assert not (conf_dir / "test-site.conf").exists()

    @pytest.mark.asyncio
    async def test_disable_site_dry_run_success(self, tmp_path):
        """Test dry-run disable returns preview without disabling."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        content = "server { listen 80; }"
        (conf_dir / "test-site.conf").write_text(content)

        with patch("endpoints.sites.get_nginx_conf_path", return_value=conf_dir):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/sites/test-site/disable?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "disable"

            # Verify file was NOT renamed
            assert (conf_dir / "test-site.conf").exists()
            assert not (conf_dir / "test-site.conf.disabled").exists()


class TestNginxReloadDryRun:
    """Tests for dry-run mode on POST /nginx/reload."""

    @pytest.mark.asyncio
    async def test_reload_dry_run_success(self):
        """Test dry-run reload returns preview without reloading."""
        mock_status = {
            "container_id": "abc123",
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.test_config = AsyncMock(
                return_value=(True, "", "nginx: configuration file test is successful")
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "reload"
            assert data["config_valid"] is True
            assert data["would_drop_connections"] is False
            assert data["estimated_downtime_ms"] == 0

            # Verify reload_nginx was NOT called
            mock_docker.reload_nginx.assert_not_called()

    @pytest.mark.asyncio
    async def test_reload_dry_run_invalid_config(self):
        """Test dry-run reload detects invalid configuration."""
        mock_status = {
            "container_id": "abc123",
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.test_config = AsyncMock(
                return_value=(False, "", "nginx: configuration file test failed")
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/reload?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is False
            assert data["config_valid"] is False


class TestNginxRestartDryRun:
    """Tests for dry-run mode on POST /nginx/restart."""

    @pytest.mark.asyncio
    async def test_restart_dry_run_success(self):
        """Test dry-run restart returns preview with warnings."""
        mock_status = {
            "container_id": "abc123",
            "status": "running",
            "running": True,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.test_config = AsyncMock(
                return_value=(True, "", "nginx: configuration file test is successful")
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/restart?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is True
            assert data["operation"] == "restart"
            assert data["would_drop_connections"] is True
            assert data["estimated_downtime_ms"] > 0
            assert len(data["warnings"]) > 0
            assert any("drop" in w.lower() for w in data["warnings"])

            # Verify restart_container was NOT called
            mock_docker.restart_container.assert_not_called()

    @pytest.mark.asyncio
    async def test_restart_dry_run_container_not_running(self):
        """Test dry-run restart when container is not running."""
        mock_status = {
            "container_id": "abc123",
            "status": "exited",
            "running": False,
        }

        with patch("endpoints.nginx.docker_service") as mock_docker:
            mock_docker.get_container_status = AsyncMock(return_value=mock_status)
            mock_docker.test_config = AsyncMock(
                return_value=(True, "", "nginx: configuration file test is successful")
            )

            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test"
            ) as client:
                response = await client.post("/nginx/restart?dry_run=true")

            assert response.status_code == 200
            data = response.json()
            assert data["dry_run"] is True
            assert data["would_succeed"] is False
            assert data["container_running"] is False
