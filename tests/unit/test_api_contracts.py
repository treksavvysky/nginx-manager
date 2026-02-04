"""
Unit tests for API response contract validation.

Verifies HTTP responses match documented Pydantic models.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "api"))

from httpx import ASGITransport, AsyncClient

from main import app


class MockTransactionContext:
    """Local copy — avoids cross-directory import of conftest."""

    def __init__(self, transaction_id: str = "txn-test-123"):
        self.id = transaction_id


@asynccontextmanager
async def _mock_transactional_operation(*args, **kwargs):
    yield MockTransactionContext()


def _mock_settings():
    s = MagicMock()
    s.validate_before_deploy = False
    s.auto_backup = False
    s.api_debug = False
    s.auth_enabled = False
    s.cors_allowed_origins = ""
    return s


class TestSiteMutationResponseContract:
    """Verify site mutation endpoints return expected fields."""

    @pytest.mark.asyncio
    async def test_create_site_response_has_required_fields(self, tmp_conf_dir):
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")
        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("endpoints.sites.settings", _mock_settings()),
            patch("endpoints.sites.get_config_generator", return_value=mock_generator),
            patch("endpoints.sites.docker_service", mock_docker),
            patch("endpoints.sites.transactional_operation", _mock_transactional_operation),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/sites/",
                    json={
                        "name": "contract-test",
                        "server_names": ["contract.com"],
                        "site_type": "static",
                        "root_path": "/var/www/test",
                    },
                )

            assert response.status_code == 201
            data = response.json()
            assert "success" in data
            assert "message" in data
            assert "site_name" in data
            assert "transaction_id" in data

    @pytest.mark.asyncio
    async def test_delete_site_not_found_returns_404(self, tmp_conf_dir):
        with patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.delete("/sites/nonexistent")

            assert response.status_code == 404


class TestDryRunResponseContract:
    """Verify dry-run endpoints return expected fields."""

    @pytest.mark.asyncio
    async def test_create_dry_run_has_required_fields(self, tmp_conf_dir):
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        mock_settings = _mock_settings()

        with (
            patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("endpoints.sites.settings", mock_settings),
            patch("endpoints.sites.get_config_generator", return_value=mock_generator),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/sites/?dry_run=true",
                    json={
                        "name": "dry-test",
                        "server_names": ["dry.com"],
                        "site_type": "static",
                        "root_path": "/var/www/test",
                    },
                )

            assert response.status_code == 201
            data = response.json()
            assert data["dry_run"] is True
            assert "would_succeed" in data
            assert "operation" in data

    @pytest.mark.asyncio
    async def test_dry_run_always_has_dry_run_true(self, tmp_conf_dir):
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { listen 80; }")

        with (
            patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("endpoints.sites.settings", _mock_settings()),
            patch("endpoints.sites.get_config_generator", return_value=mock_generator),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/sites/?dry_run=true",
                    json={
                        "name": "dry-test-2",
                        "server_names": ["dry2.com"],
                        "site_type": "static",
                        "root_path": "/var/www/test",
                    },
                )

            data = response.json()
            assert data["dry_run"] is True


class TestErrorResponseContract:
    """Verify error responses follow consistent format."""

    @pytest.mark.asyncio
    async def test_404_response_has_detail(self, tmp_conf_dir):
        with patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get("/sites/does-not-exist")

            assert response.status_code == 404
            data = response.json()
            assert "detail" in data

    @pytest.mark.asyncio
    async def test_422_validation_error(self):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/sites/", json={"invalid": "data"})

        assert response.status_code == 422
        data = response.json()
        assert "detail" in data


class TestNginxControlResponseContract:
    """Verify NGINX control endpoint response fields."""

    @pytest.mark.asyncio
    async def test_test_config_response_has_required_fields(self):
        mock_docker = MagicMock()
        mock_docker.test_config = AsyncMock(return_value=(True, "nginx: ok", ""))

        with patch("endpoints.nginx.docker_service", mock_docker):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post("/nginx/test")

            assert response.status_code == 200
            data = response.json()
            assert "success" in data
            assert "message" in data


class TestStatusCodeMapping:
    """Verify status codes for different operations."""

    @pytest.mark.asyncio
    async def test_successful_get_returns_200(self, tmp_conf_dir):
        # Create a conf file to list
        (tmp_conf_dir / "test.conf").write_text("server { listen 80; }")
        mock_parser = MagicMock()
        mock_parsed = MagicMock()
        mock_parser.parse_config_file = MagicMock(return_value=mock_parsed)

        mock_adapter = MagicMock()
        mock_legacy = {"name": "test", "server_names": ["test.com"]}

        with (
            patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("endpoints.sites.nginx_parser", mock_parser),
            patch("endpoints.sites.ConfigAdapter.to_legacy_dict", return_value=mock_legacy),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.get("/sites/")

            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_returns_201(self, tmp_conf_dir):
        mock_generator = MagicMock()
        mock_generator.generate = MagicMock(return_value="server { }")
        mock_docker = MagicMock()
        mock_docker.reload_nginx = AsyncMock(return_value=(True, "", ""))

        with (
            patch("endpoints.sites.get_nginx_conf_path", return_value=tmp_conf_dir),
            patch("endpoints.sites.settings", _mock_settings()),
            patch("endpoints.sites.get_config_generator", return_value=mock_generator),
            patch("endpoints.sites.docker_service", mock_docker),
            patch("endpoints.sites.transactional_operation", _mock_transactional_operation),
        ):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
                response = await client.post(
                    "/sites/",
                    json={
                        "name": "new-site",
                        "server_names": ["new.com"],
                        "site_type": "static",
                        "root_path": "/var/www/new",
                    },
                )

            assert response.status_code == 201
