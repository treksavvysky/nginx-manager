"""
Global test fixtures.

Overrides authentication for all tests so unit tests don't
require auth credentials or a running auth service.
"""

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

# Disable auth before any app imports
os.environ["AUTH_ENABLED"] = "false"


class MockTransactionContext:
    """Mock for transactional_operation context manager."""

    def __init__(self, transaction_id: str = "txn-test-123"):
        self.id = transaction_id


@pytest.fixture
def mock_transaction_ctx():
    """Reusable transactional_operation mock returning MockTransactionContext."""

    @asynccontextmanager
    async def _mock_transactional_operation(*args, **kwargs):
        yield MockTransactionContext()

    return _mock_transactional_operation


@pytest.fixture
def mock_docker_service():
    """Pre-configured mock docker service with common methods."""
    service = MagicMock()
    service.get_container_status = AsyncMock(
        return_value={"running": True, "container_id": "abc123", "uptime_seconds": 3600}
    )
    service.test_config = AsyncMock(return_value=(True, "nginx: configuration ok", ""))
    service.reload_nginx = AsyncMock(return_value=(True, "", ""))
    service.restart_container = AsyncMock(return_value=True)
    return service


@pytest.fixture
def tmp_conf_dir(tmp_path):
    """Temporary NGINX conf directory with helper methods."""
    conf_dir = tmp_path / "conf.d"
    conf_dir.mkdir()
    return conf_dir


@pytest.fixture
def sample_site_config():
    """Standard site config rich_dict for testing."""
    return {
        "name": "example.com",
        "server_names": ["example.com", "www.example.com"],
        "listen_ports": [80],
        "ssl_enabled": False,
        "proxy_pass": None,
        "root_path": "/var/www/example",
        "enabled": True,
        "status": "active",
        "locations": [],
    }
