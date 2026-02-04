"""
Unit tests for MCP resource handlers.

Tests all resource functions in api/mcp_server/resources.py which provide
read-only data for AI model context (sites, certificates, health, events,
transactions).
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.resources import (
    get_certificate_resource,
    get_certificates_resource,
    get_events_resource,
    get_health_resource,
    get_site_resource,
    get_sites_resource,
    get_transaction_resource,
    get_transactions_resource,
)
from models.certificate import Certificate, CertificateStatus, CertificateType
from models.event import EventCategory, EventCountBySeverity, EventSeverity
from models.transaction import (
    OperationType,
    TransactionDetail,
    TransactionDiff,
    TransactionListResponse,
    TransactionStatus,
    TransactionSummary,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_certificate(
    domain="example.com",
    status=CertificateStatus.VALID,
    days_offset=90,
    auto_renew=True,
    alt_names=None,
    certificate_type=CertificateType.LETSENCRYPT,
):
    """Create a Certificate instance for testing."""
    not_after = datetime.utcnow() + timedelta(days=days_offset)
    return Certificate(
        domain=domain,
        alt_names=alt_names or [],
        certificate_type=certificate_type,
        status=status,
        issuer="Let's Encrypt",
        serial_number="ABCD1234",
        not_before=datetime.utcnow() - timedelta(days=10),
        not_after=not_after,
        fingerprint_sha256="aa:bb:cc",
        cert_path=f"/etc/ssl/{domain}/fullchain.pem",
        key_path=f"/etc/ssl/{domain}/privkey.pem",
        auto_renew=auto_renew,
        last_renewed=None,
    )


def _make_event(
    severity=EventSeverity.INFO,
    category=EventCategory.SYSTEM,
    action="test_action",
    message="test message",
    event_id="evt-000001",
    transaction_id=None,
):
    """Create a mock event that behaves like an Event with enum-typed category.

    The resource code calls event.category.value, but the Event model's
    category field is typed as str, not EventCategory.  We use a MagicMock
    so that .category.value works as the resource handler expects.
    """
    mock_event = MagicMock()
    mock_event.id = event_id
    mock_event.timestamp = datetime.utcnow()
    mock_event.severity = severity
    mock_event.category = category  # EventCategory enum, so .value works
    mock_event.action = action
    mock_event.resource_type = "site"
    mock_event.resource_id = "example.com"
    mock_event.message = message
    mock_event.transaction_id = transaction_id
    return mock_event


def _make_transaction_summary(
    txn_id="txn-001",
    operation=OperationType.SITE_CREATE,
    status=TransactionStatus.COMPLETED,
):
    return TransactionSummary(
        id=txn_id,
        operation=operation,
        status=status,
        resource_type="site",
        resource_id="example.com",
        created_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_ms=150,
    )


def _make_transaction_detail(
    txn_id="txn-001",
    operation=OperationType.SITE_CREATE,
    status=TransactionStatus.COMPLETED,
    with_diff=False,
    resource_type="site",
    resource_id="example.com",
    error_message=None,
):
    diff = None
    if with_diff:
        diff = TransactionDiff(files_changed=2, total_additions=10, total_deletions=3)
    return TransactionDetail(
        id=txn_id,
        operation=operation,
        status=status,
        resource_type=resource_type,
        resource_id=resource_id,
        created_at=datetime.utcnow(),
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_ms=200,
        error_message=error_message,
        diff=diff,
    )


# ---------------------------------------------------------------------------
# 1. TestSitesResource
# ---------------------------------------------------------------------------


class TestSitesResource:
    """Tests for get_sites_resource()."""

    @pytest.mark.asyncio
    async def test_returns_correct_structure(self, tmp_path):
        """Result dict must contain sites list and count fields."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "mysite.conf").write_text("server { listen 80; server_name mysite.com; }")

        rich_dict = {
            "name": "mysite.com",
            "server_names": ["mysite.com"],
            "listen_ports": [80],
            "ssl_enabled": False,
            "proxy_pass": None,
            "root_path": "/var/www/mysite",
            "enabled": True,
            "status": "active",
        }

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value={}),
            patch("core.cert_helpers.match_certificate", return_value=None),
        ):
            result = await get_sites_resource()

        assert "sites" in result
        assert "total" in result
        assert "enabled_count" in result
        assert "disabled_count" in result
        assert "ssl_enabled_count" in result
        assert "certificate_count" in result
        assert result["total"] == 1
        assert result["enabled_count"] == 1
        assert result["disabled_count"] == 0

    @pytest.mark.asyncio
    async def test_empty_conf_dir(self, tmp_path):
        """Empty conf directory returns zero counts."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        with patch("config.get_nginx_conf_path", return_value=conf_dir):
            result = await get_sites_resource()

        assert result["sites"] == []
        assert result["total"] == 0
        assert result["ssl_enabled_count"] == 0

    @pytest.mark.asyncio
    async def test_nonexistent_conf_dir(self, tmp_path):
        """Non-existent conf directory returns empty result."""
        conf_dir = tmp_path / "does_not_exist"

        with patch("config.get_nginx_conf_path", return_value=conf_dir):
            result = await get_sites_resource()

        assert result == {"sites": [], "total": 0, "enabled_count": 0, "disabled_count": 0, "ssl_enabled_count": 0}

    @pytest.mark.asyncio
    async def test_ssl_enabled_count(self, tmp_path):
        """SSL-enabled sites are counted."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "secure.conf").write_text("server {}")

        rich_dict = {
            "name": "secure.com",
            "server_names": ["secure.com"],
            "listen_ports": [443],
            "ssl_enabled": True,
            "proxy_pass": None,
            "root_path": "/var/www/secure",
            "enabled": True,
            "status": "active",
        }

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value={}),
            patch("core.cert_helpers.match_certificate", return_value=None),
        ):
            result = await get_sites_resource()

        assert result["ssl_enabled_count"] == 1

    @pytest.mark.asyncio
    async def test_certificate_enrichment(self, tmp_path):
        """Sites are enriched with matching certificate data."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "site.conf").write_text("server {}")

        rich_dict = {
            "name": "site.com",
            "server_names": ["site.com"],
            "listen_ports": [80],
            "ssl_enabled": False,
            "proxy_pass": None,
            "root_path": "/var/www/site",
            "enabled": True,
            "status": "active",
        }

        cert_summary = {"domain": "site.com", "status": "valid", "days_until_expiry": 60}
        cert_map = {"site.com": cert_summary}

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value=cert_map),
            patch("core.cert_helpers.match_certificate", return_value=cert_summary),
        ):
            result = await get_sites_resource()

        assert result["certificate_count"] == 1
        assert result["sites"][0]["certificate"] == cert_summary

    @pytest.mark.asyncio
    async def test_parse_error_skipped(self, tmp_path):
        """Files that fail to parse are silently skipped."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "bad.conf").write_text("invalid{{{")

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch(
                "core.config_manager.nginx_parser.parse_config_file",
                side_effect=Exception("parse error"),
            ),
        ):
            result = await get_sites_resource()

        assert result["total"] == 0
        assert result["sites"] == []


# ---------------------------------------------------------------------------
# 2. TestSiteResource
# ---------------------------------------------------------------------------


class TestSiteResource:
    """Tests for get_site_resource(name)."""

    @pytest.mark.asyncio
    async def test_found_enabled_site(self, tmp_path):
        """Enabled site returns rich dict with enabled=True."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "mysite.conf").write_text("server {}")

        rich_dict = {
            "name": "mysite",
            "server_names": ["mysite.com"],
            "listen_ports": [80],
            "ssl_enabled": False,
            "proxy_pass": None,
            "root_path": "/var/www/mysite",
            "status": "active",
        }

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value={}),
            patch("core.cert_helpers.match_certificate", return_value=None),
        ):
            result = await get_site_resource("mysite")

        assert result["enabled"] is True
        assert "suggestions" in result
        # Should suggest adding SSL since ssl_enabled is False
        assert any("SSL" in s or "ssl" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_found_disabled_site(self, tmp_path):
        """Disabled site (.conf.disabled) returns enabled=False and suggest enabling."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "mysite.conf.disabled").write_text("server {}")

        rich_dict = {
            "name": "mysite",
            "server_names": ["mysite.com"],
            "listen_ports": [80],
            "ssl_enabled": True,
            "status": "disabled",
        }

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value={}),
            patch("core.cert_helpers.match_certificate", return_value=None),
        ):
            result = await get_site_resource("mysite")

        assert result["enabled"] is False
        assert any("enable" in s.lower() for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_not_found(self, tmp_path):
        """Missing site returns error dict with suggestions."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        with patch("config.get_nginx_conf_path", return_value=conf_dir):
            result = await get_site_resource("nonexistent")

        assert "error" in result
        assert "nonexistent" in result["error"]
        assert "suggestions" in result
        assert len(result["suggestions"]) >= 1

    @pytest.mark.asyncio
    async def test_certificate_enrichment_with_expiring_cert(self, tmp_path):
        """Site with expiring certificate gets renewal suggestion."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "mysite.conf").write_text("server {}")

        rich_dict = {
            "name": "mysite",
            "server_names": ["mysite.com"],
            "listen_ports": [80],
            "ssl_enabled": True,
            "status": "active",
        }

        cert_summary = {"domain": "mysite.com", "status": "expiring_soon", "days_until_expiry": 10}
        cert_map = {"mysite.com": cert_summary}

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=MagicMock()),
            patch("core.config_manager.ConfigAdapter.to_rich_dict", return_value=rich_dict),
            patch("core.cert_helpers.get_certificate_map", new_callable=AsyncMock, return_value=cert_map),
            patch("core.cert_helpers.match_certificate", return_value=cert_summary),
        ):
            result = await get_site_resource("mysite")

        assert result["certificate"] == cert_summary
        assert any("renew" in s.lower() for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_parse_returns_none(self, tmp_path):
        """When parser returns None, error dict is returned."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "broken.conf").write_text("server {}")

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.config_manager.nginx_parser.parse_config_file", return_value=None),
        ):
            result = await get_site_resource("broken")

        assert "error" in result
        assert "parse" in result["error"].lower() or "Failed" in result["error"]


# ---------------------------------------------------------------------------
# 3. TestCertificatesResource
# ---------------------------------------------------------------------------


class TestCertificatesResource:
    """Tests for get_certificates_resource()."""

    @pytest.mark.asyncio
    async def test_returns_correct_structure(self):
        """Result dict has certificates list plus count fields."""
        cert = _make_certificate(status=CertificateStatus.VALID)
        mock_manager = MagicMock()
        mock_manager.list_certificates = AsyncMock(return_value=[cert])

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificates_resource()

        assert "certificates" in result
        assert "total" in result
        assert "valid_count" in result
        assert "expiring_soon_count" in result
        assert "expired_count" in result
        assert "suggestions" in result
        assert result["total"] == 1
        assert result["valid_count"] == 1

    @pytest.mark.asyncio
    async def test_empty_certificates(self):
        """No certificates produces suggestion to add SSL."""
        mock_manager = MagicMock()
        mock_manager.list_certificates = AsyncMock(return_value=[])

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificates_resource()

        assert result["total"] == 0
        assert any("No certificates" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_expired_generates_urgent_suggestion(self):
        """Expired certificates produce URGENT suggestion."""
        cert = _make_certificate(status=CertificateStatus.EXPIRED, days_offset=-5)
        mock_manager = MagicMock()
        mock_manager.list_certificates = AsyncMock(return_value=[cert])

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificates_resource()

        assert result["expired_count"] == 1
        assert any("URGENT" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_expiring_soon_count(self):
        """Expiring-soon certificates are counted and produce suggestion."""
        cert = _make_certificate(status=CertificateStatus.EXPIRING_SOON, days_offset=15)
        mock_manager = MagicMock()
        mock_manager.list_certificates = AsyncMock(return_value=[cert])

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificates_resource()

        assert result["expiring_soon_count"] == 1
        assert any("expiring soon" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Exceptions return error dict with suggestions."""
        with patch("core.cert_manager.get_cert_manager", side_effect=Exception("db error")):
            result = await get_certificates_resource()

        assert result["total"] == 0
        assert "error" in result
        assert "suggestions" in result


# ---------------------------------------------------------------------------
# 4. TestCertificateResource
# ---------------------------------------------------------------------------


class TestCertificateResource:
    """Tests for get_certificate_resource(domain)."""

    @pytest.mark.asyncio
    async def test_found_valid_certificate(self):
        """Valid certificate returns full detail dict."""
        cert = _make_certificate(domain="example.com", auto_renew=True)
        mock_manager = MagicMock()
        mock_manager.get_certificate = AsyncMock(return_value=cert)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificate_resource("example.com")

        assert result["domain"] == "example.com"
        assert result["status"] == "valid"
        assert result["auto_renew"] is True
        assert "suggestions" in result
        assert "warnings" in result
        # Valid and auto_renew => no urgent suggestions, but no warnings either
        assert len(result["warnings"]) == 0

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Missing certificate returns error with suggestions."""
        mock_manager = MagicMock()
        mock_manager.get_certificate = AsyncMock(return_value=None)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificate_resource("missing.com")

        assert "error" in result
        assert "missing.com" in result["error"]
        assert "suggestions" in result
        assert len(result["suggestions"]) >= 1

    @pytest.mark.asyncio
    async def test_expired_certificate_warnings(self):
        """Expired certificate gets warning and renew suggestion."""
        cert = _make_certificate(
            domain="old.com",
            status=CertificateStatus.EXPIRED,
            days_offset=-10,
        )
        mock_manager = MagicMock()
        mock_manager.get_certificate = AsyncMock(return_value=cert)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificate_resource("old.com")

        assert any("EXPIRED" in w for w in result["warnings"])
        assert any("renew" in s.lower() for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_expiring_soon_certificate(self):
        """Certificate expiring soon gets warning."""
        cert = _make_certificate(
            domain="soon.com",
            status=CertificateStatus.EXPIRING_SOON,
            days_offset=15,
        )
        mock_manager = MagicMock()
        mock_manager.get_certificate = AsyncMock(return_value=cert)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificate_resource("soon.com")

        assert len(result["warnings"]) >= 1
        assert any("expires" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_auto_renew_disabled_suggestion(self):
        """Certificate without auto-renew gets an enable suggestion."""
        cert = _make_certificate(domain="manual.com", auto_renew=False)
        mock_manager = MagicMock()
        mock_manager.get_certificate = AsyncMock(return_value=cert)

        with patch("core.cert_manager.get_cert_manager", return_value=mock_manager):
            result = await get_certificate_resource("manual.com")

        assert any("auto-renewal" in s.lower() for s in result["suggestions"])


# ---------------------------------------------------------------------------
# 5. TestHealthResource
# ---------------------------------------------------------------------------


class TestHealthResource:
    """Tests for get_health_resource()."""

    @pytest.mark.asyncio
    async def test_healthy_status(self, tmp_path):
        """Running NGINX with no issues reports healthy."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()
        (conf_dir / "active.conf").write_text("server {}")

        mock_ds = MagicMock()
        mock_ds.get_container_status = AsyncMock(
            return_value={
                "running": True,
                "container_id": "abc123",
                "uptime_seconds": 7200,
                "worker_count": 4,
                "active_connections": 10,
                "health_status": "healthy",
            }
        )
        mock_ds.test_config = AsyncMock(return_value=(True, "ok", ""))

        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])

        mock_es = MagicMock()
        mock_es.get_event_counts_by_severity = AsyncMock(
            return_value=EventCountBySeverity(info=5, warning=0, error=0, critical=0, total=5)
        )

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.docker_service.docker_service", mock_ds),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await get_health_resource()

        assert result["status"] == "healthy"
        assert result["nginx"]["status"] == "running"
        assert result["nginx"]["config_valid"] is True
        assert "sites" in result
        assert result["sites"]["enabled"] == 1
        assert "certificates" in result
        assert "recent_events" in result
        assert "suggestions" in result
        assert "warnings" in result

    @pytest.mark.asyncio
    async def test_degraded_expired_cert(self, tmp_path):
        """Expired certificate makes overall status degraded."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        mock_ds = MagicMock()
        mock_ds.get_container_status = AsyncMock(
            return_value={
                "running": True,
                "container_id": "abc",
                "uptime_seconds": 100,
                "health_status": "healthy",
            }
        )
        mock_ds.test_config = AsyncMock(return_value=(True, "ok", ""))

        expired_cert = _make_certificate(status=CertificateStatus.EXPIRED, days_offset=-1)
        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[expired_cert])

        mock_es = MagicMock()
        mock_es.get_event_counts_by_severity = AsyncMock(
            return_value=EventCountBySeverity(info=0, warning=0, error=0, critical=0, total=0)
        )

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.docker_service.docker_service", mock_ds),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await get_health_resource()

        assert result["status"] == "degraded"
        assert result["certificates"]["expired"] == 1
        assert any("expired" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_unhealthy_nginx_stopped(self, tmp_path):
        """Stopped NGINX container reports unhealthy."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        mock_ds = MagicMock()
        mock_ds.get_container_status = AsyncMock(return_value={"running": False})
        # test_config should NOT be called when container is not running

        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])

        mock_es = MagicMock()
        mock_es.get_event_counts_by_severity = AsyncMock(
            return_value=EventCountBySeverity(info=0, warning=0, error=0, critical=0, total=0)
        )

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.docker_service.docker_service", mock_ds),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await get_health_resource()

        assert result["status"] == "unhealthy"
        assert result["nginx"]["status"] == "stopped"
        assert any("Start" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_docker_service_error(self, tmp_path):
        """DockerServiceError is handled gracefully."""
        from core.docker_service import DockerServiceError

        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        mock_ds = MagicMock()
        mock_ds.get_container_status = AsyncMock(side_effect=DockerServiceError("container missing", "not_found"))

        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])

        mock_es = MagicMock()
        mock_es.get_event_counts_by_severity = AsyncMock(
            return_value=EventCountBySeverity(info=0, warning=0, error=0, critical=0, total=0)
        )

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.docker_service.docker_service", mock_ds),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await get_health_resource()

        assert result["status"] == "unhealthy"
        assert result["nginx"]["status"] == "error"
        assert "error" in result["nginx"]

    @pytest.mark.asyncio
    async def test_all_sections_present(self, tmp_path):
        """Health result contains all expected top-level sections."""
        conf_dir = tmp_path / "conf.d"
        conf_dir.mkdir()

        mock_ds = MagicMock()
        mock_ds.get_container_status = AsyncMock(return_value={"running": True, "container_id": "x"})
        mock_ds.test_config = AsyncMock(return_value=(True, "", ""))

        mock_cm = MagicMock()
        mock_cm.list_certificates = AsyncMock(return_value=[])

        mock_es = MagicMock()
        mock_es.get_event_counts_by_severity = AsyncMock(
            return_value=EventCountBySeverity(info=0, warning=0, error=0, critical=0, total=0)
        )

        with (
            patch("config.get_nginx_conf_path", return_value=conf_dir),
            patch("core.docker_service.docker_service", mock_ds),
            patch("core.cert_manager.get_cert_manager", return_value=mock_cm),
            patch("core.event_store.get_event_store", return_value=mock_es),
        ):
            result = await get_health_resource()

        expected_keys = {
            "status",
            "timestamp",
            "nginx",
            "sites",
            "certificates",
            "recent_events",
            "suggestions",
            "warnings",
        }
        assert expected_keys.issubset(set(result.keys()))


# ---------------------------------------------------------------------------
# 6. TestEventsResource
# ---------------------------------------------------------------------------


class TestEventsResource:
    """Tests for get_events_resource()."""

    @pytest.mark.asyncio
    async def test_returns_correct_structure(self):
        """Result dict has events list and total."""
        event = _make_event()
        mock_result = MagicMock()
        mock_result.events = [event]
        mock_result.total = 1

        mock_es = MagicMock()
        mock_es.list_events = AsyncMock(return_value=mock_result)

        with patch("core.event_store.get_event_store", return_value=mock_es):
            result = await get_events_resource()

        assert "events" in result
        assert "total" in result
        assert result["total"] == 1
        assert len(result["events"]) == 1
        evt = result["events"][0]
        assert evt["id"] == "evt-000001"
        assert evt["severity"] == "info"
        assert evt["category"] == "system"
        assert evt["action"] == "test_action"
        assert evt["message"] == "test message"

    @pytest.mark.asyncio
    async def test_filtered_by_severity(self):
        """Severity filter is passed through and reflected in result."""
        mock_result = MagicMock()
        mock_result.events = []
        mock_result.total = 0

        mock_es = MagicMock()
        mock_es.list_events = AsyncMock(return_value=mock_result)

        with patch("core.event_store.get_event_store", return_value=mock_es):
            result = await get_events_resource(severity="error")

        assert result["filtered_by"] == {"severity": "error"}

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Exception returns error dict."""
        with patch("core.event_store.get_event_store", side_effect=Exception("store unavailable")):
            result = await get_events_resource()

        assert result["events"] == []
        assert result["total"] == 0
        assert "error" in result


# ---------------------------------------------------------------------------
# 7. TestTransactionsResource
# ---------------------------------------------------------------------------


class TestTransactionsResource:
    """Tests for get_transactions_resource()."""

    @pytest.mark.asyncio
    async def test_returns_correct_structure(self):
        """Result dict has transactions list with rollback info."""
        txn = _make_transaction_summary()
        mock_tm = MagicMock()
        mock_tm.list_transactions = AsyncMock(return_value=TransactionListResponse(transactions=[txn], total=1))
        mock_tm.can_rollback = AsyncMock(return_value=(True, None))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await get_transactions_resource()

        assert "transactions" in result
        assert "total" in result
        assert result["total"] == 1
        t = result["transactions"][0]
        assert t["id"] == "txn-001"
        assert t["operation"] == "site_create"
        assert t["status"] == "completed"
        assert t["can_rollback"] is True
        assert t["rollback_reason"] is None

    @pytest.mark.asyncio
    async def test_rollback_not_available(self):
        """Transactions that cannot rollback include reason."""
        txn = _make_transaction_summary(status=TransactionStatus.ROLLED_BACK)
        mock_tm = MagicMock()
        mock_tm.list_transactions = AsyncMock(return_value=TransactionListResponse(transactions=[txn], total=1))
        mock_tm.can_rollback = AsyncMock(return_value=(False, "Already rolled back"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await get_transactions_resource()

        t = result["transactions"][0]
        assert t["can_rollback"] is False
        assert t["rollback_reason"] == "Already rolled back"

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Exception returns error dict."""
        with patch("core.transaction_manager.get_transaction_manager", side_effect=Exception("db error")):
            result = await get_transactions_resource()

        assert result["transactions"] == []
        assert result["total"] == 0
        assert "error" in result


class TestTransactionResource:
    """Tests for get_transaction_resource(transaction_id)."""

    @pytest.mark.asyncio
    async def test_found_with_diff(self):
        """Found transaction includes diff details and suggestions."""
        detail = _make_transaction_detail(with_diff=True)
        mock_tm = MagicMock()
        mock_tm.get_transaction_detail = AsyncMock(return_value=detail)
        mock_tm.can_rollback = AsyncMock(return_value=(True, None))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await get_transaction_resource("txn-001")

        assert result["id"] == "txn-001"
        assert "diff" in result
        assert result["diff"]["files_changed"] == 2
        assert result["diff"]["total_additions"] == 10
        assert result["diff"]["total_deletions"] == 3
        assert result["can_rollback"] is True
        assert any("rollback" in s.lower() for s in result["suggestions"])
        # resource_type is 'site' and resource_id is set, so should suggest viewing site
        assert any("nginx://sites/" in s for s in result["suggestions"])

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Missing transaction returns error dict."""
        mock_tm = MagicMock()
        mock_tm.get_transaction_detail = AsyncMock(return_value=None)

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await get_transaction_resource("txn-missing")

        assert "error" in result
        assert "txn-missing" in result["error"]
        assert "suggestions" in result

    @pytest.mark.asyncio
    async def test_found_without_diff(self):
        """Transaction without diff does not include diff key."""
        detail = _make_transaction_detail(with_diff=False)
        mock_tm = MagicMock()
        mock_tm.get_transaction_detail = AsyncMock(return_value=detail)
        mock_tm.can_rollback = AsyncMock(return_value=(False, "No snapshot"))

        with patch("core.transaction_manager.get_transaction_manager", return_value=mock_tm):
            result = await get_transaction_resource("txn-001")

        assert "diff" not in result
        assert result["can_rollback"] is False
        assert result["rollback_reason"] == "No snapshot"
