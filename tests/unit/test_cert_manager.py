"""
Unit tests for certificate manager.

Tests the CertManager class with mocked ACME service.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import json

from core.cert_manager import (
    CertManager,
    CertificateError,
    CertificateNotFoundError,
    CertificateValidationError,
    DNSError,
)
from models.certificate import (
    Certificate,
    CertificateStatus,
    CertificateType,
    CertificateDryRunResult,
)


class TestCertManagerInit:
    """Test CertManager initialization."""

    def test_cert_manager_creation(self):
        """Test CertManager can be created."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()
                assert manager is not None


class TestCertManagerDNSCheck:
    """Test DNS checking functionality."""

    @pytest.mark.asyncio
    async def test_check_domain_dns_resolves(self):
        """Test DNS check for domain that resolves."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch('asyncio.to_thread') as mock_thread:
            mock_thread.return_value = [
                (2, 1, 6, '', ('93.184.216.34', 0))
            ]
            resolves, ips = await manager.check_domain_dns("example.com")
            assert resolves is True
            assert len(ips) > 0

    @pytest.mark.asyncio
    async def test_check_domain_dns_not_resolves(self):
        """Test DNS check for domain that doesn't resolve."""
        import socket
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch('asyncio.to_thread') as mock_thread:
            mock_thread.side_effect = socket.gaierror("Name not resolved")
            resolves, ips = await manager.check_domain_dns("nonexistent.invalid")
            assert resolves is False
            assert len(ips) == 0


class TestCertManagerDryRun:
    """Test dry-run functionality."""

    @pytest.mark.asyncio
    async def test_request_certificate_dry_run_success(self):
        """Test dry-run certificate request with valid domain."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'check_domain_dns', return_value=(True, ['1.2.3.4'])):
            with patch.object(manager, 'check_port_accessible', return_value=True):
                result = await manager.request_certificate(
                    domain="example.com",
                    dry_run=True
                )

                assert isinstance(result, CertificateDryRunResult)
                assert result.would_succeed is True
                assert result.domain_resolves is True
                assert result.port_80_accessible is True

    @pytest.mark.asyncio
    async def test_request_certificate_dry_run_dns_failure(self):
        """Test dry-run certificate request with DNS failure."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'check_domain_dns', return_value=(False, [])):
            with patch.object(manager, 'check_port_accessible', return_value=False):
                result = await manager.request_certificate(
                    domain="example.com",
                    dry_run=True
                )

                assert isinstance(result, CertificateDryRunResult)
                assert result.would_succeed is False
                assert result.domain_resolves is False
                assert len(result.warnings) > 0


class TestCertManagerDatabase:
    """Test database operations."""

    @pytest.mark.asyncio
    async def test_certificate_to_db_conversion(self):
        """Test converting certificate to database format."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        cert = Certificate(
            domain="example.com",
            alt_names=["www.example.com"],
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID,
            issuer="Let's Encrypt",
            not_after=datetime.utcnow() + timedelta(days=90)
        )

        db_row = await manager._certificate_to_db(cert)

        assert db_row["domain"] == "example.com"
        assert json.loads(db_row["alt_names_json"]) == ["www.example.com"]
        assert db_row["certificate_type"] == "letsencrypt"
        assert db_row["status"] == "valid"

    @pytest.mark.asyncio
    async def test_db_to_certificate_conversion(self):
        """Test converting database row to certificate."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        db_row = {
            "id": "cert-123",
            "domain": "example.com",
            "alt_names_json": '["www.example.com"]',
            "certificate_type": "letsencrypt",
            "status": "valid",
            "cert_path": "/etc/ssl/certs/example.com/fullchain.pem",
            "key_path": "/etc/ssl/certs/example.com/privkey.pem",
            "chain_path": None,
            "issuer": "Let's Encrypt",
            "serial_number": "abc123",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2024-04-01T00:00:00",
            "fingerprint_sha256": "abc",
            "created_at": "2024-01-01T00:00:00",
            "last_renewed": None,
            "renewal_attempts": 0,
            "last_renewal_error": None,
            "auto_renew": True,
            "acme_account_id": None,
            "acme_order_url": None
        }

        cert = await manager._db_to_certificate(db_row)

        assert cert.id == "cert-123"
        assert cert.domain == "example.com"
        assert cert.alt_names == ["www.example.com"]
        assert cert.certificate_type == CertificateType.LETSENCRYPT
        assert cert.status == CertificateStatus.VALID


class TestCertManagerRenewal:
    """Test certificate renewal functionality."""

    @pytest.mark.asyncio
    async def test_renew_certificate_not_found(self):
        """Test renewal fails when certificate not found."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'get_certificate', return_value=None):
            with pytest.raises(CertificateNotFoundError):
                await manager.renew_certificate(domain="nonexistent.com")

    @pytest.mark.asyncio
    async def test_renew_certificate_custom_rejected(self):
        """Test renewal fails for custom certificates."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        custom_cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.CUSTOM,
            status=CertificateStatus.VALID
        )

        with patch.object(manager, 'get_certificate', return_value=custom_cert):
            with pytest.raises(CertificateError) as exc_info:
                await manager.renew_certificate(domain="example.com")
            assert "custom" in str(exc_info.value.message).lower()

    @pytest.mark.asyncio
    async def test_renew_certificate_dry_run_not_needed(self):
        """Test dry-run renewal when not needed."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID,
            not_after=datetime.utcnow() + timedelta(days=60)  # Not expiring soon
        )

        with patch.object(manager, 'get_certificate', return_value=cert):
            result = await manager.renew_certificate(
                domain="example.com",
                dry_run=True
            )

            assert isinstance(result, CertificateDryRunResult)
            # Should indicate renewal not needed
            assert any("not needed" in w.get("code", "").lower() or
                      "remaining" in w.get("message", "").lower()
                      for w in result.warnings)


class TestCertManagerRevocation:
    """Test certificate revocation functionality."""

    @pytest.mark.asyncio
    async def test_revoke_certificate_not_found(self):
        """Test revocation fails when certificate not found."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'get_certificate', return_value=None):
            with pytest.raises(CertificateNotFoundError):
                await manager.revoke_certificate(domain="nonexistent.com")

    @pytest.mark.asyncio
    async def test_revoke_certificate_dry_run(self):
        """Test dry-run revocation."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID
        )

        with patch.object(manager, 'get_certificate', return_value=cert):
            result = await manager.revoke_certificate(
                domain="example.com",
                dry_run=True
            )

            assert isinstance(result, CertificateDryRunResult)
            assert result.would_succeed is True


class TestCertManagerDiagnostic:
    """Test SSL diagnostic functionality."""

    @pytest.mark.asyncio
    async def test_diagnose_ssl_ready(self):
        """Test diagnostic when domain is ready for SSL."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'check_domain_dns', return_value=(True, ['1.2.3.4'])):
            with patch.object(manager, 'check_port_accessible', side_effect=[True, True]):
                with patch.object(manager, 'get_certificate', return_value=None):
                    result = await manager.diagnose_ssl("example.com")

                    assert result.domain == "example.com"
                    assert result.dns_resolves is True
                    assert result.port_80_open is True
                    assert result.ready_for_ssl is True

    @pytest.mark.asyncio
    async def test_diagnose_ssl_dns_failure(self):
        """Test diagnostic when DNS fails."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        with patch.object(manager, 'check_domain_dns', return_value=(False, [])):
            with patch.object(manager, 'check_port_accessible', return_value=False):
                with patch.object(manager, 'get_certificate', return_value=None):
                    result = await manager.diagnose_ssl("example.com")

                    assert result.dns_resolves is False
                    assert result.ready_for_ssl is False
                    assert len(result.issues) > 0

    @pytest.mark.asyncio
    async def test_diagnose_ssl_with_existing_cert(self):
        """Test diagnostic when certificate exists."""
        with patch('core.cert_manager.get_acme_service'):
            with patch('core.cert_manager.get_database'):
                manager = CertManager()

        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID,
            issuer="Let's Encrypt",
            not_after=datetime.utcnow() + timedelta(days=90)
        )

        with patch.object(manager, 'check_domain_dns', return_value=(True, ['1.2.3.4'])):
            with patch.object(manager, 'check_port_accessible', side_effect=[True, True]):
                with patch.object(manager, 'get_certificate', return_value=cert):
                    result = await manager.diagnose_ssl("example.com")

                    assert result.has_certificate is True
                    assert result.certificate_valid is True
                    assert result.certificate_issuer == "Let's Encrypt"
