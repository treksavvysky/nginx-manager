"""
Unit tests for SSL certificate context helpers.

Tests the context helper functions for generating suggestions
and warnings for SSL certificate operations.
"""

import pytest
from datetime import datetime, timedelta

from core.context_helpers import (
    get_cert_request_suggestions,
    get_cert_renewal_suggestions,
    get_cert_expiry_warnings,
    get_cert_diagnostic_suggestions,
)
from models.certificate import Certificate, CertificateStatus, CertificateType


class TestCertRequestSuggestions:
    """Test certificate request suggestions."""

    def test_suggestions_not_reloaded(self):
        """Test suggestions when NGINX not reloaded."""
        suggestions = get_cert_request_suggestions(
            domain="example.com",
            reloaded=False,
            sites_using_cert=[]
        )
        # Should suggest reload
        reload_suggestions = [s for s in suggestions if "reload" in s["action"].lower()]
        assert len(reload_suggestions) >= 1

    def test_suggestions_no_sites(self):
        """Test suggestions when no sites using cert."""
        suggestions = get_cert_request_suggestions(
            domain="example.com",
            reloaded=True,
            sites_using_cert=[]
        )
        # Should suggest updating site config
        site_suggestions = [s for s in suggestions if "site" in s["action"].lower()]
        assert len(site_suggestions) >= 1

    def test_suggestions_include_test(self):
        """Test suggestions include testing HTTPS."""
        suggestions = get_cert_request_suggestions(
            domain="example.com",
            reloaded=True,
            sites_using_cert=["example.com"]
        )
        # Should suggest testing
        test_suggestions = [s for s in suggestions if "test" in s["action"].lower()]
        assert len(test_suggestions) >= 1


class TestCertRenewalSuggestions:
    """Test certificate renewal suggestions."""

    def test_renewal_suggestions(self):
        """Test renewal suggestions."""
        suggestions = get_cert_renewal_suggestions(domain="example.com")
        assert len(suggestions) >= 1
        # Should suggest verifying HTTPS
        verify_suggestions = [s for s in suggestions if "verify" in s["action"].lower()]
        assert len(verify_suggestions) >= 1


class TestCertExpiryWarnings:
    """Test certificate expiry warnings."""

    def test_no_warning_when_not_expiring(self):
        """Test no warning when certificate is not expiring soon."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            not_after=datetime.utcnow() + timedelta(days=60)
        )
        warnings = get_cert_expiry_warnings(cert)
        # Should have no critical warnings
        critical = [w for w in warnings if "critical" in w.get("code", "").lower()]
        assert len(critical) == 0

    def test_warning_expiring_30_days(self):
        """Test warning when certificate expires in 30 days."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            not_after=datetime.utcnow() + timedelta(days=25)
        )
        warnings = get_cert_expiry_warnings(cert)
        assert len(warnings) >= 1
        assert any("expir" in w["message"].lower() for w in warnings)

    def test_warning_expiring_14_days(self):
        """Test warning when certificate expires in 14 days."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            not_after=datetime.utcnow() + timedelta(days=10)
        )
        warnings = get_cert_expiry_warnings(cert)
        assert len(warnings) >= 1

    def test_critical_warning_expiring_7_days(self):
        """Test critical warning when certificate expires in 7 days."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            not_after=datetime.utcnow() + timedelta(days=5)
        )
        warnings = get_cert_expiry_warnings(cert)
        assert len(warnings) >= 1
        assert any("critical" in w.get("code", "").lower() for w in warnings)

    def test_critical_warning_expired(self):
        """Test critical warning when certificate is expired."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            not_after=datetime.utcnow() - timedelta(days=1)
        )
        warnings = get_cert_expiry_warnings(cert)
        assert len(warnings) >= 1
        assert any("expired" in w.get("code", "").lower() for w in warnings)

    def test_warning_auto_renew_disabled(self):
        """Test warning when auto-renew is disabled."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            auto_renew=False,
            not_after=datetime.utcnow() + timedelta(days=25)
        )
        warnings = get_cert_expiry_warnings(cert)
        auto_renew_warnings = [w for w in warnings if "auto" in w.get("code", "").lower()]
        assert len(auto_renew_warnings) >= 1

    def test_no_warning_custom_cert_no_auto_renew(self):
        """Test no auto-renew warning for custom certificates."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.CUSTOM,
            auto_renew=False,
            not_after=datetime.utcnow() + timedelta(days=25)
        )
        warnings = get_cert_expiry_warnings(cert)
        auto_renew_warnings = [w for w in warnings if "auto_renew" in w.get("code", "").lower()]
        assert len(auto_renew_warnings) == 0


class TestCertDiagnosticSuggestions:
    """Test certificate diagnostic suggestions."""

    def test_suggestions_dns_not_resolving(self):
        """Test suggestions when DNS is not resolving."""
        suggestions = get_cert_diagnostic_suggestions(
            domain="example.com",
            dns_ok=False,
            port_80_ok=False,
            has_cert=False
        )
        dns_suggestions = [s for s in suggestions if "dns" in s["action"].lower()]
        assert len(dns_suggestions) >= 1

    def test_suggestions_port_80_not_open(self):
        """Test suggestions when port 80 is not open."""
        suggestions = get_cert_diagnostic_suggestions(
            domain="example.com",
            dns_ok=True,
            port_80_ok=False,
            has_cert=False
        )
        port_suggestions = [s for s in suggestions if "port" in s["action"].lower() or "80" in s["action"]]
        assert len(port_suggestions) >= 1

    def test_suggestions_ready_no_cert(self):
        """Test suggestions when ready but no cert."""
        suggestions = get_cert_diagnostic_suggestions(
            domain="example.com",
            dns_ok=True,
            port_80_ok=True,
            has_cert=False
        )
        cert_suggestions = [s for s in suggestions if "certificate" in s["action"].lower() or "ssl" in s["action"].lower()]
        assert len(cert_suggestions) >= 1

    def test_suggestions_has_cert(self):
        """Test suggestions when certificate exists."""
        suggestions = get_cert_diagnostic_suggestions(
            domain="example.com",
            dns_ok=True,
            port_80_ok=True,
            has_cert=True
        )
        # Should suggest using HTTPS
        https_suggestions = [s for s in suggestions if "https" in s["action"].lower()]
        assert len(https_suggestions) >= 1
