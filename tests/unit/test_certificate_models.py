"""
Unit tests for certificate models.

Tests the Pydantic models for SSL certificate management.
"""

import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError

from models.certificate import (
    Certificate,
    CertificateStatus,
    CertificateType,
    CertificateRequestCreate,
    CertificateUploadRequest,
    CertificateResponse,
    CertificateMutationResponse,
    CertificateDryRunResult,
    CertificateListResponse,
    SSLDiagnosticResult,
    ACMEAccount
)


class TestCertificateModel:
    """Test Certificate model."""

    def test_certificate_creation(self):
        """Test basic certificate creation."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID
        )
        assert cert.domain == "example.com"
        assert cert.certificate_type == CertificateType.LETSENCRYPT
        assert cert.status == CertificateStatus.VALID
        assert cert.id.startswith("cert-")
        assert cert.auto_renew is True

    def test_certificate_with_expiry(self):
        """Test certificate with expiry date."""
        expiry = datetime.utcnow() + timedelta(days=30)
        cert = Certificate(
            domain="example.com",
            not_after=expiry
        )
        assert cert.days_until_expiry == 30 or cert.days_until_expiry == 29  # Allow for timing
        assert cert.is_expired is False
        assert cert.is_expiring_soon is True

    def test_certificate_expired(self):
        """Test expired certificate."""
        expiry = datetime.utcnow() - timedelta(days=1)
        cert = Certificate(
            domain="example.com",
            not_after=expiry
        )
        assert cert.is_expired is True
        assert cert.days_until_expiry < 0

    def test_certificate_not_expiring_soon(self):
        """Test certificate not expiring soon."""
        expiry = datetime.utcnow() + timedelta(days=60)
        cert = Certificate(
            domain="example.com",
            not_after=expiry
        )
        assert cert.is_expiring_soon is False

    def test_certificate_alt_names(self):
        """Test certificate with alternative names."""
        cert = Certificate(
            domain="example.com",
            alt_names=["www.example.com", "mail.example.com"]
        )
        assert len(cert.alt_names) == 2
        assert "www.example.com" in cert.alt_names


class TestCertificateRequestCreate:
    """Test CertificateRequestCreate model."""

    def test_valid_request(self):
        """Test valid certificate request."""
        request = CertificateRequestCreate(
            domain="example.com",
            alt_names=["www.example.com"],
            auto_renew=True
        )
        assert request.domain == "example.com"
        assert len(request.alt_names) == 1

    def test_domain_validation_lowercase(self):
        """Test domain is converted to lowercase."""
        request = CertificateRequestCreate(domain="EXAMPLE.COM")
        assert request.domain == "example.com"

    def test_domain_validation_strip_whitespace(self):
        """Test domain whitespace is stripped."""
        request = CertificateRequestCreate(domain="  example.com  ")
        assert request.domain == "example.com"

    def test_invalid_domain_format(self):
        """Test invalid domain format is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            CertificateRequestCreate(domain="not a valid domain!")
        assert "Invalid domain format" in str(exc_info.value)

    def test_wildcard_domain_rejected(self):
        """Test wildcard domains are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            CertificateRequestCreate(domain="*.example.com")
        # Wildcard domains are rejected (either by format or explicit wildcard check)
        assert "*.example.com" in str(exc_info.value)

    def test_empty_domain_rejected(self):
        """Test empty domain is rejected."""
        with pytest.raises(ValidationError):
            CertificateRequestCreate(domain="")

    def test_alt_names_validation(self):
        """Test alt names are validated."""
        request = CertificateRequestCreate(
            domain="example.com",
            alt_names=["WWW.EXAMPLE.COM", "  api.example.com  "]
        )
        assert "www.example.com" in request.alt_names
        assert "api.example.com" in request.alt_names


class TestCertificateUploadRequest:
    """Test CertificateUploadRequest model."""

    VALID_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfLAQG9u4MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVu
dXNlZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnVudXNlZDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC0sKlBGDfS3DQCVB8+0t0S
PLACEHOLDER_CONTENT
-----END CERTIFICATE-----"""

    VALID_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEAtLCpQRg30tw0AlQf
PLACEHOLDER_CONTENT
-----END PRIVATE KEY-----"""

    def test_valid_upload_request(self):
        """Test valid certificate upload request."""
        request = CertificateUploadRequest(
            domain="example.com",
            certificate_pem=self.VALID_CERT_PEM,
            private_key_pem=self.VALID_KEY_PEM
        )
        assert request.domain == "example.com"

    def test_invalid_certificate_pem_rejected(self):
        """Test invalid certificate PEM is rejected."""
        # Create a string that's long enough but not valid PEM
        invalid_cert = "x" * 150  # Long enough but not PEM format
        with pytest.raises(ValidationError) as exc_info:
            CertificateUploadRequest(
                domain="example.com",
                certificate_pem=invalid_cert,
                private_key_pem=self.VALID_KEY_PEM
            )
        assert "PEM format" in str(exc_info.value) or "CERTIFICATE" in str(exc_info.value)

    def test_invalid_key_pem_rejected(self):
        """Test invalid key PEM is rejected."""
        # Create a string that's long enough but not valid PEM
        invalid_key = "x" * 150  # Long enough but not PEM format
        with pytest.raises(ValidationError) as exc_info:
            CertificateUploadRequest(
                domain="example.com",
                certificate_pem=self.VALID_CERT_PEM,
                private_key_pem=invalid_key
            )
        assert "PEM format" in str(exc_info.value) or "PRIVATE KEY" in str(exc_info.value)

    def test_rsa_key_accepted(self):
        """Test RSA private key is accepted."""
        rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBANOH3jC7bMGd0njCLHPq8t7G
PLACEHOLDER
-----END RSA PRIVATE KEY-----"""
        request = CertificateUploadRequest(
            domain="example.com",
            certificate_pem=self.VALID_CERT_PEM,
            private_key_pem=rsa_key
        )
        assert "RSA PRIVATE KEY" in request.private_key_pem

    def test_ec_key_accepted(self):
        """Test EC private key is accepted."""
        ec_key = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIBg7RmJFLkGy0hLAPFfVJFwQ
PLACEHOLDER
-----END EC PRIVATE KEY-----"""
        request = CertificateUploadRequest(
            domain="example.com",
            certificate_pem=self.VALID_CERT_PEM,
            private_key_pem=ec_key
        )
        assert "EC PRIVATE KEY" in request.private_key_pem


class TestCertificateResponse:
    """Test CertificateResponse model."""

    def test_from_certificate(self):
        """Test creating response from certificate."""
        cert = Certificate(
            domain="example.com",
            certificate_type=CertificateType.LETSENCRYPT,
            status=CertificateStatus.VALID,
            issuer="Let's Encrypt",
            not_after=datetime.utcnow() + timedelta(days=90)
        )
        response = CertificateResponse.from_certificate(cert)
        assert response.domain == "example.com"
        assert response.issuer == "Let's Encrypt"
        assert response.days_until_expiry is not None

    def test_from_certificate_with_context(self):
        """Test creating response with suggestions and warnings."""
        cert = Certificate(domain="example.com")
        suggestions = [{"action": "Test", "reason": "Test"}]
        warnings = [{"code": "test", "message": "Test"}]
        response = CertificateResponse.from_certificate(
            cert,
            suggestions=suggestions,
            warnings=warnings
        )
        assert len(response.suggestions) == 1
        assert len(response.warnings) == 1


class TestCertificateDryRunResult:
    """Test CertificateDryRunResult model."""

    def test_dry_run_result(self):
        """Test dry run result creation."""
        result = CertificateDryRunResult(
            would_succeed=True,
            operation="request_certificate",
            message="Would succeed",
            domain_resolves=True,
            port_80_accessible=True
        )
        assert result.dry_run is True
        assert result.would_succeed is True

    def test_dry_run_with_warnings(self):
        """Test dry run result with warnings."""
        result = CertificateDryRunResult(
            would_succeed=False,
            operation="request_certificate",
            message="Would fail",
            warnings=[{"code": "dns_error", "message": "DNS not configured"}]
        )
        assert result.would_succeed is False
        assert len(result.warnings) == 1


class TestCertificateListResponse:
    """Test CertificateListResponse model."""

    def test_list_response(self):
        """Test certificate list response."""
        response = CertificateListResponse(
            certificates=[],
            total=0,
            valid_count=0,
            expiring_soon_count=0,
            expired_count=0
        )
        assert response.total == 0

    def test_list_response_with_certificates(self):
        """Test certificate list response with certificates."""
        cert = Certificate(domain="example.com")
        cert_response = CertificateResponse.from_certificate(cert)
        response = CertificateListResponse(
            certificates=[cert_response],
            total=1,
            valid_count=0,
            expiring_soon_count=0,
            expired_count=0
        )
        assert response.total == 1
        assert len(response.certificates) == 1


class TestSSLDiagnosticResult:
    """Test SSLDiagnosticResult model."""

    def test_diagnostic_result(self):
        """Test SSL diagnostic result."""
        result = SSLDiagnosticResult(
            domain="example.com",
            dns_resolves=True,
            dns_ip_addresses=["1.2.3.4"],
            port_80_open=True,
            port_443_open=True,
            ready_for_ssl=True
        )
        assert result.domain == "example.com"
        assert result.ready_for_ssl is True

    def test_diagnostic_with_issues(self):
        """Test diagnostic result with issues."""
        result = SSLDiagnosticResult(
            domain="example.com",
            dns_resolves=False,
            issues=["Domain does not resolve"],
            ready_for_ssl=False
        )
        assert result.ready_for_ssl is False
        assert len(result.issues) == 1


class TestACMEAccount:
    """Test ACMEAccount model."""

    def test_acme_account(self):
        """Test ACME account creation."""
        account = ACMEAccount(
            email="admin@example.com",
            directory_url="https://acme-v02.api.letsencrypt.org/directory",
            private_key_pem="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
        )
        assert account.email == "admin@example.com"
        assert account.id.startswith("acme-")


class TestCertificateMutationResponse:
    """Test CertificateMutationResponse model."""

    def test_mutation_response(self):
        """Test certificate mutation response."""
        response = CertificateMutationResponse(
            success=True,
            message="Certificate issued",
            domain="example.com",
            transaction_id="tx-123",
            reload_required=True,
            reloaded=False
        )
        assert response.success is True
        assert response.transaction_id == "tx-123"

    def test_mutation_response_with_certificate(self):
        """Test mutation response with certificate details."""
        cert = Certificate(domain="example.com")
        cert_response = CertificateResponse.from_certificate(cert)
        response = CertificateMutationResponse(
            success=True,
            message="Certificate issued",
            domain="example.com",
            transaction_id="tx-123",
            certificate=cert_response
        )
        assert response.certificate is not None
        assert response.certificate.domain == "example.com"
