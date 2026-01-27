"""
Certificate models for SSL certificate management.

Provides Pydantic models for certificate requests, responses,
and database representation with full validation.
"""

import re
import uuid
from enum import Enum
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator


class CertificateStatus(str, Enum):
    """Certificate lifecycle status."""
    PENDING = "pending"           # Certificate requested, challenge in progress
    VALID = "valid"               # Certificate active and valid
    EXPIRED = "expired"           # Certificate has expired
    EXPIRING_SOON = "expiring_soon"  # Within 30 days of expiry
    REVOKED = "revoked"           # Certificate has been revoked
    FAILED = "failed"             # Issuance failed


class CertificateType(str, Enum):
    """Type of SSL certificate."""
    LETSENCRYPT = "letsencrypt"   # Auto-managed via ACME
    CUSTOM = "custom"              # User-uploaded certificate


class Certificate(BaseModel):
    """
    Represents an SSL certificate in the system.

    Used for both database storage and API responses.
    """
    id: str = Field(
        default_factory=lambda: f"cert-{uuid.uuid4().hex[:12]}",
        description="Unique certificate identifier"
    )
    domain: str = Field(..., description="Primary domain for the certificate")
    alt_names: List[str] = Field(
        default_factory=list,
        description="Subject Alternative Names (SANs)"
    )
    certificate_type: CertificateType = Field(
        default=CertificateType.LETSENCRYPT,
        description="Type of certificate (letsencrypt or custom)"
    )
    status: CertificateStatus = Field(
        default=CertificateStatus.PENDING,
        description="Current certificate status"
    )

    # File paths (container paths)
    cert_path: Optional[str] = Field(
        None,
        description="Path to fullchain.pem"
    )
    key_path: Optional[str] = Field(
        None,
        description="Path to privkey.pem"
    )
    chain_path: Optional[str] = Field(
        None,
        description="Path to chain.pem (intermediate certificates)"
    )

    # Certificate details
    issuer: Optional[str] = Field(None, description="Certificate issuer (CA)")
    serial_number: Optional[str] = Field(None, description="Certificate serial number")
    not_before: Optional[datetime] = Field(None, description="Certificate valid from")
    not_after: Optional[datetime] = Field(None, description="Certificate expiry date")
    fingerprint_sha256: Optional[str] = Field(
        None,
        description="SHA-256 fingerprint of the certificate"
    )

    # Management metadata
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the certificate was first requested/uploaded"
    )
    last_renewed: Optional[datetime] = Field(
        None,
        description="When the certificate was last renewed"
    )
    renewal_attempts: int = Field(
        default=0,
        description="Number of renewal attempts"
    )
    last_renewal_error: Optional[str] = Field(
        None,
        description="Error message from last failed renewal"
    )
    auto_renew: bool = Field(
        default=True,
        description="Whether to auto-renew this certificate"
    )

    # ACME-specific fields
    acme_account_id: Optional[str] = Field(
        None,
        description="ACME account used to issue this certificate"
    )
    acme_order_url: Optional[str] = Field(
        None,
        description="ACME order URL for this certificate"
    )

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calculate days until certificate expires."""
        if self.not_after:
            # Handle both timezone-aware and naive datetimes
            now = datetime.utcnow()
            not_after = self.not_after
            # If not_after is timezone-aware, make it naive for comparison
            if not_after.tzinfo is not None:
                not_after = not_after.replace(tzinfo=None)
            delta = not_after - now
            return delta.days
        return None

    @property
    def is_expired(self) -> bool:
        """Check if certificate is expired."""
        if self.not_after:
            now = datetime.utcnow()
            not_after = self.not_after
            # If not_after is timezone-aware, make it naive for comparison
            if not_after.tzinfo is not None:
                not_after = not_after.replace(tzinfo=None)
            return now > not_after
        return False

    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate expires within 30 days."""
        days = self.days_until_expiry
        return days is not None and 0 < days <= 30


# Request Models

class CertificateRequestCreate(BaseModel):
    """Request to obtain a new SSL certificate from Let's Encrypt."""

    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Primary domain for the certificate"
    )
    alt_names: List[str] = Field(
        default_factory=list,
        max_length=100,
        description="Additional domains (Subject Alternative Names)"
    )
    auto_renew: bool = Field(
        default=True,
        description="Enable automatic renewal before expiry"
    )
    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after certificate installation"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        v = v.strip().lower()
        if not v:
            raise ValueError("Domain cannot be empty")
        # Basic domain validation
        if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", v):
            raise ValueError(f"Invalid domain format: {v}")
        if v.startswith("*."):
            raise ValueError("Wildcard certificates are not yet supported")
        if ".." in v:
            raise ValueError("Domain cannot contain consecutive dots")
        return v

    @field_validator("alt_names")
    @classmethod
    def validate_alt_names(cls, v: List[str]) -> List[str]:
        """Validate alternative domain names."""
        validated = []
        for name in v:
            name = name.strip().lower()
            if not name:
                continue
            if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", name):
                raise ValueError(f"Invalid domain format: {name}")
            if name.startswith("*."):
                raise ValueError("Wildcard certificates are not yet supported")
            validated.append(name)
        return validated


class CertificateUploadRequest(BaseModel):
    """Request to upload a custom SSL certificate."""

    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Primary domain for the certificate"
    )
    certificate_pem: str = Field(
        ...,
        min_length=100,
        description="PEM-encoded certificate (including chain if applicable)"
    )
    private_key_pem: str = Field(
        ...,
        min_length=100,
        description="PEM-encoded private key"
    )
    chain_pem: Optional[str] = Field(
        None,
        description="PEM-encoded intermediate certificate chain (optional)"
    )
    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after installation"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format."""
        v = v.strip().lower()
        if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", v):
            raise ValueError(f"Invalid domain format: {v}")
        return v

    @field_validator("certificate_pem")
    @classmethod
    def validate_certificate_pem(cls, v: str) -> str:
        """Validate certificate PEM format."""
        v = v.strip()
        if not v.startswith("-----BEGIN CERTIFICATE-----"):
            raise ValueError("Certificate must be in PEM format")
        if "-----END CERTIFICATE-----" not in v:
            raise ValueError("Invalid certificate PEM format")
        return v

    @field_validator("private_key_pem")
    @classmethod
    def validate_private_key_pem(cls, v: str) -> str:
        """Validate private key PEM format."""
        v = v.strip()
        if not (v.startswith("-----BEGIN PRIVATE KEY-----") or
                v.startswith("-----BEGIN RSA PRIVATE KEY-----") or
                v.startswith("-----BEGIN EC PRIVATE KEY-----")):
            raise ValueError("Private key must be in PEM format")
        return v


class CertificateRenewRequest(BaseModel):
    """Request to renew an existing certificate."""

    force: bool = Field(
        default=False,
        description="Force renewal even if certificate is not expiring soon"
    )
    auto_reload: bool = Field(
        default=False,
        description="Automatically reload NGINX after renewal"
    )


# Response Models

class CertificateResponse(BaseModel):
    """Full certificate details for API response."""

    id: str
    domain: str
    alt_names: List[str]
    certificate_type: CertificateType
    status: CertificateStatus

    # Certificate details
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    fingerprint_sha256: Optional[str] = None

    # Paths
    cert_path: Optional[str] = None
    key_path: Optional[str] = None

    # Management info
    created_at: datetime
    last_renewed: Optional[datetime] = None
    auto_renew: bool = True

    # Rich context for AI agents
    suggestions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Suggested next actions"
    )
    warnings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Non-blocking warnings about the certificate"
    )

    @classmethod
    def from_certificate(
        cls,
        cert: Certificate,
        suggestions: List[Dict[str, Any]] = None,
        warnings: List[Dict[str, Any]] = None
    ) -> "CertificateResponse":
        """Create response from Certificate model."""
        return cls(
            id=cert.id,
            domain=cert.domain,
            alt_names=cert.alt_names,
            certificate_type=cert.certificate_type,
            status=cert.status,
            issuer=cert.issuer,
            serial_number=cert.serial_number,
            not_before=cert.not_before,
            not_after=cert.not_after,
            days_until_expiry=cert.days_until_expiry,
            fingerprint_sha256=cert.fingerprint_sha256,
            cert_path=cert.cert_path,
            key_path=cert.key_path,
            created_at=cert.created_at,
            last_renewed=cert.last_renewed,
            auto_renew=cert.auto_renew,
            suggestions=suggestions or [],
            warnings=warnings or []
        )


class CertificateMutationResponse(BaseModel):
    """Response from certificate mutation operations."""

    success: bool = Field(..., description="Whether the operation succeeded")
    message: str = Field(..., description="Human-readable result message")
    domain: str = Field(..., description="Domain of the affected certificate")
    transaction_id: str = Field(..., description="Transaction ID for audit/rollback")
    certificate: Optional[CertificateResponse] = Field(
        None,
        description="Certificate details (if available)"
    )
    reload_required: bool = Field(
        default=True,
        description="Whether NGINX reload is needed"
    )
    reloaded: bool = Field(
        default=False,
        description="Whether NGINX was reloaded"
    )

    # Rich context for AI agents
    suggestions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Suggested next actions"
    )
    warnings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Non-blocking warnings"
    )


class CertificateDryRunResult(BaseModel):
    """Result of a dry-run certificate operation."""

    dry_run: bool = Field(default=True, description="Always true for dry-run")
    would_succeed: bool = Field(
        ...,
        description="Whether the operation would succeed"
    )
    operation: str = Field(
        ...,
        description="Operation that would be performed"
    )
    message: str = Field(
        ...,
        description="Summary of what would happen"
    )

    # Validation results
    domain_resolves: bool = Field(
        default=False,
        description="Whether the domain resolves in DNS"
    )
    domain_points_to_server: bool = Field(
        default=False,
        description="Whether the domain points to this server"
    )
    port_80_accessible: bool = Field(
        default=False,
        description="Whether port 80 is accessible for HTTP-01 challenge"
    )
    nginx_config_valid: bool = Field(
        default=False,
        description="Whether NGINX config would be valid"
    )

    # Impact analysis
    sites_affected: List[str] = Field(
        default_factory=list,
        description="Sites that would use this certificate"
    )
    files_to_create: List[str] = Field(
        default_factory=list,
        description="Files that would be created"
    )

    # Warnings
    warnings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Non-blocking warnings"
    )


class CertificateListResponse(BaseModel):
    """Paginated list of certificates."""

    certificates: List[CertificateResponse] = Field(
        ...,
        description="List of certificates"
    )
    total: int = Field(..., description="Total number of certificates")
    valid_count: int = Field(
        default=0,
        description="Number of valid certificates"
    )
    expiring_soon_count: int = Field(
        default=0,
        description="Number of certificates expiring within 30 days"
    )
    expired_count: int = Field(
        default=0,
        description="Number of expired certificates"
    )

    # Rich context for AI agents
    suggestions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Suggested actions based on certificate status"
    )


class SSLDiagnosticResult(BaseModel):
    """Result of SSL diagnostic check for a domain."""

    domain: str = Field(..., description="Domain that was checked")

    # DNS checks
    dns_resolves: bool = Field(
        default=False,
        description="Whether domain resolves in DNS"
    )
    dns_ip_addresses: List[str] = Field(
        default_factory=list,
        description="IP addresses the domain resolves to"
    )
    points_to_this_server: bool = Field(
        default=False,
        description="Whether domain points to this server"
    )

    # Port accessibility
    port_80_open: bool = Field(
        default=False,
        description="Whether port 80 is accessible"
    )
    port_443_open: bool = Field(
        default=False,
        description="Whether port 443 is accessible"
    )

    # Certificate status (if installed)
    has_certificate: bool = Field(
        default=False,
        description="Whether a certificate is installed"
    )
    certificate_valid: bool = Field(
        default=False,
        description="Whether the installed certificate is valid"
    )
    certificate_expiry: Optional[datetime] = Field(
        None,
        description="Certificate expiry date"
    )
    certificate_issuer: Optional[str] = Field(
        None,
        description="Certificate issuer"
    )

    # Chain validation
    chain_valid: bool = Field(
        default=False,
        description="Whether the certificate chain is complete"
    )
    chain_issues: List[str] = Field(
        default_factory=list,
        description="Issues with the certificate chain"
    )

    # Overall assessment
    ready_for_ssl: bool = Field(
        default=False,
        description="Whether domain is ready for SSL certificate"
    )
    issues: List[str] = Field(
        default_factory=list,
        description="Issues that need to be resolved"
    )
    suggestions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Suggested actions"
    )


# ACME Account Model

class ACMEAccount(BaseModel):
    """ACME account for Let's Encrypt."""

    id: str = Field(
        default_factory=lambda: f"acme-{uuid.uuid4().hex[:12]}",
        description="Account identifier"
    )
    email: Optional[str] = Field(None, description="Account email")
    directory_url: str = Field(
        ...,
        description="ACME directory URL"
    )
    account_url: Optional[str] = Field(
        None,
        description="Registered account URL"
    )
    private_key_pem: str = Field(
        ...,
        description="Account private key (PEM format)"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Account creation time"
    )
    terms_accepted: bool = Field(
        default=True,
        description="Whether terms of service were accepted"
    )
