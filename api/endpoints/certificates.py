"""
Certificate management endpoints.

REST API endpoints for managing SSL certificates including
Let's Encrypt automation and custom certificate uploads.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional, Union
import logging

from core.auth_dependency import get_current_auth, require_role
from models.auth import AuthContext, Role
from core.cert_manager import (
    get_cert_manager,
    CertManager,
    CertificateError,
    CertificateNotFoundError,
    CertificateValidationError,
    DNSError
)
from core.transaction_context import transactional_operation
from core.context_helpers import (
    get_cert_request_suggestions,
    get_cert_expiry_warnings,
    get_cert_renewal_suggestions,
)
from core.docker_service import docker_service
from models.certificate import (
    Certificate,
    CertificateStatus,
    CertificateType,
    CertificateRequestCreate,
    CertificateUploadRequest,
    CertificateRenewRequest,
    CertificateResponse,
    CertificateMutationResponse,
    CertificateDryRunResult,
    CertificateListResponse,
    SSLDiagnosticResult,
)
from models.transaction import OperationType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/certificates", tags=["SSL Certificates"])


@router.get(
    "/",
    response_model=CertificateListResponse,
    summary="List All SSL Certificates",
    description="""
    List all SSL certificates managed by the system.

    Returns certificates with their current status, expiry information,
    and suggestions for any certificates needing attention.

    **Filter Options:**
    - `status`: Filter by certificate status (valid, expired, expiring_soon, etc.)

    **Rich Context:**
    - Count of valid, expiring, and expired certificates
    - Suggestions for certificates needing renewal
    """,
    responses={
        200: {
            "description": "List of certificates",
            "content": {
                "application/json": {
                    "example": {
                        "certificates": [
                            {
                                "id": "cert-abc123",
                                "domain": "example.com",
                                "status": "valid",
                                "days_until_expiry": 45
                            }
                        ],
                        "total": 1,
                        "valid_count": 1,
                        "expiring_soon_count": 0,
                        "expired_count": 0
                    }
                }
            }
        }
    }
)
async def list_certificates(
    status: Optional[CertificateStatus] = Query(
        None,
        description="Filter by certificate status"
    ),
    auth: AuthContext = Depends(require_role(Role.VIEWER)),
) -> CertificateListResponse:
    """
    List all SSL certificates with status summaries.
    """
    try:
        cert_manager = get_cert_manager()
        certs = await cert_manager.list_certificates(status=status)

        # Build response with counts
        responses = []
        valid_count = 0
        expiring_soon_count = 0
        expired_count = 0

        for cert in certs:
            # Generate warnings for this certificate
            warnings = get_cert_expiry_warnings(cert)

            response = CertificateResponse.from_certificate(
                cert,
                warnings=warnings
            )
            responses.append(response)

            # Count by status
            if cert.status == CertificateStatus.VALID:
                valid_count += 1
            elif cert.status == CertificateStatus.EXPIRING_SOON:
                expiring_soon_count += 1
            elif cert.status == CertificateStatus.EXPIRED:
                expired_count += 1

        # Global suggestions
        suggestions = []
        if expiring_soon_count > 0:
            suggestions.append({
                "action": f"Renew {expiring_soon_count} certificate(s) expiring soon",
                "reason": "Certificates should be renewed before they expire",
                "endpoint": "POST /certificates/{domain}/renew",
                "priority": "high"
            })
        if expired_count > 0:
            suggestions.append({
                "action": f"Address {expired_count} expired certificate(s)",
                "reason": "Expired certificates will cause browser warnings",
                "priority": "critical"
            })

        return CertificateListResponse(
            certificates=responses,
            total=len(responses),
            valid_count=valid_count,
            expiring_soon_count=expiring_soon_count,
            expired_count=expired_count,
            suggestions=suggestions
        )

    except Exception as e:
        logger.error(f"Error listing certificates: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list certificates: {str(e)}"
        )


@router.get(
    "/{domain}",
    response_model=CertificateResponse,
    summary="Get Certificate Details",
    description="""
    Get detailed information about a specific SSL certificate.

    Returns full certificate details including:
    - Issuer and validity period
    - Days until expiry
    - File paths
    - Renewal status

    **Rich Context:**
    - Warnings if certificate is expiring soon
    - Suggestions for next actions
    """,
    responses={
        200: {"description": "Certificate details"},
        404: {"description": "Certificate not found"}
    }
)
async def get_certificate(domain: str, auth: AuthContext = Depends(require_role(Role.VIEWER))) -> CertificateResponse:
    """
    Get details for a specific certificate.
    """
    try:
        cert_manager = get_cert_manager()
        cert = await cert_manager.get_certificate(domain)

        if not cert:
            raise HTTPException(
                status_code=404,
                detail=f"Certificate not found for domain: {domain}"
            )

        # Generate context
        warnings = get_cert_expiry_warnings(cert)
        suggestions = []

        if cert.status == CertificateStatus.EXPIRING_SOON:
            suggestions.append({
                "action": "Renew certificate",
                "reason": f"Certificate expires in {cert.days_until_expiry} days",
                "endpoint": f"POST /certificates/{domain}/renew",
                "priority": "high"
            })
        elif cert.status == CertificateStatus.EXPIRED:
            suggestions.append({
                "action": "Request new certificate",
                "reason": "Certificate has expired",
                "endpoint": "POST /certificates/",
                "priority": "critical"
            })

        return CertificateResponse.from_certificate(
            cert,
            suggestions=suggestions,
            warnings=warnings
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting certificate for {domain}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get certificate: {str(e)}"
        )


@router.post(
    "/",
    response_model=Union[CertificateMutationResponse, CertificateDryRunResult],
    status_code=201,
    summary="Request SSL Certificate",
    description="""
    Request a new SSL certificate from Let's Encrypt.

    **Prerequisites:**
    - Domain must resolve to this server's IP address
    - Port 80 must be accessible for HTTP-01 challenge
    - A site configuration for the domain should exist (optional but recommended)

    **Dry Run Mode:**
    Add `?dry_run=true` to validate prerequisites without requesting certificate.
    This checks DNS resolution and port accessibility.

    **Process:**
    1. Validates domain DNS and connectivity
    2. Creates ACME order with Let's Encrypt
    3. Sets up HTTP-01 challenge file
    4. Validates domain ownership
    5. Downloads and installs certificate

    **Transaction Support:**
    Creates a transaction for audit trail. Certificate requests cannot be
    rolled back (revocation is separate).
    """,
    responses={
        201: {"description": "Certificate requested successfully"},
        400: {"description": "Invalid request or domain validation failed"},
        409: {"description": "Certificate already exists for domain"},
        500: {"description": "Certificate request failed"}
    }
)
async def request_certificate(
    request: CertificateRequestCreate,
    dry_run: bool = Query(
        default=False,
        description="Validate prerequisites without requesting certificate"
    ),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[CertificateMutationResponse, CertificateDryRunResult]:
    """
    Request a new SSL certificate from Let's Encrypt.
    """
    cert_manager = get_cert_manager()

    # Check if certificate already exists
    existing = await cert_manager.get_certificate(request.domain)
    if existing and existing.status == CertificateStatus.VALID:
        if dry_run:
            return CertificateDryRunResult(
                would_succeed=False,
                operation="request_certificate",
                message=f"Certificate already exists for {request.domain}",
                domain_resolves=True,
                domain_points_to_server=True,
                port_80_accessible=True,
                nginx_config_valid=True,
                sites_affected=[],
                files_to_create=[],
                warnings=[{
                    "code": "certificate_exists",
                    "message": f"Valid certificate already exists for {request.domain}",
                    "suggestion": "Use renewal endpoint or delete existing certificate first"
                }]
            )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "certificate_exists",
                "message": f"Certificate already exists for {request.domain}",
                "suggestion": "Use POST /certificates/{domain}/renew to renew or DELETE to remove"
            }
        )

    if dry_run:
        try:
            result = await cert_manager.request_certificate(
                domain=request.domain,
                alt_names=request.alt_names,
                auto_renew=request.auto_renew,
                dry_run=True
            )
            return result
        except Exception as e:
            return CertificateDryRunResult(
                would_succeed=False,
                operation="request_certificate",
                message=str(e),
                domain_resolves=False,
                domain_points_to_server=False,
                port_80_accessible=False,
                nginx_config_valid=False,
                sites_affected=[],
                files_to_create=[],
                warnings=[{
                    "code": "validation_failed",
                    "message": str(e)
                }]
            )

    # Actual certificate request with transaction
    async with transactional_operation(
        operation=OperationType.SSL_INSTALL,
        resource_type="certificate",
        resource_id=request.domain,
        request_data={
            "domain": request.domain,
            "alt_names": request.alt_names,
            "auto_renew": request.auto_renew
        }
    ) as ctx:
        try:
            cert = await cert_manager.request_certificate(
                domain=request.domain,
                alt_names=request.alt_names,
                auto_renew=request.auto_renew
            )

            # Set transaction result
            ctx.set_result({
                "certificate_id": cert.id,
                "status": cert.status.value,
                "expires": cert.not_after.isoformat() if cert.not_after else None
            })
            ctx.set_nginx_validated(True)

            # Reload NGINX if requested
            reloaded = False
            if request.auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                    ctx.set_health_verified(True)
                except Exception as e:
                    logger.warning(f"Failed to reload NGINX: {e}")

            # Generate suggestions
            suggestions = get_cert_request_suggestions(
                domain=request.domain,
                reloaded=reloaded,
                sites_using_cert=[]  # TODO: detect sites
            )

            return CertificateMutationResponse(
                success=True,
                message=f"SSL certificate issued for {request.domain}",
                domain=request.domain,
                transaction_id=ctx.id,
                certificate=CertificateResponse.from_certificate(cert),
                reload_required=True,
                reloaded=reloaded,
                suggestions=suggestions,
                warnings=[]
            )

        except DNSError as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "dns_error",
                    "message": e.message,
                    "domain": e.domain,
                    "suggestion": e.suggestion
                }
            )
        except CertificateError as e:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "certificate_error",
                    "message": e.message,
                    "domain": e.domain,
                    "suggestion": e.suggestion
                }
            )


@router.post(
    "/upload",
    response_model=Union[CertificateMutationResponse, CertificateDryRunResult],
    status_code=201,
    summary="Upload Custom Certificate",
    description="""
    Upload and install a custom SSL certificate.

    Use this endpoint when you have a certificate from another CA
    or a self-signed certificate for development.

    **Required:**
    - PEM-encoded certificate
    - PEM-encoded private key

    **Optional:**
    - Certificate chain (intermediate certificates)

    **Validation:**
    - Certificate format validation
    - Private key matching verification
    - Expiry date check

    **Dry Run Mode:**
    Add `?dry_run=true` to validate without installing.
    """,
    responses={
        201: {"description": "Certificate uploaded successfully"},
        400: {"description": "Invalid certificate or key format"},
        500: {"description": "Upload failed"}
    }
)
async def upload_certificate(
    request: CertificateUploadRequest,
    dry_run: bool = Query(
        default=False,
        description="Validate certificate without installing"
    ),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[CertificateMutationResponse, CertificateDryRunResult]:
    """
    Upload and install a custom SSL certificate.
    """
    cert_manager = get_cert_manager()

    if dry_run:
        try:
            result = await cert_manager.upload_custom_certificate(
                domain=request.domain,
                cert_pem=request.certificate_pem,
                key_pem=request.private_key_pem,
                chain_pem=request.chain_pem,
                dry_run=True
            )
            return result
        except CertificateValidationError as e:
            return CertificateDryRunResult(
                would_succeed=False,
                operation="upload_certificate",
                message=e.message,
                domain_resolves=True,
                domain_points_to_server=True,
                port_80_accessible=True,
                nginx_config_valid=False,
                sites_affected=[],
                files_to_create=[],
                warnings=[{
                    "code": "validation_failed",
                    "message": e.message,
                    "suggestion": e.suggestion
                }]
            )

    # Actual upload with transaction
    async with transactional_operation(
        operation=OperationType.SSL_INSTALL,
        resource_type="certificate",
        resource_id=request.domain,
        request_data={"domain": request.domain, "type": "custom"}
    ) as ctx:
        try:
            cert = await cert_manager.upload_custom_certificate(
                domain=request.domain,
                cert_pem=request.certificate_pem,
                key_pem=request.private_key_pem,
                chain_pem=request.chain_pem
            )

            ctx.set_result({
                "certificate_id": cert.id,
                "status": cert.status.value,
                "expires": cert.not_after.isoformat() if cert.not_after else None
            })
            ctx.set_nginx_validated(True)

            # Reload if requested
            reloaded = False
            if request.auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                    ctx.set_health_verified(True)
                except Exception as e:
                    logger.warning(f"Failed to reload NGINX: {e}")

            return CertificateMutationResponse(
                success=True,
                message=f"Custom certificate installed for {request.domain}",
                domain=request.domain,
                transaction_id=ctx.id,
                certificate=CertificateResponse.from_certificate(cert),
                reload_required=True,
                reloaded=reloaded,
                suggestions=get_cert_request_suggestions(
                    domain=request.domain,
                    reloaded=reloaded,
                    sites_using_cert=[]
                ),
                warnings=[]
            )

        except CertificateValidationError as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "validation_error",
                    "message": e.message,
                    "suggestion": e.suggestion
                }
            )


@router.post(
    "/{domain}/renew",
    response_model=Union[CertificateMutationResponse, CertificateDryRunResult],
    summary="Renew Certificate",
    description="""
    Manually trigger certificate renewal.

    By default, only renews if the certificate expires within 30 days.
    Use `?force=true` to renew regardless of expiry date.

    **Note:** Custom certificates cannot be auto-renewed. Upload a new
    certificate when needed.

    **Dry Run Mode:**
    Add `?dry_run=true` to check if renewal is needed without renewing.
    """,
    responses={
        200: {"description": "Certificate renewed successfully"},
        400: {"description": "Cannot renew (custom cert or not expiring)"},
        404: {"description": "Certificate not found"},
        500: {"description": "Renewal failed"}
    }
)
async def renew_certificate(
    domain: str,
    force: bool = Query(
        default=False,
        description="Force renewal even if not expiring soon"
    ),
    auto_reload: bool = Query(
        default=False,
        description="Automatically reload NGINX after renewal"
    ),
    dry_run: bool = Query(
        default=False,
        description="Check if renewal needed without renewing"
    ),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[CertificateMutationResponse, CertificateDryRunResult]:
    """
    Renew an existing certificate.
    """
    cert_manager = get_cert_manager()

    # Check certificate exists
    cert = await cert_manager.get_certificate(domain)
    if not cert:
        raise HTTPException(
            status_code=404,
            detail=f"Certificate not found for domain: {domain}"
        )

    if dry_run:
        result = await cert_manager.renew_certificate(
            domain=domain,
            force=force,
            dry_run=True
        )
        return result

    # Actual renewal with transaction
    async with transactional_operation(
        operation=OperationType.SSL_RENEW,
        resource_type="certificate",
        resource_id=domain,
        request_data={"domain": domain, "force": force}
    ) as ctx:
        try:
            renewed_cert = await cert_manager.renew_certificate(
                domain=domain,
                force=force
            )

            ctx.set_result({
                "certificate_id": renewed_cert.id,
                "status": renewed_cert.status.value,
                "expires": renewed_cert.not_after.isoformat() if renewed_cert.not_after else None
            })
            ctx.set_nginx_validated(True)

            # Reload if requested
            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                    ctx.set_health_verified(True)
                except Exception as e:
                    logger.warning(f"Failed to reload NGINX: {e}")

            return CertificateMutationResponse(
                success=True,
                message=f"Certificate renewed for {domain}",
                domain=domain,
                transaction_id=ctx.id,
                certificate=CertificateResponse.from_certificate(renewed_cert),
                reload_required=True,
                reloaded=reloaded,
                suggestions=get_cert_renewal_suggestions(domain),
                warnings=[]
            )

        except CertificateError as e:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "renewal_error",
                    "message": e.message,
                    "suggestion": e.suggestion
                }
            )


@router.delete(
    "/{domain}",
    response_model=Union[CertificateMutationResponse, CertificateDryRunResult],
    summary="Revoke and Remove Certificate",
    description="""
    Revoke and remove an SSL certificate.

    **Warning:** This will:
    - Revoke the certificate with the issuing CA (Let's Encrypt)
    - Remove certificate files from disk
    - Sites using this certificate will need to be updated

    **Dry Run Mode:**
    Add `?dry_run=true` to see what would happen without revoking.
    """,
    responses={
        200: {"description": "Certificate revoked successfully"},
        404: {"description": "Certificate not found"},
        500: {"description": "Revocation failed"}
    }
)
async def revoke_certificate(
    domain: str,
    auto_reload: bool = Query(
        default=False,
        description="Automatically reload NGINX after revocation"
    ),
    dry_run: bool = Query(
        default=False,
        description="Preview revocation without actually revoking"
    ),
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
) -> Union[CertificateMutationResponse, CertificateDryRunResult]:
    """
    Revoke and remove a certificate.
    """
    cert_manager = get_cert_manager()

    # Check certificate exists
    cert = await cert_manager.get_certificate(domain)
    if not cert:
        raise HTTPException(
            status_code=404,
            detail=f"Certificate not found for domain: {domain}"
        )

    if dry_run:
        result = await cert_manager.revoke_certificate(
            domain=domain,
            dry_run=True
        )
        return result

    # Actual revocation with transaction
    async with transactional_operation(
        operation=OperationType.SSL_REMOVE,
        resource_type="certificate",
        resource_id=domain,
        request_data={"domain": domain}
    ) as ctx:
        try:
            await cert_manager.revoke_certificate(domain=domain)

            ctx.set_result({"domain": domain, "status": "revoked"})
            ctx.set_nginx_validated(True)

            # Reload if requested
            reloaded = False
            if auto_reload:
                try:
                    await docker_service.reload_nginx()
                    reloaded = True
                    ctx.set_health_verified(True)
                except Exception as e:
                    logger.warning(f"Failed to reload NGINX: {e}")

            return CertificateMutationResponse(
                success=True,
                message=f"Certificate revoked for {domain}",
                domain=domain,
                transaction_id=ctx.id,
                certificate=None,
                reload_required=True,
                reloaded=reloaded,
                suggestions=[{
                    "action": "Update site configuration",
                    "reason": "Remove SSL directives or request new certificate",
                    "priority": "high"
                }],
                warnings=[{
                    "code": "ssl_removed",
                    "message": "Sites using this certificate may show errors",
                    "suggestion": "Update NGINX configuration to remove SSL or add new certificate"
                }]
            )

        except CertificateError as e:
            raise HTTPException(
                status_code=500,
                detail={
                    "error": "revocation_error",
                    "message": e.message,
                    "suggestion": e.suggestion
                }
            )


@router.get(
    "/{domain}/check",
    response_model=SSLDiagnosticResult,
    summary="SSL Diagnostic Check",
    description="""
    Perform comprehensive SSL diagnostic for a domain.

    **Checks:**
    - DNS resolution
    - IP address mapping
    - Port 80 accessibility (for HTTP-01 challenge)
    - Port 443 accessibility (for HTTPS)
    - Current certificate status
    - Certificate chain validity

    **Use Case:**
    Run this before requesting a certificate to identify
    potential issues that could cause validation failures.
    """,
    responses={
        200: {"description": "Diagnostic results"}
    }
)
async def check_ssl(domain: str, auth: AuthContext = Depends(require_role(Role.VIEWER))) -> SSLDiagnosticResult:
    """
    Perform SSL diagnostic check for a domain.
    """
    cert_manager = get_cert_manager()
    return await cert_manager.diagnose_ssl(domain)
