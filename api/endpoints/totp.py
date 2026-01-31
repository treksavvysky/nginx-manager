"""
TOTP two-factor authentication endpoints.

Enrollment, confirmation, status, and backup code management.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from core.auth_dependency import get_current_auth, require_role
from core.totp_service import TOTPServiceError, get_totp_service
from core.user_service import get_user_service
from models.auth import (
    AuthContext,
    Role,
    TOTPConfirmRequest,
    TOTPDisableRequest,
    TOTPEnrollResponse,
    TOTPStatusResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/2fa", tags=["Two-Factor Authentication"])


@router.post(
    "/enroll",
    response_model=TOTPEnrollResponse,
    summary="Enroll in 2FA",
    description="""
    Start TOTP two-factor authentication enrollment.

    Returns a QR code (as data URI) and backup codes. Scan the QR code
    with an authenticator app (Google Authenticator, Authy, etc.), then
    confirm enrollment by calling POST /auth/2fa/confirm with a valid code.

    Backup codes are one-time-use recovery codes — store them securely.
    """,
    responses={
        200: {"description": "Enrollment started, QR code and backup codes returned"},
        400: {"description": "Already enrolled or enrollment error"},
        401: {"description": "Not authenticated"},
    },
)
async def enroll(auth: AuthContext = Depends(require_role(Role.OPERATOR))):
    """Start TOTP enrollment for the current user."""
    if not auth.user_id:
        raise HTTPException(status_code=400, detail="2FA enrollment requires a user account (not API key auth).")

    user_service = get_user_service()
    user = await user_service.get_user(auth.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    totp_service = get_totp_service()
    try:
        result = await totp_service.enroll(auth.user_id, user.username)
    except TOTPServiceError as e:
        raise HTTPException(status_code=400, detail=e.message)

    return TOTPEnrollResponse(
        secret=result["secret"],
        qr_code_data_uri=result["qr_code_data_uri"],
        backup_codes=result["backup_codes"],
    )


@router.post(
    "/confirm",
    summary="Confirm 2FA Enrollment",
    description="""
    Confirm TOTP enrollment by providing a valid 6-digit code from your
    authenticator app. This activates 2FA for your account.
    """,
    responses={
        200: {"description": "2FA enrollment confirmed and activated"},
        400: {"description": "Invalid code or no pending enrollment"},
        401: {"description": "Not authenticated"},
    },
)
async def confirm(
    request: TOTPConfirmRequest,
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
):
    """Confirm TOTP enrollment with a verification code."""
    if not auth.user_id:
        raise HTTPException(status_code=400, detail="2FA confirmation requires a user account.")

    totp_service = get_totp_service()
    try:
        await totp_service.confirm(auth.user_id, request.totp_code)
    except TOTPServiceError as e:
        raise HTTPException(status_code=400, detail=e.message)

    return {
        "success": True,
        "message": "Two-factor authentication is now active.",
        "suggestions": [
            {
                "action": "Store your backup codes securely",
                "reason": "Backup codes are the only way to recover access if you lose your authenticator",
                "priority": "critical",
            },
        ],
    }


@router.post(
    "/disable",
    summary="Disable 2FA",
    description="Disable TOTP two-factor authentication. Requires password confirmation.",
    responses={
        200: {"description": "2FA disabled"},
        400: {"description": "Incorrect password or 2FA not enabled"},
        401: {"description": "Not authenticated"},
    },
)
async def disable(
    request: TOTPDisableRequest,
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
):
    """Disable TOTP 2FA for the current user."""
    if not auth.user_id:
        raise HTTPException(status_code=400, detail="2FA disable requires a user account.")

    # Verify password
    user_service = get_user_service()
    row = await user_service.db.fetch_one("SELECT password_hash, totp_enabled FROM users WHERE id = ?", (auth.user_id,))
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if not row["totp_enabled"]:
        raise HTTPException(status_code=400, detail="2FA is not enabled for this account.")
    if not user_service._verify_password(request.password, row["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect password.")

    totp_service = get_totp_service()
    await totp_service.disable(auth.user_id)

    return {
        "success": True,
        "message": "Two-factor authentication has been disabled.",
        "suggestions": [
            {
                "action": "Re-enable 2FA for better security",
                "reason": "Your account is less secure without two-factor authentication",
                "priority": "medium",
            },
        ],
    }


@router.get(
    "/status",
    response_model=TOTPStatusResponse,
    summary="2FA Status",
    description="Check the current two-factor authentication status for your account.",
    responses={
        200: {"description": "2FA status returned"},
        401: {"description": "Not authenticated"},
    },
)
async def status(auth: AuthContext = Depends(get_current_auth)):
    """Get 2FA status for the current user."""
    if not auth.user_id:
        return TOTPStatusResponse(enabled=False, enforcement="n/a", backup_codes_remaining=0)

    totp_service = get_totp_service()
    try:
        result = await totp_service.get_status(auth.user_id)
    except TOTPServiceError:
        return TOTPStatusResponse(enabled=False, enforcement="n/a", backup_codes_remaining=0)

    return TOTPStatusResponse(**result)


@router.post(
    "/backup-codes/regenerate",
    summary="Regenerate Backup Codes",
    description="""
    Generate a new set of backup codes. The old codes are invalidated.
    Requires a valid TOTP code for confirmation.
    """,
    responses={
        200: {"description": "New backup codes generated"},
        400: {"description": "2FA not enabled or invalid TOTP code"},
        401: {"description": "Not authenticated"},
    },
)
async def regenerate_backup_codes(
    request: TOTPConfirmRequest,
    auth: AuthContext = Depends(require_role(Role.OPERATOR)),
):
    """Regenerate backup codes (requires TOTP verification)."""
    if not auth.user_id:
        raise HTTPException(status_code=400, detail="Requires a user account.")

    # Verify TOTP code first
    totp_service = get_totp_service()
    verified = await totp_service.verify_totp(auth.user_id, request.totp_code)
    if not verified:
        raise HTTPException(status_code=400, detail="Invalid TOTP code.")

    try:
        codes = await totp_service.regenerate_backup_codes(auth.user_id)
    except TOTPServiceError as e:
        raise HTTPException(status_code=400, detail=e.message)

    return {
        "success": True,
        "backup_codes": codes,
        "message": "New backup codes generated. Old codes are now invalid.",
        "suggestions": [
            {
                "action": "Store these codes securely",
                "reason": "These codes are shown only once and cannot be retrieved later",
                "priority": "critical",
            },
        ],
    }
