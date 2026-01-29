"""
Authentication management endpoints.

API key creation, listing, revocation, and bootstrap.
"""

import logging

from fastapi import APIRouter, Depends, Header, HTTPException

from config import settings
from core.auth_dependency import get_current_auth, require_role
from core.auth_service import get_auth_service
from models.auth import (
    APIKeyCreateRequest,
    APIKeyCreateResponse,
    APIKeyListResponse,
    AuthContext,
    BootstrapRequest,
    BootstrapResponse,
    Role,
    TokenRefreshResponse,
    TokenRequest,
    TokenResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/bootstrap",
    response_model=BootstrapResponse,
    summary="Bootstrap Initial Admin Key",
    description="""
    Create the first admin API key using the AUTH_MASTER_KEY.

    This endpoint only works when:
    1. No API keys exist yet in the database
    2. A valid X-Master-Key header is provided matching AUTH_MASTER_KEY

    Use this once during initial setup, then use the returned key for all subsequent operations.
    """,
    responses={
        200: {"description": "Admin key created"},
        400: {"description": "Keys already exist or master key not configured"},
        401: {"description": "Invalid master key"},
    },
)
async def bootstrap(
    request: BootstrapRequest = None,
    x_master_key: str = Header(None, alias="X-Master-Key"),
):
    """Create the initial admin API key."""
    if not settings.auth_master_key:
        raise HTTPException(
            status_code=400, detail="AUTH_MASTER_KEY is not configured. Set it in environment variables."
        )

    if not x_master_key or x_master_key != settings.auth_master_key:
        raise HTTPException(status_code=401, detail="Invalid master key.")

    auth_service = get_auth_service()
    if await auth_service.has_any_keys():
        raise HTTPException(
            status_code=400, detail="API keys already exist. Use an existing admin key to create new keys."
        )

    name = request.name if request else "Initial Admin Key"
    api_key, plaintext = await auth_service.create_api_key(
        name=name,
        role=Role.ADMIN,
        description="Bootstrap admin key created during initial setup",
        created_by="bootstrap",
    )

    return BootstrapResponse(
        key=api_key,
        plaintext_key=plaintext,
        message="Admin API key created. Store the plaintext_key securely — it cannot be retrieved again.",
        suggestions=[
            {
                "action": "Store the plaintext key securely",
                "reason": "This key grants full admin access and is shown only once",
                "priority": "critical",
            },
            {
                "action": "Set AUTH_ENABLED=true and restart the API",
                "reason": "Authentication is not enforced until AUTH_ENABLED=true",
                "priority": "high",
            },
        ],
    )


@router.post(
    "/keys",
    response_model=APIKeyCreateResponse,
    summary="Create API Key",
    description="Create a new API key. Requires admin role.",
    responses={
        200: {"description": "API key created"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def create_api_key(
    request: APIKeyCreateRequest,
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """Create a new API key (admin only)."""
    auth_service = get_auth_service()
    api_key, plaintext = await auth_service.create_api_key(
        name=request.name,
        role=request.role,
        description=request.description,
        expires_at=request.expires_at,
        rate_limit_override=request.rate_limit_override,
        created_by=auth.api_key_id or auth.user_id,
    )

    return APIKeyCreateResponse(
        key=api_key,
        plaintext_key=plaintext,
    )


@router.get(
    "/keys",
    response_model=APIKeyListResponse,
    summary="List API Keys",
    description="List all API keys (without plaintext values). Requires admin role.",
    responses={
        200: {"description": "List of API keys"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def list_api_keys(
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """List all API keys (admin only)."""
    auth_service = get_auth_service()
    keys = await auth_service.list_api_keys()

    suggestions = []
    expired = [k for k in keys if k.is_expired]
    if expired:
        suggestions.append(
            {
                "action": f"Clean up {len(expired)} expired key(s)",
                "reason": "Expired keys should be revoked for security",
                "priority": "medium",
            }
        )
    inactive = [k for k in keys if not k.is_active]
    if inactive:
        suggestions.append(
            {
                "action": f"{len(inactive)} key(s) are revoked",
                "reason": "Revoked keys remain in the list for audit purposes",
                "priority": "low",
            }
        )

    return APIKeyListResponse(
        keys=keys,
        total=len(keys),
        suggestions=suggestions,
    )


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Exchange API Key for JWT Token",
    description="""
    Exchange a valid API key for a short-lived JWT token.

    JWT tokens are stateless and faster to validate than API keys.
    They are ideal for sessions with multiple requests.
    """,
    responses={
        200: {"description": "JWT token issued"},
        401: {"description": "Invalid API key"},
        400: {"description": "JWT not configured"},
    },
)
async def create_token(request: TokenRequest):
    """Exchange an API key for a JWT token."""
    auth_service = get_auth_service()

    auth_ctx = await auth_service.validate_api_key(request.api_key)
    if auth_ctx is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key.",
        )

    try:
        token, expires_in = auth_service.create_jwt_token(auth_ctx)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        role=auth_ctx.role,
    )


@router.post(
    "/token/refresh",
    response_model=TokenRefreshResponse,
    summary="Refresh JWT Token",
    description="Exchange a valid (non-expired) JWT token for a fresh one.",
    responses={
        200: {"description": "New JWT token issued"},
        401: {"description": "Invalid or expired token"},
        400: {"description": "JWT not configured"},
    },
)
async def refresh_token(
    auth: AuthContext = Depends(get_current_auth),
):
    """Refresh an existing JWT token."""
    if auth.auth_method not in ("jwt", "api_key"):
        raise HTTPException(
            status_code=400,
            detail="Token refresh requires JWT or API key authentication.",
        )

    auth_service = get_auth_service()
    try:
        token, expires_in = auth_service.create_jwt_token(auth)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return TokenRefreshResponse(
        access_token=token,
        expires_in=expires_in,
    )


@router.delete(
    "/keys/{key_id}",
    summary="Revoke API Key",
    description="Revoke (deactivate) an API key. Requires admin role.",
    responses={
        200: {"description": "Key revoked"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Key not found"},
    },
)
async def revoke_api_key(
    key_id: str,
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """Revoke an API key (admin only)."""
    auth_service = get_auth_service()

    existing = await auth_service.get_api_key(key_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found")

    # Prevent revoking your own key
    if auth.api_key_id == key_id:
        raise HTTPException(status_code=400, detail="Cannot revoke the key you are currently using.")

    await auth_service.revoke_api_key(key_id)

    return {
        "success": True,
        "message": f"API key '{existing.name}' revoked",
        "key_id": key_id,
        "suggestions": [
            {
                "action": "Rotate any systems using this key",
                "reason": "The revoked key will no longer authenticate",
                "priority": "high",
            }
        ],
    }
