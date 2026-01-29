"""
FastAPI authentication dependencies.

Provides Depends() functions for injecting authentication
context into endpoint handlers. Supports both JWT Bearer tokens
and API key authentication.
"""

import logging
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.security import APIKeyHeader

from config import settings
from models.auth import AuthContext, Role

logger = logging.getLogger(__name__)

# Header extractor (optional — doesn't raise if missing)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _extract_bearer_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


async def get_current_auth(
    request: Request,
    api_key: str | None = Depends(_api_key_header),
) -> AuthContext:
    """
    Resolve the current authentication context.

    When AUTH_ENABLED=false (default), returns a permissive admin context.
    When AUTH_ENABLED=true, checks Authorization: Bearer first, then X-API-Key.
    """
    client_ip = request.client.host if request.client else None

    if not settings.auth_enabled:
        return AuthContext(
            role=Role.ADMIN,
            auth_method="none",
            client_ip=client_ip,
        )

    from core.auth_service import get_auth_service

    auth_service = get_auth_service()

    # 1. Check for JWT Bearer token
    bearer_token = _extract_bearer_token(request)
    if bearer_token:
        auth_ctx = auth_service.validate_jwt_token(bearer_token)
        if auth_ctx is not None:
            auth_ctx.client_ip = client_ip
            return auth_ctx
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired JWT token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Check for API key
    if api_key:
        auth_ctx = await auth_service.validate_api_key(api_key)
        if auth_ctx is not None:
            auth_ctx.client_ip = client_ip
            return auth_ctx
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # No credentials provided
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide a JWT token via Authorization: Bearer header or an API key via X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer, ApiKey"},
    )


def require_role(min_role: Role) -> Callable:
    """
    Return a dependency that enforces a minimum role.

    Usage:
        @router.get("/", dependencies=[Depends(require_role(Role.VIEWER))])
        async def list_items(...):
    """

    async def _check_role(
        auth: AuthContext = Depends(get_current_auth),
    ) -> AuthContext:
        if not auth.role.has_permission(min_role):
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required role: {min_role.value}, your role: {auth.role.value}",
            )
        return auth

    return _check_role
