"""
Dashboard-specific FastAPI dependencies.

Handles cookie-based JWT auth for the dashboard and
HTMX request detection.
"""

import logging

from fastapi import Request, Response
from starlette.responses import RedirectResponse

from config import settings
from models.auth import AuthContext, Role

logger = logging.getLogger(__name__)

COOKIE_NAME = "dashboard_token"
COOKIE_MAX_AGE = 3600  # 1 hour, matches default JWT expiry


async def get_dashboard_auth(request: Request) -> AuthContext | None:
    """
    Resolve auth context from dashboard cookie.

    When AUTH_ENABLED=false, returns permissive admin context.
    When AUTH_ENABLED=true, extracts JWT from cookie and validates.
    Returns None if auth is required but not present/valid.
    """
    client_ip = request.client.host if request.client else None

    if not settings.auth_enabled:
        return AuthContext(
            role=Role.ADMIN,
            auth_method="none",
            client_ip=client_ip,
        )

    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None

    from core.auth_service import get_auth_service

    auth_service = get_auth_service()
    auth_ctx = auth_service.validate_jwt_token(token)

    if auth_ctx is None:
        return None

    # Reject challenge tokens
    payload = auth_service.decode_token_payload(token)
    if payload and payload.get("purpose") == "2fa_challenge":
        return None

    # Check session revocation
    if payload and payload.get("jti"):
        from core.session_service import get_session_service

        session_service = get_session_service()
        if await session_service.is_session_revoked(payload["jti"]):
            return None

    auth_ctx.client_ip = client_ip
    return auth_ctx


async def require_dashboard_auth(request: Request) -> AuthContext | RedirectResponse:
    """
    Require authentication for dashboard pages.

    Returns AuthContext if authenticated, or redirects to login.
    """
    auth = await get_dashboard_auth(request)
    if auth is None:
        return RedirectResponse(url="/dashboard/login", status_code=302)
    return auth


def is_htmx(request: Request) -> bool:
    """Check if the request is an HTMX request."""
    return request.headers.get("HX-Request") == "true"


def set_auth_cookie(response: Response, token: str) -> None:
    """Set the JWT auth cookie on a response."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="strict",
        secure=not settings.api_debug,
    )


def clear_auth_cookie(response: Response) -> None:
    """Clear the JWT auth cookie."""
    response.delete_cookie(key=COOKIE_NAME, samesite="strict")
