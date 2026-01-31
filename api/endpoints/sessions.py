"""
Session management endpoints.

List active sessions, revoke specific sessions, or revoke all sessions.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request

from core.auth_dependency import get_current_auth
from core.session_service import get_session_service
from models.auth import AuthContext, SessionInfo, SessionListResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sessions", tags=["Session Management"])


def _get_current_jti(request: Request) -> str | None:
    """Extract jti from the current request's Bearer token."""
    from core.auth_service import get_auth_service

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ", 1)[1]
    auth_service = get_auth_service()
    payload = auth_service.decode_token_payload(token)
    return payload.get("jti") if payload else None


@router.get(
    "",
    response_model=SessionListResponse,
    summary="List Active Sessions",
    description="List all active (non-expired, non-revoked) sessions for the current user.",
    responses={
        200: {"description": "List of active sessions"},
        401: {"description": "Not authenticated"},
    },
)
async def list_sessions(
    request: Request,
    auth: AuthContext = Depends(get_current_auth),
):
    """List active sessions for the current user."""
    if not auth.user_id:
        return SessionListResponse(sessions=[], total=0)

    session_service = get_session_service()
    rows = await session_service.list_user_sessions(auth.user_id)
    current_jti = _get_current_jti(request)

    sessions = [
        SessionInfo(
            id=row["id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            ip_address=row.get("ip_address"),
            user_agent=row.get("user_agent"),
            is_current=(row["id"] == current_jti if current_jti else False),
        )
        for row in rows
    ]

    return SessionListResponse(sessions=sessions, total=len(sessions))


@router.delete(
    "/{session_id}",
    summary="Revoke Session",
    description="Revoke a specific session. You can only revoke your own sessions unless you are an admin.",
    responses={
        200: {"description": "Session revoked"},
        401: {"description": "Not authenticated"},
        403: {"description": "Cannot revoke another user's session"},
        404: {"description": "Session not found"},
    },
)
async def revoke_session(
    session_id: str,
    auth: AuthContext = Depends(get_current_auth),
):
    """Revoke a specific session."""
    from models.auth import Role

    session_service = get_session_service()
    session = await session_service.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Ownership check
    if session["user_id"] != auth.user_id and not auth.role.has_permission(Role.ADMIN):
        raise HTTPException(status_code=403, detail="You can only revoke your own sessions.")

    await session_service.revoke_session(session_id)

    return {
        "success": True,
        "message": f"Session {session_id} revoked",
    }


@router.delete(
    "",
    summary="Revoke All Sessions",
    description="Revoke all sessions for the current user except the current one.",
    responses={
        200: {"description": "All other sessions revoked"},
        401: {"description": "Not authenticated"},
    },
)
async def revoke_all_sessions(
    request: Request,
    auth: AuthContext = Depends(get_current_auth),
):
    """Revoke all sessions except the current one."""
    if not auth.user_id:
        return {"success": True, "revoked_count": 0, "message": "No sessions to revoke"}

    current_jti = _get_current_jti(request)
    session_service = get_session_service()
    count = await session_service.revoke_all_user_sessions(auth.user_id, except_jti=current_jti)

    return {
        "success": True,
        "revoked_count": count,
        "message": f"Revoked {count} session(s). Current session preserved.",
    }
