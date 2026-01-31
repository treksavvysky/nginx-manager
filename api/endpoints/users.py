"""
User management endpoints.

User creation, authentication, listing, and password management.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException

from core.auth_dependency import get_current_auth, require_role
from core.auth_service import get_auth_service
from core.user_service import UserServiceError, get_user_service
from models.auth import (
    AuthContext,
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
    Role,
    TOTPVerifyRequest,
    User,
    UserCreateRequest,
    UserListResponse,
    UserUpdateRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login with Username and Password",
    description="""
    Authenticate with a username and password to receive a JWT token.

    If the user has 2FA enabled, this returns a short-lived challenge token
    instead of a session token. Use `POST /auth/verify-2fa` with the challenge
    token and a TOTP code to complete login.

    Accounts are locked for 30 minutes after 5 consecutive failed attempts.
    """,
    responses={
        200: {"description": "Login successful or 2FA challenge issued"},
        401: {"description": "Invalid credentials or account locked"},
        400: {"description": "JWT not configured"},
    },
)
async def login(request: LoginRequest):
    """Authenticate and receive a JWT token (or 2FA challenge)."""
    user_service = get_user_service()
    result = await user_service.authenticate(request.username, request.password)

    if result is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password, or account is locked.",
        )

    auth_ctx, totp_enabled = result
    auth_service = get_auth_service()
    user = await user_service.get_user(auth_ctx.user_id)

    if totp_enabled:
        # Issue a 2FA challenge token instead of a session token
        try:
            challenge_token, expires_in = auth_service.create_challenge_token(auth_ctx.user_id, auth_ctx.role)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        return LoginResponse(
            access_token=challenge_token,
            expires_in=expires_in,
            role=auth_ctx.role,
            user=user,
            requires_2fa=True,
            challenge_token=challenge_token,
            suggestions=[
                {
                    "action": "Complete login with POST /auth/verify-2fa",
                    "reason": "This account requires two-factor authentication",
                    "priority": "high",
                }
            ],
        )

    # No 2FA — issue session token directly
    try:
        token, expires_in = auth_service.create_jwt_token(auth_ctx)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Track session if jti present
    payload = auth_service.decode_token_payload(token)
    if payload and payload.get("jti"):
        from datetime import datetime, timedelta

        from core.session_service import get_session_service

        session_service = get_session_service()
        await session_service.create_session(
            jti=payload["jti"],
            user_id=auth_ctx.user_id,
            expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        )

    # Check 2FA enforcement (soft warning)
    from config import settings as app_settings

    totp_setup_required = False
    suggestions = [
        {
            "action": "Use Authorization: Bearer <token> header",
            "reason": "Include the JWT in subsequent requests for stateless auth",
            "priority": "high",
        }
    ]
    if auth_ctx.role == Role.ADMIN and app_settings.totp_enforce_admin:
        totp_setup_required = True
        suggestions.append(
            {
                "action": "Enable two-factor authentication",
                "reason": "2FA is recommended for admin accounts. Use POST /auth/2fa/enroll",
                "priority": "high",
            }
        )
    elif auth_ctx.role == Role.OPERATOR and app_settings.totp_enforce_operator:
        totp_setup_required = True
        suggestions.append(
            {
                "action": "Enable two-factor authentication",
                "reason": "2FA is recommended for operator accounts. Use POST /auth/2fa/enroll",
                "priority": "medium",
            }
        )

    return LoginResponse(
        access_token=token,
        expires_in=expires_in,
        role=auth_ctx.role,
        user=user,
        totp_setup_required=totp_setup_required,
        suggestions=suggestions,
    )


@router.post(
    "/verify-2fa",
    response_model=LoginResponse,
    summary="Complete 2FA Login",
    description="""
    Complete login by verifying a TOTP code after receiving a 2FA challenge.

    Provide the challenge_token from the login response and a valid 6-digit
    TOTP code from your authenticator app (or an 8-character backup code).
    """,
    responses={
        200: {"description": "2FA verified, session token returned"},
        401: {"description": "Invalid or expired challenge token, or invalid TOTP code"},
    },
)
async def verify_2fa(request: TOTPVerifyRequest):
    """Complete 2FA login with a challenge token and TOTP code."""
    auth_service = get_auth_service()
    payload = auth_service.decode_token_payload(request.challenge_token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired challenge token.")

    if payload.get("purpose") != "2fa_challenge":
        raise HTTPException(status_code=401, detail="Invalid token type. Expected a 2FA challenge token.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid challenge token.")

    # Verify TOTP code
    from core.totp_service import get_totp_service

    totp_service = get_totp_service()
    verified = await totp_service.verify_totp(user_id, request.totp_code)
    if not verified:
        raise HTTPException(status_code=401, detail="Invalid TOTP code or backup code.")

    # Issue full session token
    from models.auth import Role

    auth_ctx = AuthContext(
        user_id=user_id,
        role=Role(payload["role"]),
        auth_method="user",
    )

    try:
        token, expires_in = auth_service.create_jwt_token(auth_ctx, purpose="session")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Track session
    session_payload = auth_service.decode_token_payload(token)
    if session_payload and session_payload.get("jti"):
        from datetime import datetime, timedelta

        from core.session_service import get_session_service

        session_service = get_session_service()
        await session_service.create_session(
            jti=session_payload["jti"],
            user_id=user_id,
            expires_at=datetime.utcnow() + timedelta(seconds=expires_in),
        )

    user_service = get_user_service()
    user = await user_service.get_user(user_id)

    return LoginResponse(
        access_token=token,
        expires_in=expires_in,
        role=auth_ctx.role,
        user=user,
    )


@router.post(
    "/users",
    response_model=User,
    summary="Create User",
    description="""
    Create a new user account. Requires admin role.

    Password requirements: minimum 12 characters, at least one uppercase letter,
    one lowercase letter, and one digit.
    """,
    responses={
        200: {"description": "User created"},
        400: {"description": "Validation error or username taken"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def create_user(
    request: UserCreateRequest,
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """Create a new user account (admin only)."""
    user_service = get_user_service()
    try:
        user = await user_service.create_user(
            username=request.username,
            password=request.password,
            role=request.role,
            email=request.email,
        )
    except UserServiceError as e:
        raise HTTPException(status_code=400, detail=e.message)

    return user


@router.get(
    "/users",
    response_model=UserListResponse,
    summary="List Users",
    description="List all user accounts. Requires admin role.",
    responses={
        200: {"description": "List of users"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def list_users(
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """List all user accounts (admin only)."""
    user_service = get_user_service()
    users = await user_service.list_users()

    suggestions = []
    locked = [u for u in users if u.is_locked]
    if locked:
        suggestions.append(
            {
                "action": f"{len(locked)} user(s) are currently locked out",
                "reason": "Accounts lock after 5 failed login attempts for 30 minutes",
                "priority": "medium",
            }
        )
    inactive = [u for u in users if not u.is_active]
    if inactive:
        suggestions.append(
            {
                "action": f"{len(inactive)} user(s) are deactivated",
                "reason": "Deactivated users cannot log in",
                "priority": "low",
            }
        )

    return UserListResponse(
        users=users,
        total=len(users),
        suggestions=suggestions,
    )


@router.get(
    "/users/{user_id}",
    response_model=User,
    summary="Get User",
    description="Get a specific user account. Admins can view any user; others can only view themselves.",
    responses={
        200: {"description": "User details"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def get_user(
    user_id: str,
    auth: AuthContext = Depends(get_current_auth),
):
    """Get a user by ID (admin or self)."""
    # Allow users to view their own profile
    if auth.user_id != user_id and not auth.role.has_permission(Role.ADMIN):
        raise HTTPException(
            status_code=403,
            detail="You can only view your own profile. Admin role required for other users.",
        )

    user_service = get_user_service()
    user = await user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")

    return user


@router.put(
    "/users/{user_id}",
    response_model=User,
    summary="Update User",
    description="Update a user account. Requires admin role.",
    responses={
        200: {"description": "User updated"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def update_user(
    user_id: str,
    request: UserUpdateRequest,
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """Update a user account (admin only)."""
    user_service = get_user_service()

    # Build kwargs — use sentinel to distinguish None from not-provided
    kwargs = {}
    if request.email is not None:
        kwargs["email"] = request.email
    else:
        kwargs["email"] = ...  # sentinel: skip
    kwargs["role"] = request.role
    kwargs["is_active"] = request.is_active

    user = await user_service.update_user(user_id, **kwargs)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")

    return user


@router.post(
    "/users/{user_id}/change-password",
    summary="Change Password",
    description="""
    Change a user's password. Users can change their own password by providing
    the current password. Admins can change any user's password.
    """,
    responses={
        200: {"description": "Password changed"},
        400: {"description": "Current password incorrect"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def change_password(
    user_id: str,
    request: PasswordChangeRequest,
    auth: AuthContext = Depends(get_current_auth),
):
    """Change a user's password (admin or self)."""
    is_self = auth.user_id == user_id
    is_admin = auth.role.has_permission(Role.ADMIN)

    if not is_self and not is_admin:
        raise HTTPException(
            status_code=403,
            detail="You can only change your own password. Admin role required for other users.",
        )

    user_service = get_user_service()

    try:
        if is_admin and not is_self:
            # Admin resetting another user's password — verify admin's password
            # as the "current_password" for safety
            admin_row = None
            if auth.user_id:
                admin_row = await user_service.db.fetch_one("SELECT * FROM users WHERE id = ?", (auth.user_id,))
            if admin_row and not user_service._verify_password(request.current_password, admin_row["password_hash"]):
                raise HTTPException(
                    status_code=400,
                    detail="Your admin password is incorrect.",
                )
            success = await user_service.admin_reset_password(user_id, request.new_password)
        else:
            success = await user_service.change_password(user_id, request.current_password, request.new_password)
    except UserServiceError as e:
        raise HTTPException(status_code=404, detail=e.message)

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect.",
        )

    return {
        "success": True,
        "message": "Password changed successfully",
        "suggestions": [
            {
                "action": "Use the new password for future logins",
                "reason": "The old password is no longer valid",
                "priority": "high",
            }
        ],
    }


@router.delete(
    "/users/{user_id}",
    summary="Delete User",
    description="Delete a user account. Requires admin role. Cannot delete yourself.",
    responses={
        200: {"description": "User deleted"},
        400: {"description": "Cannot delete self"},
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "User not found"},
    },
)
async def delete_user(
    user_id: str,
    auth: AuthContext = Depends(require_role(Role.ADMIN)),
):
    """Delete a user account (admin only)."""
    if auth.user_id == user_id:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account.",
        )

    user_service = get_user_service()
    user = await user_service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{user_id}' not found")

    await user_service.delete_user(user_id)

    return {
        "success": True,
        "message": f"User '{user.username}' deleted",
        "user_id": user_id,
        "suggestions": [
            {
                "action": "Revoke any JWT tokens issued to this user",
                "reason": "Existing tokens remain valid until expiry",
                "priority": "medium",
            }
        ],
    }
