"""
User management endpoints.

User creation, authentication, listing, and password management.
"""

import logging

from fastapi import APIRouter, HTTPException, Depends

from core.auth_service import get_auth_service
from core.user_service import get_user_service, UserServiceError
from core.auth_dependency import get_current_auth, require_role
from models.auth import (
    Role,
    AuthContext,
    User,
    UserCreateRequest,
    UserUpdateRequest,
    UserListResponse,
    LoginRequest,
    LoginResponse,
    PasswordChangeRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login with Username and Password",
    description="""
    Authenticate with a username and password to receive a JWT token.

    Accounts are locked for 30 minutes after 5 consecutive failed attempts.
    """,
    responses={
        200: {"description": "Login successful, JWT token returned"},
        401: {"description": "Invalid credentials or account locked"},
        400: {"description": "JWT not configured"},
    }
)
async def login(request: LoginRequest):
    """Authenticate and receive a JWT token."""
    user_service = get_user_service()
    auth_ctx = await user_service.authenticate(request.username, request.password)

    if auth_ctx is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password, or account is locked.",
        )

    auth_service = get_auth_service()
    try:
        token, expires_in = auth_service.create_jwt_token(auth_ctx)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user = await user_service.get_user(auth_ctx.user_id)

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
    }
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
    }
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
        suggestions.append({
            "action": f"{len(locked)} user(s) are currently locked out",
            "reason": "Accounts lock after 5 failed login attempts for 30 minutes",
            "priority": "medium"
        })
    inactive = [u for u in users if not u.is_active]
    if inactive:
        suggestions.append({
            "action": f"{len(inactive)} user(s) are deactivated",
            "reason": "Deactivated users cannot log in",
            "priority": "low"
        })

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
    }
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
    }
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
    }
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
                admin_row = await user_service.db.fetch_one(
                    "SELECT * FROM users WHERE id = ?", (auth.user_id,)
                )
            if admin_row and not user_service._verify_password(
                request.current_password, admin_row["password_hash"]
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Your admin password is incorrect.",
                )
            success = await user_service.admin_reset_password(user_id, request.new_password)
        else:
            success = await user_service.change_password(
                user_id, request.current_password, request.new_password
            )
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
                "priority": "high"
            }
        ]
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
    }
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
                "priority": "medium"
            }
        ]
    }
