"""
Authentication and authorization models.

Pydantic models for API key management, auth context,
and role-based access control.
"""

from enum import Enum
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import uuid


class Role(str, Enum):
    """User/API key role with hierarchical permissions."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

    def has_permission(self, required: "Role") -> bool:
        """Check if this role meets or exceeds the required role."""
        hierarchy = {Role.ADMIN: 3, Role.OPERATOR: 2, Role.VIEWER: 1}
        return hierarchy.get(self, 0) >= hierarchy.get(required, 0)


class AuthContext(BaseModel):
    """Context for the authenticated request."""
    api_key_id: Optional[str] = None
    user_id: Optional[str] = None
    role: Role = Role.VIEWER
    auth_method: str = "none"  # "api_key", "jwt", "master_key", "none"
    client_ip: Optional[str] = None


class APIKey(BaseModel):
    """API key record (never includes the plaintext key or hash)."""
    id: str = Field(default_factory=lambda: f"key-{uuid.uuid4().hex[:12]}")
    name: str
    description: Optional[str] = None
    role: Role = Role.OPERATOR
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True
    rate_limit_override: Optional[int] = None
    created_by: Optional[str] = None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class APIKeyCreateRequest(BaseModel):
    """Request to create a new API key."""
    name: str = Field(..., min_length=1, max_length=100, description="Human-readable name for this key")
    description: Optional[str] = Field(None, max_length=500)
    role: Role = Field(default=Role.OPERATOR, description="Role for this key")
    expires_at: Optional[datetime] = Field(None, description="Optional expiration time")
    rate_limit_override: Optional[int] = Field(
        None, ge=1, le=10000,
        description="Override default rate limit (requests/minute)"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name cannot be empty")
        return v


class APIKeyCreateResponse(BaseModel):
    """Response after creating an API key. Contains the plaintext key (shown only once)."""
    key: APIKey
    plaintext_key: str = Field(
        ...,
        description="The API key value. Store this securely - it cannot be retrieved again."
    )
    message: str = "API key created successfully. Store the plaintext_key securely."
    suggestions: List[dict] = Field(default_factory=lambda: [
        {
            "action": "Store this key securely",
            "reason": "The plaintext key is only shown once and cannot be retrieved later",
            "priority": "critical"
        },
        {
            "action": "Use X-API-Key header for authentication",
            "reason": "Include the key in all API requests via the X-API-Key header",
            "priority": "high"
        }
    ])


class APIKeyListResponse(BaseModel):
    """Response for listing API keys."""
    keys: List[APIKey]
    total: int
    suggestions: List[dict] = Field(default_factory=list)


class TokenRequest(BaseModel):
    """Request to exchange an API key for a JWT token."""
    api_key: str = Field(..., description="The API key to exchange for a JWT token")


class TokenResponse(BaseModel):
    """Response containing a JWT token."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Token lifetime in seconds")
    role: Role = Field(..., description="Role encoded in the token")
    suggestions: List[dict] = Field(default_factory=lambda: [
        {
            "action": "Use Authorization: Bearer <token> header",
            "reason": "Include the JWT in subsequent requests for stateless auth",
            "priority": "high"
        }
    ])


class TokenRefreshResponse(BaseModel):
    """Response containing a refreshed JWT token."""
    access_token: str
    token_type: str = Field(default="bearer")
    expires_in: int


class BootstrapRequest(BaseModel):
    """Request to bootstrap the first admin API key."""
    name: str = Field(default="Initial Admin Key", description="Name for the bootstrap key")


class BootstrapResponse(BaseModel):
    """Response after bootstrapping."""
    key: APIKey
    plaintext_key: str
    message: str
    suggestions: List[dict] = Field(default_factory=list)


# --- User Management Models (Phase 5.2a) ---

class User(BaseModel):
    """User account record (never includes password hash)."""
    id: str = Field(default_factory=lambda: f"usr-{uuid.uuid4().hex[:12]}")
    username: str
    email: Optional[str] = None
    role: Role = Role.OPERATOR
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    password_changed_at: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None

    @property
    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until


class UserCreateRequest(BaseModel):
    """Request to create a new user account."""
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: Optional[str] = Field(None, max_length=255, description="Email address")
    password: str = Field(..., min_length=12, max_length=128, description="Password (min 12 chars, mixed case + digit)")
    role: Role = Field(default=Role.OPERATOR, description="Role for this user")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Username cannot be empty")
        import re
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError("Username may only contain letters, digits, underscores, dots, and hyphens")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        import re
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            raise ValueError("Invalid email address format")
        return v


class UserUpdateRequest(BaseModel):
    """Request to update a user account."""
    email: Optional[str] = Field(None, max_length=255)
    role: Optional[Role] = None
    is_active: Optional[bool] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        import re
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            raise ValueError("Invalid email address format")
        return v


class LoginRequest(BaseModel):
    """Request to authenticate with username and password."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class LoginResponse(BaseModel):
    """Response after successful login."""
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Token lifetime in seconds")
    role: Role
    user: User
    suggestions: List[dict] = Field(default_factory=lambda: [
        {
            "action": "Use Authorization: Bearer <token> header",
            "reason": "Include the JWT in subsequent requests for stateless auth",
            "priority": "high"
        }
    ])


class PasswordChangeRequest(BaseModel):
    """Request to change a user's password."""
    current_password: str = Field(..., description="Current password for verification")
    new_password: str = Field(..., min_length=12, max_length=128, description="New password")

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserListResponse(BaseModel):
    """Response for listing users."""
    users: List[User]
    total: int
    suggestions: List[dict] = Field(default_factory=list)
