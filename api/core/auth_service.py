"""
Authentication service for API key and JWT management.

Handles API key creation, validation, and lifecycle management.
Keys are stored as SHA-256 hashes in the database.
JWT tokens provide stateless session authentication.
"""

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta

import jwt

from config import settings
from core.database import get_database
from models.auth import APIKey, AuthContext, Role

logger = logging.getLogger(__name__)

# Key prefix for identification
KEY_PREFIX = "ngx_"
KEY_BYTES = 32  # 32 bytes = 64 hex chars


class AuthService:
    """API key authentication service."""

    def __init__(self):
        self.db = get_database()

    @staticmethod
    def _generate_key() -> str:
        """Generate a new random API key."""
        random_part = secrets.token_hex(KEY_BYTES)
        return f"{KEY_PREFIX}{random_part}"

    @staticmethod
    def _hash_key(plaintext_key: str) -> str:
        """Hash an API key using SHA-256."""
        return hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()

    async def create_api_key(
        self,
        name: str,
        role: Role = Role.OPERATOR,
        description: str | None = None,
        expires_at: datetime | None = None,
        rate_limit_override: int | None = None,
        created_by: str | None = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.

        Returns:
            Tuple of (APIKey model, plaintext key string)
        """
        plaintext_key = self._generate_key()
        key_hash = self._hash_key(plaintext_key)

        api_key = APIKey(
            name=name,
            description=description,
            role=role,
            expires_at=expires_at,
            rate_limit_override=rate_limit_override,
            created_by=created_by,
        )

        await self.db.insert(
            "api_keys",
            {
                "id": api_key.id,
                "key_hash": key_hash,
                "name": api_key.name,
                "description": api_key.description,
                "role": api_key.role.value,
                "created_at": api_key.created_at.isoformat(),
                "last_used": None,
                "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
                "is_active": True,
                "rate_limit_override": api_key.rate_limit_override,
                "created_by": api_key.created_by,
            },
        )

        logger.info(f"Created API key '{name}' (id={api_key.id}, role={role.value})")
        return api_key, plaintext_key

    async def validate_api_key(self, plaintext_key: str) -> AuthContext | None:
        """
        Validate an API key and return auth context.

        Returns None if the key is invalid, expired, or revoked.
        """
        if not plaintext_key or not plaintext_key.startswith(KEY_PREFIX):
            return None

        key_hash = self._hash_key(plaintext_key)
        row = await self.db.fetch_one("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,))

        if not row:
            return None

        if not row["is_active"]:
            logger.debug(f"Rejected inactive API key: {row['id']}")
            return None

        # Check expiration
        if row["expires_at"]:
            expires_at = datetime.fromisoformat(row["expires_at"])
            if datetime.utcnow() > expires_at:
                logger.debug(f"Rejected expired API key: {row['id']}")
                return None

        # Update last_used timestamp (fire-and-forget)
        try:
            await self.db.execute(
                "UPDATE api_keys SET last_used = ? WHERE id = ?", (datetime.utcnow().isoformat(), row["id"])
            )
        except Exception:
            pass  # Non-critical

        return AuthContext(
            api_key_id=row["id"],
            role=Role(row["role"]),
            auth_method="api_key",
        )

    async def list_api_keys(self) -> list[APIKey]:
        """List all API keys (without hashes)."""
        rows = await self.db.fetch_all("SELECT * FROM api_keys ORDER BY created_at DESC")
        keys = []
        for row in rows:
            keys.append(
                APIKey(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    role=Role(row["role"]),
                    created_at=datetime.fromisoformat(row["created_at"]),
                    last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
                    expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                    is_active=bool(row["is_active"]),
                    rate_limit_override=row["rate_limit_override"],
                    created_by=row["created_by"],
                )
            )
        return keys

    async def get_api_key(self, key_id: str) -> APIKey | None:
        """Get an API key by ID."""
        row = await self.db.fetch_one("SELECT * FROM api_keys WHERE id = ?", (key_id,))
        if not row:
            return None

        return APIKey(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            role=Role(row["role"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            is_active=bool(row["is_active"]),
            rate_limit_override=row["rate_limit_override"],
            created_by=row["created_by"],
        )

    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke (deactivate) an API key."""
        result = await self.db.update("api_keys", key_id, {"is_active": False})
        if result:
            logger.info(f"Revoked API key: {key_id}")
        return result

    async def has_any_keys(self) -> bool:
        """Check if any API keys exist in the database."""
        count = await self.db.count("api_keys")
        return count > 0

    # --- JWT Methods ---

    def create_jwt_token(
        self,
        auth_context: AuthContext,
        purpose: str = "session",
        expires_in_override: int | None = None,
    ) -> tuple[str, int]:
        """
        Create a JWT token encoding the given auth context.

        Args:
            auth_context: Authentication context to encode.
            purpose: Token purpose — "session" (default) or "2fa_challenge".
            expires_in_override: Override token lifetime in seconds.

        Returns:
            Tuple of (token_string, expires_in_seconds)

        Raises:
            ValueError: If JWT_SECRET_KEY is not configured.
        """
        secret = settings.jwt_secret_key
        if not secret:
            raise ValueError("JWT_SECRET_KEY must be configured to issue tokens. Set it in environment variables.")

        expires_in = expires_in_override or settings.jwt_expiry_minutes * 60
        now = datetime.utcnow()

        payload = {
            "sub": auth_context.api_key_id or auth_context.user_id or "anonymous",
            "role": auth_context.role.value,
            "auth_method": auth_context.auth_method,
            "purpose": purpose,
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
        }

        if auth_context.api_key_id:
            payload["api_key_id"] = auth_context.api_key_id
        if auth_context.user_id:
            payload["user_id"] = auth_context.user_id

        # Add jti for session tokens (enables revocation)
        if purpose == "session" and auth_context.user_id:
            payload["jti"] = str(uuid.uuid4())

        token = jwt.encode(payload, secret, algorithm=settings.jwt_algorithm)
        return token, expires_in

    def create_challenge_token(self, user_id: str, role: Role) -> tuple[str, int]:
        """
        Create a short-lived 2FA challenge token.

        Returns:
            Tuple of (token_string, expires_in_seconds)
        """
        ctx = AuthContext(user_id=user_id, role=role, auth_method="user")
        expires_in = settings.totp_challenge_expiry_minutes * 60
        return self.create_jwt_token(ctx, purpose="2fa_challenge", expires_in_override=expires_in)

    def validate_jwt_token(self, token: str) -> AuthContext | None:
        """
        Validate a JWT token and return auth context.

        Returns None if the token is invalid or expired.
        """
        secret = settings.jwt_secret_key
        if not secret:
            return None

        try:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[settings.jwt_algorithm],
            )
        except jwt.ExpiredSignatureError:
            logger.debug("Rejected expired JWT token")
            return None
        except jwt.InvalidTokenError as e:
            logger.debug(f"Rejected invalid JWT token: {e}")
            return None

        return AuthContext(
            api_key_id=payload.get("api_key_id"),
            user_id=payload.get("user_id"),
            role=Role(payload["role"]),
            auth_method="jwt",
        )

    def decode_token_payload(self, token: str) -> dict | None:
        """
        Decode a JWT token and return the full payload dict.

        Returns None if the token is invalid or expired.
        """
        secret = settings.jwt_secret_key
        if not secret:
            return None

        try:
            return jwt.decode(token, secret, algorithms=[settings.jwt_algorithm])
        except jwt.InvalidTokenError:
            return None


# Singleton
_auth_service: AuthService | None = None


def get_auth_service() -> AuthService:
    """Get the global auth service instance."""
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service
