"""
User management service.

Handles user creation, authentication, password management,
and account lockout. Passwords are hashed with bcrypt.
"""

import logging
from datetime import datetime, timedelta

import bcrypt

from core.database import get_database
from models.auth import AuthContext, Role, User

logger = logging.getLogger(__name__)

# Lockout settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


class UserServiceError(Exception):
    """User service error with user-friendly message."""

    def __init__(self, message: str, code: str = "user_error"):
        self.message = message
        self.code = code
        super().__init__(message)


class UserService:
    """User account management service."""

    def __init__(self):
        self.db = get_database()

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against a bcrypt hash."""
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))

    def _row_to_user(self, row: dict) -> User:
        """Convert a database row to a User model."""
        return User(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            role=Role(row["role"]),
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            password_changed_at=datetime.fromisoformat(row["password_changed_at"])
            if row["password_changed_at"]
            else None,
            failed_login_attempts=row["failed_login_attempts"] or 0,
            locked_until=datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None,
        )

    async def create_user(
        self,
        username: str,
        password: str,
        role: Role = Role.OPERATOR,
        email: str | None = None,
    ) -> User:
        """
        Create a new user account.

        Raises:
            UserServiceError: If username already exists.
        """
        # Check for duplicate username
        existing = await self.db.fetch_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            raise UserServiceError(f"Username '{username}' already exists", code="username_exists")

        password_hash = self._hash_password(password)
        now = datetime.utcnow()

        user = User(
            username=username,
            email=email,
            role=role,
            created_at=now,
            password_changed_at=now,
        )

        await self.db.insert(
            "users",
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "password_hash": password_hash,
                "role": user.role.value,
                "is_active": True,
                "created_at": user.created_at.isoformat(),
                "last_login": None,
                "password_changed_at": user.password_changed_at.isoformat(),
                "failed_login_attempts": 0,
                "locked_until": None,
            },
        )

        logger.info(f"Created user '{username}' (id={user.id}, role={role.value})")
        return user

    async def authenticate(
        self,
        username: str,
        password: str,
    ) -> AuthContext | None:
        """
        Authenticate a user by username and password.

        Returns AuthContext on success, None on failure.
        Implements account lockout after MAX_FAILED_ATTEMPTS failures.
        """
        row = await self.db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))

        if not row:
            return None

        if not row["is_active"]:
            logger.debug(f"Rejected login for inactive user: {username}")
            return None

        # Check lockout
        if row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if datetime.utcnow() < locked_until:
                logger.debug(f"Rejected login for locked user: {username}")
                return None
            # Lockout expired — reset counters
            await self.db.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (row["id"],)
            )

        # Verify password
        if not self._verify_password(password, row["password_hash"]):
            failed = (row["failed_login_attempts"] or 0) + 1
            update_data = {"failed_login_attempts": failed}

            if failed >= MAX_FAILED_ATTEMPTS:
                locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                update_data["locked_until"] = locked_until.isoformat()
                logger.warning(
                    f"User '{username}' locked after {failed} failed attempts (until {locked_until.isoformat()})"
                )

            await self.db.update("users", row["id"], update_data)
            return None

        # Success — reset failed attempts and update last_login
        now = datetime.utcnow()
        await self.db.update(
            "users",
            row["id"],
            {
                "failed_login_attempts": 0,
                "locked_until": None,
                "last_login": now.isoformat(),
            },
        )

        return AuthContext(
            user_id=row["id"],
            role=Role(row["role"]),
            auth_method="user",
        )

    async def get_user(self, user_id: str) -> User | None:
        """Get a user by ID."""
        row = await self.db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not row:
            return None
        return self._row_to_user(row)

    async def get_user_by_username(self, username: str) -> User | None:
        """Get a user by username."""
        row = await self.db.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        if not row:
            return None
        return self._row_to_user(row)

    async def list_users(self) -> list[User]:
        """List all users."""
        rows = await self.db.fetch_all("SELECT * FROM users ORDER BY created_at DESC")
        return [self._row_to_user(row) for row in rows]

    async def update_user(
        self,
        user_id: str,
        email: str | None = ...,
        role: Role | None = None,
        is_active: bool | None = None,
    ) -> User | None:
        """
        Update user fields. Only provided fields are updated.

        Uses sentinel default (...) for email to distinguish
        between None (clear) and not-provided (skip).
        """
        data = {}
        if email is not ...:
            data["email"] = email
        if role is not None:
            data["role"] = role.value
        if is_active is not None:
            data["is_active"] = is_active

        if not data:
            return await self.get_user(user_id)

        result = await self.db.update("users", user_id, data)
        if not result:
            return None

        logger.info(f"Updated user {user_id}: {list(data.keys())}")
        return await self.get_user(user_id)

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> bool:
        """
        Change a user's password after verifying the current password.

        Returns True on success, False if current password is wrong.

        Raises:
            UserServiceError: If user not found.
        """
        row = await self.db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
        if not row:
            raise UserServiceError("User not found", code="user_not_found")

        if not self._verify_password(current_password, row["password_hash"]):
            return False

        new_hash = self._hash_password(new_password)
        now = datetime.utcnow()
        await self.db.update(
            "users",
            user_id,
            {
                "password_hash": new_hash,
                "password_changed_at": now.isoformat(),
            },
        )

        logger.info(f"Password changed for user {user_id}")
        return True

    async def admin_reset_password(
        self,
        user_id: str,
        new_password: str,
    ) -> bool:
        """
        Admin reset of a user's password (no current password required).

        Returns True on success.

        Raises:
            UserServiceError: If user not found.
        """
        row = await self.db.fetch_one("SELECT id FROM users WHERE id = ?", (user_id,))
        if not row:
            raise UserServiceError("User not found", code="user_not_found")

        new_hash = self._hash_password(new_password)
        now = datetime.utcnow()
        await self.db.update(
            "users",
            user_id,
            {
                "password_hash": new_hash,
                "password_changed_at": now.isoformat(),
                "failed_login_attempts": 0,
                "locked_until": None,
            },
        )

        logger.info(f"Admin reset password for user {user_id}")
        return True

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user account."""
        result = await self.db.delete("users", user_id)
        if result:
            logger.info(f"Deleted user {user_id}")
        return result

    async def has_any_users(self) -> bool:
        """Check if any users exist in the database."""
        count = await self.db.count("users")
        return count > 0


# Singleton
_user_service: UserService | None = None


def get_user_service() -> UserService:
    """Get the global user service instance."""
    global _user_service
    if _user_service is None:
        _user_service = UserService()
    return _user_service
