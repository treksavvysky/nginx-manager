"""
Session management service.

Tracks JWT sessions in the database for revocation support.
Only user-originated JWTs (from login) are tracked — API-key-originated
tokens are stateless and not tracked.
"""

import logging
from datetime import datetime

from core.database import get_database

logger = logging.getLogger(__name__)


class SessionService:
    """JWT session lifecycle management."""

    def __init__(self):
        self.db = get_database()

    async def create_session(
        self,
        jti: str,
        user_id: str,
        expires_at: datetime,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Record a new session in the database."""
        await self.db.insert(
            "sessions",
            {
                "id": jti,
                "user_id": user_id,
                "created_at": datetime.utcnow().isoformat(),
                "expires_at": expires_at.isoformat(),
                "is_revoked": False,
                "revoked_at": None,
                "ip_address": ip_address,
                "user_agent": user_agent,
            },
        )

    async def is_session_revoked(self, jti: str) -> bool:
        """Check if a session has been revoked. Returns False for unknown sessions (fail-open)."""
        row = await self.db.fetch_one("SELECT is_revoked FROM sessions WHERE id = ?", (jti,))
        if not row:
            return False
        return bool(row["is_revoked"])

    async def revoke_session(self, jti: str) -> bool:
        """Revoke a specific session. Returns True if found and revoked."""
        now = datetime.utcnow().isoformat()
        return await self.db.update(
            "sessions",
            jti,
            {"is_revoked": True, "revoked_at": now},
        )

    async def revoke_all_user_sessions(self, user_id: str, except_jti: str | None = None) -> int:
        """Revoke all sessions for a user, optionally keeping one."""
        now = datetime.utcnow().isoformat()
        if except_jti:
            query = (
                "UPDATE sessions SET is_revoked = 1, revoked_at = ? WHERE user_id = ? AND id != ? AND is_revoked = 0"
            )
            params = (now, user_id, except_jti)
        else:
            query = "UPDATE sessions SET is_revoked = 1, revoked_at = ? WHERE user_id = ? AND is_revoked = 0"
            params = (now, user_id)

        async with self.db.connection() as db:
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor.rowcount

    async def list_user_sessions(self, user_id: str) -> list[dict]:
        """List active (non-expired, non-revoked) sessions for a user."""
        now = datetime.utcnow().isoformat()
        rows = await self.db.fetch_all(
            "SELECT * FROM sessions WHERE user_id = ? AND is_revoked = 0 AND expires_at > ? ORDER BY created_at DESC",
            (user_id, now),
        )
        return [dict(row) for row in rows]

    async def get_session(self, jti: str) -> dict | None:
        """Get a session by its ID (jti)."""
        return await self.db.fetch_one("SELECT * FROM sessions WHERE id = ?", (jti,))

    async def cleanup_expired_sessions(self) -> int:
        """Delete sessions that have expired. Returns count deleted."""
        now = datetime.utcnow().isoformat()
        async with self.db.connection() as db:
            cursor = await db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            await db.commit()
            count = cursor.rowcount
        if count:
            logger.info(f"Cleaned up {count} expired sessions")
        return count


# Singleton
_session_service: SessionService | None = None


def get_session_service() -> SessionService:
    """Get the global session service instance."""
    global _session_service
    if _session_service is None:
        _session_service = SessionService()
    return _session_service
