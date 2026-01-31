"""
TOTP two-factor authentication service.

Handles TOTP secret generation, QR code creation, code verification,
and backup code management. Secrets are encrypted at rest using the
existing EncryptionService.
"""

import base64
import hashlib
import io
import json
import logging
import secrets
import string

import pyotp
import qrcode

from config import settings
from core.database import get_database
from core.encryption_service import get_encryption_service

logger = logging.getLogger(__name__)

BACKUP_CODE_LENGTH = 8
BACKUP_CODE_COUNT = 10
BACKUP_CODE_CHARS = string.ascii_lowercase + string.digits


class TOTPServiceError(Exception):
    """TOTP service error with user-friendly message."""

    def __init__(self, message: str, code: str = "totp_error"):
        self.message = message
        self.code = code
        super().__init__(message)


class TOTPService:
    """TOTP 2FA lifecycle management."""

    def __init__(self):
        self.db = get_database()
        self.encryption = get_encryption_service()

    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret (base32-encoded, 32 chars)."""
        return pyotp.random_base32(length=32)

    def encrypt_secret(self, secret: str) -> str:
        """Encrypt a TOTP secret for database storage."""
        return self.encryption.encrypt_string(secret)

    def decrypt_secret(self, encrypted: str) -> str:
        """Decrypt a TOTP secret from database storage."""
        return self.encryption.decrypt_string(encrypted)

    def generate_provisioning_uri(self, secret: str, username: str) -> str:
        """Generate an otpauth:// URI for authenticator apps."""
        totp = pyotp.TOTP(
            secret,
            digits=settings.totp_digits,
            interval=settings.totp_interval,
        )
        return totp.provisioning_uri(
            name=username,
            issuer_name=settings.totp_issuer_name,
        )

    @staticmethod
    def generate_qr_code_data_uri(provisioning_uri: str) -> str:
        """Generate a QR code as a data:image/png;base64,... URI."""
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b64}"

    def verify_code(self, secret: str, code: str) -> bool:
        """Verify a TOTP code against a secret with 1-window tolerance."""
        totp = pyotp.TOTP(
            secret,
            digits=settings.totp_digits,
            interval=settings.totp_interval,
        )
        return totp.verify(code, valid_window=1)

    @staticmethod
    def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> list[str]:
        """Generate random backup codes."""
        return ["".join(secrets.choice(BACKUP_CODE_CHARS) for _ in range(BACKUP_CODE_LENGTH)) for _ in range(count)]

    @staticmethod
    def hash_backup_code(code: str) -> str:
        """Hash a single backup code with SHA-256."""
        return hashlib.sha256(code.lower().encode("utf-8")).hexdigest()

    @classmethod
    def hash_backup_codes(cls, codes: list[str]) -> list[str]:
        """Hash a list of backup codes."""
        return [cls.hash_backup_code(c) for c in codes]

    # --- Database Operations ---

    async def enroll(self, user_id: str, username: str) -> dict:
        """
        Start TOTP enrollment for a user.

        Returns dict with secret, provisioning_uri, qr_code_data_uri, backup_codes.
        Does NOT enable 2FA — must call confirm() after user verifies first code.
        """
        row = await self.db.fetch_one("SELECT totp_enabled FROM users WHERE id = ?", (user_id,))
        if not row:
            raise TOTPServiceError("User not found", code="user_not_found")
        if row["totp_enabled"]:
            raise TOTPServiceError("2FA is already enabled for this user", code="already_enabled")

        secret = self.generate_secret()
        encrypted = self.encrypt_secret(secret)
        backup_codes = self.generate_backup_codes()
        hashed_codes = self.hash_backup_codes(backup_codes)

        await self.db.update(
            "users",
            user_id,
            {
                "totp_secret_encrypted": encrypted,
                "backup_codes_json": json.dumps(hashed_codes),
                "totp_enabled": False,
                "totp_confirmed_at": None,
            },
        )

        uri = self.generate_provisioning_uri(secret, username)
        qr = self.generate_qr_code_data_uri(uri)

        logger.info(f"TOTP enrollment started for user {user_id}")
        return {
            "secret": secret,
            "provisioning_uri": uri,
            "qr_code_data_uri": qr,
            "backup_codes": backup_codes,
        }

    async def confirm(self, user_id: str, totp_code: str) -> bool:
        """
        Confirm TOTP enrollment by verifying the first code.

        Returns True on success.
        Raises TOTPServiceError if verification fails.
        """
        row = await self.db.fetch_one(
            "SELECT totp_secret_encrypted, totp_enabled FROM users WHERE id = ?",
            (user_id,),
        )
        if not row:
            raise TOTPServiceError("User not found", code="user_not_found")
        if row["totp_enabled"]:
            raise TOTPServiceError("2FA is already confirmed", code="already_confirmed")
        if not row["totp_secret_encrypted"]:
            raise TOTPServiceError("No pending enrollment. Call enroll first.", code="not_enrolled")

        secret = self.decrypt_secret(row["totp_secret_encrypted"])
        if not self.verify_code(secret, totp_code):
            raise TOTPServiceError("Invalid TOTP code. Please try again.", code="invalid_code")

        from datetime import datetime

        now = datetime.utcnow().isoformat()
        await self.db.update(
            "users",
            user_id,
            {"totp_enabled": True, "totp_confirmed_at": now},
        )

        logger.info(f"TOTP enrollment confirmed for user {user_id}")
        return True

    async def disable(self, user_id: str) -> bool:
        """Disable TOTP for a user. Clears secret and backup codes."""
        await self.db.update(
            "users",
            user_id,
            {
                "totp_secret_encrypted": None,
                "totp_enabled": False,
                "totp_confirmed_at": None,
                "backup_codes_json": None,
            },
        )
        logger.info(f"TOTP disabled for user {user_id}")
        return True

    async def verify_totp(self, user_id: str, code: str) -> bool:
        """
        Verify a TOTP code for a user.

        Checks TOTP code first, then falls back to backup codes.
        Returns True if verification succeeds.
        """
        row = await self.db.fetch_one(
            "SELECT totp_secret_encrypted, backup_codes_json FROM users WHERE id = ?",
            (user_id,),
        )
        if not row or not row["totp_secret_encrypted"]:
            return False

        secret = self.decrypt_secret(row["totp_secret_encrypted"])

        # Try TOTP code first
        if len(code) == settings.totp_digits and self.verify_code(secret, code):
            return True

        # Fall back to backup code
        return await self._try_backup_code(user_id, code, row["backup_codes_json"])

    async def _try_backup_code(self, user_id: str, code: str, codes_json: str | None) -> bool:
        """Try to verify and consume a backup code."""
        if not codes_json:
            return False

        hashed_codes = json.loads(codes_json)
        code_hash = self.hash_backup_code(code)

        if code_hash not in hashed_codes:
            return False

        # Consume the backup code
        hashed_codes.remove(code_hash)
        await self.db.update(
            "users",
            user_id,
            {"backup_codes_json": json.dumps(hashed_codes)},
        )
        logger.info(f"Backup code consumed for user {user_id} ({len(hashed_codes)} remaining)")
        return True

    async def regenerate_backup_codes(self, user_id: str) -> list[str]:
        """Generate new backup codes, replacing existing ones."""
        row = await self.db.fetch_one("SELECT totp_enabled FROM users WHERE id = ?", (user_id,))
        if not row:
            raise TOTPServiceError("User not found", code="user_not_found")
        if not row["totp_enabled"]:
            raise TOTPServiceError("2FA is not enabled", code="not_enabled")

        codes = self.generate_backup_codes()
        hashed = self.hash_backup_codes(codes)
        await self.db.update(
            "users",
            user_id,
            {"backup_codes_json": json.dumps(hashed)},
        )
        logger.info(f"Backup codes regenerated for user {user_id}")
        return codes

    async def get_status(self, user_id: str) -> dict:
        """Get TOTP status for a user."""
        row = await self.db.fetch_one(
            "SELECT totp_enabled, totp_confirmed_at, backup_codes_json, role FROM users WHERE id = ?",
            (user_id,),
        )
        if not row:
            raise TOTPServiceError("User not found", code="user_not_found")

        backup_remaining = 0
        if row["backup_codes_json"]:
            backup_remaining = len(json.loads(row["backup_codes_json"]))

        role = row["role"]
        if (role == "admin" and settings.totp_enforce_admin) or (role == "operator" and settings.totp_enforce_operator):
            enforcement = "enforced"
        else:
            enforcement = "optional"

        return {
            "enabled": bool(row["totp_enabled"]),
            "confirmed_at": row["totp_confirmed_at"],
            "enforcement": enforcement,
            "backup_codes_remaining": backup_remaining,
        }


# Singleton
_totp_service: TOTPService | None = None


def get_totp_service() -> TOTPService:
    """Get the global TOTP service instance."""
    global _totp_service
    if _totp_service is None:
        _totp_service = TOTPService()
    return _totp_service
