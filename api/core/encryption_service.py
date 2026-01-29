"""
Encryption service for protecting sensitive data at rest.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) from the
cryptography library to encrypt private keys stored on disk and in the database.
"""

import base64
import logging
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import settings

logger = logging.getLogger(__name__)

# Prefix used to identify Fernet-encrypted data
ENCRYPTED_PREFIX = b"gAAAAA"


class EncryptionService:
    """
    Symmetric encryption service for private keys at rest.

    Derives a Fernet key from a user-provided passphrase via PBKDF2.
    When no passphrase is configured, operates in plaintext passthrough mode.
    """

    def __init__(self):
        self._fernet: Optional[Fernet] = None
        self._enabled = False
        self._initialize()

    def _initialize(self):
        """Derive Fernet key from configured passphrase."""
        passphrase = settings.private_key_encryption_key
        if not passphrase or not settings.encrypt_private_keys:
            if settings.encrypt_private_keys and not passphrase:
                logger.warning(
                    "ENCRYPT_PRIVATE_KEYS is true but PRIVATE_KEY_ENCRYPTION_KEY is not set. "
                    "Private keys will be stored in plaintext."
                )
            return

        # Derive a 32-byte key from the passphrase using PBKDF2
        # Salt is fixed per-installation; the passphrase provides the entropy.
        # A fixed salt is acceptable here because:
        # 1. Each installation has a unique passphrase
        # 2. We're encrypting data at rest, not hashing passwords
        salt = b"nginx-manager-encryption-salt-v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
        self._fernet = Fernet(key)
        self._enabled = True
        logger.info("Encryption service initialized with PBKDF2-derived key")

    @property
    def enabled(self) -> bool:
        """Whether encryption is active."""
        return self._enabled

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt data. Returns ciphertext if encryption is enabled,
        otherwise returns plaintext unchanged.
        """
        if not self._enabled:
            return plaintext
        return self._fernet.encrypt(plaintext)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypt data. If data is not encrypted (no Fernet prefix),
        returns it unchanged for backward compatibility.
        """
        if not self._enabled:
            return data

        if not self.is_encrypted(data):
            # Data was stored before encryption was enabled
            return data

        try:
            return self._fernet.decrypt(data)
        except InvalidToken:
            raise ValueError(
                "Failed to decrypt data. The encryption key may have changed. "
                "Ensure PRIVATE_KEY_ENCRYPTION_KEY matches the key used during encryption."
            )

    def is_encrypted(self, data: bytes) -> bool:
        """Check if data appears to be Fernet-encrypted."""
        return data.startswith(ENCRYPTED_PREFIX)

    def encrypt_string(self, plaintext: str) -> str:
        """Encrypt a string, returning base64-encoded ciphertext string."""
        if not self._enabled:
            return plaintext
        encrypted = self._fernet.encrypt(plaintext.encode("utf-8"))
        return encrypted.decode("utf-8")

    def decrypt_string(self, data: str) -> str:
        """Decrypt a string. Returns unchanged if not encrypted."""
        if not self._enabled:
            return data

        if not data.startswith(ENCRYPTED_PREFIX.decode("utf-8")):
            return data

        try:
            return self._fernet.decrypt(data.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            raise ValueError(
                "Failed to decrypt data. The encryption key may have changed."
            )


# Singleton instance
_encryption_service: Optional[EncryptionService] = None


def get_encryption_service() -> EncryptionService:
    """Get the global encryption service instance."""
    global _encryption_service
    if _encryption_service is None:
        _encryption_service = EncryptionService()
    return _encryption_service
