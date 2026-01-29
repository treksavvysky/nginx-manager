"""
Unit tests for encryption service.

Tests Fernet-based encryption for private keys at rest.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestEncryptionServiceDisabled:
    """Test encryption service in plaintext passthrough mode."""

    def test_passthrough_when_disabled(self):
        """Encryption returns plaintext when not enabled."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = False
            mock_settings.private_key_encryption_key = None

            from core.encryption_service import EncryptionService
            svc = EncryptionService()

            assert svc.enabled is False
            data = b"-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
            assert svc.encrypt(data) == data
            assert svc.decrypt(data) == data

    def test_passthrough_string_when_disabled(self):
        """String encrypt/decrypt returns unchanged when not enabled."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = False
            mock_settings.private_key_encryption_key = None

            from core.encryption_service import EncryptionService
            svc = EncryptionService()

            text = "-----BEGIN PRIVATE KEY-----\ntest"
            assert svc.encrypt_string(text) == text
            assert svc.decrypt_string(text) == text

    def test_warning_when_enabled_without_key(self):
        """Logs warning when encryption requested but no key set."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = True
            mock_settings.private_key_encryption_key = None

            from core.encryption_service import EncryptionService
            svc = EncryptionService()

            assert svc.enabled is False

    def test_is_encrypted_false_for_plaintext(self):
        """is_encrypted returns False for plaintext PEM data."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = False
            mock_settings.private_key_encryption_key = None

            from core.encryption_service import EncryptionService
            svc = EncryptionService()

            data = b"-----BEGIN PRIVATE KEY-----\ntest"
            assert svc.is_encrypted(data) is False


class TestEncryptionServiceEnabled:
    """Test encryption service with active encryption."""

    def _make_service(self):
        """Create an encryption service with a test passphrase."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = True
            mock_settings.private_key_encryption_key = "test-passphrase-for-unit-tests"

            from core.encryption_service import EncryptionService
            return EncryptionService()

    def test_enabled_with_valid_key(self):
        """Service reports enabled when properly configured."""
        svc = self._make_service()
        assert svc.enabled is True

    def test_encrypt_decrypt_roundtrip(self):
        """Data survives encrypt/decrypt roundtrip."""
        svc = self._make_service()
        plaintext = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...\n-----END PRIVATE KEY-----"

        encrypted = svc.encrypt(plaintext)
        assert encrypted != plaintext
        assert svc.is_encrypted(encrypted)

        decrypted = svc.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_string_roundtrip(self):
        """String data survives encrypt/decrypt roundtrip."""
        svc = self._make_service()
        plaintext = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk..."

        encrypted = svc.encrypt_string(plaintext)
        assert encrypted != plaintext

        decrypted = svc.decrypt_string(encrypted)
        assert decrypted == plaintext

    def test_decrypt_plaintext_passthrough(self):
        """Decrypting unencrypted data returns it unchanged (migration path)."""
        svc = self._make_service()
        plaintext = b"-----BEGIN PRIVATE KEY-----\nplaintext key"

        # Should not raise, should return as-is
        result = svc.decrypt(plaintext)
        assert result == plaintext

    def test_decrypt_string_plaintext_passthrough(self):
        """Decrypting unencrypted string returns it unchanged."""
        svc = self._make_service()
        plaintext = "-----BEGIN PRIVATE KEY-----\nplaintext key"

        result = svc.decrypt_string(plaintext)
        assert result == plaintext

    def test_is_encrypted_true_for_ciphertext(self):
        """is_encrypted returns True for encrypted data."""
        svc = self._make_service()
        encrypted = svc.encrypt(b"secret data")
        assert svc.is_encrypted(encrypted) is True

    def test_different_encryptions_produce_different_output(self):
        """Fernet uses random IV so each encryption is unique."""
        svc = self._make_service()
        plaintext = b"same data"
        enc1 = svc.encrypt(plaintext)
        enc2 = svc.encrypt(plaintext)
        assert enc1 != enc2
        # But both decrypt to the same value
        assert svc.decrypt(enc1) == svc.decrypt(enc2) == plaintext

    def test_wrong_key_fails_decryption(self):
        """Decryption fails with a different passphrase."""
        svc1 = self._make_service()
        encrypted = svc1.encrypt(b"secret")

        # Create service with different key
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = True
            mock_settings.private_key_encryption_key = "different-passphrase-entirely"

            from core.encryption_service import EncryptionService
            svc2 = EncryptionService()

        with pytest.raises(ValueError, match="encryption key may have changed"):
            svc2.decrypt(encrypted)

    def test_empty_bytes_encrypt_decrypt(self):
        """Empty bytes survive roundtrip."""
        svc = self._make_service()
        encrypted = svc.encrypt(b"")
        assert svc.decrypt(encrypted) == b""


class TestEncryptionServiceSingleton:
    """Test singleton pattern."""

    def test_get_encryption_service_returns_same_instance(self):
        """Singleton returns same instance."""
        with patch('core.encryption_service.settings') as mock_settings:
            mock_settings.encrypt_private_keys = False
            mock_settings.private_key_encryption_key = None

            import core.encryption_service as mod
            # Reset singleton
            mod._encryption_service = None

            svc1 = mod.get_encryption_service()
            svc2 = mod.get_encryption_service()
            assert svc1 is svc2

            # Cleanup
            mod._encryption_service = None
