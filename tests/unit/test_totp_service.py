"""
Unit tests for TOTP two-factor authentication service.

Tests cover secret generation, code verification, backup codes,
encryption integration, and database enrollment flows.
"""

import hashlib
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pyotp
import pytest

from core.totp_service import TOTPService, TOTPServiceError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_passthrough_encryption():
    """Create a mock encryption service that passes values through unchanged."""
    mock_enc = MagicMock()
    mock_enc.encrypt_string = MagicMock(side_effect=lambda x: x)
    mock_enc.decrypt_string = MagicMock(side_effect=lambda x: x)
    return mock_enc


def _make_service():
    """Create a TOTPService with passthrough encryption and a mock database."""
    mock_db = MagicMock()
    mock_db.fetch_one = AsyncMock(return_value=None)
    mock_db.update = AsyncMock(return_value=True)
    mock_enc = _make_passthrough_encryption()
    with (
        patch("core.totp_service.get_database", return_value=mock_db),
        patch("core.totp_service.get_encryption_service", return_value=mock_enc),
    ):
        service = TOTPService()
    return service, mock_db, mock_enc


# ---------------------------------------------------------------------------
# 1. TestTOTPGeneration
# ---------------------------------------------------------------------------


class TestTOTPGeneration:
    """Pure function tests for TOTP generation utilities (no mocking needed)."""

    def test_generate_secret_is_base32(self):
        """Generated secret is valid base32, 32 characters long."""
        secret = TOTPService.generate_secret()
        assert len(secret) == 32
        # base32 characters: A-Z and 2-7
        import base64

        # Should not raise on decode
        decoded = base64.b32decode(secret)
        assert len(decoded) > 0

    def test_provisioning_uri_format(self):
        """Provisioning URI follows otpauth:// format with username and issuer."""
        service, _, _ = _make_service()
        secret = TOTPService.generate_secret()
        uri = service.generate_provisioning_uri(secret, "testuser")

        assert uri.startswith("otpauth://totp/")
        assert "testuser" in uri
        assert "issuer=" in uri
        assert secret in uri

    def test_qr_code_data_uri_format(self):
        """QR code output is a valid data URI with PNG base64 content."""
        uri = "otpauth://totp/NGINX%20Manager:testuser?secret=ABCDEFGH&issuer=NGINX+Manager"
        data_uri = TOTPService.generate_qr_code_data_uri(uri)

        assert data_uri.startswith("data:image/png;base64,")
        # Verify the base64 portion is non-empty and decodable
        b64_part = data_uri.split(",", 1)[1]
        assert len(b64_part) > 100  # a real PNG is much larger


# ---------------------------------------------------------------------------
# 2. TestTOTPVerification
# ---------------------------------------------------------------------------


class TestTOTPVerification:
    """Tests for TOTP code verification logic."""

    def test_valid_code_accepted(self):
        """A freshly generated TOTP code is accepted."""
        service, _, _ = _make_service()
        secret = TOTPService.generate_secret()
        code = pyotp.TOTP(secret).now()

        assert service.verify_code(secret, code) is True

    def test_invalid_code_rejected(self):
        """A clearly wrong code is rejected."""
        service, _, _ = _make_service()
        secret = TOTPService.generate_secret()

        assert service.verify_code(secret, "000000") is False

    def test_window_tolerance(self):
        """A code from the previous time step is accepted with valid_window=1."""
        service, _, _ = _make_service()
        secret = TOTPService.generate_secret()
        totp = pyotp.TOTP(secret)

        # Generate code for 30 seconds ago (previous time step)
        previous_code = totp.at(int(time.time()) - 30)
        assert service.verify_code(secret, previous_code) is True


# ---------------------------------------------------------------------------
# 3. TestBackupCodes
# ---------------------------------------------------------------------------


class TestBackupCodes:
    """Tests for backup code generation and hashing."""

    def test_generate_backup_codes_count_and_length(self):
        """Default generation produces 10 codes, each 8 characters long."""
        codes = TOTPService.generate_backup_codes()
        assert len(codes) == 10
        for code in codes:
            assert len(code) == 8
            assert code.isalnum()

    def test_backup_codes_unique(self):
        """All generated backup codes are unique."""
        codes = TOTPService.generate_backup_codes()
        assert len(set(codes)) == len(codes)

    def test_hash_backup_code_sha256(self):
        """Hashed backup code is a 64-character hex string (SHA-256)."""
        hashed = TOTPService.hash_backup_code("abcd1234")
        assert len(hashed) == 64
        # Verify it is valid hex
        int(hashed, 16)

    def test_hash_round_trip(self):
        """hash_backup_code matches a direct hashlib.sha256 on lowercase input."""
        code = "AbCd1234"
        expected = hashlib.sha256(code.lower().encode("utf-8")).hexdigest()
        assert TOTPService.hash_backup_code(code) == expected

    def test_hash_backup_codes_batch(self):
        """hash_backup_codes returns a list of hashes matching individual calls."""
        codes = ["code1111", "code2222", "code3333"]
        hashed_list = TOTPService.hash_backup_codes(codes)
        assert len(hashed_list) == 3
        for code, hashed in zip(codes, hashed_list, strict=True):
            assert hashed == TOTPService.hash_backup_code(code)


# ---------------------------------------------------------------------------
# 4. TestTOTPEncryption
# ---------------------------------------------------------------------------


class TestTOTPEncryption:
    """Tests for encrypt/decrypt secret integration with EncryptionService."""

    def test_encrypt_decrypt_round_trip(self):
        """Secret survives encrypt then decrypt with passthrough encryption mock."""
        service, _, _ = _make_service()
        secret = TOTPService.generate_secret()
        encrypted = service.encrypt_secret(secret)
        decrypted = service.decrypt_secret(encrypted)
        assert decrypted == secret

    def test_encrypt_passthrough_when_disabled(self):
        """When encryption service is a passthrough, encrypt returns input unchanged."""
        service, _, mock_enc = _make_service()
        secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PX"
        encrypted = service.encrypt_secret(secret)
        assert encrypted == secret
        mock_enc.encrypt_string.assert_called_once_with(secret)


# ---------------------------------------------------------------------------
# 5. TestTOTPEnrollment (async, database-mocked)
# ---------------------------------------------------------------------------


class TestTOTPEnrollment:
    """Tests for enrollment, confirmation, and related DB flows."""

    @pytest.mark.asyncio
    async def test_enroll_returns_secret_and_qr(self):
        """Enrollment returns dict with secret, provisioning_uri, qr_code_data_uri, backup_codes."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"totp_enabled": False})
        mock_db.update = AsyncMock(return_value=True)
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            result = await service.enroll("user-123", "admin")

        assert "secret" in result
        assert "provisioning_uri" in result
        assert "qr_code_data_uri" in result
        assert "backup_codes" in result
        assert len(result["backup_codes"]) == 10
        assert result["provisioning_uri"].startswith("otpauth://totp/")
        assert result["qr_code_data_uri"].startswith("data:image/png;base64,")
        mock_db.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_enroll_already_enabled_raises(self):
        """Enrolling a user with 2FA already enabled raises TOTPServiceError."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"totp_enabled": True})
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            with pytest.raises(TOTPServiceError, match="already enabled"):
                await service.enroll("user-123", "admin")

    @pytest.mark.asyncio
    async def test_enroll_user_not_found_raises(self):
        """Enrolling a nonexistent user raises TOTPServiceError."""
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value=None)
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            with pytest.raises(TOTPServiceError, match="User not found"):
                await service.enroll("nonexistent", "ghost")

    @pytest.mark.asyncio
    async def test_confirm_valid_code(self):
        """Confirming enrollment with a valid TOTP code enables 2FA."""
        secret = TOTPService.generate_secret()
        valid_code = pyotp.TOTP(secret).now()

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"totp_secret_encrypted": secret, "totp_enabled": False})
        mock_db.update = AsyncMock(return_value=True)
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            result = await service.confirm("user-123", valid_code)

        assert result is True
        # Verify that totp_enabled was set to True in the update call
        update_call_args = mock_db.update.call_args
        assert update_call_args[0][0] == "users"
        assert update_call_args[0][1] == "user-123"
        assert update_call_args[0][2]["totp_enabled"] is True

    @pytest.mark.asyncio
    async def test_confirm_invalid_code_raises(self):
        """Confirming with an invalid code raises TOTPServiceError."""
        secret = TOTPService.generate_secret()

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(return_value={"totp_secret_encrypted": secret, "totp_enabled": False})
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            with pytest.raises(TOTPServiceError, match="Invalid TOTP code"):
                await service.confirm("user-123", "000000")

    @pytest.mark.asyncio
    async def test_verify_totp_with_backup_code(self):
        """verify_totp falls back to backup codes when TOTP code does not match."""
        secret = TOTPService.generate_secret()
        backup_code = "abcd1234"
        hashed = TOTPService.hash_backup_code(backup_code)

        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(
            return_value={
                "totp_secret_encrypted": secret,
                "backup_codes_json": json.dumps([hashed, "otherhash"]),
            }
        )
        mock_db.update = AsyncMock(return_value=True)
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            result = await service.verify_totp("user-123", backup_code)

        assert result is True
        # Backup code should be consumed (removed from the list)
        update_call = mock_db.update.call_args
        remaining = json.loads(update_call[0][2]["backup_codes_json"])
        assert hashed not in remaining
        assert "otherhash" in remaining

    @pytest.mark.asyncio
    async def test_get_status_returns_correct_fields(self):
        """get_status returns enabled, confirmed_at, enforcement, backup_codes_remaining."""
        hashed_codes = ["hash1", "hash2", "hash3"]
        mock_db = MagicMock()
        mock_db.fetch_one = AsyncMock(
            return_value={
                "totp_enabled": True,
                "totp_confirmed_at": "2026-01-01T00:00:00",
                "backup_codes_json": json.dumps(hashed_codes),
                "role": "admin",
            }
        )
        mock_enc = _make_passthrough_encryption()

        with (
            patch("core.totp_service.get_database", return_value=mock_db),
            patch("core.totp_service.get_encryption_service", return_value=mock_enc),
        ):
            service = TOTPService()
            status = await service.get_status("user-123")

        assert status["enabled"] is True
        assert status["confirmed_at"] == "2026-01-01T00:00:00"
        assert status["backup_codes_remaining"] == 3
        assert status["enforcement"] in ("enforced", "optional")
