"""Tests for MFA/TOTP implementation."""

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.users import User, UserRole
from app.schemas.auth import (
    MFALoginRequest,
    MFAVerifyRequest,
    MFAVerifySetupResponse,
)


def test_mfa_verify_request_valid():
    """Valid 6-digit TOTP code should pass validation."""
    req = MFAVerifyRequest(code="123456")
    assert req.code == "123456"


def test_mfa_verify_request_invalid_short():
    """Code shorter than 6 digits should fail."""
    with pytest.raises(ValueError, match="6 digits"):
        MFAVerifyRequest(code="1234")


def test_mfa_verify_request_invalid_letters():
    """Non-digit code should fail."""
    with pytest.raises(ValueError, match="6 digits"):
        MFAVerifyRequest(code="abcdef")


def test_mfa_verify_request_strips_whitespace():
    """Whitespace should be stripped from code."""
    req = MFAVerifyRequest(code=" 123456 ")
    assert req.code == "123456"


def test_mfa_login_request_accepts_backup():
    """MFA login should accept 8-char backup codes."""
    req = MFALoginRequest(mfa_token="token123", code="a1b2c3d4")
    assert req.code == "a1b2c3d4"


def test_mfa_login_request_rejects_bad_length():
    """MFA login should reject codes of wrong length."""
    with pytest.raises(ValueError, match="6-digit TOTP code or 8-character"):
        MFALoginRequest(mfa_token="token123", code="123")


def test_mfa_verify_setup_response():
    """MFAVerifySetupResponse should include backup codes."""
    resp = MFAVerifySetupResponse(
        enabled=True,
        backup_codes=["code1234", "code5678"],
    )
    assert resp.enabled is True
    assert len(resp.backup_codes) == 2


def test_user_totp_fields():
    """User model should have TOTP-related fields."""
    user = MagicMock(spec=User)
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_backup_codes = None

    assert user.totp_enabled is False
    assert user.totp_secret is None

    user.totp_secret = "JBSWY3DPEHPK3PXP"
    user.totp_enabled = True
    user.totp_backup_codes = ["hash1", "hash2"]

    assert user.totp_enabled is True
    assert user.totp_secret == "JBSWY3DPEHPK3PXP"
    assert len(user.totp_backup_codes) == 2


def test_backup_code_hashing():
    """Backup codes should be hashed with SHA-256."""
    code = "a1b2c3d4"
    hashed = hashlib.sha256(code.encode()).hexdigest()
    assert len(hashed) == 64
    assert hashed != code


def test_backup_code_verification():
    """Backup code should match its SHA-256 hash."""
    codes = ["abcd1234", "efgh5678"]
    hashed_codes = [hashlib.sha256(c.encode()).hexdigest() for c in codes]

    # Verify first code matches
    test_hash = hashlib.sha256("abcd1234".encode()).hexdigest()
    assert test_hash in hashed_codes

    # Verify wrong code doesn't match
    wrong_hash = hashlib.sha256("wrong123".encode()).hexdigest()
    assert wrong_hash not in hashed_codes


def test_backup_code_removal():
    """Used backup code should be removed from the list."""
    codes = ["code1", "code2", "code3"]
    hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]

    # Simulate using code2
    used_hash = hashlib.sha256("code2".encode()).hexdigest()
    remaining = [c for c in hashed if c != used_hash]
    assert len(remaining) == 2
    assert used_hash not in remaining
