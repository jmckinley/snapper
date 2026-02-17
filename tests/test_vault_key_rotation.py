"""Tests for PII vault key rotation."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.audit_logs import AuditAction
from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.services.pii_vault import (
    decrypt_value,
    encrypt_value,
    get_encryption_key,
    rotate_vault_key,
)


def test_encryption_key_versioning():
    """Different versions should produce different keys."""
    key_v1 = get_encryption_key(1)
    key_v2 = get_encryption_key(2)
    assert key_v1 != key_v2
    assert len(key_v1) > 0
    assert len(key_v2) > 0


def test_encrypt_decrypt_v1():
    """Encrypt and decrypt with version 1 should round-trip."""
    plaintext = "4111111111111111"
    ciphertext = encrypt_value(plaintext, key_version=1)
    result = decrypt_value(ciphertext, key_version=1)
    assert result == plaintext


def test_encrypt_decrypt_v2():
    """Encrypt and decrypt with version 2 should round-trip."""
    plaintext = "my-secret-data"
    ciphertext = encrypt_value(plaintext, key_version=2)
    result = decrypt_value(ciphertext, key_version=2)
    assert result == plaintext


def test_cross_version_decrypt_fails():
    """Decrypting with wrong version should fail."""
    plaintext = "sensitive-info"
    ciphertext = encrypt_value(plaintext, key_version=1)

    with pytest.raises(Exception):
        decrypt_value(ciphertext, key_version=2)


def test_vault_entry_has_key_version():
    """PIIVaultEntry model should have encryption_key_version field."""
    entry = MagicMock(spec=PIIVaultEntry)
    entry.encryption_key_version = 1
    assert entry.encryption_key_version == 1

    entry.encryption_key_version = 3
    assert entry.encryption_key_version == 3


def test_vault_key_rotated_audit_action():
    """VAULT_KEY_ROTATED should exist in AuditAction enum."""
    assert AuditAction.VAULT_KEY_ROTATED == "vault_key_rotated"


@pytest.mark.asyncio
async def test_rotate_vault_key_empty():
    """Rotating with no entries should return 0."""
    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    count = await rotate_vault_key(db, new_version=2)
    assert count == 0


@pytest.mark.asyncio
async def test_rotate_vault_key_reencrypts():
    """Rotation should re-encrypt entries with new version."""
    plaintext = "test-pii-value"
    old_cipher = encrypt_value(plaintext, key_version=1)

    entry = MagicMock(spec=PIIVaultEntry)
    entry.id = uuid.uuid4()
    entry.encrypted_value = old_cipher
    entry.encryption_key_version = 1
    entry.is_deleted = False

    db = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [entry]
    db.execute = AsyncMock(return_value=mock_result)
    db.flush = AsyncMock()

    count = await rotate_vault_key(db, new_version=2)
    assert count == 1
    assert entry.encryption_key_version == 2
    # Verify the new ciphertext decrypts correctly with v2
    decrypted = decrypt_value(entry.encrypted_value, key_version=2)
    assert decrypted == plaintext
