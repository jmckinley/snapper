"""Tests for PII Vault model, encryption service, and API."""

import pytest
import re
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.services.pii_vault import (
    VAULT_TOKEN_REGEX,
    decrypt_value,
    domain_matches,
    encrypt_value,
    find_vault_tokens,
    generate_token,
    mask_value,
)


# ============================================================================
# Encryption round-trip tests
# ============================================================================


class TestEncryption:
    """Test Fernet encryption/decryption."""

    def test_encrypt_decrypt_round_trip(self):
        """Encrypting then decrypting should return the original value."""
        plaintext = "4111111111111234"
        ciphertext = encrypt_value(plaintext)
        assert isinstance(ciphertext, bytes)
        assert len(ciphertext) > 0
        assert decrypt_value(ciphertext) == plaintext

    def test_encrypt_produces_different_output(self):
        """Each encryption should produce different ciphertext (Fernet uses random IV)."""
        plaintext = "test-value"
        c1 = encrypt_value(plaintext)
        c2 = encrypt_value(plaintext)
        assert c1 != c2  # Different IVs

    def test_encrypt_empty_string(self):
        """Empty string should encrypt and decrypt correctly."""
        plaintext = ""
        ciphertext = encrypt_value(plaintext)
        assert decrypt_value(ciphertext) == plaintext

    def test_encrypt_unicode(self):
        """Unicode values should encrypt and decrypt correctly."""
        plaintext = "John Doe, 東京都渋谷区"
        ciphertext = encrypt_value(plaintext)
        assert decrypt_value(ciphertext) == plaintext

    def test_encrypt_long_value(self):
        """Long values (full address, etc.) should work."""
        plaintext = "123 Main Street, Apartment 4B, Springfield, IL 62701, United States of America"
        ciphertext = encrypt_value(plaintext)
        assert decrypt_value(ciphertext) == plaintext


# ============================================================================
# Token generation tests
# ============================================================================


class TestTokenGeneration:
    """Test vault token format and uniqueness."""

    def test_token_format(self):
        """Token should match {{SNAPPER_VAULT:<8hex>}} format."""
        token = generate_token()
        assert re.match(r"^\{\{SNAPPER_VAULT:[a-f0-9]{8}\}\}$", token)

    def test_token_uniqueness(self):
        """Tokens should be unique."""
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_token_regex_detection(self):
        """The VAULT_TOKEN_REGEX should detect tokens in text."""
        token = generate_token()
        text = f'browser fill [{{"ref":"15","value":"{token}"}}]'
        matches = VAULT_TOKEN_REGEX.findall(text)
        assert len(matches) == 1
        assert matches[0] == token

    def test_find_multiple_tokens(self):
        """find_vault_tokens should find all tokens in a string."""
        t1 = "{{SNAPPER_VAULT:a1b2c3d4}}"
        t2 = "{{SNAPPER_VAULT:e5f6a7b8}}"
        text = f'fields: [{{"value":"{t1}"}},{{"value":"{t2}"}}]'
        found = find_vault_tokens(text)
        assert len(found) == 2
        assert t1 in found
        assert t2 in found

    def test_find_no_tokens(self):
        """find_vault_tokens should return empty list when no tokens present."""
        text = 'browser fill [{"ref":"15","value":"John Smith"}]'
        assert find_vault_tokens(text) == []


# ============================================================================
# Masking tests
# ============================================================================


class TestMasking:
    """Test PII value masking for display."""

    def test_mask_credit_card(self):
        """Credit card should show last 4 digits."""
        assert mask_value("4111111111111234", PIICategory.CREDIT_CARD) == "****-****-****-1234"

    def test_mask_credit_card_with_dashes(self):
        """Credit card with dashes should still mask correctly."""
        assert mask_value("4111-1111-1111-1234", PIICategory.CREDIT_CARD) == "****-****-****-1234"

    def test_mask_email(self):
        """Email should show first char of local part and full domain."""
        assert mask_value("john@example.com", PIICategory.EMAIL) == "j***@example.com"

    def test_mask_phone(self):
        """Phone should show last 4 digits."""
        result = mask_value("+15551234567", PIICategory.PHONE)
        assert result.endswith("4567")
        assert "***" in result

    def test_mask_name(self):
        """Name should show first letter of each word."""
        assert mask_value("John Smith", PIICategory.NAME) == "J*** S***"

    def test_mask_ssn(self):
        """SSN should show last 4 digits."""
        assert mask_value("123-45-6789", PIICategory.SSN) == "***-**-6789"

    def test_mask_address(self):
        """Address should keep street number, mask rest."""
        result = mask_value("123 Main Street", PIICategory.ADDRESS)
        assert result.startswith("123")
        assert "***" in result

    def test_mask_passport(self):
        """Passport should show last 4 chars."""
        result = mask_value("AB1234567", PIICategory.PASSPORT)
        assert result.endswith("4567")
        assert "*" in result

    def test_mask_bank_account(self):
        """Bank account should show last 4 digits."""
        result = mask_value("123456789012", PIICategory.BANK_ACCOUNT)
        assert result.endswith("9012")
        assert "*" in result

    def test_mask_custom(self):
        """Custom category should use generic masking."""
        result = mask_value("some-custom-value", PIICategory.CUSTOM)
        assert result.endswith("alue")
        assert "*" in result

    def test_mask_empty(self):
        """Empty value should return asterisks."""
        assert mask_value("", PIICategory.CREDIT_CARD) == "****"


# ============================================================================
# Domain matching tests
# ============================================================================


class TestDomainMatching:
    """Test domain whitelist pattern matching."""

    def test_exact_domain(self):
        assert domain_matches("expedia.com", "expedia.com") is True
        assert domain_matches("evil.com", "expedia.com") is False

    def test_wildcard_subdomain(self):
        assert domain_matches("www.expedia.com", "*.expedia.com") is True
        assert domain_matches("checkout.expedia.com", "*.expedia.com") is True
        assert domain_matches("expedia.com", "*.expedia.com") is False

    def test_case_insensitive(self):
        assert domain_matches("EXPEDIA.COM", "expedia.com") is True
        assert domain_matches("expedia.com", "EXPEDIA.COM") is True

    def test_full_wildcard(self):
        assert domain_matches("anything.com", "*") is True


# ============================================================================
# Vault CRUD tests (async, need DB mock)
# ============================================================================


class TestVaultCRUD:
    """Test vault create/list/delete operations."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock async database session."""
        db = AsyncMock()
        db.add = MagicMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        return db

    @pytest.mark.asyncio
    async def test_create_entry(self, mock_db):
        """Creating an entry should encrypt the value and generate a token."""
        from app.services.pii_vault import create_entry

        entry = await create_entry(
            db=mock_db,
            owner_chat_id="12345",
            owner_name="John",
            label="My Visa",
            category=PIICategory.CREDIT_CARD,
            raw_value="4111111111111234",
        )

        assert entry.token.startswith("{{SNAPPER_VAULT:")
        assert entry.masked_value == "****-****-****-1234"
        assert entry.owner_chat_id == "12345"
        assert entry.category == PIICategory.CREDIT_CARD
        assert isinstance(entry.encrypted_value, bytes)
        # Verify we can decrypt
        assert decrypt_value(entry.encrypted_value) == "4111111111111234"

    @pytest.mark.asyncio
    async def test_create_entry_with_domains(self, mock_db):
        """Creating an entry with allowed_domains should persist them."""
        from app.services.pii_vault import create_entry

        entry = await create_entry(
            db=mock_db,
            owner_chat_id="12345",
            owner_name="John",
            label="Travel Card",
            category=PIICategory.CREDIT_CARD,
            raw_value="4111111111111234",
            allowed_domains=["*.expedia.com", "*.delta.com"],
        )

        assert entry.allowed_domains == ["*.expedia.com", "*.delta.com"]

    @pytest.mark.asyncio
    async def test_delete_entry_ownership_check(self, mock_db):
        """Deleting should fail if requester doesn't own the entry."""
        from app.services.pii_vault import delete_entry

        # Create a mock entry owned by user "111"
        mock_entry = MagicMock()
        mock_entry.owner_chat_id = "111"
        mock_entry.is_deleted = False

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        # User "222" tries to delete it
        result = await delete_entry(
            db=mock_db,
            entry_id=str(uuid4()),
            requester_chat_id="222",
        )

        assert result is False
        assert mock_entry.is_deleted is False  # Not changed

    @pytest.mark.asyncio
    async def test_delete_entry_owner_succeeds(self, mock_db):
        """Owner should be able to delete their own entry."""
        from app.services.pii_vault import delete_entry

        mock_entry = MagicMock()
        mock_entry.owner_chat_id = "111"
        mock_entry.is_deleted = False

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await delete_entry(
            db=mock_db,
            entry_id=str(uuid4()),
            requester_chat_id="111",
        )

        assert result is True
        assert mock_entry.is_deleted is True


# ============================================================================
# Token resolution tests
# ============================================================================


class TestTokenResolution:
    """Test vault token resolution (decrypt + validation)."""

    @pytest.fixture
    def mock_db(self):
        db = AsyncMock()
        db.flush = AsyncMock()
        db.commit = AsyncMock()
        return db

    def _make_entry(self, token, raw_value, owner="111", domains=None, max_uses=None, expires_at=None):
        """Helper to create a mock vault entry."""
        entry = MagicMock(spec=PIIVaultEntry)
        entry.token = token
        entry.owner_chat_id = owner
        entry.encrypted_value = encrypt_value(raw_value)
        entry.category = PIICategory.CREDIT_CARD
        entry.label = "Test Card"
        entry.masked_value = "****-****-****-1234"
        entry.allowed_domains = domains or []
        entry.max_uses = max_uses
        entry.use_count = 0
        entry.expires_at = expires_at
        entry.last_used_at = None
        entry.last_used_domain = None
        return entry

    @pytest.mark.asyncio
    async def test_resolve_valid_token(self, mock_db):
        """Valid token should resolve to decrypted value."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token])

        assert token in resolved
        assert resolved[token]["value"] == "4111111111111234"
        assert resolved[token]["category"] == "credit_card"

    @pytest.mark.asyncio
    async def test_resolve_expired_token(self, mock_db):
        """Expired token should not resolve."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(
            token, "4111111111111234",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token])
        assert token not in resolved

    @pytest.mark.asyncio
    async def test_resolve_max_uses_exceeded(self, mock_db):
        """Token with exhausted uses should not resolve."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", max_uses=1)
        entry.use_count = 1  # Already used

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token])
        assert token not in resolved

    @pytest.mark.asyncio
    async def test_resolve_domain_whitelist_pass(self, mock_db):
        """Token with matching domain should resolve."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", domains=["*.expedia.com"])

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token], destination_domain="checkout.expedia.com")
        assert token in resolved

    @pytest.mark.asyncio
    async def test_resolve_domain_whitelist_fail(self, mock_db):
        """Token with non-matching domain should not resolve."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", domains=["*.expedia.com"])

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token], destination_domain="evil.com")
        assert token not in resolved

    @pytest.mark.asyncio
    async def test_resolve_ownership_check(self, mock_db):
        """Token owned by different user should not resolve."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", owner="111")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, [token], requester_chat_id="222")
        assert token not in resolved

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_token(self, mock_db):
        """Non-existent token should be skipped."""
        from app.services.pii_vault import resolve_tokens

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        resolved = await resolve_tokens(mock_db, ["{{SNAPPER_VAULT:deadbeef}}"])
        assert len(resolved) == 0
