"""Tests for PII Vault model, encryption service, and API."""

import pytest
import re
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.services.pii_vault import (
    BRUTE_FORCE_MAX_FAILURES,
    VAULT_TOKEN_REGEX,
    check_token_lookup_limit,
    decrypt_value,
    domain_matches,
    encrypt_value,
    find_vault_tokens,
    generate_token,
    mask_value,
    record_token_lookup_failure,
    record_token_lookup_success,
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
        """Token should match {{SNAPPER_VAULT:<32hex>}} format (128-bit entropy)."""
        token = generate_token()
        assert re.match(r"^\{\{SNAPPER_VAULT:[a-f0-9]{32}\}\}$", token)

    def test_token_entropy(self):
        """New tokens should have 128-bit entropy (32 hex chars)."""
        token = generate_token()
        # Extract hex portion: {{SNAPPER_VAULT:...}}
        hex_part = token[len("{{SNAPPER_VAULT:"):-len("}}")]
        assert len(hex_part) == 32  # 16 bytes = 32 hex chars = 128 bits

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

    def test_regex_detects_old_8char_tokens(self):
        """VAULT_TOKEN_REGEX should still detect old 8-char (32-bit) tokens."""
        old_token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        assert VAULT_TOKEN_REGEX.match(old_token)
        found = find_vault_tokens(f"value: {old_token}")
        assert old_token in found

    def test_regex_detects_new_32char_tokens(self):
        """VAULT_TOKEN_REGEX should detect new 32-char (128-bit) tokens."""
        new_token = "{{SNAPPER_VAULT:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6}}"
        assert VAULT_TOKEN_REGEX.match(new_token)
        found = find_vault_tokens(f"value: {new_token}")
        assert new_token in found


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

    # --- JSON structured data masking ---

    def test_mask_credit_card_json(self):
        """Credit card JSON should show last 4 and exp date."""
        import json
        val = json.dumps({"number": "4111111111111234", "exp": "12/27", "cvc": "123"})
        result = mask_value(val, PIICategory.CREDIT_CARD)
        assert result == "****-****-****-1234 exp 12/27"

    def test_mask_name_json(self):
        """Name JSON should show first letter of each part."""
        import json
        val = json.dumps({"first": "John", "last": "Smith"})
        result = mask_value(val, PIICategory.NAME)
        assert result == "J*** S***"

    def test_mask_name_json_single_char(self):
        """Name JSON with single-char name should not mask."""
        import json
        val = json.dumps({"first": "J", "last": "S"})
        result = mask_value(val, PIICategory.NAME)
        assert result == "J S"

    def test_mask_address_json(self):
        """Address JSON should show street number, city initial, state, and zip."""
        import json
        val = json.dumps({"street": "123 Main St", "city": "Springfield", "state": "IL", "zip": "62704"})
        result = mask_value(val, PIICategory.ADDRESS)
        assert "123" in result
        assert "S***" in result  # city masked
        assert "IL" in result
        assert "62704" in result

    def test_mask_address_json_with_apt(self):
        """Address JSON with apartment in street should mask correctly."""
        import json
        val = json.dumps({"street": "456 Oak Ave, Apt 2B", "city": "Denver", "state": "CO", "zip": "80202"})
        result = mask_value(val, PIICategory.ADDRESS)
        assert "456" in result
        assert "CO" in result
        assert "80202" in result

    def test_mask_bank_account_json(self):
        """Bank account JSON should show last 4 of each number."""
        import json
        val = json.dumps({"routing": "021000021", "account": "1234567890"})
        result = mask_value(val, PIICategory.BANK_ACCOUNT)
        assert "Routing:" in result
        assert "Acct:" in result
        assert "0021" in result  # last 4 of routing
        assert "7890" in result  # last 4 of account

    def test_mask_name_plain_string_fallback(self):
        """Plain string name should still work (backward compat)."""
        assert mask_value("John Smith", PIICategory.NAME) == "J*** S***"

    def test_mask_address_plain_string_fallback(self):
        """Plain string address should still work (backward compat)."""
        result = mask_value("123 Main Street", PIICategory.ADDRESS)
        assert result.startswith("123")
        assert "***" in result

    def test_mask_bank_account_plain_string_fallback(self):
        """Plain account number string should still work (backward compat)."""
        result = mask_value("123456789012", PIICategory.BANK_ACCOUNT)
        assert result.endswith("9012")
        assert "*" in result


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
        assert domain_matches("expedia.com", "*.expedia.com") is True  # bare domain matches wildcard

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

    @pytest.mark.asyncio
    async def test_resolve_ownership_enforced_when_provided(self, mock_db):
        """When requester_chat_id is provided, ownership must match."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", owner="user_A")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        # Same owner should succeed
        resolved = await resolve_tokens(mock_db, [token], requester_chat_id="user_A")
        assert token in resolved

    @pytest.mark.asyncio
    async def test_resolve_ownership_mismatch_fails(self, mock_db):
        """Ownership mismatch should prevent token resolution."""
        from app.services.pii_vault import resolve_tokens

        token = "{{SNAPPER_VAULT:a1b2c3d4}}"
        entry = self._make_entry(token, "4111111111111234", owner="user_A")

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = entry
        mock_db.execute = AsyncMock(return_value=mock_result)

        # Different owner should fail
        resolved = await resolve_tokens(mock_db, [token], requester_chat_id="user_B")
        assert token not in resolved


# ============================================================================
# Brute-force protection tests
# ============================================================================


class TestBruteForceProtection:
    """Test brute-force protection for token lookups."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        redis.set = AsyncMock()
        redis.delete = AsyncMock()
        return redis

    @pytest.mark.asyncio
    async def test_check_limit_allows_by_default(self, mock_redis):
        """No lockout by default."""
        mock_redis.get = AsyncMock(return_value=None)
        allowed = await check_token_lookup_limit(mock_redis, "user1")
        assert allowed is True

    @pytest.mark.asyncio
    async def test_check_limit_blocks_when_locked(self, mock_redis):
        """Locked out user should be blocked."""
        mock_redis.get = AsyncMock(return_value="1")
        allowed = await check_token_lookup_limit(mock_redis, "user1")
        assert allowed is False

    @pytest.mark.asyncio
    async def test_failure_counter_increments(self, mock_redis):
        """Failure counter should increment on each failure."""
        mock_redis.get = AsyncMock(return_value="2")
        triggered = await record_token_lookup_failure(mock_redis, "user1")
        # 2 + 1 = 3, below threshold of 5
        assert triggered is False

    @pytest.mark.asyncio
    async def test_lockout_triggered_at_threshold(self, mock_redis):
        """Lockout should trigger after BRUTE_FORCE_MAX_FAILURES failures."""
        mock_redis.get = AsyncMock(return_value=str(BRUTE_FORCE_MAX_FAILURES - 1))
        triggered = await record_token_lookup_failure(mock_redis, "user1")
        assert triggered is True
        # Should have set lockout key
        mock_redis.set.assert_any_call("vault_lockout:user1", "1", expire=900)

    @pytest.mark.asyncio
    async def test_success_clears_failures(self, mock_redis):
        """Successful lookup should clear the failure counter."""
        await record_token_lookup_success(mock_redis, "user1")
        mock_redis.delete.assert_called_with("vault_failures:user1")

    @pytest.mark.asyncio
    async def test_resolve_with_brute_force_lockout(self):
        """resolve_tokens should return empty when locked out."""
        from app.services.pii_vault import resolve_tokens

        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        # Simulate lockout
        mock_redis.get = AsyncMock(return_value="1")

        resolved = await resolve_tokens(
            mock_db,
            ["{{SNAPPER_VAULT:deadbeef}}"],
            requester_chat_id="locked_user",
            redis=mock_redis,
        )
        assert len(resolved) == 0
