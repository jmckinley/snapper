"""PII Vault encryption and management service."""

import fnmatch
import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Optional
from uuid import uuid4

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.pii_vault import PIICategory, PIIVaultEntry

logger = logging.getLogger(__name__)
settings = get_settings()

# Token regex for detection in text (accepts both old 8-char and new 32-char tokens)
VAULT_TOKEN_REGEX = re.compile(r"\{\{SNAPPER_VAULT:[a-f0-9]{8,32}\}\}")


def get_encryption_key() -> bytes:
    """
    Derive a Fernet-compatible encryption key from SECRET_KEY using HKDF.

    This ensures the vault encryption is tied to the application secret
    but uses a separate derived key for defense-in-depth.
    """
    secret_bytes = settings.SECRET_KEY.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"snapper-pii-vault-v1",
        info=b"pii-vault-encryption-key",
    )
    derived = hkdf.derive(secret_bytes)
    return base64.urlsafe_b64encode(derived)


def encrypt_value(plaintext: str) -> bytes:
    """Encrypt a plaintext value using Fernet (AES-128-CBC + HMAC)."""
    key = get_encryption_key()
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt_value(ciphertext: bytes) -> str:
    """Decrypt a Fernet-encrypted value back to plaintext."""
    key = get_encryption_key()
    f = Fernet(key)
    return f.decrypt(ciphertext).decode("utf-8")


def generate_token() -> str:
    """Generate a unique vault reference token (128-bit entropy)."""
    hex_id = os.urandom(16).hex()  # 32 hex chars
    return "{{SNAPPER_VAULT:" + hex_id + "}}"


def mask_value(raw_value: str, category: PIICategory) -> str:
    """
    Generate a masked display value based on PII category.

    Examples:
        credit_card: "4111111111111234" -> "****-****-****-1234"
        email: "john@example.com" -> "j***@example.com"
        phone: "+15551234567" -> "+1***-***-4567"
        name: "John Smith" -> "J*** S***"
        ssn: "123-45-6789" -> "***-**-6789"
        address: "123 Main St, City, ST 12345" -> "123 M*** S*, C***, ** 12345"
    """
    if not raw_value:
        return "****"

    if category == PIICategory.CREDIT_CARD:
        # Handle JSON card data {"number": "...", "exp": "...", "cvc": "..."}
        try:
            card = json.loads(raw_value)
            if isinstance(card, dict) and "number" in card:
                last4 = card["number"][-4:]
                exp = card.get("exp", "**/**")
                return f"****-****-****-{last4} exp {exp}"
        except (json.JSONDecodeError, TypeError):
            pass
        # Fallback: plain card number
        digits = re.sub(r"[^0-9]", "", raw_value)
        if len(digits) >= 4:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"

    elif category == PIICategory.EMAIL:
        parts = raw_value.split("@")
        if len(parts) == 2:
            local = parts[0]
            return f"{local[0]}***@{parts[1]}" if local else f"***@{parts[1]}"
        return "***@***.***"

    elif category == PIICategory.PHONE:
        digits = re.sub(r"[^0-9+]", "", raw_value)
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-***-****"

    elif category == PIICategory.NAME:
        # Handle JSON name data {"first": "...", "last": "..."}
        try:
            name = json.loads(raw_value)
            if isinstance(name, dict) and "first" in name:
                first = name["first"]
                last = name.get("last", "")
                f_mask = f"{first[0]}***" if len(first) > 1 else first
                l_mask = f"{last[0]}***" if len(last) > 1 else last
                return f"{f_mask} {l_mask}".strip()
        except (json.JSONDecodeError, TypeError):
            pass
        # Fallback: plain string
        words = raw_value.split()
        masked_words = []
        for word in words:
            if len(word) > 1:
                masked_words.append(f"{word[0]}***")
            else:
                masked_words.append(word)
        return " ".join(masked_words)

    elif category == PIICategory.SSN:
        digits = re.sub(r"[^0-9]", "", raw_value)
        if len(digits) >= 4:
            return f"***-**-{digits[-4:]}"
        return "***-**-****"

    elif category == PIICategory.PASSPORT:
        if len(raw_value) >= 4:
            return f"{'*' * (len(raw_value) - 4)}{raw_value[-4:]}"
        return "****"

    elif category == PIICategory.BANK_ACCOUNT:
        # Handle JSON bank data {"routing": "...", "account": "..."}
        try:
            bank = json.loads(raw_value)
            if isinstance(bank, dict) and "account" in bank:
                acct = bank["account"]
                routing = bank.get("routing", "")
                acct_mask = f"****{acct[-4:]}" if len(acct) >= 4 else "****"
                routing_mask = f"****{routing[-4:]}" if len(routing) >= 4 else "****"
                return f"Routing: {routing_mask} / Acct: {acct_mask}"
        except (json.JSONDecodeError, TypeError):
            pass
        # Fallback: plain account number
        digits = re.sub(r"[^0-9]", "", raw_value)
        if len(digits) >= 4:
            return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
        return "****"

    elif category == PIICategory.ADDRESS:
        # Handle JSON address data {"street": "...", "city": "...", "state": "...", "zip": "..."}
        try:
            addr = json.loads(raw_value)
            if isinstance(addr, dict) and "street" in addr:
                street = addr["street"]
                city = addr.get("city", "")
                state = addr.get("state", "")
                zip_code = addr.get("zip", "")
                # Mask street: keep first number, mask the rest
                street_words = street.split()
                if street_words:
                    masked_street = [street_words[0]]  # Keep street number
                    for w in street_words[1:]:
                        if len(w) > 1:
                            masked_street.append(f"{w[0]}***")
                        else:
                            masked_street.append(w)
                    street_masked = " ".join(masked_street)
                else:
                    street_masked = "****"
                city_masked = f"{city[0]}***" if len(city) > 1 else city
                return f"{street_masked}, {city_masked}, {state} {zip_code}".strip()
        except (json.JSONDecodeError, TypeError):
            pass
        # Fallback: plain string address
        words = raw_value.split()
        if len(words) >= 2:
            masked = [words[0]]  # Keep street number
            for w in words[1:]:
                if re.match(r"^\d{5}", w):  # Keep zip codes
                    masked.append(w)
                elif len(w) > 1:
                    masked.append(f"{w[0]}***")
                else:
                    masked.append(w)
            return " ".join(masked)
        return "****"

    # CUSTOM or fallback
    if len(raw_value) > 4:
        return f"{'*' * (len(raw_value) - 4)}{raw_value[-4:]}"
    return "****"


def domain_matches(domain: str, pattern: str) -> bool:
    """Check if a domain matches a whitelist pattern (supports wildcards).

    *.example.com matches both sub.example.com and example.com itself.
    """
    domain = domain.lower()
    pattern = pattern.lower()
    if fnmatch.fnmatch(domain, pattern):
        return True
    # *.example.com should also match example.com (bare domain)
    if pattern.startswith("*.") and domain == pattern[2:]:
        return True
    return False


async def create_entry(
    db: AsyncSession,
    owner_chat_id: str,
    owner_name: str,
    label: str,
    category: PIICategory,
    raw_value: str,
    agent_id: Optional[str] = None,
    allowed_domains: Optional[list] = None,
    max_uses: Optional[int] = None,
    expires_at: Optional[datetime] = None,
    placeholder_value: Optional[str] = None,
) -> PIIVaultEntry:
    """Create a new encrypted vault entry and return it with its token."""
    token = generate_token()
    encrypted = encrypt_value(raw_value)
    masked = mask_value(raw_value, category)

    entry = PIIVaultEntry(
        id=uuid4(),
        owner_chat_id=str(owner_chat_id),
        owner_name=owner_name,
        agent_id=agent_id,
        label=label,
        category=category,
        token=token,
        encrypted_value=encrypted,
        masked_value=masked,
        allowed_domains=allowed_domains or [],
        max_uses=max_uses,
        expires_at=expires_at,
        placeholder_value=placeholder_value,
    )

    db.add(entry)
    await db.flush()

    logger.info(f"Created vault entry {entry.id} for owner {owner_chat_id}: {label}")
    return entry


async def list_entries(
    db: AsyncSession,
    owner_chat_id: str,
) -> list[PIIVaultEntry]:
    """List vault entries for an owner (masked values only, never decrypted)."""
    stmt = select(PIIVaultEntry).where(
        PIIVaultEntry.owner_chat_id == str(owner_chat_id),
        PIIVaultEntry.is_deleted == False,
    ).order_by(PIIVaultEntry.created_at.desc())

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_entry_by_token(
    db: AsyncSession,
    token: str,
) -> Optional[PIIVaultEntry]:
    """Look up a vault entry by its token."""
    stmt = select(PIIVaultEntry).where(
        PIIVaultEntry.token == token,
        PIIVaultEntry.is_deleted == False,
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def get_entries_by_placeholder(
    db: AsyncSession,
    placeholder_value: str,
    owner_chat_id: Optional[str] = None,
) -> list[PIIVaultEntry]:
    """Look up vault entries by their placeholder value.

    Returns entries whose placeholder_value matches the detected PII value,
    optionally scoped by owner.
    """
    stmt = select(PIIVaultEntry).where(
        PIIVaultEntry.placeholder_value == placeholder_value,
        PIIVaultEntry.is_deleted == False,
    )
    if owner_chat_id:
        stmt = stmt.where(PIIVaultEntry.owner_chat_id == str(owner_chat_id))

    result = await db.execute(stmt)
    return list(result.scalars().all())


async def resolve_placeholders(
    db: AsyncSession,
    placeholder_map: dict[str, str],
    destination_domain: Optional[str] = None,
    requester_chat_id: Optional[str] = None,
    redis=None,
) -> dict[str, dict]:
    """
    Resolve placeholder values to their decrypted vault values.

    Args:
        placeholder_map: dict mapping placeholder_value -> vault_token
        destination_domain: domain for whitelist checking
        requester_chat_id: owner chat ID for ownership enforcement
        redis: redis client for brute-force protection

    Returns a dict mapping placeholder_value -> {value, category, label, masked_value}
    """
    if not placeholder_map:
        return {}

    # Use resolve_tokens for the actual tokens, then re-key by placeholder
    tokens = list(placeholder_map.values())
    resolved_by_token = await resolve_tokens(
        db=db,
        tokens=tokens,
        destination_domain=destination_domain,
        requester_chat_id=requester_chat_id,
        redis=redis,
    )

    resolved = {}
    for placeholder, token in placeholder_map.items():
        if token in resolved_by_token:
            resolved[placeholder] = resolved_by_token[token]

    return resolved


async def delete_entry(
    db: AsyncSession,
    entry_id: str,
    requester_chat_id: str,
) -> bool:
    """Soft-delete a vault entry (ownership check)."""
    from uuid import UUID

    try:
        entry_uuid = UUID(entry_id)
    except ValueError:
        return False

    stmt = select(PIIVaultEntry).where(
        PIIVaultEntry.id == entry_uuid,
        PIIVaultEntry.is_deleted == False,
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()

    if not entry:
        return False

    if entry.owner_chat_id != str(requester_chat_id):
        logger.warning(
            f"Unauthorized vault delete attempt: {requester_chat_id} tried to delete entry owned by {entry.owner_chat_id}"
        )
        return False

    entry.is_deleted = True
    await db.flush()

    logger.info(f"Deleted vault entry {entry_id} by owner {requester_chat_id}")
    return True


async def resolve_tokens(
    db: AsyncSession,
    tokens: list[str],
    destination_domain: Optional[str] = None,
    requester_chat_id: Optional[str] = None,
    redis=None,
) -> dict[str, dict]:
    """
    Resolve vault tokens to their decrypted values.

    Returns a dict mapping token -> {value, category, label, masked_value}
    for each successfully resolved token.

    Checks:
    - Brute-force lockout (if redis provided)
    - Token exists and is not deleted
    - Not expired
    - Domain whitelist (if configured)
    - Max uses not exceeded
    - Ownership (always enforced when requester_chat_id provided)
    """
    resolved = {}

    # Brute-force protection: check lockout
    bf_identifier = requester_chat_id or "anonymous"
    if redis:
        allowed = await check_token_lookup_limit(redis, bf_identifier)
        if not allowed:
            logger.warning(f"Token lookup locked out for: {bf_identifier}")
            return resolved

    has_failures = False

    for token in tokens:
        entry = await get_entry_by_token(db, token)

        if not entry:
            logger.warning(f"Vault token not found: {token}")
            has_failures = True
            continue

        # Enforce ownership check
        if requester_chat_id and entry.owner_chat_id != str(requester_chat_id):
            logger.warning(
                f"Token ownership mismatch: {token} (owner={entry.owner_chat_id}, requester={requester_chat_id})"
            )
            has_failures = True
            continue

        # Check expiration
        if entry.expires_at and datetime.utcnow() > entry.expires_at.replace(tzinfo=None):
            logger.warning(f"Vault token expired: {token}")
            has_failures = True
            continue

        # Check max uses
        if entry.max_uses is not None and entry.use_count >= entry.max_uses:
            logger.warning(f"Vault token max uses exceeded: {token}")
            has_failures = True
            continue

        # Check domain whitelist
        if entry.allowed_domains and destination_domain:
            domain_ok = any(
                domain_matches(destination_domain, pattern)
                for pattern in entry.allowed_domains
            )
            if not domain_ok:
                logger.warning(
                    f"Domain {destination_domain} not in whitelist for token {token}"
                )
                has_failures = True
                continue

        # Decrypt and resolve
        try:
            plaintext = decrypt_value(entry.encrypted_value)
        except Exception as e:
            logger.error(f"Failed to decrypt vault entry {entry.id}: {e}")
            has_failures = True
            continue

        # Update usage tracking
        entry.use_count += 1
        entry.last_used_at = datetime.utcnow()
        if destination_domain:
            entry.last_used_domain = destination_domain

        resolved[token] = {
            "value": plaintext,
            "category": entry.category.value if hasattr(entry.category, "value") else entry.category,
            "label": entry.label,
            "masked_value": entry.masked_value,
        }

    # Record brute-force metrics
    if redis:
        if has_failures and not resolved:
            await record_token_lookup_failure(redis, bf_identifier)
        elif resolved:
            await record_token_lookup_success(redis, bf_identifier)

    if resolved:
        await db.flush()

    return resolved


def find_vault_tokens(text: str) -> list[str]:
    """Find all vault tokens in a text string."""
    return VAULT_TOKEN_REGEX.findall(text)


# ============================================================================
# Brute-force protection for token lookups
# ============================================================================

BRUTE_FORCE_MAX_FAILURES = 5
BRUTE_FORCE_LOCKOUT_SECONDS = 900  # 15 minutes


async def check_token_lookup_limit(redis, identifier: str) -> bool:
    """Check if identifier is locked out from token lookups. Returns True if allowed."""
    lockout_key = f"vault_lockout:{identifier}"
    locked = await redis.get(lockout_key)
    return locked is None


async def record_token_lookup_failure(redis, identifier: str) -> bool:
    """Record a failed token lookup. Returns True if lockout was triggered."""
    failure_key = f"vault_failures:{identifier}"
    count = await redis.get(failure_key)
    count = int(count) if count else 0
    count += 1

    # Set/update the failure counter with 15 min expiry
    await redis.set(failure_key, str(count), expire=BRUTE_FORCE_LOCKOUT_SECONDS)

    if count >= BRUTE_FORCE_MAX_FAILURES:
        # Trigger lockout
        lockout_key = f"vault_lockout:{identifier}"
        await redis.set(lockout_key, "1", expire=BRUTE_FORCE_LOCKOUT_SECONDS)
        logger.warning(f"Vault token lookup lockout triggered for: {identifier}")
        return True

    return False


async def record_token_lookup_success(redis, identifier: str) -> None:
    """Clear failure counter on successful token lookup."""
    failure_key = f"vault_failures:{identifier}"
    await redis.delete(failure_key)
