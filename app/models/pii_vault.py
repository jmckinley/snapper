"""PII Vault model for encrypted storage of sensitive personal data."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class PIICategory(str, Enum):
    """Categories of PII data stored in the vault."""

    CREDIT_CARD = "credit_card"
    NAME = "name"
    ADDRESS = "address"
    PHONE = "phone"
    EMAIL = "email"
    SSN = "ssn"
    PASSPORT = "passport"
    BANK_ACCOUNT = "bank_account"
    CUSTOM = "custom"


class PIIVaultEntry(Base):
    """
    Encrypted PII vault entry.

    Stores sensitive personal data encrypted at rest with AES-256-GCM.
    Legacy entries may use Fernet (AES-128-CBC); the encryption_scheme column
    tracks which scheme each entry uses for backward-compatible decryption.
    Each entry is owned by a specific Telegram user (multi-tenant by chat_id).
    """

    __tablename__ = "pii_vault_entries"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Organization scoping
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Organization this vault entry belongs to",
    )

    # Ownership (multi-tenant keyed by Telegram chat ID)
    owner_chat_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Telegram chat ID of the PII owner",
    )
    owner_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Display name of the PII owner",
    )

    # Agent association (null = usable by any agent)
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Agent this entry is restricted to, null for any agent",
    )

    # Entry details
    label: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable label, e.g. 'John Visa ending 1234'",
    )
    category: Mapped[PIICategory] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Vault token (the reference users give to agents)
    token: Mapped[str] = mapped_column(
        String(52),
        unique=True,
        nullable=False,
        index=True,
        comment="Vault reference token: {{SNAPPER_VAULT:<hex>}}",
    )

    # Placeholder value (safe dummy value agents can use instead of vault token)
    placeholder_value: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Safe dummy value agents use instead of vault token (e.g., Stripe test card 4242424242424242)",
    )

    # Encrypted value (AES-256-GCM; legacy entries may be Fernet)
    encrypted_value: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
        comment="AES-256-GCM encrypted PII value (nonce || ciphertext || tag)",
    )
    encryption_key_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        comment="Version of encryption key used",
    )
    encryption_scheme: Mapped[str] = mapped_column(
        String(20),
        default="aes-256-gcm",
        server_default="aes-256-gcm",
        nullable=False,
        comment="Encryption scheme: 'aes-256-gcm' (current) or 'fernet' (legacy)",
    )

    # Masked display value (safe to show in UI/Telegram)
    masked_value: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Masked display value, e.g. ****-****-****-1234",
    )

    # Domain restrictions
    allowed_domains: Mapped[Optional[list]] = mapped_column(
        JSONB,
        default=list,
        nullable=True,
        comment="Domains where this PII can be submitted, e.g. ['*.expedia.com']",
    )

    # Usage limits
    max_uses: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
        comment="Maximum number of times this entry can be used (null = unlimited)",
    )
    use_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    # Usage tracking
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_used_domain: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )

    # Expiration
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Entry expires after this time (null = no expiration)",
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Soft delete
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_vault_owner_category", "owner_chat_id", "category"),
        Index("ix_vault_active", "is_deleted", "owner_chat_id"),
        Index("ix_vault_placeholder", "placeholder_value", "is_deleted", "owner_chat_id"),
    )

    def __repr__(self) -> str:
        return f"<PIIVaultEntry(id={self.id}, label={self.label}, category={self.category})>"
