"""Agent model for Snapper instances."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AgentStatus(str, Enum):
    """Agent operational status."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"
    PENDING = "pending"


class TrustLevel(str, Enum):
    """Agent trust level for rule evaluation."""

    UNTRUSTED = "untrusted"  # Default - most restrictive
    LIMITED = "limited"
    STANDARD = "standard"
    ELEVATED = "elevated"  # Most permissive


class Agent(Base):
    """
    Snapper agent instance.

    Represents a registered Snapper instance that is managed by the Rules Manager.
    Agents have configurable trust levels and security restrictions.
    """

    __tablename__ = "agents"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Agent identification
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique Snapper agent identifier",
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Status and trust
    status: Mapped[AgentStatus] = mapped_column(
        String(50),
        default=AgentStatus.PENDING,
        nullable=False,
        index=True,
    )
    trust_level: Mapped[TrustLevel] = mapped_column(
        String(50),
        default=TrustLevel.UNTRUSTED,
        nullable=False,
    )

    # Security configuration
    allowed_origins: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
        comment="Allowed WebSocket origins for this agent",
    )
    require_localhost_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether agent can only be accessed from localhost",
    )

    # Metadata (use agent_metadata to avoid SQLAlchemy Base.metadata conflict)
    agent_metadata: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    tags: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
    )

    # Rate limiting overrides
    rate_limit_max_requests: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Override default rate limit for this agent",
    )
    rate_limit_window_seconds: Mapped[Optional[int]] = mapped_column(
        nullable=True,
        comment="Override default rate limit window for this agent",
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
    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Last activity tracking
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_rule_evaluation_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    rules: Mapped[List["Rule"]] = relationship(
        "Rule",
        back_populates="agent",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_agents_status_trust", "status", "trust_level"),
        Index("ix_agents_active", "is_deleted", "status"),
    )

    def __repr__(self) -> str:
        return f"<Agent(id={self.id}, name={self.name}, status={self.status})>"

    @property
    def is_active(self) -> bool:
        """Check if agent is active and not deleted."""
        return self.status == AgentStatus.ACTIVE and not self.is_deleted

    def can_access_from_origin(self, origin: str) -> bool:
        """Check if given origin is allowed for this agent."""
        if not self.allowed_origins:
            return False
        return origin in self.allowed_origins
