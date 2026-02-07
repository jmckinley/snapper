"""Agent model for Snapper instances."""

import secrets
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


def generate_api_key() -> str:
    """Generate a secure API key with snp_ prefix."""
    return f"snp_{secrets.token_urlsafe(32)}"


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


class ExecutionEnvironment(str, Enum):
    """Agent execution environment for sandbox enforcement."""

    UNKNOWN = "unknown"       # Not reported - treated as untrusted
    BARE_METAL = "bare_metal" # Running directly on host
    CONTAINER = "container"   # Docker/Podman container
    VM = "vm"                 # Virtual machine
    SANDBOX = "sandbox"       # Dedicated sandbox environment


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
    owner_chat_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Telegram chat ID of the agent owner for per-user notifications",
    )
    external_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Unique Snapper agent identifier",
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # API Key for authentication
    api_key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
        index=True,
        default=generate_api_key,
        comment="API key for agent authentication (snp_...)",
    )
    api_key_last_used: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Last time the API key was used",
    )

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

    # Version and environment tracking (for enforcement rules)
    agent_version: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        comment="Reported agent version (e.g., 2026.1.29)",
    )
    agent_type: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Agent framework type (openclaw, claude-code, cursor, etc.)",
    )
    execution_environment: Mapped[ExecutionEnvironment] = mapped_column(
        String(50),
        default=ExecutionEnvironment.UNKNOWN,
        nullable=False,
        comment="Reported execution environment for sandbox enforcement",
    )

    # Trust scoring (auto-adjusting based on behavior)
    trust_score: Mapped[float] = mapped_column(
        default=1.0,
        nullable=False,
        comment="Adaptive trust score (0.0-1.0), reduced on violations",
    )
    auto_adjust_trust: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether to auto-reduce trust score on denials",
    )
    violation_count: Mapped[int] = mapped_column(
        default=0,
        nullable=False,
        comment="Number of rule violations by this agent",
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
