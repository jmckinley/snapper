"""Rule model for security policy definitions."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional, TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.agents import Agent


class RuleType(str, Enum):
    """Types of security rules."""

    # Command control
    COMMAND_ALLOWLIST = "command_allowlist"
    COMMAND_DENYLIST = "command_denylist"

    # Time-based restrictions
    TIME_RESTRICTION = "time_restriction"

    # Rate limiting
    RATE_LIMIT = "rate_limit"

    # ClawHub skill control
    SKILL_ALLOWLIST = "skill_allowlist"
    SKILL_DENYLIST = "skill_denylist"

    # Security protections
    CREDENTIAL_PROTECTION = "credential_protection"
    NETWORK_EGRESS = "network_egress"
    ORIGIN_VALIDATION = "origin_validation"

    # Approval workflows
    HUMAN_IN_LOOP = "human_in_loop"

    # Access control
    LOCALHOST_RESTRICTION = "localhost_restriction"

    # File system
    FILE_ACCESS = "file_access"

    # Version and environment enforcement (Feb 2026)
    VERSION_ENFORCEMENT = "version_enforcement"
    SANDBOX_REQUIRED = "sandbox_required"


class RuleAction(str, Enum):
    """Action to take when rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    LOG_ONLY = "log_only"


class Rule(Base):
    """
    Security rule definition.

    Rules define security policies for AI agents. They are evaluated
    in priority order (highest first) with deny-by-default semantics.
    """

    __tablename__ = "rules"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Rule identification
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Agent association (null for global rules)
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="Agent this rule applies to, null for global rules",
    )

    # Rule configuration
    rule_type: Mapped[RuleType] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    action: Mapped[RuleAction] = mapped_column(
        String(50),
        default=RuleAction.DENY,
        nullable=False,
    )
    priority: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        index=True,
        comment="Higher priority rules are evaluated first",
    )

    # Rule parameters (type-specific configuration)
    parameters: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Type-specific rule parameters",
    )

    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        index=True,
    )

    # Metadata
    tags: Mapped[List[str]] = mapped_column(
        "tags",
        JSONB,
        default=list,
        nullable=False,
    )
    source: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Origin of rule (manual, template, cve-mitigation, etc.)",
    )
    source_reference: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        comment="Reference ID if created from template or CVE",
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
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )

    # Statistics
    match_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
        comment="Number of times this rule has matched",
    )
    last_matched_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    agent: Mapped[Optional["Agent"]] = relationship(
        "Agent",
        back_populates="rules",
    )

    __table_args__ = (
        Index("ix_rules_agent_type", "agent_id", "rule_type"),
        Index("ix_rules_active_priority", "is_active", "priority"),
        Index("ix_rules_evaluation", "is_active", "is_deleted", "agent_id", "priority"),
    )

    def __repr__(self) -> str:
        return f"<Rule(id={self.id}, name={self.name}, type={self.rule_type})>"

    @property
    def is_global(self) -> bool:
        """Check if this is a global rule (applies to all agents)."""
        return self.agent_id is None


# Rule parameter schemas for validation
RULE_PARAMETER_SCHEMAS = {
    RuleType.COMMAND_ALLOWLIST: {
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Regex patterns for allowed commands",
            },
        },
        "required": ["patterns"],
    },
    RuleType.COMMAND_DENYLIST: {
        "type": "object",
        "properties": {
            "patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Regex patterns for denied commands",
            },
        },
        "required": ["patterns"],
    },
    RuleType.TIME_RESTRICTION: {
        "type": "object",
        "properties": {
            "allowed_hours": {
                "type": "object",
                "properties": {
                    "start": {"type": "integer", "minimum": 0, "maximum": 23},
                    "end": {"type": "integer", "minimum": 0, "maximum": 23},
                },
            },
            "allowed_days": {
                "type": "array",
                "items": {"type": "integer", "minimum": 0, "maximum": 6},
                "description": "0=Monday, 6=Sunday",
            },
            "timezone": {"type": "string", "default": "UTC"},
        },
    },
    RuleType.RATE_LIMIT: {
        "type": "object",
        "properties": {
            "max_requests": {"type": "integer", "minimum": 1},
            "window_seconds": {"type": "integer", "minimum": 1},
            "scope": {
                "type": "string",
                "enum": ["agent", "ip", "user"],
                "default": "agent",
            },
        },
        "required": ["max_requests", "window_seconds"],
    },
    RuleType.SKILL_ALLOWLIST: {
        "type": "object",
        "properties": {
            "skills": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of allowed ClawHub skill IDs",
            },
            "allow_verified_only": {"type": "boolean", "default": True},
        },
    },
    RuleType.SKILL_DENYLIST: {
        "type": "object",
        "properties": {
            "skills": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of denied ClawHub skill IDs",
            },
            "auto_block_flagged": {
                "type": "boolean",
                "default": True,
                "description": "Automatically block skills flagged as malicious",
            },
        },
    },
    RuleType.CREDENTIAL_PROTECTION: {
        "type": "object",
        "properties": {
            "protected_patterns": {
                "type": "array",
                "items": {"type": "string"},
                "description": "File patterns to protect (e.g., *.pem, .env)",
            },
            "block_plaintext_secrets": {"type": "boolean", "default": True},
        },
    },
    RuleType.NETWORK_EGRESS: {
        "type": "object",
        "properties": {
            "allowed_hosts": {
                "type": "array",
                "items": {"type": "string"},
            },
            "denied_hosts": {
                "type": "array",
                "items": {"type": "string"},
            },
            "allowed_ports": {
                "type": "array",
                "items": {"type": "integer"},
            },
        },
    },
    RuleType.ORIGIN_VALIDATION: {
        "type": "object",
        "properties": {
            "allowed_origins": {
                "type": "array",
                "items": {"type": "string"},
            },
            "strict_mode": {
                "type": "boolean",
                "default": True,
                "description": "Reject requests with missing Origin header",
            },
        },
        "required": ["allowed_origins"],
    },
    RuleType.HUMAN_IN_LOOP: {
        "type": "object",
        "properties": {
            "require_approval_for": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["file_write", "network", "shell", "credential_access"],
                },
            },
            "timeout_seconds": {"type": "integer", "default": 300},
            "auto_deny_on_timeout": {"type": "boolean", "default": True},
        },
    },
    RuleType.LOCALHOST_RESTRICTION: {
        "type": "object",
        "properties": {
            "enabled": {"type": "boolean", "default": True},
            "allowed_ips": {
                "type": "array",
                "items": {"type": "string"},
                "default": ["127.0.0.1", "::1"],
            },
        },
    },
    RuleType.FILE_ACCESS: {
        "type": "object",
        "properties": {
            "allowed_paths": {
                "type": "array",
                "items": {"type": "string"},
            },
            "denied_paths": {
                "type": "array",
                "items": {"type": "string"},
            },
            "read_only_paths": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
    },
    RuleType.VERSION_ENFORCEMENT: {
        "type": "object",
        "properties": {
            "minimum_versions": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Map of agent_type to minimum version (e.g., {'openclaw': '2026.1.29'})",
            },
            "blocked_versions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific versions to block entirely",
            },
            "allow_unknown_version": {
                "type": "boolean",
                "default": False,
                "description": "Whether to allow agents that don't report a version",
            },
        },
        "required": ["minimum_versions"],
    },
    RuleType.SANDBOX_REQUIRED: {
        "type": "object",
        "properties": {
            "allowed_environments": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["container", "vm", "sandbox"],
                },
                "default": ["container", "vm", "sandbox"],
                "description": "Execution environments that satisfy sandbox requirement",
            },
            "allow_unknown": {
                "type": "boolean",
                "default": False,
                "description": "Whether to allow agents with unknown execution environment",
            },
        },
    },
}
