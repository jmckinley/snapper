"""Security issue and CVE tracking models."""

import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class IssueSeverity(str, Enum):
    """Security issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueStatus(str, Enum):
    """Security issue status."""

    ACTIVE = "active"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    IGNORED = "ignored"


class SecurityIssue(Base):
    """
    Security vulnerability or issue tracking.

    Tracks CVEs, security advisories, and other vulnerabilities
    that may affect AI agents.
    """

    __tablename__ = "security_issues"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Issue identification
    cve_id: Mapped[Optional[str]] = mapped_column(
        String(50),
        nullable=True,
        unique=True,
        index=True,
        comment="CVE identifier if applicable",
    )
    title: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Severity assessment
    severity: Mapped[IssueSeverity] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
        comment="CVSS v3.1 base score",
    )
    cvss_vector: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="CVSS v3.1 vector string",
    )

    # Status tracking
    status: Mapped[IssueStatus] = mapped_column(
        String(20),
        default=IssueStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    # Affected components
    affected_components: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
    )
    affected_versions: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
    )

    # Mitigation
    mitigation_rules: Mapped[List[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)),
        default=list,
        nullable=False,
        comment="Rule IDs that mitigate this issue",
    )
    auto_generate_rules: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Whether to auto-generate mitigation rules",
    )
    mitigation_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Source information
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Source of vulnerability info (nvd, github, manual)",
    )
    source_url: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
    )
    references: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
    )

    # Additional details
    details: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )
    tags: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,
        nullable=False,
    )

    # Timestamps
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    mitigated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
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

    __table_args__ = (
        Index("ix_security_issues_active", "status", "severity"),
    )

    def __repr__(self) -> str:
        return f"<SecurityIssue(id={self.id}, cve_id={self.cve_id}, severity={self.severity})>"


class MaliciousSkill(Base):
    """
    Tracked malicious or suspicious ClawHub skill.

    Maintains a database of skills that have been flagged
    as potentially dangerous.
    """

    __tablename__ = "malicious_skills"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Skill identification
    skill_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="ClawHub skill identifier",
    )
    skill_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    author: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    repository_url: Mapped[Optional[str]] = mapped_column(
        String(1000),
        nullable=True,
    )

    # Classification
    threat_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Type of threat (data_exfil, backdoor, credential_theft, etc.)",
    )
    severity: Mapped[IssueSeverity] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    confidence: Mapped[str] = mapped_column(
        String(20),
        default="medium",
        nullable=False,
        comment="Detection confidence (low, medium, high, confirmed)",
    )

    # Analysis
    analysis_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    indicators: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Indicators of compromise found",
    )

    # Status
    is_blocked: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether threat has been manually verified",
    )

    # Source
    reported_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Detection source (scan, user_report, intel_feed)",
    )

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_malicious_skills_blocked", "is_blocked", "severity"),
    )

    def __repr__(self) -> str:
        return f"<MaliciousSkill(skill_id={self.skill_id}, threat={self.threat_type})>"


class SecurityRecommendation(Base):
    """
    AI-generated security recommendation.

    Provides actionable security suggestions based on
    agent configuration and threat intelligence.
    """

    __tablename__ = "security_recommendations"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Target
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="Agent this recommendation applies to, null for global",
    )

    # Recommendation details
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Why this recommendation is important",
    )

    # Severity and impact
    severity: Mapped[IssueSeverity] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    impact_score: Mapped[int] = mapped_column(
        default=50,
        nullable=False,
        comment="Impact on security score if implemented (0-100)",
    )

    # Implementation
    recommended_rules: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Suggested rule configurations",
    )
    is_one_click: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Whether recommendation can be applied with one click",
    )

    # Status
    is_applied: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    is_dismissed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    applied_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    applied_rule_ids: Mapped[List[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)),
        default=list,
        nullable=False,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    __table_args__ = (
        Index("ix_recommendations_pending", "is_applied", "is_dismissed", "severity"),
    )

    def __repr__(self) -> str:
        return f"<SecurityRecommendation(id={self.id}, title={self.title})>"
