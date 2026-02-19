"""Threat event model for persistent threat detection storage."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ThreatType(str, Enum):
    """Types of detected threats."""

    DATA_EXFILTRATION = "data_exfiltration"
    PII_MISUSE = "pii_misuse"
    CREDENTIAL_THEFT = "credential_theft"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ENCODED_EXFILTRATION = "encoded_exfiltration"
    VAULT_TOKEN_EXTRACTION = "vault_token_extraction"
    LIVING_OFF_THE_LAND = "living_off_the_land"
    VOLUME_ANOMALY = "volume_anomaly"
    SLOW_DRIP_EXFILTRATION = "slow_drip_exfiltration"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"


class ThreatSeverity(str, Enum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(str, Enum):
    """Threat event lifecycle status."""

    ACTIVE = "active"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ThreatEvent(Base):
    """Persistent threat event record.

    Created when a composite threat score crosses a threshold,
    or when a kill chain completes.
    """

    __tablename__ = "threat_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    agent_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    threat_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    threat_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    kill_chain: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Name of completed kill chain, if any",
    )

    signals: Mapped[list] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment="Contributing signal dicts",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    details: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Baseline stats, anomaly scores, etc.",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default=ThreatStatus.ACTIVE,
        nullable=False,
        index=True,
    )

    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    resolution_notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_threat_events_agent_status", "agent_id", "status"),
        Index("ix_threat_events_severity_time", "severity", "created_at"),
        Index("ix_threat_events_type", "threat_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<ThreatEvent(id={self.id}, type={self.threat_type}, "
            f"severity={self.severity}, score={self.threat_score})>"
        )
