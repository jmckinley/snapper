"""Shadow AI detection model.

Tracks discoveries of unauthorized AI tools, models, and services
found via network, process, or container scanning.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ShadowAIStatus(str, Enum):
    """Resolution status of a shadow AI detection."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class ShadowAIDetection(Base):
    """
    A detected instance of unauthorized AI tool usage.

    Findings can come from local scans (process/network/container)
    or from remote discovery agents reporting via the /shadow-ai/report
    endpoint.
    """

    __tablename__ = "shadow_ai_detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Classification
    detection_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="process | network | dns | container | mcp_server",
    )

    # Process-level detail
    process_name: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    pid: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    command_line: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )

    # Network-level detail
    destination: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
        comment="IP:port or domain for network detections",
    )

    # Container-level detail
    container_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )
    container_image: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )

    # Source host
    host_identifier: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Hostname or container ID of the scanning host",
    )

    # Extra metadata
    details: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        default=dict,
        nullable=True,
    )

    # Status / resolution
    status: Mapped[ShadowAIStatus] = mapped_column(
        String(20),
        default=ShadowAIStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    resolved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Occurrence tracking
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )

    # Organization scope
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
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

    __table_args__ = (
        Index("ix_shadow_ai_host_type", "host_identifier", "detection_type"),
        Index("ix_shadow_ai_status_time", "status", "last_seen_at"),
        Index("ix_shadow_ai_org_status", "organization_id", "status"),
    )

    def __repr__(self) -> str:
        return (
            f"<ShadowAIDetection(id={self.id}, type={self.detection_type}, "
            f"status={self.status}, host={self.host_identifier})>"
        )
