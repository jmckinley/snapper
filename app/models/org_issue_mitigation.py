"""Per-organization CVE/issue mitigation tracking.

SecurityIssue and MaliciousSkill are shared global intelligence.
This model tracks each org's mitigation status independently.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class OrgIssueMitigation(Base):
    """Per-org tracking of whether a global SecurityIssue has been mitigated."""

    __tablename__ = "org_issue_mitigations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    issue_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_issues.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        comment="active | mitigated | ignored",
    )
    mitigated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    rule_ids: Mapped[dict] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment="List of UUID strings for org-specific mitigation rules",
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "issue_id", name="uq_org_issue_mitigation"),
    )

    def __repr__(self) -> str:
        return f"<OrgIssueMitigation(org={self.organization_id}, issue={self.issue_id}, status={self.status})>"
