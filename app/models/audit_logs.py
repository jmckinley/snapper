"""Audit log model for immutable security event tracking."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AuditAction(str, Enum):
    """Types of auditable actions."""

    # Rule enforcement
    RULE_EVALUATED = "rule_evaluated"
    RULE_MATCHED = "rule_matched"
    REQUEST_ALLOWED = "request_allowed"
    REQUEST_DENIED = "request_denied"
    REQUEST_PENDING_APPROVAL = "request_pending_approval"

    # Rule management
    RULE_CREATED = "rule_created"
    RULE_UPDATED = "rule_updated"
    RULE_DELETED = "rule_deleted"
    RULE_ACTIVATED = "rule_activated"
    RULE_DEACTIVATED = "rule_deactivated"

    # Agent management
    AGENT_REGISTERED = "agent_registered"
    AGENT_UPDATED = "agent_updated"
    AGENT_DELETED = "agent_deleted"
    AGENT_SUSPENDED = "agent_suspended"
    AGENT_ACTIVATED = "agent_activated"
    AGENT_QUARANTINED = "agent_quarantined"

    # Security events
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ORIGIN_VIOLATION = "origin_violation"
    HOST_VIOLATION = "host_violation"
    CREDENTIAL_ACCESS_BLOCKED = "credential_access_blocked"
    MALICIOUS_SKILL_BLOCKED = "malicious_skill_blocked"
    CVE_MITIGATION_TRIGGERED = "cve_mitigation_triggered"
    SECURITY_ALERT = "security_alert"
    PII_PURGE = "pii_purge"
    IP_WHITELIST_CHANGED = "ip_whitelist_changed"

    # System events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGED = "config_changed"
    SECURITY_SCAN_COMPLETED = "security_scan_completed"

    # User actions
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"

    # PII Vault events
    PII_VAULT_CREATED = "pii_vault_created"
    PII_VAULT_ACCESSED = "pii_vault_accessed"
    PII_VAULT_DELETED = "pii_vault_deleted"
    PII_GATE_TRIGGERED = "pii_gate_triggered"
    PII_SUBMISSION_APPROVED = "pii_submission_approved"
    PII_SUBMISSION_DENIED = "pii_submission_denied"


class AuditSeverity(str, Enum):
    """Severity levels for audit events."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AuditLog(Base):
    """
    Immutable audit log entry.

    Audit logs provide a complete trail of security-relevant events
    for compliance and forensic analysis.
    """

    __tablename__ = "audit_logs"

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
        comment="Organization this audit log belongs to",
    )

    # Event classification
    action: Mapped[AuditAction] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        String(20),
        default=AuditSeverity.INFO,
        nullable=False,
        index=True,
    )

    # Associated entities
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # Request context
    request_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        index=True,
        comment="Correlation ID for request tracing",
    )
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
    )
    origin: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    endpoint: Mapped[Optional[str]] = mapped_column(
        String(500),
        nullable=True,
    )
    method: Mapped[Optional[str]] = mapped_column(
        String(10),
        nullable=True,
    )

    # Event details
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
        comment="Additional event-specific details",
    )

    # Change tracking
    old_value: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Previous state for update events",
    )
    new_value: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="New state for update events",
    )

    # Timestamp (immutable)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    __table_args__ = (
        Index("ix_audit_logs_agent_action", "agent_id", "action"),
        Index("ix_audit_logs_severity_time", "severity", "created_at"),
        Index("ix_audit_logs_time_range", "created_at", postgresql_using="brin"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, severity={self.severity})>"


class PolicyViolation(Base):
    """
    Security policy violation record.

    Tracks specific security violations for reporting and alerting.
    """

    __tablename__ = "policy_violations"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Violation classification
    violation_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Associated entities
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    audit_log_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Violation details
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    context: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Request info
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
    )
    request_id: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
    )

    # Status
    is_resolved: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
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

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_violations_unresolved", "is_resolved", "severity"),
    )

    def __repr__(self) -> str:
        return f"<PolicyViolation(id={self.id}, type={self.violation_type})>"


class Alert(Base):
    """
    Security alert for notification.

    Alerts are generated from violations and audit events
    that require immediate attention.
    """

    __tablename__ = "alerts"

    # Primary key
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Alert classification
    alert_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    severity: Mapped[AuditSeverity] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    # Associated entities
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    violation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Alert content
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
        nullable=False,
    )

    # Notification tracking
    notification_channels: Mapped[list] = mapped_column(
        JSONB,
        default=list,
        nullable=False,
        comment="Channels this alert was sent to",
    )
    notification_sent_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Status
    is_acknowledged: Mapped[bool] = mapped_column(
        default=False,
        nullable=False,
    )
    acknowledged_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    acknowledged_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_alerts_unacknowledged", "is_acknowledged", "severity"),
    )

    def __repr__(self) -> str:
        return f"<Alert(id={self.id}, type={self.alert_type}, severity={self.severity})>"
