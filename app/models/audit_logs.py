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
    USER_REGISTERED = "user_registered"
    USER_LOGIN_FAILED = "user_login_failed"
    USER_LOCKED = "user_locked"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"

    # Organization actions
    ORG_CREATED = "org_created"
    ORG_UPDATED = "org_updated"
    ORG_DELETED = "org_deleted"
    ORG_MEMBER_INVITED = "org_member_invited"
    ORG_MEMBER_REMOVED = "org_member_removed"
    ORG_SWITCHED = "org_switched"

    # Key management
    API_KEY_ROTATED = "api_key_rotated"
    VAULT_KEY_ROTATED = "vault_key_rotated"

    # MFA
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"

    # User management
    USER_UNLOCKED = "user_unlocked"
    PASSWORD_CHANGED = "password_changed"
    PROFILE_UPDATED = "profile_updated"
    SESSION_REVOKED = "session_revoked"

    # PII Vault events
    PII_VAULT_CREATED = "pii_vault_created"
    PII_VAULT_ACCESSED = "pii_vault_accessed"
    PII_VAULT_DELETED = "pii_vault_deleted"
    PII_GATE_TRIGGERED = "pii_gate_triggered"
    PII_SUBMISSION_APPROVED = "pii_submission_approved"
    PII_SUBMISSION_DENIED = "pii_submission_denied"

    # Meta admin events
    META_IMPERSONATION_START = "meta_impersonation_start"
    META_IMPERSONATION_STOP = "meta_impersonation_stop"
    META_ORG_PROVISIONED = "meta_org_provisioned"
    META_PLAN_CHANGED = "meta_plan_changed"
    META_FEATURE_FLAG_CHANGED = "meta_feature_flag_changed"

    # Threat detection events
    THREAT_DETECTED = "threat_detected"
    THREAT_SCORE_ELEVATED = "threat_score_elevated"
    THREAT_KILL_CHAIN_COMPLETED = "threat_kill_chain_completed"
    THREAT_AGENT_QUARANTINED = "threat_agent_quarantined"
    THREAT_RESOLVED = "threat_resolved"
    THREAT_FALSE_POSITIVE = "threat_false_positive"


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
        Index("ix_audit_logs_org_action_time", "organization_id", "action", "created_at"),
        Index("ix_audit_logs_org_time", "organization_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, severity={self.severity})>"

    def to_cef(self) -> str:
        """Format this audit log entry as a CEF string for SIEM integration."""
        from app.services.event_publisher import format_cef

        return format_cef(
            action=self.action if isinstance(self.action, str) else self.action.value,
            severity=self.severity if isinstance(self.severity, str) else self.severity.value,
            message=self.message or "",
            agent_id=str(self.agent_id) if self.agent_id else None,
            rule_id=str(self.rule_id) if self.rule_id else None,
            ip_address=self.ip_address,
            user_id=str(self.user_id) if self.user_id else None,
            request_id=self.request_id,
            details=self.details,
            timestamp=self.created_at,
        )


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
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
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
    organization_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
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
