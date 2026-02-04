"""Pydantic schemas for audit endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.audit_logs import AuditAction, AuditSeverity


class AuditLogResponse(BaseModel):
    """Schema for audit log response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    action: AuditAction
    severity: AuditSeverity
    agent_id: Optional[UUID] = None
    rule_id: Optional[UUID] = None
    user_id: Optional[UUID] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None
    origin: Optional[str] = None
    user_agent: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    created_at: datetime


class AuditLogListResponse(BaseModel):
    """Schema for paginated audit log list."""

    items: List[AuditLogResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AuditLogFilterRequest(BaseModel):
    """Schema for filtering audit logs."""

    agent_id: Optional[UUID] = None
    rule_id: Optional[UUID] = None
    action: Optional[AuditAction] = None
    severity: Optional[AuditSeverity] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    request_id: Optional[str] = None
    ip_address: Optional[str] = None


class ViolationResponse(BaseModel):
    """Schema for policy violation response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    violation_type: str
    severity: AuditSeverity
    agent_id: Optional[UUID] = None
    rule_id: Optional[UUID] = None
    audit_log_id: Optional[UUID] = None
    description: str
    context: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    request_id: Optional[str] = None
    is_resolved: bool
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    resolution_notes: Optional[str] = None
    created_at: datetime


class ViolationListResponse(BaseModel):
    """Schema for paginated violation list."""

    items: List[ViolationResponse]
    total: int
    page: int
    page_size: int
    pages: int
    unresolved_count: int


class ViolationResolve(BaseModel):
    """Schema for resolving a violation."""

    resolution_notes: Optional[str] = Field(None, max_length=1000)


class AlertResponse(BaseModel):
    """Schema for alert response."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_type: str
    severity: AuditSeverity
    agent_id: Optional[UUID] = None
    violation_id: Optional[UUID] = None
    title: str
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    notification_channels: List[str] = Field(default_factory=list)
    notification_sent_at: Optional[datetime] = None
    is_acknowledged: bool
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[UUID] = None
    created_at: datetime


class AlertListResponse(BaseModel):
    """Schema for paginated alert list."""

    items: List[AlertResponse]
    total: int
    page: int
    page_size: int
    pages: int
    unacknowledged_count: int


class AlertAcknowledge(BaseModel):
    """Schema for acknowledging an alert."""

    notes: Optional[str] = Field(None, max_length=500)


class ComplianceReportResponse(BaseModel):
    """Schema for compliance report."""

    report_period_start: datetime
    report_period_end: datetime
    generated_at: datetime

    # Summary statistics
    total_agents: int
    active_agents: int
    total_rules: int
    active_rules: int

    # Enforcement statistics
    total_evaluations: int
    requests_allowed: int
    requests_denied: int
    requests_pending_approval: int

    # Violation statistics
    total_violations: int
    violations_by_severity: Dict[str, int]
    violations_by_type: Dict[str, int]
    unresolved_violations: int

    # Alert statistics
    total_alerts: int
    alerts_by_severity: Dict[str, int]
    unacknowledged_alerts: int

    # Security metrics
    security_score_average: float
    cves_mitigated: int
    malicious_skills_blocked: int

    # Detailed breakdowns
    top_violated_rules: List[Dict[str, Any]]
    top_violating_agents: List[Dict[str, Any]]
    enforcement_by_rule_type: Dict[str, Dict[str, int]]
