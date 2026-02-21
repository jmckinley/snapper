"""Pydantic schemas for meta admin API endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# ---------------------------------------------------------------------------
# Dashboard schemas
# ---------------------------------------------------------------------------


class HourlyEvalBucket(BaseModel):
    """One hour of evaluation volume data."""

    hour: str  # ISO format "2026-02-20T14:00"
    allowed: int = 0
    denied: int = 0
    pending: int = 0


class OrgUsageRow(BaseModel):
    """Per-org usage summary for the dashboard table."""

    org_id: UUID
    org_name: str
    plan_id: str
    is_active: bool
    agent_count: int = 0
    rule_count: int = 0
    user_count: int = 0
    evals_24h: int = 0
    denied_24h: int = 0
    threats_active: int = 0
    last_activity: Optional[datetime] = None


class AgentTypeBreakdown(BaseModel):
    """Agent count grouped by framework type."""

    agent_type: str  # "claude-code", "cursor", "openclaw", "unknown"
    count: int
    active_count: int = 0


class FunnelStats(BaseModel):
    """Customer acquisition funnel for the last 30 days."""

    invitations_sent_30d: int = 0
    invitations_accepted_30d: int = 0
    registrations_30d: int = 0
    orgs_with_first_eval: int = 0
    orgs_active_7d: int = 0


class DashboardResponse(BaseModel):
    """Consolidated dashboard data for the admin overview."""

    total_orgs: int
    active_orgs: int
    total_users: int
    total_agents: int
    total_rules: int
    evals_24h: int = 0
    denied_24h: int = 0
    active_threats: int = 0
    hourly_evals: List[HourlyEvalBucket]
    org_usage: List[OrgUsageRow]
    agent_types: List[AgentTypeBreakdown]
    funnel: FunnelStats
    generated_at: datetime


class PerformanceStats(BaseModel):
    """Performance metrics from Prometheus histograms."""

    avg_request_latency_ms: float = 0.0
    p95_request_latency_ms: float = 0.0
    avg_eval_latency_ms: float = 0.0
    p95_eval_latency_ms: float = 0.0
    requests_per_minute: float = 0.0
    evals_per_minute: float = 0.0
    error_rate_pct: float = 0.0


class ProvisionOrgRequest(BaseModel):
    """Request body for provisioning a new organization."""

    name: str = Field(..., min_length=2, max_length=255)
    slug: Optional[str] = Field(None, max_length=100, pattern=r"^[a-z0-9][a-z0-9\-]*$")
    plan_id: str = Field(default="free", max_length=50)
    owner_email: EmailStr
    owner_name: Optional[str] = Field(None, max_length=255)
    allowed_email_domains: List[str] = Field(default_factory=list)
    max_seats: Optional[int] = Field(None, ge=1)
    feature_overrides: Dict[str, Any] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)
    trial_days: Optional[int] = Field(None, ge=1, le=365)


class ProvisionOrgResponse(BaseModel):
    """Response from provisioning a new organization."""

    id: UUID
    name: str
    slug: str
    plan_id: str
    is_active: bool
    allowed_email_domains: List[str]
    max_seats: Optional[int]
    invitation_token: str
    owner_email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MetaOrgListItem(BaseModel):
    """Summary of an organization for list views."""

    id: UUID
    name: str
    slug: str
    plan_id: str
    is_active: bool
    member_count: int = 0
    agent_count: int = 0
    owner_email: Optional[str] = None
    created_at: datetime


class MetaOrgDetail(MetaOrgListItem):
    """Detailed organization info for admin views."""

    allowed_email_domains: List[str] = Field(default_factory=list)
    max_seats: Optional[int] = None
    feature_overrides: Dict[str, Any] = Field(default_factory=dict)
    settings: Dict[str, Any] = Field(default_factory=dict)
    subscription_status: Optional[str] = None
    stripe_customer_id: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    recent_audit: List[Dict[str, Any]] = Field(default_factory=list)


class MetaOrgUpdate(BaseModel):
    """Fields that can be updated on an organization by meta admin."""

    name: Optional[str] = Field(None, min_length=2, max_length=255)
    plan_id: Optional[str] = Field(None, max_length=50)
    is_active: Optional[bool] = None
    allowed_email_domains: Optional[List[str]] = None
    max_seats: Optional[int] = None
    feature_overrides: Optional[Dict[str, Any]] = None
    settings: Optional[Dict[str, Any]] = None


class MetaFeatureUpdate(BaseModel):
    """Toggle individual feature flags for an org."""

    features: Dict[str, bool]


class ImpersonateRequest(BaseModel):
    """Request body for starting impersonation."""

    org_id: UUID


class ImpersonateResponse(BaseModel):
    """Response after starting impersonation."""

    org_id: UUID
    org_name: str
    message: str = "Impersonation started"


class MetaUserItem(BaseModel):
    """User summary for cross-org search."""

    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    is_active: bool
    is_meta_admin: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    organizations: List[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class MetaUserUpdate(BaseModel):
    """Fields meta admin can update on any user."""

    is_active: Optional[bool] = None
    require_password_change: Optional[bool] = None


class PlatformStats(BaseModel):
    """Platform-wide statistics for the admin dashboard."""

    total_organizations: int
    total_users: int
    total_agents: int
    total_rules: int
    total_evaluations_24h: int = 0
    active_organizations: int = 0


class MetaAuditQuery(BaseModel):
    """Query parameters for cross-org audit search."""

    org_id: Optional[UUID] = None
    user_id: Optional[UUID] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    since: Optional[datetime] = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
