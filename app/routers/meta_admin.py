"""Meta admin API for platform operations: org provisioning, impersonation, user management."""

import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import case, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import (
    DbSessionDep,
    RequireMetaAdminDep,
    get_impersonation_context,
    require_meta_admin,
    strict_rate_limit,
)
from app.models.agents import Agent
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.organizations import (
    Invitation,
    InvitationStatus,
    Organization,
    OrganizationMembership,
    OrgRole,
    Plan,
    Team,
)
from app.models.rules import Rule
from app.models.users import User
from app.schemas.meta_admin import (
    AgentTypeBreakdown,
    DashboardResponse,
    FunnelStats,
    HourlyEvalBucket,
    ImpersonateRequest,
    ImpersonateResponse,
    MetaFeatureUpdate,
    MetaOrgDetail,
    MetaOrgListItem,
    MetaOrgUpdate,
    MetaUserItem,
    MetaUserUpdate,
    OrgUsageRow,
    PerformanceStats,
    PlatformStats,
    ProvisionOrgRequest,
    ProvisionOrgResponse,
)
from app.models.audit_logs import Alert, PolicyViolation
from app.models.org_issue_mitigation import OrgIssueMitigation
from app.models.pii_vault import PIIVaultEntry
from app.models.security_issues import SecurityRecommendation
from app.models.threat_events import ThreatEvent
from app.services.auth import create_access_token, verify_token

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/meta",
    tags=["Meta Admin"],
    dependencies=[Depends(require_meta_admin), Depends(strict_rate_limit)],
)


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "org"


def _audit(
    action: AuditAction,
    message: str,
    request: Request,
    user_id: uuid.UUID = None,
    org_id: uuid.UUID = None,
    severity: AuditSeverity = AuditSeverity.INFO,
    details: dict = None,
) -> AuditLog:
    """Create an audit log entry with impersonation context."""
    imp_ctx = get_impersonation_context(request)
    merged_details = dict(details or {})
    if imp_ctx:
        merged_details["impersonated_by"] = imp_ctx["impersonated_by"]
    return AuditLog(
        action=action,
        severity=severity,
        message=message,
        user_id=user_id,
        organization_id=org_id,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent", "") or "")[:500],
        endpoint=str(request.url.path),
        method=request.method,
        details=merged_details,
    )


# ---------------------------------------------------------------------------
# 1. Platform stats
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=PlatformStats)
async def platform_stats(
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Platform-wide statistics for the admin overview."""
    orgs = (await db.execute(select(func.count(Organization.id)).where(Organization.deleted_at.is_(None)))).scalar() or 0
    active_orgs = (await db.execute(select(func.count(Organization.id)).where(Organization.deleted_at.is_(None), Organization.is_active == True))).scalar() or 0
    users = (await db.execute(select(func.count(User.id)).where(User.deleted_at.is_(None)))).scalar() or 0
    agents = (await db.execute(select(func.count(Agent.id)).where(Agent.is_deleted == False))).scalar() or 0
    rules = (await db.execute(select(func.count(Rule.id)).where(Rule.is_deleted == False))).scalar() or 0

    # Evaluations in last 24h
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    evals = (
        await db.execute(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == AuditAction.RULE_EVALUATED,
                AuditLog.created_at >= since_24h,
            )
        )
    ).scalar() or 0

    return PlatformStats(
        total_organizations=orgs,
        active_organizations=active_orgs,
        total_users=users,
        total_agents=agents,
        total_rules=rules,
        total_evaluations_24h=evals,
    )


# ---------------------------------------------------------------------------
# 1b. Dashboard (consolidated)
# ---------------------------------------------------------------------------


@router.get("/dashboard", response_model=DashboardResponse)
async def dashboard(
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Consolidated dashboard data: counts, hourly evals, org usage, agent types, funnel."""
    now = datetime.now(timezone.utc)
    since_24h = now - timedelta(hours=24)
    since_7d = now - timedelta(days=7)
    since_30d = now - timedelta(days=30)

    # --- 1. Top-level counts ---
    total_orgs = (await db.execute(
        select(func.count(Organization.id)).where(Organization.deleted_at.is_(None))
    )).scalar() or 0

    active_orgs = (await db.execute(
        select(func.count(Organization.id)).where(
            Organization.deleted_at.is_(None), Organization.is_active == True
        )
    )).scalar() or 0

    total_users = (await db.execute(
        select(func.count(User.id)).where(User.deleted_at.is_(None))
    )).scalar() or 0

    total_agents = (await db.execute(
        select(func.count(Agent.id)).where(Agent.is_deleted == False)
    )).scalar() or 0

    total_rules = (await db.execute(
        select(func.count(Rule.id)).where(Rule.is_deleted == False)
    )).scalar() or 0

    # --- 2. Eval + denial counts (24h) ---
    eval_actions = [
        AuditAction.REQUEST_ALLOWED,
        AuditAction.REQUEST_DENIED,
        AuditAction.REQUEST_PENDING_APPROVAL,
    ]
    eval_rows = (await db.execute(
        select(AuditLog.action, func.count(AuditLog.id))
        .where(AuditLog.action.in_(eval_actions), AuditLog.created_at >= since_24h)
        .group_by(AuditLog.action)
    )).all()

    eval_counts = {row[0]: row[1] for row in eval_rows}
    evals_24h = sum(eval_counts.values())
    denied_24h = eval_counts.get(AuditAction.REQUEST_DENIED, 0)

    # --- 3. Active threats ---
    from app.models.threat_events import ThreatStatus

    active_threats = (await db.execute(
        select(func.count(ThreatEvent.id)).where(
            ThreatEvent.status.in_([ThreatStatus.ACTIVE, ThreatStatus.INVESTIGATING])
        )
    )).scalar() or 0

    # --- 4. Hourly time series (24h) ---
    hourly_rows = (await db.execute(
        select(
            func.date_trunc(literal_column("'hour'"), AuditLog.created_at).label("hour"),
            func.count(case(
                (AuditLog.action == AuditAction.REQUEST_ALLOWED, 1),
            )).label("allowed"),
            func.count(case(
                (AuditLog.action == AuditAction.REQUEST_DENIED, 1),
            )).label("denied"),
            func.count(case(
                (AuditLog.action == AuditAction.REQUEST_PENDING_APPROVAL, 1),
            )).label("pending"),
        )
        .where(AuditLog.action.in_(eval_actions), AuditLog.created_at >= since_24h)
        .group_by("hour")
        .order_by("hour")
    )).all()

    # Build map of actual data
    hourly_map = {}
    for row in hourly_rows:
        h = row[0]
        hourly_map[h.strftime("%Y-%m-%dT%H:00")] = (row[1], row[2], row[3])

    # Pre-fill all 24 hours
    hourly_evals = []
    for i in range(24):
        h = (now - timedelta(hours=23 - i)).replace(minute=0, second=0, microsecond=0)
        key = h.strftime("%Y-%m-%dT%H:00")
        allowed, denied, pending = hourly_map.get(key, (0, 0, 0))
        hourly_evals.append(HourlyEvalBucket(
            hour=key, allowed=allowed, denied=denied, pending=pending
        ))

    # --- 5. Per-org usage (consolidated via subqueries) ---
    agent_counts_sq = (
        select(
            Agent.organization_id.label("org_id"),
            func.count(Agent.id).label("cnt"),
        )
        .where(Agent.is_deleted == False)
        .group_by(Agent.organization_id)
    ).subquery("agent_counts")

    rule_counts_sq = (
        select(
            Rule.organization_id.label("org_id"),
            func.count(Rule.id).label("cnt"),
        )
        .where(Rule.is_deleted == False)
        .group_by(Rule.organization_id)
    ).subquery("rule_counts")

    member_counts_sq = (
        select(
            OrganizationMembership.organization_id.label("org_id"),
            func.count(OrganizationMembership.id).label("cnt"),
        )
        .group_by(OrganizationMembership.organization_id)
    ).subquery("member_counts")

    eval_stats_sq = (
        select(
            AuditLog.organization_id.label("org_id"),
            func.count(case((AuditLog.action.in_(eval_actions), 1))).label("evals"),
            func.count(case((AuditLog.action == AuditAction.REQUEST_DENIED, 1))).label("denied"),
            func.max(AuditLog.created_at).label("last_act"),
        )
        .where(AuditLog.created_at >= since_24h, AuditLog.organization_id.isnot(None))
        .group_by(AuditLog.organization_id)
    ).subquery("eval_stats")

    threat_counts_sq = (
        select(
            ThreatEvent.organization_id.label("org_id"),
            func.count(ThreatEvent.id).label("cnt"),
        )
        .where(ThreatEvent.status.in_([ThreatStatus.ACTIVE, ThreatStatus.INVESTIGATING]))
        .group_by(ThreatEvent.organization_id)
    ).subquery("threat_counts")

    org_stmt = (
        select(
            Organization,
            func.coalesce(agent_counts_sq.c.cnt, 0).label("agent_cnt"),
            func.coalesce(rule_counts_sq.c.cnt, 0).label("rule_cnt"),
            func.coalesce(member_counts_sq.c.cnt, 0).label("member_cnt"),
            func.coalesce(eval_stats_sq.c.evals, 0).label("org_evals"),
            func.coalesce(eval_stats_sq.c.denied, 0).label("org_denied"),
            func.coalesce(threat_counts_sq.c.cnt, 0).label("org_threats"),
            eval_stats_sq.c.last_act.label("last_activity"),
        )
        .outerjoin(agent_counts_sq, Organization.id == agent_counts_sq.c.org_id)
        .outerjoin(rule_counts_sq, Organization.id == rule_counts_sq.c.org_id)
        .outerjoin(member_counts_sq, Organization.id == member_counts_sq.c.org_id)
        .outerjoin(eval_stats_sq, Organization.id == eval_stats_sq.c.org_id)
        .outerjoin(threat_counts_sq, Organization.id == threat_counts_sq.c.org_id)
        .where(Organization.deleted_at.is_(None))
        .order_by(func.coalesce(eval_stats_sq.c.evals, 0).desc())
        .limit(50)
    )

    org_rows = (await db.execute(org_stmt)).all()

    org_usage = [
        OrgUsageRow(
            org_id=row[0].id,
            org_name=row[0].name,
            plan_id=row[0].plan_id,
            is_active=row[0].is_active,
            agent_count=row[1],
            rule_count=row[2],
            user_count=row[3],
            evals_24h=row[4],
            denied_24h=row[5],
            threats_active=row[6],
            last_activity=row[7],
        )
        for row in org_rows
    ]

    # --- 6. Agent type breakdown ---
    type_rows = (await db.execute(
        select(
            func.coalesce(Agent.agent_type, "unknown").label("atype"),
            func.count(Agent.id).label("total"),
            func.count(case(
                (Agent.status == "active", 1),
            )).label("active"),
        )
        .where(Agent.is_deleted == False)
        .group_by("atype")
        .order_by(func.count(Agent.id).desc())
    )).all()

    agent_types = [
        AgentTypeBreakdown(agent_type=r[0], count=r[1], active_count=r[2])
        for r in type_rows
    ]

    # --- 7. Customer funnel ---
    inv_sent = (await db.execute(
        select(func.count(Invitation.id)).where(Invitation.created_at >= since_30d)
    )).scalar() or 0

    inv_accepted = (await db.execute(
        select(func.count(Invitation.id)).where(
            Invitation.status == InvitationStatus.ACCEPTED,
            Invitation.created_at >= since_30d,
        )
    )).scalar() or 0

    registrations = (await db.execute(
        select(func.count(User.id)).where(
            User.deleted_at.is_(None),
            User.created_at >= since_30d,
        )
    )).scalar() or 0

    # Orgs that have at least one eval ever
    orgs_with_eval = (await db.execute(
        select(func.count(func.distinct(AuditLog.organization_id))).where(
            AuditLog.action.in_(eval_actions),
            AuditLog.organization_id.isnot(None),
        )
    )).scalar() or 0

    # Orgs active in last 7 days
    orgs_active_7d = (await db.execute(
        select(func.count(func.distinct(AuditLog.organization_id))).where(
            AuditLog.action.in_(eval_actions),
            AuditLog.organization_id.isnot(None),
            AuditLog.created_at >= since_7d,
        )
    )).scalar() or 0

    funnel = FunnelStats(
        invitations_sent_30d=inv_sent,
        invitations_accepted_30d=inv_accepted,
        registrations_30d=registrations,
        orgs_with_first_eval=orgs_with_eval,
        orgs_active_7d=orgs_active_7d,
    )

    return DashboardResponse(
        total_orgs=total_orgs,
        active_orgs=active_orgs,
        total_users=total_users,
        total_agents=total_agents,
        total_rules=total_rules,
        evals_24h=evals_24h,
        denied_24h=denied_24h,
        active_threats=active_threats,
        hourly_evals=hourly_evals,
        org_usage=org_usage,
        agent_types=agent_types,
        funnel=funnel,
        generated_at=now,
    )


# ---------------------------------------------------------------------------
# 1c. Performance stats (Prometheus)
# ---------------------------------------------------------------------------


@router.get("/dashboard/perf", response_model=PerformanceStats)
async def dashboard_perf(
    admin: RequireMetaAdminDep,
):
    """Performance metrics derived from in-process Prometheus histograms."""
    from app.middleware.metrics import PROMETHEUS_AVAILABLE

    if not PROMETHEUS_AVAILABLE:
        return PerformanceStats()

    from app.middleware.metrics import (
        REQUEST_COUNT,
        REQUEST_LATENCY,
        RULE_EVALUATION_LATENCY,
        RULE_EVALUATIONS,
    )

    def _histogram_stats(histogram) -> tuple[float, float, float]:
        """Extract avg, p95, and total count from a Prometheus Histogram.

        Returns (avg_ms, p95_ms, total_count).
        """
        total_sum = 0.0
        total_count = 0.0
        # Collect all bucket data for P95 calculation
        all_buckets = []

        for metric in histogram.collect():
            for sample in metric.samples:
                if sample.name.endswith("_sum"):
                    total_sum += sample.value
                elif sample.name.endswith("_count"):
                    total_count += sample.value
                elif sample.name.endswith("_bucket"):
                    le = sample.labels.get("le", "")
                    if le != "+Inf":
                        try:
                            all_buckets.append((float(le), sample.value))
                        except (ValueError, TypeError):
                            pass

        if total_count == 0:
            return 0.0, 0.0, 0.0

        avg_ms = (total_sum / total_count) * 1000.0

        # P95 from cumulative histogram buckets
        p95_ms = 0.0
        target = total_count * 0.95
        # Sort by boundary
        all_buckets.sort(key=lambda x: x[0])
        prev_count = 0.0
        prev_bound = 0.0
        for bound, cum_count in all_buckets:
            if cum_count >= target:
                # Linear interpolation within this bucket
                bucket_count = cum_count - prev_count
                if bucket_count > 0:
                    fraction = (target - prev_count) / bucket_count
                    p95_ms = (prev_bound + fraction * (bound - prev_bound)) * 1000.0
                else:
                    p95_ms = bound * 1000.0
                break
            prev_count = cum_count
            prev_bound = bound
        else:
            # All samples beyond last bucket
            p95_ms = avg_ms

        return avg_ms, p95_ms, total_count

    req_avg, req_p95, req_total = _histogram_stats(REQUEST_LATENCY)
    eval_avg, eval_p95, eval_total = _histogram_stats(RULE_EVALUATION_LATENCY)

    # Error rate: count 5xx status codes vs total
    total_requests = 0.0
    error_requests = 0.0
    for metric in REQUEST_COUNT.collect():
        for sample in metric.samples:
            if sample.name.endswith("_total"):
                val = sample.value
                total_requests += val
                status = sample.labels.get("status", "")
                if status.startswith("5"):
                    error_requests += val

    error_rate = (error_requests / total_requests * 100.0) if total_requests > 0 else 0.0

    # Rough requests/min: assume process uptime is proportional to histogram data
    # Use a simple heuristic: total requests / (time since startup in minutes)
    # Since we don't track process start time here, just report raw totals as rate proxy
    # The frontend can compute deltas between refreshes for true rate
    req_per_min = total_requests  # Total count (frontend computes delta)
    eval_per_min = eval_total

    return PerformanceStats(
        avg_request_latency_ms=round(req_avg, 2),
        p95_request_latency_ms=round(req_p95, 2),
        avg_eval_latency_ms=round(eval_avg, 2),
        p95_eval_latency_ms=round(eval_p95, 2),
        requests_per_minute=round(req_per_min, 1),
        evals_per_minute=round(eval_per_min, 1),
        error_rate_pct=round(error_rate, 2),
    )


# ---------------------------------------------------------------------------
# 2. List all orgs
# ---------------------------------------------------------------------------


@router.get("/orgs", response_model=list[MetaOrgListItem])
async def list_orgs(
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
    search: Optional[str] = Query(None),
    plan_id: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List all organizations with optional filters."""
    stmt = select(Organization).where(Organization.deleted_at.is_(None))

    if search:
        term = f"%{search}%"
        stmt = stmt.where(
            Organization.name.ilike(term) | Organization.slug.ilike(term)
        )
    if plan_id:
        stmt = stmt.where(Organization.plan_id == plan_id)
    if is_active is not None:
        stmt = stmt.where(Organization.is_active == is_active)

    # Pre-compute counts via subqueries to avoid N+1 per-org queries
    member_counts_sq = (
        select(
            OrganizationMembership.organization_id.label("org_id"),
            func.count(OrganizationMembership.id).label("cnt"),
        )
        .group_by(OrganizationMembership.organization_id)
    ).subquery("member_counts")

    agent_counts_sq = (
        select(
            Agent.organization_id.label("org_id"),
            func.count(Agent.id).label("cnt"),
        )
        .where(Agent.is_deleted == False)
        .group_by(Agent.organization_id)
    ).subquery("agent_counts")

    # Get owner email per org (first OWNER member)
    owner_sq = (
        select(
            OrganizationMembership.organization_id.label("org_id"),
            func.min(User.email).label("owner_email"),
        )
        .join(User, OrganizationMembership.user_id == User.id)
        .where(OrganizationMembership.role == OrgRole.OWNER)
        .group_by(OrganizationMembership.organization_id)
    ).subquery("owners")

    joined_stmt = (
        select(
            Organization,
            func.coalesce(member_counts_sq.c.cnt, 0).label("member_cnt"),
            func.coalesce(agent_counts_sq.c.cnt, 0).label("agent_cnt"),
            owner_sq.c.owner_email,
        )
        .outerjoin(member_counts_sq, Organization.id == member_counts_sq.c.org_id)
        .outerjoin(agent_counts_sq, Organization.id == agent_counts_sq.c.org_id)
        .outerjoin(owner_sq, Organization.id == owner_sq.c.org_id)
        .where(stmt.whereclause)
        .order_by(Organization.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(joined_stmt)
    rows = result.all()

    return [
        MetaOrgListItem(
            id=row[0].id,
            name=row[0].name,
            slug=row[0].slug,
            plan_id=row[0].plan_id,
            is_active=row[0].is_active,
            member_count=row[1],
            agent_count=row[2],
            owner_email=row[3],
            created_at=row[0].created_at,
        )
        for row in rows
    ]


# ---------------------------------------------------------------------------
# 3. Org detail
# ---------------------------------------------------------------------------


@router.get("/orgs/{org_id}", response_model=MetaOrgDetail)
async def get_org_detail(
    org_id: uuid.UUID,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Get detailed information about a specific organization."""
    org = await _get_org(db, org_id)

    member_count = (
        await db.execute(
            select(func.count(OrganizationMembership.id)).where(
                OrganizationMembership.organization_id == org.id
            )
        )
    ).scalar() or 0

    agent_count = (
        await db.execute(
            select(func.count(Agent.id)).where(
                Agent.organization_id == org.id,
                Agent.is_deleted == False,
            )
        )
    ).scalar() or 0

    owner_row = await db.execute(
        select(User.email)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            OrganizationMembership.organization_id == org.id,
            OrganizationMembership.role == OrgRole.OWNER,
        )
        .limit(1)
    )
    owner_email = owner_row.scalar_one_or_none()

    # Usage stats
    from app.services.plans import get_usage

    usage = await get_usage(db, org.id)

    # Recent audit (last 10)
    audit_rows = await db.execute(
        select(AuditLog)
        .where(AuditLog.organization_id == org.id)
        .order_by(AuditLog.created_at.desc())
        .limit(10)
    )
    recent_audit = [
        {
            "id": str(a.id),
            "action": a.action.value if hasattr(a.action, "value") else str(a.action),
            "message": a.message,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in audit_rows.scalars().all()
    ]

    return MetaOrgDetail(
        id=org.id,
        name=org.name,
        slug=org.slug,
        plan_id=org.plan_id,
        is_active=org.is_active,
        member_count=member_count,
        agent_count=agent_count,
        owner_email=owner_email,
        created_at=org.created_at,
        allowed_email_domains=org.allowed_email_domains or [],
        max_seats=org.max_seats,
        feature_overrides=org.feature_overrides or {},
        settings=org.settings or {},
        subscription_status=org.subscription_status,
        stripe_customer_id=org.stripe_customer_id,
        usage=usage,
        recent_audit=recent_audit,
    )


# ---------------------------------------------------------------------------
# 4. Provision org
# ---------------------------------------------------------------------------


@router.post("/provision-org", response_model=ProvisionOrgResponse, status_code=201)
async def provision_org(
    request: Request,
    body: ProvisionOrgRequest,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """
    Provision a new organization and invite the owner.

    Creates the org, default team, and sends an invitation email to the owner.
    """
    # Validate plan exists
    plan = await db.execute(select(Plan).where(Plan.id == body.plan_id))
    if not plan.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Plan '{body.plan_id}' not found")

    # Generate slug
    slug = body.slug or _slugify(body.name)
    existing = await db.execute(select(Organization).where(Organization.slug == slug))
    if existing.scalar_one_or_none():
        slug = f"{slug}-{secrets.token_hex(3)}"

    # Create organization
    org = Organization(
        id=uuid.uuid4(),
        name=body.name,
        slug=slug,
        plan_id=body.plan_id,
        is_active=True,
        allowed_email_domains=body.allowed_email_domains,
        max_seats=body.max_seats,
        feature_overrides=body.feature_overrides,
        settings=body.settings,
    )

    # Set trial if specified
    if body.trial_days:
        org.subscription_status = "trialing"
        org.plan_period_end = datetime.now(timezone.utc) + timedelta(days=body.trial_days)

    db.add(org)
    await db.flush()

    # Create default team
    team = Team(
        id=uuid.uuid4(),
        organization_id=org.id,
        name="General",
        slug="general",
        is_default=True,
    )
    db.add(team)

    # Create invitation for the owner
    inv_token = secrets.token_urlsafe(32)
    invitation = Invitation(
        id=uuid.uuid4(),
        organization_id=org.id,
        email=body.owner_email.lower().strip(),
        role=OrgRole.OWNER,
        token=inv_token,
        invited_by=admin.id,
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(days=14),
    )
    db.add(invitation)
    await db.flush()

    # Send provisioning email
    from app.services.email import send_org_provisioned

    send_org_provisioned(
        to=body.owner_email,
        org_name=body.name,
        plan_name=body.plan_id,
        token=inv_token,
    )

    # Audit
    db.add(
        _audit(
            AuditAction.META_ORG_PROVISIONED,
            f"Provisioned org '{body.name}' with owner {body.owner_email}",
            request,
            user_id=admin.id,
            org_id=org.id,
            details={
                "plan_id": body.plan_id,
                "owner_email": body.owner_email,
                "trial_days": body.trial_days,
            },
        )
    )

    return ProvisionOrgResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        plan_id=org.plan_id,
        is_active=org.is_active,
        allowed_email_domains=org.allowed_email_domains or [],
        max_seats=org.max_seats,
        invitation_token=inv_token,
        owner_email=body.owner_email,
        created_at=org.created_at,
    )


# ---------------------------------------------------------------------------
# 5. Update org
# ---------------------------------------------------------------------------


@router.patch("/orgs/{org_id}", response_model=MetaOrgDetail)
async def update_org(
    org_id: uuid.UUID,
    body: MetaOrgUpdate,
    request: Request,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Update an organization's name, plan, status, domains, seats, features, or settings."""
    org = await _get_org(db, org_id)
    changes = {}

    if body.name is not None:
        changes["name"] = {"old": org.name, "new": body.name}
        org.name = body.name
    if body.plan_id is not None and body.plan_id != org.plan_id:
        # Validate plan exists
        p = await db.execute(select(Plan).where(Plan.id == body.plan_id))
        if not p.scalar_one_or_none():
            raise HTTPException(400, detail=f"Plan '{body.plan_id}' not found")
        changes["plan_id"] = {"old": org.plan_id, "new": body.plan_id}
        org.plan_id = body.plan_id
        db.add(
            _audit(
                AuditAction.META_PLAN_CHANGED,
                f"Plan changed for '{org.name}': {changes['plan_id']['old']} -> {body.plan_id}",
                request,
                user_id=admin.id,
                org_id=org.id,
            )
        )
    if body.is_active is not None:
        changes["is_active"] = {"old": org.is_active, "new": body.is_active}
        org.is_active = body.is_active
    if body.allowed_email_domains is not None:
        changes["allowed_email_domains"] = {
            "old": org.allowed_email_domains,
            "new": body.allowed_email_domains,
        }
        org.allowed_email_domains = body.allowed_email_domains
    if body.max_seats is not None:
        changes["max_seats"] = {"old": org.max_seats, "new": body.max_seats}
        org.max_seats = body.max_seats
    if body.feature_overrides is not None:
        changes["feature_overrides"] = {
            "old": org.feature_overrides,
            "new": body.feature_overrides,
        }
        org.feature_overrides = body.feature_overrides
    if body.settings is not None:
        changes["settings"] = {"old": org.settings, "new": body.settings}
        org.settings = body.settings

    if not changes:
        raise HTTPException(400, detail="No fields to update")

    await db.flush()

    db.add(
        _audit(
            AuditAction.ORG_UPDATED,
            f"Meta admin updated org '{org.name}'",
            request,
            user_id=admin.id,
            org_id=org.id,
            details={"changes": changes},
        )
    )

    # Return refreshed detail
    return await get_org_detail(org_id, admin, db)


# ---------------------------------------------------------------------------
# 6. Feature flags
# ---------------------------------------------------------------------------


@router.patch("/orgs/{org_id}/features")
async def update_features(
    org_id: uuid.UUID,
    body: MetaFeatureUpdate,
    request: Request,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Toggle per-org feature flags."""
    org = await _get_org(db, org_id)

    old_overrides = dict(org.feature_overrides or {})
    new_overrides = dict(old_overrides)
    new_overrides.update(body.features)
    org.feature_overrides = new_overrides
    await db.flush()

    db.add(
        _audit(
            AuditAction.META_FEATURE_FLAG_CHANGED,
            f"Feature flags updated for '{org.name}'",
            request,
            user_id=admin.id,
            org_id=org.id,
            details={"old": old_overrides, "new": new_overrides},
        )
    )

    return {"message": "Feature flags updated", "feature_overrides": new_overrides}


# ---------------------------------------------------------------------------
# 7. Impersonate
# ---------------------------------------------------------------------------


@router.post("/impersonate", response_model=ImpersonateResponse)
async def impersonate(
    request: Request,
    response: Response,
    body: ImpersonateRequest,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """
    Start impersonating an organization.

    Issues a scoped JWT with the target org context and the admin's real user ID
    stored in the 'imp' claim. Cookie TTL is limited.
    """
    settings = get_settings()
    org = await _get_org(db, body.org_id)

    if not org.is_active:
        raise HTTPException(400, detail="Cannot impersonate a suspended organization")

    ttl = getattr(settings, "META_ADMIN_IMPERSONATION_TIMEOUT_MINUTES", 60)

    # Issue impersonation token: admin user in target org as "owner"
    access_token = create_access_token(
        user_id=admin.id,
        org_id=org.id,
        role="owner",
        is_meta_admin=True,
        impersonating_user_id=str(admin.id),
        expire_minutes=ttl,
    )

    # Set cookie with shorter TTL
    response.set_cookie(
        key="snapper_access_token",
        value=access_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=ttl * 60,
    )

    # Audit
    db.add(
        _audit(
            AuditAction.META_IMPERSONATION_START,
            f"Meta admin started impersonating org '{org.name}'",
            request,
            user_id=admin.id,
            org_id=org.id,
            severity=AuditSeverity.WARNING,
        )
    )

    return ImpersonateResponse(org_id=org.id, org_name=org.name)


# ---------------------------------------------------------------------------
# 8. Stop impersonation
# ---------------------------------------------------------------------------


@router.post("/stop-impersonation")
async def stop_impersonation(
    request: Request,
    response: Response,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Revert from impersonation back to the admin's own org context."""
    settings = get_settings()
    imp = getattr(request.state, "impersonating_user_id", None)
    if not imp:
        raise HTTPException(400, detail="Not currently impersonating")

    # Get admin's default org
    default_org = admin.default_organization_id
    if not default_org:
        raise HTTPException(500, detail="Admin has no default organization")

    # Issue a fresh token for the admin's own org
    access_token = create_access_token(
        user_id=admin.id,
        org_id=default_org,
        role="owner",
        is_meta_admin=True,
    )

    response.set_cookie(
        key="snapper_access_token",
        value=access_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    # Audit
    db.add(
        _audit(
            AuditAction.META_IMPERSONATION_STOP,
            "Meta admin stopped impersonation",
            request,
            user_id=admin.id,
            severity=AuditSeverity.WARNING,
        )
    )

    return {"message": "Impersonation stopped", "org_id": str(default_org)}


# ---------------------------------------------------------------------------
# 9. Search users across all orgs
# ---------------------------------------------------------------------------


@router.get("/users", response_model=list[MetaUserItem])
async def list_users(
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search users across all organizations."""
    stmt = select(User).where(User.deleted_at.is_(None))

    if search:
        term = f"%{search}%"
        stmt = stmt.where(User.email.ilike(term) | User.username.ilike(term))
    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)

    stmt = stmt.order_by(User.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    users = result.scalars().all()

    items = []
    for u in users:
        # Get org names
        org_rows = await db.execute(
            select(Organization.name)
            .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
            .where(OrganizationMembership.user_id == u.id, Organization.deleted_at.is_(None))
        )
        org_names = [row[0] for row in org_rows.all()]

        items.append(
            MetaUserItem(
                id=u.id,
                email=u.email,
                username=u.username,
                full_name=u.full_name,
                is_active=u.is_active,
                is_meta_admin=u.is_meta_admin,
                last_login_at=u.last_login_at,
                created_at=u.created_at,
                organizations=org_names,
            )
        )

    return items


# ---------------------------------------------------------------------------
# 10. Update user
# ---------------------------------------------------------------------------


@router.patch("/users/{user_id}")
async def update_user(
    user_id: uuid.UUID,
    body: MetaUserUpdate,
    request: Request,
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
):
    """Suspend/unsuspend a user or force password reset."""
    stmt = select(User).where(User.id == user_id, User.deleted_at.is_(None))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, detail="User not found")

    changes = {}
    if body.is_active is not None:
        changes["is_active"] = {"old": user.is_active, "new": body.is_active}
        user.is_active = body.is_active
    if body.require_password_change is not None:
        changes["require_password_change"] = {
            "old": user.require_password_change,
            "new": body.require_password_change,
        }
        user.require_password_change = body.require_password_change

    if not changes:
        raise HTTPException(400, detail="No fields to update")

    await db.flush()

    action = "suspended" if body.is_active is False else "updated"
    db.add(
        _audit(
            AuditAction.ORG_UPDATED,
            f"Meta admin {action} user {user.email}",
            request,
            user_id=admin.id,
            severity=AuditSeverity.WARNING,
            details={"target_user_id": str(user_id), "changes": changes},
        )
    )

    return {"message": f"User {action}", "user_id": str(user_id), "changes": changes}


# ---------------------------------------------------------------------------
# 11. Cross-org audit log search
# ---------------------------------------------------------------------------


@router.get("/audit")
async def search_audit(
    admin: RequireMetaAdminDep,
    db: DbSessionDep,
    org_id: Optional[uuid.UUID] = Query(None),
    user_id: Optional[uuid.UUID] = Query(None),
    action: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """Search audit logs across all organizations."""
    stmt = select(AuditLog)

    if org_id:
        stmt = stmt.where(AuditLog.organization_id == org_id)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if severity:
        stmt = stmt.where(AuditLog.severity == severity)
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            stmt = stmt.where(AuditLog.created_at >= since_dt)
        except ValueError:
            pass

    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [
        {
            "id": str(log.id),
            "organization_id": str(log.organization_id) if log.organization_id else None,
            "action": log.action.value if hasattr(log.action, "value") else str(log.action),
            "severity": log.severity.value if hasattr(log.severity, "value") else str(log.severity),
            "message": log.message,
            "user_id": str(log.user_id) if log.user_id else None,
            "agent_id": str(log.agent_id) if log.agent_id else None,
            "details": log.details,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


# ---------------------------------------------------------------------------
# Test Cleanup
# ---------------------------------------------------------------------------

TEST_PREFIXES = ("e2e-", "e2emua", "e2emub", "e2emeta", "e2epw", "pw-reg-",
                 "pwreg", "meta-test-", "metatest", "e2e-meta-test-org")


@router.post("/cleanup-test", openapi_extra={"x-internal": True})
async def cleanup_test_data(
    db: DbSessionDep,
    meta_admin: RequireMetaAdminDep,
    confirm: bool = Query(False),
):
    """Hard-delete all test users, orgs, and related data created by E2E tests.

    Matches users/orgs whose email, username, slug, or name start with known
    test prefixes. Protected real data: john@greatfallsventures.com, Default
    Organization, all agents.
    """
    if not confirm:
        return {"message": "Pass ?confirm=true to actually delete test data."}

    # Find test users
    user_conditions = [User.email.ilike(f"{p}%") for p in TEST_PREFIXES]
    user_conditions += [User.username.ilike(f"{p}%") for p in TEST_PREFIXES]
    from sqlalchemy import or_
    test_users = (await db.execute(
        select(User).where(or_(*user_conditions))
    )).scalars().all()

    test_user_ids = [u.id for u in test_users]

    # Find test orgs (by slug or name prefix)
    org_conditions = [Organization.slug.ilike(f"{p}%") for p in TEST_PREFIXES]
    org_conditions += [Organization.name.ilike(f"{p}%") for p in TEST_PREFIXES]
    org_conditions += [Organization.name.ilike("E2E %")]
    org_conditions += [Organization.name.ilike("Updated Meta Test%")]
    test_orgs = (await db.execute(
        select(Organization).where(or_(*org_conditions))
    )).scalars().all()

    test_org_ids = [o.id for o in test_orgs]

    if not test_user_ids and not test_org_ids:
        return {"message": "No test data found.", "deleted": {}}

    deleted = {}

    # Delete related data for test orgs (SET NULL FKs won't cascade)
    if test_org_ids:
        for model, label in [
            (Rule, "rules"),
            (AuditLog, "audit_logs"),
            (Alert, "alerts"),
            (PolicyViolation, "policy_violations"),
            (SecurityRecommendation, "security_recommendations"),
            (PIIVaultEntry, "pii_vault_entries"),
            (OrgIssueMitigation, "org_issue_mitigations"),
            (ThreatEvent, "threat_events"),
        ]:
            if hasattr(model, "organization_id"):
                result = await db.execute(
                    select(func.count()).select_from(model).where(
                        model.organization_id.in_(test_org_ids)
                    )
                )
                count = result.scalar()
                if count:
                    await db.execute(
                        model.__table__.delete().where(
                            model.organization_id.in_(test_org_ids)
                        )
                    )
                    deleted[label] = count

        # Delete test orgs (CASCADE handles memberships, teams, invitations)
        for org in test_orgs:
            await db.delete(org)
        deleted["organizations"] = len(test_orgs)

    # Delete test users
    if test_user_ids:
        for user in test_users:
            await db.delete(user)
        deleted["users"] = len(test_users)

    await db.commit()

    logging.getLogger(__name__).info(
        "Meta admin test cleanup by %s: %s", meta_admin.email, deleted
    )
    return {"message": "Test data cleaned up.", "deleted": deleted}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_org(db: AsyncSession, org_id: uuid.UUID) -> Organization:
    """Fetch an organization or raise 404."""
    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id, Organization.deleted_at.is_(None)
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(404, detail="Organization not found")
    return org
