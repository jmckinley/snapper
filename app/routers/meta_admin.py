"""Meta admin API for platform operations: org provisioning, impersonation, user management."""

import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
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
    ImpersonateRequest,
    ImpersonateResponse,
    MetaFeatureUpdate,
    MetaOrgDetail,
    MetaOrgListItem,
    MetaOrgUpdate,
    MetaUserItem,
    MetaUserUpdate,
    PlatformStats,
    ProvisionOrgRequest,
    ProvisionOrgResponse,
)
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

    stmt = stmt.order_by(Organization.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    orgs = result.scalars().all()

    items = []
    for org in orgs:
        # Count members
        member_count = (
            await db.execute(
                select(func.count(OrganizationMembership.id)).where(
                    OrganizationMembership.organization_id == org.id
                )
            )
        ).scalar() or 0

        # Count agents
        agent_count = (
            await db.execute(
                select(func.count(Agent.id)).where(
                    Agent.organization_id == org.id,
                    Agent.is_deleted == False,
                )
            )
        ).scalar() or 0

        # Find owner
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

        items.append(
            MetaOrgListItem(
                id=org.id,
                name=org.name,
                slug=org.slug,
                plan_id=org.plan_id,
                is_active=org.is_active,
                member_count=member_count,
                agent_count=agent_count,
                owner_email=owner_email,
                created_at=org.created_at,
            )
        )

    return items


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
