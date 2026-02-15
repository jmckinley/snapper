"""Organization management API endpoints."""

import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import DbSessionDep, default_rate_limit
from app.models.agents import Agent
from app.models.organizations import (
    Invitation,
    InvitationStatus,
    Organization,
    OrganizationMembership,
    OrgRole,
    Team,
)
from app.models.rules import Rule
from app.models.users import User
from app.schemas.organizations import (
    InviteRequest,
    InviteResponse,
    MemberResponse,
    OrgCreate,
    OrgDetailResponse,
    OrgResponse,
    OrgUpdate,
    UpdateMemberRoleRequest,
    UsageResponse,
)
from app.services.plans import check_quota, get_usage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/organizations", dependencies=[Depends(default_rate_limit)])


# ---------------------------------------------------------------------------
# Role hierarchy helpers
# ---------------------------------------------------------------------------

ROLE_HIERARCHY = {
    OrgRole.OWNER.value: 4,
    OrgRole.ADMIN.value: 3,
    OrgRole.MEMBER.value: 2,
    OrgRole.VIEWER.value: 1,
}


def require_role(current_role: str, min_role: str) -> None:
    """
    Verify that *current_role* meets or exceeds *min_role* in the hierarchy.

    Raises HTTPException 403 if the user's role is insufficient.
    """
    current_level = ROLE_HIERARCHY.get(current_role, 0)
    required_level = ROLE_HIERARCHY.get(min_role, 0)
    if current_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires at least '{min_role}' role. Your role: '{current_role}'.",
        )


# ---------------------------------------------------------------------------
# Auth-context helper dependencies
# ---------------------------------------------------------------------------


async def get_current_user_id(request: Request) -> UUID:
    """Get authenticated user ID from request state (set by auth middleware)."""
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return UUID(str(user_id))


async def get_current_org_id(request: Request) -> UUID:
    """Get current org ID from request state."""
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No organization context",
        )
    return UUID(str(org_id))


async def get_current_role(request: Request) -> str:
    """Get current user's role in the org."""
    return getattr(request.state, "user_role", "viewer")


# ---------------------------------------------------------------------------
# Helper: verify the caller is a member of the target org
# ---------------------------------------------------------------------------


async def _verify_membership(
    db: AsyncSession, user_id: UUID, org_id: UUID
) -> OrganizationMembership:
    """
    Return the membership record if the user belongs to the org.

    Raises 403 if the user is not a member.
    """
    result = await db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == org_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization",
        )
    return membership


# ---------------------------------------------------------------------------
# Slug generation helper
# ---------------------------------------------------------------------------


def _slugify(text: str) -> str:
    """Convert text to a URL-safe slug."""
    import re

    slug = text.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug or "org"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=List[OrgResponse])
async def list_organizations(
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
):
    """List all organizations for the current user."""
    stmt = (
        select(Organization)
        .join(
            OrganizationMembership,
            OrganizationMembership.organization_id == Organization.id,
        )
        .where(
            OrganizationMembership.user_id == user_id,
            Organization.deleted_at.is_(None),
            Organization.is_active == True,
        )
        .order_by(Organization.created_at.asc())
    )
    result = await db.execute(stmt)
    orgs = result.scalars().all()
    return [OrgResponse.model_validate(org) for org in orgs]


@router.post("", response_model=OrgResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrgCreate,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
):
    """
    Create a new organization.

    The creating user becomes the owner. A default team is created automatically.
    """
    import uuid as _uuid

    # Generate slug if not provided
    slug = payload.slug or _slugify(payload.name)

    # Ensure slug uniqueness
    existing = await db.execute(
        select(Organization).where(Organization.slug == slug)
    )
    if existing.scalar_one_or_none():
        slug = f"{slug}-{secrets.token_hex(3)}"

    # Create organization
    org = Organization(
        id=_uuid.uuid4(),
        name=payload.name,
        slug=slug,
        plan_id="free",
        is_active=True,
    )
    db.add(org)
    await db.flush()

    # Create default team
    team = Team(
        id=_uuid.uuid4(),
        organization_id=org.id,
        name="Default",
        slug="default",
        is_default=True,
    )
    db.add(team)

    # Create owner membership
    membership = OrganizationMembership(
        id=_uuid.uuid4(),
        user_id=user_id,
        organization_id=org.id,
        role=OrgRole.OWNER,
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()

    logger.info(f"Organization created: {org.id} ({org.name}) by user {user_id}")
    return OrgResponse.model_validate(org)


@router.get("/{org_id}", response_model=OrgDetailResponse)
async def get_organization(
    org_id: UUID,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
):
    """Get organization details including resource counts."""
    # Verify membership
    await _verify_membership(db, user_id, org_id)

    # Fetch org
    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Counts
    member_count_result = await db.execute(
        select(func.count()).select_from(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
        )
    )
    member_count = member_count_result.scalar() or 0

    agent_count_result = await db.execute(
        select(func.count()).select_from(Agent).where(
            Agent.organization_id == org_id,
            Agent.is_deleted == False,
        )
    )
    agent_count = agent_count_result.scalar() or 0

    rule_count_result = await db.execute(
        select(func.count()).select_from(Rule).where(
            Rule.organization_id == org_id,
            Rule.is_deleted == False,
        )
    )
    rule_count = rule_count_result.scalar() or 0

    return OrgDetailResponse(
        id=org.id,
        name=org.name,
        slug=org.slug,
        plan_id=org.plan_id,
        is_active=org.is_active,
        created_at=org.created_at,
        settings=org.settings or {},
        feature_overrides=org.feature_overrides or {},
        member_count=member_count,
        agent_count=agent_count,
        rule_count=rule_count,
    )


@router.patch("/{org_id}", response_model=OrgResponse)
async def update_organization(
    org_id: UUID,
    payload: OrgUpdate,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    current_role: str = Depends(get_current_role),
):
    """Update organization name or settings. Requires admin or owner role."""
    require_role(current_role, "admin")

    # Verify membership
    await _verify_membership(db, user_id, org_id)

    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if payload.name is not None:
        org.name = payload.name
    if payload.settings is not None:
        org.settings = payload.settings

    await db.flush()
    logger.info(f"Organization updated: {org.id} by user {user_id}")
    return OrgResponse.model_validate(org)


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_organization(
    org_id: UUID,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    current_role: str = Depends(get_current_role),
):
    """Soft-delete an organization. Requires owner role."""
    require_role(current_role, "owner")

    # Verify membership
    await _verify_membership(db, user_id, org_id)

    result = await db.execute(
        select(Organization).where(
            Organization.id == org_id,
            Organization.deleted_at.is_(None),
        )
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    org.deleted_at = datetime.now(timezone.utc)
    org.is_active = False
    await db.flush()

    logger.info(f"Organization soft-deleted: {org.id} by user {user_id}")
    return None


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------


@router.get("/{org_id}/members", response_model=List[MemberResponse])
async def list_members(
    org_id: UUID,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
):
    """List all members of an organization."""
    # Verify caller is a member
    await _verify_membership(db, user_id, org_id)

    stmt = (
        select(
            OrganizationMembership.id,
            OrganizationMembership.user_id,
            User.email,
            User.username,
            OrganizationMembership.role,
            OrganizationMembership.accepted_at,
            OrganizationMembership.created_at,
        )
        .join(User, User.id == OrganizationMembership.user_id)
        .where(OrganizationMembership.organization_id == org_id)
        .order_by(OrganizationMembership.created_at.asc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        MemberResponse(
            id=row.id,
            user_id=row.user_id,
            email=row.email,
            username=row.username,
            role=row.role if isinstance(row.role, str) else row.role.value,
            accepted_at=row.accepted_at,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/{org_id}/members/invite",
    response_model=InviteResponse,
    status_code=status.HTTP_201_CREATED,
)
async def invite_member(
    org_id: UUID,
    payload: InviteRequest,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    current_role: str = Depends(get_current_role),
):
    """
    Invite a user to the organization by email.

    Requires admin or owner role. Checks team_members quota before creating
    the invitation.
    """
    import uuid as _uuid

    require_role(current_role, "admin")

    # Verify membership
    await _verify_membership(db, user_id, org_id)

    # Check quota
    await check_quota(db, org_id, "team_members")

    # Check for existing pending invitation for this email + org
    existing_invite = await db.execute(
        select(Invitation).where(
            Invitation.organization_id == org_id,
            Invitation.email == payload.email,
            Invitation.status == InvitationStatus.PENDING,
        )
    )
    if existing_invite.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A pending invitation already exists for this email",
        )

    # Check if user is already a member
    existing_user = await db.execute(
        select(User).where(User.email == payload.email, User.deleted_at.is_(None))
    )
    user_record = existing_user.scalar_one_or_none()
    if user_record:
        existing_membership = await db.execute(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == user_record.id,
                OrganizationMembership.organization_id == org_id,
            )
        )
        if existing_membership.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User is already a member of this organization",
            )

    # Create invitation
    invitation = Invitation(
        id=_uuid.uuid4(),
        organization_id=org_id,
        email=payload.email,
        role=OrgRole(payload.role),
        token=secrets.token_urlsafe(32),
        invited_by=user_id,
        status=InvitationStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(invitation)
    await db.flush()

    logger.info(
        f"Invitation created: {invitation.id} for {payload.email} "
        f"to org {org_id} by user {user_id}"
    )

    return InviteResponse(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role if isinstance(invitation.role, str) else invitation.role.value,
        status=invitation.status if isinstance(invitation.status, str) else invitation.status.value,
        expires_at=invitation.expires_at,
    )


@router.patch("/{org_id}/members/{member_user_id}", response_model=MemberResponse)
async def update_member_role(
    org_id: UUID,
    member_user_id: UUID,
    payload: UpdateMemberRoleRequest,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    current_role: str = Depends(get_current_role),
):
    """
    Change a member's role. Requires owner role.

    Cannot demote yourself (the owner).
    """
    require_role(current_role, "owner")

    # Verify caller is a member
    await _verify_membership(db, user_id, org_id)

    # Cannot change own role
    if member_user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot change your own role",
        )

    # Fetch target membership
    result = await db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == member_user_id,
            OrganizationMembership.organization_id == org_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Member not found")

    # Update role
    membership.role = OrgRole(payload.role)
    await db.flush()

    # Fetch user details for response
    user_result = await db.execute(
        select(User).where(User.id == member_user_id)
    )
    target_user = user_result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    logger.info(
        f"Member role updated: user {member_user_id} in org {org_id} "
        f"to {payload.role} by user {user_id}"
    )

    return MemberResponse(
        id=membership.id,
        user_id=membership.user_id,
        email=target_user.email,
        username=target_user.username,
        role=membership.role if isinstance(membership.role, str) else membership.role.value,
        accepted_at=membership.accepted_at,
        created_at=membership.created_at,
    )


@router.delete(
    "/{org_id}/members/{member_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_member(
    org_id: UUID,
    member_user_id: UUID,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    current_role: str = Depends(get_current_role),
):
    """
    Remove a member from the organization.

    Requires admin or owner role. Cannot remove the owner.
    """
    require_role(current_role, "admin")

    # Verify caller is a member
    await _verify_membership(db, user_id, org_id)

    # Fetch target membership
    result = await db.execute(
        select(OrganizationMembership).where(
            OrganizationMembership.user_id == member_user_id,
            OrganizationMembership.organization_id == org_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Member not found")

    # Cannot remove the owner
    member_role = membership.role if isinstance(membership.role, str) else membership.role.value
    if member_role == OrgRole.OWNER.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the organization owner",
        )

    await db.delete(membership)
    await db.flush()

    logger.info(
        f"Member removed: user {member_user_id} from org {org_id} by user {user_id}"
    )
    return None


# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------


@router.get("/{org_id}/usage", response_model=UsageResponse)
async def get_organization_usage(
    org_id: UUID,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
):
    """Get quota usage for the organization."""
    # Verify membership
    await _verify_membership(db, user_id, org_id)

    usage_data = await get_usage(db, org_id)
    return UsageResponse(**usage_data)
