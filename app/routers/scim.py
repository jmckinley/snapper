"""SCIM 2.0 Service Provider endpoints.

Enables automated user provisioning/deprovisioning from identity providers
like Okta, Entra ID, and OneLogin. Per-org SCIM bearer token auth.

RFC 7644: https://datatracker.ietf.org/doc/html/rfc7644
"""

import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.organizations import Organization, OrganizationMembership, OrgRole
from app.models.users import User
from app.services.auth import hash_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scim/v2", tags=["scim"])


# --- Auth ---

async def verify_scim_token(
    db: AsyncSession, token: str
) -> Organization:
    """Verify SCIM bearer token and return the associated organization."""
    # SCIM tokens are stored in org.settings["scim_bearer_token"]
    stmt = select(Organization).where(
        Organization.is_active == True,
        Organization.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    orgs = result.scalars().all()

    for org in orgs:
        scim_token = (org.settings or {}).get("scim_bearer_token")
        if scim_token and scim_token == token:
            return org

    raise HTTPException(status_code=401, detail="Invalid SCIM bearer token")


async def get_scim_org(
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
) -> tuple:
    """Dependency that extracts and verifies SCIM auth, returns (db, org)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization[7:]
    org = await verify_scim_token(db, token)
    return db, org


# --- SCIM Response Helpers ---

def user_to_scim(user: User, membership: Optional[OrganizationMembership] = None) -> Dict[str, Any]:
    """Convert a User to SCIM 2.0 User resource."""
    resource: Dict[str, Any] = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": str(user.id),
        "userName": user.email,
        "active": user.is_active,
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if user.created_at else None,
            "lastModified": user.updated_at.isoformat() if user.updated_at else None,
        },
    }

    if user.full_name:
        parts = user.full_name.split(" ", 1)
        resource["name"] = {
            "givenName": parts[0],
            "familyName": parts[1] if len(parts) > 1 else "",
            "formatted": user.full_name,
        }

    resource["emails"] = [
        {"value": user.email, "primary": True, "type": "work"}
    ]

    if membership:
        resource["roles"] = [{"value": membership.role if isinstance(membership.role, str) else membership.role.value}]

    return resource


def scim_error(status: int, detail: str, scim_type: str = "") -> JSONResponse:
    """Return a SCIM-formatted error response."""
    body: Dict[str, Any] = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": status,
    }
    if scim_type:
        body["scimType"] = scim_type
    return JSONResponse(status_code=status, content=body)


def scim_list_response(
    resources: List[Dict[str, Any]], total: int, start_index: int, count: int
) -> Dict[str, Any]:
    """Build SCIM ListResponse."""
    return {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": count,
        "Resources": resources,
    }


# --- Users ---

@router.get("/Users")
async def list_users(
    request: Request,
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=1000),
    filter: Optional[str] = Query(None),
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """List users in the organization (SCIM 2.0)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    # Build query: users who are members of this org
    base_stmt = (
        select(User, OrganizationMembership)
        .join(
            OrganizationMembership,
            OrganizationMembership.user_id == User.id,
        )
        .where(
            OrganizationMembership.organization_id == org.id,
            User.deleted_at.is_(None),
        )
    )

    # Handle filter (SCIM filter syntax, basic support)
    if filter:
        # Support: userName eq "email@example.com"
        if "userName eq" in filter:
            email = filter.split('"')[1] if '"' in filter else ""
            if email:
                base_stmt = base_stmt.where(User.email == email.lower())

    # Count
    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    # Paginate
    stmt = base_stmt.offset(startIndex - 1).limit(count)
    result = await db.execute(stmt)
    rows = result.all()

    resources = [user_to_scim(user, membership) for user, membership in rows]
    return scim_list_response(resources, total, startIndex, len(resources))


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Get a single user by ID (SCIM 2.0)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return scim_error(400, "Invalid user ID format")

    stmt = (
        select(User, OrganizationMembership)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            User.id == uid,
            OrganizationMembership.organization_id == org.id,
            User.deleted_at.is_(None),
        )
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        return scim_error(404, "User not found")

    user, membership = row
    return user_to_scim(user, membership)


@router.post("/Users", status_code=201)
async def create_user(
    request: Request,
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Create a user via SCIM provisioning."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    body = await request.json()

    email = body.get("userName", "")
    if not email:
        emails = body.get("emails", [])
        if emails:
            email = emails[0].get("value", "")

    if not email:
        return scim_error(400, "userName (email) is required", "invalidValue")

    email = email.lower().strip()

    # Check if user already exists
    stmt = select(User).where(User.email == email, User.deleted_at.is_(None))
    existing = (await db.execute(stmt)).scalar_one_or_none()

    if existing:
        # Check if already a member
        mem_stmt = select(OrganizationMembership).where(
            OrganizationMembership.user_id == existing.id,
            OrganizationMembership.organization_id == org.id,
        )
        mem = (await db.execute(mem_stmt)).scalar_one_or_none()
        if mem:
            return scim_error(409, "User already exists", "uniqueness")

        # Add membership to existing user
        membership = OrganizationMembership(
            id=uuid.uuid4(),
            user_id=existing.id,
            organization_id=org.id,
            role=OrgRole.MEMBER,
            accepted_at=datetime.now(timezone.utc),
        )
        db.add(membership)
        await db.flush()
        return user_to_scim(existing, membership)

    # Extract name
    name_data = body.get("name", {})
    full_name = name_data.get("formatted") or (
        f"{name_data.get('givenName', '')} {name_data.get('familyName', '')}".strip()
    )

    # Create new user
    username = email.split("@")[0]
    # Ensure uniqueness
    existing_username = (
        await db.execute(select(User).where(User.username == username))
    ).scalar_one_or_none()
    if existing_username:
        username = f"{username}-{uuid.uuid4().hex[:6]}"

    user = User(
        id=uuid.uuid4(),
        email=email,
        username=username,
        password_hash=hash_password(uuid.uuid4().hex),
        full_name=full_name or None,
        is_active=body.get("active", True),
        is_verified=True,
        oauth_provider="scim",
        default_organization_id=org.id,
    )
    db.add(user)
    await db.flush()

    membership = OrganizationMembership(
        id=uuid.uuid4(),
        user_id=user.id,
        organization_id=org.id,
        role=OrgRole.MEMBER,
        accepted_at=datetime.now(timezone.utc),
    )
    db.add(membership)
    await db.flush()

    logger.info(f"SCIM provisioned user {user.id} ({email}) to org {org.id}")
    return JSONResponse(status_code=201, content=user_to_scim(user, membership))


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Replace (update) a user via SCIM."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return scim_error(400, "Invalid user ID format")

    stmt = (
        select(User, OrganizationMembership)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            User.id == uid,
            OrganizationMembership.organization_id == org.id,
            User.deleted_at.is_(None),
        )
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        return scim_error(404, "User not found")

    user, membership = row
    body = await request.json()

    # Update active status
    if "active" in body:
        user.is_active = body["active"]

    # Update name
    name_data = body.get("name", {})
    if name_data:
        full_name = name_data.get("formatted") or (
            f"{name_data.get('givenName', '')} {name_data.get('familyName', '')}".strip()
        )
        if full_name:
            user.full_name = full_name

    await db.flush()
    return user_to_scim(user, membership)


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Patch a user via SCIM (typically used for deactivation)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return scim_error(400, "Invalid user ID format")

    stmt = (
        select(User, OrganizationMembership)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            User.id == uid,
            OrganizationMembership.organization_id == org.id,
            User.deleted_at.is_(None),
        )
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        return scim_error(404, "User not found")

    user, membership = row
    body = await request.json()

    # Process SCIM PatchOp operations
    operations = body.get("Operations", [])
    for op in operations:
        op_type = op.get("op", "").lower()
        path = op.get("path", "")
        value = op.get("value")

        if op_type == "replace":
            if path == "active" or (not path and isinstance(value, dict) and "active" in value):
                active = value if isinstance(value, bool) else value.get("active", True)
                user.is_active = active
            elif path == "name" or (not path and isinstance(value, dict) and "name" in value):
                name_data = value if path == "name" else value.get("name", {})
                full_name = name_data.get("formatted") or (
                    f"{name_data.get('givenName', '')} {name_data.get('familyName', '')}".strip()
                )
                if full_name:
                    user.full_name = full_name

    await db.flush()
    return user_to_scim(user, membership)


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    authorization: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a user (soft delete, keeps audit trail)."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    org = await verify_scim_token(db, authorization[7:])

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return scim_error(400, "Invalid user ID format")

    stmt = (
        select(User, OrganizationMembership)
        .join(OrganizationMembership, OrganizationMembership.user_id == User.id)
        .where(
            User.id == uid,
            OrganizationMembership.organization_id == org.id,
            User.deleted_at.is_(None),
        )
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        return scim_error(404, "User not found")

    user, membership = row
    user.is_active = False
    user.deleted_at = datetime.now(timezone.utc)
    await db.flush()

    logger.info(f"SCIM deprovisioned user {user.id} from org {org.id}")
    return JSONResponse(status_code=204, content=None)
