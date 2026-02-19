"""Approval policy CRUD API.

Server-side auto-approve/auto-deny rules stored in Organization.settings["approval_policies"].
Follows the same JSONB pattern as app/routers/webhooks.py.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.organizations import Organization

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/approval-policies", tags=["approvals"])


# --- Schemas ---

class PolicyConditions(BaseModel):
    request_types: Optional[List[str]] = Field(None, description="Filter by request type: command, tool, file_access, etc.")
    command_patterns: Optional[List[str]] = Field(None, description="Regex patterns for command matching")
    tool_names: Optional[List[str]] = Field(None, description="Exact tool name matches")
    min_trust_score: Optional[float] = Field(None, ge=0.0, le=2.0, description="Minimum agent trust score")
    agent_names: Optional[List[str]] = Field(None, description="Specific agent names")


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    conditions: PolicyConditions
    decision: str = Field(..., pattern="^(approve|deny)$", description="Auto-decision: approve or deny")
    priority: int = Field(default=0, ge=0, le=1000)
    max_auto_per_hour: int = Field(default=100, ge=1, le=10000)
    active: bool = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    conditions: Optional[PolicyConditions] = None
    decision: Optional[str] = Field(None, pattern="^(approve|deny)$")
    priority: Optional[int] = Field(None, ge=0, le=1000)
    max_auto_per_hour: Optional[int] = Field(None, ge=1, le=10000)
    active: Optional[bool] = None


class PolicyResponse(BaseModel):
    id: str
    name: str
    conditions: Dict[str, Any]
    decision: str
    priority: int
    max_auto_per_hour: int
    active: bool
    created_at: str
    created_by: Optional[str] = None


class PolicyTestRequest(BaseModel):
    """Dry-run a request against policies."""
    agent_id: Optional[str] = None
    agent_name: str = "test-agent"
    request_type: str = "command"
    command: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[dict] = None
    trust_score: float = 1.0
    has_pii: bool = False


class PolicyTestResponse(BaseModel):
    matched: bool
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    decision: Optional[str] = None
    reason: str


# --- Helpers ---

def _get_org_id(request: Request) -> Optional[str]:
    return getattr(request.state, "org_id", None)


async def _get_org(db: AsyncSession, org_id: str) -> Organization:
    stmt = select(Organization).where(
        Organization.id == uuid.UUID(org_id),
        Organization.is_active == True,
    )
    result = await db.execute(stmt)
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


def _get_policies(org: Organization) -> List[Dict[str, Any]]:
    return (org.settings or {}).get("approval_policies", [])


def _save_policies(org: Organization, policies: List[Dict[str, Any]]) -> None:
    settings = dict(org.settings or {})
    settings["approval_policies"] = policies
    org.settings = settings


def _policy_to_response(p: Dict[str, Any]) -> PolicyResponse:
    return PolicyResponse(
        id=p["id"],
        name=p["name"],
        conditions=p.get("conditions", {}),
        decision=p["decision"],
        priority=p.get("priority", 0),
        max_auto_per_hour=p.get("max_auto_per_hour", 100),
        active=p.get("active", True),
        created_at=p.get("created_at", ""),
        created_by=p.get("created_by"),
    )


# --- Endpoints ---

@router.get("", response_model=List[PolicyResponse], tags=["Core"])
async def list_policies(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all approval policies for the organization."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    policies = _get_policies(org)
    return [_policy_to_response(p) for p in policies]


@router.post("", response_model=PolicyResponse, status_code=201, tags=["Core"])
async def create_policy(
    data: PolicyCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new approval policy."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    policies = _get_policies(org)

    user_id = getattr(request.state, "user_id", None)

    policy = {
        "id": str(uuid.uuid4()),
        "name": data.name,
        "conditions": data.conditions.model_dump(exclude_none=True),
        "decision": data.decision,
        "priority": data.priority,
        "max_auto_per_hour": data.max_auto_per_hour,
        "active": data.active,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": str(user_id) if user_id else None,
    }
    policies.append(policy)
    _save_policies(org, policies)
    await db.flush()

    return _policy_to_response(policy)


@router.put("/{policy_id}", response_model=PolicyResponse, tags=["Core"])
async def update_policy(
    policy_id: str,
    data: PolicyUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update an approval policy."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    policies = _get_policies(org)

    for p in policies:
        if p["id"] == policy_id:
            if data.name is not None:
                p["name"] = data.name
            if data.conditions is not None:
                p["conditions"] = data.conditions.model_dump(exclude_none=True)
            if data.decision is not None:
                p["decision"] = data.decision
            if data.priority is not None:
                p["priority"] = data.priority
            if data.max_auto_per_hour is not None:
                p["max_auto_per_hour"] = data.max_auto_per_hour
            if data.active is not None:
                p["active"] = data.active

            _save_policies(org, policies)
            await db.flush()
            return _policy_to_response(p)

    raise HTTPException(status_code=404, detail="Policy not found")


@router.delete("/{policy_id}", status_code=204, tags=["Core"])
async def delete_policy(
    policy_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete an approval policy."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    policies = _get_policies(org)
    original_len = len(policies)
    policies = [p for p in policies if p["id"] != policy_id]

    if len(policies) == original_len:
        raise HTTPException(status_code=404, detail="Policy not found")

    _save_policies(org, policies)
    await db.flush()
    return None


@router.post("/test", response_model=PolicyTestResponse, tags=["Core"])
async def test_policies(
    data: PolicyTestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Dry-run a request against approval policies without executing anything."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)

    if not org.settings or not org.settings.get("approval_policies_enabled", True):
        return PolicyTestResponse(matched=False, reason="Approval policies are disabled for this organization")

    policies = _get_policies(org)
    if not policies:
        return PolicyTestResponse(matched=False, reason="No approval policies configured")

    from app.services.approval_policies import _evaluate_conditions

    # Sort by priority descending
    sorted_policies = sorted(
        [p for p in policies if p.get("active", True)],
        key=lambda p: p.get("priority", 0),
        reverse=True,
    )

    for policy in sorted_policies:
        conditions = policy.get("conditions", {})
        decision = policy.get("decision", "approve")

        # PII safety
        if data.has_pii and decision == "approve":
            continue

        if _evaluate_conditions(
            conditions,
            data.request_type,
            data.command,
            data.tool_name,
            data.agent_name,
            data.trust_score,
        ):
            return PolicyTestResponse(
                matched=True,
                policy_id=policy["id"],
                policy_name=policy["name"],
                decision=decision,
                reason=f"Policy '{policy['name']}' would {decision} this request",
            )

    return PolicyTestResponse(matched=False, reason="No policy matched the request")
