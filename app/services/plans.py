"""Plan lookup, quota checking, and feature flags."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.agents import Agent
from app.models.organizations import (
    Organization,
    OrganizationMembership,
    Plan,
    Team,
)
from app.models.pii_vault import PIIVaultEntry
from app.models.rules import Rule

logger = logging.getLogger(__name__)


async def get_plan(db: AsyncSession, plan_id: str) -> Plan:
    """
    Fetch a plan from the database by its ID.

    Raises HTTPException 404 if the plan does not exist.
    """
    result = await db.execute(select(Plan).where(Plan.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise HTTPException(status_code=404, detail=f"Plan '{plan_id}' not found")
    return plan


async def _count_resource(
    db: AsyncSession, org_id: UUID, resource_type: str
) -> int:
    """
    Count existing resources for an organization.

    Supported resource types: agents, rules, vault_entries, team_members, teams.
    """
    if resource_type == "agents":
        stmt = select(func.count()).select_from(Agent).where(
            Agent.organization_id == org_id,
            Agent.is_deleted == False,
        )
    elif resource_type == "rules":
        stmt = select(func.count()).select_from(Rule).where(
            Rule.organization_id == org_id,
            Rule.is_deleted == False,
        )
    elif resource_type == "vault_entries":
        stmt = select(func.count()).select_from(PIIVaultEntry).where(
            PIIVaultEntry.organization_id == org_id,
            PIIVaultEntry.is_deleted == False,
        )
    elif resource_type == "team_members":
        stmt = select(func.count()).select_from(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
        )
    elif resource_type == "teams":
        stmt = select(func.count()).select_from(Team).where(
            Team.organization_id == org_id,
        )
    else:
        raise ValueError(f"Unknown resource type: {resource_type}")

    result = await db.execute(stmt)
    return result.scalar() or 0


def _get_plan_limit(plan: Plan, resource_type: str) -> int:
    """Get the plan limit for a given resource type."""
    limit_map = {
        "agents": plan.max_agents,
        "rules": plan.max_rules,
        "vault_entries": plan.max_vault_entries,
        "team_members": plan.max_team_members,
        "teams": plan.max_teams,
    }
    limit = limit_map.get(resource_type)
    if limit is None:
        raise ValueError(f"Unknown resource type for plan limit: {resource_type}")
    return limit


async def check_quota(
    db: AsyncSession, org_id: UUID, resource_type: str
) -> None:
    """
    Check whether an organization is within its plan quota for a resource type.

    resource_type is one of: "agents", "rules", "vault_entries", "team_members", "teams".

    If the organization exceeds its plan limit, raises HTTPException 402 with
    details about the quota exceeded state.

    A limit of -1 means unlimited. If SELF_HOSTED is True, all checks are skipped.
    """
    if get_settings().SELF_HOSTED:
        return

    # Fetch the organization to get plan_id
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    plan = await get_plan(db, org.plan_id)
    limit = _get_plan_limit(plan, resource_type)

    # Org-level overrides take precedence over plan limits
    org_override_map = {
        "team_members": org.max_seats,
        "agents": org.max_agents_override,
        "rules": org.max_rules_override,
        "vault_entries": org.max_vault_entries_override,
    }
    org_override = org_override_map.get(resource_type)
    if org_override is not None:
        limit = org_override

    # -1 means unlimited
    if limit == -1:
        return

    used = await _count_resource(db, org_id, resource_type)

    if used >= limit:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "quota_exceeded",
                "resource": resource_type,
                "used": used,
                "limit": limit,
                "upgrade_url": "/billing",
            },
        )


async def has_feature(
    db: AsyncSession, org_id: UUID, feature_name: str
) -> bool:
    """
    Check whether an organization has a specific feature enabled.

    Feature resolution order:
    1. Organization-level feature_overrides (takes precedence)
    2. Plan-level features dict

    Returns True if the feature is enabled, False otherwise.
    """
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        return False

    # Check org-level overrides first
    if org.feature_overrides and feature_name in org.feature_overrides:
        return bool(org.feature_overrides[feature_name])

    # Fall back to plan features
    plan = await get_plan(db, org.plan_id)
    if plan.features and feature_name in plan.features:
        return bool(plan.features[feature_name])

    return False


async def get_usage(db: AsyncSession, org_id: UUID) -> dict:
    """
    Return usage counts vs plan limits for all resource types.

    Returns a dict suitable for constructing a UsageResponse.
    """
    # Fetch org and plan
    org_result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    plan = await get_plan(db, org.plan_id)

    # Count all resources
    resource_types = ["agents", "rules", "vault_entries", "team_members", "teams"]
    counts = {}
    for rt in resource_types:
        counts[rt] = await _count_resource(db, org_id, rt)

    def _make_stat(resource_type: str) -> dict:
        limit = _get_plan_limit(plan, resource_type)
        # Org-level overrides
        org_override_map = {
            "team_members": org.max_seats,
            "agents": org.max_agents_override,
            "rules": org.max_rules_override,
            "vault_entries": org.max_vault_entries_override,
        }
        org_override = org_override_map.get(resource_type)
        if org_override is not None:
            limit = org_override
        return {
            "used": counts[resource_type],
            "limit": limit,
            "is_unlimited": limit == -1,
        }

    # Merge plan features with org overrides
    merged_features = dict(plan.features) if plan.features else {}
    if org.feature_overrides:
        merged_features.update(org.feature_overrides)

    return {
        "plan_id": plan.id,
        "plan_name": plan.name,
        "agents": _make_stat("agents"),
        "rules": _make_stat("rules"),
        "vault_entries": _make_stat("vault_entries"),
        "team_members": _make_stat("team_members"),
        "teams": _make_stat("teams"),
        "features": merged_features,
    }
