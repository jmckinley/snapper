"""Approval policy evaluation engine.

Evaluates server-side auto-approve/auto-deny policies at approval-creation time.
Policies are stored in Organization.settings["approval_policies"] JSONB.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.config import get_settings

logger = logging.getLogger(__name__)

# Default max auto-approvals per policy per hour
DEFAULT_POLICY_HOURLY_CAP = 100


class PolicyMatch:
    """Result of a policy evaluation."""

    def __init__(self, policy_id: str, policy_name: str, decision: str):
        self.policy_id = policy_id
        self.policy_name = policy_name
        self.decision = decision


def _matches_patterns(value: Optional[str], patterns: List[str]) -> bool:
    """Check if a value matches any regex pattern in the list."""
    if not value or not patterns:
        return False
    for pattern in patterns:
        try:
            if re.search(pattern, value):
                return True
        except re.error:
            logger.warning(f"Invalid regex in approval policy: {pattern}")
    return False


def _evaluate_conditions(
    conditions: Dict[str, Any],
    request_type: str,
    command: Optional[str],
    tool_name: Optional[str],
    agent_name: str,
    trust_score: float,
) -> bool:
    """Check if all conditions in a policy match the request.

    All specified conditions must match (AND logic).
    Unspecified conditions are treated as matching.
    """
    # request_types filter
    request_types = conditions.get("request_types")
    if request_types and request_type not in request_types:
        return False

    # command_patterns filter (regex allowlist)
    command_patterns = conditions.get("command_patterns")
    if command_patterns:
        if not command or not _matches_patterns(command, command_patterns):
            return False

    # tool_names filter (exact match)
    tool_names = conditions.get("tool_names")
    if tool_names:
        if not tool_name or tool_name not in tool_names:
            return False

    # min_trust_score threshold
    min_trust = conditions.get("min_trust_score")
    if min_trust is not None:
        if trust_score < min_trust:
            return False

    # agent_names filter
    agent_names = conditions.get("agent_names")
    if agent_names:
        if agent_name not in agent_names:
            return False

    return True


async def _check_policy_safety_brake(redis, policy_id: str, max_per_hour: int) -> bool:
    """Check and increment per-policy hourly counter. Returns True if within limit."""
    key = f"policy_count:{policy_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)
    return count <= max_per_hour


async def evaluate_approval_policies(
    db,
    organization_id: Optional[str],
    approval_data: Dict[str, Any],
    agent,
    redis=None,
) -> Optional[PolicyMatch]:
    """Evaluate approval policies for an organization.

    Args:
        db: Database session
        organization_id: Org to load policies from
        approval_data: Dict with keys: request_type, command, tool_name, tool_input,
                       vault_tokens, pii_context
        agent: Agent ORM object (has name, trust_score)
        redis: Redis client for safety brake counters

    Returns:
        PolicyMatch if a policy auto-decides, None if no policy matches.
    """
    if not organization_id:
        return None

    # Load org and check kill switch
    try:
        from app.models.organizations import Organization
        from sqlalchemy import select

        stmt = select(Organization).where(Organization.id == UUID(organization_id))
        result = await db.execute(stmt)
        org = result.scalar_one_or_none()
        if not org or not org.settings:
            return None

        if not org.settings.get("approval_policies_enabled", True):
            return None

        policies = org.settings.get("approval_policies", [])
        if not policies:
            return None
    except Exception as e:
        logger.warning(f"Failed to load approval policies: {e}")
        return None

    # Hard rule: policies NEVER auto-approve when vault_tokens present (PII)
    vault_tokens = approval_data.get("vault_tokens") or []
    has_pii = bool(vault_tokens)

    # Sort by priority descending
    sorted_policies = sorted(
        [p for p in policies if p.get("active", True)],
        key=lambda p: p.get("priority", 0),
        reverse=True,
    )

    request_type = approval_data.get("request_type", "")
    command = approval_data.get("command")
    tool_name = approval_data.get("tool_name")
    agent_name = getattr(agent, "name", "")
    trust_score = getattr(agent, "trust_score", 1.0)

    for policy in sorted_policies:
        conditions = policy.get("conditions", {})
        decision = policy.get("decision", "approve")
        policy_id = policy.get("id", "unknown")
        policy_name = policy.get("name", "Unnamed Policy")

        # PII safety: policies cannot auto-approve PII requests
        if has_pii and decision == "approve":
            continue

        if not _evaluate_conditions(
            conditions, request_type, command, tool_name, agent_name, trust_score
        ):
            continue

        # Safety brake: check per-policy hourly cap
        max_per_hour = policy.get("max_auto_per_hour", DEFAULT_POLICY_HOURLY_CAP)
        if redis:
            within_limit = await _check_policy_safety_brake(redis, policy_id, max_per_hour)
            if not within_limit:
                logger.warning(f"Policy {policy_name} ({policy_id}) hit safety brake ({max_per_hour}/hour)")
                continue

        logger.info(f"Approval policy matched: {policy_name} ({policy_id}) -> {decision}")
        return PolicyMatch(policy_id=policy_id, policy_name=policy_name, decision=decision)

    return None
