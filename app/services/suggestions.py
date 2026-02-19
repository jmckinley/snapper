"""Smart suggestions engine.

Aggregates signals from existing data sources into prioritized, actionable
suggestions displayed on the dashboard. Each suggestion is dismissible
(stored in Redis with a 30-day TTL).
"""

import hashlib
import logging
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

DISMISS_PREFIX = "dismissed_suggestions:"
DISMISS_TTL_SECONDS = 30 * 24 * 3600  # 30 days
MAX_SUGGESTIONS = 5

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Suggestion:
    id: str
    category: str  # onboarding | security | coverage | performance | feature
    severity: str  # critical | high | medium | low
    icon: str
    title: str
    description: str
    action_label: str
    action_url: str
    action_type: str  # link | api_post | dismiss_only
    metric: Optional[str] = None
    dismissible: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _suggestion_id(key: str) -> str:
    """Generate a stable suggestion ID from a key string."""
    return hashlib.sha256(key.encode()).hexdigest()[:16]


async def _check_learning_mode() -> Optional[Suggestion]:
    """Critical: Learning mode still on — deny rules not enforcing."""
    settings = get_settings()
    if settings.LEARNING_MODE:
        return Suggestion(
            id=_suggestion_id("learning_mode_on"),
            category="security",
            severity="critical",
            icon="\u26a0\ufe0f",
            title="Switch to enforcement mode",
            description="Learning mode is on \u2014 deny rules are logging but not blocking. Switch to enforcement to start protecting your agents.",
            action_label="Go to Settings",
            action_url="/settings",
            action_type="link",
        )
    return None


async def _check_no_rules(db) -> Optional[Suggestion]:
    """Critical: No rules configured at all."""
    try:
        from app.models.rules import Rule
        from sqlalchemy import select, func

        result = await db.execute(
            select(func.count(Rule.id)).where(Rule.is_active == True)
        )
        count = result.scalar() or 0
        if count == 0:
            return Suggestion(
                id=_suggestion_id("no_rules"),
                category="onboarding",
                severity="critical",
                icon="\U0001f6e1\ufe0f",
                title="Create your first security rules",
                description="You don't have any active rules yet. Rules define what your agents can and can't do.",
                action_label="Create Rules",
                action_url="/integrations",
                action_type="link",
            )
    except Exception as e:
        logger.debug(f"Failed to check rules count: {e}")
    return None


async def _check_uncovered_traffic(db) -> Optional[Suggestion]:
    """High: Traffic with no matching rules."""
    try:
        from app.services.traffic_discovery import discover_traffic

        insights = await discover_traffic(db, hours=168)
        if not insights:
            return None

        total_uncovered = insights.total_uncovered

        if total_uncovered > 0:
            return Suggestion(
                id=_suggestion_id("uncovered_traffic"),
                category="coverage",
                severity="high",
                icon="\U0001f4e1",
                title="Uncovered agent commands detected",
                description=f"{total_uncovered} commands have been seen in traffic but have no rules covering them.",
                action_label="Create Rules",
                action_url="/integrations",
                action_type="link",
                metric=f"{total_uncovered} uncovered commands",
            )
    except Exception as e:
        logger.debug(f"Failed to check traffic coverage: {e}")
    return None


async def _check_no_notifications() -> Optional[Suggestion]:
    """High: No notification channel configured."""
    settings = get_settings()
    has_telegram = bool(settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID)
    has_slack = bool(settings.SLACK_BOT_TOKEN and settings.SLACK_APP_TOKEN)
    if not has_telegram and not has_slack:
        return Suggestion(
            id=_suggestion_id("no_notifications"),
            category="onboarding",
            severity="high",
            icon="\U0001f514",
            title="Set up alert notifications",
            description="No Telegram or Slack bot is configured. You won't be notified when agents need approval or trigger blocks.",
            action_label="Configure Alerts",
            action_url="/settings",
            action_type="link",
        )
    return None


async def _check_trust_scoring(db) -> Optional[Suggestion]:
    """High: All agents have trust scoring disabled."""
    try:
        from app.models.agents import Agent, AgentStatus
        from sqlalchemy import select, func

        total = await db.execute(
            select(func.count(Agent.id)).where(
                Agent.deleted_at.is_(None),
                Agent.status == AgentStatus.ACTIVE,
            )
        )
        total_count = total.scalar() or 0
        if total_count == 0:
            return None

        enabled = await db.execute(
            select(func.count(Agent.id)).where(
                Agent.deleted_at.is_(None),
                Agent.status == AgentStatus.ACTIVE,
                Agent.auto_adjust_trust == True,
            )
        )
        enabled_count = enabled.scalar() or 0

        if enabled_count == 0:
            return Suggestion(
                id=_suggestion_id("trust_scoring_disabled"),
                category="feature",
                severity="high",
                icon="\U0001f4ca",
                title="Enable adaptive trust scoring",
                description="Trust scoring adjusts rate limits based on agent behavior, but no agents have it enabled yet.",
                action_label="Manage Agents",
                action_url="/agents",
                action_type="link",
                metric=f"0/{total_count} agents enabled",
            )
    except Exception as e:
        logger.debug(f"Failed to check trust scoring: {e}")
    return None


async def _check_no_approval_policies(db, redis) -> Optional[Suggestion]:
    """High: No approval policies and there are pending approvals."""
    try:
        # Check for pending approvals
        pending_count = 0
        cursor = 0
        while True:
            cursor, keys = await redis.scan(cursor, match="approval:*", count=100)
            pending_count += len(keys)
            if cursor == 0:
                break

        if pending_count == 0:
            return None

        # Check if any org has policies
        from app.models.organizations import Organization
        from sqlalchemy import select

        result = await db.execute(select(Organization).where(Organization.is_active == True))
        orgs = result.scalars().all()

        has_policies = False
        for org in orgs:
            policies = (org.settings or {}).get("approval_policies", [])
            if policies:
                has_policies = True
                break

        if not has_policies:
            return Suggestion(
                id=_suggestion_id("no_approval_policies"),
                category="feature",
                severity="high",
                icon="\u2699\ufe0f",
                title="Automate approvals with policies",
                description="You have pending approvals but no automation policies. Policies can auto-approve safe patterns or auto-deny dangerous ones.",
                action_label="Create Policy",
                action_url="/approvals?tab=policies",
                action_type="link",
                metric=f"{pending_count} pending",
            )
    except Exception as e:
        logger.debug(f"Failed to check approval policies: {e}")
    return None


async def _check_no_webhooks(db) -> Optional[Suggestion]:
    """Medium: No webhooks configured for bot integration."""
    try:
        from app.models.organizations import Organization
        from sqlalchemy import select

        result = await db.execute(select(Organization).where(Organization.is_active == True))
        orgs = result.scalars().all()

        has_webhooks = False
        for org in orgs:
            webhooks = (org.settings or {}).get("webhooks", [])
            if webhooks:
                has_webhooks = True
                break

        if not has_webhooks:
            return Suggestion(
                id=_suggestion_id("no_webhooks"),
                category="feature",
                severity="medium",
                icon="\U0001f517",
                title="Connect an approval bot via webhooks",
                description="Webhooks let external bots receive approval requests and decide automatically.",
                action_label="Add Webhook",
                action_url="/approvals?tab=webhooks",
                action_type="link",
            )
    except Exception as e:
        logger.debug(f"Failed to check webhooks: {e}")
    return None


async def _check_pii_vault_unused(db) -> Optional[Suggestion]:
    """Medium: Agent has traffic but no vault entries."""
    try:
        from app.models.pii_vault import PIIVaultEntry
        from app.models.audit_logs import AuditLog
        from sqlalchemy import select, func

        vault_count = await db.execute(select(func.count(PIIVaultEntry.id)))
        vault_total = vault_count.scalar() or 0

        if vault_total > 0:
            return None

        # Check if there's any traffic at all
        audit_count = await db.execute(select(func.count(AuditLog.id)))
        audit_total = audit_count.scalar() or 0

        if audit_total > 0:
            return Suggestion(
                id=_suggestion_id("pii_vault_unused"),
                category="security",
                severity="medium",
                icon="\U0001f512",
                title="Protect sensitive data with PII Vault",
                description="Your agents are active but no secrets are stored in the PII Vault. Use vault tokens to keep credentials out of agent traffic.",
                action_label="Learn More",
                action_url="/help",
                action_type="link",
            )
    except Exception as e:
        logger.debug(f"Failed to check PII vault: {e}")
    return None


async def _check_no_agents(db) -> Optional[Suggestion]:
    """Critical: No agents registered at all."""
    try:
        from app.models.agents import Agent
        from sqlalchemy import select, func

        result = await db.execute(
            select(func.count(Agent.id)).where(Agent.deleted_at.is_(None))
        )
        count = result.scalar() or 0
        if count == 0:
            return Suggestion(
                id=_suggestion_id("no_agents"),
                category="onboarding",
                severity="critical",
                icon="\U0001f916",
                title="Register your first AI agent",
                description="No agents are connected to Snapper yet. Register an agent to start monitoring and controlling its actions.",
                action_label="Add Agent",
                action_url="/agents",
                action_type="link",
            )
    except Exception as e:
        logger.debug(f"Failed to check agents count: {e}")
    return None


async def _get_dismissed_ids(redis, org_key: str) -> set:
    """Get set of dismissed suggestion IDs from Redis."""
    try:
        members = await redis.smembers(f"{DISMISS_PREFIX}{org_key}")
        if members:
            return {m.decode() if isinstance(m, bytes) else m for m in members}
    except Exception:
        pass
    return set()


async def dismiss_suggestion(redis, org_key: str, suggestion_id: str) -> bool:
    """Mark a suggestion as dismissed for 30 days."""
    key = f"{DISMISS_PREFIX}{org_key}"
    await redis.sadd(key, suggestion_id)
    await redis.expire(key, DISMISS_TTL_SECONDS)
    return True


async def generate_suggestions(
    db,
    redis,
    org_key: str = "default",
) -> List[Suggestion]:
    """Generate prioritized suggestions based on current system state.

    Args:
        db: Async database session
        redis: Redis client
        org_key: Organization identifier for dismiss tracking

    Returns:
        Top MAX_SUGGESTIONS suggestions sorted by severity.
    """
    dismissed = await _get_dismissed_ids(redis, org_key)

    # Run all checks — order doesn't matter, we sort by severity
    checks = [
        _check_learning_mode(),
        _check_no_agents(db),
        _check_no_rules(db),
        _check_uncovered_traffic(db),
        _check_no_notifications(),
        _check_trust_scoring(db),
        _check_no_approval_policies(db, redis),
        _check_no_webhooks(db),
        _check_pii_vault_unused(db),
    ]

    suggestions = []
    for coro in checks:
        try:
            result = await coro
            if result and result.id not in dismissed:
                suggestions.append(result)
        except Exception as e:
            logger.debug(f"Suggestion check failed: {e}")

    # Sort by severity (critical first)
    suggestions.sort(key=lambda s: SEVERITY_ORDER.get(s.severity, 99))

    return suggestions[:MAX_SUGGESTIONS]
