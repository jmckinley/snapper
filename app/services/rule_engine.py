"""Core rule engine for security policy evaluation."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.rules import Rule, RuleAction, RuleType
from app.models.agents import Agent, AgentStatus
from app.redis_client import RedisClient

logger = logging.getLogger(__name__)
settings = get_settings()


class EvaluationDecision(str, Enum):
    """Final decision from rule evaluation."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class EvaluationContext:
    """Context for rule evaluation."""

    agent_id: UUID
    request_type: str  # command, skill, network, file_access, etc.

    # Request details
    command: Optional[str] = None
    skill_id: Optional[str] = None
    target_host: Optional[str] = None
    target_port: Optional[int] = None
    file_path: Optional[str] = None
    file_operation: Optional[str] = None  # read, write, delete

    # Request context
    origin: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None

    # Time context
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EvaluationResult:
    """Result of rule evaluation."""

    decision: EvaluationDecision
    matched_rules: List[UUID] = field(default_factory=list)
    blocking_rule: Optional[UUID] = None
    reason: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    evaluation_time_ms: float = 0.0
    logged: bool = False


class RuleEngine:
    """
    Security rule evaluation engine.

    Implements deny-by-default semantics with priority-based rule evaluation.
    Rules are always loaded fresh from the database to ensure changes take
    effect immediately (caching disabled for security).
    """

    # Rule caching disabled for security - rules must always be evaluated fresh
    # to ensure changes take effect immediately
    CACHE_ENABLED = False

    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis
        self._evaluators = {
            RuleType.COMMAND_ALLOWLIST: self._evaluate_command_allowlist,
            RuleType.COMMAND_DENYLIST: self._evaluate_command_denylist,
            RuleType.TIME_RESTRICTION: self._evaluate_time_restriction,
            RuleType.RATE_LIMIT: self._evaluate_rate_limit,
            RuleType.SKILL_ALLOWLIST: self._evaluate_skill_allowlist,
            RuleType.SKILL_DENYLIST: self._evaluate_skill_denylist,
            RuleType.CREDENTIAL_PROTECTION: self._evaluate_credential_protection,
            RuleType.NETWORK_EGRESS: self._evaluate_network_egress,
            RuleType.ORIGIN_VALIDATION: self._evaluate_origin_validation,
            RuleType.HUMAN_IN_LOOP: self._evaluate_human_in_loop,
            RuleType.LOCALHOST_RESTRICTION: self._evaluate_localhost_restriction,
            RuleType.FILE_ACCESS: self._evaluate_file_access,
        }

    async def evaluate(self, context: EvaluationContext) -> EvaluationResult:
        """
        Evaluate rules for the given context.

        Evaluation algorithm:
        1. Load rules (cached) with inheritance: global -> agent-specific
        2. Sort by priority (descending)
        3. For each rule:
           - If DENY matches -> short-circuit return DENIED
           - If REQUIRE_APPROVAL matches -> return pending approval
           - If ALLOW matches -> mark allow_found=True, continue
        4. If no ALLOW found -> DENY by default (fail-safe)
        """
        start_time = datetime.utcnow()
        result = EvaluationResult(decision=EvaluationDecision.DENY)

        try:
            # Load rules for this agent
            rules = await self._load_rules(context.agent_id)

            if not rules:
                # No rules = deny by default
                result.reason = "No rules configured - deny by default"
                return result

            allow_found = False
            matched_rules: List[UUID] = []

            # Evaluate rules in priority order
            for rule in rules:
                if not rule.is_active:
                    continue

                # Get evaluator for this rule type
                evaluator = self._evaluators.get(rule.rule_type)
                if not evaluator:
                    logger.warning(f"No evaluator for rule type: {rule.rule_type}")
                    continue

                # Evaluate the rule
                matches, action = await evaluator(rule, context)

                if matches:
                    matched_rules.append(rule.id)

                    if action == RuleAction.DENY:
                        # Short-circuit on DENY
                        result.decision = EvaluationDecision.DENY
                        result.blocking_rule = rule.id
                        result.reason = f"Denied by rule: {rule.name}"
                        result.matched_rules = matched_rules
                        return result

                    elif action == RuleAction.REQUIRE_APPROVAL:
                        # Return pending approval
                        result.decision = EvaluationDecision.REQUIRE_APPROVAL
                        result.blocking_rule = rule.id
                        result.reason = f"Requires approval: {rule.name}"
                        result.matched_rules = matched_rules
                        return result

                    elif action == RuleAction.ALLOW:
                        allow_found = True

                    # LOG_ONLY continues evaluation

            # Final decision based on whether any ALLOW rule matched
            if allow_found:
                result.decision = EvaluationDecision.ALLOW
                result.reason = "Allowed by matching rules"
            else:
                result.decision = EvaluationDecision.DENY
                result.reason = "No ALLOW rule matched - deny by default"

            result.matched_rules = matched_rules

        except Exception as e:
            logger.exception(f"Error during rule evaluation: {e}")
            result.decision = EvaluationDecision.DENY
            result.reason = f"Evaluation error - deny by default: {str(e)}"

        finally:
            end_time = datetime.utcnow()
            result.evaluation_time_ms = (end_time - start_time).total_seconds() * 1000

        return result

    async def _load_rules(self, agent_id: UUID) -> List[Rule]:
        """Load rules for agent with inheritance (global + agent-specific)."""
        # Always load fresh from database - caching disabled for security
        # This ensures rule changes take effect immediately
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        ).order_by(Rule.priority.desc())

        result = await self.db.execute(stmt)
        rules = list(result.scalars().all())

        return rules

    async def invalidate_cache(self, agent_id: Optional[UUID] = None):
        """No-op: Rule caching is disabled for security."""
        # Caching disabled - rules are always loaded fresh from database
        pass

    # --- Rule Type Evaluators ---

    async def _evaluate_command_allowlist(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate command allowlist rule."""
        if context.request_type != "command" or not context.command:
            return False, rule.action

        patterns = rule.parameters.get("patterns", [])
        for pattern in patterns:
            try:
                if re.match(pattern, context.command, re.IGNORECASE):
                    return True, rule.action
            except re.error:
                logger.warning(f"Invalid regex pattern in rule {rule.id}: {pattern}")

        return False, rule.action

    async def _evaluate_command_denylist(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate command denylist rule.

        Returns the rule's configured action (deny, require_approval, etc.)
        when a pattern matches, allowing for approval workflows.
        """
        if context.request_type != "command" or not context.command:
            return False, rule.action

        patterns = rule.parameters.get("patterns", [])
        for pattern in patterns:
            try:
                if re.match(pattern, context.command, re.IGNORECASE):
                    return True, rule.action  # Return rule's action (deny, require_approval, etc.)
            except re.error:
                logger.warning(f"Invalid regex pattern in rule {rule.id}: {pattern}")

        return False, rule.action

    async def _evaluate_time_restriction(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate time-based restriction rule."""
        params = rule.parameters
        now = context.timestamp

        # Check allowed hours
        allowed_hours = params.get("allowed_hours")
        if allowed_hours:
            start_hour = allowed_hours.get("start", 0)
            end_hour = allowed_hours.get("end", 23)
            current_hour = now.hour

            if start_hour <= end_hour:
                in_allowed_hours = start_hour <= current_hour <= end_hour
            else:
                # Wrap around (e.g., 22-6)
                in_allowed_hours = current_hour >= start_hour or current_hour <= end_hour

            if not in_allowed_hours:
                return True, RuleAction.DENY

        # Check allowed days
        allowed_days = params.get("allowed_days")
        if allowed_days:
            current_day = now.weekday()  # 0=Monday
            if current_day not in allowed_days:
                return True, RuleAction.DENY

        return False, rule.action

    async def _evaluate_rate_limit(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate rate limit rule."""
        params = rule.parameters
        max_requests = params.get("max_requests", 100)
        window_seconds = params.get("window_seconds", 60)
        scope = params.get("scope", "agent")

        # Build rate limit key based on scope
        if scope == "agent":
            key = f"rate:{context.agent_id}"
        elif scope == "ip":
            key = f"rate:{context.ip_address or 'unknown'}"
        else:
            key = f"rate:{context.agent_id}:{context.ip_address or 'unknown'}"

        allowed, remaining, retry_after = await self.redis.check_rate_limit(
            key=key,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

        if not allowed:
            return True, RuleAction.DENY

        return False, rule.action

    async def _evaluate_skill_allowlist(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate ClawHub skill allowlist rule."""
        if context.request_type != "skill" or not context.skill_id:
            return False, rule.action

        params = rule.parameters
        allowed_skills = params.get("skills", [])
        allow_verified_only = params.get("allow_verified_only", True)

        if context.skill_id in allowed_skills:
            return True, rule.action

        # If verified-only mode, this would check skill verification status
        # For now, return false as skill not in allowlist
        return False, rule.action

    async def _evaluate_skill_denylist(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate ClawHub skill denylist rule.

        Supports:
        - Exact skill name matching (blocked_skills)
        - Pattern matching (blocked_patterns) for typosquats
        - Publisher blocking (blocked_publishers) for known bad actors
        """
        if context.request_type != "skill" or not context.skill_id:
            return False, rule.action

        params = rule.parameters
        skill_id = context.skill_id.lower()

        # Check exact match in denied skills list
        denied_skills = params.get("skills", []) or params.get("blocked_skills", [])
        for denied in denied_skills:
            if skill_id == denied.lower():
                return True, rule.action

        # Check pattern matching (for typosquats like clawhub-XXXXX)
        blocked_patterns = params.get("blocked_patterns", [])
        for pattern in blocked_patterns:
            try:
                if re.match(pattern, skill_id, re.IGNORECASE):
                    return True, rule.action
            except re.error:
                logger.warning(f"Invalid regex pattern in skill denylist: {pattern}")

        # Check publisher blocking (skill_id format: publisher/skill-name)
        blocked_publishers = params.get("blocked_publishers", [])
        if "/" in skill_id:
            publisher = skill_id.split("/")[0]
            if publisher.lower() in [p.lower() for p in blocked_publishers]:
                return True, rule.action

        # Check database for flagged malicious skills
        auto_block_flagged = params.get("auto_block_flagged", True)
        if auto_block_flagged:
            from app.models.security_issues import MaliciousSkill
            stmt = select(MaliciousSkill).where(
                MaliciousSkill.skill_id == skill_id,
                MaliciousSkill.is_blocked == True,
            )
            result = await self.db.execute(stmt)
            if result.scalar_one_or_none():
                return True, rule.action

        return False, rule.action

    async def _evaluate_credential_protection(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate credential protection rule."""
        if context.request_type not in ("file_access", "command"):
            return False, rule.action

        params = rule.parameters
        protected_patterns = params.get("protected_patterns", [
            r"\.env$",
            r"\.pem$",
            r"\.key$",
            r"credentials\.json$",
            r"secrets\.ya?ml$",
            r"\.aws/credentials$",
            r"\.ssh/",
        ])

        # Check file path
        target = context.file_path or context.command or ""

        for pattern in protected_patterns:
            try:
                if re.search(pattern, target, re.IGNORECASE):
                    return True, RuleAction.DENY
            except re.error:
                pass

        return False, rule.action

    async def _evaluate_network_egress(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate network egress rule."""
        if context.request_type != "network" or not context.target_host:
            return False, rule.action

        params = rule.parameters
        allowed_hosts = params.get("allowed_hosts", [])
        denied_hosts = params.get("denied_hosts", [])
        allowed_ports = params.get("allowed_ports", [])

        # Check denied hosts first
        for host_pattern in denied_hosts:
            if re.match(host_pattern, context.target_host, re.IGNORECASE):
                return True, RuleAction.DENY

        # Check allowed hosts
        if allowed_hosts:
            host_allowed = False
            for host_pattern in allowed_hosts:
                if re.match(host_pattern, context.target_host, re.IGNORECASE):
                    host_allowed = True
                    break
            if not host_allowed:
                return True, RuleAction.DENY

        # Check allowed ports
        if allowed_ports and context.target_port:
            if context.target_port not in allowed_ports:
                return True, RuleAction.DENY

        return False, rule.action

    async def _evaluate_origin_validation(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """
        Evaluate origin validation rule.
        Mitigates CVE-2026-25253 WebSocket RCE.

        Note: This rule type acts as a gate - it can DENY requests with invalid
        origins but does NOT grant ALLOW for valid origins. The actual ALLOW
        must come from other rules (e.g., command_allowlist).
        """
        params = rule.parameters
        allowed_origins = params.get("allowed_origins", [])
        strict_mode = params.get("strict_mode", True)

        # If no origin provided
        if not context.origin:
            if strict_mode:
                return True, RuleAction.DENY
            # Not strict mode - origin check passes, continue evaluation
            return False, rule.action

        # Check if origin is allowed
        if context.origin in allowed_origins:
            # Origin is valid - rule passes but doesn't grant access
            # Other rules must still explicitly ALLOW the request
            return False, rule.action

        # Origin not in allowed list - DENY the request
        return True, RuleAction.DENY

    async def _evaluate_human_in_loop(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate human-in-the-loop approval rule."""
        params = rule.parameters
        require_approval_for = params.get("require_approval_for", [])

        # Map request types to approval categories
        type_mapping = {
            "file_access": "file_write" if context.file_operation == "write" else None,
            "network": "network",
            "command": "shell",
            "credential": "credential_access",
        }

        approval_category = type_mapping.get(context.request_type)
        if approval_category and approval_category in require_approval_for:
            return True, RuleAction.REQUIRE_APPROVAL

        return False, rule.action

    async def _evaluate_localhost_restriction(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """
        Evaluate localhost restriction rule.
        Mitigates authentication bypass vulnerabilities.
        """
        params = rule.parameters
        enabled = params.get("enabled", True)
        allowed_ips = params.get("allowed_ips", ["127.0.0.1", "::1"])

        if not enabled:
            return False, rule.action

        if not context.ip_address:
            return True, RuleAction.DENY

        if context.ip_address in allowed_ips:
            return True, RuleAction.ALLOW

        return True, RuleAction.DENY

    async def _evaluate_file_access(
        self, rule: Rule, context: EvaluationContext
    ) -> tuple[bool, RuleAction]:
        """Evaluate file access rule."""
        if context.request_type != "file_access" or not context.file_path:
            return False, rule.action

        params = rule.parameters
        allowed_paths = params.get("allowed_paths", [])
        denied_paths = params.get("denied_paths", [])
        read_only_paths = params.get("read_only_paths", [])

        file_path = context.file_path

        # Check denied paths first
        for pattern in denied_paths:
            if re.match(pattern, file_path):
                return True, RuleAction.DENY

        # Check read-only paths
        if context.file_operation in ("write", "delete"):
            for pattern in read_only_paths:
                if re.match(pattern, file_path):
                    return True, RuleAction.DENY

        # Check allowed paths
        if allowed_paths:
            path_allowed = False
            for pattern in allowed_paths:
                if re.match(pattern, file_path):
                    path_allowed = True
                    break
            if not path_allowed:
                return True, RuleAction.DENY

        return False, rule.action


async def get_rule_engine(db: AsyncSession, redis: RedisClient) -> RuleEngine:
    """Factory function for rule engine."""
    return RuleEngine(db, redis)
