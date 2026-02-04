"""Tests for the rule engine."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)


class TestRuleEngine:
    """Tests for RuleEngine class."""

    @pytest.mark.asyncio
    async def test_deny_by_default_no_rules(self, db_session, redis, sample_agent):
        """Test that requests are denied when no rules match."""
        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="ls -la",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.DENY
        assert "No ALLOW rule matched" in result.reason or "deny by default" in result.reason.lower()

    @pytest.mark.asyncio
    async def test_allow_rule_matches(self, db_session, redis, sample_agent):
        """Test that ALLOW rules permit matching requests."""
        # Create allow rule
        rule = Rule(
            id=uuid4(),
            name="Allow ls",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": ["^ls.*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="ls -la",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.ALLOW
        assert rule.id in result.matched_rules

    @pytest.mark.asyncio
    async def test_deny_rule_short_circuits(self, db_session, redis, sample_agent):
        """Test that DENY rules short-circuit evaluation."""
        # Create allow rule with lower priority
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=5,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        # Create deny rule with higher priority
        deny_rule = Rule(
            id=uuid4(),
            name="Deny rm",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=10,
            parameters={"patterns": ["^rm.*"]},
            is_active=True,
        )
        db_session.add_all([allow_rule, deny_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.DENY
        assert result.blocking_rule == deny_rule.id

    @pytest.mark.asyncio
    async def test_require_approval_rule(self, db_session, redis, sample_agent):
        """Test that REQUIRE_APPROVAL rules return pending status."""
        rule = Rule(
            id=uuid4(),
            name="Approval for writes",
            agent_id=sample_agent.id,
            rule_type=RuleType.HUMAN_IN_LOOP,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=10,
            parameters={
                "require_approval_for": ["file_write"],
                "timeout_seconds": 300,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="file_access",
            file_path="/etc/passwd",
            file_operation="write",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.REQUIRE_APPROVAL
        assert result.blocking_rule == rule.id

    @pytest.mark.asyncio
    async def test_global_rules_apply(self, db_session, redis, sample_agent, global_rule):
        """Test that global rules apply to all agents."""
        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="file_access",
            file_path="/home/user/.env",
            file_operation="read",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.DENY
        assert global_rule.id in result.matched_rules

    @pytest.mark.asyncio
    async def test_inactive_rules_ignored(self, db_session, redis, sample_agent):
        """Test that inactive rules are not evaluated."""
        rule = Rule(
            id=uuid4(),
            name="Inactive rule",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=False,  # Inactive
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)

        # Should deny because inactive rule doesn't count
        assert result.decision == EvaluationDecision.DENY
        assert rule.id not in result.matched_rules

    @pytest.mark.asyncio
    async def test_priority_ordering(self, db_session, redis, sample_agent):
        """Test that rules are evaluated in priority order."""
        # Lower priority allow
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all low priority",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=1,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        # Higher priority deny
        deny_rule = Rule(
            id=uuid4(),
            name="Deny dangerous high priority",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": [".*dangerous.*"]},
            is_active=True,
        )
        db_session.add_all([allow_rule, deny_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test dangerous command - should be denied
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="run dangerous command",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

        # Test safe command - should be allowed
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="run safe command",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW


class TestCredentialProtection:
    """Tests for credential protection rule type."""

    @pytest.mark.asyncio
    async def test_blocks_env_files(self, db_session, redis, sample_agent, global_rule):
        """Test that .env files are blocked."""
        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="file_access",
            file_path="/app/.env",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_blocks_pem_files(self, db_session, redis, sample_agent, global_rule):
        """Test that .pem files are blocked."""
        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="file_access",
            file_path="/root/.ssh/key.pem",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY


class TestRateLimiting:
    """Tests for rate limiting rule type."""

    @pytest.mark.asyncio
    async def test_rate_limit_allows_within_limit(self, db_session, redis, sample_agent):
        """Test that requests within rate limit are allowed."""
        rule = Rule(
            id=uuid4(),
            name="Rate limit",
            agent_id=sample_agent.id,
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=10,
            parameters={"max_requests": 10, "window_seconds": 60, "scope": "agent"},
            is_active=True,
        )
        # Also add allow rule
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=5,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # First request should be allowed
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="ls",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW
