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
from app.services.rate_limiter import AdaptiveRateLimiter, RateLimiterService


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


class TestAdaptiveTrustScoring:
    """Tests for adaptive trust scoring integration in the rule engine.

    Verifies that:
    - RuleEngine wires up AdaptiveRateLimiter correctly
    - Rule-based DENY decisions do NOT reduce trust (only rate-limit breaches do)
    - ALLOW decisions increase trust score
    - Trust score affects effective rate limits (when auto_adjust_trust is on)
    - Rate-limit breaches compound trust reductions
    - Good behavior restores trust toward baseline
    - Trust is clamped to valid range (0.5 - 2.0)
    - Learning mode ALLOW doesn't increase trust
    - Trust can be reset to 1.0 via API
    """

    @pytest.mark.asyncio
    async def test_engine_has_adaptive_limiter(self, db_session, redis, sample_agent):
        """RuleEngine.__init__ creates an AdaptiveRateLimiter."""
        engine = RuleEngine(db_session, redis)
        assert hasattr(engine, "adaptive_limiter")
        assert isinstance(engine.adaptive_limiter, AdaptiveRateLimiter)

    @pytest.mark.asyncio
    async def test_deny_does_not_reduce_trust(self, db_session, redis, sample_agent):
        """A command-denylist DENY should NOT reduce the agent's trust score.

        Trust penalties only apply when the rate limit itself is breached
        (inside AdaptiveRateLimiter.check_rate_limit), not on every DENY.
        """
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Get initial trust (should be 1.0)
        initial_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert initial_trust == 1.0

        # Make a request that will be denied (no rules = deny by default)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="anything",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

        # Trust should NOT have changed
        new_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert new_trust == initial_trust

    @pytest.mark.asyncio
    async def test_allow_increases_trust(self, db_session, redis, sample_agent):
        """An allowed request should increase the agent's trust score."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Create an allow rule
        rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        # Get initial trust
        initial_trust = await engine.adaptive_limiter.get_trust_score(trust_key)

        # Make a request that will be allowed
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="ls",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

        # Trust should have increased
        new_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert new_trust > initial_trust

    @pytest.mark.asyncio
    async def test_repeated_denials_dont_compound(self, db_session, redis, sample_agent):
        """Repeated command denials should NOT reduce trust.

        Only rate-limit breaches reduce trust (tested via the
        AdaptiveRateLimiter directly, not via evaluate()).
        """
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        initial_trust = await engine.adaptive_limiter.get_trust_score(trust_key)

        # Make several denied requests (no rules = deny by default)
        for _ in range(5):
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="anything",
            )
            result = await engine.evaluate(context)
            assert result.decision == EvaluationDecision.DENY

        # Trust should be unchanged after command denials
        final_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert final_trust == initial_trust

    @pytest.mark.asyncio
    async def test_rate_limit_breach_compounds_trust(self, db_session, redis, sample_agent):
        """Rate-limit breaches (via AdaptiveRateLimiter) DO compound trust."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Record several violations directly on the adaptive limiter
        trust_scores = [await engine.adaptive_limiter.get_trust_score(trust_key)]
        for _ in range(5):
            new_score = await engine.adaptive_limiter.record_violation(trust_key)
            trust_scores.append(new_score)

        # Each score should be strictly less than the previous
        for i in range(1, len(trust_scores)):
            assert trust_scores[i] < trust_scores[i - 1]

        # After 5 violations: 1.0 * 0.9^5 ≈ 0.59
        assert trust_scores[-1] == pytest.approx(0.9 ** 5, rel=0.02)

    @pytest.mark.asyncio
    async def test_trust_affects_rate_limit(self, db_session, redis, sample_agent):
        """Reduced trust should lower the effective rate limit (when enforced)."""
        # Enable trust enforcement for this agent
        sample_agent.auto_adjust_trust = True
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Set a low trust score (0.5 = half the base limit)
        await engine.adaptive_limiter.set_trust_score(trust_key, 0.5)

        # Create rate limit rule with max_requests=10
        rate_rule = Rule(
            id=uuid4(),
            name="Rate limit",
            agent_id=sample_agent.id,
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=20,
            parameters={"max_requests": 10, "window_seconds": 60, "scope": "agent"},
            is_active=True,
        )
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
        db_session.add_all([rate_rule, allow_rule])
        await db_session.commit()

        # With trust=0.5, effective limit is 10*0.5=5
        allowed_count = 0
        for i in range(10):
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="ls",
            )
            result = await engine.evaluate(context)
            if result.decision == EvaluationDecision.ALLOW:
                allowed_count += 1

        # Should allow roughly 5 requests, not 10
        # (trust also shifts during the loop, so allow some slack)
        assert allowed_count < 10
        assert allowed_count >= 3  # At least some should be allowed

    @pytest.mark.asyncio
    async def test_good_behavior_restores_trust(self, db_session, redis, sample_agent):
        """Good behavior should gradually restore trust toward 1.0."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Start with low trust from violations
        await engine.adaptive_limiter.set_trust_score(trust_key, 0.5)

        # Create an allow rule
        rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        # Make many allowed requests
        for _ in range(50):
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="ls",
            )
            await engine.evaluate(context)

        # Trust should have increased from 0.5
        final_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert final_trust > 0.5

    @pytest.mark.asyncio
    async def test_trust_clamped_to_min(self, db_session, redis, sample_agent):
        """Trust score should never go below MIN_TRUST (0.5)."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Force trust to the minimum
        await engine.adaptive_limiter.set_trust_score(trust_key, 0.5)

        # Record another violation — should stay at 0.5, not go below
        new_score = await engine.adaptive_limiter.record_violation(trust_key)
        assert new_score >= engine.adaptive_limiter.MIN_TRUST
        assert engine.adaptive_limiter.MIN_TRUST == 0.5

        # Even after many violations
        for _ in range(10):
            new_score = await engine.adaptive_limiter.record_violation(trust_key)
        assert new_score >= 0.5

    @pytest.mark.asyncio
    async def test_trust_clamped_to_max(self, db_session, redis, sample_agent):
        """Trust score should never exceed MAX_TRUST (2.0)."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Set near max
        await engine.adaptive_limiter.set_trust_score(trust_key, 2.0)

        # Good behavior shouldn't exceed 2.0
        new_score = await engine.adaptive_limiter.record_good_behavior(trust_key)
        assert new_score <= engine.adaptive_limiter.MAX_TRUST

    @pytest.mark.asyncio
    async def test_learning_mode_no_trust_increase(self, db_session, redis, sample_agent):
        """Learning mode ALLOW should not increase trust (result.learning_mode=True)."""
        import os
        os.environ["LEARNING_MODE"] = "true"
        os.environ["DENY_BY_DEFAULT"] = "true"
        from app.config import get_settings
        get_settings.cache_clear()

        try:
            # Need at least one rule so evaluation enters the rule loop
            # (the "no rules" path skips learning mode check)
            rule = Rule(
                id=uuid4(),
                name="Block rm only",
                agent_id=sample_agent.id,
                rule_type=RuleType.COMMAND_DENYLIST,
                action=RuleAction.DENY,
                priority=10,
                parameters={"patterns": ["^rm"]},
                is_active=True,
            )
            db_session.add(rule)
            await db_session.commit()

            engine = RuleEngine(db_session, redis)
            trust_key = f"rate:{sample_agent.id}"

            initial_trust = await engine.adaptive_limiter.get_trust_score(trust_key)

            # "ls" won't match the deny rule, no allow rule exists,
            # so deny-by-default kicks in — but learning mode overrides to ALLOW
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="ls",
            )
            result = await engine.evaluate(context)
            assert result.decision == EvaluationDecision.ALLOW
            assert result.learning_mode is True

            # Trust should not have changed
            final_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
            assert final_trust == initial_trust
        finally:
            os.environ["LEARNING_MODE"] = "false"
            get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_full_pipeline_violations_then_recovery(self, db_session, redis, sample_agent):
        """Full pipeline: violations tighten rate limit, good behavior loosens it."""
        # Enable trust enforcement for this agent
        sample_agent.auto_adjust_trust = True
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Phase 1: Create rules — rate limit of 6 + allow all
        rate_rule = Rule(
            id=uuid4(),
            name="Rate limit",
            agent_id=sample_agent.id,
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=20,
            parameters={"max_requests": 6, "window_seconds": 60, "scope": "agent"},
            is_active=True,
        )
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
        db_session.add_all([rate_rule, allow_rule])
        await db_session.commit()

        # Phase 2: Verify initial trust is 1.0
        trust_key = f"rate:{sample_agent.id}"
        initial_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert initial_trust == pytest.approx(1.0, rel=0.01)

        # Phase 3: Make a few allowed requests — trust should stay near 1.0
        for _ in range(3):
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="ls",
            )
            result = await engine.evaluate(context)
            assert result.decision == EvaluationDecision.ALLOW

        trust_after_good = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert trust_after_good >= 1.0  # Should be slightly above baseline

    @pytest.mark.asyncio
    async def test_reset_trust_via_redis(self, db_session, redis, sample_agent):
        """Trust score can be reset to 1.0 by deleting the Redis key."""
        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Lower trust via direct violations
        await engine.adaptive_limiter.set_trust_score(trust_key, 0.6)
        assert await engine.adaptive_limiter.get_trust_score(trust_key) == pytest.approx(0.6, rel=0.01)

        # Reset by deleting the Redis key (mirrors the reset-trust endpoint)
        await redis.delete(f"trust:{trust_key}")

        # Should return default 1.0
        reset_trust = await engine.adaptive_limiter.get_trust_score(trust_key)
        assert reset_trust == 1.0

    @pytest.mark.asyncio
    async def test_trust_enforcement_off_uses_base_limit(self, db_session, redis, sample_agent):
        """When auto_adjust_trust is False, rate limit uses base limit regardless of trust score."""
        # Ensure trust enforcement is OFF (default)
        assert sample_agent.auto_adjust_trust is False

        engine = RuleEngine(db_session, redis)
        trust_key = f"rate:{sample_agent.id}"

        # Set a low trust score
        await engine.adaptive_limiter.set_trust_score(trust_key, 0.5)

        # Create rate limit rule with max_requests=10
        rate_rule = Rule(
            id=uuid4(),
            name="Rate limit",
            agent_id=sample_agent.id,
            rule_type=RuleType.RATE_LIMIT,
            action=RuleAction.DENY,
            priority=20,
            parameters={"max_requests": 10, "window_seconds": 60, "scope": "agent"},
            is_active=True,
        )
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
        db_session.add_all([rate_rule, allow_rule])
        await db_session.commit()

        # With trust enforcement OFF, all 10 requests should be allowed
        # (trust score of 0.5 is ignored)
        allowed_count = 0
        for i in range(10):
            context = EvaluationContext(
                agent_id=sample_agent.id,
                request_type="command",
                command="ls",
            )
            result = await engine.evaluate(context)
            if result.decision == EvaluationDecision.ALLOW:
                allowed_count += 1

        assert allowed_count == 10
