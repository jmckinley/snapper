"""Tests for skill denylist pattern matching (ClawHavoc campaign mitigations)."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import MaliciousSkill, IssueSeverity
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)


class TestSkillDenylistPatterns:
    """Tests for enhanced skill denylist with pattern matching."""

    @pytest.mark.asyncio
    async def test_exact_skill_match_blocked(self, db_session, redis, sample_agent):
        """Test that exact skill name 'clawhub' in blocked_skills is denied."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": ["clawhub", "shell-executor-pro"],
                "blocked_patterns": [],
                "blocked_publishers": [],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="clawhub",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_pattern_match_blocked(self, db_session, redis, sample_agent):
        """Test that 'clawhub-abc123' matches pattern and is denied."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [],
                "blocked_patterns": [r"^clawhub[0-9a-z\-]*$"],
                "blocked_publishers": [],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="clawhub-abc123",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_typosquat_pattern_blocked(self, db_session, redis, sample_agent):
        """Test that typosquat 'clawdhub' matches pattern and is denied."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [],
                "blocked_patterns": [r"^clawdhub[0-9a-z\-]*$"],
                "blocked_publishers": [],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="clawdhub",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_publisher_blocked(self, db_session, redis, sample_agent):
        """Test that publisher 'hightower6eu/skill' is denied."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Publishers",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [],
                "blocked_patterns": [],
                "blocked_publishers": ["hightower6eu"],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="hightower6eu/crypto-trader",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_safe_skill_allowed(self, db_session, redis, sample_agent):
        """Test that 'legitimate-tool' not matching any blocks is allowed."""
        denylist_rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": ["clawhub"],
                "blocked_patterns": [r"^clawhub[0-9a-z\-]*$"],
                "blocked_publishers": ["hightower6eu"],
                "auto_block_flagged": False,  # Disable DB lookup for this test
            },
            is_active=True,
        )
        allowlist_rule = Rule(
            id=uuid4(),
            name="Allow Safe Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"skills": ["legitimate-tool"]},
            is_active=True,
        )
        db_session.add_all([denylist_rule, allowlist_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="legitimate-tool",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_case_insensitive_matching(self, db_session, redis, sample_agent):
        """Test that 'CLAWHUB' matches 'clawhub' (case insensitive)."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": ["clawhub"],
                "blocked_patterns": [],
                "blocked_publishers": [],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="CLAWHUB",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_database_flagged_skill(self, db_session, redis, sample_agent):
        """Test that a skill flagged in MaliciousSkill DB is denied."""
        # Create a malicious skill entry in the database
        malicious_skill = MaliciousSkill(
            id=uuid4(),
            skill_id="db-flagged-skill",
            skill_name="DB Flagged Skill",
            threat_type="data_exfil",
            severity=IssueSeverity.CRITICAL,
            is_blocked=True,
            source="scan",
        )
        db_session.add(malicious_skill)

        # Create rule with auto_block_flagged enabled
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [],
                "blocked_patterns": [],
                "blocked_publishers": [],
                "auto_block_flagged": True,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="db-flagged-skill",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_multiple_patterns_any_match(self, db_session, redis, sample_agent):
        """Test that first matching pattern triggers deny."""
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=None,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [],
                "blocked_patterns": [
                    r".*crypto-trader.*",
                    r".*polymarket-bot.*",
                    r".*-auto-updater.*",
                ],
                "blocked_publishers": [],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test crypto-trader pattern
        context1 = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="my-crypto-trader-pro",
        )
        result1 = await engine.evaluate(context1)
        assert result1.decision == EvaluationDecision.DENY

        # Test polymarket-bot pattern
        context2 = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="polymarket-bot-v2",
        )
        result2 = await engine.evaluate(context2)
        assert result2.decision == EvaluationDecision.DENY

        # Test auto-updater pattern
        context3 = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill",
            skill_id="skill-auto-updater",
        )
        result3 = await engine.evaluate(context3)
        assert result3.decision == EvaluationDecision.DENY
