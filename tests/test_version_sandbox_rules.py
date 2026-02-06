"""Tests for VERSION_ENFORCEMENT and SANDBOX_REQUIRED rule types."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel, ExecutionEnvironment
from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)


class TestVersionEnforcement:
    """Tests for VERSION_ENFORCEMENT rule type."""

    @pytest.mark.asyncio
    async def test_version_enforcement_blocks_old_openclaw(self, db_session, redis):
        """Test that OpenClaw 2026.1.0 < 2026.1.29 is denied."""
        # Create agent with old version
        agent = Agent(
            id=uuid4(),
            name="Old OpenClaw Agent",
            external_id=f"old-openclaw-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            agent_type="openclaw",
            agent_version="2026.1.0",
        )
        db_session.add(agent)

        # Create version enforcement rule
        rule = Rule(
            id=uuid4(),
            name="Block Vulnerable OpenClaw",
            agent_id=None,  # Global rule
            rule_type=RuleType.VERSION_ENFORCEMENT,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "minimum_versions": {"openclaw": "2026.1.29"},
                "allow_unknown_version": False,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_version_enforcement_allows_current(self, db_session, redis):
        """Test that OpenClaw 2026.1.29 is allowed (meets minimum)."""
        agent = Agent(
            id=uuid4(),
            name="Current OpenClaw Agent",
            external_id=f"current-openclaw-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            agent_type="openclaw",
            agent_version="2026.1.29",
        )
        db_session.add(agent)

        # Version enforcement rule
        version_rule = Rule(
            id=uuid4(),
            name="Block Vulnerable OpenClaw",
            agent_id=None,
            rule_type=RuleType.VERSION_ENFORCEMENT,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "minimum_versions": {"openclaw": "2026.1.29"},
                "allow_unknown_version": False,
            },
            is_active=True,
        )
        # Allow rule for commands
        allow_rule = Rule(
            id=uuid4(),
            name="Allow Commands",
            agent_id=None,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([version_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_version_enforcement_unknown_denied(self, db_session, redis):
        """Test that agents without version reported are denied by default."""
        agent = Agent(
            id=uuid4(),
            name="Unknown Version Agent",
            external_id=f"unknown-ver-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            agent_type="openclaw",
            agent_version=None,  # No version
        )
        db_session.add(agent)

        rule = Rule(
            id=uuid4(),
            name="Block Vulnerable OpenClaw",
            agent_id=None,
            rule_type=RuleType.VERSION_ENFORCEMENT,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "minimum_versions": {"openclaw": "2026.1.29"},
                "allow_unknown_version": False,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_version_enforcement_allow_unknown_option(self, db_session, redis):
        """Test that allow_unknown_version=True allows agents without version."""
        agent = Agent(
            id=uuid4(),
            name="Unknown Version Agent",
            external_id=f"unknown-allowed-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            agent_type="openclaw",
            agent_version=None,
        )
        db_session.add(agent)

        version_rule = Rule(
            id=uuid4(),
            name="Block Vulnerable OpenClaw",
            agent_id=None,
            rule_type=RuleType.VERSION_ENFORCEMENT,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "minimum_versions": {"openclaw": "2026.1.29"},
                "allow_unknown_version": True,  # Allow unknown
            },
            is_active=True,
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow Commands",
            agent_id=None,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([version_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW


class TestSandboxRequired:
    """Tests for SANDBOX_REQUIRED rule type."""

    @pytest.mark.asyncio
    async def test_sandbox_required_blocks_bare_metal(self, db_session, redis):
        """Test that bare_metal environment is denied."""
        agent = Agent(
            id=uuid4(),
            name="Bare Metal Agent",
            external_id=f"bare-metal-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            execution_environment=ExecutionEnvironment.BARE_METAL,
        )
        db_session.add(agent)

        rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": False,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_sandbox_required_allows_container(self, db_session, redis):
        """Test that container environment is allowed."""
        agent = Agent(
            id=uuid4(),
            name="Container Agent",
            external_id=f"container-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            execution_environment=ExecutionEnvironment.CONTAINER,
        )
        db_session.add(agent)

        sandbox_rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": False,
            },
            is_active=True,
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow Commands",
            agent_id=None,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([sandbox_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_sandbox_required_allows_vm(self, db_session, redis):
        """Test that vm environment is allowed."""
        agent = Agent(
            id=uuid4(),
            name="VM Agent",
            external_id=f"vm-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            execution_environment=ExecutionEnvironment.VM,
        )
        db_session.add(agent)

        sandbox_rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": False,
            },
            is_active=True,
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow Commands",
            agent_id=None,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([sandbox_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_sandbox_unknown_env_denied(self, db_session, redis):
        """Test that unknown environment is denied by default."""
        agent = Agent(
            id=uuid4(),
            name="Unknown Env Agent",
            external_id=f"unknown-env-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            execution_environment=ExecutionEnvironment.UNKNOWN,
        )
        db_session.add(agent)

        rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": False,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_sandbox_allow_unknown_option(self, db_session, redis):
        """Test that allow_unknown=True allows unknown environments."""
        agent = Agent(
            id=uuid4(),
            name="Unknown Env Agent",
            external_id=f"unknown-allowed-env-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            execution_environment=ExecutionEnvironment.UNKNOWN,
        )
        db_session.add(agent)

        sandbox_rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": True,  # Allow unknown
            },
            is_active=True,
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow Commands",
            agent_id=None,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([sandbox_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_combined_version_and_sandbox(self, db_session, redis):
        """Test that both version and sandbox rules are evaluated correctly."""
        # Agent with good version but bad environment
        agent = Agent(
            id=uuid4(),
            name="Combined Test Agent",
            external_id=f"combined-test-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            agent_type="openclaw",
            agent_version="2026.1.29",  # Good version
            execution_environment=ExecutionEnvironment.BARE_METAL,  # Bad environment
        )
        db_session.add(agent)

        version_rule = Rule(
            id=uuid4(),
            name="Block Vulnerable OpenClaw",
            agent_id=None,
            rule_type=RuleType.VERSION_ENFORCEMENT,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "minimum_versions": {"openclaw": "2026.1.29"},
                "allow_unknown_version": False,
            },
            is_active=True,
        )
        sandbox_rule = Rule(
            id=uuid4(),
            name="Require Sandbox",
            agent_id=None,
            rule_type=RuleType.SANDBOX_REQUIRED,
            action=RuleAction.DENY,
            priority=90,
            parameters={
                "allowed_environments": ["container", "vm", "sandbox"],
                "allow_unknown": False,
            },
            is_active=True,
        )
        db_session.add_all([version_rule, sandbox_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=agent.id,
            request_type="command",
            command="ls",
        )

        # Should be denied because of sandbox rule (bare_metal not allowed)
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY
