"""Tests for agent trust scoring and execution environment fields."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel, ExecutionEnvironment


class TestAgentTrustScoringFields:
    """Tests for the new trust scoring fields on the Agent model."""

    @pytest.mark.asyncio
    async def test_agent_has_trust_score_field(self, db_session):
        """Test that agents have trust_score field with default 1.0."""
        agent = Agent(
            id=uuid4(),
            name="Test Agent",
            external_id=f"test-trust-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db_session.add(agent)
        await db_session.commit()
        await db_session.refresh(agent)

        assert hasattr(agent, "trust_score")
        assert agent.trust_score == 1.0

    @pytest.mark.asyncio
    async def test_agent_has_violation_count(self, db_session):
        """Test that agents have violation_count field with default 0."""
        agent = Agent(
            id=uuid4(),
            name="Test Agent",
            external_id=f"test-violation-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db_session.add(agent)
        await db_session.commit()
        await db_session.refresh(agent)

        assert hasattr(agent, "violation_count")
        assert agent.violation_count == 0

    @pytest.mark.asyncio
    async def test_agent_auto_adjust_flag(self, db_session):
        """Test that agents have auto_adjust_trust field with default False."""
        agent = Agent(
            id=uuid4(),
            name="Test Agent",
            external_id=f"test-autoadjust-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db_session.add(agent)
        await db_session.commit()
        await db_session.refresh(agent)

        assert hasattr(agent, "auto_adjust_trust")
        assert agent.auto_adjust_trust is False

        # Test that it can be set to True
        agent.auto_adjust_trust = True
        await db_session.commit()
        await db_session.refresh(agent)
        assert agent.auto_adjust_trust is True

    @pytest.mark.asyncio
    async def test_execution_environment_field(self, db_session):
        """Test that agents have execution_environment field with ExecutionEnvironment enum."""
        # Test default value
        agent = Agent(
            id=uuid4(),
            name="Test Agent",
            external_id=f"test-execenv-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db_session.add(agent)
        await db_session.commit()
        await db_session.refresh(agent)

        assert hasattr(agent, "execution_environment")
        assert agent.execution_environment == ExecutionEnvironment.UNKNOWN

        # Test all enum values can be stored
        for env in ExecutionEnvironment:
            agent.execution_environment = env
            await db_session.commit()
            await db_session.refresh(agent)
            assert agent.execution_environment == env

    @pytest.mark.asyncio
    async def test_execution_environment_enum_values(self):
        """Test that ExecutionEnvironment enum has expected values."""
        assert ExecutionEnvironment.UNKNOWN.value == "unknown"
        assert ExecutionEnvironment.BARE_METAL.value == "bare_metal"
        assert ExecutionEnvironment.CONTAINER.value == "container"
        assert ExecutionEnvironment.VM.value == "vm"
        assert ExecutionEnvironment.SANDBOX.value == "sandbox"
