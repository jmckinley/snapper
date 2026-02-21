"""Tests for role-based rule targeting."""

import pytest
from uuid import uuid4

from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)


class TestRoleBasedRuleFiltering:
    """Tests for target_roles filtering in the rule engine."""

    @pytest.mark.asyncio
    async def test_rule_with_matching_role_applies(self, db_session, redis, sample_agent):
        """Rule with target_roles fires when user_role matches."""
        rule = Rule(
            id=uuid4(),
            name="Viewer deny all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": [".*"]},
            is_active=True,
            target_roles=["viewer"],
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
            user_role="viewer",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.DENY
        assert rule.id in result.matched_rules

    @pytest.mark.asyncio
    async def test_rule_with_non_matching_role_skipped(self, db_session, redis, sample_agent):
        """Rule with target_roles is skipped when user_role doesn't match."""
        # Create a deny rule that targets only viewers
        deny_rule = Rule(
            id=uuid4(),
            name="Viewer deny",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": [".*"]},
            is_active=True,
            target_roles=["viewer"],
        )
        # Create an allow rule for everyone
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([deny_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Admin user should skip the viewer-only deny rule
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
            user_role="admin",
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.ALLOW
        assert deny_rule.id not in result.matched_rules

    @pytest.mark.asyncio
    async def test_role_targeted_rule_skipped_for_unauthenticated(
        self, db_session, redis, sample_agent
    ):
        """Role-targeted rules are skipped when no user_role (unauthenticated)."""
        deny_rule = Rule(
            id=uuid4(),
            name="Viewer deny",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": [".*"]},
            is_active=True,
            target_roles=["viewer"],
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([deny_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # No user_role — role-targeted rules should be skipped
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
            user_role=None,
        )

        result = await engine.evaluate(context)

        assert result.decision == EvaluationDecision.ALLOW
        assert deny_rule.id not in result.matched_rules

    @pytest.mark.asyncio
    async def test_rule_with_null_target_roles_applies_to_all(
        self, db_session, redis, sample_agent
    ):
        """Rules with target_roles=None apply to all users (authenticated or not)."""
        deny_rule = Rule(
            id=uuid4(),
            name="Deny all (no role filter)",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": ["^rm "]},
            is_active=True,
            target_roles=None,  # Applies to everyone
        )
        db_session.add(deny_rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Should apply to admin
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
            user_role="admin",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

        # Should apply to unauthenticated
        context2 = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="rm -rf /",
            user_role=None,
        )
        result2 = await engine.evaluate(context2)
        assert result2.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_multiple_target_roles(self, db_session, redis, sample_agent):
        """Rule with multiple target_roles fires for any matching role."""
        rule = Rule(
            id=uuid4(),
            name="Restrict viewer and member",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"patterns": ["^sudo "]},
            is_active=True,
            target_roles=["viewer", "member"],
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Member should be denied
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="sudo reboot",
            user_role="member",
        )
        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

        # Owner should not be affected (rule only targets viewer/member)
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(allow_rule)
        await db_session.commit()

        context2 = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="sudo reboot",
            user_role="owner",
        )
        result2 = await engine.evaluate(context2)
        assert result2.decision == EvaluationDecision.ALLOW

    @pytest.mark.asyncio
    async def test_require_approval_with_role_targeting(
        self, db_session, redis, sample_agent
    ):
        """REQUIRE_APPROVAL rules respect role targeting."""
        approval_rule = Rule(
            id=uuid4(),
            name="Viewers need approval for writes",
            agent_id=sample_agent.id,
            rule_type=RuleType.HUMAN_IN_LOOP,
            action=RuleAction.REQUIRE_APPROVAL,
            priority=50,
            parameters={"require_approval_for": ["shell"]},
            is_active=True,
            target_roles=["viewer"],
        )
        allow_rule = Rule(
            id=uuid4(),
            name="Allow all commands",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add_all([approval_rule, allow_rule])
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Viewer should get require_approval
        viewer_ctx = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="make deploy",
            user_role="viewer",
        )
        viewer_result = await engine.evaluate(viewer_ctx)
        assert viewer_result.decision == EvaluationDecision.REQUIRE_APPROVAL

        # Admin should just get allow (approval rule is skipped)
        admin_ctx = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="command",
            command="make deploy",
            user_role="admin",
        )
        admin_result = await engine.evaluate(admin_ctx)
        assert admin_result.decision == EvaluationDecision.ALLOW


class TestTargetRolesSchema:
    """Tests for target_roles validation in rule schemas."""

    def test_valid_target_roles(self):
        """Valid target role values are accepted."""
        from app.schemas.rules import RuleCreate

        rule = RuleCreate(
            name="Test",
            rule_type=RuleType.COMMAND_DENYLIST,
            parameters={"patterns": [".*"]},
            target_roles=["viewer", "member"],
        )
        assert rule.target_roles == ["viewer", "member"]

    def test_invalid_target_roles_rejected(self):
        """Invalid role values are rejected."""
        from app.schemas.rules import RuleCreate
        from pydantic import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            RuleCreate(
                name="Test",
                rule_type=RuleType.COMMAND_DENYLIST,
                parameters={"patterns": [".*"]},
                target_roles=["viewer", "superadmin"],
            )

        assert "Invalid target roles" in str(exc_info.value)

    def test_null_target_roles_accepted(self):
        """None (null) target_roles is accepted (means all users)."""
        from app.schemas.rules import RuleCreate

        rule = RuleCreate(
            name="Test",
            rule_type=RuleType.COMMAND_DENYLIST,
            parameters={"patterns": [".*"]},
            target_roles=None,
        )
        assert rule.target_roles is None

    def test_empty_list_target_roles_accepted(self):
        """Empty list is valid (would match no one, but syntactically valid)."""
        from app.schemas.rules import RuleCreate

        rule = RuleCreate(
            name="Test",
            rule_type=RuleType.COMMAND_DENYLIST,
            parameters={"patterns": [".*"]},
            target_roles=[],
        )
        assert rule.target_roles == []

    def test_all_valid_roles(self):
        """All four valid roles are accepted."""
        from app.schemas.rules import RuleCreate

        rule = RuleCreate(
            name="Test",
            rule_type=RuleType.COMMAND_DENYLIST,
            parameters={"patterns": [".*"]},
            target_roles=["owner", "admin", "member", "viewer"],
        )
        assert len(rule.target_roles) == 4

    def test_target_roles_in_update_schema(self):
        """RuleUpdate also validates target_roles."""
        from app.schemas.rules import RuleUpdate
        from pydantic import ValidationError

        update = RuleUpdate(target_roles=["admin"])
        assert update.target_roles == ["admin"]

        with pytest.raises(ValidationError):
            RuleUpdate(target_roles=["invalid_role"])

    def test_target_roles_in_response_schema(self):
        """RuleResponse includes target_roles."""
        from app.schemas.rules import RuleResponse

        fields = RuleResponse.model_fields
        assert "target_roles" in fields


class TestEvaluationContextUserRole:
    """Tests for user_role field in EvaluationContext."""

    def test_context_default_user_role_none(self):
        """EvaluationContext defaults user_role to None."""
        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="command",
        )
        assert context.user_role is None
        assert context.user_id is None

    def test_context_with_user_role(self):
        """EvaluationContext accepts user_role."""
        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="command",
            user_role="admin",
            user_id="some-user-id",
        )
        assert context.user_role == "admin"
        assert context.user_id == "some-user-id"
