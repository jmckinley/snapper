"""Tests for SecurityMonitor service.

Instantiates SecurityMonitor(db_session, redis) directly and tests
each scoring method with controlled DB state.
"""

import pytest
from uuid import uuid4

from sqlalchemy import select

from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    MaliciousSkill,
    SecurityIssue,
)
from app.services.security_monitor import SecurityMonitor


class TestCredentialProtectionScore:
    """Tests for _calculate_credential_protection_score."""

    @pytest.mark.asyncio
    async def test_no_rules_returns_zero(self, db_session, redis):
        """No credential protection rules → 0 points."""
        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_credential_protection_score(None)
        assert score == 0

    @pytest.mark.asyncio
    async def test_full_coverage_returns_max(self, db_session, redis):
        """Rules covering all 4 essential patterns → 15 points (max)."""
        rule = Rule(
            id=uuid4(),
            name="Full Credential Protection",
            rule_type=RuleType.CREDENTIAL_PROTECTION,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "protected_patterns": [
                    r"\.env$",
                    r"\.pem$",
                    r"\.key$",
                    r"credentials\.json$",
                ],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_credential_protection_score(None)
        assert score == 15  # max weight for credential_protection

    @pytest.mark.asyncio
    async def test_partial_coverage_proportional(self, db_session, redis):
        """Rules covering 2 of 4 patterns → proportional score."""
        rule = Rule(
            id=uuid4(),
            name="Partial Credential Protection",
            rule_type=RuleType.CREDENTIAL_PROTECTION,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "protected_patterns": [r"\.env$", r"\.pem$"],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_credential_protection_score(None)
        # 2/4 coverage * 15 max = 7 (int truncation)
        assert score == 7

    @pytest.mark.asyncio
    async def test_regex_patterns_normalize_correctly(self, db_session, redis):
        """Regex patterns like r'\\.env$' should match essential '.env'."""
        rule = Rule(
            id=uuid4(),
            name="Regex Credential Protection",
            rule_type=RuleType.CREDENTIAL_PROTECTION,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "protected_patterns": [
                    r"\.env$",       # Should match ".env"
                    r"\.pem$",       # Should match ".pem"
                    r"\.key$",       # Should match ".key"
                    r"credentials",  # Should match "credentials"
                ],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_credential_protection_score(None)
        assert score == 15


class TestCVEMitigationScore:
    """Tests for _calculate_cve_mitigation_score."""

    @pytest.mark.asyncio
    async def test_no_issues_returns_zero(self, db_session, redis):
        """No SecurityIssue records → 0 (unknown, not perfect)."""
        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_cve_mitigation_score(None)
        assert score == 0

    @pytest.mark.asyncio
    async def test_all_resolved_returns_max(self, db_session, redis):
        """All issues resolved → 20 points (max)."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-RESOLVED",
            title="Resolved CVE",
            description="Already resolved.",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.RESOLVED,
            source="test",
        )
        db_session.add(issue)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_cve_mitigation_score(None)
        assert score == 20  # max weight for cve_mitigation

    @pytest.mark.asyncio
    async def test_active_with_mitigation_partial_score(self, db_session, redis):
        """Active issue with mitigation_rules → partial score."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-MITIGATED",
            title="Partially Mitigated",
            description="Has mitigation rules.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            mitigation_rules=[uuid4()],
        )
        db_session.add(issue)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_cve_mitigation_score(None)
        # 1 active issue with mitigation / 1 total = 100% → 20 points
        assert score == 20

    @pytest.mark.asyncio
    async def test_active_without_mitigation_zero(self, db_session, redis):
        """Active issue without mitigation → 0 points."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-NOMITIGATE",
            title="Unmitigated",
            description="No mitigation.",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="test",
        )
        db_session.add(issue)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_cve_mitigation_score(None)
        assert score == 0


class TestSkillProtectionScore:
    """Tests for _calculate_skill_protection_score."""

    @pytest.mark.asyncio
    async def test_no_rules_returns_zero(self, db_session, redis):
        """No skill denylist rules → 0 points."""
        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_skill_protection_score(None)
        assert score == 0

    @pytest.mark.asyncio
    async def test_auto_block_flagged_returns_max(self, db_session, redis):
        """Rule with auto_block_flagged=True → 20 points (max)."""
        rule = Rule(
            id=uuid4(),
            name="Auto Block Skills",
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"auto_block_flagged": True},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_skill_protection_score(None)
        assert score == 20

    @pytest.mark.asyncio
    async def test_rules_without_auto_block_half_score(self, db_session, redis):
        """Skill rules without auto_block → 10 points (half)."""
        rule = Rule(
            id=uuid4(),
            name="Manual Block Skills",
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={"blocked_skills": ["bad-skill"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        score = await monitor._calculate_skill_protection_score(None)
        assert score == 10


class TestCalculateSecurityScore:
    """Tests for the full calculate_security_score method."""

    @pytest.mark.asyncio
    async def test_empty_db_returns_zero_grade_f(self, db_session, redis):
        """Empty DB → score 0, grade 'F'."""
        monitor = SecurityMonitor(db_session, redis)
        result = await monitor.calculate_security_score(None)

        assert result["score"] == 0
        assert result["grade"] == "F"
        assert "breakdown" in result

    @pytest.mark.asyncio
    async def test_all_rule_types_present_high_score(self, db_session, redis):
        """Having important rule types + audit logs → high score."""
        # Create rules covering important types
        types_to_create = [
            (RuleType.ORIGIN_VALIDATION, {}),
            (RuleType.SKILL_DENYLIST, {"auto_block_flagged": True}),
            (RuleType.CREDENTIAL_PROTECTION, {
                "protected_patterns": [r"\.env$", r"\.pem$", r"\.key$", r"credentials"],
            }),
            (RuleType.LOCALHOST_RESTRICTION, {}),
            (RuleType.RATE_LIMIT, {"max_requests": 100, "window_seconds": 60}),
        ]
        for rt, params in types_to_create:
            rule = Rule(
                id=uuid4(),
                name=f"Test {rt.value}",
                rule_type=rt,
                action=RuleAction.DENY,
                priority=100,
                parameters=params,
                is_active=True,
            )
            db_session.add(rule)

        # Create an audit log for audit compliance points
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
        log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_DENIED,
            severity=AuditSeverity.INFO,
            message="Test audit log",
        )
        db_session.add(log)
        await db_session.commit()

        monitor = SecurityMonitor(db_session, redis)
        result = await monitor.calculate_security_score(None)

        # Should have a high score from rule coverage + skill + cred + rate + audit
        assert result["score"] >= 60
        assert result["grade"] != "F"

    @pytest.mark.asyncio
    async def test_grade_boundaries(self, db_session, redis):
        """Verify score_to_grade mapping for boundary values."""
        monitor = SecurityMonitor(db_session, redis)

        assert monitor._score_to_grade(95) == "A+"
        assert monitor._score_to_grade(90) == "A"
        assert monitor._score_to_grade(85) == "B+"
        assert monitor._score_to_grade(80) == "B"
        assert monitor._score_to_grade(75) == "C+"
        assert monitor._score_to_grade(70) == "C"
        assert monitor._score_to_grade(60) == "D"
        assert monitor._score_to_grade(59) == "F"
        assert monitor._score_to_grade(0) == "F"
        assert monitor._score_to_grade(100) == "A+"
