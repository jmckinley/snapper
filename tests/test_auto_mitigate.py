"""Tests for auto-mitigation of threat feed vulnerabilities.

Covers:
- auto_mitigate_issue() service function (all 3 strategies)
- Refactored /mitigate router endpoint
- Background task hooks (NVD + GitHub) with mocked feeds
- Runtime toggle endpoint (POST /api/v1/setup/auto-mitigate)
- Redis override precedence for the setting
"""

import pytest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    SecurityIssue,
)
from app.services.security_monitor import auto_mitigate_issue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_db_context(db_session: AsyncSession):
    """Create a mock get_db_context that yields the test db_session."""
    @asynccontextmanager
    async def mock_db_context():
        yield db_session
    return mock_db_context


def _make_github_advisory(ghsa_id, cve_id=None, severity="high", summary="Test advisory"):
    """Build a fake GitHub advisory dict."""
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "severity": severity,
        "summary": summary,
        "description": f"Description for {ghsa_id}",
        "html_url": f"https://github.com/advisories/{ghsa_id}",
        "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"},
        "published_at": "2026-02-19T00:00:00Z",
        "references": [],
        "vulnerabilities": [
            {"package": {"name": "test-pkg"}, "vulnerable_version_range": "< 1.0"}
        ],
    }


def _make_nvd_cve(cve_id, description, cvss_score=7.0):
    """Build a fake NVD CVE response item."""
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-02-19T00:00:00",
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": cvss_score, "vectorString": "CVSS:3.1/AV:N"}}
                ]
            },
        }
    }


def _mock_httpx(response_json):
    """Return a patched httpx.AsyncClient context manager returning response_json."""
    mock_response = MagicMock()
    mock_response.json.return_value = response_json
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ===========================================================================
# 1. Service function: auto_mitigate_issue() — 3 strategies
# ===========================================================================


class TestAutoMitigateService:
    """Tests for the auto_mitigate_issue() service function."""

    @pytest.mark.asyncio
    async def test_strategy1_template_match_creates_rule(self, db_session):
        """CVE matching a RULE_TEMPLATE creates a rule via Strategy 1."""
        # CVE-2026-25253 has a matching template "cve-2026-25253-mitigation"
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-25253",
            title="WebSocket RCE Vulnerability",
            description="Remote code execution via WebSocket origin bypass",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["status"] == "mitigated"
        assert result["method"] in ("template_rule", "existing_rule")
        assert len(result["rules_created"]) >= 1

        # Verify the issue record was updated
        await db_session.refresh(issue)
        assert issue.status == IssueStatus.MITIGATED
        assert issue.mitigated_at is not None
        assert len(issue.mitigation_rules) >= 1

    @pytest.mark.asyncio
    async def test_strategy1_links_existing_template_rule(self, db_session):
        """If template rule already exists, links it instead of creating a duplicate."""
        # Pre-create the rule from template
        rule = Rule(
            id=uuid4(),
            name="CVE-2026-25253 Mitigation",
            rule_type=RuleType.ORIGIN_VALIDATION,
            action=RuleAction.DENY,
            priority=100,
            parameters={"allowed_origins": ["http://localhost:8000"]},
            is_active=True,
            source="template",
            source_reference="cve-2026-25253-mitigation",
        )
        db_session.add(rule)

        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-25253",
            title="WebSocket RCE",
            description="Origin bypass",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "existing_rule"
        assert str(rule.id) in result["rules_created"]

        # No duplicate rule should have been created
        rules = (await db_session.execute(
            select(Rule).where(Rule.source_reference == "cve-2026-25253-mitigation")
        )).scalars().all()
        assert len(rules) == 1

    @pytest.mark.asyncio
    async def test_strategy2_infers_credential_protection(self, db_session):
        """CVE mentioning 'credential' in description triggers Strategy 2 inference."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-CRED",
            title="CVE-2026-FAKE-CRED: Credential exposure in agent config",
            description="An attacker can steal credential files via path traversal in the agent configuration handler.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["status"] == "mitigated"
        assert result["method"] == "inferred_rule"
        assert len(result["rules_created"]) == 1

        # Verify the rule is CREDENTIAL_PROTECTION
        rule = (await db_session.execute(
            select(Rule).where(Rule.id == result["rules_created"][0])
        )).scalar_one()
        assert rule.rule_type == RuleType.CREDENTIAL_PROTECTION
        assert "auto-mitigation" in rule.tags

    @pytest.mark.asyncio
    async def test_strategy2_infers_command_injection(self, db_session):
        """CVE mentioning 'command injection' triggers COMMAND_DENYLIST."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-CMDI",
            title="CVE-2026-FAKE-CMDI: Remote command injection in tool executor",
            description="The tool executor allows remote code execution via unescaped shell metacharacters.",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "inferred_rule"
        rule = (await db_session.execute(
            select(Rule).where(Rule.id == result["rules_created"][0])
        )).scalar_one()
        assert rule.rule_type == RuleType.COMMAND_DENYLIST

    @pytest.mark.asyncio
    async def test_strategy2_infers_network_egress(self, db_session):
        """CVE mentioning 'exfiltration' triggers NETWORK_EGRESS."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-EXFIL",
            title="CVE-2026-FAKE-EXFIL: Data exfiltration via outbound HTTP",
            description="Agent can exfiltrate data through unrestricted outbound network egress.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "inferred_rule"
        rule = (await db_session.execute(
            select(Rule).where(Rule.id == result["rules_created"][0])
        )).scalar_one()
        assert rule.rule_type == RuleType.NETWORK_EGRESS

    @pytest.mark.asyncio
    async def test_strategy2_infers_file_access(self, db_session):
        """CVE mentioning 'path traversal' triggers FILE_ACCESS."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-TRAV",
            title="CVE-2026-FAKE-TRAV: Directory traversal in file reader",
            description="Path traversal allows reading /etc/passwd via file access tool.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "inferred_rule"
        rule = (await db_session.execute(
            select(Rule).where(Rule.id == result["rules_created"][0])
        )).scalar_one()
        assert rule.rule_type == RuleType.FILE_ACCESS

    @pytest.mark.asyncio
    async def test_strategy2_infers_skill_denylist(self, db_session):
        """CVE mentioning 'malicious plugin' triggers SKILL_DENYLIST."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-SKILL",
            title="CVE-2026-FAKE-SKILL: Malicious marketplace plugin",
            description="A typosquatted extension in the skill marketplace can run arbitrary code.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "inferred_rule"
        rule = (await db_session.execute(
            select(Rule).where(Rule.id == result["rules_created"][0])
        )).scalar_one()
        assert rule.rule_type == RuleType.SKILL_DENYLIST

    @pytest.mark.asyncio
    async def test_strategy2_links_existing_rule_type(self, db_session):
        """If a matching rule type already exists, links it instead of creating."""
        # Pre-create a CREDENTIAL_PROTECTION rule
        existing = Rule(
            id=uuid4(),
            name="Existing Cred Rule",
            rule_type=RuleType.CREDENTIAL_PROTECTION,
            action=RuleAction.DENY,
            priority=100,
            parameters={"protected_patterns": [r"\.env$"]},
            is_active=True,
        )
        db_session.add(existing)

        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-CRED2",
            title="CVE-2026-FAKE-CRED2: Token credential leakage",
            description="Secret token credential leaked via debug endpoint.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["method"] == "existing_rule"
        assert str(existing.id) in result["rules_created"]

    @pytest.mark.asyncio
    async def test_strategy3_fallback_reviewed(self, db_session):
        """CVE with no keyword match falls back to 'reviewed'."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-OBSCURE",
            title="CVE-2026-FAKE-OBSCURE: Obscure timing side-channel",
            description="A theoretical timing attack against the hash comparison.",
            severity=IssueSeverity.LOW,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert result["status"] == "mitigated"
        assert result["method"] == "reviewed"
        assert result["rules_created"] == []

        await db_session.refresh(issue)
        assert issue.status == IssueStatus.MITIGATED
        assert issue.mitigation_notes is not None
        assert "no auto-mitigation rule" in issue.mitigation_notes.lower()

    @pytest.mark.asyncio
    async def test_auto_generate_rules_false_skips_strategy2(self, db_session):
        """Issue with auto_generate_rules=False skips Strategy 2 inference."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-NOGEN",
            title="CVE-2026-FAKE-NOGEN: Credential leak (opt-out)",
            description="A credential leak vulnerability that opted out of auto-generation.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=False,  # Explicitly disabled
        )
        db_session.add(issue)
        await db_session.commit()

        result = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        # Should still be marked mitigated, but as "reviewed" (no rules)
        assert result["method"] == "reviewed"
        assert result["rules_created"] == []

    @pytest.mark.asyncio
    async def test_nonexistent_issue_returns_not_found(self, db_session):
        """Non-existent issue_id returns not_found status."""
        result = await auto_mitigate_issue(db_session, uuid4())
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_creates_audit_log_for_new_rule(self, db_session):
        """New rule creation generates an AuditLog entry."""
        from app.models.audit_logs import AuditLog, AuditAction

        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-AUDIT",
            title="CVE-2026-FAKE-AUDIT: Command injection for audit test",
            description="Remote code execution via injection in CLI tool.",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        logs = (await db_session.execute(
            select(AuditLog).where(AuditLog.action == AuditAction.RULE_CREATED)
        )).scalars().all()
        assert len(logs) >= 1
        assert any("CVE-2026-FAKE-AUDIT" in (log.message or "") for log in logs)

    @pytest.mark.asyncio
    async def test_idempotent_double_mitigate(self, db_session):
        """Mitigating the same issue twice is safe (idempotent)."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-IDEM",
            title="CVE-2026-FAKE-IDEM: Credential theft idempotency test",
            description="Credential theft via misconfigured secret store.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        r1 = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        r2 = await auto_mitigate_issue(db_session, issue.id)
        await db_session.commit()

        assert r1["status"] == "mitigated"
        assert r2["status"] == "mitigated"
        # Second call should link existing, not create duplicate
        assert r2["method"] == "existing_rule"


# ===========================================================================
# 2. Router endpoint (refactored to use service function)
# ===========================================================================


class TestMitigateEndpoint:
    """Tests for POST /api/v1/security/vulnerabilities/{id}/mitigate."""

    @pytest.mark.asyncio
    async def test_endpoint_mitigates_credential_cve(self, client, db_session):
        """Endpoint auto-mitigates a fake credential CVE via API."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-EP1",
            title="CVE-2026-FAKE-EP1: Credential exposure via API endpoint",
            description="Agent leaks authentication credentials through unprotected debug endpoint.",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/security/vulnerabilities/{issue.id}/mitigate"
        )
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "mitigated"
        assert data["method"] == "inferred_rule"
        assert len(data["rules_created"]) == 1

    @pytest.mark.asyncio
    async def test_endpoint_404_for_nonexistent(self, client):
        """Endpoint returns 404 for unknown issue."""
        response = await client.post(
            f"/api/v1/security/vulnerabilities/{uuid4()}/mitigate"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_endpoint_returns_reviewed_for_no_match(self, client, db_session):
        """Endpoint returns reviewed method when no keywords match."""
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-FAKE-NOMATCH",
            title="CVE-2026-FAKE-NOMATCH: Obscure hardware bug",
            description="A theoretical microarchitecture bug in ARM chips.",
            severity=IssueSeverity.LOW,
            status=IssueStatus.ACTIVE,
            source="test",
            auto_generate_rules=True,
        )
        db_session.add(issue)
        await db_session.commit()

        response = await client.post(
            f"/api/v1/security/vulnerabilities/{issue.id}/mitigate"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["method"] == "reviewed"
        assert data["rules_created"] == []


# ===========================================================================
# 3. Background task hooks (NVD + GitHub auto-mitigate after fetch)
# ===========================================================================


class TestNVDAutoMitigation:
    """Tests for auto-mitigation after NVD fetch."""

    @pytest.mark.asyncio
    async def test_nvd_fetch_auto_mitigates_when_enabled(self, db_session, redis):
        """New NVD CVEs are auto-mitigated when AUTO_MITIGATE_THREATS=True."""
        cves = {
            "vulnerabilities": [
                _make_nvd_cve("CVE-2026-NVD-001", "Credential theft via misconfigured auth token handler"),
                _make_nvd_cve("CVE-2026-NVD-002", "Command injection in shell executor module", 9.0),
            ]
        }

        mock_client = _mock_httpx(cves)

        # Ensure Redis says auto-mitigate is ON
        await redis.set("config:auto_mitigate_threats", "1")

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)), \
             patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _fetch_nvd_updates_async
            await _fetch_nvd_updates_async()

        # Verify issues were created
        issues = (await db_session.execute(select(SecurityIssue))).scalars().all()
        assert len(issues) == 2

        # Verify both are mitigated
        for issue in issues:
            assert issue.status == IssueStatus.MITIGATED
            assert issue.mitigated_at is not None

        # Verify rules were created (credential + command injection)
        rules = (await db_session.execute(
            select(Rule).where(Rule.tags.contains(["auto-mitigation"]))
        )).scalars().all()
        assert len(rules) >= 2

    @pytest.mark.asyncio
    async def test_nvd_fetch_skips_mitigation_when_disabled(self, db_session, redis):
        """New NVD CVEs stay ACTIVE when auto-mitigate is OFF."""
        cves = {
            "vulnerabilities": [
                _make_nvd_cve("CVE-2026-NVD-SKIP", "Credential leak in config parser"),
            ]
        }

        mock_client = _mock_httpx(cves)

        # Set auto-mitigate OFF via Redis
        await redis.set("config:auto_mitigate_threats", "0")

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)), \
             patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _fetch_nvd_updates_async
            await _fetch_nvd_updates_async()

        issues = (await db_session.execute(select(SecurityIssue))).scalars().all()
        assert len(issues) == 1
        assert issues[0].status == IssueStatus.ACTIVE  # NOT mitigated
        assert issues[0].mitigation_rules is None or issues[0].mitigation_rules == []


class TestGitHubAutoMitigation:
    """Tests for auto-mitigation after GitHub advisory fetch."""

    @pytest.mark.asyncio
    async def test_github_fetch_auto_mitigates_when_enabled(self, db_session, redis):
        """New GitHub advisories are auto-mitigated when enabled."""
        advisories = [
            _make_github_advisory(
                "GHSA-AUTO-001",
                cve_id="CVE-2026-GH-001",
                severity="critical",
                summary="Path traversal in file reader allowing directory traversal to /etc/shadow",
            ),
            _make_github_advisory(
                "GHSA-AUTO-002",
                cve_id="CVE-2026-GH-002",
                severity="high",
                summary="Data exfiltration through unrestricted outbound egress",
            ),
        ]

        mock_client = _mock_httpx(advisories)
        await redis.set("config:auto_mitigate_threats", "1")

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)), \
             patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        issues = (await db_session.execute(select(SecurityIssue))).scalars().all()
        assert len(issues) == 2

        # Both should be mitigated
        for issue in issues:
            assert issue.status == IssueStatus.MITIGATED

        # Verify correct rule types were inferred
        rules = (await db_session.execute(
            select(Rule).where(Rule.tags.contains(["auto-mitigation"]))
        )).scalars().all()
        rule_types = {r.rule_type for r in rules}
        assert RuleType.FILE_ACCESS in rule_types
        assert RuleType.NETWORK_EGRESS in rule_types

    @pytest.mark.asyncio
    async def test_github_fetch_skips_mitigation_when_disabled(self, db_session, redis):
        """New GitHub advisories stay ACTIVE when auto-mitigate is OFF."""
        advisories = [
            _make_github_advisory(
                "GHSA-NOAUTO",
                cve_id="CVE-2026-GH-NOAUTO",
                severity="high",
                summary="Credential exposure via leaked token authentication",
            ),
        ]

        mock_client = _mock_httpx(advisories)
        await redis.set("config:auto_mitigate_threats", "0")

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)), \
             patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        issues = (await db_session.execute(select(SecurityIssue))).scalars().all()
        assert len(issues) == 1
        assert issues[0].status == IssueStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_mitigation_failure_does_not_block_feed(self, db_session, redis):
        """If auto_mitigate_issue raises for one CVE, other CVEs still get created."""
        advisories = [
            _make_github_advisory("GHSA-FAIL-001", cve_id="CVE-2026-FAIL1", summary="Credential theft"),
            _make_github_advisory("GHSA-FAIL-002", cve_id="CVE-2026-FAIL2", summary="Command injection via RCE"),
        ]

        mock_client = _mock_httpx(advisories)
        await redis.set("config:auto_mitigate_threats", "1")

        call_count = 0
        original_fn = auto_mitigate_issue

        async def failing_first_call(db, issue_id):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Simulated mitigation failure")
            return await original_fn(db, issue_id)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)), \
             patch("app.tasks.security_research.redis_client", redis), \
             patch("app.tasks.security_research.auto_mitigate_issue", side_effect=failing_first_call):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        # Both issues should still exist in DB
        issues = (await db_session.execute(select(SecurityIssue))).scalars().all()
        assert len(issues) == 2

        # At least one should have been mitigated (the one that didn't fail)
        mitigated = [i for i in issues if i.status == IssueStatus.MITIGATED]
        assert len(mitigated) >= 1


# ===========================================================================
# 4. Runtime toggle endpoint
# ===========================================================================


class TestAutoMitigateToggle:
    """Tests for POST /api/v1/setup/auto-mitigate and the settings exposure."""

    @pytest.mark.asyncio
    async def test_toggle_on(self, client, redis):
        """POST with enabled=true sets Redis key to '1'."""
        response = await client.post(
            "/api/v1/setup/auto-mitigate",
            json={"enabled": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["auto_mitigate_threats"] is True

        # Verify Redis was set
        val = await redis.get("config:auto_mitigate_threats")
        assert val == "1"

    @pytest.mark.asyncio
    async def test_toggle_off(self, client, redis):
        """POST with enabled=false sets Redis key to '0'."""
        response = await client.post(
            "/api/v1/setup/auto-mitigate",
            json={"enabled": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["auto_mitigate_threats"] is False

        val = await redis.get("config:auto_mitigate_threats")
        assert val == "0"

    @pytest.mark.asyncio
    async def test_setup_status_reflects_toggle(self, client, redis):
        """GET /setup/status config includes auto_mitigate_threats from Redis."""
        # Set Redis override to OFF
        await redis.set("config:auto_mitigate_threats", "0")

        response = await client.get("/api/v1/setup/status")
        assert response.status_code == 200
        data = response.json()
        assert data["config"]["auto_mitigate_threats"] is False

        # Flip to ON
        await redis.set("config:auto_mitigate_threats", "1")
        response = await client.get("/api/v1/setup/status")
        data = response.json()
        assert data["config"]["auto_mitigate_threats"] is True

    @pytest.mark.asyncio
    async def test_setup_status_defaults_to_config_when_no_redis_key(self, client, redis):
        """Without Redis override, setup/status falls back to config file default (True)."""
        # Make sure Redis key doesn't exist
        await redis.client.delete("config:auto_mitigate_threats")

        response = await client.get("/api/v1/setup/status")
        assert response.status_code == 200
        data = response.json()
        # Default is True (from config.py AUTO_MITIGATE_THREATS)
        assert data["config"]["auto_mitigate_threats"] is True


# ===========================================================================
# 5. _is_auto_mitigate_enabled() Redis override precedence
# ===========================================================================


class TestAutoMitigateEnabledCheck:
    """Tests for _is_auto_mitigate_enabled() helper in background tasks."""

    @pytest.mark.asyncio
    async def test_redis_override_true(self, redis):
        """Redis key '1' → enabled regardless of config."""
        await redis.set("config:auto_mitigate_threats", "1")

        with patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _is_auto_mitigate_enabled
            assert await _is_auto_mitigate_enabled() is True

    @pytest.mark.asyncio
    async def test_redis_override_false(self, redis):
        """Redis key '0' → disabled regardless of config."""
        await redis.set("config:auto_mitigate_threats", "0")

        with patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _is_auto_mitigate_enabled
            assert await _is_auto_mitigate_enabled() is False

    @pytest.mark.asyncio
    async def test_no_redis_key_falls_back_to_config(self, redis):
        """No Redis key → falls back to settings.AUTO_MITIGATE_THREATS."""
        await redis.client.delete("config:auto_mitigate_threats")

        with patch("app.tasks.security_research.redis_client", redis):
            from app.tasks.security_research import _is_auto_mitigate_enabled
            # Default config is True
            assert await _is_auto_mitigate_enabled() is True
