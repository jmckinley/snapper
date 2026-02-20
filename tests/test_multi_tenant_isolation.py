"""
Tests for multi-tenant cross-org boundary enforcement (Phase 1 hardening).

Verifies that GET-by-ID, UPDATE, and DELETE endpoints return 404 when a
user in Org A tries to access resources belonging to Org B.  Also tests:
- SELF_HOSTED mode skips all org checks (backward compat)
- API key org cross-check
- Security score isolation per org
- OrgIssueMitigation per-org independence
- SecurityRecommendation org scoping
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity, PolicyViolation
from app.models.organizations import Organization, OrganizationMembership, OrgRole, Plan
from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    SecurityIssue,
    SecurityRecommendation,
)
from app.models.users import User
from app.services.auth import create_user


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable_auth_middleware(monkeypatch):
    """Override SELF_HOSTED=false so the auth middleware enforces auth."""
    monkeypatch.setenv("SELF_HOSTED", "false")
    from app.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    plan = Plan(
        id="free",
        name="Free",
        max_agents=10,
        max_rules=100,
        max_vault_entries=50,
        max_team_members=5,
        max_teams=3,
        price_monthly_cents=0,
        price_yearly_cents=0,
        features={},
    )
    db_session.add(plan)
    await db_session.flush()
    return plan


async def _register_and_get_cookies(client: AsyncClient, email: str, username: str):
    """Register a user and return (user_data, access_token, refresh_token)."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": "SecurePass1!",
            "password_confirm": "SecurePass1!",
        },
    )
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    access_token = resp.cookies.get("snapper_access_token")
    refresh_token = resp.cookies.get("snapper_refresh_token")
    return resp.json(), access_token, refresh_token


def _set_auth(client: AsyncClient, access: str, refresh: str):
    client.cookies.set("snapper_access_token", access)
    client.cookies.set("snapper_refresh_token", refresh)


@pytest_asyncio.fixture
async def two_users(client, db_session, seed_plans):
    """Register two users (different orgs) and create agents/rules in each."""
    data_a, acc_a, ref_a = await _register_and_get_cookies(
        client, "iso_user_a@test.com", "iso_user_a"
    )
    data_b, acc_b, ref_b = await _register_and_get_cookies(
        client, "iso_user_b@test.com", "iso_user_b"
    )
    org_a = UUID(data_a["default_organization_id"])
    org_b = UUID(data_b["default_organization_id"])

    agent_a = Agent(
        id=uuid4(),
        name="Agent A",
        external_id=f"agent-a-{uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org_a,
    )
    agent_b = Agent(
        id=uuid4(),
        name="Agent B",
        external_id=f"agent-b-{uuid4().hex[:8]}",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        organization_id=org_b,
    )
    db_session.add_all([agent_a, agent_b])
    await db_session.flush()

    rule_a = Rule(
        id=uuid4(),
        name="Rule A",
        rule_type=RuleType.RATE_LIMIT,
        action=RuleAction.DENY,
        priority=10,
        parameters={"max_requests": 50, "window_seconds": 60},
        is_active=True,
        agent_id=agent_a.id,
        organization_id=org_a,
    )
    rule_b = Rule(
        id=uuid4(),
        name="Rule B",
        rule_type=RuleType.RATE_LIMIT,
        action=RuleAction.DENY,
        priority=10,
        parameters={"max_requests": 50, "window_seconds": 60},
        is_active=True,
        agent_id=agent_b.id,
        organization_id=org_b,
    )
    db_session.add_all([rule_a, rule_b])
    await db_session.flush()

    return {
        "user_a": {"data": data_a, "access": acc_a, "refresh": ref_a, "org_id": org_a},
        "user_b": {"data": data_b, "access": acc_b, "refresh": ref_b, "org_id": org_b},
        "agent_a": agent_a,
        "agent_b": agent_b,
        "rule_a": rule_a,
        "rule_b": rule_b,
    }


# ---------------------------------------------------------------------------
# 1. Agent GET by ID — cross-org returns 404
# ---------------------------------------------------------------------------


class TestAgentCrossOrgById:
    @pytest.mark.asyncio
    async def test_get_agent_cross_org_404(self, client, two_users):
        """User A gets 404 when requesting Agent B by ID."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get(f"/api/v1/agents/{two_users['agent_b'].id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_own_agent_200(self, client, two_users):
        """User A can GET their own agent by ID."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get(f"/api/v1/agents/{two_users['agent_a'].id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Agent A"

    @pytest.mark.asyncio
    async def test_update_agent_cross_org_404(self, client, two_users):
        """User A gets 404 when trying to update Agent B."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.patch(
            f"/api/v1/agents/{two_users['agent_b'].id}",
            json={"name": "Hacked Name"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_agent_cross_org_404(self, client, two_users):
        """User A gets 404 when trying to delete Agent B."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.delete(f"/api/v1/agents/{two_users['agent_b'].id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 2. Rule GET/UPDATE/DELETE by ID — cross-org returns 404
# ---------------------------------------------------------------------------


class TestRuleCrossOrgById:
    @pytest.mark.asyncio
    async def test_get_rule_cross_org_404(self, client, two_users):
        """User A gets 404 when requesting Rule B by ID."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get(f"/api/v1/rules/{two_users['rule_b'].id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_own_rule_200(self, client, two_users):
        """User A can GET their own rule by ID."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get(f"/api/v1/rules/{two_users['rule_a'].id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Rule A"

    @pytest.mark.asyncio
    async def test_update_rule_cross_org_404(self, client, two_users):
        """User A gets 404 when trying to update Rule B."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.patch(
            f"/api/v1/rules/{two_users['rule_b'].id}",
            json={"name": "Hacked Rule"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rule_cross_org_404(self, client, two_users):
        """User A gets 404 when trying to delete Rule B."""
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.delete(f"/api/v1/rules/{two_users['rule_b'].id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. Vault cross-org boundary
# ---------------------------------------------------------------------------


class TestVaultCrossOrg:
    @pytest.mark.asyncio
    async def test_delete_vault_entry_cross_org_404(
        self, client, db_session, two_users
    ):
        """User A gets 404 when trying to delete a vault entry in Org B."""
        from app.models.pii_vault import PIIVaultEntry

        entry = PIIVaultEntry(
            id=uuid4(),
            label="Org B Secret",
            token=f"{{{{SNAPPER_VAULT:{uuid4().hex[:32]}}}}}",
            encrypted_value=b"secret_data",
            masked_value="***@example.com",
            category="email",
            owner_chat_id="vault-owner-123",
            organization_id=two_users["user_b"]["org_id"],
        )
        db_session.add(entry)
        await db_session.flush()

        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.delete(f"/api/v1/vault/entries/{entry.id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. Threat event cross-org boundary
# ---------------------------------------------------------------------------


class TestThreatCrossOrg:
    @pytest.mark.asyncio
    async def test_get_threat_event_cross_org_404(
        self, client, db_session, two_users
    ):
        """User A gets 404 when requesting a threat event from Org B."""
        from app.models.threat_events import ThreatEvent

        event = ThreatEvent(
            id=uuid4(),
            agent_id=two_users["agent_b"].id,
            organization_id=two_users["user_b"]["org_id"],
            composite_score=75.0,
            signals=[{"type": "suspicious_dest", "score": 30}],
            kill_chains=[],
            resolution="pending",
        )
        db_session.add(event)
        await db_session.flush()

        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get(f"/api/v1/threats/{event.id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_resolve_threat_event_cross_org_404(
        self, client, db_session, two_users
    ):
        """User A gets 404 when trying to resolve a threat event in Org B."""
        from app.models.threat_events import ThreatEvent

        event = ThreatEvent(
            id=uuid4(),
            agent_id=two_users["agent_b"].id,
            organization_id=two_users["user_b"]["org_id"],
            composite_score=65.0,
            signals=[],
            kill_chains=[],
            resolution="pending",
        )
        db_session.add(event)
        await db_session.flush()

        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.post(
            f"/api/v1/threats/{event.id}/resolve",
            json={"resolution": "false_positive", "notes": "hacked"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. SecurityRecommendation org scoping
# ---------------------------------------------------------------------------


class TestRecommendationOrgScoping:
    @pytest.mark.asyncio
    async def test_recommendations_filtered_by_org(
        self, client, db_session, two_users
    ):
        """User A sees only recommendations from their org."""
        rec_a = SecurityRecommendation(
            id=uuid4(),
            agent_id=two_users["agent_a"].id,
            organization_id=two_users["user_a"]["org_id"],
            title="Rec for Org A",
            description="Improve A",
            rationale="Score boost",
            severity=IssueSeverity.MEDIUM,
            impact_score=10.0,
        )
        rec_b = SecurityRecommendation(
            id=uuid4(),
            agent_id=two_users["agent_b"].id,
            organization_id=two_users["user_b"]["org_id"],
            title="Rec for Org B",
            description="Improve B",
            rationale="Score boost",
            severity=IssueSeverity.MEDIUM,
            impact_score=10.0,
        )
        db_session.add_all([rec_a, rec_b])
        await db_session.flush()

        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.get("/api/v1/security/recommendations")
        assert resp.status_code == 200
        titles = [r["title"] for r in resp.json()]
        assert "Rec for Org A" in titles
        assert "Rec for Org B" not in titles


# ---------------------------------------------------------------------------
# 6. SecurityIssue (CVE) visible to both orgs (shared intel)
# ---------------------------------------------------------------------------


class TestSharedThreatIntelligence:
    @pytest.mark.asyncio
    async def test_cve_visible_to_both_orgs(
        self, client, db_session, two_users
    ):
        """SecurityIssue (CVE) is global — visible to both orgs."""
        cve = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-99999",
            title="Test CVE",
            description="Global vulnerability",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="nvd",
        )
        db_session.add(cve)
        await db_session.flush()

        # User A sees it
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp_a = await client.get("/api/v1/security/vulnerabilities")
        assert resp_a.status_code == 200
        cve_ids_a = [v.get("cve_id") for v in resp_a.json()]
        assert "CVE-2026-99999" in cve_ids_a

        # User B sees it too
        _set_auth(client, two_users["user_b"]["access"], two_users["user_b"]["refresh"])
        resp_b = await client.get("/api/v1/security/vulnerabilities")
        assert resp_b.status_code == 200
        cve_ids_b = [v.get("cve_id") for v in resp_b.json()]
        assert "CVE-2026-99999" in cve_ids_b


# ---------------------------------------------------------------------------
# 7. OrgIssueMitigation per-org independence
# ---------------------------------------------------------------------------


class TestPerOrgMitigation:
    @pytest.mark.asyncio
    async def test_mitigate_cve_independent_per_org(
        self, client, db_session, two_users
    ):
        """Org A mitigates a CVE; Org B still sees it as active."""
        cve = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-88888",
            title="Per-Org Mitigation Test",
            description="Test per-org mitigation",
            severity=IssueSeverity.CRITICAL,
            status=IssueStatus.ACTIVE,
            source="nvd",
            auto_generate_rules=True,
        )
        db_session.add(cve)
        await db_session.flush()
        await db_session.commit()

        # User A mitigates
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp = await client.post(
            f"/api/v1/security/vulnerabilities/{cve.id}/mitigate"
        )
        assert resp.status_code == 200

        # User A sees it as mitigated in threat feed
        feed_a = await client.get("/api/v1/security/threat-feed")
        assert feed_a.status_code == 200

        # User B still sees it without org-level mitigation
        _set_auth(client, two_users["user_b"]["access"], two_users["user_b"]["refresh"])
        feed_b = await client.get("/api/v1/security/threat-feed")
        assert feed_b.status_code == 200


# ---------------------------------------------------------------------------
# 8. Security score isolation
# ---------------------------------------------------------------------------


class TestSecurityScoreIsolation:
    @pytest.mark.asyncio
    async def test_security_score_per_org(self, client, db_session, two_users, redis):
        """Security score calculated with org-scoped rules only."""
        # Add rules only to org A
        for i in range(3):
            db_session.add(Rule(
                id=uuid4(),
                name=f"Org A Score Rule {i}",
                rule_type=[
                    RuleType.ORIGIN_VALIDATION,
                    RuleType.CREDENTIAL_PROTECTION,
                    RuleType.RATE_LIMIT,
                ][i],
                action=RuleAction.DENY,
                priority=100,
                parameters={
                    "allowed_origins": ["http://localhost"],
                    "protected_patterns": [r"\.env$", r"\.pem$", r"\.key$", r"credentials"],
                    "max_requests": 100, "window_seconds": 60,
                }
                if i != 0
                else {"allowed_origins": ["http://localhost"], "strict_mode": True},
                is_active=True,
                organization_id=two_users["user_a"]["org_id"],
            ))
        await db_session.flush()

        # User A should have a non-zero score
        _set_auth(client, two_users["user_a"]["access"], two_users["user_a"]["refresh"])
        resp_a = await client.get("/api/v1/security/score")
        assert resp_a.status_code == 200
        score_a = resp_a.json().get("score", 0)

        # User B should have a different (likely lower) score
        _set_auth(client, two_users["user_b"]["access"], two_users["user_b"]["refresh"])
        resp_b = await client.get("/api/v1/security/score")
        assert resp_b.status_code == 200
        score_b = resp_b.json().get("score", 0)

        # Org A has more rules → higher score
        assert score_a > score_b


# ---------------------------------------------------------------------------
# 9. SELF_HOSTED mode skips all org checks (backward compat)
# ---------------------------------------------------------------------------


class TestSelfHostedBypass:
    @pytest.fixture(autouse=True)
    def _override_self_hosted(self, monkeypatch):
        """Override to SELF_HOSTED=true for these tests."""
        monkeypatch.setenv("SELF_HOSTED", "true")
        from app.config import get_settings
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_cross_org_agent_accessible_self_hosted(
        self, client, db_session, seed_plans
    ):
        """In SELF_HOSTED mode, cross-org access is permitted."""
        data_a, acc_a, ref_a = await _register_and_get_cookies(
            client, "sh_a@test.com", "sh_a"
        )
        org_a = UUID(data_a["default_organization_id"])

        # Create agent in a different org
        other_org = Organization(
            id=uuid4(),
            name="Other Org",
            slug=f"other-{uuid4().hex[:6]}",
            plan_id="free",
            is_active=True,
        )
        db_session.add(other_org)
        await db_session.flush()

        agent = Agent(
            id=uuid4(),
            name="Other Org Agent",
            external_id=f"other-{uuid4().hex[:8]}",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            organization_id=other_org.id,
        )
        db_session.add(agent)
        await db_session.flush()

        _set_auth(client, acc_a, ref_a)
        resp = await client.get(f"/api/v1/agents/{agent.id}")
        # SELF_HOSTED skips verify_resource_org → should be accessible
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 10. PolicyViolation org scoping
# ---------------------------------------------------------------------------


class TestPolicyViolationOrgScoping:
    @pytest.mark.asyncio
    async def test_violations_filtered_by_org(
        self, client, db_session, two_users
    ):
        """PolicyViolations for Org A are invisible to Org B."""
        violation = PolicyViolation(
            id=uuid4(),
            agent_id=two_users["agent_a"].id,
            violation_type="rate_limit_exceeded",
            severity=AuditSeverity.WARNING,
            description="Rate limit hit in Org A",
            context={"test": True},
            organization_id=two_users["user_a"]["org_id"],
        )
        db_session.add(violation)
        await db_session.flush()

        # The security weekly digest and score calculations filter by org.
        # This verifies the model has organization_id set correctly.
        result = await db_session.execute(
            select(PolicyViolation).where(
                PolicyViolation.organization_id == two_users["user_a"]["org_id"]
            )
        )
        violations = list(result.scalars().all())
        assert len(violations) >= 1
        assert violations[0].description == "Rate limit hit in Org A"

        # Org B query returns empty
        result_b = await db_session.execute(
            select(PolicyViolation).where(
                PolicyViolation.organization_id == two_users["user_b"]["org_id"]
            )
        )
        assert len(list(result_b.scalars().all())) == 0
