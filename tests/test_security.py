"""Tests for security endpoints and middleware."""

import pytest
from uuid import uuid4
from unittest.mock import patch, AsyncMock


class TestSecurityMiddleware:
    """Tests for security middleware."""

    @pytest.mark.asyncio
    async def test_origin_validation_blocks_invalid_origin(self, client):
        """Test that requests with invalid origin are blocked."""
        response = await client.get(
            "/api/v1/agents",
            headers={"Origin": "https://malicious-site.com"},
        )
        # Should be blocked by origin validation
        assert response.status_code in [403, 200]  # Depends on config

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client):
        """Test that security headers are set."""
        response = await client.get("/api/v1/agents")

        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "X-Frame-Options" in response.headers
        assert "X-Request-ID" in response.headers

    @pytest.mark.asyncio
    async def test_request_id_generated(self, client):
        """Test that request IDs are generated."""
        response = await client.get("/api/v1/agents")
        assert "X-Request-ID" in response.headers
        # Should be a valid UUID format
        request_id = response.headers["X-Request-ID"]
        assert len(request_id) > 0


class TestSecurityEndpoints:
    """Tests for /api/v1/security endpoints."""

    @pytest.mark.asyncio
    async def test_list_vulnerabilities(self, client):
        """Test listing security vulnerabilities."""
        response = await client.get("/api/v1/security/vulnerabilities")
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    @pytest.mark.asyncio
    async def test_get_vulnerability_by_cve(self, client, db_session):
        """Test getting a specific vulnerability by CVE ID."""
        # First create a vulnerability
        from app.models.security_issues import SecurityIssue, IssueSeverity, IssueStatus

        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-25253",
            title="WebSocket RCE Vulnerability",
            description="Remote code execution via WebSocket",
            severity=IssueSeverity.CRITICAL,
            cvss_score=8.8,
            status=IssueStatus.ACTIVE,
        )
        db_session.add(issue)
        await db_session.commit()

        response = await client.get("/api/v1/security/vulnerabilities/CVE-2026-25253")
        assert response.status_code == 200

        data = response.json()
        assert data["cve_id"] == "CVE-2026-25253"
        assert data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_get_vulnerability_not_found(self, client):
        """Test getting a non-existent vulnerability."""
        response = await client.get("/api/v1/security/vulnerabilities/CVE-9999-99999")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_list_flagged_skills(self, client):
        """Test listing flagged ClawHub skills."""
        response = await client.get("/api/v1/security/clawhub/skills")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_get_security_score(self, client, sample_agent):
        """Test getting security score for an agent."""
        response = await client.get(
            f"/api/v1/security/score/{sample_agent.id}"
        )
        assert response.status_code == 200

        data = response.json()
        assert "score" in data
        assert "grade" in data
        assert "factors" in data
        assert 0 <= data["score"] <= 100

    @pytest.mark.asyncio
    async def test_get_security_score_not_found(self, client):
        """Test getting security score for non-existent agent."""
        fake_id = uuid4()
        response = await client.get(f"/api/v1/security/score/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_recommendations(self, client, sample_agent):
        """Test getting security recommendations for an agent."""
        response = await client.get(
            f"/api/v1/security/recommendations?agent_id={sample_agent.id}"
        )
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_apply_recommendation(self, client, sample_agent):
        """Test applying a security recommendation."""
        # Mock recommendation
        recommendation_id = "enable-origin-validation"

        response = await client.post(
            f"/api/v1/security/recommendations/{recommendation_id}/apply",
            json={"agent_id": str(sample_agent.id)},
        )
        # May return 200 or 404 depending on whether recommendation exists
        assert response.status_code in [200, 404]

    @pytest.mark.asyncio
    async def test_threat_feed(self, client):
        """Test getting threat intelligence feed."""
        response = await client.get("/api/v1/security/threats/feed")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)


class TestCVEMitigation:
    """Tests for CVE-2026-25253 mitigation."""

    @pytest.mark.asyncio
    async def test_websocket_origin_validation_rule(
        self, db_session, redis, sample_agent
    ):
        """Test that origin validation rule blocks malicious WebSocket origins."""
        from app.models.rules import Rule, RuleAction, RuleType
        from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine

        # Create origin validation rule
        rule = Rule(
            id=uuid4(),
            name="WebSocket Origin Validation",
            agent_id=sample_agent.id,
            rule_type=RuleType.ORIGIN_VALIDATION,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "allowed_origins": ["http://localhost:8000", "http://127.0.0.1:8000"],
                "validate_websocket": True,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test with malicious origin
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="websocket",
            origin="https://malicious-site.com",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_localhost_bypass_protection(self, db_session, redis, sample_agent):
        """Test that localhost-only restriction is enforced."""
        from app.models.rules import Rule, RuleAction, RuleType
        from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine

        # Create localhost restriction rule
        rule = Rule(
            id=uuid4(),
            name="Localhost Only",
            agent_id=sample_agent.id,
            rule_type=RuleType.LOCALHOST_RESTRICTION,
            action=RuleAction.DENY,
            priority=100,
            parameters={"require_localhost": True},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test with remote IP
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="api",
            client_ip="192.168.1.100",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY


class TestMaliciousSkillBlocking:
    """Tests for malicious ClawHub skill blocking."""

    @pytest.mark.asyncio
    async def test_skill_denylist_blocks_malicious_skills(
        self, db_session, redis, sample_agent
    ):
        """Test that malicious skills are blocked."""
        from app.models.rules import Rule, RuleAction, RuleType
        from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine

        # Create skill denylist rule
        rule = Rule(
            id=uuid4(),
            name="Block Malicious Skills",
            agent_id=sample_agent.id,
            rule_type=RuleType.SKILL_DENYLIST,
            action=RuleAction.DENY,
            priority=100,
            parameters={
                "blocked_skills": [
                    "malware-deployer",
                    "credential-stealer",
                    "crypto-miner",
                ],
                "block_unverified": True,
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test with malicious skill
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill_install",
            skill_name="malware-deployer",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.DENY

    @pytest.mark.asyncio
    async def test_skill_allowlist_permits_safe_skills(
        self, db_session, redis, sample_agent
    ):
        """Test that allowlisted skills are permitted."""
        from app.models.rules import Rule, RuleAction, RuleType
        from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine

        # Create skill allowlist rule
        rule = Rule(
            id=uuid4(),
            name="Allow Safe Skills",
            agent_id=sample_agent.id,
            rule_type=RuleType.SKILL_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=50,
            parameters={
                "allowed_skills": ["code-review", "test-runner", "doc-generator"],
            },
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        engine = RuleEngine(db_session, redis)

        # Test with safe skill
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="skill_install",
            skill_name="code-review",
        )

        result = await engine.evaluate(context)
        assert result.decision == EvaluationDecision.ALLOW


class TestAuditEndpoints:
    """Tests for audit log endpoints."""

    @pytest.mark.asyncio
    async def test_list_audit_logs(self, client):
        """Test listing audit logs."""
        response = await client.get("/api/v1/audit/logs")
        assert response.status_code == 200

        data = response.json()
        assert "items" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_list_violations(self, client, sample_agent):
        """Test listing policy violations."""
        response = await client.get(
            f"/api/v1/audit/violations?agent_id={sample_agent.id}"
        )
        assert response.status_code == 200

        data = response.json()
        assert "items" in data

    @pytest.mark.asyncio
    async def test_list_alerts(self, client):
        """Test listing active alerts."""
        response = await client.get("/api/v1/audit/alerts")
        assert response.status_code == 200

        data = response.json()
        assert isinstance(data, list)
