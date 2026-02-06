"""Tests for IP whitelist API endpoints."""

import pytest
from uuid import uuid4

from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import (
    EvaluationContext,
    EvaluationDecision,
    RuleEngine,
)


class TestIPWhitelistAPI:
    """Tests for IP whitelist endpoints in /agents/{agent_id}/whitelist-ip."""

    @pytest.mark.asyncio
    async def test_whitelist_ip_success(self, client, sample_agent, redis):
        """Test that a valid IP is successfully added to whitelist."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "192.168.1.100", "ttl_hours": 24},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "192.168.1.100" in data["message"]

        # Verify IP is in Redis set
        whitelist_key = f"network_whitelist:{sample_agent.id}"
        members = await redis.smembers(whitelist_key)
        assert "192.168.1.100" in members

    @pytest.mark.asyncio
    async def test_whitelist_invalid_format(self, client, sample_agent):
        """Test that invalid IP format returns 400."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "not-an-ip-!!!"},
        )

        assert response.status_code == 400
        assert "Invalid IP address" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_whitelist_hostname_allowed(self, client, sample_agent, redis):
        """Test that domain names are accepted."""
        response = await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "api.example.com"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

        # Verify hostname is in Redis set
        whitelist_key = f"network_whitelist:{sample_agent.id}"
        members = await redis.smembers(whitelist_key)
        assert "api.example.com" in members

    @pytest.mark.asyncio
    async def test_list_whitelisted_ips(self, client, sample_agent, redis):
        """Test that GET returns list of whitelisted IPs."""
        # Add some IPs using the API
        await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "10.0.0.1", "ttl_hours": 1},
        )
        await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "10.0.0.2", "ttl_hours": 1},
        )

        response = await client.get(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
        )

        assert response.status_code == 200
        data = response.json()
        assert str(sample_agent.id) == data["agent_id"]
        assert "10.0.0.1" in data["whitelisted_ips"]
        assert "10.0.0.2" in data["whitelisted_ips"]

    @pytest.mark.asyncio
    async def test_remove_whitelisted_ip(self, client, sample_agent, redis):
        """Test that DELETE removes IP from whitelist."""
        # Add an IP first using the API
        await client.post(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "192.168.1.50", "ttl_hours": 1},
        )

        response = await client.delete(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "192.168.1.50"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "success"

        # Verify IP is removed (via GET API)
        list_response = await client.get(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
        )
        assert "192.168.1.50" not in list_response.json()["whitelisted_ips"]

    @pytest.mark.asyncio
    async def test_remove_nonexistent_ip_404(self, client, sample_agent, redis):
        """Test that removing non-existent IP returns 404."""
        response = await client.delete(
            f"/api/v1/agents/{sample_agent.id}/whitelist-ip",
            params={"ip_address": "1.2.3.4"},
        )

        assert response.status_code == 404
        assert "not found in whitelist" in response.json()["detail"]


class TestWhitelistBypassesEgressRule:
    """Tests for whitelisted IP bypassing network egress rules."""

    @pytest.mark.asyncio
    async def test_whitelist_bypasses_egress_rule(self, db_session, redis, sample_agent):
        """Test that a whitelisted IP is not blocked by network egress rules."""
        # Create network egress rule that allows specific hosts, denies others
        egress_rule = Rule(
            id=uuid4(),
            name="Network Egress Control",
            agent_id=sample_agent.id,
            rule_type=RuleType.NETWORK_EGRESS,
            action=RuleAction.ALLOW,  # ALLOW action when check passes
            priority=100,
            parameters={
                "allowed_hosts": ["api.example.com"],  # Only allow specific host
                "denied_hosts": [],
            },
            is_active=True,
        )
        db_session.add(egress_rule)
        await db_session.commit()

        # First, test that an unlisted IP is blocked (no allow host match + no whitelist)
        engine = RuleEngine(db_session, redis)
        context = EvaluationContext(
            agent_id=sample_agent.id,
            request_type="network",
            target_host="192.168.100.50",  # Not in allowed_hosts
        )

        result = await engine.evaluate(context)
        # Should be DENY because 192.168.100.50 not in allowed_hosts
        assert result.decision == EvaluationDecision.DENY

        # Now whitelist the IP
        whitelist_key = f"network_whitelist:{sample_agent.id}"
        await redis.sadd(whitelist_key, "192.168.100.50")

        # Re-evaluate - should now skip the egress check entirely
        # The rule won't even evaluate the host since it's whitelisted
        result2 = await engine.evaluate(context)
        # With whitelist, the egress rule returns (False, action) - meaning no match
        # So we need another ALLOW rule to actually allow it
        # For now, just verify it's not denied by the egress rule specifically
        # The result should be DENY due to "no ALLOW rule matched" not "blocked by egress"
        assert result2.decision == EvaluationDecision.DENY
        # Verify it wasn't blocked by the egress rule (blocking_rule should be None)
        assert result2.blocking_rule is None
