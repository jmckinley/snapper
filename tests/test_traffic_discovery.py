"""Tests for traffic discovery service and API endpoints.

Covers:
  - parse_tool_name() — all 6 parsing paths
  - discover_traffic() — audit log analysis, grouping, coverage
  - check_coverage() — rule pattern matching
  - generate_rules_for_server() — smart default rule generation
  - generate_rule_from_command() — single-command rule generation
  - Custom MCP template — enable with server name
  - Traffic API endpoints — insights, coverage, create-rule, create-server-rules
"""

import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from app.data.integration_templates import INTEGRATION_TEMPLATES
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
from app.models.rules import Rule, RuleType, RuleAction
from app.services.traffic_discovery import (
    parse_tool_name,
    check_coverage,
    discover_traffic,
    generate_rules_for_server,
    generate_rule_from_command,
    KNOWN_MCP_SERVERS,
    BUILTIN_TOOLS,
)


# ---------------------------------------------------------------------------
# parse_tool_name()
# ---------------------------------------------------------------------------


class TestParseToolName:
    """Tests for the 6-step tool name parsing cascade."""

    def test_claude_mcp_double_underscore(self):
        """Standard Claude format: mcp__server__tool."""
        result = parse_tool_name("mcp__github__create_issue")
        assert result.server_key == "github"
        assert result.tool_name == "create_issue"
        assert result.source_type == "mcp"
        assert "GitHub" in result.display_name
        assert result.template_id == "github"

    def test_claude_mcp_plugin_format(self):
        """Claude Code plugin: mcp__plugin_name_server__tool."""
        result = parse_tool_name("mcp__plugin_myext_slack__list_channels")
        assert result.server_key == "slack"
        assert result.tool_name == "list_channels"
        assert result.source_type == "mcp"
        assert "Plugin" in result.display_name

    def test_builtin_tool_exact_match(self):
        """Built-in tool: bare name like 'browser'."""
        result = parse_tool_name("browser")
        assert result.server_key == "browser"
        assert result.source_type == "builtin"
        assert result.display_name == "Browser"

    def test_builtin_tool_exec(self):
        """Built-in tool: exec."""
        result = parse_tool_name("exec")
        assert result.server_key == "exec"
        assert result.source_type == "builtin"

    def test_cli_command_git(self):
        """CLI command: 'git status'."""
        result = parse_tool_name("git status")
        assert result.server_key == "git"
        assert result.tool_name == "status"
        assert result.source_type == "cli"
        assert "CLI" in result.display_name

    def test_cli_command_curl(self):
        """CLI command: 'curl https://example.com'."""
        result = parse_tool_name("curl https://example.com")
        assert result.server_key == "curl"
        assert result.source_type == "cli"

    def test_openclaw_single_underscore(self):
        """OpenClaw format: server_tool (single underscore)."""
        result = parse_tool_name("slack_list_channels")
        assert result.server_key == "slack"
        assert result.tool_name == "list_channels"
        assert result.source_type == "mcp"
        assert result.template_id == "slack"

    def test_openclaw_github_prefix(self):
        """OpenClaw format with github prefix."""
        result = parse_tool_name("github_create_issue")
        assert result.server_key == "github"
        assert result.tool_name == "create_issue"
        assert result.source_type == "mcp"

    def test_unknown_tool(self):
        """Unknown tool returns 'other' server_key."""
        result = parse_tool_name("some_random_thing_42")
        assert result.source_type == "unknown"
        assert result.server_key == "other"

    def test_empty_string(self):
        """Empty string returns unknown."""
        result = parse_tool_name("")
        assert result.server_key == "unknown"
        assert result.source_type == "unknown"

    def test_known_server_maps_to_display_name(self):
        """Known server keys resolve to friendly display names."""
        result = parse_tool_name("mcp__postgres__read_query")
        assert result.server_key == "postgres"
        assert "PostgreSQL" in result.display_name
        assert result.template_id == "database"

    def test_hyphenated_server_name(self):
        """Hyphenated server: mcp__brave-search__search."""
        result = parse_tool_name("mcp__brave-search__search")
        assert result.server_key == "brave-search"
        assert "Brave" in result.display_name
        assert result.source_type == "mcp"

    def test_aws_cli_detected(self):
        """AWS CLI command parsed correctly."""
        result = parse_tool_name("aws s3 ls")
        assert result.server_key == "aws-cli"
        assert result.source_type == "cli"


# ---------------------------------------------------------------------------
# check_coverage()
# ---------------------------------------------------------------------------


class TestCheckCoverage:

    @pytest.mark.asyncio
    async def test_uncovered_command_returns_false(self, db_session: AsyncSession):
        """Command with no matching rule returns covered=False."""
        result = await check_coverage(db_session, "mcp__unknown__do_stuff")
        assert result["covered"] is False
        assert result["matching_rules"] == []

    @pytest.mark.asyncio
    async def test_covered_by_allowlist(self, db_session: AsyncSession):
        """Command matching an allowlist pattern returns covered=True."""
        rule = Rule(
            id=uuid4(),
            name="Test Allow",
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=100,
            parameters={"patterns": ["^mcp__github__create.*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        result = await check_coverage(db_session, "mcp__github__create_issue")
        assert result["covered"] is True
        assert len(result["matching_rules"]) == 1
        assert result["matching_rules"][0]["name"] == "Test Allow"

    @pytest.mark.asyncio
    async def test_covered_by_denylist(self, db_session: AsyncSession):
        """Command matching a denylist pattern returns covered=True."""
        rule = Rule(
            id=uuid4(),
            name="Block Delete",
            rule_type=RuleType.COMMAND_DENYLIST,
            action=RuleAction.DENY,
            priority=200,
            parameters={"patterns": ["^mcp__github__delete.*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        result = await check_coverage(db_session, "mcp__github__delete_repo")
        assert result["covered"] is True
        assert result["matching_rules"][0]["action"] == "deny"

    @pytest.mark.asyncio
    async def test_inactive_rule_not_counted(self, db_session: AsyncSession):
        """Inactive rules should not provide coverage."""
        rule = Rule(
            id=uuid4(),
            name="Inactive Allow",
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=100,
            parameters={"patterns": ["^mcp__slack__.*"]},
            is_active=False,
        )
        db_session.add(rule)
        await db_session.commit()

        result = await check_coverage(db_session, "mcp__slack__list_channels")
        assert result["covered"] is False


# ---------------------------------------------------------------------------
# discover_traffic()
# ---------------------------------------------------------------------------


class TestDiscoverTraffic:

    async def _create_audit_log(
        self, db: AsyncSession, command: str, action: AuditAction, agent_id=None, minutes_ago: int = 5
    ):
        """Helper to create audit log entries."""
        log = AuditLog(
            id=uuid4(),
            action=action,
            severity=AuditSeverity.INFO,
            agent_id=agent_id,
            message=f"Test: {command}",
            details={},
            new_value={"command": command},
            created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        )
        db.add(log)
        await db.commit()
        return log

    @pytest.mark.asyncio
    async def test_empty_with_no_audit_data(self, db_session: AsyncSession):
        """No audit logs → empty insights."""
        insights = await discover_traffic(db_session, hours=168)
        assert insights.total_evaluations == 0
        assert insights.total_unique_commands == 0
        assert insights.service_groups == []

    @pytest.mark.asyncio
    async def test_groups_mcp_commands_by_server_prefix(self, db_session: AsyncSession):
        """MCP commands grouped by server prefix."""
        await self._create_audit_log(db_session, "mcp__github__create_issue", AuditAction.REQUEST_ALLOWED)
        await self._create_audit_log(db_session, "mcp__github__list_repos", AuditAction.REQUEST_ALLOWED)
        await self._create_audit_log(db_session, "mcp__slack__post_message", AuditAction.REQUEST_DENIED)

        insights = await discover_traffic(db_session, hours=168)
        assert insights.total_evaluations == 3
        assert insights.total_unique_commands == 3

        # Should have 2 service groups: github, slack
        keys = {g.server_key for g in insights.service_groups}
        assert "github" in keys
        assert "slack" in keys

        github_group = next(g for g in insights.service_groups if g.server_key == "github")
        assert len(github_group.commands) == 2
        assert github_group.total_count == 2

    @pytest.mark.asyncio
    async def test_identifies_uncovered_commands(self, db_session: AsyncSession):
        """Commands without matching rules show as uncovered."""
        await self._create_audit_log(db_session, "mcp__unknown__something", AuditAction.REQUEST_ALLOWED)

        insights = await discover_traffic(db_session, hours=168)
        assert insights.total_uncovered == 1
        group = insights.service_groups[0]
        assert group.uncovered_count == 1
        assert group.commands[0].has_matching_rule is False

    @pytest.mark.asyncio
    async def test_marks_covered_when_rule_matches(self, db_session: AsyncSession):
        """Commands with matching rules show as covered."""
        rule = Rule(
            id=uuid4(),
            name="Allow GitHub",
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=100,
            parameters={"patterns": ["^mcp__github__.*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        await self._create_audit_log(db_session, "mcp__github__create_issue", AuditAction.REQUEST_ALLOWED)

        insights = await discover_traffic(db_session, hours=168)
        assert insights.total_uncovered == 0
        group = insights.service_groups[0]
        assert group.commands[0].has_matching_rule is True

    @pytest.mark.asyncio
    async def test_hours_parameter_limits_time_range(self, db_session: AsyncSession):
        """Logs outside the hours window are excluded."""
        # Recent log (5 min ago)
        await self._create_audit_log(db_session, "mcp__github__recent", AuditAction.REQUEST_ALLOWED, minutes_ago=5)
        # Old log (25 hours ago)
        await self._create_audit_log(db_session, "mcp__github__old", AuditAction.REQUEST_ALLOWED, minutes_ago=1500)

        insights = await discover_traffic(db_session, hours=24)
        assert insights.total_evaluations == 1
        assert insights.total_unique_commands == 1

    @pytest.mark.asyncio
    async def test_maps_prefix_to_template_id(self, db_session: AsyncSession):
        """Known server prefixes link to their template IDs."""
        await self._create_audit_log(db_session, "mcp__github__list_repos", AuditAction.REQUEST_ALLOWED)

        insights = await discover_traffic(db_session, hours=168)
        group = next(g for g in insights.service_groups if g.server_key == "github")
        assert group.has_template is True
        assert group.template_id == "github"

    @pytest.mark.asyncio
    async def test_decision_buckets(self, db_session: AsyncSession):
        """Decisions are bucketed into allow/deny/pending."""
        await self._create_audit_log(db_session, "mcp__github__push", AuditAction.REQUEST_ALLOWED)
        await self._create_audit_log(db_session, "mcp__github__push", AuditAction.REQUEST_DENIED)
        await self._create_audit_log(db_session, "mcp__github__push", AuditAction.REQUEST_PENDING_APPROVAL)

        insights = await discover_traffic(db_session, hours=168)
        cmd = insights.service_groups[0].commands[0]
        assert cmd.decisions.get("allow") == 1
        assert cmd.decisions.get("deny") == 1
        assert cmd.decisions.get("pending") == 1


# ---------------------------------------------------------------------------
# generate_rules_for_server()
# ---------------------------------------------------------------------------


class TestGenerateRulesForServer:

    def test_creates_three_rules(self):
        """Should generate exactly 3 rules: allow reads, approve writes, deny destructive."""
        rules = generate_rules_for_server("google_calendar")
        assert len(rules) == 3

        actions = {r["action"] for r in rules}
        assert actions == {"allow", "require_approval", "deny"}

    def test_patterns_use_provided_server_name(self):
        """Patterns include the server name in both Claude and OpenClaw formats."""
        rules = generate_rules_for_server("google_calendar")
        allow_rule = next(r for r in rules if r["action"] == "allow")
        patterns = allow_rule["parameters"]["patterns"]

        # Should have Claude-style and OpenClaw-style patterns
        assert any("mcp__" in p for p in patterns)
        assert any("google_calendar_" in p for p in patterns)

    def test_known_server_uses_display_name(self):
        """Known server resolves to a friendly display name in rule names."""
        rules = generate_rules_for_server("github")
        assert "GitHub" in rules[0]["name"]

    def test_unknown_server_uses_titleized_name(self):
        """Unknown server gets a titleized name."""
        rules = generate_rules_for_server("my-custom-thing")
        assert "My Custom Thing" in rules[0]["name"]

    def test_rejects_empty_server_name(self):
        """Empty server name raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            generate_rules_for_server("")

    def test_rejects_whitespace_only(self):
        """Whitespace-only name raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            generate_rules_for_server("   ")

    def test_rule_types_are_correct(self):
        """Allow/approve = command_allowlist, deny = command_denylist."""
        rules = generate_rules_for_server("test")
        allow = next(r for r in rules if r["action"] == "allow")
        deny = next(r for r in rules if r["action"] == "deny")
        assert allow["rule_type"] == "command_allowlist"
        assert deny["rule_type"] == "command_denylist"

    def test_deny_has_highest_priority(self):
        """Deny rules should have the highest priority."""
        rules = generate_rules_for_server("test")
        deny = next(r for r in rules if r["action"] == "deny")
        allow = next(r for r in rules if r["action"] == "allow")
        assert deny["priority"] > allow["priority"]


# ---------------------------------------------------------------------------
# generate_rule_from_command()
# ---------------------------------------------------------------------------


class TestGenerateRuleFromCommand:

    def test_prefix_mode_mcp(self):
        """Prefix mode for MCP command generates broad server pattern."""
        rule = generate_rule_from_command("mcp__github__create_issue", action="allow", pattern_mode="prefix")
        pattern = rule["parameters"]["patterns"][0]
        assert pattern.startswith("^mcp__github__")
        assert pattern.endswith(".*")

    def test_exact_mode(self):
        """Exact mode generates anchored pattern for the exact command."""
        rule = generate_rule_from_command("mcp__github__create_issue", action="deny", pattern_mode="exact")
        pattern = rule["parameters"]["patterns"][0]
        assert pattern.startswith("^")
        assert pattern.endswith("$")
        assert "mcp__github__create_issue" in pattern

    def test_auto_generates_descriptive_name(self):
        """Name auto-generated from parsed tool name when not provided."""
        rule = generate_rule_from_command("mcp__github__create_issue")
        assert "GitHub" in rule["name"]
        assert "create_issue" in rule["name"]
        assert "(auto)" in rule["name"]

    def test_custom_name_used(self):
        """Custom name overrides auto-generated name."""
        rule = generate_rule_from_command("mcp__github__push", name="My Custom Rule")
        assert rule["name"] == "My Custom Rule"

    def test_rejects_empty_command(self):
        """Empty command raises ValueError."""
        with pytest.raises(ValueError, match="must not be empty"):
            generate_rule_from_command("")

    def test_deny_sets_command_denylist_type(self):
        """Action 'deny' results in command_denylist rule type."""
        rule = generate_rule_from_command("mcp__slack__post", action="deny")
        assert rule["rule_type"] == "command_denylist"

    def test_allow_sets_command_allowlist_type(self):
        """Action 'allow' results in command_allowlist rule type."""
        rule = generate_rule_from_command("mcp__slack__post", action="allow")
        assert rule["rule_type"] == "command_allowlist"


# ---------------------------------------------------------------------------
# Custom MCP template enable
# ---------------------------------------------------------------------------


class TestCustomMCPTemplate:

    @pytest.mark.asyncio
    async def test_enable_generates_three_rules(self, client: AsyncClient, db_session: AsyncSession):
        """Enabling custom_mcp with server_name creates 3 rules."""
        response = await client.post(
            "/api/v1/integrations/custom_mcp/enable",
            json={"custom_server_name": "google_calendar"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["rules_created"] == 3

        result = await db_session.execute(
            select(Rule).where(
                Rule.source == "integration",
                Rule.source_reference == "custom_mcp:google_calendar",
            )
        )
        rules = list(result.scalars().all())
        assert len(rules) == 3

    @pytest.mark.asyncio
    async def test_patterns_use_provided_server_name(self, client: AsyncClient, db_session: AsyncSession):
        """Created rules have patterns containing the server name."""
        await client.post(
            "/api/v1/integrations/custom_mcp/enable",
            json={"custom_server_name": "my_server"},
        )

        result = await db_session.execute(
            select(Rule).where(Rule.source_reference == "custom_mcp:my_server")
        )
        rules = list(result.scalars().all())
        for rule in rules:
            patterns = rule.parameters.get("patterns", [])
            assert any("my_server" in p for p in patterns)

    @pytest.mark.asyncio
    async def test_rejects_missing_server_name(self, client: AsyncClient):
        """Enabling custom_mcp without server_name returns 400."""
        response = await client.post(
            "/api/v1/integrations/custom_mcp/enable",
            json={},
        )
        assert response.status_code == 400
        assert "custom_server_name" in response.json()["detail"]



# ---------------------------------------------------------------------------
# Traffic API endpoints
# ---------------------------------------------------------------------------


class TestTrafficInsightsEndpoint:

    @pytest.mark.asyncio
    async def test_returns_empty_insights(self, client: AsyncClient):
        """GET /traffic/insights with no data returns empty."""
        response = await client.get("/api/v1/integrations/traffic/insights?hours=24")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 0
        assert data["service_groups"] == []

    @pytest.mark.asyncio
    async def test_returns_grouped_data(self, client: AsyncClient, db_session: AsyncSession):
        """Insights endpoint returns service groups from audit data."""
        log = AuditLog(
            id=uuid4(),
            action=AuditAction.REQUEST_ALLOWED,
            severity=AuditSeverity.INFO,
            message="Allowed mcp__github__list_repos",
            details={},
            new_value={"command": "mcp__github__list_repos"},
            created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db_session.add(log)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/traffic/insights?hours=24")
        assert response.status_code == 200
        data = response.json()
        assert data["total_evaluations"] == 1
        assert len(data["service_groups"]) == 1
        assert data["service_groups"][0]["server_key"] == "github"


class TestTrafficCoverageEndpoint:

    @pytest.mark.asyncio
    async def test_uncovered_command(self, client: AsyncClient):
        """Coverage check for uncovered command returns covered=False."""
        response = await client.get("/api/v1/integrations/traffic/coverage?command=mcp__unknown__do_stuff")
        assert response.status_code == 200
        data = response.json()
        assert data["covered"] is False
        assert "parsed" in data

    @pytest.mark.asyncio
    async def test_covered_command(self, client: AsyncClient, db_session: AsyncSession):
        """Coverage check with matching rule returns covered=True."""
        rule = Rule(
            id=uuid4(),
            name="Allow GitHub",
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=100,
            parameters={"patterns": ["^mcp__github__.*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        response = await client.get("/api/v1/integrations/traffic/coverage?command=mcp__github__create_issue")
        assert response.status_code == 200
        data = response.json()
        assert data["covered"] is True


class TestCreateRuleEndpoint:

    @pytest.mark.asyncio
    async def test_creates_rule_from_command(self, client: AsyncClient, db_session: AsyncSession):
        """POST /traffic/create-rule creates a rule and returns it."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-rule",
            json={
                "command": "mcp__github__create_issue",
                "action": "allow",
                "pattern_mode": "prefix",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "id" in data
        assert data["action"] == "allow"
        assert "GitHub" in data["name"]

    @pytest.mark.asyncio
    async def test_rejects_empty_command(self, client: AsyncClient):
        """Empty command returns 400."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-rule",
            json={"command": "  ", "action": "allow"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_rejects_invalid_action(self, client: AsyncClient):
        """Invalid action returns 400."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-rule",
            json={"command": "mcp__github__push", "action": "invalid"},
        )
        assert response.status_code == 400


class TestCreateServerRulesEndpoint:

    @pytest.mark.asyncio
    async def test_creates_three_rules(self, client: AsyncClient, db_session: AsyncSession):
        """POST /traffic/create-server-rules creates 3 smart default rules."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-server-rules",
            json={"server_name": "notion"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["rules_created"] == 3
        assert data["server_name"] == "notion"

        # Verify in DB
        result = await db_session.execute(
            select(Rule).where(Rule.source_reference == "mcp_server:notion")
        )
        rules = list(result.scalars().all())
        assert len(rules) == 3

    @pytest.mark.asyncio
    async def test_rejects_empty_server_name(self, client: AsyncClient):
        """Empty server name returns 400."""
        response = await client.post(
            "/api/v1/integrations/traffic/create-server-rules",
            json={"server_name": "  "},
        )
        assert response.status_code == 400


class TestKnownServersEndpoint:

    @pytest.mark.asyncio
    async def test_returns_known_servers(self, client: AsyncClient):
        """GET /traffic/known-servers returns list of known MCP servers."""
        response = await client.get("/api/v1/integrations/traffic/known-servers")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0

        # Check structure
        server = data[0]
        assert "display" in server
        assert "icon" in server
        assert "keys" in server
        assert isinstance(server["keys"], list)
