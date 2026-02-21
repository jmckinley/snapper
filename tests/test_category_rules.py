"""Tests for category-based rule templates."""

import re
import pytest

from app.data.category_rule_templates import (
    CATEGORY_RULE_TEMPLATES,
    generate_rules_from_category,
    get_category_info,
    get_all_categories,
)


class TestCategoryRuleTemplates:
    """Test template structure and completeness."""

    def test_all_13_categories_have_templates(self):
        expected = {
            "data_store", "code_repository", "filesystem", "shell_exec",
            "browser_automation", "network_http", "communication",
            "cloud_infra", "identity_auth", "payment_finance",
            "ai_model", "monitoring", "general",
        }
        assert set(CATEGORY_RULE_TEMPLATES.keys()) == expected

    def test_each_category_has_rules(self):
        for cat, template in CATEGORY_RULE_TEMPLATES.items():
            assert "rules" in template, f"{cat} has no rules"
            assert len(template["rules"]) >= 2, f"{cat} has fewer than 2 rules"
            assert "name" in template, f"{cat} has no name"
            assert "posture" in template, f"{cat} has no posture"

    def test_rule_structure(self):
        """Each rule must have required fields."""
        required_fields = {"name", "rule_type", "action", "priority", "parameters"}
        for cat, template in CATEGORY_RULE_TEMPLATES.items():
            for i, rule in enumerate(template["rules"]):
                for field in required_fields:
                    assert field in rule, f"{cat} rule {i} missing '{field}'"

    def test_valid_rule_types(self):
        valid_types = {
            "command_allowlist", "command_denylist",
            "credential_protection",
        }
        for cat, template in CATEGORY_RULE_TEMPLATES.items():
            for rule in template["rules"]:
                assert rule["rule_type"] in valid_types, (
                    f"{cat}: invalid rule_type '{rule['rule_type']}'"
                )

    def test_valid_actions(self):
        valid_actions = {"allow", "deny", "require_approval"}
        for cat, template in CATEGORY_RULE_TEMPLATES.items():
            for rule in template["rules"]:
                assert rule["action"] in valid_actions, (
                    f"{cat}: invalid action '{rule['action']}'"
                )

    def test_placeholders_present(self):
        """Templates must use {server_key} or {server_display} placeholders."""
        for cat, template in CATEGORY_RULE_TEMPLATES.items():
            has_placeholder = False
            for rule in template["rules"]:
                if "{server_key}" in rule.get("name", "") or "{server_display}" in rule.get("name", ""):
                    has_placeholder = True
                    break
            assert has_placeholder, f"{cat} has no placeholder in rule names"


class TestGenerateRulesFromCategory:
    """Test rule generation from templates."""

    def test_basic_generation(self):
        rules = generate_rules_from_category("data_store", "postgres", "PostgreSQL")
        assert len(rules) >= 3
        # All should have expanded names
        for rule in rules:
            assert "PostgreSQL" in rule["name"]
            assert "{server_key}" not in rule["name"]
            assert "{server_display}" not in rule["name"]

    def test_patterns_are_valid_regex(self):
        """Expanded patterns must compile as valid regex."""
        rules = generate_rules_from_category("data_store", "postgres", "PostgreSQL")
        for rule in rules:
            for pattern in rule.get("parameters", {}).get("patterns", []):
                try:
                    re.compile(pattern)
                except re.error as e:
                    pytest.fail(f"Invalid regex in {rule['name']}: {pattern} — {e}")

    def test_patterns_match_mcp_format(self):
        """Patterns should match standard MCP tool name format."""
        rules = generate_rules_from_category("data_store", "postgres", "PostgreSQL")

        # Find the allow-reads rule
        allow_rule = next(r for r in rules if r["action"] == "allow")
        patterns = allow_rule["parameters"]["patterns"]

        # Should match mcp__postgres__read_data
        assert any(re.search(p, "mcp__postgres__read_data") for p in patterns)
        assert any(re.search(p, "mcp__postgres__query_table") for p in patterns)

    def test_deny_matches_destructive(self):
        """Deny rules should match destructive operations."""
        rules = generate_rules_from_category("data_store", "postgres", "PostgreSQL")
        deny_rules = [r for r in rules if r["action"] == "deny"]
        assert len(deny_rules) >= 1

        # Find the destructive deny
        deny_patterns = []
        for r in deny_rules:
            deny_patterns.extend(r["parameters"].get("patterns", []))

        assert any(re.search(p, "mcp__postgres__delete_record") for p in deny_patterns)
        assert any(re.search(p, "mcp__postgres__drop_table") for p in deny_patterns)

    def test_unknown_category_falls_back_to_general(self):
        rules = generate_rules_from_category("nonexistent", "test", "Test")
        assert len(rules) >= 3  # Should get general template

    def test_each_rule_has_id(self):
        rules = generate_rules_from_category("data_store", "postgres", "PostgreSQL")
        for rule in rules:
            assert "id" in rule
            assert rule["id"].startswith("postgres-cat-")

    def test_special_regex_chars_escaped(self):
        """Server keys with regex-special chars must be escaped."""
        rules = generate_rules_from_category("network_http", "brave-search", "Brave Search")
        for rule in rules:
            for pattern in rule.get("parameters", {}).get("patterns", []):
                # Should have escaped the hyphen
                assert "brave\\-search" in pattern or "brave-search" not in pattern.replace("\\-", "X")

    @pytest.mark.parametrize("category", list(CATEGORY_RULE_TEMPLATES.keys()))
    def test_all_categories_generate_rules(self, category):
        """Every category must produce valid rules."""
        rules = generate_rules_from_category(category, "test_server", "Test Server")
        assert len(rules) >= 2
        for rule in rules:
            assert "name" in rule
            assert "rule_type" in rule
            assert "action" in rule
            assert "Test Server" in rule["name"]


class TestCategoryInfoHelpers:
    """Test category info retrieval."""

    def test_get_category_info(self):
        info = get_category_info("data_store")
        assert info["category"] == "data_store"
        assert info["name"] == "Data Store Security"
        assert info["posture"] == "strict"
        assert info["rule_count"] >= 3

    def test_get_all_categories(self):
        categories = get_all_categories()
        assert len(categories) == 13
        names = [c["category"] for c in categories]
        assert "data_store" in names
        assert "general" in names

    def test_unknown_category_info(self):
        info = get_category_info("nonexistent")
        # Should fall back to general
        assert info["category"] == "nonexistent"
        assert info["rule_count"] >= 3


class TestPostureDistribution:
    """Verify security postures are assigned correctly."""

    def test_strict_categories(self):
        strict = ["data_store", "filesystem", "browser_automation", "cloud_infra"]
        for cat in strict:
            assert CATEGORY_RULE_TEMPLATES[cat]["posture"] == "strict"

    def test_very_strict_categories(self):
        very_strict = ["shell_exec", "identity_auth"]
        for cat in very_strict:
            assert CATEGORY_RULE_TEMPLATES[cat]["posture"] == "very_strict"

    def test_maximum_categories(self):
        assert CATEGORY_RULE_TEMPLATES["payment_finance"]["posture"] == "maximum"

    def test_moderate_categories(self):
        moderate = ["code_repository", "network_http", "communication", "ai_model"]
        for cat in moderate:
            assert CATEGORY_RULE_TEMPLATES[cat]["posture"] == "moderate"

    def test_low_categories(self):
        assert CATEGORY_RULE_TEMPLATES["monitoring"]["posture"] == "low"

    def test_default_category(self):
        assert CATEGORY_RULE_TEMPLATES["general"]["posture"] == "default"
