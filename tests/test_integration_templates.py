"""Tests for integration template data structures.

Validates that all templates have consistent structure, unique rule IDs,
valid enum values, and correct category references.
"""

import pytest

from app.data.integration_templates import (
    INTEGRATION_CATEGORIES,
    INTEGRATION_TEMPLATES,
    get_template,
    get_templates_by_category,
)
from app.models.rules import RuleType


class TestTemplateStructure:
    """Validate structural integrity of all integration templates."""

    REQUIRED_TEMPLATE_KEYS = {"name", "description", "icon", "category", "mcp_matcher", "rules"}
    REQUIRED_RULE_KEYS = {"id", "name", "rule_type", "action"}

    def test_all_templates_have_required_keys(self):
        """All templates must have name, description, icon, category, mcp_matcher, rules."""
        for template_id, template in INTEGRATION_TEMPLATES.items():
            missing = self.REQUIRED_TEMPLATE_KEYS - set(template.keys())
            assert not missing, (
                f"Template '{template_id}' missing keys: {missing}"
            )

    def test_all_template_categories_exist_in_categories_dict(self):
        """Every template's category must reference a valid INTEGRATION_CATEGORIES key."""
        for template_id, template in INTEGRATION_TEMPLATES.items():
            category = template.get("category")
            assert category in INTEGRATION_CATEGORIES, (
                f"Template '{template_id}' has unknown category '{category}'. "
                f"Valid: {list(INTEGRATION_CATEGORIES.keys())}"
            )

    def test_all_rules_have_required_fields(self):
        """Every rule in every template must have id, name, rule_type, action."""
        for template_id, template in INTEGRATION_TEMPLATES.items():
            for i, rule in enumerate(template.get("rules", [])):
                missing = self.REQUIRED_RULE_KEYS - set(rule.keys())
                assert not missing, (
                    f"Template '{template_id}' rule #{i} ({rule.get('name', '?')}) "
                    f"missing keys: {missing}"
                )

    def test_all_rule_ids_globally_unique(self):
        """Every rule ID across all templates must be unique."""
        seen_ids = {}
        for template_id, template in INTEGRATION_TEMPLATES.items():
            for rule in template.get("rules", []):
                rule_id = rule.get("id")
                assert rule_id not in seen_ids, (
                    f"Duplicate rule ID '{rule_id}' in template '{template_id}' "
                    f"(first seen in '{seen_ids[rule_id]}')"
                )
                seen_ids[rule_id] = template_id
        # Sanity: we should have a substantial number of rules
        assert len(seen_ids) > 50, f"Only {len(seen_ids)} rules found across all templates"

    def test_all_rule_types_match_enum(self):
        """Every rule_type value must be a valid RuleType enum member."""
        valid_values = {rt.value for rt in RuleType}
        for template_id, template in INTEGRATION_TEMPLATES.items():
            for rule in template.get("rules", []):
                rt = rule.get("rule_type")
                assert rt in valid_values, (
                    f"Template '{template_id}' rule '{rule.get('name')}' "
                    f"has invalid rule_type '{rt}'. Valid: {valid_values}"
                )

    def test_selectable_templates_have_default_enabled_on_all_rules(self):
        """Templates with selectable_rules=True must set default_enabled on every rule."""
        for template_id, template in INTEGRATION_TEMPLATES.items():
            if not template.get("selectable_rules"):
                continue
            for rule in template.get("rules", []):
                assert "default_enabled" in rule, (
                    f"Selectable template '{template_id}' rule '{rule.get('name')}' "
                    f"is missing 'default_enabled' flag"
                )


class TestHelperFunctions:
    """Tests for integration template helper functions."""

    def test_get_template_returns_known_template(self):
        """get_template should return a dict for a known template ID."""
        template = get_template("gmail")
        assert template is not None
        assert template["name"] == "Gmail"

    def test_get_template_returns_none_for_unknown(self):
        """get_template should return None for unknown template ID."""
        assert get_template("nonexistent-integration") is None

    def test_get_templates_by_category_groups_correctly(self):
        """get_templates_by_category should return all categories with their templates."""
        result = get_templates_by_category()
        assert isinstance(result, dict)
        # Every category with templates should be present
        for template in INTEGRATION_TEMPLATES.values():
            cat = template["category"]
            assert cat in result, f"Category '{cat}' missing from result"
