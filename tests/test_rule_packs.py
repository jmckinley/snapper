"""Tests for rule pack data structures.

Validates that all packs have consistent structure, unique rule IDs,
valid enum values, and correct category references.
"""

import pytest

from app.data.rule_packs import (
    RULE_PACK_CATEGORIES,
    RULE_PACKS,
    get_rule_pack,
    get_packs_by_category,
)
from app.models.rules import RuleType


class TestPackStructure:
    """Validate structural integrity of all rule packs."""

    REQUIRED_PACK_KEYS = {"name", "description", "icon", "category", "mcp_matcher", "rules"}
    REQUIRED_RULE_KEYS = {"id", "name", "rule_type", "action"}

    def test_all_packs_have_required_keys(self):
        """All packs must have name, description, icon, category, mcp_matcher, rules."""
        for pack_id, pack in RULE_PACKS.items():
            missing = self.REQUIRED_PACK_KEYS - set(pack.keys())
            assert not missing, (
                f"Pack '{pack_id}' missing keys: {missing}"
            )

    def test_all_pack_categories_exist_in_categories_dict(self):
        """Every pack's category must reference a valid RULE_PACK_CATEGORIES key."""
        for pack_id, pack in RULE_PACKS.items():
            category = pack.get("category")
            assert category in RULE_PACK_CATEGORIES, (
                f"Pack '{pack_id}' has unknown category '{category}'. "
                f"Valid: {list(RULE_PACK_CATEGORIES.keys())}"
            )

    def test_all_rules_have_required_fields(self):
        """Every rule in every pack must have id, name, rule_type, action."""
        for pack_id, pack in RULE_PACKS.items():
            for i, rule in enumerate(pack.get("rules", [])):
                missing = self.REQUIRED_RULE_KEYS - set(rule.keys())
                assert not missing, (
                    f"Pack '{pack_id}' rule #{i} ({rule.get('name', '?')}) "
                    f"missing keys: {missing}"
                )

    def test_all_rule_ids_globally_unique(self):
        """Every rule ID across all packs must be unique."""
        seen_ids = {}
        for pack_id, pack in RULE_PACKS.items():
            for rule in pack.get("rules", []):
                rule_id = rule.get("id")
                assert rule_id not in seen_ids, (
                    f"Duplicate rule ID '{rule_id}' in pack '{pack_id}' "
                    f"(first seen in '{seen_ids[rule_id]}')"
                )
                seen_ids[rule_id] = pack_id
        # Sanity: we should have a substantial number of rules
        # (9 packs with ~29 rules total)
        assert len(seen_ids) > 20, f"Only {len(seen_ids)} rules found across all packs"

    def test_all_rule_types_match_enum(self):
        """Every rule_type value must be a valid RuleType enum member."""
        valid_values = {rt.value for rt in RuleType}
        for pack_id, pack in RULE_PACKS.items():
            for rule in pack.get("rules", []):
                rt = rule.get("rule_type")
                assert rt in valid_values, (
                    f"Pack '{pack_id}' rule '{rule.get('name')}' "
                    f"has invalid rule_type '{rt}'. Valid: {valid_values}"
                )

    def test_selectable_packs_have_default_enabled_on_all_rules(self):
        """Packs with selectable_rules=True must set default_enabled on every rule."""
        for pack_id, pack in RULE_PACKS.items():
            if not pack.get("selectable_rules"):
                continue
            for rule in pack.get("rules", []):
                assert "default_enabled" in rule, (
                    f"Selectable pack '{pack_id}' rule '{rule.get('name')}' "
                    f"is missing 'default_enabled' flag"
                )

    def test_no_custom_mcp_entry(self):
        """custom_mcp should not exist in RULE_PACKS."""
        assert "custom_mcp" not in RULE_PACKS


class TestHelperFunctions:
    """Tests for rule pack helper functions."""

    def test_get_rule_pack_returns_known_pack(self):
        """get_rule_pack should return a dict for a known pack ID."""
        pack = get_rule_pack("gmail")
        assert pack is not None
        assert pack["name"] == "Gmail / Email"

    def test_get_rule_pack_returns_none_for_unknown(self):
        """get_rule_pack should return None for unknown pack ID."""
        assert get_rule_pack("nonexistent-pack") is None

    def test_get_packs_by_category_groups_correctly(self):
        """get_packs_by_category should return all categories with their packs."""
        result = get_packs_by_category()
        assert isinstance(result, dict)
        # Every category with packs should be present
        for pack in RULE_PACKS.values():
            cat = pack["category"]
            assert cat in result, f"Category '{cat}' missing from result"
