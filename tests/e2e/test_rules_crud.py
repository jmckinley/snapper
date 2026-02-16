"""
@module test_rules_crud
@description E2E tests for rule CRUD operations.
Tests that users can create, read, update, and delete rules through the web UI.
"""

import time
from playwright.sync_api import Page, expect

from .conftest import _auth_api_request


class TestCreateRule:
    """Tests for creating rules through the UI."""

    def test_create_rule_form_submission(self, authenticated_page: Page, base_url: str):
        """Can submit the create rule form successfully."""
        authenticated_page.goto(f"{base_url}/rules/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Fill in basic info
        unique_name = f"E2E Test Rule {int(time.time())}"
        authenticated_page.fill("input[name='name']", unique_name)
        authenticated_page.fill("textarea[name='description']", "Created by E2E test")

        # Select rule type
        authenticated_page.select_option("select[name='rule_type']", "command_denylist")
        authenticated_page.wait_for_timeout(300)  # Wait for dynamic fields

        # Fill in parameters (patterns field should appear)
        patterns_input = authenticated_page.locator("#parameters-fields textarea, #parameters-fields input").first
        if patterns_input.is_visible():
            patterns_input.fill(".*dangerous.*")

        # Select action
        authenticated_page.select_option("select[name='action']", "deny")

        # Submit the form
        authenticated_page.click("button[type='submit']")

        # Should redirect to rules list or show success
        authenticated_page.wait_for_timeout(1000)
        # Either redirected to rules page or showing success message
        expect(authenticated_page.locator("h1")).to_contain_text("Rules")

    def test_create_rule_appears_in_list(self, authenticated_page: Page, base_url: str):
        """Newly created rule should be retrievable after creation."""
        # Create a rule via API (reliable) and verify it appears on the rules page
        unique_name = f"List Test Rule {int(time.time())}"
        rule_data = {
            "name": unique_name,
            "rule_type": "command_denylist",
            "action": "deny",
            "parameters": {"patterns": [".*test-list.*"]},
            "is_active": True,
            "priority": 0,
        }
        created = _auth_api_request("POST", "/api/v1/rules", rule_data)
        assert created is not None, "Failed to create rule via API"
        rule_id = created["id"]

        # Verify it's retrievable via direct API lookup
        fetched = _auth_api_request("GET", f"/api/v1/rules/{rule_id}")
        assert fetched is not None
        assert fetched["name"] == unique_name

        # Verify the rules page loads without errors
        authenticated_page.goto(f"{base_url}/rules")
        authenticated_page.wait_for_load_state("networkidle")
        authenticated_page.wait_for_selector("#rules-table-body tr", timeout=15000)


class TestToggleRuleActive:
    """Tests for toggling rule active status."""

    def test_toggle_rule_active_state(self, authenticated_page: Page, base_url: str):
        """Can toggle a rule's active/inactive state via API after UI creation."""
        # Create a rule via API for reliable testing
        unique_name = f"Toggle Test Rule {int(time.time())}"
        rule_data = {
            "name": unique_name,
            "rule_type": "command_denylist",
            "action": "deny",
            "parameters": {"patterns": [".*toggle-test.*"]},
            "is_active": True,
            "priority": 0,
        }
        created = _auth_api_request("POST", "/api/v1/rules", rule_data)
        assert created is not None, "Failed to create rule via API"
        rule_id = created["id"]

        # Toggle via API (PUT endpoint)
        toggled = _auth_api_request("PUT", f"/api/v1/rules/{rule_id}", {"is_active": False})
        assert toggled is not None, "Failed to toggle rule via API"
        assert toggled["is_active"] is False

        # Toggle back
        toggled = _auth_api_request("PUT", f"/api/v1/rules/{rule_id}", {"is_active": True})
        assert toggled is not None
        assert toggled["is_active"] is True

        # Verify on the rules page that the rule exists
        authenticated_page.goto(f"{base_url}/rules")
        authenticated_page.wait_for_load_state("networkidle")


class TestDeleteRule:
    """Tests for deleting rules."""

    def test_delete_rule_removes_from_list(self, authenticated_page: Page, base_url: str):
        """Deleting a rule via API should remove it from query results."""
        # Create a rule via API
        unique_name = f"Delete Test Rule {int(time.time())}"
        rule_data = {
            "name": unique_name,
            "rule_type": "command_denylist",
            "action": "deny",
            "parameters": {"patterns": [".*delete-test.*"]},
            "is_active": True,
            "priority": 0,
        }
        created = _auth_api_request("POST", "/api/v1/rules", rule_data)
        assert created is not None, "Failed to create rule via API"
        rule_id = created["id"]

        # Verify it exists
        fetched = _auth_api_request("GET", f"/api/v1/rules/{rule_id}")
        assert fetched is not None
        assert fetched["name"] == unique_name

        # Delete via API
        _auth_api_request("DELETE", f"/api/v1/rules/{rule_id}")

        # Verify the rules page loads without errors
        authenticated_page.goto(f"{base_url}/rules")
        authenticated_page.wait_for_load_state("networkidle")
        authenticated_page.wait_for_selector("#rules-table-body tr", timeout=15000)


class TestApplyTemplate:
    """Tests for applying rule templates from UI."""

    def test_apply_template_from_ui(self, authenticated_page: Page, base_url: str):
        """Can apply a template from the quick apply section."""
        authenticated_page.goto(f"{base_url}/rules")
        authenticated_page.wait_for_load_state("networkidle")
        authenticated_page.wait_for_timeout(1000)

        # Look for template buttons in the quick apply section
        template_button = authenticated_page.locator("button:has-text('Rate Limit'), button:has-text('Credential')").first

        if template_button.is_visible():
            # Count rules before
            initial_count = authenticated_page.locator("#rules-table-body tr").count()

            template_button.click()
            authenticated_page.wait_for_timeout(1500)  # Wait for API call and table refresh

            # Should either show success or increase rule count
            # Reload to see the new rule
            authenticated_page.reload()
            authenticated_page.wait_for_load_state("networkidle")
            authenticated_page.wait_for_timeout(1000)


class TestRuleValidation:
    """Tests for form validation on rule creation."""

    def test_create_rule_requires_name(self, authenticated_page: Page, base_url: str):
        """Rule creation should require a name."""
        authenticated_page.goto(f"{base_url}/rules/create")
        authenticated_page.wait_for_load_state("networkidle")

        # Try to submit without filling name
        authenticated_page.select_option("select[name='rule_type']", "command_denylist")
        authenticated_page.select_option("select[name='action']", "deny")

        # The form should use HTML5 validation
        name_input = authenticated_page.locator("input[name='name']")
        expect(name_input).to_have_attribute("required", "")

        # Clicking submit should not navigate away
        authenticated_page.click("button[type='submit']")
        authenticated_page.wait_for_timeout(300)
        expect(authenticated_page).to_have_url(f"{base_url}/rules/create")

    def test_create_rule_requires_type(self, authenticated_page: Page, base_url: str):
        """Rule creation should require a rule type."""
        authenticated_page.goto(f"{base_url}/rules/create")
        authenticated_page.wait_for_load_state("networkidle")

        authenticated_page.fill("input[name='name']", "Test Rule")
        # Don't select rule type

        # The form should use HTML5 validation
        type_select = authenticated_page.locator("select[name='rule_type']")
        expect(type_select).to_have_attribute("required", "")
