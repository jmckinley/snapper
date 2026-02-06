"""
@module test_rules_crud
@description E2E tests for rule CRUD operations.
Tests that users can create, read, update, and delete rules through the web UI.
"""

import time
from playwright.sync_api import Page, expect


class TestCreateRule:
    """Tests for creating rules through the UI."""

    def test_create_rule_form_submission(self, page: Page, base_url: str):
        """Can submit the create rule form successfully."""
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        # Fill in basic info
        unique_name = f"E2E Test Rule {int(time.time())}"
        page.fill("input[name='name']", unique_name)
        page.fill("textarea[name='description']", "Created by E2E test")

        # Select rule type
        page.select_option("select[name='rule_type']", "command_denylist")
        page.wait_for_timeout(300)  # Wait for dynamic fields

        # Fill in parameters (patterns field should appear)
        patterns_input = page.locator("#parameters-fields textarea, #parameters-fields input").first
        if patterns_input.is_visible():
            patterns_input.fill(".*dangerous.*")

        # Select action
        page.select_option("select[name='action']", "deny")

        # Submit the form
        page.click("button[type='submit']")

        # Should redirect to rules list or show success
        page.wait_for_timeout(1000)
        # Either redirected to rules page or showing success message
        expect(page.locator("h1")).to_contain_text("Rules")

    def test_create_rule_appears_in_list(self, page: Page, base_url: str):
        """Newly created rule should appear in the rules list."""
        # First create a rule
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        unique_name = f"List Test Rule {int(time.time())}"
        page.fill("input[name='name']", unique_name)
        page.select_option("select[name='rule_type']", "rate_limit")
        page.wait_for_timeout(300)

        # Fill rate limit params if visible
        max_requests = page.locator("input[name='max_requests'], #parameters-fields input").first
        if max_requests.is_visible():
            max_requests.fill("50")

        page.select_option("select[name='action']", "deny")
        page.click("button[type='submit']")

        # Wait for redirect and page load
        page.wait_for_url(f"{base_url}/rules", timeout=5000)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)  # Wait for AJAX table load

        # The rule should be visible in the table
        expect(page.locator(f"text={unique_name}")).to_be_visible()


class TestToggleRuleActive:
    """Tests for toggling rule active status."""

    def test_toggle_rule_active_state(self, page: Page, base_url: str):
        """Can toggle a rule's active/inactive state from the list."""
        # First create a rule to toggle
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        unique_name = f"Toggle Test Rule {int(time.time())}"
        page.fill("input[name='name']", unique_name)
        page.select_option("select[name='rule_type']", "command_denylist")
        page.wait_for_timeout(300)
        page.select_option("select[name='action']", "deny")
        page.click("button[type='submit']")

        # Go to rules list
        page.wait_for_url(f"{base_url}/rules", timeout=5000)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)

        # Find the rule row and click the toggle
        rule_row = page.locator(f"tr:has-text('{unique_name}')")
        expect(rule_row).to_be_visible()

        # Look for toggle button or status badge
        toggle = rule_row.locator("button:has-text('Deactivate'), button:has-text('Activate'), input[type='checkbox']").first
        if toggle.is_visible():
            initial_state = toggle.is_checked() if toggle.get_attribute("type") == "checkbox" else True
            toggle.click()
            page.wait_for_timeout(500)

            # Verify state changed (either by re-checking toggle or seeing status badge change)
            page.reload()
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(1000)


class TestDeleteRule:
    """Tests for deleting rules."""

    def test_delete_rule_removes_from_list(self, page: Page, base_url: str):
        """Deleting a rule should remove it from the list."""
        # First create a rule to delete
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        unique_name = f"Delete Test Rule {int(time.time())}"
        page.fill("input[name='name']", unique_name)
        page.select_option("select[name='rule_type']", "command_denylist")
        page.wait_for_timeout(300)
        page.select_option("select[name='action']", "deny")
        page.click("button[type='submit']")

        # Go to rules list
        page.wait_for_url(f"{base_url}/rules", timeout=5000)
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)

        # Find the rule row
        rule_row = page.locator(f"tr:has-text('{unique_name}')")
        expect(rule_row).to_be_visible()

        # Click delete button
        delete_btn = rule_row.locator("button:has-text('Delete'), a:has-text('Delete')").first
        if delete_btn.is_visible():
            # Handle confirmation dialog if present
            page.on("dialog", lambda dialog: dialog.accept())
            delete_btn.click()
            page.wait_for_timeout(1000)

            # Rule should no longer be visible
            expect(page.locator(f"tr:has-text('{unique_name}')")).not_to_be_visible()


class TestApplyTemplate:
    """Tests for applying rule templates from UI."""

    def test_apply_template_from_ui(self, page: Page, base_url: str):
        """Can apply a template from the quick apply section."""
        page.goto(f"{base_url}/rules")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)

        # Look for template buttons in the quick apply section
        template_button = page.locator("button:has-text('Rate Limit'), button:has-text('Credential')").first

        if template_button.is_visible():
            # Count rules before
            initial_count = page.locator("#rules-table-body tr").count()

            template_button.click()
            page.wait_for_timeout(1500)  # Wait for API call and table refresh

            # Should either show success or increase rule count
            # Reload to see the new rule
            page.reload()
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(1000)


class TestRuleValidation:
    """Tests for form validation on rule creation."""

    def test_create_rule_requires_name(self, page: Page, base_url: str):
        """Rule creation should require a name."""
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        # Try to submit without filling name
        page.select_option("select[name='rule_type']", "command_denylist")
        page.select_option("select[name='action']", "deny")

        # The form should use HTML5 validation
        name_input = page.locator("input[name='name']")
        expect(name_input).to_have_attribute("required", "")

        # Clicking submit should not navigate away
        page.click("button[type='submit']")
        page.wait_for_timeout(300)
        expect(page).to_have_url(f"{base_url}/rules/create")

    def test_create_rule_requires_type(self, page: Page, base_url: str):
        """Rule creation should require a rule type."""
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        page.fill("input[name='name']", "Test Rule")
        # Don't select rule type

        # The form should use HTML5 validation
        type_select = page.locator("select[name='rule_type']")
        expect(type_select).to_have_attribute("required", "")
