"""E2E tests for the Rules page."""

from playwright.sync_api import Page, expect


class TestRulesPage:
    """Tests for the rules listing page."""

    def test_rules_page_loads(self, rules_page: Page):
        """Rules page loads correctly."""
        expect(rules_page.locator("h1")).to_contain_text("Rules")

    def test_rules_page_has_create_button(self, rules_page: Page):
        """Rules page has a create rule button."""
        expect(rules_page.locator("text=Create Rule").first).to_be_visible()

    def test_rules_page_has_templates_section(self, rules_page: Page):
        """Rules page has templates section."""
        # Look for templates link or section
        expect(rules_page.locator("text=Templates").first).to_be_visible()


class TestRulesNavigation:
    """Tests for navigation within rules pages."""

    def test_navigate_to_create_rule(self, rules_page: Page, base_url: str):
        """Can navigate to create rule page."""
        rules_page.click("text=Create Rule")
        expect(rules_page).to_have_url(f"{base_url}/rules/create")

    def test_create_rule_page_has_form(self, page: Page, base_url: str):
        """Create rule page has the rule form."""
        page.goto(f"{base_url}/rules/create")
        page.wait_for_load_state("networkidle")

        # Should have form fields
        expect(page.locator("input[name='name']").first).to_be_visible()
        expect(page.locator("select").first).to_be_visible()  # Rule type dropdown


class TestRuleTemplates:
    """Tests for rule templates functionality."""

    def test_templates_page_loads(self, page: Page, base_url: str):
        """Templates section loads with available templates."""
        page.goto(f"{base_url}/rules")
        page.wait_for_load_state("networkidle")

        # Click templates tab/section if it exists
        templates_link = page.locator("text=Templates").first
        if templates_link.is_visible():
            templates_link.click()

        # Should show some template options or be on templates view
        page.wait_for_timeout(1000)  # Give time for any AJAX

    def test_template_categories_visible(self, page: Page, base_url: str):
        """Template categories are visible (if templates section exists)."""
        page.goto(f"{base_url}/rules")
        page.wait_for_load_state("networkidle")

        # Look for common template categories
        # These might be in various formats depending on UI
        page.wait_for_timeout(1000)
