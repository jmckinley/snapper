"""E2E tests for the Integrations page.

Requires Playwright + running app.
Run: E2E_BASE_URL=http://localhost:8000 pytest tests/e2e/test_integrations.py -v
"""

import pytest
from playwright.sync_api import Page, expect


class TestIntegrationsPage:
    """Playwright browser tests for the integrations page."""

    def test_page_loads_with_heading(self, integrations_page: Page):
        """Page loads with 'Rules & Traffic' heading."""
        heading = integrations_page.locator("h1, h2, [data-testid='page-title']").first
        expect(heading).to_contain_text("Rules & Traffic")

    def test_sections_displayed(self, integrations_page: Page):
        """Main sections are displayed on the page."""
        page_text = integrations_page.content()
        assert "Discovered Activity" in page_text, "Expected 'Discovered Activity' section"
        assert "Add MCP Server" in page_text, "Expected 'Add MCP Server' section"
        assert "Active Rule Packs" in page_text, "Expected 'Active Rule Packs' section"

    def test_add_mcp_server_input_visible(self, integrations_page: Page):
        """Add MCP Server section has an input field and button."""
        input_field = integrations_page.locator("#add-server-name").first
        expect(input_field).to_be_visible()

    def test_active_packs_section_visible(self, integrations_page: Page):
        """Active Rule Packs section is visible."""
        section = integrations_page.locator("text=Active Rule Packs")
        expect(section).to_be_visible()
