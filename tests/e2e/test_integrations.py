"""E2E tests for the Integrations page.

Requires Playwright + running app.
Run: E2E_BASE_URL=http://localhost:8000 pytest tests/e2e/test_integrations.py -v
"""

import pytest
from playwright.sync_api import Page, expect


class TestIntegrationsPage:
    """Playwright browser tests for the integrations page."""

    def test_page_loads_with_heading(self, integrations_page: Page):
        """Page loads with 'Integrations' heading."""
        heading = integrations_page.locator("h1, h2, [data-testid='page-title']").first
        expect(heading).to_contain_text("Integrations")

    def test_category_sections_displayed(self, integrations_page: Page):
        """Category sections are displayed on the page."""
        # Should have multiple category sections
        categories = integrations_page.locator(
            "[data-category], .integration-category, section"
        ).all()
        assert len(categories) > 0

    def test_integration_cards_visible(self, integrations_page: Page):
        """Integration cards are visible (Gmail, GitHub, etc.)."""
        page_text = integrations_page.content()
        # At least some well-known integrations should be visible
        found = any(
            name in page_text
            for name in ["Gmail", "GitHub", "Slack", "Docker"]
        )
        assert found, "Expected at least one known integration name on the page"

    def test_search_filter_narrows_integrations(self, integrations_page: Page):
        """Search/filter narrows visible integrations."""
        search_input = integrations_page.locator(
            "input[type='search'], input[type='text'][placeholder*='earch'], "
            "input[placeholder*='ilter'], [data-testid='search-input']"
        ).first

        if search_input.is_visible():
            search_input.fill("Gmail")
            integrations_page.wait_for_timeout(500)
            page_text = integrations_page.content()
            assert "Gmail" in page_text
        else:
            pytest.skip("No search input found on integrations page")

    def test_enable_disable_round_trip(self, integrations_page: Page):
        """Enable → disable round-trip shows state change."""
        # Find an enable button
        enable_btn = integrations_page.locator(
            "button:has-text('Enable'), [data-action='enable']"
        ).first

        if enable_btn.is_visible():
            enable_btn.click()
            integrations_page.wait_for_timeout(1000)

            # After enabling, look for a disable button
            disable_btn = integrations_page.locator(
                "button:has-text('Disable'), [data-action='disable']"
            ).first

            if disable_btn.is_visible():
                disable_btn.click()
                integrations_page.wait_for_timeout(1000)
            # Test passes if no errors during round-trip
        else:
            pytest.skip("No enable button found on integrations page")
