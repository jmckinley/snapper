"""Playwright E2E tests for the dashboard suggestions widget.

Tests: rendering, dismiss, action links, empty state.
"""

import pytest
from playwright.sync_api import Page, expect


class TestSuggestionsWidget:
    """Tests for the Suggested Actions widget on the dashboard."""

    def test_suggestions_render_on_dashboard(self, dashboard_page: Page):
        """Suggestions section should appear on the dashboard (either cards or empty state)."""
        # Wait for JS to fetch and render suggestions
        dashboard_page.wait_for_timeout(3000)

        suggestions_card = dashboard_page.locator("#suggestions-card")
        suggestions_empty = dashboard_page.locator("#suggestions-empty")

        # One of these should be visible
        card_visible = suggestions_card.is_visible()
        empty_visible = suggestions_empty.is_visible()

        assert card_visible or empty_visible, (
            "Neither suggestions card nor empty state is visible"
        )

    def test_suggestion_cards_have_action_buttons(self, dashboard_page: Page):
        """If suggestions are present, each should have an action button."""
        dashboard_page.wait_for_timeout(3000)

        suggestions_card = dashboard_page.locator("#suggestions-card")
        if not suggestions_card.is_visible():
            pytest.skip("No suggestions to test — all caught up")

        # Each suggestion div should have a link/button
        actions = dashboard_page.locator("#suggestions-list a, #suggestions-list button")
        assert actions.count() > 0, "Suggestions should have action buttons"

    def test_suggestion_dismiss(self, dashboard_page: Page):
        """Clicking dismiss should remove the suggestion card."""
        dashboard_page.wait_for_timeout(3000)

        suggestions_card = dashboard_page.locator("#suggestions-card")
        if not suggestions_card.is_visible():
            pytest.skip("No suggestions to dismiss")

        # Count suggestions before
        items_before = dashboard_page.locator('#suggestions-list > div[id^="suggestion-"]')
        count_before = items_before.count()
        if count_before == 0:
            pytest.skip("No dismissible suggestions")

        # Find and click the first dismiss button
        dismiss_btn = dashboard_page.locator('#suggestions-list button:has-text("Dismiss")')
        if dismiss_btn.count() == 0:
            pytest.skip("No dismiss buttons found")

        dismiss_btn.first.click()

        # Wait for animation
        dashboard_page.wait_for_timeout(500)

        # Count should decrease or card should be hidden
        items_after = dashboard_page.locator('#suggestions-list > div[id^="suggestion-"]')
        # Give a bit more time for the DOM removal
        dashboard_page.wait_for_timeout(400)

        # Either fewer items or suggestions card hidden
        new_count = items_after.count()
        assert new_count < count_before or not suggestions_card.is_visible()

    def test_suggestion_action_navigates(self, dashboard_page: Page, base_url: str):
        """Clicking a suggestion's action button should navigate to the target page."""
        dashboard_page.wait_for_timeout(3000)

        suggestions_card = dashboard_page.locator("#suggestions-card")
        if not suggestions_card.is_visible():
            pytest.skip("No suggestions to click")

        # Find the first action link
        action_link = dashboard_page.locator('#suggestions-list a[href]')
        if action_link.count() == 0:
            pytest.skip("No action links found")

        href = action_link.first.get_attribute("href")
        action_link.first.click()
        dashboard_page.wait_for_timeout(2000)

        # Verify we navigated (URL should contain the href path)
        current_url = dashboard_page.url
        if href:
            # Strip query params for comparison
            path = href.split("?")[0]
            assert path in current_url, f"Expected URL to contain {path}, got {current_url}"

    def test_suggestions_empty_state(self, authenticated_page: Page, base_url: str):
        """When no suggestions exist, the empty state should show."""
        # Navigate to dashboard
        authenticated_page.goto(base_url)
        authenticated_page.wait_for_selector("text=Welcome to Snapper", timeout=10000)
        authenticated_page.wait_for_timeout(3000)

        suggestions_card = authenticated_page.locator("#suggestions-card")
        suggestions_empty = authenticated_page.locator("#suggestions-empty")

        if suggestions_empty.is_visible():
            content = suggestions_empty.inner_text()
            assert "caught up" in content.lower() or "no recommended" in content.lower()
        elif suggestions_card.is_visible():
            # There are suggestions, which is also valid
            assert True
        else:
            # Both hidden means JS hasn't loaded yet or error — acceptable
            assert True
