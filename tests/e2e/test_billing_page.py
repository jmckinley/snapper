"""
Playwright E2E tests for the /billing page.
"""

import pytest
from playwright.sync_api import Page, expect


class TestBillingPage:
    """Tests for the /billing page."""

    def test_billing_page_renders(self, authenticated_page: Page, base_url: str):
        """Billing page shows the 'Billing' heading."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content", timeout=15000)
        expect(authenticated_page.locator("h1")).to_contain_text("Billing")

    def test_billing_shows_current_plan(self, authenticated_page: Page, base_url: str):
        """Billing page shows the 'Current Plan' section with plan name."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        expect(authenticated_page.locator("text=Current Plan")).to_be_visible()
        expect(authenticated_page.locator("#plan-name")).to_be_visible()

    def test_billing_shows_usage(self, authenticated_page: Page, base_url: str):
        """Billing page shows usage bars."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        expect(authenticated_page.locator("text=Resource Usage")).to_be_visible()
        expect(authenticated_page.locator("#usage-bars")).to_be_visible()

    def test_billing_shows_plan_features(self, authenticated_page: Page, base_url: str):
        """Billing page shows plan features section."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        expect(authenticated_page.locator("#plan-features")).to_be_visible()

    def test_billing_upgrade_option(self, authenticated_page: Page, base_url: str):
        """Billing page shows upgrade section for free plan users."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        # Free plan should show upgrade options
        expect(authenticated_page.locator("h2:has-text('Upgrade')")).to_be_visible()

    def test_billing_subscription_status(self, authenticated_page: Page, base_url: str):
        """Billing page shows the subscription status element."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        expect(authenticated_page.locator("#subscription-status")).to_be_visible()

    def test_billing_plan_comparison(self, authenticated_page: Page, base_url: str):
        """Billing page shows the plan comparison table."""
        authenticated_page.goto(f"{base_url}/billing")
        authenticated_page.wait_for_selector("#billing-content:not(.hidden)", timeout=15000)
        expect(authenticated_page.locator("text=Plan Comparison")).to_be_visible()
        # Check that plan tier columns exist
        expect(authenticated_page.locator("text=Free").first).to_be_visible()
        expect(authenticated_page.locator("text=Pro").first).to_be_visible()
        expect(authenticated_page.locator("text=Enterprise").first).to_be_visible()
