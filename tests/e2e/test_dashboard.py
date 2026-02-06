"""
@module test_dashboard
@description E2E tests for the Dashboard page.
Tests dashboard loading, stats display, navigation, and integration modals.
"""

from playwright.sync_api import Page, expect


class TestDashboardPage:
    """Tests for the main dashboard."""

    def test_dashboard_loads(self, dashboard_page: Page):
        """Dashboard page loads with welcome banner."""
        expect(dashboard_page.locator("text=Welcome to Snapper")).to_be_visible()
        expect(dashboard_page.locator("text=Fine-grained security control")).to_be_visible()

    def test_dashboard_has_stats(self, dashboard_page: Page):
        """Dashboard shows statistics cards."""
        expect(dashboard_page.locator("text=Integrations Active")).to_be_visible()
        expect(dashboard_page.locator("text=Rules Active")).to_be_visible()
        expect(dashboard_page.locator("text=Blocked Today")).to_be_visible()
        expect(dashboard_page.locator("text=Approvals Pending")).to_be_visible()

    def test_dashboard_has_quick_add_integrations(self, dashboard_page: Page):
        """Dashboard shows quick add integrations section."""
        expect(dashboard_page.locator("text=Quick Add Integrations")).to_be_visible()
        expect(dashboard_page.locator("text=View all 30+ integrations")).to_be_visible()

    def test_dashboard_has_recent_blocks(self, dashboard_page: Page):
        """Dashboard shows recent blocks section."""
        expect(dashboard_page.locator("text=Recent Blocks")).to_be_visible()

    def test_dashboard_has_active_integrations(self, dashboard_page: Page):
        """Dashboard shows active integrations section."""
        expect(dashboard_page.locator("text=Active Integrations")).to_be_visible()

    def test_dashboard_has_recent_activity(self, dashboard_page: Page):
        """Dashboard shows recent activity section."""
        expect(dashboard_page.locator("text=Recent Activity")).to_be_visible()

    def test_navigation_to_agents(self, dashboard_page: Page, base_url: str):
        """Can navigate to agents page from nav."""
        dashboard_page.click("nav a:has-text('Agents')")
        expect(dashboard_page).to_have_url(f"{base_url}/agents")

    def test_navigation_to_integrations(self, dashboard_page: Page, base_url: str):
        """Can navigate to integrations page from nav."""
        dashboard_page.click("nav a:has-text('Integrations')")
        expect(dashboard_page).to_have_url(f"{base_url}/integrations")

    def test_navigation_to_security(self, dashboard_page: Page, base_url: str):
        """Can navigate to security page from sidebar."""
        dashboard_page.click("nav a:has-text('Security')")
        expect(dashboard_page).to_have_url(f"{base_url}/security")


class TestIntegrationModal:
    """Tests for the integration enable modal."""

    def test_clicking_integration_opens_modal(self, dashboard_page: Page):
        """Clicking an integration shows the enable modal."""
        # Wait for integrations to load
        dashboard_page.wait_for_selector("#popular-integrations button", timeout=5000)

        # Click on GitHub integration (one of the popular ones)
        github_btn = dashboard_page.locator("#popular-integrations button:has-text('GitHub')")
        if github_btn.count() > 0:
            github_btn.click()
            dashboard_page.wait_for_timeout(500)
            # Modal should appear
            expect(dashboard_page.locator("#enable-modal")).to_be_visible()

    def test_modal_can_be_closed(self, dashboard_page: Page):
        """Enable modal can be closed with cancel button."""
        dashboard_page.wait_for_selector("#popular-integrations button", timeout=5000)

        github_btn = dashboard_page.locator("#popular-integrations button:has-text('GitHub')")
        if github_btn.count() > 0:
            github_btn.click()
            dashboard_page.wait_for_selector("#enable-modal", state="visible")

            # Click cancel
            dashboard_page.click("#enable-modal button:has-text('Cancel')")
            dashboard_page.wait_for_timeout(300)
            expect(dashboard_page.locator("#enable-modal")).to_be_hidden()
