"""
@module test_dashboard
@description E2E tests for the Dashboard page.
Tests dashboard loading, stats display, navigation, and active services.
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
        expect(dashboard_page.get_by_text("Services Active", exact=True)).to_be_visible()
        expect(dashboard_page.locator("text=Rules Active")).to_be_visible()
        expect(dashboard_page.locator("text=Blocked (24h)")).to_be_visible()
        expect(dashboard_page.locator("text=Approvals Pending")).to_be_visible()

    def test_dashboard_has_traffic_summary(self, dashboard_page: Page):
        """Dashboard shows traffic summary section."""
        expect(dashboard_page.locator("text=Traffic Summary")).to_be_visible()

    def test_dashboard_has_recent_blocks(self, dashboard_page: Page):
        """Dashboard shows recent blocks section."""
        expect(dashboard_page.locator("text=Recent Blocks")).to_be_visible()

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
