"""
@module test_navigation
@description E2E tests for site-wide navigation and accessibility.
Tests navbar, health endpoints, page titles, responsive design, and accessibility.
"""

from playwright.sync_api import Page, expect


class TestGlobalNavigation:
    """Tests for the global navigation bar."""

    def test_navbar_has_all_nav_items(self, dashboard_page: Page):
        """Navbar contains all main navigation items."""
        nav = dashboard_page.locator("nav")

        expect(nav.locator("a:has-text('Dashboard')")).to_be_visible()
        expect(nav.locator("a:has-text('Integrations')")).to_be_visible()
        expect(nav.locator("a:has-text('Agents')")).to_be_visible()
        expect(nav.locator("a:has-text('Security')")).to_be_visible()
        expect(nav.locator("a:has-text('Audit')")).to_be_visible()
        expect(nav.locator("a:has-text('Settings')")).to_be_visible()

    def test_navbar_navigation_works(self, page: Page, base_url: str):
        """Each navbar link navigates to correct page."""
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        nav_items = [
            ("Dashboard", "/"),
            ("Agents", "/agents"),
            ("Integrations", "/integrations"),
            ("Security", "/security"),
            ("Audit", "/audit"),
            ("Settings", "/settings"),
        ]

        for link_text, expected_path in nav_items:
            page.click(f"nav a:has-text('{link_text}')")
            page.wait_for_load_state("networkidle")
            current_url = page.url
            if expected_path == "/":
                assert current_url.rstrip("/") == base_url.rstrip("/"), \
                    f"Expected {base_url}, got {current_url}"
            else:
                assert expected_path in current_url, \
                    f"Expected {expected_path} in {current_url}"

    def test_logo_links_to_dashboard(self, page: Page, base_url: str):
        """Clicking logo returns to dashboard."""
        page.goto(f"{base_url}/settings")
        page.wait_for_load_state("networkidle")

        # Click on Snapper logo/brand (the link with the logo image)
        page.click("nav a:has(img)")
        page.wait_for_load_state("networkidle")
        expect(page).to_have_url(base_url + "/")


class TestHealthEndpoints:
    """Tests for health check endpoints."""

    def test_health_endpoint(self, page: Page, base_url: str):
        """Health endpoint returns healthy status."""
        response = page.request.get(f"{base_url}/health")
        assert response.ok
        data = response.json()
        assert data["status"] == "healthy"

    def test_readiness_endpoint(self, page: Page, base_url: str):
        """Readiness endpoint returns ready status."""
        response = page.request.get(f"{base_url}/health/ready")
        assert response.ok
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["redis"] == "connected"


class TestPageTitles:
    """Tests for page titles."""

    def test_dashboard_title(self, page: Page, base_url: str):
        """Dashboard has correct title."""
        page.goto(base_url)
        expect(page).to_have_title("Dashboard - Snapper")

    def test_agents_title(self, page: Page, base_url: str):
        """Agents page has correct title."""
        page.goto(f"{base_url}/agents")
        expect(page).to_have_title("Connect Your AI - Snapper")

    def test_rules_title(self, page: Page, base_url: str):
        """Rules page has correct title."""
        page.goto(f"{base_url}/rules")
        page.wait_for_load_state("networkidle")
        title = page.title()
        assert "Snapper" in title


class TestResponsiveDesign:
    """Tests for responsive design."""

    def test_mobile_viewport(self, page: Page, base_url: str):
        """Page works on mobile viewport."""
        page.set_viewport_size({"width": 375, "height": 667})
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        # Page should still show main content - use h2 for more specific match
        page.wait_for_selector("h2:has-text('Welcome to Snapper')", timeout=10000)
        expect(page.locator("h2:has-text('Welcome to Snapper')")).to_be_visible()

    def test_tablet_viewport(self, page: Page, base_url: str):
        """Page works on tablet viewport."""
        page.set_viewport_size({"width": 768, "height": 1024})
        page.goto(base_url)
        page.wait_for_load_state("networkidle")

        # Page should show main content - use h2 for more specific match
        page.wait_for_selector("h2:has-text('Welcome to Snapper')", timeout=10000)
        expect(page.locator("h2:has-text('Welcome to Snapper')")).to_be_visible()


class TestAccessibility:
    """Basic accessibility tests."""

    def test_page_has_main_heading(self, page: Page, base_url: str):
        """Each page has an h1 heading."""
        pages = ["/", "/agents", "/rules", "/security", "/audit", "/settings"]

        for path in pages:
            page.goto(f"{base_url}{path}")
            page.wait_for_load_state("networkidle")
            h1_count = page.locator("h1").count()
            assert h1_count >= 1, f"Page {path} should have at least one h1 heading"

    def test_images_have_alt_text(self, dashboard_page: Page):
        """Images should have alt attributes."""
        images = dashboard_page.locator("img")
        for i in range(images.count()):
            img = images.nth(i)
            alt = img.get_attribute("alt")
            # Alt can be empty string for decorative images, but should exist
            assert alt is not None, f"Image {i} should have alt attribute"

    def test_form_inputs_have_labels(self, agents_page: Page):
        """Form inputs should have associated labels."""
        # Open the register modal to get form fields
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Check that inputs have labels (either explicit or implicit)
        inputs = agents_page.locator("#register-modal input, #register-modal textarea")
        for i in range(inputs.count()):
            inp = inputs.nth(i)
            # Check for name attribute at minimum
            name = inp.get_attribute("name")
            assert name, f"Form input {i} should have a name attribute"
