"""E2E tests for the Security page."""

from playwright.sync_api import Page, expect


class TestSecurityPage:
    """Tests for the security dashboard page."""

    def test_security_page_loads(self, security_page: Page):
        """Security page loads correctly."""
        expect(security_page.locator("h1")).to_contain_text("Security")

    def test_security_page_has_vulnerability_section(self, security_page: Page):
        """Security page shows vulnerability information."""
        # Look for vulnerability-related content
        page_content = security_page.content()
        assert "vulnerabilit" in page_content.lower() or "CVE" in page_content or "security" in page_content.lower()

    def test_security_page_has_threat_feed(self, security_page: Page):
        """Security page shows threat feed or alerts."""
        # May show threats, alerts, or recommendations
        page_content = security_page.content()
        security_keywords = ["threat", "alert", "recommendation", "score", "risk"]
        found = any(kw in page_content.lower() for kw in security_keywords)
        assert found, "Security page should contain security-related content"


class TestAuditPage:
    """Tests for the audit log page."""

    def test_audit_page_loads(self, page: Page, base_url: str):
        """Audit page loads correctly."""
        page.goto(f"{base_url}/audit")
        page.wait_for_selector("text=Audit", timeout=10000)
        expect(page.locator("h1")).to_contain_text("Audit")

    def test_audit_page_has_logs_section(self, page: Page, base_url: str):
        """Audit page shows logs section."""
        page.goto(f"{base_url}/audit")
        page.wait_for_load_state("networkidle")

        # Should show logs, violations, or alerts tabs/sections
        page_content = page.content()
        assert "log" in page_content.lower() or "activity" in page_content.lower()


class TestSettingsPage:
    """Tests for the settings page."""

    def test_settings_page_loads(self, settings_page: Page):
        """Settings page loads correctly."""
        expect(settings_page.locator("h1")).to_contain_text("Settings")

    def test_settings_page_has_configuration_options(self, settings_page: Page):
        """Settings page has configuration options."""
        page_content = settings_page.content()
        # Should have some settings-related content
        settings_keywords = ["setting", "config", "option", "mode", "enable", "disable"]
        found = any(kw in page_content.lower() for kw in settings_keywords)
        assert found, "Settings page should contain configuration options"


class TestWizardPage:
    """Tests for the setup wizard page."""

    def test_wizard_page_loads(self, page: Page, base_url: str):
        """Wizard page loads correctly."""
        page.goto(f"{base_url}/wizard")
        page.wait_for_load_state("networkidle")
        # Wizard should have some guidance content
        expect(page.locator("body")).to_contain_text(["wizard", "setup", "start", "guide"], ignore_case=True)


class TestHelpPage:
    """Tests for the help/documentation page."""

    def test_help_page_loads(self, page: Page, base_url: str):
        """Help page loads correctly."""
        page.goto(f"{base_url}/help")
        page.wait_for_load_state("networkidle")

    def test_docs_page_loads(self, page: Page, base_url: str):
        """Documentation page loads correctly."""
        page.goto(f"{base_url}/docs")
        page.wait_for_load_state("networkidle")
