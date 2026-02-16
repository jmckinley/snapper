"""
Playwright E2E tests for organization management pages (settings, members).
"""

import pytest
from playwright.sync_api import Page, expect


class TestOrgSettingsPage:
    """Tests for the /org/settings page."""

    def test_settings_page_renders(self, authenticated_page: Page, base_url: str):
        """Org settings page shows heading, name input, and disabled slug."""
        authenticated_page.goto(f"{base_url}/org/settings")
        authenticated_page.wait_for_selector("text=Organization Settings", timeout=10000)
        expect(authenticated_page.locator("h1")).to_contain_text("Organization Settings")
        expect(authenticated_page.locator("#org-name")).to_be_visible()
        expect(authenticated_page.locator("#org-slug")).to_be_visible()
        # Slug should be disabled
        expect(authenticated_page.locator("#org-slug")).to_be_disabled()

    def test_settings_shows_plan(self, authenticated_page: Page, base_url: str):
        """Org settings page shows the plan badge."""
        authenticated_page.goto(f"{base_url}/org/settings")
        authenticated_page.wait_for_selector("#plan-badge", timeout=10000)
        expect(authenticated_page.locator("#plan-badge")).to_be_visible()

    def test_settings_has_members_link(self, authenticated_page: Page, base_url: str):
        """Org settings page has a 'Manage Members' link."""
        authenticated_page.goto(f"{base_url}/org/settings")
        authenticated_page.wait_for_selector("text=Organization Settings", timeout=10000)
        link = authenticated_page.locator("a:has-text('Manage Members')")
        expect(link).to_be_visible()


class TestMembersPage:
    """Tests for the /org/members page."""

    def test_members_page_renders(self, authenticated_page: Page, base_url: str):
        """Members page shows heading, 'Organization Members', and invite button."""
        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("h1", timeout=10000)
        expect(authenticated_page.locator("h1")).to_contain_text("Members")
        expect(authenticated_page.locator("text=Organization Members")).to_be_visible()
        expect(authenticated_page.locator("button:has-text('Invite Member')")).to_be_visible()

    def test_members_shows_current_user(self, authenticated_page: Page, base_url: str):
        """Members page shows the test user in the list."""
        from tests.e2e.conftest import TEST_EMAIL

        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("text=Organization Members", timeout=10000)
        # Wait for members to load (async JS fetch)
        authenticated_page.wait_for_selector(f"text={TEST_EMAIL}", timeout=10000)
        expect(authenticated_page.locator(f"text={TEST_EMAIL}")).to_be_visible()

    def test_invite_modal_opens(self, authenticated_page: Page, base_url: str):
        """Clicking 'Invite Member' opens the invite modal."""
        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("text=Organization Members", timeout=10000)
        # Click the "Invite Member" button in the header
        authenticated_page.locator("button:has-text('Invite Member')").click()
        authenticated_page.wait_for_selector("#invite-modal:not(.hidden)", timeout=5000)
        expect(authenticated_page.locator("#invite-modal")).to_be_visible()
        expect(authenticated_page.locator("#invite-email")).to_be_visible()
        expect(authenticated_page.locator("#invite-role")).to_be_visible()

    def test_invite_form_fields(self, authenticated_page: Page, base_url: str):
        """Invite modal has email input and role select with 3 options."""
        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("text=Organization Members", timeout=10000)
        authenticated_page.locator("button:has-text('Invite Member')").click()
        authenticated_page.wait_for_selector("#invite-modal:not(.hidden)", timeout=5000)
        # Check role options
        options = authenticated_page.locator("#invite-role option")
        assert options.count() == 3
        # Values should include viewer, member, admin
        values = [options.nth(i).get_attribute("value") for i in range(3)]
        assert "viewer" in values
        assert "member" in values
        assert "admin" in values

    def test_members_role_column(self, authenticated_page: Page, base_url: str):
        """Members list shows the 'Owner' badge for the org owner."""
        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("text=Organization Members", timeout=10000)
        # Wait for members to load
        from tests.e2e.conftest import TEST_EMAIL
        authenticated_page.wait_for_selector(f"text={TEST_EMAIL}", timeout=10000)
        expect(authenticated_page.locator("text=Owner").first).to_be_visible()

    def test_org_settings_link(self, authenticated_page: Page, base_url: str):
        """Members page has an 'Org Settings' link in the page header."""
        authenticated_page.goto(f"{base_url}/org/members")
        authenticated_page.wait_for_selector("h1", timeout=10000)
        # Use role-based locator to target the visible link (not the dropdown one)
        link = authenticated_page.get_by_role("link", name="Org Settings")
        expect(link).to_be_visible()
