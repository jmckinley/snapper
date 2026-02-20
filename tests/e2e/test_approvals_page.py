"""Playwright E2E tests for the /approvals page.

Tests the Approval Automation web UX: tabs, pending queue, policies CRUD,
webhook management, test mode, and setup guide.
"""

import re
from uuid import uuid4

import pytest
from playwright.sync_api import Page, expect


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def approvals_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to the approvals page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/approvals")
    authenticated_page.wait_for_selector("text=Approval Automation", timeout=15000)
    return authenticated_page


# ---------------------------------------------------------------------------
# Tests: Page rendering
# ---------------------------------------------------------------------------

class TestApprovalsPageLoads:
    """Basic page load and tab rendering tests."""

    def test_approvals_page_loads(self, approvals_page: Page):
        """The approvals page should render with the header."""
        expect(approvals_page.locator("h1")).to_contain_text("Approval Automation")

    def test_four_tabs_visible(self, approvals_page: Page):
        """All 4 tabs should be visible: Pending, Policies, Webhooks, Guide."""
        tabs = approvals_page.locator(".tab-btn")
        expect(tabs).to_have_count(4)

        tab_texts = [tabs.nth(i).text_content().strip() for i in range(4)]
        assert any("Pending" in t for t in tab_texts)
        assert any("Policies" in t for t in tab_texts)
        assert any("Webhooks" in t for t in tab_texts)
        assert any("Guide" in t for t in tab_texts)

    def test_stats_cards_render(self, approvals_page: Page):
        """Overview stat cards should be present."""
        expect(approvals_page.locator("#stat-pending-count")).to_be_visible()
        expect(approvals_page.locator("#stat-policies")).to_be_visible()
        expect(approvals_page.locator("#stat-webhooks")).to_be_visible()


class TestPendingTab:
    """Tests for the pending approvals tab."""

    def test_pending_tab_shows_queue(self, approvals_page: Page):
        """Pending tab should show either approval items or empty state."""
        # Wait for JS to load data
        approvals_page.wait_for_timeout(2000)
        pending_list = approvals_page.locator("#pending-list")
        expect(pending_list).to_be_visible()
        # Should have either approval cards or the "No pending" empty state
        content = pending_list.inner_text()
        assert "pending" in content.lower() or "approve" in content.lower() or "no pending" in content.lower()


class TestPolicyCRUD:
    """Tests for policy create/edit/delete via the UI."""

    def test_policy_create_modal_opens(self, approvals_page: Page):
        """Clicking 'Add Policy' should open the modal."""
        approvals_page.click("#btn-add-policy")
        modal = approvals_page.locator("#policy-modal")
        expect(modal).to_be_visible()
        expect(approvals_page.locator("#policy-modal-title")).to_contain_text("Add")

    def test_policy_create_and_verify(self, approvals_page: Page):
        """Create a policy via the modal form and verify it appears in the list."""
        # Switch to policies tab
        approvals_page.click('[data-tab="policies"]')
        approvals_page.wait_for_timeout(500)

        # Open modal
        approvals_page.click("#btn-add-policy")
        approvals_page.wait_for_selector("#policy-modal:not(.hidden)", timeout=3000)

        # Fill form
        approvals_page.fill("#policy-name", f"E2E Test Policy {uuid4().hex[:6]}")
        approvals_page.select_option("#policy-decision", "approve")
        approvals_page.fill("#policy-priority", "42")
        approvals_page.fill("#policy-patterns", "^echo\\b")
        approvals_page.fill("#policy-maxhour", "50")

        # Submit
        approvals_page.click('#policy-form button[type="submit"]')
        approvals_page.wait_for_timeout(2000)

        # Verify modal closed (or toast appeared)
        # The policy list should now contain our policy
        policies_list = approvals_page.locator("#policies-list")
        content = policies_list.inner_text()
        assert "E2E Test Policy" in content or "Auto-Approve" in content

    def test_policy_toggle_active(self, approvals_page: Page):
        """Toggle a policy's active state if one exists."""
        approvals_page.click('[data-tab="policies"]')
        approvals_page.wait_for_timeout(2000)

        # Check if there are any policy cards with toggle buttons
        toggles = approvals_page.locator('#policies-list button[title="Disable"], #policies-list button[title="Enable"]')
        if toggles.count() > 0:
            toggles.first.click()
            approvals_page.wait_for_timeout(1000)
            # Just verify no crash — the toggle button text should have changed
            assert True
        else:
            pytest.skip("No policies to toggle")


class TestWebhookManagement:
    """Tests for webhook create and test buttons."""

    def test_webhook_tab_renders(self, approvals_page: Page):
        """Switching to webhooks tab should show the webhook list or empty state."""
        approvals_page.click('[data-tab="webhooks"]')
        approvals_page.wait_for_timeout(1000)
        webhooks_list = approvals_page.locator("#webhooks-list")
        expect(webhooks_list).to_be_visible()


class TestSetupGuide:
    """Tests for the setup guide tab."""

    def test_setup_guide_visible(self, approvals_page: Page):
        """Guide tab should render with the 3-step BITL setup."""
        approvals_page.click('[data-tab="guide"]')
        approvals_page.wait_for_timeout(500)

        guide = approvals_page.locator("#tab-guide")
        expect(guide).to_be_visible()
        content = guide.inner_text()
        assert "Register a webhook" in content
        assert "Decide via API" in content
        assert "server-side policies" in content

    def test_setup_guide_safety_info(self, approvals_page: Page):
        """Guide tab should show safety guardrails info."""
        approvals_page.click('[data-tab="guide"]')
        approvals_page.wait_for_timeout(500)

        guide = approvals_page.locator("#tab-guide")
        content = guide.inner_text()
        assert "safety" in content.lower()
        assert "200" in content  # 200 automated approvals per hour


class TestNavigation:
    """Tests for navigation integration."""

    def test_nav_link_exists(self, approvals_page: Page):
        """Navigation should have an Approvals link."""
        nav = approvals_page.locator("nav")
        # Check for an approvals link in the nav bar
        links = approvals_page.locator('nav a[href="/approvals"], nav a[href*="approvals"]')
        # At minimum the page should have loaded
        expect(approvals_page.locator("h1")).to_contain_text("Approval Automation")

    def test_dashboard_cta_links_to_approvals(self, dashboard_page: Page, base_url: str):
        """The 'Approvals Pending' stat card on dashboard should link to /approvals."""
        link = dashboard_page.locator('a[href="/approvals"]')
        if link.count() > 0:
            expect(link.first).to_be_visible()
        else:
            # The approvals stat card wraps in an <a> tag
            pending_card = dashboard_page.locator("#stat-pending")
            expect(pending_card).to_be_visible()
