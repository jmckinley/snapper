"""
@module test_agents
@description E2E tests for the Agents (Connect Your AI) page.
Tests agent registration, OpenClaw setup modal, and agent actions.
"""

import re
import time
from playwright.sync_api import Page, expect


class TestAgentsPage:
    """Tests for the agents listing page."""

    def test_agents_page_loads(self, agents_page: Page):
        """Agents page loads with correct heading."""
        expect(agents_page.locator("h1")).to_contain_text("Connect Your AI")
        expect(agents_page.locator("text=Tell Snapper which AI assistants")).to_be_visible()

    def test_agents_page_has_getting_started(self, agents_page: Page):
        """Agents page shows getting started banner."""
        expect(agents_page.locator("text=Quick Start: Connect OpenClaw")).to_be_visible()

    def test_agents_page_has_add_button(self, agents_page: Page):
        """Agents page has 'Add Another AI' button."""
        expect(agents_page.locator("text=Add Another AI")).to_be_visible()

    def test_agents_page_shows_ai_options(self, agents_page: Page):
        """Agents page shows available AI service options."""
        # Use more specific locators since text appears multiple times
        help_section = agents_page.locator("text=What AI services can I connect?")
        expect(help_section).to_be_visible()
        # Check for the AI options in the help grid - use .first to avoid strict mode violations
        expect(agents_page.locator("h4:has-text('OpenClaw')").first).to_be_visible()
        expect(agents_page.locator("h4:has-text('Claude Code')").first).to_be_visible()
        expect(agents_page.locator("h4:has-text('Cursor')").first).to_be_visible()
        expect(agents_page.locator("h4:has-text('GitHub Copilot')").first).to_be_visible()


class TestOpenClawSetupModal:
    """Tests for the OpenClaw setup wizard modal."""

    def _open_openclaw_modal(self, page: Page):
        """Ensure the getting-started banner is visible and click Connect OpenClaw."""
        # The banner hides when agents exist — force-show it for testing
        page.evaluate("document.getElementById('getting-started')?.classList.remove('hidden')")
        page.wait_for_timeout(300)
        btn = page.locator("button:has-text('Connect OpenClaw')")
        btn.scroll_into_view_if_needed()
        btn.click()
        page.wait_for_timeout(500)  # Wait for modal animation

    def test_connect_openclaw_opens_modal(self, agents_page: Page):
        """Clicking 'Connect OpenClaw' opens the setup modal."""
        self._open_openclaw_modal(agents_page)
        expect(agents_page.locator("#openclaw-modal")).not_to_have_class("hidden")
        expect(agents_page.locator("text=Where is OpenClaw running?")).to_be_visible()

    def test_platform_selection_shows_all_options(self, agents_page: Page):
        """Setup modal shows all platform options."""
        self._open_openclaw_modal(agents_page)

        expect(agents_page.locator(".platform-btn:has-text('macOS')")).to_be_visible()
        expect(agents_page.locator(".platform-btn:has-text('Linux')")).to_be_visible()
        expect(agents_page.locator(".platform-btn:has-text('DigitalOcean')")).to_be_visible()
        expect(agents_page.locator(".platform-btn:has-text('Docker')")).to_be_visible()
        expect(agents_page.locator(".platform-btn:has-text('AWS')")).to_be_visible()

    def test_selecting_platform_shows_instructions(self, agents_page: Page):
        """Selecting a platform shows setup instructions."""
        self._open_openclaw_modal(agents_page)

        # Select macOS
        agents_page.click(".platform-btn:has-text('macOS')")
        agents_page.wait_for_timeout(300)

        # Should show instructions
        expect(agents_page.locator("text=Setup Instructions for macOS")).to_be_visible()
        expect(agents_page.locator("text=Your Snapper Connection Details")).to_be_visible()

    def test_back_button_returns_to_platform_selection(self, agents_page: Page):
        """Back button returns to platform selection step."""
        self._open_openclaw_modal(agents_page)

        # Select a platform
        agents_page.click(".platform-btn:has-text('Docker')")
        agents_page.wait_for_timeout(300)
        expect(agents_page.locator("text=Setup Instructions for Docker")).to_be_visible()

        # Click back button (the SVG arrow button)
        agents_page.click("#setup-step-2 button >> nth=0")
        agents_page.wait_for_timeout(300)

        # Should be back at platform selection
        expect(agents_page.locator("text=Where is OpenClaw running?")).to_be_visible()

    def test_modal_can_be_closed(self, agents_page: Page):
        """OpenClaw modal can be closed with cancel button."""
        self._open_openclaw_modal(agents_page)

        agents_page.click("#openclaw-modal button:has-text('Cancel')")
        agents_page.wait_for_timeout(300)
        expect(agents_page.locator("#openclaw-modal")).to_have_class(re.compile("hidden"))


class TestRegisterAgentModal:
    """Tests for the generic agent registration modal."""

    def test_add_another_ai_opens_modal(self, agents_page: Page):
        """Clicking 'Add Another AI' opens registration modal."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_timeout(300)
        expect(agents_page.locator("#register-modal")).to_be_visible()
        expect(agents_page.locator("text=Connect Another AI Service")).to_be_visible()

    def test_register_modal_has_required_fields(self, agents_page: Page):
        """Registration modal has name and agent ID fields."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        expect(agents_page.locator("#register-modal input[name='name']")).to_be_visible()
        expect(agents_page.locator("#register-modal input[name='external_id']")).to_be_visible()
        expect(agents_page.locator("#register-modal textarea[name='description']")).to_be_visible()

    def test_register_agent_flow(self, agents_page: Page):
        """Can register a new agent through the form."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Fill in the form
        unique_id = f"test-agent-{int(time.time())}"
        agents_page.fill("input[name='name']", "E2E Test Agent")
        agents_page.fill("input[name='external_id']", unique_id)
        agents_page.fill("textarea[name='description']", "Created by E2E test")

        # Submit
        agents_page.click("#register-modal button:has-text('Add AI Service')")

        # Modal should close and agent should appear in list
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # The new agent should appear in the list
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)
        expect(agents_page.locator(f"code:has-text('{unique_id}')")).to_be_visible()

    def test_modal_can_be_cancelled(self, agents_page: Page):
        """Registration modal can be cancelled."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.click("#register-modal button:has-text('Cancel')")
        expect(agents_page.locator("#register-modal")).to_be_hidden()


class TestAgentActions:
    """Tests for agent actions (activate, suspend, etc.)."""

    def test_agent_list_loads(self, agents_page: Page):
        """Agent list loads from API."""
        # Wait for the list to load (either shows agents or empty state)
        agents_page.wait_for_selector("#agents-list", timeout=5000)
        # Should not show loading spinner after load
        agents_page.wait_for_timeout(1000)
        expect(agents_page.locator("#agents-list >> text=Loading...")).not_to_be_visible()

    def test_api_key_section_visible(self, agents_page: Page):
        """API key section is visible for registered agents."""
        # First, create an agent if needed
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        unique_id = f"api-key-test-{int(time.time())}"
        agents_page.fill("input[name='name']", "API Key Test Agent")
        agents_page.fill("input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # Wait for agent to appear
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # Should see API key section
        expect(agents_page.locator("text=API Key").first).to_be_visible()
        expect(agents_page.locator("code:has-text('snp_')").first).to_be_visible()
