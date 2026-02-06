"""E2E tests for the Agents (Connect Your AI) page."""

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
        expect(agents_page.locator("text=OpenClaw")).to_be_visible()
        expect(agents_page.locator("text=Claude Code")).to_be_visible()
        expect(agents_page.locator("text=Cursor")).to_be_visible()
        expect(agents_page.locator("text=GitHub Copilot")).to_be_visible()


class TestOpenClawSetupModal:
    """Tests for the OpenClaw setup wizard modal."""

    def test_connect_openclaw_opens_modal(self, agents_page: Page):
        """Clicking 'Connect OpenClaw' opens the setup modal."""
        agents_page.click("text=Connect OpenClaw")
        expect(agents_page.locator("#openclaw-modal")).to_be_visible()
        expect(agents_page.locator("text=Where is OpenClaw running?")).to_be_visible()

    def test_platform_selection_shows_all_options(self, agents_page: Page):
        """Setup modal shows all platform options."""
        agents_page.click("text=Connect OpenClaw")
        agents_page.wait_for_selector("#openclaw-modal", state="visible")

        expect(agents_page.locator("text=macOS")).to_be_visible()
        expect(agents_page.locator("text=Linux / Ubuntu")).to_be_visible()
        expect(agents_page.locator("text=DigitalOcean")).to_be_visible()
        expect(agents_page.locator("text=Docker")).to_be_visible()
        expect(agents_page.locator("text=AWS / EC2")).to_be_visible()

    def test_selecting_platform_shows_instructions(self, agents_page: Page):
        """Selecting a platform shows setup instructions."""
        agents_page.click("text=Connect OpenClaw")
        agents_page.wait_for_selector("#openclaw-modal", state="visible")

        # Select macOS
        agents_page.click(".platform-btn:has-text('macOS')")

        # Should show instructions
        expect(agents_page.locator("text=Setup Instructions for macOS")).to_be_visible()
        expect(agents_page.locator("text=Your Snapper Connection Details")).to_be_visible()

    def test_back_button_returns_to_platform_selection(self, agents_page: Page):
        """Back button returns to platform selection step."""
        agents_page.click("text=Connect OpenClaw")
        agents_page.wait_for_selector("#openclaw-modal", state="visible")

        # Select a platform
        agents_page.click(".platform-btn:has-text('Docker')")
        agents_page.wait_for_selector("text=Setup Instructions for Docker")

        # Click back
        agents_page.click("#setup-step-2 button:has-text('')")  # Back arrow button

        # Should be back at platform selection
        expect(agents_page.locator("text=Where is OpenClaw running?")).to_be_visible()

    def test_modal_can_be_closed(self, agents_page: Page):
        """OpenClaw modal can be closed with cancel button."""
        agents_page.click("text=Connect OpenClaw")
        agents_page.wait_for_selector("#openclaw-modal", state="visible")

        agents_page.click("#openclaw-modal >> text=Cancel")
        expect(agents_page.locator("#openclaw-modal")).to_be_hidden()


class TestRegisterAgentModal:
    """Tests for the generic agent registration modal."""

    def test_add_another_ai_opens_modal(self, agents_page: Page):
        """Clicking 'Add Another AI' opens registration modal."""
        agents_page.click("text=Add Another AI")
        expect(agents_page.locator("#register-modal")).to_be_visible()
        expect(agents_page.locator("text=Connect Another AI Service")).to_be_visible()

    def test_register_modal_has_required_fields(self, agents_page: Page):
        """Registration modal has name and agent ID fields."""
        agents_page.click("text=Add Another AI")
        agents_page.wait_for_selector("#register-modal", state="visible")

        expect(agents_page.locator("#register-modal input[name='name']")).to_be_visible()
        expect(agents_page.locator("#register-modal input[name='external_id']")).to_be_visible()
        expect(agents_page.locator("#register-modal textarea[name='description']")).to_be_visible()

    def test_register_agent_flow(self, agents_page: Page):
        """Can register a new agent through the form."""
        agents_page.click("text=Add Another AI")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Fill in the form
        unique_id = f"test-agent-{int(time.time())}"
        agents_page.fill("input[name='name']", "E2E Test Agent")
        agents_page.fill("input[name='external_id']", unique_id)
        agents_page.fill("textarea[name='description']", "Created by E2E test")

        # Submit
        agents_page.click("#register-modal >> text=Add AI Service")

        # Modal should close and agent should appear in list
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # The new agent should appear in the list
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)
        expect(agents_page.locator(f"text={unique_id}")).to_be_visible()

    def test_modal_can_be_cancelled(self, agents_page: Page):
        """Registration modal can be cancelled."""
        agents_page.click("text=Add Another AI")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.click("#register-modal >> text=Cancel")
        expect(agents_page.locator("#register-modal")).to_be_hidden()


class TestAgentActions:
    """Tests for agent actions (activate, suspend, etc.)."""

    def test_agent_list_loads(self, agents_page: Page):
        """Agent list loads from API."""
        # Wait for the list to load (either shows agents or empty state)
        agents_page.wait_for_selector("#agents-list", timeout=5000)
        # Should not show loading spinner after load
        expect(agents_page.locator("#agents-list >> text=Loading...")).not_to_be_visible()

    def test_api_key_section_visible(self, agents_page: Page):
        """API key section is visible for registered agents."""
        # First, create an agent if needed
        agents_page.click("text=Add Another AI")
        agents_page.wait_for_selector("#register-modal", state="visible")

        unique_id = f"api-key-test-{int(time.time())}"
        agents_page.fill("input[name='name']", "API Key Test Agent")
        agents_page.fill("input[name='external_id']", unique_id)
        agents_page.click("#register-modal >> text=Add AI Service")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # Wait for agent to appear
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # Should see API key section
        expect(agents_page.locator("text=API Key").first).to_be_visible()
        expect(agents_page.locator("text=snp_").first).to_be_visible()
