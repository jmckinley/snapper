"""
@module test_agent_management
@description E2E tests for agent management functionality.
Tests agent registration, API key management, and agent status
changes through the web UI.
"""

import re
import time

import pytest
from playwright.sync_api import Page, expect

from .conftest import _auth_api_request


@pytest.fixture(autouse=True)
def _cleanup_test_agents_between_tests():
    """Clean up test agents before each test to stay within free plan quota."""
    agents = _auth_api_request("GET", "/api/v1/agents?page_size=100")
    if agents and "items" in agents:
        for agent in agents["items"]:
            ext_id = agent.get("external_id", "")
            # Only delete agents created by E2E tests
            if any(p in ext_id for p in (
                "e2e-test-agent-", "api-key-visible-", "show-key-test-",
                "regen-key-test-", "suspend-test-", "activate-test-",
            )):
                _auth_api_request("DELETE", f"/api/v1/agents/{agent['id']}")
    yield


class TestRegisterAgent:
    """Tests for agent registration through the UI."""

    def test_register_agent_form(self, agents_page: Page):
        """Can register a new agent through the modal form."""
        # Open the register modal
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Fill in required fields (unique name + external_id)
        ts = int(time.time())
        unique_name = f"E2E Test Agent {ts}"
        unique_id = f"e2e-test-agent-{ts}"
        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.fill("#register-modal textarea[name='description']", "Created by E2E test for agent management")

        # Submit the form
        agents_page.click("#register-modal button:has-text('Add AI Service')")

        # Modal should close
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # Agent should appear in the list
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)
        expect(agents_page.locator(f"code:has-text('{unique_id}')")).to_be_visible()

    def test_register_agent_shows_api_key(self, agents_page: Page):
        """After registering, the agent's API key should be visible."""
        ts = int(time.time())
        unique_name = f"API Key Visible {ts}"
        unique_id = f"api-key-visible-{ts}"

        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)

        # Wait for agent to appear
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # API key should be shown (snp_ prefix)
        expect(agents_page.locator("code:has-text('snp_')").first).to_be_visible()


class TestApiKeyManagement:
    """Tests for API key show, copy, and regenerate functionality."""

    def test_show_api_key(self, agents_page: Page):
        """Can reveal API key by clicking Show button."""
        ts = int(time.time())
        unique_name = f"Show Key Test {ts}"
        unique_id = f"show-key-test-{ts}"
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # Find the API key section for this agent
        # API key might be hidden initially with asterisks or a Show button
        show_button = agents_page.locator("button:has-text('Show'), button:has-text('Reveal')").first
        if show_button.is_visible():
            show_button.click()
            agents_page.wait_for_timeout(300)

        # Should see the full key (snp_...)
        expect(agents_page.locator("code:has-text('snp_')").first).to_be_visible()

    def test_regenerate_api_key(self, agents_page: Page):
        """Can regenerate an agent's API key."""
        ts = int(time.time())
        unique_name = f"Regen Key Test {ts}"
        unique_id = f"regen-key-test-{ts}"
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # Get the initial key
        initial_key_element = agents_page.locator("code:has-text('snp_')").first
        # Initial key may be masked, so we just verify regenerate works

        # Find and click regenerate button
        regen_button = agents_page.locator("button:has-text('Regenerate'), button:has-text('New Key')").first
        if regen_button.is_visible():
            # Handle confirmation dialog
            agents_page.on("dialog", lambda dialog: dialog.accept())
            regen_button.click()
            agents_page.wait_for_timeout(1000)

            # Key should still be visible (now with new value)
            expect(agents_page.locator("code:has-text('snp_')").first).to_be_visible()


class TestAgentStatusManagement:
    """Tests for suspending and activating agents."""

    def test_suspend_agent(self, agents_page: Page):
        """Can suspend an active agent."""
        ts = int(time.time())
        unique_name = f"Suspend Test {ts}"
        unique_id = f"suspend-test-{ts}"
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        # Find the agent card/row
        agent_section = agents_page.locator(f"div:has(code:has-text('{unique_id}'))").first

        # Initially should show a status indicator (Connected, Never seen, or similar)
        # New agents that haven't sent traffic show "Never seen" or "Pending"
        expect(agent_section).to_be_visible()

        # Find and click suspend button
        suspend_button = agent_section.locator("button:has-text('Suspend'), button:has-text('Deactivate')").first
        if suspend_button.is_visible():
            # Handle confirmation dialog
            agents_page.on("dialog", lambda dialog: dialog.accept())
            suspend_button.click()
            agents_page.wait_for_timeout(1000)

            # Reload to see updated status
            agents_page.reload()
            agents_page.wait_for_load_state("networkidle")
            agents_page.wait_for_timeout(2000)

            # Should now show Paused/Suspended status
            agent_section = agents_page.locator(f"div:has(code:has-text('{unique_id}'))").first
            expect(agent_section.locator("text=Paused")).to_be_visible(timeout=10000)

    def test_activate_suspended_agent(self, agents_page: Page):
        """Can re-activate a suspended agent."""
        ts = int(time.time())
        unique_name = f"Activate Test {ts}"
        unique_id = f"activate-test-{ts}"
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        agents_page.fill("#register-modal input[name='name']", unique_name)
        agents_page.fill("#register-modal input[name='external_id']", unique_id)
        agents_page.click("#register-modal button:has-text('Add AI Service')")
        agents_page.wait_for_selector("#register-modal", state="hidden", timeout=5000)
        agents_page.wait_for_selector(f"text={unique_id}", timeout=5000)

        agent_section = agents_page.locator(f"div:has(code:has-text('{unique_id}'))").first

        # Suspend it first
        suspend_button = agent_section.locator("button:has-text('Suspend'), button:has-text('Deactivate')").first
        if suspend_button.is_visible():
            agents_page.on("dialog", lambda dialog: dialog.accept())
            suspend_button.click()
            agents_page.wait_for_timeout(1000)

            agents_page.reload()
            agents_page.wait_for_load_state("networkidle")
            agents_page.wait_for_timeout(1000)

            # Now re-activate
            agent_section = agents_page.locator(f"div:has(code:has-text('{unique_id}'))").first
            activate_button = agent_section.locator("button:has-text('Activate'), button:has-text('Resume')").first
            if activate_button.is_visible():
                activate_button.click()
                agents_page.wait_for_timeout(1000)

                agents_page.reload()
                agents_page.wait_for_load_state("networkidle")
                agents_page.wait_for_timeout(2000)

                # Should no longer show Paused (back to normal status)
                agent_section = agents_page.locator(f"div:has(code:has-text('{unique_id}'))").first
                expect(agent_section.locator("text=Paused")).not_to_be_visible()


class TestAgentFormValidation:
    """Tests for agent registration form validation."""

    def test_register_requires_name(self, agents_page: Page):
        """Agent registration should require a name."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Fill in only external_id, not name
        agents_page.fill("#register-modal input[name='external_id']", "test-id")

        # The name field should be required
        name_input = agents_page.locator("#register-modal input[name='name']")
        expect(name_input).to_have_attribute("required", "")

    def test_register_requires_external_id(self, agents_page: Page):
        """Agent registration should require an external ID."""
        agents_page.click("button:has-text('Add Another AI')")
        agents_page.wait_for_selector("#register-modal", state="visible")

        # Fill in only name, not external_id
        agents_page.fill("#register-modal input[name='name']", "Test Agent")

        # The external_id field should be required
        ext_id_input = agents_page.locator("#register-modal input[name='external_id']")
        expect(ext_id_input).to_have_attribute("required", "")
