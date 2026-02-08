"""
E2E tests for setup wizard with Cursor, Windsurf, and Cline agent types.

Covers full wizard flows for each new agent type:
- Select card, register, apply profile, skip notifications, verify result.

Run with:
    E2E_BASE_URL=http://localhost:8000 pytest tests/e2e/test_wizard_new_agents.py -v
"""

import os
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"


@pytest.fixture(autouse=True)
def screenshot_dir():
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def wizard_page(page: Page) -> Page:
    page.goto(f"{BASE_URL}/wizard", wait_until="networkidle")
    return page


def _navigate_to_step2(page: Page) -> Page:
    """Helper: advance from step 1 to step 2."""
    page.click("text=Continue")
    page.wait_for_selector("#step2", state="visible")
    return page


def _complete_wizard_flow(page: Page, agent_type: str, agent_label: str):
    """Helper: run through the full wizard flow for a given agent type.

    Returns the page at step 5 for assertion.
    """
    # Step 1 -> 2
    _navigate_to_step2(page)

    # Select agent type card
    page.click(f'[data-type="{agent_type}"]')
    page.screenshot(path=str(SCREENSHOT_DIR / f"flow_{agent_type}_step2.png"))

    # Verify card is selected (highlighted)
    card = page.locator(f'[data-type="{agent_type}"]')
    class_attr = card.get_attribute("class")
    assert "border-primary-500" in class_attr, f"{agent_type} card not highlighted"

    # Host/port should be hidden for known agent types
    expect(page.locator("#custom-host-port")).to_be_hidden()

    # Register button should be enabled
    expect(page.locator("#register-btn")).to_be_enabled()

    # Click Register
    page.click("#register-btn")
    page.wait_for_selector("#register-success", state="visible", timeout=10000)
    success_text = page.locator("#register-success").text_content()
    page.screenshot(path=str(SCREENSHOT_DIR / f"flow_{agent_type}_registered.png"))

    # Step 3: Security profile
    page.wait_for_selector("#step3", state="visible", timeout=5000)
    page.click("#apply-btn")
    page.wait_for_selector("#step4", state="visible", timeout=5000)

    # Step 4: Skip notifications
    page.click("text=Skip for now")

    # Step 5: Final result
    page.wait_for_selector("#step5", state="visible", timeout=10000)
    page.screenshot(path=str(SCREENSHOT_DIR / f"flow_{agent_type}_step5.png"))

    # Verify agent ID displayed
    agent_id = page.locator("#display-agent-id").text_content()
    assert len(agent_id) > 10, f"Agent ID too short: {agent_id}"

    # Verify config snippet contains env vars
    snippet = page.locator("#config-snippet").text_content()
    assert "SNAPPER_URL=" in snippet
    assert "SNAPPER_AGENT_ID=" in snippet
    assert "SNAPPER_API_KEY=" in snippet
    assert "snp_" in snippet

    return page


class TestWizardCursorFlow:
    """Full wizard flow for Cursor agent type."""

    def test_cursor_card_hides_host_port(self, wizard_page: Page):
        """Selecting Cursor hides host/port fields."""
        _navigate_to_step2(wizard_page)
        wizard_page.click('[data-type="cursor"]')
        expect(wizard_page.locator("#custom-host-port")).to_be_hidden()
        expect(wizard_page.locator("#register-btn")).to_be_enabled()

    def test_cursor_full_flow(self, wizard_page: Page):
        """Complete Cursor wizard flow end to end."""
        page = _complete_wizard_flow(wizard_page, "cursor", "Cursor")

        # Cursor snippet should mention preToolUse or cursor hooks
        snippet = page.locator("#config-snippet").text_content()
        assert "cursor" in snippet.lower() or "preToolUse" in snippet


class TestWizardWindsurfFlow:
    """Full wizard flow for Windsurf agent type."""

    def test_windsurf_card_hides_host_port(self, wizard_page: Page):
        """Selecting Windsurf hides host/port fields."""
        _navigate_to_step2(wizard_page)
        wizard_page.click('[data-type="windsurf"]')
        expect(wizard_page.locator("#custom-host-port")).to_be_hidden()
        expect(wizard_page.locator("#register-btn")).to_be_enabled()

    def test_windsurf_full_flow(self, wizard_page: Page):
        """Complete Windsurf wizard flow end to end."""
        page = _complete_wizard_flow(wizard_page, "windsurf", "Windsurf")

        # Windsurf snippet should mention windsurf or codeium hooks
        snippet = page.locator("#config-snippet").text_content()
        assert "windsurf" in snippet.lower() or "codeium" in snippet.lower()


class TestWizardClineFlow:
    """Full wizard flow for Cline agent type."""

    def test_cline_card_hides_host_port(self, wizard_page: Page):
        """Selecting Cline hides host/port fields."""
        _navigate_to_step2(wizard_page)
        wizard_page.click('[data-type="cline"]')
        expect(wizard_page.locator("#custom-host-port")).to_be_hidden()
        expect(wizard_page.locator("#register-btn")).to_be_enabled()

    def test_cline_full_flow(self, wizard_page: Page):
        """Complete Cline wizard flow end to end."""
        page = _complete_wizard_flow(wizard_page, "cline", "Cline")

        # Cline snippet should mention cline hooks
        snippet = page.locator("#config-snippet").text_content()
        assert "cline" in snippet.lower()


class TestWizardClaudeCodeFlow:
    """Full wizard flow for Claude Code (to fill the gap from test_wizard.py)."""

    def test_claude_code_full_flow(self, wizard_page: Page):
        """Complete Claude Code wizard flow end to end."""
        page = _complete_wizard_flow(wizard_page, "claude-code", "Claude Code")

        # Claude Code snippet should mention .claude or PreToolUse
        snippet = page.locator("#config-snippet").text_content()
        assert "claude" in snippet.lower() or "PreToolUse" in snippet
