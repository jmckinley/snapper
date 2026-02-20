"""
E2E tests for the setup wizard with agent-type selection and install-config.

Run with:
    E2E_BASE_URL=http://localhost:8000 pytest tests/e2e/test_wizard.py -v
"""

from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

from .conftest import _auth_api_request

SCREENSHOT_DIR = Path(__file__).parent / "screenshots"


def _delete_agent_by_external_id(ext_id: str):
    """Delete an agent by external_id to allow re-registration in wizard tests."""
    agents = _auth_api_request("GET", "/api/v1/agents?page_size=100")
    if not agents or "items" not in agents:
        return
    for agent in agents["items"]:
        if agent.get("external_id") == ext_id:
            _auth_api_request("DELETE", f"/api/v1/agents/{agent['id']}")


@pytest.fixture(autouse=True)
def _cleanup_all_agents_for_quota():
    """Delete ALL agents before each wizard test to stay within free plan quota.

    Uses cleanup-test endpoint first (hard-deletes wizard agents globally,
    including from other test-user orgs), then deletes remaining org agents.
    """
    _auth_api_request("POST", "/api/v1/agents/cleanup-test?confirm=true")
    agents = _auth_api_request("GET", "/api/v1/agents?page_size=100")
    if agents and "items" in agents:
        for agent in agents["items"]:
            _auth_api_request("DELETE", f"/api/v1/agents/{agent['id']}")
    yield


@pytest.fixture(autouse=True)
def screenshot_dir():
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def wizard_page(authenticated_page: Page, base_url: str) -> Page:
    authenticated_page.goto(f"{base_url}/wizard", wait_until="networkidle")
    return authenticated_page


class TestWizardStep1:
    """Step 1: Discovery page loads and Continue works."""

    def test_wizard_loads(self, wizard_page: Page):
        expect(wizard_page.locator("h1")).to_contain_text("Welcome to Snapper")
        wizard_page.screenshot(path=str(SCREENSHOT_DIR / "wizard_step1_loaded.png"))

    def test_continue_to_step2(self, wizard_page: Page):
        wizard_page.click("text=Continue")
        expect(wizard_page.locator("#step2")).to_be_visible()
        wizard_page.screenshot(path=str(SCREENSHOT_DIR / "wizard_step2_visible.png"))


class TestWizardStep2AgentType:
    """Step 2: Agent type cards display and behave correctly."""

    @pytest.fixture
    def step2_page(self, wizard_page: Page) -> Page:
        wizard_page.click("text=Continue")
        wizard_page.wait_for_selector("#step2", state="visible")
        return wizard_page

    def test_agent_cards_visible(self, step2_page: Page):
        cards = step2_page.locator(".agent-type-card")
        expect(cards).to_have_count(10)
        expect(step2_page.locator('[data-type="openclaw"]')).to_be_visible()
        expect(step2_page.locator('[data-type="claude-code"]')).to_be_visible()
        expect(step2_page.locator('[data-type="cursor"]')).to_be_visible()
        expect(step2_page.locator('[data-type="windsurf"]')).to_be_visible()
        expect(step2_page.locator('[data-type="cline"]')).to_be_visible()
        expect(step2_page.locator('[data-type="openai"]')).to_be_visible()
        expect(step2_page.locator('[data-type="anthropic"]')).to_be_visible()
        expect(step2_page.locator('[data-type="gemini"]')).to_be_visible()
        expect(step2_page.locator('[data-type="browser-extension"]')).to_be_visible()
        expect(step2_page.locator('[data-type="custom"]')).to_be_visible()

    def test_register_button_starts_disabled(self, step2_page: Page):
        btn = step2_page.locator("#register-btn")
        expect(btn).to_be_disabled()

    def test_select_openclaw_hides_host_port(self, step2_page: Page):
        step2_page.click('[data-type="openclaw"]')
        expect(step2_page.locator("#agent-name-field")).to_be_visible()
        expect(step2_page.locator("#custom-host-port")).to_be_hidden()
        expect(step2_page.locator("#register-btn")).to_be_enabled()
        step2_page.screenshot(path=str(SCREENSHOT_DIR / "wizard_step2_openclaw_selected.png"))

    def test_select_claude_code_hides_host_port(self, step2_page: Page):
        step2_page.click('[data-type="claude-code"]')
        expect(step2_page.locator("#agent-name-field")).to_be_visible()
        expect(step2_page.locator("#custom-host-port")).to_be_hidden()
        expect(step2_page.locator("#register-btn")).to_be_enabled()
        step2_page.screenshot(path=str(SCREENSHOT_DIR / "wizard_step2_claude_code_selected.png"))

    def test_select_custom_shows_host_port(self, step2_page: Page):
        step2_page.click('[data-type="custom"]')
        expect(step2_page.locator("#agent-name-field")).to_be_visible()
        expect(step2_page.locator("#custom-host-port")).to_be_visible()
        expect(step2_page.locator("#register-btn")).to_be_enabled()
        step2_page.screenshot(path=str(SCREENSHOT_DIR / "wizard_step2_custom_selected.png"))

    def test_selected_card_highlighted(self, step2_page: Page):
        step2_page.click('[data-type="openclaw"]')
        card = step2_page.locator('[data-type="openclaw"]')
        # to_have_class matches the full class string; use to_have_attribute for substring
        class_attr = card.get_attribute("class")
        assert "border-primary-500" in class_attr


class TestWizardStep4Notifications:
    """Step 4: Notification options show both Telegram and Slack."""

    @pytest.fixture
    def step4_page(self, wizard_page: Page) -> Page:
        """Navigate to step 4 (notifications) via a quick registration flow."""
        _delete_agent_by_external_id("openclaw-main")
        page = wizard_page
        page.click("text=Continue")
        page.wait_for_selector("#step2", state="visible")
        page.click('[data-type="openclaw"]')
        page.click("#register-btn")
        page.wait_for_selector("#register-success", state="visible", timeout=30000)
        page.wait_for_selector("#step3", state="visible", timeout=10000)
        page.click("#apply-btn")
        page.wait_for_selector("#step4", state="visible", timeout=10000)
        return page

    def test_telegram_option_visible(self, step4_page: Page):
        """Telegram notification option is visible in step 4."""
        telegram_option = step4_page.locator('[data-channel="telegram"]')
        expect(telegram_option).to_be_visible()
        expect(step4_page.locator("#notify-telegram")).to_be_visible()
        step4_page.screenshot(
            path=str(SCREENSHOT_DIR / "wizard_step4_notifications.png")
        )

    def test_slack_option_visible(self, step4_page: Page):
        """Slack notification option is visible in step 4."""
        slack_option = step4_page.locator('[data-channel="slack"]')
        expect(slack_option).to_be_visible()
        expect(step4_page.locator("#notify-slack")).to_be_visible()

    def test_telegram_fields_toggle(self, step4_page: Page):
        """Checking Telegram shows token/chat fields."""
        # Click the checkbox directly to avoid double-toggle from label click behavior
        step4_page.locator("#notify-telegram").check()
        step4_page.wait_for_timeout(300)
        expect(step4_page.locator("#telegram-fields")).to_be_visible()
        expect(step4_page.locator("#wizard-telegram-token")).to_be_visible()
        expect(step4_page.locator("#wizard-telegram-chat")).to_be_visible()

    def test_slack_fields_toggle(self, step4_page: Page):
        """Checking Slack shows webhook field."""
        step4_page.locator("#notify-slack").check()
        step4_page.wait_for_timeout(300)
        expect(step4_page.locator("#slack-fields")).to_be_visible()
        expect(step4_page.locator("#wizard-slack-webhook")).to_be_visible()

    def test_skip_notifications_advances(self, step4_page: Page):
        """Skip for now advances to step 5."""
        step4_page.click("text=Skip for now")
        expect(step4_page.locator("#step5")).to_be_visible(timeout=10000)


class TestWizardOpenClawFlow:
    """Full wizard flow selecting OpenClaw."""

    def test_openclaw_register_and_install(self, wizard_page: Page):
        _delete_agent_by_external_id("openclaw-main")
        page = wizard_page

        # Step 1 -> 2
        page.click("text=Continue")
        page.wait_for_selector("#step2", state="visible")

        # Select OpenClaw
        page.click('[data-type="openclaw"]')
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_step2.png"))

        # Register
        page.click("#register-btn")
        page.wait_for_selector("#register-success", state="visible", timeout=30000)
        success_text = page.locator("#register-success").text_content()
        assert "OpenClaw" in success_text
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_registered.png"))

        # Step 3: Security profile (auto-advances after registration)
        page.wait_for_selector("#step3", state="visible", timeout=10000)
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_step3.png"))

        # Apply profile (recommended is pre-selected)
        page.click("#apply-btn")
        page.wait_for_selector("#step4", state="visible", timeout=5000)
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_step4.png"))

        # Step 4: Skip notifications
        page.click("text=Skip for now")

        # Step 5: Final step with install result
        page.wait_for_selector("#step5", state="visible", timeout=10000)
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_step5.png"))

        # Verify agent ID is displayed
        agent_id = page.locator("#display-agent-id").text_content()
        assert len(agent_id) > 10, f"Agent ID looks too short: {agent_id}"

        # Verify install result banner shows (either success or fallback)
        install_result = page.locator("#install-result")
        expect(install_result).to_be_visible()
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_final.png"))


class TestWizardCustomFlow:
    """Full wizard flow selecting Custom agent."""

    def test_custom_register_shows_snippet(self, wizard_page: Page):
        _delete_agent_by_external_id("snapper-10.0.0.1-9999")
        page = wizard_page

        # Step 1 -> 2
        page.click("text=Continue")
        page.wait_for_selector("#step2", state="visible")

        # Select Custom
        page.click('[data-type="custom"]')
        page.fill("#agent-name", "E2E Test Custom Agent")
        page.fill("#agent-host", "10.0.0.1")
        page.fill("#agent-port", "9999")
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_custom_step2.png"))

        # Register
        page.click("#register-btn")
        page.wait_for_selector("#register-success", state="visible", timeout=30000)
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_custom_registered.png"))

        # Step 3 -> apply
        page.wait_for_selector("#step3", state="visible", timeout=5000)
        page.click("#apply-btn")
        page.wait_for_selector("#step4", state="visible", timeout=5000)

        # Step 4 -> skip notifications
        page.click("text=Skip for now")

        # Step 5: Should show config snippet (no auto-install for custom)
        page.wait_for_selector("#step5", state="visible", timeout=10000)
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_custom_step5.png"))

        # Config snippet should be visible with env var content
        snippet = page.locator("#config-snippet").text_content()
        assert "SNAPPER_URL=" in snippet
        assert "SNAPPER_AGENT_ID=" in snippet
        assert "SNAPPER_API_KEY=" in snippet
        assert "snp_" in snippet

        # Install result should NOT be visible (custom doesn't auto-install)
        install_result = page.locator("#install-result")
        expect(install_result).to_be_hidden()

        page.screenshot(path=str(SCREENSHOT_DIR / "flow_custom_final.png"))
