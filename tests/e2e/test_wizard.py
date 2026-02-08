"""
E2E tests for the setup wizard with agent-type selection and install-config.

Run with:
    E2E_BASE_URL=https://76.13.127.76:8443 npx playwright test tests/e2e/test_wizard.py
    or:
    E2E_BASE_URL=https://76.13.127.76:8443 pytest tests/e2e/test_wizard.py -v
"""

import os
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get("E2E_BASE_URL", "https://76.13.127.76:8443")
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"


@pytest.fixture(autouse=True)
def screenshot_dir():
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


@pytest.fixture
def wizard_page(page: Page) -> Page:
    page.goto(f"{BASE_URL}/wizard", wait_until="networkidle")
    return page


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

    def test_six_agent_cards_visible(self, step2_page: Page):
        cards = step2_page.locator(".agent-type-card")
        expect(cards).to_have_count(6)
        expect(step2_page.locator('[data-type="openclaw"]')).to_be_visible()
        expect(step2_page.locator('[data-type="claude-code"]')).to_be_visible()
        expect(step2_page.locator('[data-type="cursor"]')).to_be_visible()
        expect(step2_page.locator('[data-type="windsurf"]')).to_be_visible()
        expect(step2_page.locator('[data-type="cline"]')).to_be_visible()
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


class TestWizardOpenClawFlow:
    """Full wizard flow selecting OpenClaw."""

    def test_openclaw_register_and_install(self, wizard_page: Page):
        page = wizard_page

        # Step 1 -> 2
        page.click("text=Continue")
        page.wait_for_selector("#step2", state="visible")

        # Select OpenClaw
        page.click('[data-type="openclaw"]')
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_step2.png"))

        # Register
        page.click("#register-btn")
        page.wait_for_selector("#register-success", state="visible", timeout=10000)
        success_text = page.locator("#register-success").text_content()
        assert "OpenClaw" in success_text
        page.screenshot(path=str(SCREENSHOT_DIR / "flow_openclaw_registered.png"))

        # Step 3: Security profile (auto-advances after registration)
        page.wait_for_selector("#step3", state="visible", timeout=5000)
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
        page.wait_for_selector("#register-success", state="visible", timeout=10000)
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
