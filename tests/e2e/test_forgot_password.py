"""
Playwright E2E tests for the forgot/reset password pages.
"""

import pytest
from playwright.sync_api import Page, expect


class TestForgotPasswordPage:
    """Tests for the /forgot-password page."""

    def test_forgot_password_renders(self, page: Page, base_url: str):
        """Forgot password page shows heading, email input, and submit button."""
        page.goto(f"{base_url}/forgot-password")
        expect(page.locator("h2")).to_contain_text("Reset your password")
        expect(page.locator("#email")).to_be_visible()
        expect(page.locator("#submit-btn")).to_be_visible()

    def test_forgot_password_submit(self, page: Page, base_url: str):
        """Submitting an email shows a success message."""
        page.goto(f"{base_url}/forgot-password")
        page.fill("#email", "test@example.com")
        page.click("#submit-btn")
        # Wait for success message to appear
        page.wait_for_selector("#success-message:not(.hidden)", timeout=10000)
        expect(page.locator("#success-message")).to_be_visible()

    def test_reset_password_page_renders(self, page: Page, base_url: str):
        """Reset password page shows heading and password inputs."""
        page.goto(f"{base_url}/reset-password?token=test-token")
        expect(page.locator("h2")).to_contain_text("Set new password")
        expect(page.locator("#new_password")).to_be_visible()
        expect(page.locator("#password_confirm")).to_be_visible()
        expect(page.locator("#submit-btn")).to_be_visible()
