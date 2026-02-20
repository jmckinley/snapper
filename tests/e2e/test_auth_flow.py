"""
Playwright E2E tests for authentication flows: login, register, logout.
"""

from uuid import uuid4

import pytest
from playwright.sync_api import Page, expect


class TestLoginPage:
    """Tests for the /login page."""

    def test_login_page_renders(self, page: Page, base_url: str):
        """Login page shows heading, email/password inputs, and submit button."""
        page.goto(f"{base_url}/login")
        expect(page.locator("h2")).to_contain_text("Sign in to Snapper")
        expect(page.locator("#email")).to_be_visible()
        expect(page.locator("#password")).to_be_visible()
        expect(page.locator("#submit-btn")).to_be_visible()

    def test_login_has_register_link(self, page: Page, base_url: str):
        """Login page has a 'Sign up' link to the register page."""
        page.goto(f"{base_url}/login")
        link = page.locator("a[href='/register']")
        expect(link).to_be_visible()
        expect(link).to_contain_text("Sign up")

    def test_login_has_forgot_password_link(self, page: Page, base_url: str):
        """Login page has a 'Forgot password?' link."""
        page.goto(f"{base_url}/login")
        link = page.locator("a[href='/forgot-password']")
        expect(link).to_be_visible()
        expect(link).to_contain_text("Forgot password?")

    def test_login_valid_credentials(self, page: Page, base_url: str):
        """Valid credentials redirect to the dashboard."""
        from tests.e2e.conftest import TEST_EMAIL, TEST_PASSWORD

        page.goto(f"{base_url}/login")
        page.fill("#email", TEST_EMAIL)
        page.fill("#password", TEST_PASSWORD)
        page.click("#submit-btn")
        page.wait_for_url(lambda url: "/login" not in url, timeout=15000)
        # Should land on dashboard
        assert "/login" not in page.url

    def test_login_invalid_credentials(self, page: Page, base_url: str):
        """Invalid credentials show an error message."""
        page.goto(f"{base_url}/login")
        page.fill("#email", "wrong@example.com")
        page.fill("#password", "WrongPassword1!")
        page.click("#submit-btn")
        # Wait for error to appear
        page.wait_for_selector("#error-message:not(.hidden)", timeout=10000)
        expect(page.locator("#error-message")).to_be_visible()


class TestRegisterPage:
    """Tests for the /register page."""

    def test_register_page_renders(self, page: Page, base_url: str):
        """Register page shows heading, 4 inputs, and submit button."""
        page.goto(f"{base_url}/register")
        expect(page.locator("h2")).to_contain_text("Create your account")
        expect(page.locator("#email")).to_be_visible()
        expect(page.locator("#username")).to_be_visible()
        expect(page.locator("#password")).to_be_visible()
        expect(page.locator("#password_confirm")).to_be_visible()
        expect(page.locator("#submit-btn")).to_be_visible()

    def test_register_has_login_link(self, page: Page, base_url: str):
        """Register page has a 'Sign in' link."""
        page.goto(f"{base_url}/register")
        link = page.locator("a[href='/login']")
        expect(link).to_be_visible()
        expect(link).to_contain_text("Sign in")

    def test_register_new_user(self, page: Page, base_url: str):
        """Registering with unique credentials redirects to dashboard."""
        uid = uuid4().hex[:8]
        page.goto(f"{base_url}/register")
        page.fill("#email", f"pw-reg-{uid}@test.com")
        page.fill("#username", f"pwreg{uid}")
        page.fill("#password", "TestRegister1!")
        page.fill("#password_confirm", "TestRegister1!")
        page.click("#submit-btn")
        page.wait_for_url(lambda url: "/register" not in url, timeout=15000)
        assert "/register" not in page.url

    def test_register_duplicate_email(self, page: Page, base_url: str):
        """Registering with an existing email shows an error."""
        from tests.e2e.conftest import TEST_EMAIL

        uid = uuid4().hex[:8]
        page.goto(f"{base_url}/register")
        page.fill("#email", TEST_EMAIL)  # already registered
        page.fill("#username", f"duptest{uid}")
        page.fill("#password", "DupEmail123!")
        page.fill("#password_confirm", "DupEmail123!")
        page.click("#submit-btn")
        page.wait_for_selector("#error-message:not(.hidden)", timeout=10000)
        expect(page.locator("#error-message")).to_be_visible()


class TestLogoutFlow:
    """Tests for the logout flow."""

    def test_logout_redirects_to_login(self, authenticated_page: Page, base_url: str):
        """Clicking logout redirects to the login page."""
        # Navigate to dashboard to ensure we're on an authenticated page
        authenticated_page.goto(base_url)
        authenticated_page.wait_for_selector("text=Welcome to Snapper", timeout=10000)
        # Open user menu dropdown first, then click logout
        authenticated_page.click("#user-menu-btn")
        authenticated_page.wait_for_selector("#user-menu-dropdown:not(.hidden)", timeout=5000)
        authenticated_page.click("#logout-btn")
        authenticated_page.wait_for_url(lambda url: "/login" in url, timeout=10000)
        assert "/login" in authenticated_page.url

    def test_unauthenticated_redirect(self, page: Page, base_url: str):
        """Accessing / without auth redirects to /login."""
        page.goto(base_url)
        page.wait_for_url(lambda url: "/login" in url, timeout=10000)
        assert "/login" in page.url
