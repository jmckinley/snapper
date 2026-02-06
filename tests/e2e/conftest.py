"""Playwright E2E test configuration and fixtures."""

import os
import pytest
from playwright.sync_api import Page, expect

# Base URL for E2E tests - defaults to local Docker setup
BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Configure browser context for all tests."""
    return {
        **browser_context_args,
        "viewport": {"width": 1280, "height": 720},
        "ignore_https_errors": True,
    }


@pytest.fixture(scope="session")
def base_url():
    """Return the base URL for the app."""
    return BASE_URL


@pytest.fixture
def dashboard_page(page: Page, base_url: str) -> Page:
    """Navigate to dashboard and wait for it to load."""
    page.goto(base_url)
    # Wait for the dashboard to fully load
    page.wait_for_selector("text=Welcome to Snapper", timeout=10000)
    return page


@pytest.fixture
def agents_page(page: Page, base_url: str) -> Page:
    """Navigate to agents page and wait for it to load."""
    page.goto(f"{base_url}/agents")
    page.wait_for_selector("text=Connect Your AI", timeout=10000)
    return page


@pytest.fixture
def rules_page(page: Page, base_url: str) -> Page:
    """Navigate to rules page and wait for it to load."""
    page.goto(f"{base_url}/rules")
    page.wait_for_selector("text=Rules", timeout=10000)
    return page


@pytest.fixture
def security_page(page: Page, base_url: str) -> Page:
    """Navigate to security page and wait for it to load."""
    page.goto(f"{base_url}/security")
    page.wait_for_selector("text=Security", timeout=10000)
    return page


@pytest.fixture
def settings_page(page: Page, base_url: str) -> Page:
    """Navigate to settings page and wait for it to load."""
    page.goto(f"{base_url}/settings")
    page.wait_for_selector("text=Settings", timeout=10000)
    return page
