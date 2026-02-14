"""
@module conftest
@description Playwright E2E test configuration and fixtures.
"""

import os
import urllib.request
import json
import ssl
from pathlib import Path
import pytest
from playwright.sync_api import Page, expect

# Base URL for E2E tests - defaults to local Docker setup
BASE_URL = os.environ.get("E2E_BASE_URL", "http://localhost:8000")

# Directory for screenshots on failure
SCREENSHOT_DIR = Path(__file__).parent / "screenshots"

# Wizard external_id prefixes that get reused across test runs.
# Docker container hostname varies, so we match by prefix.
WIZARD_EXTERNAL_PREFIXES = [
    "openclaw-main",
    "claude-code-",
    "cursor-",
    "windsurf-",
    "cline-",
    "snapper-10.0.0.1-",  # custom agent test uses host=10.0.0.1
]


def _api_request(method, path, data=None):
    """Make a direct API request (bypassing Playwright) for test setup/teardown."""
    url = f"{BASE_URL}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            content = resp.read()
            if content:
                return json.loads(content)
            return {"status": resp.status}
    except urllib.error.HTTPError as e:
        content = e.read()
        if content:
            try:
                return json.loads(content)
            except Exception:
                pass
        return None
    except Exception:
        return None


def _cleanup_wizard_agents():
    """Delete agents created by previous wizard test runs to avoid 409 conflicts."""
    agents = _api_request("GET", "/api/v1/agents?page_size=100")
    if not agents or "items" not in agents:
        return
    for agent in agents["items"]:
        ext_id = agent.get("external_id", "")
        if any(ext_id == prefix or ext_id.startswith(prefix) for prefix in WIZARD_EXTERNAL_PREFIXES):
            _api_request("DELETE", f"/api/v1/agents/{agent['id']}")


@pytest.fixture(scope="session", autouse=True)
def cleanup_stale_test_data():
    """Clean up stale test data before running E2E suite."""
    _cleanup_wizard_agents()
    yield


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


@pytest.fixture
def integrations_page(page: Page, base_url: str) -> Page:
    """Navigate to integrations page and wait for it to load."""
    page.goto(f"{base_url}/integrations")
    page.wait_for_selector("text=Rules & Traffic", timeout=10000)
    return page


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Capture screenshot on test failure for easier debugging."""
    outcome = yield
    report = outcome.get_result()

    if report.when == "call" and report.failed:
        # Try to get the page fixture
        page = item.funcargs.get("page")
        if page is None:
            # Try other page fixtures
            for fixture_name in ["dashboard_page", "agents_page", "rules_page", "security_page", "settings_page"]:
                page = item.funcargs.get(fixture_name)
                if page is not None:
                    break

        if page is not None:
            try:
                # Create screenshots directory if it doesn't exist
                SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

                # Generate filename from test name
                test_name = item.name.replace("/", "_").replace("::", "_")
                screenshot_path = SCREENSHOT_DIR / f"{test_name}.png"

                page.screenshot(path=str(screenshot_path))
                print(f"\nScreenshot saved: {screenshot_path}")
            except Exception as e:
                print(f"\nFailed to capture screenshot: {e}")
