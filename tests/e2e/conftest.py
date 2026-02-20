"""
@module conftest
@description Playwright E2E test configuration and fixtures.

Handles authentication: registers a session-scoped test user via the API,
then logs in via the UI before each test to obtain cookies.
"""

import os
import urllib.request
import http.cookiejar
import json
import ssl
from pathlib import Path
from uuid import uuid4

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

# Session-scoped test user credentials (unique per suite run)
_TEST_USER_SUFFIX = uuid4().hex[:8]
TEST_EMAIL = f"e2e-pw-{_TEST_USER_SUFFIX}@test.com"
TEST_USERNAME = f"e2epw{_TEST_USER_SUFFIX}"
TEST_PASSWORD = "PlaywrightE2E1!"

# SSL context for API requests (accept self-signed certs)
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _api_request(method, path, data=None, cookie_jar=None):
    """Make a direct API request (bypassing Playwright) for test setup/teardown."""
    url = f"{BASE_URL}{path}"

    body = json.dumps(data).encode() if data else None
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    if cookie_jar is not None:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSL_CTX),
            urllib.request.HTTPCookieProcessor(cookie_jar),
        )
    else:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_SSL_CTX),
        )

    try:
        with opener.open(req, timeout=15) as resp:
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


def _register_test_user():
    """Register the session-scoped test user via the API. Returns user data or None."""
    jar = http.cookiejar.CookieJar()
    result = _api_request(
        "POST",
        "/api/v1/auth/register",
        data={
            "email": TEST_EMAIL,
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
            "password_confirm": TEST_PASSWORD,
        },
        cookie_jar=jar,
    )
    return result


def _get_auth_jar():
    """Return a cookie jar authenticated as the test user."""
    jar = http.cookiejar.CookieJar()
    _api_request(
        "POST",
        "/api/v1/auth/login",
        data={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        cookie_jar=jar,
    )
    return jar


def _auth_api_request(method, path, data=None):
    """Make an authenticated API request as the test user."""
    jar = _get_auth_jar()
    return _api_request(method, path, data=data, cookie_jar=jar)


def _cleanup_wizard_agents():
    """Delete agents created by previous wizard test runs to avoid 409 conflicts."""
    jar = _get_auth_jar()
    agents = _api_request("GET", "/api/v1/agents?page_size=100", cookie_jar=jar)
    if not agents or "items" not in agents:
        return
    for agent in agents["items"]:
        ext_id = agent.get("external_id", "")
        if any(ext_id == prefix or ext_id.startswith(prefix) for prefix in WIZARD_EXTERNAL_PREFIXES):
            _api_request("DELETE", f"/api/v1/agents/{agent['id']}", cookie_jar=jar)


def _cleanup_test_agents():
    """Hard-delete agents matching test name patterns via the cleanup-test endpoint."""
    jar = _get_auth_jar()
    _api_request("POST", "/api/v1/agents/cleanup-test?confirm=true", cookie_jar=jar)


def _login_via_ui(page: Page, base_url: str):
    """Fill the login form and submit, wait for redirect to dashboard."""
    page.goto(f"{base_url}/login", wait_until="networkidle")
    page.wait_for_selector("#login-form", timeout=15000)
    page.fill("#email", TEST_EMAIL)
    page.fill("#password", TEST_PASSWORD)
    page.click("#submit-btn")
    # Wait for redirect to dashboard (or any authenticated page)
    page.wait_for_url(lambda url: "/login" not in url, timeout=30000)


@pytest.fixture(scope="session", autouse=True)
def register_test_user():
    """Register the test user once per session. Runs before any test."""
    result = _register_test_user()
    if result is None or (isinstance(result, dict) and "detail" in result):
        # User may already exist from a previous run — that's fine
        pass
    yield
    _cleanup_test_agents()


@pytest.fixture(scope="session", autouse=True)
def cleanup_stale_test_data(register_test_user):
    """Clean up stale test data before and after running E2E suite."""
    _cleanup_wizard_agents()
    yield
    _cleanup_test_agents()


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
def authenticated_page(page: Page, base_url: str) -> Page:
    """Log in via the UI and return an authenticated page."""
    _login_via_ui(page, base_url)
    return page


@pytest.fixture
def dashboard_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to dashboard and wait for it to load."""
    authenticated_page.goto(base_url)
    # Wait for the dashboard to fully load
    authenticated_page.wait_for_selector("text=Welcome to Snapper", timeout=10000)
    return authenticated_page


@pytest.fixture
def agents_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to agents page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/agents")
    authenticated_page.wait_for_selector("text=Connect Your AI", timeout=10000)
    return authenticated_page


@pytest.fixture
def rules_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to rules page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/rules")
    authenticated_page.wait_for_selector("text=Rules", timeout=10000)
    return authenticated_page


@pytest.fixture
def security_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to security page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/security")
    authenticated_page.wait_for_selector("text=Security", timeout=10000)
    return authenticated_page


@pytest.fixture
def settings_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to settings page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/settings")
    authenticated_page.wait_for_selector("text=Settings", timeout=10000)
    return authenticated_page


@pytest.fixture
def integrations_page(authenticated_page: Page, base_url: str) -> Page:
    """Navigate to integrations page and wait for it to load."""
    authenticated_page.goto(f"{base_url}/integrations")
    authenticated_page.wait_for_selector("text=Rules & Traffic", timeout=10000)
    return authenticated_page


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
            for fixture_name in [
                "authenticated_page",
                "dashboard_page",
                "agents_page",
                "rules_page",
                "security_page",
                "settings_page",
            ]:
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
