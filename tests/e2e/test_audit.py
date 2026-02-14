"""
E2E tests for the Audit & Monitoring dashboard page.

Covers:
- Page loads with correct heading
- Summary stats cards visible and populated
- Activity timeline chart renders
- Tab switching (Logs, Violations, Alerts)
- Filter controls present (severity, action, dates, search)
- Pagination controls visible
- Log detail modal opens/closes

Run with:
    E2E_BASE_URL=http://localhost:8000 pytest tests/e2e/test_audit.py -v
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
def audit_page(page: Page) -> Page:
    page.goto(f"{BASE_URL}/audit", wait_until="networkidle")
    return page


class TestAuditPageLoads:
    """Basic page load and heading."""

    def test_audit_page_loads(self, audit_page: Page):
        """Audit page loads with correct heading."""
        expect(audit_page.locator("h1")).to_contain_text("Audit")
        audit_page.screenshot(path=str(SCREENSHOT_DIR / "audit_loaded.png"))

    def test_audit_page_title(self, audit_page: Page):
        """Page title contains Audit."""
        title = audit_page.title()
        assert "Audit" in title


class TestAuditStatsCards:
    """Summary stats cards at top of page."""

    def test_stats_cards_visible(self, audit_page: Page):
        """All 4 stat cards are visible."""
        cards = audit_page.locator("#stats-cards .stat-card")
        expect(cards).to_have_count(4)

    def test_total_evaluations_card(self, audit_page: Page):
        """Total Evaluations card visible with a number."""
        audit_page.wait_for_selector("#stat-total", timeout=5000)
        expect(audit_page.locator("text=Total Evaluations")).to_be_visible()

    def test_allowed_card(self, audit_page: Page):
        """Allowed card visible."""
        expect(audit_page.locator("#stats-cards >> text=Allowed")).to_be_visible()

    def test_blocked_card(self, audit_page: Page):
        """Blocked card visible."""
        expect(audit_page.locator("#stats-cards >> text=Blocked")).to_be_visible()

    def test_pending_card(self, audit_page: Page):
        """Pending Approval card visible."""
        expect(audit_page.locator("#stats-cards >> text=Pending Approval")).to_be_visible()

    def test_stats_populate_after_load(self, audit_page: Page):
        """Stats cards show numbers (not --) after data loads."""
        # Wait for JS to populate stats
        audit_page.wait_for_function(
            'document.getElementById("stat-total").textContent !== "--"',
            timeout=10000,
        )
        total_text = audit_page.locator("#stat-total").text_content()
        # Should be a number now
        assert total_text.isdigit()


class TestActivityChart:
    """7-day traffic line chart."""

    def test_chart_canvas_visible(self, audit_page: Page):
        """Chart canvas element exists."""
        expect(audit_page.locator("#daily-chart")).to_be_visible()

    def test_chart_title(self, audit_page: Page):
        """Chart section has Traffic heading."""
        expect(audit_page.locator("text=Traffic (Last 7 Days)")).to_be_visible()

    def test_agent_filter_dropdown(self, audit_page: Page):
        """Agent filter dropdown exists with 'All Agents' default."""
        sel = audit_page.locator("#chart-agent-filter")
        expect(sel).to_be_visible()
        expect(sel.locator("option").first).to_have_text("All Agents")


class TestAuditTabs:
    """Tab switching between Logs, Violations, Alerts."""

    def test_logs_tab_active_by_default(self, audit_page: Page):
        """Audit Logs tab is active on initial load."""
        logs_tab = audit_page.locator('#tab-logs')
        expect(logs_tab).to_be_visible()

    def test_switch_to_violations_tab(self, audit_page: Page):
        """Clicking Violations tab shows violations content."""
        audit_page.click('button[data-tab="violations"]')
        expect(audit_page.locator("#tab-violations")).to_be_visible()
        expect(audit_page.locator("#tab-logs")).to_be_hidden()
        audit_page.screenshot(path=str(SCREENSHOT_DIR / "audit_violations_tab.png"))

    def test_switch_to_alerts_tab(self, audit_page: Page):
        """Clicking Alerts tab shows alerts content."""
        audit_page.click('button[data-tab="alerts"]')
        expect(audit_page.locator("#tab-alerts")).to_be_visible()
        expect(audit_page.locator("#tab-logs")).to_be_hidden()
        audit_page.screenshot(path=str(SCREENSHOT_DIR / "audit_alerts_tab.png"))

    def test_switch_back_to_logs(self, audit_page: Page):
        """Can switch back to Logs tab."""
        audit_page.click('button[data-tab="violations"]')
        audit_page.click('button[data-tab="logs"]')
        expect(audit_page.locator("#tab-logs")).to_be_visible()
        expect(audit_page.locator("#tab-violations")).to_be_hidden()


class TestAuditFilters:
    """Filter controls in the Logs tab."""

    def test_severity_dropdown_present(self, audit_page: Page):
        """Severity filter dropdown exists."""
        expect(audit_page.locator("#filter-severity")).to_be_visible()

    def test_action_dropdown_present(self, audit_page: Page):
        """Action filter dropdown exists."""
        expect(audit_page.locator("#filter-action")).to_be_visible()

    def test_start_date_picker_present(self, audit_page: Page):
        """Start date picker exists."""
        expect(audit_page.locator("#filter-start-date")).to_be_visible()

    def test_end_date_picker_present(self, audit_page: Page):
        """End date picker exists."""
        expect(audit_page.locator("#filter-end-date")).to_be_visible()

    def test_search_input_present(self, audit_page: Page):
        """Search text input exists."""
        expect(audit_page.locator("#filter-search")).to_be_visible()

    def test_severity_dropdown_has_options(self, audit_page: Page):
        """Severity dropdown has expected options."""
        options = audit_page.locator("#filter-severity option")
        # All, Critical, Error, Warning, Info = 5 options
        expect(options).to_have_count(5)

    def test_action_dropdown_has_options(self, audit_page: Page):
        """Action dropdown has expected options."""
        options = audit_page.locator("#filter-action option")
        # At least All + some action types
        count = options.count()
        assert count >= 4


class TestAuditPagination:
    """Pagination controls."""

    def test_pagination_controls_visible(self, audit_page: Page):
        """Pagination area is visible."""
        expect(audit_page.locator("#logs-pagination")).to_be_visible()

    def test_page_indicator_present(self, audit_page: Page):
        """Page X of Y indicator present."""
        expect(audit_page.locator("#page-current")).to_be_visible()
        expect(audit_page.locator("#page-total")).to_be_visible()

    def test_prev_next_buttons(self, audit_page: Page):
        """Previous and Next buttons exist."""
        expect(audit_page.locator("#btn-prev")).to_be_visible()
        expect(audit_page.locator("#btn-next")).to_be_visible()


class TestAuditLogTable:
    """Logs table structure."""

    def test_table_headers_present(self, audit_page: Page):
        """Table has Time, Severity, Action, Message, Details columns."""
        headers = audit_page.locator("#tab-logs thead th")
        expect(headers).to_have_count(5)

    def test_table_body_exists(self, audit_page: Page):
        """Table body exists for log entries."""
        expect(audit_page.locator("#logs-table")).to_be_visible()
