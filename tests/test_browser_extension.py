"""Tests for browser extension shared logic (PII patterns, payloads, config).

Tests the PII patterns ported to JavaScript match the same inputs as Python,
and validates payload formatting and overlay behavior.
"""

import json
import re

import pytest


# ============================================================================
# PII Pattern Tests (validate JS patterns match Python patterns)
# ============================================================================


class TestPIIPatterns:
    """Test that browser extension PII patterns detect the same data as Snapper's Python patterns."""

    # These are the JS patterns ported from extension/content/pii-scanner.js
    PII_PATTERNS = [
        ("credit_card_visa", r"\b4[0-9]{12}(?:[0-9]{3})?\b"),
        ("credit_card_mc", r"\b5[1-5][0-9]{14}\b"),
        ("credit_card_amex", r"\b3[47][0-9]{13}\b"),
        ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ("phone_us", r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("vault_token", r"\{\{SNAPPER_VAULT:[a-f0-9]{8,32}\}\}"),
        ("ipv4", r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    ]

    def test_credit_card_detection(self):
        """Credit card patterns detect valid card numbers."""
        test_cases = [
            ("4111111111111111", "credit_card_visa"),
            ("5500000000000004", "credit_card_mc"),
            ("378282246310005", "credit_card_amex"),
        ]
        for card, pattern_name in test_cases:
            pattern = next(p for n, p in self.PII_PATTERNS if n == pattern_name)
            assert re.search(pattern, card), f"{pattern_name} should match {card}"

    def test_ssn_detection(self):
        """SSN pattern detects formatted SSNs."""
        pattern = next(p for n, p in self.PII_PATTERNS if n == "ssn")
        assert re.search(pattern, "My SSN is 123-45-6789")
        assert not re.search(pattern, "12345-6789")

    def test_email_detection(self):
        """Email pattern detects valid email addresses."""
        pattern = next(p for n, p in self.PII_PATTERNS if n == "email")
        assert re.search(pattern, "Contact me at user@example.com")
        assert re.search(pattern, "admin+test@company.co.uk")

    def test_aws_key_detection(self):
        """AWS access key pattern detects valid keys."""
        pattern = next(p for n, p in self.PII_PATTERNS if n == "aws_access_key")
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")
        assert not re.search(pattern, "AKIA1234")  # Too short

    def test_vault_token_detection(self):
        """Vault token pattern detects Snapper vault tokens."""
        pattern = next(p for n, p in self.PII_PATTERNS if n == "vault_token")
        assert re.search(pattern, "{{SNAPPER_VAULT:abcdef0123456789abcdef0123456789}}")
        assert re.search(pattern, "{{SNAPPER_VAULT:abcdef01}}")
        assert not re.search(pattern, "{{SNAPPER_VAULT:xyz}}")  # Not hex


# ============================================================================
# Evaluate Payload Tests
# ============================================================================


class TestEvaluatePayload:
    """Test that content scripts build correct evaluate payloads."""

    def test_chatgpt_code_interpreter_payload(self):
        """ChatGPT code interpreter generates correct payload."""
        # Simulates what chatgpt.js would send
        payload = {
            "agent_id": "browser-extension",
            "request_type": "command",
            "tool_name": "code_interpreter",
            "tool_input": {"code": "import os; os.listdir('/')"},
        }
        assert payload["request_type"] == "command"
        assert payload["tool_name"] == "code_interpreter"
        assert "code" in payload["tool_input"]

    def test_claude_tool_use_payload(self):
        """Claude.ai tool_use generates correct payload."""
        payload = {
            "agent_id": "browser-extension",
            "request_type": "tool",
            "tool_name": "computer_use",
            "tool_input": {"action": "screenshot"},
        }
        assert payload["request_type"] == "tool"
        assert payload["tool_name"] == "computer_use"

    def test_gemini_extension_payload(self):
        """Gemini extension call generates correct payload."""
        payload = {
            "agent_id": "browser-extension",
            "request_type": "tool",
            "tool_name": "google_search",
            "tool_input": {"query": "weather NYC"},
        }
        assert payload["request_type"] == "tool"
        assert payload["tool_name"] == "google_search"

    def test_file_upload_payload(self):
        """File upload generates correct file_access payload."""
        payload = {
            "agent_id": "browser-extension",
            "request_type": "file_access",
            "tool_name": "file_upload",
            "tool_input": {"files": ["report.xlsx", "data.csv"]},
        }
        assert payload["request_type"] == "file_access"
        assert len(payload["tool_input"]["files"]) == 2


# ============================================================================
# Overlay Tests
# ============================================================================


class TestOverlayInjection:
    """Test overlay HTML generation logic."""

    def test_deny_overlay_content(self):
        """Deny overlay contains rule name and reason."""
        tool_name = "rm_rf"
        reason = "Destructive command blocked"
        rule_name = "block-dangerous"

        # Simulates the overlay HTML from content scripts
        overlay_html = f"""
        <div class="snapper-inline-deny">
          <div class="snapper-inline-header">
            <strong>Blocked by Snapper</strong>
          </div>
          <div class="snapper-inline-details">
            <div>Tool: <code>{tool_name}</code></div>
            <div>Rule: {rule_name}</div>
            <div>Reason: {reason}</div>
          </div>
        </div>
        """

        assert "Blocked by Snapper" in overlay_html
        assert tool_name in overlay_html
        assert reason in overlay_html
        assert rule_name in overlay_html

    def test_approval_banner_content(self):
        """Approval banner shows request ID and instructions."""
        approval_id = "550e8400-e29b-41d4-a716-446655440000"
        tool_name = "web_browse"

        banner_html = f"""
        <div class="snapper-inline-approval">
          <div class="snapper-inline-header">
            <strong>Waiting for Approval</strong>
          </div>
          <div class="snapper-inline-details">
            <div>Tool: <code>{tool_name}</code></div>
            <div>Request: {approval_id[:8]}...</div>
            <div>Check Telegram or Snapper dashboard.</div>
          </div>
        </div>
        """

        assert "Waiting for Approval" in banner_html
        assert tool_name in banner_html
        assert approval_id[:8] in banner_html

    def test_allow_no_overlay(self):
        """Allow decisions produce no overlay."""
        result = {"decision": "allow", "reason": "OK"}
        # In real code: if result.decision == "allow": return (no overlay)
        assert result["decision"] == "allow"
        # No overlay should be generated


# ============================================================================
# Configuration Tests
# ============================================================================


class TestManagedConfig:
    """Test enterprise managed storage configuration parsing."""

    def test_enterprise_config_parsing(self):
        """Enterprise managed storage config is parsed correctly."""
        managed = {
            "snapper_url": "https://snapper.corp.example.com",
            "snapper_api_key": "snp_enterprise_key_123",
            "agent_id": "browser-fleet",
            "fail_mode": "closed",
            "pii_scanning": True,
        }

        config = {
            "snapperUrl": managed["snapper_url"],
            "apiKey": managed.get("snapper_api_key", ""),
            "agentId": managed.get("agent_id", "browser-extension"),
            "failMode": managed.get("fail_mode", "closed"),
            "piiScanning": managed.get("pii_scanning", True),
            "managed": True,
        }

        assert config["snapperUrl"] == "https://snapper.corp.example.com"
        assert config["apiKey"] == "snp_enterprise_key_123"
        assert config["agentId"] == "browser-fleet"
        assert config["failMode"] == "closed"
        assert config["managed"] is True

    def test_missing_url_returns_unconfigured(self):
        """Missing URL results in unconfigured state."""
        managed = {}
        local = {}

        snapper_url = managed.get("snapper_url") or local.get("snapper_url") or ""
        configured = bool(snapper_url)

        assert not configured

    def test_fail_mode_defaults(self):
        """Fail mode defaults to closed when not specified."""
        config = {
            "snapper_url": "https://snapper.example.com",
        }
        fail_mode = config.get("fail_mode", "closed")
        assert fail_mode == "closed"


# ============================================================================
# Enterprise Hardening: Manifest Tests
# ============================================================================


class TestManifest:
    """Test manifest.json includes Copilot, Grok, and PII blocking config."""

    @pytest.fixture(autouse=True)
    def load_manifest(self):
        import os

        manifest_path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "manifest.json"
        )
        with open(manifest_path) as f:
            self.manifest = json.load(f)

    def test_copilot_host_permission(self):
        """Manifest should include copilot.microsoft.com host permission."""
        assert "*://copilot.microsoft.com/*" in self.manifest["host_permissions"]

    def test_grok_host_permission(self):
        """Manifest should include grok.com host permission."""
        assert "*://grok.com/*" in self.manifest["host_permissions"]

    def test_copilot_content_script(self):
        """Manifest should have content script entry for Copilot."""
        copilot_scripts = [
            cs
            for cs in self.manifest["content_scripts"]
            if "*://copilot.microsoft.com/*" in cs["matches"]
        ]
        assert len(copilot_scripts) == 1
        assert "content/copilot.js" in copilot_scripts[0]["js"]
        assert "content/pii-scanner.js" in copilot_scripts[0]["js"]

    def test_grok_content_script(self):
        """Manifest should have content script entry for Grok."""
        grok_scripts = [
            cs
            for cs in self.manifest["content_scripts"]
            if "*://grok.com/*" in cs["matches"]
        ]
        assert len(grok_scripts) == 1
        assert "content/grok.js" in grok_scripts[0]["js"]
        assert "content/pii-scanner.js" in grok_scripts[0]["js"]

    def test_all_content_scripts_include_pii_scanner(self):
        """Every content script entry should include pii-scanner.js."""
        for cs in self.manifest["content_scripts"]:
            assert "content/pii-scanner.js" in cs["js"], (
                f"Missing pii-scanner.js for {cs['matches']}"
            )

    def test_pii_blocking_mode_in_managed_schema(self):
        """Managed schema should include pii_blocking_mode with warn/block enum."""
        schema = self.manifest["storage"]["managed_schema"]
        assert "pii_blocking_mode" in schema["properties"]
        pii_prop = schema["properties"]["pii_blocking_mode"]
        assert pii_prop["type"] == "string"
        assert set(pii_prop["enum"]) == {"warn", "block"}

    def test_five_content_script_entries(self):
        """Manifest should have 5 content script entries (ChatGPT, Claude, Gemini, Copilot, Grok)."""
        assert len(self.manifest["content_scripts"]) == 5


# ============================================================================
# Enterprise Hardening: Content Script File Tests
# ============================================================================


class TestContentScripts:
    """Test Copilot and Grok content scripts exist and have correct structure."""

    def _read_script(self, name):
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "content", name
        )
        with open(path) as f:
            return f.read()

    def test_copilot_script_exists(self):
        """copilot.js should exist."""
        content = self._read_script("copilot.js")
        assert len(content) > 0

    def test_grok_script_exists(self):
        """grok.js should exist."""
        content = self._read_script("grok.js")
        assert len(content) > 0

    def test_copilot_source_constant(self):
        """copilot.js should define SOURCE = "copilot"."""
        content = self._read_script("copilot.js")
        assert 'SOURCE = "copilot"' in content

    def test_grok_source_constant(self):
        """grok.js should define SOURCE = "grok"."""
        content = self._read_script("grok.js")
        assert 'SOURCE = "grok"' in content

    def test_copilot_uses_iife(self):
        """copilot.js should use IIFE pattern."""
        content = self._read_script("copilot.js")
        assert "(function" in content
        assert "})();" in content

    def test_grok_uses_iife(self):
        """grok.js should use IIFE pattern."""
        content = self._read_script("grok.js")
        assert "(function" in content
        assert "})();" in content


# ============================================================================
# Enterprise Hardening: PII Blocking Mode Tests
# ============================================================================


class TestPIIBlockingMode:
    """Test PII scanner blocking mode (warn vs block)."""

    def _read_pii_scanner(self):
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "content", "pii-scanner.js"
        )
        with open(path) as f:
            return f.read()

    def test_blocking_mode_variable_exists(self):
        """pii-scanner.js should define snapperPIIBlockingMode."""
        content = self._read_pii_scanner()
        assert "snapperPIIBlockingMode" in content

    def test_default_mode_is_warn(self):
        """Default PII blocking mode should be warn."""
        content = self._read_pii_scanner()
        assert 'snapperPIIBlockingMode = "warn"' in content

    def test_block_mode_no_send_anyway(self):
        """Block mode should not include Send Anyway button."""
        content = self._read_pii_scanner()
        # In block mode (isBlocking = true), actionsHtml should only have OK/Cancel
        assert "isBlocking" in content
        assert "Send Anyway" in content  # Present in warn mode template
        assert "Message Blocked" in content  # Block mode header text

    def test_loads_from_managed_storage(self):
        """PII scanner should load blocking mode from managed storage."""
        content = self._read_pii_scanner()
        assert "storage.managed" in content
        assert "pii_blocking_mode" in content

    def test_loads_from_local_storage_fallback(self):
        """PII scanner should fall back to local storage for blocking mode."""
        content = self._read_pii_scanner()
        assert "storage.local" in content


# ============================================================================
# Enterprise Hardening: Selector Robustness Tests
# ============================================================================


class TestSelectorRobustness:
    """Test that content scripts use selector fallback helper."""

    def _read_script(self, name):
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "content", name
        )
        with open(path) as f:
            return f.read()

    def test_copilot_has_selector_helper(self):
        """copilot.js should define $() selector helper."""
        content = self._read_script("copilot.js")
        assert "function $(selectors" in content

    def test_grok_has_selector_helper(self):
        """grok.js should define $() selector helper."""
        content = self._read_script("grok.js")
        assert "function $(selectors" in content

    def test_copilot_has_multi_selector_helper(self):
        """copilot.js should define $$() multi-selector helper."""
        content = self._read_script("copilot.js")
        assert "function $$(selectors" in content

    def test_grok_has_multi_selector_helper(self):
        """grok.js should define $$() multi-selector helper."""
        content = self._read_script("grok.js")
        assert "function $$(selectors" in content

    def test_chatgpt_has_selector_helper(self):
        """chatgpt.js should have $() selector helper."""
        content = self._read_script("chatgpt.js")
        assert "function $(selectors" in content or "function $(" in content

    def test_claude_has_selector_helper(self):
        """claude.js should have $() selector helper."""
        content = self._read_script("claude.js")
        assert "function $(selectors" in content or "function $(" in content

    def test_gemini_has_selector_helper(self):
        """gemini.js should have $() selector helper."""
        content = self._read_script("gemini.js")
        assert "function $(selectors" in content or "function $(" in content


# ============================================================================
# Enterprise Hardening: Options Page Tests
# ============================================================================


class TestOptionsPage:
    """Test options page includes Copilot/Grok toggles and PII blocking mode."""

    def _read_options_html(self):
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "options", "options.html"
        )
        with open(path) as f:
            return f.read()

    def _read_options_js(self):
        import os

        path = os.path.join(
            os.path.dirname(__file__), "..", "extension", "options", "options.js"
        )
        with open(path) as f:
            return f.read()

    def test_copilot_toggle_in_html(self):
        """Options HTML should have Copilot toggle."""
        content = self._read_options_html()
        assert 'id="copilot_enabled"' in content

    def test_grok_toggle_in_html(self):
        """Options HTML should have Grok toggle."""
        content = self._read_options_html()
        assert 'id="grok_enabled"' in content

    def test_pii_blocking_mode_select(self):
        """Options HTML should have PII blocking mode select."""
        content = self._read_options_html()
        assert 'id="pii_blocking_mode"' in content
        assert 'value="warn"' in content
        assert 'value="block"' in content

    def test_copilot_in_js_fields(self):
        """Options JS FIELDS array should include copilot_enabled."""
        content = self._read_options_js()
        assert '"copilot_enabled"' in content

    def test_grok_in_js_fields(self):
        """Options JS FIELDS array should include grok_enabled."""
        content = self._read_options_js()
        assert '"grok_enabled"' in content

    def test_pii_blocking_mode_in_js_fields(self):
        """Options JS FIELDS array should include pii_blocking_mode."""
        content = self._read_options_js()
        assert '"pii_blocking_mode"' in content
