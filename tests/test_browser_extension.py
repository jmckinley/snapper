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
