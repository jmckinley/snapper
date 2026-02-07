"""Tests for API key and secret detection patterns.

Test values are constructed at runtime via helpers so that no literal
secret-shaped strings appear in source (avoids GitHub push protection).
"""

import json

import pytest

from app.utils.pii_patterns import PII_PATTERNS, API_KEY_PATTERNS, detect_pii


# --- Helpers to build fake keys at runtime ---

def _pad(prefix: str, char: str, total: int) -> str:
    """Build a fake key: prefix + repeated char to reach total length."""
    return prefix + char * (total - len(prefix))


def _fake_openai():
    return _pad("sk-", "a", 51)


def _fake_openai_proj():
    return _pad("sk-proj-", "b", 51)


def _fake_anthropic():
    return _pad("sk-ant-api03-", "c", 50)


def _fake_aws_access():
    return "AKIA" + "A" * 16


def _fake_aws_secret():
    return "aws_secret_access_key = " + "A" * 40


def _fake_github(prefix="ghp_"):
    return prefix + "x" * 36


def _fake_google():
    return "AIza" + "x" * 35


def _fake_stripe(prefix="sk_live_"):
    return prefix + "x" * 24


def _fake_slack(prefix="xoxb-"):
    return prefix + "1234567890-" + "a" * 10


def _fake_sendgrid():
    return "SG." + "a" * 22 + "." + "b" * 20


def _fake_twilio():
    return "SK" + "0" * 32


# --- Tests ---


class TestOpenAIKeyDetection:
    def test_detects_sk_key(self):
        text = "my key is " + _fake_openai()
        findings = detect_pii(text, {"api_key_openai": PII_PATTERNS["api_key_openai"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_openai"

    def test_detects_sk_proj_key(self):
        text = "key: " + _fake_openai_proj()
        findings = detect_pii(text, {"api_key_openai": PII_PATTERNS["api_key_openai"]})
        assert len(findings) == 1

    def test_ignores_short_sk_prefix(self):
        text = "sk-short"
        findings = detect_pii(text, {"api_key_openai": PII_PATTERNS["api_key_openai"]})
        assert len(findings) == 0


class TestAnthropicKeyDetection:
    def test_detects_sk_ant_key(self):
        text = "export ANTHROPIC_API_KEY=" + _fake_anthropic()
        findings = detect_pii(text, {"api_key_anthropic": PII_PATTERNS["api_key_anthropic"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_anthropic"

    def test_ignores_short_sk_ant(self):
        text = "sk-ant-short"
        findings = detect_pii(text, {"api_key_anthropic": PII_PATTERNS["api_key_anthropic"]})
        assert len(findings) == 0


class TestAWSKeyDetection:
    def test_detects_akia_key(self):
        text = "aws_access_key_id = " + _fake_aws_access()
        findings = detect_pii(text, {"api_key_aws": PII_PATTERNS["api_key_aws"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_aws"

    def test_ignores_wrong_prefix(self):
        text = "ASIA" + "1" * 16
        findings = detect_pii(text, {"api_key_aws": PII_PATTERNS["api_key_aws"]})
        assert len(findings) == 0

    def test_detects_aws_secret(self):
        text = _fake_aws_secret()
        findings = detect_pii(text, {"api_key_aws_secret": PII_PATTERNS["api_key_aws_secret"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_aws_secret"


class TestGitHubTokenDetection:
    def test_detects_ghp_token(self):
        text = "token: " + _fake_github("ghp_")
        findings = detect_pii(text, {"api_key_github": PII_PATTERNS["api_key_github"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_github"

    def test_detects_gho_token(self):
        text = "GITHUB_TOKEN=" + _fake_github("gho_")
        findings = detect_pii(text, {"api_key_github": PII_PATTERNS["api_key_github"]})
        assert len(findings) == 1

    def test_ignores_short_gh_prefix(self):
        text = "ghp_short"
        findings = detect_pii(text, {"api_key_github": PII_PATTERNS["api_key_github"]})
        assert len(findings) == 0


class TestGoogleKeyDetection:
    def test_detects_aiza_key(self):
        text = "apiKey: " + _fake_google()
        findings = detect_pii(text, {"api_key_google": PII_PATTERNS["api_key_google"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_google"


class TestStripeKeyDetection:
    def test_detects_sk_live(self):
        text = "stripe_key=" + _fake_stripe("sk_live_")
        findings = detect_pii(text, {"api_key_stripe": PII_PATTERNS["api_key_stripe"]})
        assert len(findings) == 1

    def test_detects_sk_test(self):
        text = "STRIPE_KEY=" + _fake_stripe("sk_test_")
        findings = detect_pii(text, {"api_key_stripe": PII_PATTERNS["api_key_stripe"]})
        assert len(findings) == 1

    def test_detects_pk_live(self):
        text = _fake_stripe("pk_live_")
        findings = detect_pii(text, {"api_key_stripe": PII_PATTERNS["api_key_stripe"]})
        assert len(findings) == 1


class TestSlackTokenDetection:
    def test_detects_xoxb_token(self):
        text = "SLACK_TOKEN=" + _fake_slack("xoxb-")
        findings = detect_pii(text, {"api_key_slack": PII_PATTERNS["api_key_slack"]})
        assert len(findings) == 1

    def test_detects_xoxp_token(self):
        text = "token: " + _fake_slack("xoxp-")
        findings = detect_pii(text, {"api_key_slack": PII_PATTERNS["api_key_slack"]})
        assert len(findings) == 1


class TestGenericSecretDetection:
    def test_detects_api_key_assignment(self):
        text = 'api_key="' + "a" * 40 + '"'
        findings = detect_pii(text, {"generic_secret": PII_PATTERNS["generic_secret"]})
        assert len(findings) == 1

    def test_detects_secret_key_assignment(self):
        text = "secret_key: " + "b" * 40
        findings = detect_pii(text, {"generic_secret": PII_PATTERNS["generic_secret"]})
        assert len(findings) == 1

    def test_ignores_short_values(self):
        text = "api_key=short"
        findings = detect_pii(text, {"generic_secret": PII_PATTERNS["generic_secret"]})
        assert len(findings) == 0


class TestSendGridKeyDetection:
    def test_detects_sendgrid_key(self):
        text = "SENDGRID_API_KEY=" + _fake_sendgrid()
        findings = detect_pii(text, {"api_key_sendgrid": PII_PATTERNS["api_key_sendgrid"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_sendgrid"


class TestTwilioKeyDetection:
    def test_detects_twilio_key(self):
        text = "TWILIO_API_KEY=" + _fake_twilio()
        findings = detect_pii(text, {"api_key_twilio": PII_PATTERNS["api_key_twilio"]})
        assert len(findings) == 1
        assert findings[0]["type"] == "api_key_twilio"


class TestMultipleKeysInText:
    def test_detects_multiple_keys(self):
        text = "\n".join([
            "OPENAI_API_KEY=" + _fake_openai(),
            "STRIPE_KEY=" + _fake_stripe("sk_live_"),
            "AWS_KEY=" + _fake_aws_access(),
        ])
        findings = detect_pii(text, API_KEY_PATTERNS)
        types = {f["type"] for f in findings}
        assert "api_key_openai" in types
        assert "api_key_stripe" in types
        assert "api_key_aws" in types

    def test_keys_in_json_tool_input(self):
        """Simulates what the PII gate would scan — JSON-serialized tool_input."""
        tool_input = {
            "command": "curl -H 'Authorization: Bearer " + _fake_anthropic() + "' https://api.example.com",
        }
        text = json.dumps(tool_input)
        findings = detect_pii(text, API_KEY_PATTERNS)
        assert len(findings) >= 1
        assert any(f["type"] == "api_key_anthropic" for f in findings)


class TestAPIKeyPatternsDict:
    def test_api_key_patterns_populated(self):
        assert len(API_KEY_PATTERNS) >= 8

    def test_all_start_with_api_key(self):
        for key in API_KEY_PATTERNS:
            assert key.startswith("api_key_"), f"{key} doesn't start with api_key_"
