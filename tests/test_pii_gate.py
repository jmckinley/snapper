"""Tests for PII Gate rule evaluator."""

import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine


@pytest.fixture
def mock_db():
    """Create a mock async database session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    return db


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    return redis


@pytest.fixture
def pii_gate_rule():
    """Create a PII gate rule for testing."""
    rule = MagicMock(spec=Rule)
    rule.id = uuid4()
    rule.name = "PII Gate Protection"
    rule.rule_type = RuleType.PII_GATE
    rule.action = RuleAction.REQUIRE_APPROVAL
    rule.priority = 200
    rule.is_active = True
    rule.parameters = {
        "scan_tool_input": True,
        "scan_command": True,
        "detect_vault_tokens": True,
        "detect_raw_pii": True,
        "pii_categories": ["credit_card", "email", "phone_us_ca", "street_address", "name_with_title"],
        "exempt_domains": [],
        "require_vault_for_approval": False,
    }
    return rule


# ============================================================================
# Vault token detection tests
# ============================================================================


class TestVaultTokenDetection:
    """Test detection of vault tokens in tool_input."""

    @pytest.mark.asyncio
    async def test_detect_vault_token_in_tool_input(self, mock_db, mock_redis, pii_gate_rule):
        """Vault tokens in tool_input should trigger PII gate."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "15", "value": "{{SNAPPER_VAULT:a7f3b2c1}}"}],
                    "url": "https://expedia.com/checkout",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert action == RuleAction.REQUIRE_APPROVAL
        assert "pii_detected" in context.metadata
        assert len(context.metadata["pii_detected"]["vault_tokens"]) == 1

    @pytest.mark.asyncio
    async def test_detect_multiple_vault_tokens(self, mock_db, mock_redis, pii_gate_rule):
        """Multiple vault tokens should all be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [
                        {"ref": "15", "value": "{{SNAPPER_VAULT:a7f3b2c1}}"},
                        {"ref": "20", "value": "{{SNAPPER_VAULT:d4e5f6a7}}"},
                    ],
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert len(context.metadata["pii_detected"]["vault_tokens"]) == 2


# ============================================================================
# Raw PII detection tests
# ============================================================================


class TestRawPIIDetection:
    """Test detection of raw PII in tool_input and commands."""

    @pytest.mark.asyncio
    async def test_detect_credit_card_in_form_fields(self, mock_db, mock_redis, pii_gate_rule):
        """Credit card number in browser form fields should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "4111111111111234"}],
                    "url": "https://expedia.com/checkout",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert len(context.metadata["pii_detected"]["raw_pii"]) >= 1
        pii_types = [p["type"] for p in context.metadata["pii_detected"]["raw_pii"]]
        assert "credit_card" in pii_types

    @pytest.mark.asyncio
    async def test_detect_email_in_command(self, mock_db, mock_redis, pii_gate_rule):
        """Email address in command text should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="command",
            command='curl -d "email=john@example.com" https://api.example.com/register',
            metadata={},
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii_types = [p["type"] for p in context.metadata["pii_detected"]["raw_pii"]]
        assert "email" in pii_types

    @pytest.mark.asyncio
    async def test_detect_name_with_title(self, mock_db, mock_redis, pii_gate_rule):
        """Name with title (Mr. John Smith) should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "type",
                    "text": "Mr. John Smith",
                    "ref": "name_field",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii_types = [p["type"] for p in context.metadata["pii_detected"]["raw_pii"]]
        assert "name_with_title" in pii_types


# ============================================================================
# Domain exemption tests
# ============================================================================


class TestDomainExemption:
    """Test domain exemption in PII gate."""

    @pytest.mark.asyncio
    async def test_exempt_domain_skips_check(self, mock_db, mock_redis, pii_gate_rule):
        """PII in requests to exempt domains should not trigger the gate."""
        pii_gate_rule.parameters["exempt_domains"] = ["*.internal.corp"]

        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "4111111111111234"}],
                    "url": "https://app.internal.corp/settings",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is False

    @pytest.mark.asyncio
    async def test_non_exempt_domain_triggers_check(self, mock_db, mock_redis, pii_gate_rule):
        """PII in requests to non-exempt domains should trigger the gate."""
        pii_gate_rule.parameters["exempt_domains"] = ["*.internal.corp"]

        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "4111111111111234"}],
                    "url": "https://expedia.com/checkout",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True


# ============================================================================
# require_vault_for_approval tests
# ============================================================================


class TestRequireVaultMode:
    """Test strict mode where raw PII is denied outright."""

    @pytest.mark.asyncio
    async def test_raw_pii_denied_when_vault_required(self, mock_db, mock_redis, pii_gate_rule):
        """Raw PII should be denied (not just require approval) when require_vault_for_approval is set."""
        pii_gate_rule.parameters["require_vault_for_approval"] = True

        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "4111111111111234"}],
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert action == RuleAction.DENY

    @pytest.mark.asyncio
    async def test_vault_token_allowed_when_vault_required(self, mock_db, mock_redis, pii_gate_rule):
        """Vault tokens should still get REQUIRE_APPROVAL even in strict mode."""
        pii_gate_rule.parameters["require_vault_for_approval"] = True

        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "15", "value": "{{SNAPPER_VAULT:a7f3b2c1}}"}],
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert action == RuleAction.REQUIRE_APPROVAL


# ============================================================================
# No-match tests
# ============================================================================


class TestNoMatch:
    """Test cases where PII gate should not trigger."""

    @pytest.mark.asyncio
    async def test_no_pii_in_tool_input(self, mock_db, mock_redis, pii_gate_rule):
        """Normal browser actions without PII should not trigger the gate."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "click",
                    "ref": "submit-button",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is False

    @pytest.mark.asyncio
    async def test_no_pii_in_navigate(self, mock_db, mock_redis, pii_gate_rule):
        """Browser navigate without PII should not trigger."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "navigate",
                    "url": "https://expedia.com/flights",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is False

    @pytest.mark.asyncio
    async def test_empty_context(self, mock_db, mock_redis, pii_gate_rule):
        """Empty context should not trigger."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="tool",
            metadata={},
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is False


# ============================================================================
# Masking correctness in detection
# ============================================================================


class TestDetectionMasking:
    """Test that detected PII is correctly masked in pii_detected output."""

    @pytest.mark.asyncio
    async def test_credit_card_masked_in_detection(self, mock_db, mock_redis, pii_gate_rule):
        """Detected credit cards should be masked in pii_detected output."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "4111111111111234"}],
                },
            },
        )

        await engine._evaluate_pii_gate(pii_gate_rule, context)

        raw_pii = context.metadata["pii_detected"]["raw_pii"]
        cc_items = [p for p in raw_pii if p["type"] == "credit_card"]
        assert len(cc_items) >= 1
        # Should be masked, not showing full number
        assert "4111111111111234" not in cc_items[0]["masked"]
        assert "1234" in cc_items[0]["masked"]

    @pytest.mark.asyncio
    async def test_destination_url_captured(self, mock_db, mock_redis, pii_gate_rule):
        """Destination URL should be captured in pii_detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [{"ref": "card", "value": "{{SNAPPER_VAULT:a7f3b2c1}}"}],
                    "url": "https://expedia.com/checkout",
                },
            },
        )

        await engine._evaluate_pii_gate(pii_gate_rule, context)

        pii = context.metadata["pii_detected"]
        assert pii["destination_url"] == "https://expedia.com/checkout"
        assert "expedia.com" in pii["destination_domain"]


# ============================================================================
# Browser tool_input scanning
# ============================================================================


class TestBrowserToolInputScanning:
    """Test scanning of various browser tool_input formats."""

    @pytest.mark.asyncio
    async def test_scan_fill_action(self, mock_db, mock_redis, pii_gate_rule):
        """Browser fill action with PII in fields should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "fill",
                    "fields": [
                        {"ref": "15", "value": "{{SNAPPER_VAULT:a1b2c3d4}}"},
                        {"ref": "20", "value": "Mr. John Smith"},
                    ],
                    "url": "https://expedia.com/checkout",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii = context.metadata["pii_detected"]
        assert len(pii["vault_tokens"]) == 1
        assert len(pii["raw_pii"]) >= 1

    @pytest.mark.asyncio
    async def test_scan_type_action(self, mock_db, mock_redis, pii_gate_rule):
        """Browser type action with PII text should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "type",
                    "text": "john.smith@example.com",
                    "ref": "email_field",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii_types = [p["type"] for p in context.metadata["pii_detected"]["raw_pii"]]
        assert "email" in pii_types

    @pytest.mark.asyncio
    async def test_pii_in_curl_command_body(self, mock_db, mock_redis, pii_gate_rule):
        """PII in curl command body should be detected."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="command",
            command='curl -X POST https://api.stripe.com/v1/charges -d "card=4111111111111234&email=john@example.com"',
            metadata={},
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii_types = [p["type"] for p in context.metadata["pii_detected"]["raw_pii"]]
        assert "credit_card" in pii_types
        assert "email" in pii_types


# ============================================================================
# Amount extraction tests
# ============================================================================


class TestAmountExtraction:
    """Test extraction of monetary amounts from tool_input."""

    def test_dollar_in_form_field(self):
        """Dollar amount in a form field value should be extracted."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"fields": [{"ref": "total", "value": "$1,247.50", "label": "Total"}]},
            "",
        )
        assert "$1,247.50" in amounts

    def test_amount_in_named_field(self):
        """Numeric value in a price-keyword field should be extracted."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"fields": [{"ref": "5", "value": "299.99", "label": "price"}]},
            "",
        )
        assert "299.99" in amounts

    def test_amount_top_level_key(self):
        """Amount in a top-level tool_input key should be extracted."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"total": "$549.00", "action": "pay"},
            "",
        )
        assert "$549.00" in amounts

    def test_currency_in_scan_text(self):
        """Dollar amount in scan text (fallback) should be extracted."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {},
            'Booking total is $1,899.00 for 3 nights',
        )
        assert "$1,899.00" in amounts

    def test_euro_amount(self):
        """Euro amounts should be detected."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"fields": [{"ref": "1", "value": "€450.00"}]},
            "",
        )
        assert "€450.00" in amounts

    def test_usd_suffix(self):
        """'1234.56 USD' format should be detected."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {},
            "Total charge: 750.00 USD",
        )
        assert len(amounts) >= 1
        assert any("750" in a for a in amounts)

    def test_no_amount(self):
        """No amounts in input should return empty list."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"fields": [{"ref": "1", "value": "John Smith"}]},
            "just some text",
        )
        assert amounts == []

    def test_no_duplicates(self):
        """Same amount appearing multiple times should only appear once."""
        from app.services.rule_engine import RuleEngine
        amounts = RuleEngine._extract_amounts(
            {"total": "$500.00"},
            "The total is $500.00",
        )
        assert amounts.count("$500.00") == 1
