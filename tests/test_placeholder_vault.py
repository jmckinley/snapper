"""Tests for PII Vault placeholder value feature."""

import json
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from uuid import uuid4

from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.models.rules import Rule, RuleAction, RuleType
from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_db():
    """Create a mock async database session."""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    return redis


@pytest.fixture
def pii_gate_rule():
    """Create a PII gate rule with default settings."""
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
        "pii_categories": ["credit_card", "email", "phone_us_ca"],
        "exempt_domains": [],
        "require_vault_for_approval": False,
    }
    return rule


@pytest.fixture
def pii_gate_rule_strict():
    """Create a strict PII gate rule (require vault for approval)."""
    rule = MagicMock(spec=Rule)
    rule.id = uuid4()
    rule.name = "PII Gate Strict"
    rule.rule_type = RuleType.PII_GATE
    rule.action = RuleAction.REQUIRE_APPROVAL
    rule.priority = 200
    rule.is_active = True
    rule.parameters = {
        "scan_tool_input": True,
        "scan_command": True,
        "detect_vault_tokens": True,
        "detect_raw_pii": True,
        "pii_categories": ["credit_card", "email", "phone_us_ca"],
        "exempt_domains": [],
        "require_vault_for_approval": True,
    }
    return rule


@pytest.fixture
def pii_gate_rule_auto():
    """Create a PII gate rule in auto mode."""
    rule = MagicMock(spec=Rule)
    rule.id = uuid4()
    rule.name = "PII Gate Auto"
    rule.rule_type = RuleType.PII_GATE
    rule.action = RuleAction.REQUIRE_APPROVAL
    rule.priority = 200
    rule.is_active = True
    rule.parameters = {
        "scan_tool_input": True,
        "scan_command": True,
        "detect_vault_tokens": True,
        "detect_raw_pii": True,
        "pii_categories": ["credit_card", "email"],
        "exempt_domains": [],
        "require_vault_for_approval": False,
        "pii_mode": "auto",
    }
    return rule


def _make_vault_entry(
    token="{{SNAPPER_VAULT:deadbeef12345678deadbeef12345678}}",
    placeholder_value=None,
    category=PIICategory.CREDIT_CARD,
    owner_chat_id="12345",
    label="Test Card",
):
    """Create a mock PIIVaultEntry."""
    entry = MagicMock(spec=PIIVaultEntry)
    entry.id = uuid4()
    entry.token = token
    entry.placeholder_value = placeholder_value
    entry.category = category
    entry.owner_chat_id = owner_chat_id
    entry.label = label
    entry.masked_value = "****-****-****-4242"
    entry.is_deleted = False
    entry.encrypted_value = b"encrypted"
    entry.allowed_domains = []
    entry.max_uses = None
    entry.use_count = 0
    entry.expires_at = None
    entry.last_used_at = None
    entry.last_used_domain = None
    return entry


def _mock_agent(owner_chat_id="12345"):
    """Create a mock Agent."""
    agent = MagicMock()
    agent.id = uuid4()
    agent.name = "test-agent"
    agent.owner_chat_id = owner_chat_id
    return agent


# ============================================================================
# Service layer: create_entry with placeholder
# ============================================================================


class TestCreateEntryWithPlaceholder:
    """Test create_entry accepts placeholder_value."""

    @pytest.mark.asyncio
    async def test_create_entry_with_placeholder(self, mock_db):
        """create_entry should accept and store placeholder_value."""
        from app.services.pii_vault import create_entry

        mock_db.flush = AsyncMock()

        entry = await create_entry(
            db=mock_db,
            owner_chat_id="12345",
            owner_name="Test User",
            label="Test Visa",
            category=PIICategory.CREDIT_CARD,
            raw_value="4532015112830366",
            placeholder_value="4242424242424242",
        )

        assert entry.placeholder_value == "4242424242424242"
        assert entry.label == "Test Visa"
        mock_db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_entry_without_placeholder(self, mock_db):
        """create_entry should work fine with no placeholder."""
        from app.services.pii_vault import create_entry

        mock_db.flush = AsyncMock()

        entry = await create_entry(
            db=mock_db,
            owner_chat_id="12345",
            owner_name="Test User",
            label="Test Email",
            category=PIICategory.EMAIL,
            raw_value="john@real-domain.com",
        )

        assert entry.placeholder_value is None


# ============================================================================
# Service layer: get_entries_by_placeholder
# ============================================================================


class TestGetEntriesByPlaceholder:
    """Test placeholder lookup in vault service."""

    @pytest.mark.asyncio
    async def test_lookup_by_placeholder(self, mock_db):
        """Should find entries matching a placeholder value."""
        from app.services.pii_vault import get_entries_by_placeholder

        entry = _make_vault_entry(placeholder_value="4242424242424242")

        # Mock the query result
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [entry]
        mock_db.execute.return_value = mock_result

        entries = await get_entries_by_placeholder(mock_db, "4242424242424242")
        assert len(entries) == 1
        assert entries[0].placeholder_value == "4242424242424242"

    @pytest.mark.asyncio
    async def test_lookup_by_placeholder_with_owner(self, mock_db):
        """Should scope placeholder lookup by owner."""
        from app.services.pii_vault import get_entries_by_placeholder

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result

        entries = await get_entries_by_placeholder(
            mock_db, "4242424242424242", owner_chat_id="99999"
        )
        assert len(entries) == 0

    @pytest.mark.asyncio
    async def test_lookup_nonexistent_placeholder(self, mock_db):
        """Should return empty list for unknown placeholder."""
        from app.services.pii_vault import get_entries_by_placeholder

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result

        entries = await get_entries_by_placeholder(mock_db, "nonexistent")
        assert len(entries) == 0


# ============================================================================
# Service layer: resolve_placeholders
# ============================================================================


class TestResolvePlaceholders:
    """Test placeholder resolution."""

    @pytest.mark.asyncio
    async def test_resolve_placeholder_map(self, mock_db):
        """resolve_placeholders should map placeholder -> decrypted value."""
        from app.services.pii_vault import resolve_placeholders

        token = "{{SNAPPER_VAULT:deadbeef12345678deadbeef12345678}}"
        placeholder_map = {"4242424242424242": token}

        # We patch resolve_tokens since it's called internally
        with patch("app.services.pii_vault.resolve_tokens") as mock_resolve:
            mock_resolve.return_value = {
                token: {
                    "value": "4532015112830366",
                    "category": "credit_card",
                    "label": "Test Visa",
                    "masked_value": "****-****-****-0366",
                }
            }

            result = await resolve_placeholders(
                db=mock_db,
                placeholder_map=placeholder_map,
            )

        assert "4242424242424242" in result
        assert result["4242424242424242"]["value"] == "4532015112830366"

    @pytest.mark.asyncio
    async def test_resolve_empty_placeholder_map(self, mock_db):
        """Empty map should return empty result."""
        from app.services.pii_vault import resolve_placeholders

        result = await resolve_placeholders(db=mock_db, placeholder_map={})
        assert result == {}


# ============================================================================
# Rule engine: PII gate with placeholder matching
# ============================================================================


class TestPIIGatePlaceholderMatching:
    """Test that the PII gate evaluator matches placeholder values to vault entries."""

    @pytest.mark.asyncio
    async def test_placeholder_credit_card_triggers_approval(
        self, mock_db, mock_redis, pii_gate_rule
    ):
        """A known placeholder credit card should trigger PII gate with placeholder_matches."""
        engine = RuleEngine(mock_db, mock_redis)

        entry = _make_vault_entry(
            placeholder_value="4242424242424242",
            token="{{SNAPPER_VAULT:aabbccddaabbccddaabbccddaabbccdd}}",
        )
        agent = _mock_agent()

        # Mock get_entries_by_placeholder to return our entry
        with patch("app.services.pii_vault.get_entries_by_placeholder") as mock_get_ph:
            mock_get_ph.return_value = [entry]

            # Mock agent lookup
            mock_agent_result = MagicMock()
            mock_agent_result.scalar_one_or_none.return_value = agent
            mock_db.execute.return_value = mock_agent_result

            context = EvaluationContext(
                agent_id=agent.id,
                request_type="browser_action",
                metadata={
                    "tool_name": "browser",
                    "tool_input": {
                        "action": "fill",
                        "fields": [{"ref": "cc", "value": "4242424242424242"}],
                        "url": "https://store.example.com/checkout",
                    },
                },
            )

            matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        assert action == RuleAction.REQUIRE_APPROVAL

        # Verify placeholder_matches was set in context
        pii_detected = context.metadata.get("pii_detected", {})
        assert "placeholder_matches" in pii_detected
        assert "4242424242424242" in pii_detected["placeholder_matches"]
        assert (
            pii_detected["placeholder_matches"]["4242424242424242"]
            == "{{SNAPPER_VAULT:aabbccddaabbccddaabbccddaabbccdd}}"
        )

    @pytest.mark.asyncio
    async def test_placeholder_in_strict_mode_not_denied(
        self, mock_db, mock_redis, pii_gate_rule_strict
    ):
        """In strict mode, a placeholder-matched value should NOT be denied (it has a vault entry)."""
        engine = RuleEngine(mock_db, mock_redis)

        entry = _make_vault_entry(
            placeholder_value="4242424242424242",
            token="{{SNAPPER_VAULT:aabbccddaabbccddaabbccddaabbccdd}}",
        )
        agent = _mock_agent()

        with patch("app.services.pii_vault.get_entries_by_placeholder") as mock_get_ph:
            mock_get_ph.return_value = [entry]

            mock_agent_result = MagicMock()
            mock_agent_result.scalar_one_or_none.return_value = agent
            mock_db.execute.return_value = mock_agent_result

            context = EvaluationContext(
                agent_id=agent.id,
                request_type="browser_action",
                metadata={
                    "tool_name": "browser",
                    "tool_input": {
                        "action": "fill",
                        "fields": [{"ref": "cc", "value": "4242424242424242"}],
                    },
                },
            )

            matches, action = await engine._evaluate_pii_gate(
                pii_gate_rule_strict, context
            )

        # Should NOT be denied — the placeholder maps to a vault entry
        assert matches is True
        assert action != RuleAction.DENY

    @pytest.mark.asyncio
    async def test_raw_pii_without_placeholder_in_strict_mode_denied(
        self, mock_db, mock_redis, pii_gate_rule_strict
    ):
        """In strict mode, raw PII without a matching placeholder should be denied."""
        engine = RuleEngine(mock_db, mock_redis)

        agent = _mock_agent()

        with patch("app.services.pii_vault.get_entries_by_placeholder") as mock_get_ph:
            mock_get_ph.return_value = []  # No matching placeholder

            mock_agent_result = MagicMock()
            mock_agent_result.scalar_one_or_none.return_value = agent
            mock_db.execute.return_value = mock_agent_result

            context = EvaluationContext(
                agent_id=agent.id,
                request_type="browser_action",
                metadata={
                    "tool_name": "browser",
                    "tool_input": {
                        "action": "fill",
                        "fields": [{"ref": "cc", "value": "4532015112830366"}],
                    },
                },
            )

            matches, action = await engine._evaluate_pii_gate(
                pii_gate_rule_strict, context
            )

        assert matches is True
        assert action == RuleAction.DENY

    @pytest.mark.asyncio
    async def test_placeholder_in_auto_mode_allows(
        self, mock_db, mock_redis, pii_gate_rule_auto
    ):
        """In auto mode, a placeholder-matched value should be ALLOWED (for inline resolution)."""
        engine = RuleEngine(mock_db, mock_redis)

        entry = _make_vault_entry(
            placeholder_value="user@example.com",
            token="{{SNAPPER_VAULT:eeff00112233445566778899aabbccdd}}",
            category=PIICategory.EMAIL,
        )
        agent = _mock_agent()

        with patch("app.services.pii_vault.get_entries_by_placeholder") as mock_get_ph:
            mock_get_ph.return_value = [entry]

            mock_agent_result = MagicMock()
            mock_agent_result.scalar_one_or_none.return_value = agent
            mock_db.execute.return_value = mock_agent_result

            context = EvaluationContext(
                agent_id=agent.id,
                request_type="browser_action",
                metadata={
                    "tool_name": "browser",
                    "tool_input": {
                        "action": "fill",
                        "fields": [{"ref": "email", "value": "user@example.com"}],
                    },
                },
            )

            matches, action = await engine._evaluate_pii_gate(
                pii_gate_rule_auto, context
            )

        assert matches is True
        assert action == RuleAction.ALLOW

        pii_detected = context.metadata.get("pii_detected", {})
        assert "user@example.com" in pii_detected.get("placeholder_matches", {})

    @pytest.mark.asyncio
    async def test_no_pii_no_match(self, mock_db, mock_redis, pii_gate_rule):
        """No PII or tokens should not match."""
        engine = RuleEngine(mock_db, mock_redis)

        context = EvaluationContext(
            agent_id=uuid4(),
            request_type="browser_action",
            metadata={
                "tool_name": "browser",
                "tool_input": {
                    "action": "click",
                    "selector": "#submit-button",
                },
            },
        )

        matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)
        assert matches is False

    @pytest.mark.asyncio
    async def test_mixed_vault_token_and_placeholder(
        self, mock_db, mock_redis, pii_gate_rule
    ):
        """A tool_input with both vault tokens and placeholder values should detect both."""
        engine = RuleEngine(mock_db, mock_redis)

        vault_entry = _make_vault_entry(
            token="{{SNAPPER_VAULT:1111222233334444aaaa5555bbbb6666}}",
        )
        placeholder_entry = _make_vault_entry(
            placeholder_value="user@example.com",
            token="{{SNAPPER_VAULT:eeff00112233445566778899aabbccdd}}",
            category=PIICategory.EMAIL,
        )
        agent = _mock_agent()

        with patch("app.services.pii_vault.get_entries_by_placeholder") as mock_get_ph:
            mock_get_ph.return_value = [placeholder_entry]

            # Mock agent lookup and vault token lookup
            async def mock_execute(stmt):
                result = MagicMock()
                # Check if this is an agent lookup or vault lookup
                stmt_str = str(stmt)
                if "agents" in stmt_str.lower():
                    result.scalar_one_or_none.return_value = agent
                else:
                    result.scalar_one_or_none.return_value = vault_entry
                return result

            mock_db.execute = AsyncMock(side_effect=mock_execute)

            context = EvaluationContext(
                agent_id=agent.id,
                request_type="browser_action",
                metadata={
                    "tool_name": "browser",
                    "tool_input": {
                        "action": "fill",
                        "fields": [
                            {"ref": "name", "value": "{{SNAPPER_VAULT:1111222233334444aaaa5555bbbb6666}}"},
                            {"ref": "email", "value": "user@example.com"},
                        ],
                    },
                },
            )

            matches, action = await engine._evaluate_pii_gate(pii_gate_rule, context)

        assert matches is True
        pii_detected = context.metadata.get("pii_detected", {})
        assert len(pii_detected.get("vault_tokens", [])) >= 1
        assert "user@example.com" in pii_detected.get("placeholder_matches", {})


# ============================================================================
# API: VaultEntryCreate/Response with placeholder_value
# ============================================================================


class TestVaultAPISchemas:
    """Test that vault API schemas include placeholder_value."""

    def test_create_schema_accepts_placeholder(self):
        """VaultEntryCreate should accept placeholder_value."""
        from app.routers.vault import VaultEntryCreate

        data = VaultEntryCreate(
            owner_chat_id="12345",
            label="Test Card",
            category=PIICategory.CREDIT_CARD,
            raw_value="4532015112830366",
            placeholder_value="4242424242424242",
        )
        assert data.placeholder_value == "4242424242424242"

    def test_create_schema_placeholder_optional(self):
        """VaultEntryCreate placeholder_value should be optional."""
        from app.routers.vault import VaultEntryCreate

        data = VaultEntryCreate(
            owner_chat_id="12345",
            label="Test Card",
            category=PIICategory.CREDIT_CARD,
            raw_value="4532015112830366",
        )
        assert data.placeholder_value is None

    def test_response_schema_includes_placeholder(self):
        """VaultEntryResponse should include placeholder_value."""
        from app.routers.vault import VaultEntryResponse

        resp = VaultEntryResponse(
            id="test-id",
            owner_chat_id="12345",
            label="Test Card",
            category="credit_card",
            token="{{SNAPPER_VAULT:test}}",
            masked_value="****-****-****-0366",
            placeholder_value="4242424242424242",
            allowed_domains=[],
            max_uses=None,
            use_count=0,
            created_at="2026-02-09T00:00:00",
        )
        assert resp.placeholder_value == "4242424242424242"

    def test_response_schema_placeholder_optional(self):
        """VaultEntryResponse placeholder_value should be optional."""
        from app.routers.vault import VaultEntryResponse

        resp = VaultEntryResponse(
            id="test-id",
            owner_chat_id="12345",
            label="Test Card",
            category="credit_card",
            token="{{SNAPPER_VAULT:test}}",
            masked_value="****-****-****-0366",
            allowed_domains=[],
            max_uses=None,
            use_count=0,
            created_at="2026-02-09T00:00:00",
        )
        assert resp.placeholder_value is None
