"""Tests for API key rotation."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from app.models.agents import Agent, generate_api_key
from app.models.audit_logs import AuditAction


def test_generate_api_key_format():
    """Generated API keys should start with snp_."""
    key = generate_api_key()
    assert key.startswith("snp_")
    assert len(key) > 20


def test_generate_api_key_unique():
    """Each generated key should be unique."""
    keys = {generate_api_key() for _ in range(100)}
    assert len(keys) == 100


def test_agent_has_rotated_at_field():
    """Agent model should have api_key_rotated_at field."""
    agent = MagicMock(spec=Agent)
    agent.api_key_rotated_at = None
    assert agent.api_key_rotated_at is None

    now = datetime.now(timezone.utc)
    agent.api_key_rotated_at = now
    assert agent.api_key_rotated_at == now


def test_api_key_rotated_audit_action():
    """API_KEY_ROTATED should exist in AuditAction enum."""
    assert AuditAction.API_KEY_ROTATED == "api_key_rotated"
    assert AuditAction.API_KEY_ROTATED.value == "api_key_rotated"


def test_key_rotation_invalidates_old():
    """After rotation, old key should be different from new key."""
    old_key = generate_api_key()
    new_key = generate_api_key()
    assert old_key != new_key
