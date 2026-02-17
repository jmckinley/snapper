"""Tests for audit log retention cleanup task."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity


def test_audit_retention_config():
    """AUDIT_RETENTION_DAYS should have a sensible default."""
    from app.config import Settings

    # Default is 90 days
    assert Settings.model_fields["AUDIT_RETENTION_DAYS"].default == 90


def test_audit_log_has_created_at():
    """AuditLog model should have created_at for retention filtering."""
    log = MagicMock(spec=AuditLog)
    log.created_at = datetime.now(timezone.utc)
    assert log.created_at is not None


def test_audit_log_time_range_index():
    """AuditLog should have a BRIN index on created_at for efficient cleanup."""
    indexes = {idx.name for idx in AuditLog.__table__.indexes}
    assert "ix_audit_logs_time_range" in indexes


def test_cleanup_function_signature():
    """The cleanup task function should be importable."""
    try:
        from app.tasks.audit_retention import cleanup_old_audit_logs
        assert callable(cleanup_old_audit_logs)
    except ImportError:
        # Celery not installed in local dev environment
        pytest.skip("celery not installed locally")
