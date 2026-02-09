"""Tests for security defaults data and DB upsert functions.

Validates MALICIOUS_SKILL_RECORDS structure and tests the
create_malicious_skill_records DB function.
"""

import pytest
from uuid import uuid4

from app.models.security_issues import IssueSeverity, MaliciousSkill
from app.scripts.apply_security_defaults import (
    MALICIOUS_SKILL_RECORDS,
    create_malicious_skill_records,
)


class TestMaliciousSkillRecords:
    """Validate the MALICIOUS_SKILL_RECORDS data structure."""

    REQUIRED_FIELDS = {"skill_id", "skill_name", "threat_type", "severity"}

    def test_all_records_have_required_fields(self):
        """Every record must have skill_id, skill_name, threat_type, severity."""
        for i, record in enumerate(MALICIOUS_SKILL_RECORDS):
            missing = self.REQUIRED_FIELDS - set(record.keys())
            assert not missing, (
                f"Record #{i} ({record.get('skill_id', '?')}) missing: {missing}"
            )

    def test_all_skill_ids_are_unique(self):
        """No duplicate skill_ids in the records list."""
        ids = [r["skill_id"] for r in MALICIOUS_SKILL_RECORDS]
        duplicates = [sid for sid in ids if ids.count(sid) > 1]
        assert len(ids) == len(set(ids)), (
            f"Duplicate skill_ids found: {set(duplicates)}"
        )

    def test_severity_values_are_valid_enum_members(self):
        """Every severity must be a valid IssueSeverity."""
        for record in MALICIOUS_SKILL_RECORDS:
            severity = record["severity"]
            assert isinstance(severity, IssueSeverity), (
                f"Record '{record['skill_id']}' has invalid severity type: "
                f"{type(severity).__name__} ({severity})"
            )


class TestCreateMaliciousSkillRecords:
    """Test create_malicious_skill_records DB function."""

    @pytest.mark.asyncio
    async def test_creates_all_records(self, db_session):
        """First run should create all records from the list."""
        count = await create_malicious_skill_records(db_session)
        assert count == len(MALICIOUS_SKILL_RECORDS)

    @pytest.mark.asyncio
    async def test_idempotent_second_call_returns_zero(self, db_session):
        """Second run should skip all existing records and create 0."""
        await create_malicious_skill_records(db_session)
        count = await create_malicious_skill_records(db_session)
        assert count == 0

    @pytest.mark.asyncio
    async def test_created_records_have_correct_fields(self, db_session):
        """Verify a created record has the expected field values."""
        from sqlalchemy import select

        await create_malicious_skill_records(db_session)

        stmt = select(MaliciousSkill).where(
            MaliciousSkill.skill_id == "shell-executor-pro"
        )
        result = (await db_session.execute(stmt)).scalar_one_or_none()

        assert result is not None
        assert result.skill_name == "Shell Executor Pro"
        assert result.threat_type == "rce"
        assert result.severity == IssueSeverity.CRITICAL
        assert result.is_blocked is True
        assert result.is_verified is True
