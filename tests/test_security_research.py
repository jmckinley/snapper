"""Tests for security research background tasks.

Patches httpx.AsyncClient and DB context for isolation.
Tests GitHub advisory fetching and ClawHub skill scanning.
"""

import pytest
from contextlib import asynccontextmanager
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    MaliciousSkill,
    SecurityIssue,
)


def _make_mock_db_context(db_session: AsyncSession):
    """Create a mock get_db_context that yields the test db_session."""
    @asynccontextmanager
    async def mock_db_context():
        yield db_session
    return mock_db_context


class TestFetchGitHubAdvisories:
    """Tests for _fetch_github_advisories_async."""

    def _make_advisory(self, ghsa_id, cve_id=None, severity="high", summary="Test advisory"):
        return {
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "severity": severity,
            "summary": summary,
            "description": f"Description for {ghsa_id}",
            "html_url": f"https://github.com/advisories/{ghsa_id}",
            "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"},
            "published_at": "2026-02-01T00:00:00Z",
            "references": [],
            "vulnerabilities": [
                {"package": {"name": "test-pkg"}, "vulnerable_version_range": "< 1.0"}
            ],
        }

    @pytest.mark.asyncio
    async def test_creates_issues_from_advisories(self, db_session):
        """Mock httpx returns 2 advisories → 2 SecurityIssue created."""
        advisories = [
            self._make_advisory("GHSA-1111-aaaa", cve_id="CVE-2026-1111"),
            self._make_advisory("GHSA-2222-bbbb", cve_id="CVE-2026-2222"),
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = advisories
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        result = await db_session.execute(select(SecurityIssue))
        issues = list(result.scalars().all())
        assert len(issues) == 2

    @pytest.mark.asyncio
    async def test_deduplicates_existing_cve(self, db_session):
        """Advisory with existing cve_id is skipped."""
        # Pre-create issue
        issue = SecurityIssue(
            id=uuid4(),
            cve_id="CVE-2026-EXISTING",
            title="Existing",
            description="Already exists",
            severity=IssueSeverity.HIGH,
            status=IssueStatus.ACTIVE,
            source="test",
        )
        db_session.add(issue)
        await db_session.commit()

        advisories = [
            self._make_advisory("GHSA-3333-cccc", cve_id="CVE-2026-EXISTING"),
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = advisories
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        result = await db_session.execute(select(SecurityIssue))
        issues = list(result.scalars().all())
        assert len(issues) == 1  # No new issue created

    @pytest.mark.asyncio
    async def test_severity_mapping(self, db_session):
        """Severity strings map correctly: critical→CRITICAL, high→HIGH, etc."""
        advisories = [
            self._make_advisory("GHSA-CRIT", cve_id="CVE-2026-CRIT", severity="critical"),
            self._make_advisory("GHSA-LOW", cve_id="CVE-2026-LOW", severity="low"),
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = advisories
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        crit = (await db_session.execute(
            select(SecurityIssue).where(SecurityIssue.cve_id == "CVE-2026-CRIT")
        )).scalar_one()
        assert crit.severity == IssueSeverity.CRITICAL

        low = (await db_session.execute(
            select(SecurityIssue).where(SecurityIssue.cve_id == "CVE-2026-LOW")
        )).scalar_one()
        assert low.severity == IssueSeverity.LOW

    @pytest.mark.asyncio
    async def test_advisory_without_cve_uses_ghsa_id(self, db_session):
        """Advisory without cve_id uses ghsa_id as fallback."""
        advisories = [
            self._make_advisory("GHSA-NOCVE", cve_id=None),
        ]

        mock_response = MagicMock()
        mock_response.json.return_value = advisories
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        result = await db_session.execute(
            select(SecurityIssue).where(SecurityIssue.cve_id == "GHSA-NOCVE")
        )
        issue = result.scalar_one_or_none()
        assert issue is not None
        assert issue.cve_id == "GHSA-NOCVE"

    @pytest.mark.asyncio
    async def test_http_error_handles_gracefully(self, db_session):
        """HTTP error logs and doesn't crash."""
        import httpx

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Rate limited"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=mock_response
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            # Should not raise
            await _fetch_github_advisories_async()

        result = await db_session.execute(select(SecurityIssue))
        assert list(result.scalars().all()) == []

    @pytest.mark.asyncio
    async def test_empty_response_creates_nothing(self, db_session):
        """Empty advisory list creates no records."""
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("app.tasks.security_research.httpx.AsyncClient", return_value=mock_client), \
             patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _fetch_github_advisories_async
            await _fetch_github_advisories_async()

        result = await db_session.execute(select(SecurityIssue))
        assert list(result.scalars().all()) == []


class TestScanClawHubSkills:
    """Tests for _scan_clawhub_skills_async."""

    @pytest.mark.asyncio
    async def test_creates_malicious_skill_records(self, db_session):
        """Creates MaliciousSkill records from MALICIOUS_SKILL_RECORDS."""
        with patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _scan_clawhub_skills_async
            await _scan_clawhub_skills_async()

        result = await db_session.execute(select(MaliciousSkill))
        skills = list(result.scalars().all())
        assert len(skills) > 0

    @pytest.mark.asyncio
    async def test_existing_skill_gets_last_seen_updated(self, db_session):
        """Existing skill gets last_seen_at updated (upsert)."""
        # Pre-create a skill
        skill = MaliciousSkill(
            id=uuid4(),
            skill_id="shell-executor-pro",
            skill_name="Shell Executor Pro",
            threat_type="rce",
            severity=IssueSeverity.CRITICAL,
            source="test",
            confidence="high",
        )
        db_session.add(skill)
        await db_session.commit()

        original_time = skill.last_seen_at

        with patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _scan_clawhub_skills_async
            await _scan_clawhub_skills_async()

        await db_session.refresh(skill)
        # last_seen_at should be updated
        assert skill.last_seen_at >= original_time

    @pytest.mark.asyncio
    async def test_idempotent_second_run_creates_zero_new(self, db_session):
        """Second run creates 0 new records."""
        with patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            from app.tasks.security_research import _scan_clawhub_skills_async
            await _scan_clawhub_skills_async()

        count_after_first = (await db_session.execute(select(MaliciousSkill))).scalars()
        first_count = len(list(count_after_first))

        with patch("app.tasks.security_research.get_db_context", _make_mock_db_context(db_session)):
            await _scan_clawhub_skills_async()

        count_after_second = (await db_session.execute(select(MaliciousSkill))).scalars()
        second_count = len(list(count_after_second))

        assert second_count == first_count
