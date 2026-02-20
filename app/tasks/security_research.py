"""Security research background tasks."""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional

import httpx

from app.config import get_settings
from app.database import get_db_context
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    MaliciousSkill,
    SecurityIssue,
    SecurityRecommendation,
)
from app.redis_client import redis_client
from app.services.security_monitor import SecurityMonitor, auto_mitigate_issue
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


def run_async(coro):
    """Run async coroutine in sync context.

    Uses asyncio.run() instead of get_event_loop() because Celery
    workers fork from the parent process and inherit a stale loop.
    """
    return asyncio.run(coro)


async def _is_auto_mitigate_enabled() -> bool:
    """Check whether auto-mitigation is enabled (Redis override > config)."""
    try:
        await redis_client.connect()
        override = await redis_client.get("config:auto_mitigate_threats")
        if override is not None:
            return override == "1"
    except Exception:
        pass
    return settings.AUTO_MITIGATE_THREATS


async def _are_security_feeds_enabled() -> bool:
    """Check whether security feeds are enabled (Redis override > config)."""
    try:
        await redis_client.connect()
        override = await redis_client.get("config:security_feeds_enabled")
        if override is not None:
            return override == "1"
    except Exception:
        pass
    return settings.SECURITY_FEEDS_ENABLED


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_nvd_updates(self):
    """
    Fetch latest vulnerabilities from NVD (National Vulnerability Database).

    Runs every 6 hours to check for new CVEs that may affect Snapper.
    """
    if not run_async(_are_security_feeds_enabled()):
        logger.info("Security feeds disabled (air-gapped mode), skipping NVD fetch")
        return

    logger.info("Starting NVD vulnerability fetch...")

    try:
        run_async(_fetch_nvd_updates_async())
        logger.info("NVD vulnerability fetch completed")
    except Exception as e:
        logger.exception(f"NVD fetch failed: {e}")
        raise self.retry(exc=e)


async def _fetch_nvd_updates_async():
    """Async implementation of NVD fetch."""
    # Calculate date range (last 7 days)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=7)

    # NVD API endpoint
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
        "keywordSearch": "snapper OR websocket OR agent",  # Relevant keywords
        "resultsPerPage": 100,
    }

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                base_url,
                params=params,
                headers=headers,
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch from NVD: {e}")
            return

    vulnerabilities = data.get("vulnerabilities", [])
    logger.info(f"Found {len(vulnerabilities)} CVEs from NVD")

    new_issue_ids = []

    async with get_db_context() as db:
        from sqlalchemy import select

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id")

            if not cve_id:
                continue

            # Check if already exists
            stmt = select(SecurityIssue).where(SecurityIssue.cve_id == cve_id)
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                continue

            # Extract CVSS score
            metrics = cve_data.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
            cvss_score = cvss_data.get("cvssData", {}).get("baseScore")

            # Determine severity
            if cvss_score:
                if cvss_score >= 9.0:
                    severity = IssueSeverity.CRITICAL
                elif cvss_score >= 7.0:
                    severity = IssueSeverity.HIGH
                elif cvss_score >= 4.0:
                    severity = IssueSeverity.MEDIUM
                else:
                    severity = IssueSeverity.LOW
            else:
                severity = IssueSeverity.MEDIUM

            # Extract description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d.get("value") for d in descriptions if d.get("lang") == "en"),
                "No description available"
            )

            # Create security issue
            issue = SecurityIssue(
                cve_id=cve_id,
                title=f"{cve_id}: {description[:100]}...",
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_data.get("cvssData", {}).get("vectorString"),
                status=IssueStatus.ACTIVE,
                source="nvd",
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_at=datetime.fromisoformat(
                    cve_data.get("published", "").replace("Z", "+00:00")
                ) if cve_data.get("published") else None,
                auto_generate_rules=True,
            )
            db.add(issue)
            await db.flush()
            new_issue_ids.append(issue.id)

        await db.commit()

    # Auto-mitigate new issues if enabled
    if new_issue_ids and await _is_auto_mitigate_enabled():
        logger.info(f"Auto-mitigating {len(new_issue_ids)} new NVD issues")
        async with get_db_context() as db:
            for issue_id in new_issue_ids:
                try:
                    result = await auto_mitigate_issue(db, issue_id)
                    logger.info(f"Auto-mitigated {issue_id}: {result.get('method')}")
                except Exception as e:
                    logger.warning(f"Auto-mitigation failed for {issue_id}: {e}")
            await db.commit()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_github_advisories(self):
    """
    Fetch GitHub security advisories.

    Runs every 4 hours to check for new advisories.
    """
    if not run_async(_are_security_feeds_enabled()):
        logger.info("Security feeds disabled (air-gapped mode), skipping GitHub fetch")
        return

    logger.info("Starting GitHub advisory fetch...")

    try:
        run_async(_fetch_github_advisories_async())
        logger.info("GitHub advisory fetch completed")
    except Exception as e:
        logger.exception(f"GitHub fetch failed: {e}")
        raise self.retry(exc=e)


async def _fetch_github_advisories_async():
    """Async implementation of GitHub advisory fetch.

    Uses the GitHub Advisory Database REST API to fetch recent
    reviewed advisories for the pip ecosystem. Works with or without
    a GITHUB_TOKEN (unauthenticated requests have lower rate limits).
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    else:
        logger.warning(
            "GITHUB_TOKEN not configured; using unauthenticated access "
            "(lower rate limits). Set GITHUB_TOKEN for higher throughput."
        )

    # REST API: fetch reviewed advisories for the pip ecosystem
    base_url = "https://api.github.com/advisories"
    params = {
        "type": "reviewed",
        "ecosystem": "pip",
        "per_page": 50,
        "sort": "published",
        "direction": "desc",
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                base_url,
                params=params,
                headers=headers,
                timeout=60.0,
            )
            response.raise_for_status()
            advisories = response.json()
        except httpx.HTTPStatusError as e:
            logger.error(
                f"GitHub advisory API returned {e.response.status_code}: "
                f"{e.response.text[:200]}"
            )
            return
        except Exception as e:
            logger.error(f"Failed to fetch from GitHub advisories API: {e}")
            return

    if not isinstance(advisories, list):
        logger.error(
            f"Unexpected GitHub response type: {type(advisories).__name__}"
        )
        return

    logger.info(f"Found {len(advisories)} advisories from GitHub")

    # Map GitHub severity strings to our IssueSeverity enum
    severity_map = {
        "critical": IssueSeverity.CRITICAL,
        "high": IssueSeverity.HIGH,
        "medium": IssueSeverity.MEDIUM,
        "low": IssueSeverity.LOW,
    }

    from sqlalchemy import select

    new_issue_ids = []

    async with get_db_context() as db:
        created_count = 0
        for advisory in advisories:
            # Prefer the CVE ID if available, fall back to GHSA ID
            ghsa_id = advisory.get("ghsa_id", "")
            cve_id = advisory.get("cve_id") or ghsa_id

            if not cve_id:
                continue

            # Check if already exists (by cve_id)
            stmt = select(SecurityIssue).where(
                SecurityIssue.cve_id == cve_id
            )
            existing = (await db.execute(stmt)).scalar_one_or_none()
            if existing:
                continue

            # Extract fields
            summary = advisory.get("summary", "No summary")
            description = advisory.get("description", summary)
            severity_str = (advisory.get("severity") or "medium").lower()
            severity = severity_map.get(severity_str, IssueSeverity.MEDIUM)
            html_url = advisory.get("html_url", "")

            # CVSS data
            cvss = advisory.get("cvss", {}) or {}
            cvss_score = cvss.get("score")
            cvss_vector = cvss.get("vector_string")

            # Published timestamp
            published_at = None
            published_str = advisory.get("published_at")
            if published_str:
                try:
                    published_at = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    pass

            # Collect references
            references = []
            if html_url:
                references.append(html_url)
            for ref in advisory.get("references", []) or []:
                ref_url = ref if isinstance(ref, str) else ref.get("url", "")
                if ref_url and ref_url not in references:
                    references.append(ref_url)

            # Extract affected package names
            affected_components = []
            for vuln in advisory.get("vulnerabilities", []) or []:
                pkg = vuln.get("package", {}) or {}
                pkg_name = pkg.get("name")
                if pkg_name and pkg_name not in affected_components:
                    affected_components.append(pkg_name)

            # Affected version ranges
            affected_versions = []
            for vuln in advisory.get("vulnerabilities", []) or []:
                vr = vuln.get("vulnerable_version_range")
                if vr:
                    affected_versions.append(vr)

            issue = SecurityIssue(
                cve_id=cve_id,
                title=f"{cve_id}: {summary[:200]}",
                description=description[:5000],
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                status=IssueStatus.ACTIVE,
                source="github",
                source_url=html_url,
                published_at=published_at,
                references=references,
                affected_components=affected_components,
                affected_versions=affected_versions,
                auto_generate_rules=True,
                details={
                    "ghsa_id": ghsa_id,
                    "github_severity": severity_str,
                },
            )
            db.add(issue)
            await db.flush()
            new_issue_ids.append(issue.id)
            created_count += 1

        await db.commit()
        logger.info(f"Created {created_count} new SecurityIssue records from GitHub")

    # Auto-mitigate new issues if enabled
    if new_issue_ids and await _is_auto_mitigate_enabled():
        logger.info(f"Auto-mitigating {len(new_issue_ids)} new GitHub advisory issues")
        async with get_db_context() as db:
            for issue_id in new_issue_ids:
                try:
                    result = await auto_mitigate_issue(db, issue_id)
                    logger.info(f"Auto-mitigated {issue_id}: {result.get('method')}")
                except Exception as e:
                    logger.warning(f"Auto-mitigation failed for {issue_id}: {e}")
            await db.commit()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def scan_clawhub_skills(self):
    """
    Scan ClawHub for potentially malicious skills.

    Runs every 2 hours to detect new threats.
    """
    if not run_async(_are_security_feeds_enabled()):
        logger.info("Security feeds disabled (air-gapped mode), skipping ClawHub scan")
        return

    logger.info("Starting ClawHub skill scan...")

    try:
        run_async(_scan_clawhub_skills_async())
        logger.info("ClawHub skill scan completed")
    except Exception as e:
        logger.exception(f"ClawHub scan failed: {e}")
        raise self.retry(exc=e)


async def _scan_clawhub_skills_async():
    """Async implementation of ClawHub skill scan.

    Populates the malicious_skills table from the curated
    MALICIOUS_SKILL_RECORDS list (sourced from ClawHavoc campaign
    analysis, ToxicSkills study, and Snyk research). Uses upsert
    logic to avoid duplicates on re-runs.
    """
    from sqlalchemy import select
    from app.scripts.apply_security_defaults import MALICIOUS_SKILL_RECORDS

    async with get_db_context() as db:
        created_count = 0
        updated_count = 0

        for record_data in MALICIOUS_SKILL_RECORDS:
            skill_id = record_data["skill_id"]

            # Check if skill_id already exists
            stmt = select(MaliciousSkill).where(
                MaliciousSkill.skill_id == skill_id
            )
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing:
                # Update last_seen_at to mark as still active
                existing.last_seen_at = datetime.utcnow()
                updated_count += 1
                continue

            skill = MaliciousSkill(
                skill_id=skill_id,
                skill_name=record_data["skill_name"],
                author=record_data.get("author"),
                threat_type=record_data["threat_type"],
                severity=record_data["severity"],
                analysis_notes=record_data.get("description"),
                indicators=record_data.get("indicators", {}),
                confidence=record_data.get("confidence", "medium"),
                source=record_data.get("source", "scan"),
                is_blocked=record_data.get("is_blocked", True),
                is_verified=record_data.get("is_verified", False),
            )
            db.add(skill)
            created_count += 1

        await db.commit()
        logger.info(
            f"ClawHub scan complete: {created_count} new skills added, "
            f"{updated_count} existing skills refreshed"
        )


@celery_app.task(bind=True)
def generate_recommendations(self):
    """
    Generate security recommendations based on current state.

    Runs daily to provide actionable security suggestions.
    """
    logger.info("Generating security recommendations...")

    try:
        run_async(_generate_recommendations_async())
        logger.info("Recommendation generation completed")
    except Exception as e:
        logger.exception(f"Recommendation generation failed: {e}")


async def _generate_recommendations_async():
    """Async implementation of recommendation generation."""
    async with get_db_context() as db:
        await redis_client.connect()
        monitor = SecurityMonitor(db, redis_client)

        # Get all agents
        from sqlalchemy import select
        from app.models.agents import Agent

        stmt = select(Agent).where(Agent.is_deleted == False)
        result = await db.execute(stmt)
        agents = list(result.scalars().all())

        for agent in agents:
            # Calculate score and get suggestions
            score_data = await monitor.calculate_security_score(agent.id)

            for suggestion in score_data.get("improvement_suggestions", []):
                # Create recommendation
                rec = SecurityRecommendation(
                    agent_id=agent.id,
                    organization_id=agent.organization_id,
                    title=suggestion["title"],
                    description=suggestion["description"],
                    rationale=f"Improve security score by {suggestion['potential_gain']} points",
                    severity=IssueSeverity.MEDIUM,
                    impact_score=suggestion["potential_gain"],
                    recommended_rules=suggestion.get("action", {}),
                    is_one_click=True,
                )
                db.add(rec)

        await db.commit()


@celery_app.task(bind=True)
def calculate_security_scores(self):
    """
    Calculate and cache security scores for all agents.

    Runs hourly to keep scores up to date.
    """
    logger.info("Calculating security scores...")

    try:
        run_async(_calculate_security_scores_async())
        logger.info("Security score calculation completed")
    except Exception as e:
        logger.exception(f"Score calculation failed: {e}")


async def _calculate_security_scores_async():
    """Async implementation of score calculation."""
    async with get_db_context() as db:
        await redis_client.connect()
        monitor = SecurityMonitor(db, redis_client)

        # Calculate global score
        await monitor.calculate_security_score(None)

        # Calculate per-agent scores (org-aware)
        from sqlalchemy import select
        from app.models.agents import Agent

        stmt = select(Agent).where(Agent.is_deleted == False)
        result = await db.execute(stmt)
        agents = list(result.scalars().all())

        for agent in agents:
            await monitor.calculate_security_score(agent.id, org_id=agent.organization_id)


@celery_app.task(bind=True)
def send_weekly_digest(self):
    """
    Send weekly security digest.

    Runs every Monday at 8 AM UTC as specified in CLAUDE.md.
    """
    logger.info("Sending weekly security digest...")

    try:
        run_async(_send_weekly_digest_async())
        logger.info("Weekly digest sent")
    except Exception as e:
        logger.exception(f"Weekly digest failed: {e}")


async def _send_weekly_digest_async():
    """Async implementation of weekly digest.

    Generates per-org digests when organizations exist, falling back
    to a single global digest for self-hosted / single-tenant setups.
    """
    from app.tasks.alerts import send_alert

    async with get_db_context() as db:
        await redis_client.connect()

        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)

        from sqlalchemy import func, select
        from app.models.audit_logs import AuditLog, PolicyViolation

        # Collect org IDs (None = global/self-hosted)
        org_ids: list = [None]
        try:
            from app.models.organizations import Organization
            orgs_result = await db.execute(select(Organization.id))
            found_orgs = [row[0] for row in orgs_result]
            if found_orgs:
                org_ids = found_orgs
        except Exception:
            pass  # organizations table may not exist in self-hosted

        # Count new CVEs (global — same for all orgs)
        cves_stmt = select(func.count()).select_from(SecurityIssue).where(
            SecurityIssue.discovered_at >= week_ago
        )
        new_cves = (await db.execute(cves_stmt)).scalar() or 0

        for oid in org_ids:
            # Count violations (org-scoped)
            violations_stmt = select(func.count()).select_from(PolicyViolation).where(
                PolicyViolation.created_at >= week_ago
            )
            if oid:
                violations_stmt = violations_stmt.where(PolicyViolation.organization_id == oid)
            violations_count = (await db.execute(violations_stmt)).scalar() or 0

            # Count blocked requests (org-scoped)
            blocked_stmt = select(func.count()).select_from(AuditLog).where(
                AuditLog.created_at >= week_ago,
                AuditLog.action == "request_denied",
            )
            if oid:
                blocked_stmt = blocked_stmt.where(AuditLog.organization_id == oid)
            blocked_count = (await db.execute(blocked_stmt)).scalar() or 0

            digest = f"""
Snapper Rules Manager - Weekly Security Digest
Period: {week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}

Summary:
- New CVEs discovered: {new_cves}
- Policy violations: {violations_count}
- Blocked requests: {blocked_count}

Please review the dashboard for detailed information.
"""

            metadata = {}
            if oid:
                metadata["organization_id"] = str(oid)

            send_alert.delay(
                title="Weekly Security Digest",
                message=digest,
                severity="info",
                channels=["email", "slack"],
                metadata=metadata,
            )
