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
from app.services.security_monitor import SecurityMonitor
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


def run_async(coro):
    """Run async coroutine in sync context."""
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(coro)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_nvd_updates(self):
    """
    Fetch latest vulnerabilities from NVD (National Vulnerability Database).

    Runs every 6 hours to check for new CVEs that may affect Snapper.
    """
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

    async with get_db_context() as db:
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id")

            if not cve_id:
                continue

            # Check if already exists
            from sqlalchemy import select
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

        await db.commit()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def fetch_github_advisories(self):
    """
    Fetch GitHub security advisories.

    Runs every 4 hours to check for new advisories.
    """
    logger.info("Starting GitHub advisory fetch...")

    try:
        run_async(_fetch_github_advisories_async())
        logger.info("GitHub advisory fetch completed")
    except Exception as e:
        logger.exception(f"GitHub fetch failed: {e}")
        raise self.retry(exc=e)


async def _fetch_github_advisories_async():
    """Async implementation of GitHub advisory fetch."""
    if not settings.GITHUB_TOKEN:
        logger.warning("GitHub token not configured, skipping advisory fetch")
        return

    # GraphQL query for security advisories
    query = """
    query {
        securityAdvisories(first: 50, orderBy: {field: PUBLISHED_AT, direction: DESC}) {
            nodes {
                ghsaId
                summary
                description
                severity
                publishedAt
                cvss {
                    score
                    vectorString
                }
                vulnerabilities(first: 10) {
                    nodes {
                        package {
                            name
                            ecosystem
                        }
                    }
                }
                references {
                    url
                }
            }
        }
    }
    """

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                "https://api.github.com/graphql",
                json={"query": query},
                headers={
                    "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
                    "Content-Type": "application/json",
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch from GitHub: {e}")
            return

    advisories = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    logger.info(f"Found {len(advisories)} advisories from GitHub")

    # Process and store advisories (similar to NVD)
    # ... implementation similar to NVD ...


@celery_app.task(bind=True, max_retries=3, default_retry_delay=300)
def scan_clawhub_skills(self):
    """
    Scan ClawHub for potentially malicious skills.

    Runs every 2 hours to detect new threats.
    """
    logger.info("Starting ClawHub skill scan...")

    try:
        run_async(_scan_clawhub_skills_async())
        logger.info("ClawHub skill scan completed")
    except Exception as e:
        logger.exception(f"ClawHub scan failed: {e}")
        raise self.retry(exc=e)


async def _scan_clawhub_skills_async():
    """Async implementation of ClawHub skill scan."""
    # This would integrate with ClawHub's API to scan skills
    # For now, this is a placeholder that would:
    # 1. Fetch recent/popular skills from ClawHub
    # 2. Analyze each skill for suspicious patterns
    # 3. Update the malicious_skills table

    logger.info("ClawHub scan - placeholder implementation")

    # Known malicious patterns to check for
    suspicious_patterns = [
        r"eval\s*\(",
        r"exec\s*\(",
        r"subprocess\.call",
        r"os\.system",
        r"curl.*\|.*sh",
        r"base64\.decode",
        r"requests\.post.*credentials",
    ]

    # In a real implementation, this would:
    # 1. Call ClawHub API to get skill list
    # 2. Download and analyze skill code
    # 3. Check against suspicious patterns
    # 4. Flag or block malicious skills


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

        # Calculate per-agent scores
        from sqlalchemy import select
        from app.models.agents import Agent

        stmt = select(Agent).where(Agent.is_deleted == False)
        result = await db.execute(stmt)
        agents = list(result.scalars().all())

        for agent in agents:
            await monitor.calculate_security_score(agent.id)


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
    """Async implementation of weekly digest."""
    from app.tasks.alerts import send_alert

    async with get_db_context() as db:
        await redis_client.connect()

        # Generate digest content
        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)

        # Get statistics
        from sqlalchemy import func, select
        from app.models.audit_logs import AuditLog, PolicyViolation

        # Count violations
        violations_stmt = select(func.count()).select_from(PolicyViolation).where(
            PolicyViolation.created_at >= week_ago
        )
        violations_count = (await db.execute(violations_stmt)).scalar() or 0

        # Count blocked requests
        blocked_stmt = select(func.count()).select_from(AuditLog).where(
            AuditLog.created_at >= week_ago,
            AuditLog.action == "request_denied",
        )
        blocked_count = (await db.execute(blocked_stmt)).scalar() or 0

        # Count new CVEs
        cves_stmt = select(func.count()).select_from(SecurityIssue).where(
            SecurityIssue.discovered_at >= week_ago
        )
        new_cves = (await db.execute(cves_stmt)).scalar() or 0

        # Compose digest
        digest = f"""
Snapper Rules Manager - Weekly Security Digest
Period: {week_ago.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}

Summary:
- New CVEs discovered: {new_cves}
- Policy violations: {violations_count}
- Blocked requests: {blocked_count}

Please review the dashboard for detailed information.
"""

        # Send via configured channels
        send_alert.delay(
            title="Weekly Security Digest",
            message=digest,
            severity="info",
            channels=["email", "slack"],
        )
