"""AI-powered periodic review of agent activity logs.

Complements the deterministic heuristic engine with an LLM that
reasons about subtle attack patterns, context-dependent misuse, and
behavioral shifts that regex/state-machine approaches miss.

Runs every 15 minutes (configurable). Queries recent audit logs and
threat signals, sends a structured summary to Claude, and creates
ThreatEvents or adjusts scores based on findings.

**Air-gapped / offline safe:** This task is strictly opt-in via
THREAT_AI_REVIEW_ENABLED (default False). If disabled or if
ANTHROPIC_API_KEY is not set, the task exits immediately with no
side effects. Network failures are caught and logged — they never
affect the deterministic heuristic engine, kill chain detection,
or any other threat analysis. The full threat detection system
operates without internet connectivity.
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

# Redis key to track last review timestamp
LAST_REVIEW_KEY = "threat:ai_review:last_run"

# Anthropic Messages API endpoint
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

SYSTEM_PROMPT = """\
You are a security analyst for Snapper, an Agent Application Firewall (AAF) \
that monitors AI agent traffic. Your job is to review recent agent activity \
logs and identify suspicious behavioral patterns that simple rule-based \
detection might miss.

Focus on:
1. **Behavioral shifts** — An agent that normally does non-sensitive work \
(file listing, text formatting) suddenly accessing credentials, git configs, \
system files, or making unusual network requests.
2. **Subtle exfiltration** — Data leaving in small chunks across many requests, \
encoded payloads, DNS exfiltration patterns, or sensitive data mixed into \
legitimate-looking requests.
3. **Social engineering prep** — Agents gathering organizational info, user \
lists, email addresses, or internal URLs that could enable phishing or lateral \
movement.
4. **Privilege probing** — Repeated attempts at slightly different privilege \
escalation paths, testing access boundaries systematically.
5. **Vault/PII reconnaissance** — Patterns suggesting an agent is mapping \
where PII is stored or how vault tokens work, even without triggering \
individual rules.
6. **Multi-agent coordination** — Two or more agents acting in concert \
(one reads files, another sends them out) that wouldn't trigger single-agent \
kill chains.
7. **Timing anomalies** — Activity at unusual hours, burst patterns that \
suggest automated exfiltration rather than human-directed work.

For each finding, provide:
- A severity (critical, high, medium, low)
- A threat type (data_exfiltration, pii_misuse, credential_theft, \
privilege_escalation, behavioral_anomaly, reconnaissance)
- A description of what you observed and why it's suspicious
- Which agent(s) are involved
- A confidence score (0.0 to 1.0)
- A recommended threat score adjustment (0 to 30 points to add)

Respond ONLY with valid JSON. If nothing suspicious is found, return:
{"findings": []}

Otherwise return:
{"findings": [{"severity": "...", "threat_type": "...", "description": "...", \
"agent_ids": ["..."], "confidence": 0.8, "score_adjustment": 15}]}
"""


def _run_async(coro):
    """Run async coroutine in sync Celery context.

    Uses asyncio.run() to ensure a clean event loop in forked workers.
    """
    return asyncio.run(coro)


@celery_app.task(bind=True, max_retries=1, default_retry_delay=300, time_limit=120)
def ai_threat_review(self):
    """Periodic AI review of agent activity logs."""
    if not settings.THREAT_AI_REVIEW_ENABLED:
        return {"status": "disabled"}

    if not settings.ANTHROPIC_API_KEY:
        logger.warning("AI threat review enabled but ANTHROPIC_API_KEY not set")
        return {"status": "no_api_key"}

    try:
        result = _run_async(_ai_review_async())
        return result
    except Exception as e:
        logger.exception(f"AI threat review failed: {e}")
        raise self.retry(exc=e)


async def _ai_review_async() -> Dict[str, Any]:
    """Async implementation of AI threat review."""
    from app.redis_client import RedisClient

    redis = RedisClient()
    await redis.connect()
    try:
        # Check when we last ran to avoid duplicate reviews
        last_run = await redis.get(LAST_REVIEW_KEY)
        now = time.time()
        if last_run:
            elapsed = now - float(last_run)
            if elapsed < settings.THREAT_AI_REVIEW_INTERVAL_SECONDS * 0.8:
                return {"status": "skipped", "reason": "too_recent"}

        # Mark this run
        await redis.set(LAST_REVIEW_KEY, str(now), expire=settings.THREAT_AI_REVIEW_INTERVAL_SECONDS * 2)

        # 1. Gather recent activity data
        activity_summary = await _gather_activity_summary()
        if not activity_summary:
            return {"status": "no_activity"}

        # 2. Call Claude for analysis
        findings = await _call_anthropic(activity_summary)
        if not findings:
            return {"status": "no_findings"}

        # 3. Process findings
        processed = await _process_findings(findings)

        return {
            "status": "completed",
            "findings_count": len(findings),
            "actions_taken": processed,
        }
    finally:
        await redis.close()


async def _gather_activity_summary() -> Optional[str]:
    """Gather recent audit logs and threat signals into a text summary.

    Pulls from the database (audit_logs) and Redis (threat signals,
    baselines) to build a structured view for the AI.
    """
    from app.database import get_db_context
    from app.models.audit_logs import AuditLog
    from app.models.agents import Agent
    from sqlalchemy import select, desc
    from app.redis_client import RedisClient

    max_events = settings.THREAT_AI_MAX_EVENTS_PER_REVIEW
    lookback = timedelta(minutes=30)
    cutoff = datetime.now(timezone.utc) - lookback

    sections = []

    # --- Recent audit logs ---
    try:
        async with get_db_context() as db:
            stmt = (
                select(AuditLog)
                .where(AuditLog.created_at >= cutoff)
                .order_by(desc(AuditLog.created_at))
                .limit(max_events)
            )
            result = await db.execute(stmt)
            logs = result.scalars().all()

            if not logs:
                return None

            # Get agent names for context
            agent_ids = {log.agent_id for log in logs if log.agent_id}
            agent_names = {}
            if agent_ids:
                agents = await db.execute(
                    select(Agent).where(Agent.id.in_(agent_ids))
                )
                for agent in agents.scalars().all():
                    agent_names[str(agent.id)] = agent.name

            log_entries = []
            for log in logs:
                agent_name = agent_names.get(str(log.agent_id), "unknown") if log.agent_id else "system"
                entry = {
                    "time": log.created_at.isoformat() if log.created_at else "",
                    "action": log.action if isinstance(log.action, str) else log.action.value,
                    "agent": agent_name,
                    "agent_id": str(log.agent_id) if log.agent_id else None,
                    "message": (log.message or "")[:200],
                }
                if log.new_value:
                    # Include request details but truncate
                    details = {}
                    for k in ("request_type", "command", "file_path", "tool_name", "decision"):
                        if k in log.new_value:
                            val = str(log.new_value[k])[:150]
                            if val and val != "None":
                                details[k] = val
                    if details:
                        entry["details"] = details
                log_entries.append(entry)

            sections.append(
                f"## Recent Audit Logs ({len(log_entries)} events, last 30 min)\n"
                + json.dumps(log_entries, indent=2, default=str)
            )
    except Exception as e:
        logger.warning(f"Failed to gather audit logs for AI review: {e}")

    # --- Active threat scores and baselines from Redis ---
    redis = None
    try:
        redis = RedisClient()
        await redis.connect()

        # Active threat scores
        try:
            score_keys = await redis.keys("threat:score:*")
            if score_keys:
                scores = {}
                for key in score_keys[:20]:
                    agent_id = key.replace("threat:score:", "")
                    val = await redis.get(key)
                    if val:
                        scores[agent_id[:8]] = float(val)
                if scores:
                    sections.append(
                        f"## Current Threat Scores\n"
                        + json.dumps(scores, indent=2)
                    )
        except Exception:
            pass

        # Agent baselines summary
        try:
            baseline_keys = await redis.keys("baseline:stats:*")
            if baseline_keys:
                baselines = {}
                for key in baseline_keys[:20]:
                    agent_id = key.replace("baseline:stats:", "")
                    stats = await redis.hgetall(key)
                    if stats:
                        baselines[agent_id[:8]] = {
                            "total_requests": stats.get("total_requests_7d", "0"),
                            "unique_destinations": stats.get("unique_destinations", "0"),
                            "unique_tools": stats.get("unique_tools", "0"),
                            "avg_bytes_out": stats.get("avg_bytes_out", "0"),
                        }
                if baselines:
                    sections.append(
                        f"## Agent Baselines (7-day)\n"
                        + json.dumps(baselines, indent=2)
                    )
        except Exception:
            pass
    except Exception:
        pass
    finally:
        if redis:
            await redis.close()

    if not sections:
        return None

    return "\n\n".join(sections)


async def _call_anthropic(activity_summary: str) -> List[Dict[str, Any]]:
    """Call Claude to analyze agent activity.

    Uses the Messages API directly via httpx (no SDK dependency).
    """
    api_key = settings.ANTHROPIC_API_KEY
    model = settings.THREAT_AI_MODEL

    user_message = (
        "Review the following agent activity from the last 30 minutes. "
        "Identify any suspicious patterns, behavioral anomalies, or potential "
        "attack indicators. Focus on patterns that wouldn't be caught by "
        "simple regex rules or individual request analysis.\n\n"
        f"{activity_summary}"
    )

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                ANTHROPIC_API_URL,
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": 2048,
                    "system": SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": user_message},
                    ],
                },
            )

            if response.status_code != 200:
                logger.warning(
                    f"Anthropic API returned {response.status_code}: "
                    f"{response.text[:200]}"
                )
                return []

            data = response.json()
            content = data.get("content", [])
            if not content:
                return []

            text = content[0].get("text", "")
            if not text:
                return []

            # Parse JSON response
            # Handle potential markdown code blocks
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0].strip()
            elif "```" in text:
                text = text.split("```")[1].split("```")[0].strip()

            parsed = json.loads(text)
            findings = parsed.get("findings", [])

            logger.info(f"AI threat review found {len(findings)} findings")
            return findings

    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse AI response as JSON: {e}")
        return []
    except Exception as e:
        logger.warning(f"Anthropic API call failed: {e}")
        return []


async def _process_findings(findings: List[Dict[str, Any]]) -> int:
    """Process AI findings: create threat events and adjust scores."""
    from app.database import get_db_context
    from app.models.threat_events import ThreatEvent
    from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
    from app.models.agents import Agent
    from app.redis_client import RedisClient
    from app.services.threat_detector import get_threat_score, set_threat_score
    from uuid import UUID
    from sqlalchemy import select

    redis = RedisClient()
    await redis.connect()
    actions_taken = 0

    for finding in findings:
        try:
            confidence = float(finding.get("confidence", 0))
            if confidence < 0.5:
                continue  # Skip low-confidence findings

            severity = finding.get("severity", "medium")
            threat_type = finding.get("threat_type", "behavioral_anomaly")
            description = finding.get("description", "AI-detected anomaly")
            agent_ids = finding.get("agent_ids", [])
            score_adj = min(float(finding.get("score_adjustment", 0)), 30)

            # Scale adjustment by confidence
            score_adj = score_adj * confidence

            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
            }
            db_severity = severity_map.get(severity, "medium")

            audit_severity_map = {
                "critical": AuditSeverity.CRITICAL,
                "high": AuditSeverity.ERROR,
                "medium": AuditSeverity.WARNING,
                "low": AuditSeverity.INFO,
            }

            for agent_id_str in agent_ids:
                try:
                    async with get_db_context() as db:
                        # Resolve agent ID (could be partial)
                        agent = None
                        try:
                            agent_uuid = UUID(agent_id_str)
                            agent = (await db.execute(
                                select(Agent).where(Agent.id == agent_uuid)
                            )).scalar_one_or_none()
                        except (ValueError, Exception):
                            # Try matching by name
                            agent = (await db.execute(
                                select(Agent).where(Agent.name == agent_id_str)
                            )).scalar_one_or_none()

                        if not agent:
                            logger.debug(f"AI review: agent '{agent_id_str}' not found, skipping")
                            continue

                        # Create threat event
                        event = ThreatEvent(
                            agent_id=agent.id,
                            organization_id=agent.organization_id,
                            threat_type=threat_type,
                            severity=db_severity,
                            threat_score=score_adj,
                            signals=[],
                            description=f"[AI Review] {description}",
                            details={
                                "source": "ai_review",
                                "model": settings.THREAT_AI_MODEL,
                                "confidence": confidence,
                                "raw_finding": finding,
                            },
                            status="active",
                        )
                        db.add(event)

                        # Create audit log
                        audit = AuditLog(
                            action=AuditAction.THREAT_DETECTED,
                            severity=audit_severity_map.get(severity, AuditSeverity.WARNING),
                            agent_id=agent.id,
                            organization_id=agent.organization_id,
                            message=f"[AI Review] {description[:200]}",
                            details={
                                "source": "ai_review",
                                "threat_type": threat_type,
                                "confidence": confidence,
                                "score_adjustment": score_adj,
                            },
                        )
                        db.add(audit)
                        actions_taken += 1

                    # Adjust threat score in Redis
                    if score_adj > 0:
                        current = await get_threat_score(redis, str(agent.id))
                        new_score = min(current + score_adj, 100.0)
                        await set_threat_score(redis, str(agent.id), new_score)

                        logger.info(
                            f"AI review: {agent.name} score {current:.0f} → {new_score:.0f} "
                            f"(+{score_adj:.0f}, {threat_type}, confidence={confidence:.1f})"
                        )

                    # Fire alert for high-severity findings
                    if severity in ("critical", "high") and confidence >= 0.7:
                        try:
                            from app.tasks.alerts import send_alert
                            send_alert.delay(
                                title=f"AI Threat Review: {agent.name}",
                                message=(
                                    f"*{severity.upper()}* ({confidence:.0%} confidence)\n\n"
                                    f"{description}\n\n"
                                    f"Threat type: {threat_type}\n"
                                    f"Score adjustment: +{score_adj:.0f}"
                                ),
                                severity="error" if severity == "high" else "critical",
                                metadata={
                                    "agent_id": str(agent.id),
                                    "agent_name": agent.name,
                                    "threat_type": threat_type,
                                    "source": "ai_review",
                                    "agent_owner_chat_id": getattr(agent, "owner_chat_id", None),
                                },
                            )
                        except Exception:
                            pass

                except Exception as e:
                    logger.debug(f"Failed to process finding for agent {agent_id_str}: {e}")

        except Exception as e:
            logger.warning(f"Failed to process AI finding: {e}")

    await redis.close()
    return actions_taken
