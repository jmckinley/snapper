"""Background Celery task for periodic Shadow AI scanning.

Follows the established async Celery patterns:
  - asyncio.run() for clean event loop in forked workers
  - Fresh RedisClient per task (avoids stale CircuitBreaker lock)
  - engine.dispose() at task start to reset DB connection pool
"""

import asyncio
import logging
from datetime import datetime, timezone

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(name="shadow-ai-scan", bind=True, max_retries=0, time_limit=60)
def scan_for_shadow_ai(self):
    """Run a full shadow AI scan on the current host."""
    if not settings.SHADOW_AI_DETECTION_ENABLED:
        return {"skipped": True, "reason": "SHADOW_AI_DETECTION_ENABLED is False"}

    return _run_async(_scan_async())


async def _scan_async():
    """Async implementation of the shadow AI scan."""
    from app.database import engine, get_db_context
    from app.models.shadow_ai import ShadowAIDetection, ShadowAIStatus
    from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
    from app.services.shadow_ai_detector import run_full_scan
    from sqlalchemy import select, and_

    # Reset DB connection pool for new event loop
    await engine.dispose()

    findings = await run_full_scan()
    logger.info(f"Shadow AI scan completed: {len(findings)} finding(s)")

    if not findings:
        return {"findings": 0}

    new_count = 0
    updated_count = 0

    async with get_db_context() as db:
        for finding in findings:
            # Build a deduplication key: type + host + (destination | process + pid | container_id)
            dedup_filters = [
                ShadowAIDetection.detection_type == finding["detection_type"],
                ShadowAIDetection.host_identifier == finding["host_identifier"],
                ShadowAIDetection.status == ShadowAIStatus.ACTIVE,
            ]

            if finding.get("container_id"):
                dedup_filters.append(
                    ShadowAIDetection.container_id == finding["container_id"]
                )
            elif finding.get("destination"):
                dedup_filters.append(
                    ShadowAIDetection.destination == finding["destination"]
                )
            elif finding.get("process_name"):
                dedup_filters.append(
                    ShadowAIDetection.process_name == finding["process_name"]
                )

            existing = (
                await db.execute(
                    select(ShadowAIDetection).where(and_(*dedup_filters))
                )
            ).scalar_one_or_none()

            if existing:
                existing.last_seen_at = datetime.now(timezone.utc)
                existing.occurrence_count += 1
                if finding.get("details"):
                    existing.details = finding["details"]
                updated_count += 1
            else:
                detection = ShadowAIDetection(
                    detection_type=finding["detection_type"],
                    process_name=finding.get("process_name"),
                    pid=finding.get("pid"),
                    command_line=finding.get("command_line"),
                    destination=finding.get("destination"),
                    container_id=finding.get("container_id"),
                    container_image=finding.get("container_image"),
                    host_identifier=finding["host_identifier"],
                    details=finding.get("details", {}),
                    status=ShadowAIStatus.ACTIVE,
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_at=datetime.now(timezone.utc),
                    occurrence_count=1,
                )
                db.add(detection)

                # Audit log for new detections
                audit = AuditLog(
                    action=AuditAction.SHADOW_AI_DETECTED,
                    severity=AuditSeverity.WARNING,
                    message=(
                        f"Shadow AI detected on {finding['host_identifier']}: "
                        f"{finding['detection_type']} — "
                        f"{finding.get('process_name') or finding.get('destination') or finding.get('container_image') or 'unknown'}"
                    ),
                    details=finding,
                )
                db.add(audit)
                new_count += 1

    # Alert on new findings
    if new_count > 0:
        try:
            from app.tasks.alerts import send_alert
            send_alert.delay(
                title=f"Shadow AI: {new_count} New Detection(s)",
                message=(
                    f"Found {new_count} new unauthorized AI tool(s) on this host.\n"
                    f"Updated {updated_count} existing finding(s).\n"
                    "Review in the Shadow AI dashboard."
                ),
                severity="warning",
                metadata={"new_count": new_count, "updated_count": updated_count},
            )
        except Exception:
            pass

    return {"new": new_count, "updated": updated_count}
