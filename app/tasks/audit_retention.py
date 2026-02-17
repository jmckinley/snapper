"""Audit log retention cleanup task."""

import logging

from app.tasks import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.audit_retention.cleanup_old_audit_logs")
def cleanup_old_audit_logs():
    """
    Delete audit logs older than AUDIT_RETENTION_DAYS.

    Runs daily. Batch deletes 1000 rows at a time to avoid long locks.
    """
    import asyncio

    asyncio.get_event_loop().run_until_complete(_cleanup())


async def _cleanup():
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import delete, select, func

    from app.config import get_settings
    from app.database import get_db_context
    from app.models.audit_logs import AuditLog

    settings = get_settings()
    retention_days = settings.AUDIT_RETENTION_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    total_deleted = 0
    batch_size = 1000

    async with get_db_context() as db:
        while True:
            # Find batch of old IDs
            stmt = (
                select(AuditLog.id)
                .where(AuditLog.created_at < cutoff)
                .limit(batch_size)
            )
            result = await db.execute(stmt)
            ids = [row[0] for row in result.all()]

            if not ids:
                break

            del_stmt = delete(AuditLog).where(AuditLog.id.in_(ids))
            await db.execute(del_stmt)
            await db.commit()
            total_deleted += len(ids)

            if len(ids) < batch_size:
                break

    logger.info(
        f"Audit retention cleanup: deleted {total_deleted} logs "
        f"older than {retention_days} days"
    )
    return {"deleted": total_deleted, "retention_days": retention_days}
