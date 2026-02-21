"""Daily Celery task to pre-compute extension config bundles for all active orgs.

Follows the established async Celery patterns:
  - asyncio.run() for clean event loop
  - engine.dispose() at task start
  - fresh Redis per task
"""

import asyncio
import logging

from app.tasks import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(name="extension-config-refresh", bind=True, max_retries=0, time_limit=120)
def refresh_extension_configs(self):
    """Pre-compute extension config bundles for all active organizations."""
    return _run_async(_refresh_async())


async def _refresh_async():
    from sqlalchemy import select

    from app.database import engine, get_db_context
    from app.models.organizations import Organization
    from app.redis_client import RedisClient
    from app.services.extension_config import build_config_bundle, cache_bundle

    # Reset DB pool for new event loop
    await engine.dispose()

    redis = RedisClient()
    await redis.connect()

    try:
        async with get_db_context() as db:
            result = await db.execute(
                select(Organization).where(
                    Organization.is_active.is_(True),
                    Organization.deleted_at.is_(None),
                )
            )
            orgs = result.scalars().all()

            count = 0
            for org in orgs:
                try:
                    bundle = await build_config_bundle(db, org.id)
                    await cache_bundle(org.id, bundle, redis)
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to build config for org {org.id}: {e}")

            # Also cache the global default bundle
            global_bundle = await build_config_bundle(db, None)
            await cache_bundle(None, global_bundle, redis)

            logger.info(f"Extension config refresh: {count} org bundles + global cached")
            return {"orgs_cached": count}
    finally:
        await redis.close()
