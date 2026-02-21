"""Daily Celery task to sync MCP server catalog from public registries.

Follows the established async Celery patterns:
  - asyncio.run() for clean event loop
  - engine.dispose() at task start
"""

import asyncio
import logging

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(name="mcp-catalog-sync", bind=True, max_retries=0, time_limit=900)
def sync_mcp_catalog(self, force_full: bool = False):
    """Sync MCP server catalog from public registries.

    Args:
        force_full: If True, skip incremental sync and re-fetch everything.
    """
    return _run_async(_sync_async(force_full=force_full))


async def _sync_async(force_full: bool = False):
    from app.database import engine, get_db_context
    from app.services.mcp_catalog import sync_catalog

    # Reset DB pool for new event loop
    await engine.dispose()

    async with get_db_context() as db:
        result = await sync_catalog(db, force_full=force_full)

    return result
