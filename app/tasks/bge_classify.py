"""Celery task for background BGE classification of MCP servers.

Runs after catalog sync completes. Processes servers still classified
as 'general' that have descriptions, using the BGE embedding model.

Follows established async Celery patterns:
  - asyncio.run() for clean event loop
  - engine.dispose() at task start
  - Batch processing for efficiency
"""

import asyncio
import logging

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

BATCH_SIZE = 100


def _run_async(coro):
    return asyncio.run(coro)


@celery_app.task(
    name="bge-classify-servers",
    bind=True,
    max_retries=0,
    time_limit=300,
)
def bge_classify_servers(self):
    """Classify servers with BGE embeddings that tiers 1+2 couldn't handle."""
    return _run_async(_classify_async())


async def _classify_async():
    from sqlalchemy import select, func
    from app.database import engine, get_db_context
    from app.models.mcp_catalog import MCPServerCatalog
    from app.services.bge_classifier import is_available, batch_embed_and_classify

    # Reset DB pool for new event loop
    await engine.dispose()

    if not is_available():
        logger.info("BGE classifier not available — skipping")
        return {"classified": 0, "skipped": True}

    classified_count = 0

    async with get_db_context() as db:
        # Count total needing classification
        total = (await db.execute(
            select(func.count(MCPServerCatalog.id)).where(
                MCPServerCatalog.security_category == "general",
                MCPServerCatalog.description.isnot(None),
                MCPServerCatalog.description != "",
            )
        )).scalar() or 0

        if total == 0:
            logger.info("No servers need BGE classification")
            return {"classified": 0, "total_eligible": 0}

        logger.info(f"BGE classification: {total} servers to process")

        # Process in batches
        offset = 0
        while offset < total:
            result = await db.execute(
                select(MCPServerCatalog)
                .where(
                    MCPServerCatalog.security_category == "general",
                    MCPServerCatalog.description.isnot(None),
                    MCPServerCatalog.description != "",
                )
                .order_by(MCPServerCatalog.popularity_score.desc())
                .offset(offset)
                .limit(BATCH_SIZE)
            )
            servers = result.scalars().all()

            if not servers:
                break

            # Build text inputs: "name: description"
            texts = [
                f"{s.name}: {s.description}" for s in servers
            ]

            # Batch classify
            results = batch_embed_and_classify(texts)

            # Update servers
            batch_classified = 0
            for server, (category, confidence) in zip(servers, results):
                if category != "general":
                    server.security_category = category
                    meta = dict(server.security_metadata or {})
                    meta["classification_method"] = "bge"
                    meta["classification_confidence"] = round(confidence, 3)
                    server.security_metadata = meta
                    batch_classified += 1

            classified_count += batch_classified
            await db.commit()

            logger.info(
                f"BGE batch: {batch_classified}/{len(servers)} classified "
                f"(offset={offset})"
            )
            offset += BATCH_SIZE

    logger.info(f"BGE classification complete: {classified_count}/{total} classified")
    return {"classified": classified_count, "total_eligible": total}
