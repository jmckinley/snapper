"""Async SQLAlchemy database setup with PostgreSQL.

@module database
@description Database engine, session factory, and connection management for async PostgreSQL.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import AsyncAdaptedQueuePool

from app.config import get_settings

settings = get_settings()

# Create async engine with connection pooling and health checks
engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=AsyncAdaptedQueuePool,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,  # Health check connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
    echo=settings.DEBUG,
)


# Set query timeout for safety
@event.listens_for(engine.sync_engine, "connect")
def set_query_timeout(dbapi_connection, connection_record):
    """Set query timeout to prevent long-running queries."""
    cursor = dbapi_connection.cursor()
    cursor.execute(f"SET statement_timeout = '{settings.DATABASE_QUERY_TIMEOUT}s'")
    cursor.close()


# Session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# Base class for models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database sessions."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database sessions outside of request context."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Verify database connectivity on startup.

    Table creation is handled exclusively by Alembic migrations
    (alembic upgrade head) which must be run before starting the app.
    This avoids race conditions when multiple gunicorn workers start
    simultaneously and each try to create tables.
    """
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))


async def check_db_health() -> bool:
    """Check database connectivity."""
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
            return True
    except Exception:
        return False


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()
