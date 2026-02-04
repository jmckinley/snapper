"""Pytest fixtures for Snapper Rules Manager tests."""

import asyncio
import os
from typing import AsyncGenerator, Generator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

# Set test environment
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars!"
os.environ["DATABASE_URL"] = "postgresql+asyncpg://snapper:snapper@localhost:5432/snapper_test"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["DENY_BY_DEFAULT"] = "true"
os.environ["VALIDATE_WEBSOCKET_ORIGIN"] = "false"
os.environ["REQUIRE_LOCALHOST_ONLY"] = "false"
os.environ["ALLOWED_ORIGINS"] = "http://testserver"
os.environ["ALLOWED_HOSTS"] = "testserver,localhost"

from app.config import get_settings
from app.database import Base, get_db
from app.main import app
from app.redis_client import redis_client, RedisClient
from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType


settings = get_settings()


# Create test database engine
test_engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=NullPool,
    echo=False,
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session
        await session.rollback()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with database session override."""

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=app, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def redis(db_session: AsyncSession) -> AsyncGenerator[RedisClient, None]:
    """Create a Redis client for testing."""
    await redis_client.connect()
    yield redis_client
    # Clean up test keys
    await redis_client.client.flushdb()
    await redis_client.close()


@pytest_asyncio.fixture
async def sample_agent(db_session: AsyncSession) -> Agent:
    """Create a sample agent for testing."""
    agent = Agent(
        id=uuid4(),
        name="Test Agent",
        external_id=f"test-agent-{uuid4().hex[:8]}",
        description="A test agent",
        status=AgentStatus.ACTIVE,
        trust_level=TrustLevel.STANDARD,
        allowed_origins=["http://localhost:8000"],
        require_localhost_only=False,
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest_asyncio.fixture
async def sample_rule(db_session: AsyncSession, sample_agent: Agent) -> Rule:
    """Create a sample rule for testing."""
    rule = Rule(
        id=uuid4(),
        name="Test Rule",
        description="A test rule",
        agent_id=sample_agent.id,
        rule_type=RuleType.RATE_LIMIT,
        action=RuleAction.DENY,
        priority=10,
        parameters={"max_requests": 100, "window_seconds": 60},
        is_active=True,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule


@pytest_asyncio.fixture
async def global_rule(db_session: AsyncSession) -> Rule:
    """Create a global rule (no agent_id) for testing."""
    rule = Rule(
        id=uuid4(),
        name="Global Test Rule",
        description="A global test rule",
        agent_id=None,
        rule_type=RuleType.CREDENTIAL_PROTECTION,
        action=RuleAction.DENY,
        priority=100,
        parameters={
            "protected_patterns": [r"\.env$", r"\.pem$"],
            "block_plaintext_secrets": True,
        },
        is_active=True,
    )
    db_session.add(rule)
    await db_session.commit()
    await db_session.refresh(rule)
    return rule
