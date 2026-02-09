"""
@module conftest
@description Pytest fixtures for Snapper Rules Manager tests.
"""

import asyncio
import os
from typing import AsyncGenerator, Generator
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

# Detect Docker environment (inside container, use service names; outside, use localhost)
def _get_db_host():
    """Get database host based on environment."""
    # If running inside Docker container
    if os.path.exists("/.dockerenv"):
        return "postgres"
    return "localhost"

def _get_redis_host():
    """Get Redis host based on environment."""
    if os.path.exists("/.dockerenv"):
        return "redis"
    return "localhost"

# Set test environment
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-only-32chars!"
os.environ["DATABASE_URL"] = f"postgresql+asyncpg://snapper:snapper@{_get_db_host()}:5432/snapper_test"
os.environ["REDIS_URL"] = f"redis://{_get_redis_host()}:6379/15"
os.environ["DENY_BY_DEFAULT"] = "true"
os.environ["LEARNING_MODE"] = "false"
os.environ["VALIDATE_WEBSOCKET_ORIGIN"] = "false"
os.environ["REQUIRE_LOCALHOST_ONLY"] = "false"
os.environ["ALLOWED_ORIGINS"] = "http://testserver"
os.environ["ALLOWED_HOSTS"] = "testserver,localhost"
os.environ["REQUIRE_API_KEY"] = "false"
os.environ["REQUIRE_VAULT_AUTH"] = "false"

from app.config import get_settings

# Clear settings cache to ensure test environment variables take effect
get_settings.cache_clear()

from app.database import Base, get_db
from app.main import app
from app.redis_client import redis_client, RedisClient, get_redis
from app.models.agents import Agent, AgentStatus, TrustLevel
from app.models.rules import Rule, RuleAction, RuleType
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity, PolicyViolation, Alert


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


@pytest.fixture(scope="function", autouse=True)
def clear_settings_cache():
    """Clear settings cache before each test to ensure env vars take effect."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


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
async def client(db_session: AsyncSession, redis: RedisClient) -> AsyncGenerator[AsyncClient, None]:
    """Create a test client with database session and redis overrides."""

    async def override_get_db():
        yield db_session

    async def override_get_redis():
        return redis

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_redis] = override_get_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
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


@pytest_asyncio.fixture
async def sample_audit_log(db_session: AsyncSession, sample_agent: Agent) -> AuditLog:
    """Create a sample audit log entry for testing."""
    log = AuditLog(
        id=uuid4(),
        action=AuditAction.REQUEST_DENIED,
        severity=AuditSeverity.WARNING,
        agent_id=sample_agent.id,
        message="Test audit log entry",
        details={"test": True},
    )
    db_session.add(log)
    await db_session.commit()
    await db_session.refresh(log)
    return log


@pytest_asyncio.fixture
async def sample_violation(db_session: AsyncSession, sample_agent: Agent) -> PolicyViolation:
    """Create a sample policy violation for testing."""
    violation = PolicyViolation(
        id=uuid4(),
        violation_type="rate_limit_exceeded",
        severity=AuditSeverity.WARNING,
        agent_id=sample_agent.id,
        description="Test policy violation",
        context={"test": True},
        is_resolved=False,
    )
    db_session.add(violation)
    await db_session.commit()
    await db_session.refresh(violation)
    return violation


@pytest_asyncio.fixture
async def sample_alert(db_session: AsyncSession, sample_agent: Agent) -> Alert:
    """Create a sample alert for testing."""
    alert = Alert(
        id=uuid4(),
        alert_type="security_violation",
        severity=AuditSeverity.ERROR,
        agent_id=sample_agent.id,
        title="Test Alert",
        message="Test alert message",
        details={"test": True},
        is_acknowledged=False,
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)
    return alert


@pytest_asyncio.fixture
async def once_allow_key(redis: RedisClient, sample_agent: Agent):
    """Create a one-time approval key in Redis for testing Allow Once functionality."""
    import hashlib
    test_command = "cat /etc/passwd"
    cmd_hash = hashlib.sha256(test_command.encode()).hexdigest()[:16]
    key = f"once_allow:{sample_agent.name}:{cmd_hash}"
    await redis.set(key, "1", expire=300)
    return key, test_command


@pytest_asyncio.fixture
async def telegram_context(redis: RedisClient, sample_agent: Agent):
    """Create a Telegram callback context in Redis for testing Telegram callbacks."""
    import json
    import hashlib
    context_data = {
        "type": "run",
        "value": "test command",
        "agent_id": sample_agent.name,
    }
    context_key = hashlib.sha256(json.dumps(context_data).encode()).hexdigest()[:12]
    await redis.set(f"tg_ctx:{context_key}", json.dumps(context_data), expire=3600)
    return context_key, context_data


@pytest_asyncio.fixture
async def sample_security_issue(db_session: AsyncSession):
    """Create a sample SecurityIssue for testing."""
    from app.models.security_issues import SecurityIssue, IssueSeverity, IssueStatus

    issue = SecurityIssue(
        id=uuid4(),
        cve_id="CVE-2026-TEST-001",
        title="Test CVE: Critical Vulnerability",
        description="A test vulnerability for unit testing.",
        severity=IssueSeverity.CRITICAL,
        cvss_score=9.0,
        status=IssueStatus.ACTIVE,
        source="test",
    )
    db_session.add(issue)
    await db_session.commit()
    await db_session.refresh(issue)
    return issue


@pytest_asyncio.fixture
async def sample_malicious_skill(db_session: AsyncSession):
    """Create a sample MaliciousSkill for testing."""
    from app.models.security_issues import MaliciousSkill, IssueSeverity

    skill = MaliciousSkill(
        id=uuid4(),
        skill_id="test-malicious",
        skill_name="Test Malicious",
        threat_type="typosquatting",
        severity=IssueSeverity.CRITICAL,
        is_blocked=True,
        is_verified=True,
        source="test",
        confidence="confirmed",
    )
    db_session.add(skill)
    await db_session.commit()
    await db_session.refresh(skill)
    return skill


@pytest_asyncio.fixture
async def sample_recommendation(db_session: AsyncSession):
    """Create a sample SecurityRecommendation for testing."""
    from app.models.security_issues import SecurityRecommendation, IssueSeverity

    rec = SecurityRecommendation(
        id=uuid4(),
        title="Test Credential Protection",
        description="Add credential protection rules",
        rationale="Improve score",
        severity=IssueSeverity.HIGH,
        impact_score=25,
        recommended_rules={
            "rules": [
                {
                    "rule_type": "credential_protection",
                    "action": "deny",
                    "name": "Test Rule",
                    "parameters": {"protected_patterns": [".env"]},
                }
            ]
        },
        is_applied=False,
        is_dismissed=False,
    )
    db_session.add(rec)
    await db_session.commit()
    await db_session.refresh(rec)
    return rec
