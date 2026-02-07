# CLAUDE.md

## Project Overview

Snapper is a security-focused application that enables users to impose granular restrictions on AI agents. The system provides rule-based control over agent commands, time-based restrictions, rate limiting, and other security constraints to enhance AI agent operational safety.

## Tech Stack

| Component | Technology | Notes |
|-----------|------------|-------|
| Backend API | FastAPI | RESTful API with async support |
| Database | PostgreSQL | Primary data store for rules and configurations |
| Caching/Rate Limiting | Redis | Session management and rate limiting |
| Frontend | HTML/CSS/JavaScript | Server-rendered with Tailwind CSS |
| Styling | Tailwind CSS | Utility-first CSS framework |
| Language | Python 3.11+ | Main development language |
| ORM | SQLAlchemy | Database operations with Alembic migrations |

## Project Structure

```
snapper/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── config.py              # Configuration settings
│   ├── database.py            # Database connection and setup
│   ├── models/                # SQLAlchemy models
│   │   ├── __init__.py
│   │   ├── rules.py           # Rule definitions (incl. PII_GATE type)
│   │   ├── agents.py          # Agent configurations
│   │   ├── pii_vault.py       # PII vault encrypted storage model
│   │   └── users.py           # User management
│   ├── routers/               # API route handlers
│   │   ├── __init__.py
│   │   ├── rules.py           # Rules CRUD + evaluate endpoint
│   │   ├── agents.py          # Agent management
│   │   ├── vault.py           # PII vault CRUD API
│   │   ├── approvals.py       # Approval workflow + token resolution
│   │   ├── telegram.py        # Telegram bot (/vault, /pii, /test, etc.)
│   │   └── security.py        # Security research endpoints
│   ├── services/              # Business logic
│   │   ├── __init__.py
│   │   ├── rule_engine.py     # Rule evaluation (incl. PII gate evaluator)
│   │   ├── pii_vault.py       # Fernet encryption, token resolution, CRUD
│   │   ├── rate_limiter.py    # Rate limiting implementation
│   │   └── security_monitor.py # Security research integration
│   ├── schemas/               # Pydantic models
│   │   ├── __init__.py
│   │   ├── rules.py
│   │   └── agents.py
│   └── templates/             # Jinja2 templates
│       ├── base.html
│       ├── dashboard.html
│       └── rules/
├── plugins/                   # OpenClaw plugins
│   └── snapper-guard/         # Browser interception + PII vault plugin
│       ├── index.ts
│       └── openclaw.plugin.json
├── static/                    # Static assets
│   ├── css/
│   └── js/
├── alembic/                   # Database migrations
├── tests/                     # Test suite
├── requirements.txt
├── docker-compose.yml         # Development environment
└── README.md
```

## Commands

Snapper runs exclusively in Docker — no bare-metal installs.

```bash
# Local development
docker compose up -d

# Production deployment (Ubuntu VPS)
./deploy.sh

# Production compose (manual)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Database migrations
docker compose exec app alembic upgrade head
docker compose exec app alembic revision --autogenerate -m "description"

# Run unit tests
docker compose exec app pytest tests/ -v

# Run specific test files
docker compose exec app pytest tests/test_pii_vault.py tests/test_pii_gate.py -v
docker compose exec app pytest tests/test_allow_once_always.py -v
docker compose exec app pytest tests/test_telegram_callbacks.py -v
docker compose exec app pytest tests/test_openclaw_templates.py -v

# Run with coverage
docker compose exec app pytest tests/ --cov=app --cov-report=term-missing

# E2E tests (requires Playwright on host, app running)
E2E_BASE_URL=http://localhost:8000 pytest tests/e2e -v

# Linting (inside container)
docker compose exec app black app/ tests/
docker compose exec app flake8 app/ tests/
docker compose exec app mypy app/
```

## Code Patterns

### Rule Definition Structure
```python
class Rule(BaseModel):
    agent_id: str
    rule_type: RuleType  # COMMAND_ALLOW, TIME_RESTRICTION, RATE_LIMIT, PII_GATE
    parameters: Dict[str, Any]
    is_active: bool = True
    priority: int = 0
```

### Rate Limiting Pattern
```python
@rate_limit(max_requests=10, window_seconds=60)
async def protected_endpoint():
    pass
```

### Rule Engine Integration
- Rules are evaluated in priority order (higher priority first)
- Use dependency injection for rule engine in route handlers
- Implement async rule evaluation for performance
- Cache frequently accessed rules in Redis

### Database Patterns
- Use SQLAlchemy async sessions
- Implement soft deletes for audit trails
- Index agent_id and rule_type columns for performance
- Use database constraints to ensure data integrity

### Security Research Integration
- Implement background tasks for periodic security updates
- Store research findings with timestamps and sources
- Provide API endpoints for latest security insights
- Cache security data with appropriate TTL

## CLAUDE NOTES

- **Agent Integration**: Study the agent hooks and permissions system before implementing integrations
- **Security Priority**: All rule evaluations must fail-safe (deny by default)
- **Performance**: Use Redis for caching rules and rate limiting counters
- **Compatibility**: Currently supports OpenClaw (running in Docker); design rule schema to adapt to future agent frameworks
- **Security Research**: Implement background job for weekly security research updates since 1/28/26
- **Rate Limiting**: Use sliding window algorithm with Redis for accurate rate limiting
- **Audit Trail**: Log all rule changes and enforcement actions
- **API Design**: Follow REST conventions and provide OpenAPI documentation
- **Testing**: Focus on rule engine logic and security boundary testing
- **Error Handling**: Provide clear error messages for rule violations
- **Allow Once/Always**: Telegram callbacks store temporary Redis keys for one-time approvals
- **OpenClaw Templates**: 4 pre-configured templates for safe commands, sync, dangerous blocks, and approval requirements
- **PII Vault**: Fernet-encrypted PII storage with vault tokens (`{{SNAPPER_VAULT:<8hex>}}`). Key derived from SECRET_KEY via HKDF.
- **PII Gate**: Rule evaluator that scans tool_input and commands for vault tokens + raw PII patterns. Two modes: protected (require approval) and auto (inline resolution).
- **snapper-guard Plugin**: OpenClaw plugin (`plugins/snapper-guard/`) that intercepts browser tool calls, calls evaluate endpoint, and replaces vault tokens with real values in tool params via `before_tool_call` hook.