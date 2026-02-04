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
│   │   ├── rules.py           # Rule definitions
│   │   ├── agents.py          # Agent configurations
│   │   └── users.py           # User management
│   ├── routers/               # API route handlers
│   │   ├── __init__.py
│   │   ├── rules.py           # Rules CRUD operations
│   │   ├── agents.py          # Agent management
│   │   └── security.py        # Security research endpoints
│   ├── services/              # Business logic
│   │   ├── __init__.py
│   │   ├── rule_engine.py     # Rule evaluation and enforcement
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

```bash
# Install dependencies
pip install -r requirements.txt

# Development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Database migrations
alembic upgrade head
alembic revision --autogenerate -m "description"

# Run tests
pytest tests/ -v

# Linting
black app/ tests/
flake8 app/ tests/
mypy app/

# Docker development
docker-compose up -d
```

## Code Patterns

### Rule Definition Structure
```python
class Rule(BaseModel):
    agent_id: str
    rule_type: RuleType  # COMMAND_ALLOW, TIME_RESTRICTION, RATE_LIMIT
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
- **Compatibility**: Design rule schema to adapt to various AI agent frameworks
- **Security Research**: Implement background job for weekly security research updates since 1/28/26
- **Rate Limiting**: Use sliding window algorithm with Redis for accurate rate limiting
- **Audit Trail**: Log all rule changes and enforcement actions
- **API Design**: Follow REST conventions and provide OpenAPI documentation
- **Testing**: Focus on rule engine logic and security boundary testing
- **Error Handling**: Provide clear error messages for rule violations