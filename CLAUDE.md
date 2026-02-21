# CLAUDE.md

## Project Overview

Snapper is an Agent Application Firewall (AAF) that inspects and enforces security policy on traffic in both directions between AI agents and the outside world. It provides rule-based control over agent commands, PII detection and encryption, malicious skill blocking, time-based restrictions, rate limiting, and human-in-the-loop approval workflows.

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
│   │   ├── integrations.py    # Integration templates + traffic discovery API
│   │   ├── approvals.py       # Approval workflow + token resolution
│   │   ├── telegram.py        # Telegram bot (/vault, /pii, /test, etc.)
│   │   ├── slack.py           # Slack bot (slash commands, approvals, vault)
│   │   └── security.py        # Security research endpoints
│   ├── services/              # Business logic
│   │   ├── __init__.py
│   │   ├── rule_engine.py     # Rule evaluation (incl. PII gate evaluator)
│   │   ├── pii_vault.py       # AES-256-GCM encryption, token resolution, CRUD
│   │   ├── traffic_discovery.py # MCP server detection, coverage analysis
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
docker compose exec app pytest tests/test_integrations.py tests/test_security_monitor.py -v
docker compose exec app pytest tests/test_security_research.py tests/test_security_defaults.py -v
docker compose exec app pytest tests/test_integration_templates.py -v
docker compose exec app pytest tests/test_traffic_discovery.py -v

# Run with coverage
docker compose exec app pytest tests/ --cov=app --cov-report=term-missing

# E2E tests (requires Playwright on host, app running)
E2E_BASE_URL=http://localhost:8000 pytest tests/e2e -v

# Live E2E integration tests (against running Snapper instance)
# Tests all 15 rule types, approval workflow, PII vault, emergency block, audit trail
bash scripts/e2e_live_test.sh                                  # on VPS (default http://127.0.0.1:8000)
SNAPPER_URL=http://localhost:8000 bash scripts/e2e_live_test.sh  # local with custom URL
E2E_CHAT_ID=<chat_id> bash scripts/e2e_live_test.sh             # with OpenClaw live agent tests

# OpenClaw full-pipeline E2E tests (real agent traffic, ~12 min)
# 19 tests: access control, rate limiting, PII detection, approvals, metadata, emergency block, audit
E2E_CHAT_ID=<chat_id> bash scripts/e2e_openclaw_test.sh

# Integration E2E tests (traffic discovery, templates, custom MCP)
# 109 tests: templates, known servers, traffic insights, coverage, rule creation, custom MCP, legacy
bash scripts/e2e_integrations_test.sh

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
- **Security Priority**: All rule evaluations must fail-safe (deny by default). DENY always short-circuits. Higher-priority ALLOW prevents lower-priority REQUIRE_APPROVAL from overriding.
- **Performance**: Use Redis for caching rules and rate limiting counters
- **Compatibility**: Currently supports OpenClaw (running in Docker); design rule schema to adapt to future agent frameworks
- **Security Research**: Implement background job for weekly security research updates since 1/28/26
- **Rate Limiting**: Use sliding window algorithm with Redis for accurate rate limiting
- **Trust Scoring**: Adaptive trust score (0.5–2.0) tracked per agent. Only rate-limit breaches penalize trust (not rule denials). Enforcement is per-agent opt-in via `auto_adjust_trust` (default off = info-only). Manage via `/trust` Telegram command, `POST /agents/{id}/reset-trust`, or dashboard buttons.
- **Audit Trail**: Log all rule changes and enforcement actions
- **API Design**: Follow REST conventions and provide OpenAPI documentation
- **Testing**: Focus on rule engine logic and security boundary testing
- **Error Handling**: Provide clear error messages for rule violations
- **Allow Once/Always**: Telegram callbacks store temporary Redis keys for one-time approvals
- **OpenClaw Templates**: 4 pre-configured templates for safe commands, sync, dangerous blocks, and approval requirements
- **PII Vault**: AES-256-GCM encrypted PII storage with vault tokens (`{{SNAPPER_VAULT:<32hex>}}`). Key derived from SECRET_KEY via HKDF.
- **PII Gate**: Rule evaluator that scans tool_input and commands for vault tokens + raw PII patterns. Two modes: protected (require approval) and auto (inline resolution).
- **snapper-guard Plugin**: OpenClaw plugin (`plugins/snapper-guard/`) that intercepts browser tool calls, calls evaluate endpoint, and replaces vault tokens with real values in tool params via `before_tool_call` hook.
- **Shell Hooks**: Use `$SNAPPER_URL` and `$SNAPPER_API_KEY` env vars (not hardcoded URLs/keys). Scripts in `scripts/openclaw-hooks/`.
- **Slack Bot**: Full Telegram parity via Socket Mode (`app/routers/slack.py`). Uses slack-bolt[async]. Commands prefixed with `/snapper-` to avoid conflicts. PII vault uses DM-based multi-step flow. Alert routing: numeric `owner_chat_id` → Telegram, `U`-prefix → Slack DM.
- **Traffic Discovery**: `app/services/traffic_discovery.py` parses tool names from audit logs to detect MCP servers, CLI tools, and builtins. 40+ known servers in registry. Coverage analysis checks commands against active rules. Fallback chain: known-server curated rules → category template rules (tier 2.5, from MCP catalog classification) → smart defaults (3 generic rules per server). Custom MCP template for arbitrary servers.
- **Integration Templates**: 10 simplified templates in `app/data/integration_templates.py` (was 30). Templates: shell, filesystem, github, browser, network, aws, database, slack, gmail, custom_mcp. 5 categories: system, developer, network, cloud, communication. Legacy rules from removed templates continue to work.
- **MCP Security Categories**: 13 security categories in `app/data/category_rule_templates.py`. Classifier in `app/services/server_classifier.py` (tiers 1+2) and `app/services/bge_classifier.py` (tier 3). Auto-apply logic in `_auto_apply_category_rules()` in `app/routers/rules.py`. Category templates generate 3-5 rules per server based on security posture. `AUTO_CATEGORY_RULES=true` to enable.