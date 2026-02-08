# Getting Started with Snapper

Snapper is a security rules manager for AI agents. It controls what your AI agent
can do — allow, deny, or require approval for commands, file access, network calls,
and PII handling. Supports OpenClaw, Claude Code, Cursor, Windsurf, Cline, and custom agents.

## What You Need

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | 24.0+ | With Compose plugin (v2) |
| Git | 2.30+ | For cloning repository |
| Python | 3.11+ | Only for E2E tests on host |

**Verify your setup:**
```bash
docker compose version        # Must show v2.x
git --version                 # Must show 2.30+
docker info --format '{{.ServerVersion}}'  # Must show 24.0+
```

At least one supported AI agent should be installed (OpenClaw, Claude Code, Cursor, Windsurf, or Cline).

## Install

### Local Development

Works on macOS, Linux, or Windows with Docker Desktop.

```bash
git clone https://github.com/jmckinley/snapper.git
cd snapper
./setup.sh
```

The setup script validates prerequisites, creates `.env` with a random `SECRET_KEY`, starts containers, runs migrations, and opens the dashboard in your browser.

Dashboard: http://localhost:8000
API Docs: http://localhost:8000/api/docs

### Production (Ubuntu VPS)

#### Option 1: Automated (Recommended)

```bash
git clone https://github.com/jmckinley/snapper.git /opt/snapper
cd /opt/snapper
./deploy.sh
```

The script handles:
- Generating secure `SECRET_KEY`
- Building production containers (Gunicorn, 4 workers)
- Running database migrations
- Configuring Caddy reverse proxy with TLS
- Opening firewall ports

Result: Snapper at `https://your-server-ip:8443`

If Docker, Caddy, or basic tools are missing, `deploy.sh` will detect them and offer to install from official repositories (Ubuntu/Debian only). You don't need to install these manually first.

#### Option 2: Manual

1. **Clone and configure:**
```bash
git clone https://github.com/jmckinley/snapper.git /opt/snapper
cd /opt/snapper
cp .env.example .env
```

2. **Edit `.env`:**
```bash
# Generate a secure secret key
SECRET_KEY=$(openssl rand -hex 32)

# Set your server's IP/hostname
ALLOWED_HOSTS=localhost,127.0.0.1,your-server-ip
ALLOWED_ORIGINS=https://your-server-ip:8443
```

3. **Start services:**
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

4. **Run migrations:**
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec app alembic upgrade head
```

5. **Configure Caddy (optional but recommended):**
```bash
# /etc/caddy/Caddyfile
your-server-ip:8443 {
    tls internal
    reverse_proxy localhost:8000
}
```

## First Run

### Option A: CLI (Recommended)

The fastest way to get started after containers are running:

```bash
python scripts/snapper-cli.py init
```

This auto-detects your installed agents, registers one, applies a security profile, and writes hook configuration — all in one step.

### Option B: Setup Wizard

On first visit to the dashboard, Snapper automatically redirects you to the **setup wizard**. It walks through five steps:

1. **Select your agent type** — Choose from OpenClaw, Claude Code, Cursor, Windsurf, Cline, or Custom. You'll get an API key (`snp_xxx`).

2. **Pick a security profile** — Choose one:
   - **Recommended** — Blocks dangerous commands, requires approval for sensitive ones, allows common safe commands
   - **Strict** — Deny by default, explicit allowlist only
   - **Permissive** — Learning mode, logs everything but blocks nothing (good for initial setup)

3. **Set up Telegram notifications** (optional) — Enter your bot token and chat ID.

4. **Get your config snippet** — For known agents (OpenClaw, Claude Code, Cursor, Windsurf, Cline), Snapper auto-installs hook config. For custom agents, copy the config snippet manually.

After setup, your agent is protected and rules are applied.

## Verify It Works

**Via Telegram** (if configured):
```
/test run ls
→ ALLOWED

/test run rm -rf /
→ DENIED by rule "Block dangerous commands"
```

**Via the API:**
```bash
# Test a safe command
curl -s -X POST http://localhost:8000/api/v1/rules/evaluate \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "openclaw-main", "request_type": "run", "command": "ls"}' \
  | jq '.decision'
# → "allow"

# Test a dangerous command
curl -s -X POST http://localhost:8000/api/v1/rules/evaluate \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "openclaw-main", "request_type": "run", "command": "rm -rf /"}' \
  | jq '.decision'
# → "deny"
```

**Via the dashboard:**
Open http://localhost:8000 and check the Rules page to see your active rules.

## Environment Variables

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Session signing key (32+ chars) | `openssl rand -hex 32` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://user:pass@host/db` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |

### Security Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `LEARNING_MODE` | `true` | Log violations but don't block |
| `DENY_BY_DEFAULT` | `false` | Deny unknown requests (when learning mode off) |
| `REQUIRE_API_KEY` | `false` | Require API key for agent requests |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,app` | Accepted Host headers |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | CORS/WebSocket origins |

### Telegram Integration

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your chat ID (optional, restricts access) |

See [Telegram Setup Guide](TELEGRAM_SETUP.md) for details.

See `.env.example` for the full list including database, Redis, Celery, alerting, and notification settings.

## Container Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Network                       │
├─────────────┬─────────────┬─────────────┬──────────────┤
│     app     │   postgres  │    redis    │ celery-worker │
│  (FastAPI)  │  (Database) │   (Cache)   │   (Tasks)    │
│  :8000      │   :5432     │   :6379     │              │
└─────────────┴─────────────┴─────────────┴──────────────┘
                      │
                      ▼
              ┌──────────────┐
              │    Caddy     │
              │  (Reverse    │
              │   Proxy)     │
              │   :8443      │
              └──────────────┘
```

## Health Checks

```bash
# Basic health
curl http://localhost:8000/health

# Full readiness (DB + Redis)
curl http://localhost:8000/health/ready
```

Expected response:
```json
{
  "status": "ready",
  "database": "connected",
  "redis": "connected"
}
```

## Updating

### Development

```bash
cd snapper
git pull
docker compose up -d --build
docker compose exec app alembic upgrade head
```

### Production

```bash
cd /opt/snapper
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec app alembic upgrade head
```

## Troubleshooting

### Container won't start

```bash
# Check logs
docker compose logs app

# Verify database is ready
docker compose exec postgres pg_isready

# Check Redis
docker compose exec redis redis-cli ping
```

### 403 Forbidden on dashboard

Your server's IP isn't in `ALLOWED_HOSTS`. Add it to `.env`:

```bash
ALLOWED_HOSTS=localhost,127.0.0.1,your-server-ip
```

Then restart with `--force-recreate`:

```bash
docker compose up -d --force-recreate
```

### Database migrations fail

```bash
# Check current migration status
docker compose exec app alembic current

# Reset to clean state (WARNING: destroys data)
docker compose down -v
docker compose up -d
docker compose exec app alembic upgrade head
```

### Environment variables not updating

`docker compose restart` doesn't pick up `.env` changes. Use:

```bash
docker compose up -d --force-recreate
```

### Port already in use

```bash
# Find what's using port 8000
lsof -i :8000

# Or change the port in docker-compose.yml
ports:
  - "8001:8000"
```

## PII Vault Notes

The PII vault uses `SECRET_KEY` from your `.env` to derive the Fernet encryption key via HKDF. Changing `SECRET_KEY` after vault entries are created will make them unrecoverable. Back up your `SECRET_KEY` securely.

## Uninstalling

```bash
# Stop and remove containers
docker compose down

# Remove volumes (deletes all data)
docker compose down -v

# Remove images
docker rmi snapper-app snapper-celery-worker snapper-celery-beat

# Remove directory
rm -rf /opt/snapper
```

## What's Next

- [Telegram Setup](TELEGRAM_SETUP.md) — Approval notifications on your phone
- [User Guide](USER_GUIDE.md) — Rules, PII vault, approval workflows, agent setup for all types
- [Security Guide](SECURITY.md) — Encryption, PII detection, rate limiting, infrastructure hardening
- [OpenClaw Integration Guide](OPENCLAW_INTEGRATION.md) — Plugin vs shell hook details (OpenClaw-specific)
- [API Reference](API.md) — REST API documentation
- [Interactive API Docs](http://localhost:8000/api/docs) — Swagger UI
