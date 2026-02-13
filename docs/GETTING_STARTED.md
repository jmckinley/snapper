# Getting Started with Snapper

Snapper is an Agent Application Firewall (AAF) for AI agents. It inspects and
enforces security policy on traffic in both directions — blocking dangerous actions,
detecting PII exfiltration, preventing malicious skill installation, and requiring
human approval for sensitive operations. Supports OpenClaw, Claude Code, Cursor,
Windsurf, Cline, and custom agents.

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

Works on any Ubuntu/Debian VPS (Hostinger, Hetzner, DigitalOcean, AWS, etc.).

#### Option 1: Automated (Recommended)

```bash
git clone https://github.com/jmckinley/snapper.git /opt/snapper
cd /opt/snapper
./deploy.sh                              # IP-based, self-signed TLS on :8443
./deploy.sh --domain snapper.example.com # with automatic Let's Encrypt
```

**Available flags:**

| Flag | Description |
|------|-------------|
| `--domain DOMAIN` | Domain name — enables automatic Let's Encrypt TLS |
| `--port PORT` | HTTPS port (default: 443 with domain, 8443 without) |
| `--repo URL` | Git repo URL (for forks) |
| `--host IP` | Override auto-detected server IP |
| `--yes` | Non-interactive mode (skip all confirmation prompts) |
| `--no-openclaw` | Skip automatic OpenClaw detection and integration |

The script handles:
- **Prerequisite installation** — Installs Docker, Caddy, and UFW if missing (offers to install, or auto-installs with `--yes`)
- **Secure `.env` generation** — Random `SECRET_KEY`, production-hardened defaults
- **Container build** — Gunicorn with 4 workers, `restart: unless-stopped` for reboot survival
- **Database migrations** — Runs `alembic upgrade head` automatically
- **TLS configuration** — Let's Encrypt (with `--domain`) or self-signed certificate (IP-only)
- **Firewall** — Opens necessary ports in UFW (plus ports 80/443 for Let's Encrypt ACME)
- **OpenClaw auto-integration** — If OpenClaw is detected on the same server, automatically registers the agent, applies security rules, copies hooks, injects env vars, and installs the snapper-guard plugin (skip with `--no-openclaw`)
- **Security assessment** — Runs a security posture check at the end (including OpenClaw integration status)

**Production defaults** (set automatically in `.env`):

| Setting | Value | Why |
|---------|-------|-----|
| `LEARNING_MODE` | `false` | Rules are enforced, not just logged |
| `DENY_BY_DEFAULT` | `true` | Unknown requests are blocked |
| `REQUIRE_API_KEY` | `true` | Agents must authenticate with `snp_` keys |
| `REQUIRE_VAULT_AUTH` | `true` | Vault writes require API key |
| `DEBUG` | `false` | No debug output in production |

Result: Snapper at `https://your-domain/` or `https://your-ip:8443`

**Post-deploy:** Run `python3 scripts/snapper-cli.py security-check` anytime, or `security-check --fix` to auto-remediate .env settings.

#### Option 2: Manual

1. **Clone and configure:**
```bash
git clone https://github.com/jmckinley/snapper.git /opt/snapper
cd /opt/snapper
cp .env.example .env
```

2. **Edit `.env` for production:**
```bash
SECRET_KEY=$(openssl rand -hex 32)
LEARNING_MODE=false
DENY_BY_DEFAULT=true
REQUIRE_API_KEY=true
REQUIRE_VAULT_AUTH=true
DEBUG=false
ALLOWED_HOSTS=localhost,127.0.0.1,your-server-ip,app
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

5. **Configure Caddy:**
```bash
# /etc/caddy/Caddyfile — Option A: domain with Let's Encrypt
snapper.example.com {
    reverse_proxy localhost:8000
}

# /etc/caddy/Caddyfile — Option B: IP with self-signed cert
:8443 {
    tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem
    reverse_proxy localhost:8000
}
```

## First Run

> **Production with OpenClaw?** If you deployed with `deploy.sh` and OpenClaw is on the same server, agent registration and integration are handled automatically — skip to [Verify It Works](#verify-it-works).

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

3. **Set up notifications** (optional) — Telegram and/or Slack. Enter your bot token and chat ID.

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

**Via Slack** (if configured):
```
/snapper-test run ls
→ ALLOWED

/snapper-test run rm -rf /
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

| Variable | Dev Default | Prod Default | Description |
|----------|-------------|--------------|-------------|
| `LEARNING_MODE` | `true` | `false` | Log violations but don't block |
| `DENY_BY_DEFAULT` | `false` | `true` | Deny unknown requests (when learning mode off) |
| `REQUIRE_API_KEY` | `false` | `true` | Require API key for agent requests |
| `REQUIRE_VAULT_AUTH` | `false` | `true` | Require API key for vault writes |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,app` | `<ip>,localhost,127.0.0.1,app` | Accepted Host headers |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | `https://<ip>:8443` | CORS/WebSocket origins |

### Telegram Integration

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Bot token from @BotFather |
| `TELEGRAM_CHAT_ID` | Your chat ID (optional, restricts access) |

See [Telegram Setup Guide](TELEGRAM_SETUP.md) for details.

### Slack Integration

| Variable | Description |
|----------|-------------|
| `SLACK_BOT_TOKEN` | Bot token (`xoxb-...`) from your Slack app |
| `SLACK_APP_TOKEN` | App-level token (`xapp-...`) for Socket Mode |
| `SLACK_ALERT_CHANNEL` | Default channel ID for alerts (optional fallback) |

See [Slack Setup Guide](SLACK_SETUP.md) for details.

See `.env.example` for the full list including database, Redis, Celery, alerting, and notification settings.

## Container Architecture

All containers run with `restart: unless-stopped` — they survive VPS reboots automatically.

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
              │    Caddy     │    --domain: Let's Encrypt on :443
              │  (Reverse    │    IP-only:  Self-signed on :8443
              │   Proxy)     │
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
- [Slack Setup](SLACK_SETUP.md) — Approval notifications in Slack
- [User Guide](USER_GUIDE.md) — Rules, PII vault, approval workflows, integrations, agent setup for all types
- [Security Guide](SECURITY.md) — Encryption, PII detection, rate limiting, infrastructure hardening
- [OpenClaw Integration Guide](OPENCLAW_INTEGRATION.md) — Plugin vs shell hook details (OpenClaw-specific)
- [API Reference](API.md) — REST API documentation
- [Interactive API Docs](http://localhost:8000/api/docs) — Swagger UI
