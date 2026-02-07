# Installation Guide

Complete guide for installing Snapper in development and production environments.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Docker | 24.0+ | With Compose plugin (v2) |
| Git | 2.30+ | For cloning repository |
| Python | 3.11+ | Only for E2E tests on host |

## Quick Start (Development)

```bash
git clone https://github.com/jmckinley/snapper.git
cd snapper
docker compose up -d
```

Dashboard: http://localhost:8000
API Docs: http://localhost:8000/api/docs

## Production Deployment (Ubuntu VPS)

### Option 1: Automated (Recommended)

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

### Option 2: Manual

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

## OpenClaw Integration

If you're running OpenClaw on the same server:

### Option A: snapper-guard Plugin (Recommended)

Supports PII vault token resolution and browser form fill interception.

1. Register OpenClaw agent:
```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{"name": "OpenClaw", "external_id": "openclaw-main"}'
```

2. Copy plugin to OpenClaw extensions:
```bash
cp -r /opt/snapper/plugins/snapper-guard ~/.openclaw/extensions/
```

3. Add plugin config to `~/.openclaw/openclaw.json`:
```json
{
  "plugins": {
    "entries": {
      "snapper-guard": {
        "enabled": true,
        "config": {
          "snapperUrl": "http://127.0.0.1:8000",
          "agentId": "openclaw-main",
          "apiKey": "snp_your_key_here"
        }
      }
    }
  }
}
```

4. Restart OpenClaw:
```bash
docker compose restart openclaw-gateway
```

### Option B: Shell Hook

Intercepts shell commands only (no browser/PII support).

1. Create shell wrapper at `/opt/openclaw/hooks/snapper-shell.sh`

2. Add to OpenClaw's docker-compose.yml:
```yaml
services:
  openclaw-gateway:
    volumes:
      - ./hooks:/app/hooks:ro
    environment:
      SHELL: /app/hooks/snapper-shell.sh
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

3. Restart OpenClaw:
```bash
docker compose up -d --force-recreate openclaw-gateway
```

See [OpenClaw Integration Guide](OPENCLAW_INTEGRATION.md) for full details.

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
