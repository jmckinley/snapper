# Snapper

**Security rules manager for AI agents** — Fine-grained control over what AI assistants can do.

![Snapper Dashboard](https://img.shields.io/badge/status-beta-yellow) ![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## What is Snapper?

Snapper sits between your AI coding assistants (OpenClaw, Claude Code, Cursor, GitHub Copilot) and the actions they take. It lets you:

- **Allow** specific commands, tools, or integrations
- **Deny** dangerous operations (like `rm -rf /` or accessing `.env` files)
- **Require approval** for sensitive actions before they execute

Think of it as a firewall for AI agents.

## Installation

There are two paths: **local development** (any OS with Docker) and **production deployment** (Ubuntu VPS).

### Local Development

Works on macOS, Linux, or Windows with Docker Desktop.

```bash
git clone https://github.com/jmckinley/snapper.git
cd snapper
docker compose up -d
```

That's it. Dashboard at http://localhost:8000, API docs at http://localhost:8000/api/docs.

To customize settings, copy `.env.example` to `.env` and edit — defaults work out of the box.

### Production (Ubuntu VPS)

One command on a fresh Ubuntu server with Docker installed:

```bash
git clone https://github.com/jmckinley/snapper.git /opt/snapper
cd /opt/snapper
./deploy.sh
```

The script handles everything:
- Generates a production `.env` with a random `SECRET_KEY`
- Builds containers with gunicorn (4 workers)
- Runs database migrations
- Configures Caddy reverse proxy with self-signed TLS
- Opens the firewall port

Result: Snapper at `https://your-server-ip:8443`

**Prerequisites:** `git`, `docker` with compose plugin, `caddy`, `ufw` (all standard on Ubuntu 24.04).

**To update a running deployment:**
```bash
cd /opt/snapper
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm app alembic upgrade head
```

## Agent Setup

### OpenClaw

```bash
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/quick-setup.sh | bash
```

Options: `--strict` (require approval for sensitive actions) or `--permissive` (logging only).

### Claude Code

```bash
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/claude-code-setup.sh | bash
```

Restart Claude Code after setup for hooks to take effect.

<details>
<summary>Manual Claude Code setup</summary>

1. Install the hook:
```bash
mkdir -p ~/.claude/hooks
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/claude-code-hook.sh \
  -o ~/.claude/hooks/pre_tool_use.sh
chmod +x ~/.claude/hooks/pre_tool_use.sh
```

2. Add to `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/pre_tool_use.sh"
          }
        ]
      }
    ]
  }
}
```

3. Optionally set environment variables:
```bash
export SNAPPER_URL=http://localhost:8000
export SNAPPER_AGENT_ID=claude-code-$(hostname)
```
</details>

## Features

### Rule Types

| Rule Type | Description |
|-----------|-------------|
| **Command Allowlist** | Only allow specific shell commands |
| **Command Denylist** | Block dangerous commands (rm -rf, etc.) |
| **Credential Protection** | Block access to .env, .pem, SSH keys |
| **Rate Limiting** | Prevent runaway agents |
| **Time Restrictions** | Only allow operations during work hours |
| **Skill Allow/Deny** | Control which MCP tools can be used |
| **Network Egress** | Control outbound network access |
| **Human-in-Loop** | Require approval for sensitive actions (via Telegram/Slack) |

### Security

- **Deny-by-default** — Nothing is allowed unless explicitly permitted
- **Origin validation** — Prevents WebSocket hijacking (CVE-2026-25253)
- **Rate limiting** — Sliding window algorithm with circuit breaker
- **Audit logging** — Every action is logged for review

### Telegram Bot

Control Snapper from your phone with the Telegram bot:

**Commands:**
- `/test run <command>` — Test if a command would be allowed
- `/rules` — View active security rules
- `/pending` — List pending approvals
- `/block` — Emergency block ALL agent actions
- `/unblock` — Resume normal operation

**Quick actions:** When a test is blocked, tap inline buttons to:
- **Allow Once** — One-time pass (no rule created)
- **Allow Always** — Create a persistent allow rule
- **View Rule** — See rule details

See [Telegram Setup Guide](docs/TELEGRAM_SETUP.md) for configuration.

### Notifications & Approvals

Get alerts and approve/deny requests from your phone:

- **Telegram** — Test rules, manage approvals, emergency controls
- **Slack** — Webhook notifications
- **Email** — SMTP alerts
- **PagerDuty** — Critical incidents
- **Webhooks** — Custom integrations

## Dashboard

| Page | Description |
|------|-------------|
| **Dashboard** | Overview, security score, quick actions |
| **Agents** | Connect and manage AI assistants |
| **Rules** | Create and manage security rules |
| **Security** | Vulnerability tracking, threat feed |
| **Audit** | Review all agent actions |
| **Integrations** | Configure Slack, GitHub, and more |
| **Settings** | Configure alerts and notifications |

## API

Swagger docs at `/api/docs`. Key endpoints:

```
GET    /api/v1/agents          # List agents
POST   /api/v1/rules           # Create a rule
POST   /api/v1/rules/evaluate  # Evaluate a request (used by hooks)
GET    /api/v1/audit/logs      # Get audit logs
GET    /health                 # Health check
GET    /health/ready           # Readiness check (DB + Redis)
```

## Configuration

All settings are environment variables. Copy `.env.example` to `.env` to customize.

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *required* | Session signing key (`openssl rand -hex 32`) |
| `DENY_BY_DEFAULT` | `true` | Deny unknown requests (fail-safe) |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,app` | Accepted Host headers |
| `ALLOWED_ORIGINS` | `http://localhost:8000` | CORS/WebSocket origins |
| `REQUIRE_LOCALHOST_ONLY` | `false` | Reject non-localhost requests |
| `DEBUG` | `true` | Debug mode (set `false` in production) |

See `.env.example` for the full list including database, Redis, Celery, alerting, and notification settings.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Assistant  │────▶│  PreToolUse     │────▶│    Snapper      │
│  (Claude Code)  │     │  Hook           │     │  Rule Engine    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                                ┌─────────────────┐
                                                │   Allow / Deny  │
                                                │ / Ask Approval  │
                                                └─────────────────┘
```

**Stack:** FastAPI, PostgreSQL, Redis, Celery, Gunicorn, Docker Compose.

**Containers (5):** app, postgres, redis, celery-worker, celery-beat.

## Common Commands

```bash
# Logs
docker compose logs -f app

# Stop
docker compose down

# Restart
docker compose restart

# Reset database
docker compose down -v && docker compose up -d

# Run migrations
docker compose exec app alembic upgrade head

# Run tests
docker compose exec app python -m pytest tests/ -v
```

For production, prefix with `-f docker-compose.yml -f docker-compose.prod.yml`.

## Troubleshooting

**"Connection refused" on port 8000** — Services may still be starting. Wait 30 seconds, then check `docker compose logs app`.

**403 on dashboard** — Your server's IP/hostname isn't in `ALLOWED_HOSTS`. Add it to `.env`.

**Rate limit errors (429)** — You're hitting the rate limiter. Wait a few seconds or adjust limits in Settings.

**Agent not connecting** — Verify the agent is registered, check `SNAPPER_URL`, and ensure the agent ID matches.

## License

MIT License — see LICENSE file for details.

## Support

- **Issues**: https://github.com/jmckinley/snapper/issues
- **Discussions**: https://github.com/jmckinley/snapper/discussions
