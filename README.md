# Snapper

**Security rules manager for AI agents** - Give yourself fine-grained control over what AI assistants can do.

![Snapper Dashboard](https://img.shields.io/badge/status-beta-yellow) ![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue) ![License](https://img.shields.io/badge/license-MIT-green)

## What is Snapper?

Snapper sits between your AI coding assistants (OpenClaw, Claude Code, Cursor, GitHub Copilot) and the actions they take. It lets you:

- **Allow** specific commands, tools, or integrations
- **Deny** dangerous operations (like `rm -rf /` or accessing `.env` files)
- **Require approval** for sensitive actions before they execute

Think of it as a firewall for AI agents.

## For OpenClaw Users

**One command. That's it.**

```bash
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/quick-setup.sh | bash
```

This automatically:
- Installs and starts Snapper
- Registers your OpenClaw instance
- Applies recommended security rules
- Installs the PreToolUse hook

Your OpenClaw is protected against CVE-2026-25253, credential exposure, and malicious skills.

**Options:**
```bash
# Strict mode (requires approval for sensitive actions)
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/quick-setup.sh | bash -s -- --strict

# Permissive mode (logging only, no blocking)
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/quick-setup.sh | bash -s -- --permissive
```

## For Claude Code Users

**One command. That's it.**

```bash
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/claude-code-setup.sh | bash
```

This automatically:
- Installs and starts Snapper
- Registers your Claude Code instance
- Applies recommended security rules
- Installs the PreToolUse hook in `~/.claude/hooks/`
- Updates your `~/.claude/settings.json`

**Note:** Restart Claude Code after setup for hooks to take effect.

**Options:**
```bash
# Strict mode (requires approval for sensitive actions)
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/claude-code-setup.sh | bash -s -- --strict

# Permissive mode (logging only, no blocking)
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/claude-code-setup.sh | bash -s -- --permissive
```

## Quick Start (General)

### One-Command Install

```bash
curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/install.sh | bash
```

This will:
1. Check for Docker & Docker Compose
2. Pull and start all services
3. Apply default security rules
4. Open the dashboard at http://localhost:8000

### Manual Install

```bash
# Clone the repository
git clone https://github.com/jmckinley/snapper.git
cd snapper

# Start services
docker compose up -d

# Open dashboard
open http://localhost:8000
```

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

### Integrations

Snapper works with any MCP-compatible AI assistant:

- **OpenClaw** - Full integration with setup wizard
- **Claude Code** - Via MCP server configuration
- **Cursor** - Via MCP server configuration
- **GitHub Copilot** - Via custom integration
- **Custom MCP Servers** - Build your own

### Security Features

- **Deny-by-default** - Nothing is allowed unless explicitly permitted
- **Origin validation** - Prevents WebSocket hijacking (CVE-2026-25253)
- **Rate limiting** - Sliding window algorithm with circuit breaker
- **Audit logging** - Every action is logged for review

### Notifications & Approvals

Get alerts and approve/deny requests from your phone:

- **Telegram** - Popular with OpenClaw users, with inline approve/deny buttons
- **Slack** - Webhook notifications
- **Email** - SMTP alerts
- **PagerDuty** - For critical incidents
- **Webhooks** - Custom integrations

**Telegram Quick Setup:**
1. Message [@BotFather](https://t.me/BotFather) to create a bot
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Add to `.env`: `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`

## Dashboard

Access the dashboard at http://localhost:8000 after installation.

| Page | Description |
|------|-------------|
| **Dashboard** | Overview, security score, quick actions |
| **Agents** | Connect and manage AI assistants |
| **Integrations** | Configure Slack, GitHub, and more |
| **Rules** | Create and manage security rules |
| **Security** | Vulnerability tracking, threat feed |
| **Audit** | Review all agent actions |
| **Settings** | Configure alerts and notifications |

## API

Full REST API available at http://localhost:8000/api/docs

### Key Endpoints

```bash
# List agents
GET /api/v1/agents

# Create a rule
POST /api/v1/rules

# Evaluate a request (used by MCP servers)
POST /api/v1/rules/evaluate

# Get audit logs
GET /api/v1/audit/logs
```

## Configuration

Environment variables (set in `.env`):

```bash
# Security (required)
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=postgresql+asyncpg://snapper:snapper@postgres:5432/snapper

# Redis
REDIS_URL=redis://redis:6379/0

# Security settings
DENY_BY_DEFAULT=true          # Fail-safe: deny unknown requests
VALIDATE_WEBSOCKET_ORIGIN=true # CVE-2026-25253 mitigation

# Optional
DEBUG=false
LOG_LEVEL=INFO
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Assistant  │────▶│  MCP Server     │────▶│    Snapper      │
│  (Claude Code)  │     │  (Slack, etc.)  │     │  Rule Engine    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                        │
                                                        ▼
                                               ┌─────────────────┐
                                               │   Allow/Deny/   │
                                               │ Require Approval│
                                               └─────────────────┘
```

## Development

```bash
# Run locally (without Docker)
pip install -r requirements.txt
uvicorn app.main:app --reload

# Run tests
docker compose exec app python -m pytest tests/ -v

# Database migrations
docker compose exec app alembic upgrade head
```

## Commands

```bash
# View logs
docker compose logs -f app

# Stop services
docker compose down

# Restart
docker compose restart

# Reset database
docker compose down -v && docker compose up -d
```

## Troubleshooting

### "Connection refused" on port 8000
Services may still be starting. Wait 30 seconds and try again, or check:
```bash
docker compose logs app
```

### Rate limit errors (429)
You're hitting the rate limiter. Wait a few seconds or adjust limits in Settings.

### Agent not connecting
1. Verify the agent is registered in Snapper
2. Check the agent's `SNAPPER_URL` environment variable
3. Ensure the agent ID matches

## Contributing

Contributions welcome! Please read our contributing guidelines first.

## License

MIT License - see LICENSE file for details.

## Support

- **Issues**: https://github.com/jmckinley/snapper/issues
- **Discussions**: https://github.com/jmckinley/snapper/discussions
