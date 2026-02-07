# Getting Started with Snapper

Snapper is a security rules manager for OpenClaw. It controls what your AI agent
can do — allow, deny, or require approval for commands, file access, network calls,
and PII handling.

## What You Need

- **Docker 24.0+** with Compose v2 — check: `docker compose version`
- **Git** — check: `git --version`
- **OpenClaw running in Docker** on the same machine or network

## Install (2 minutes)

```bash
git clone https://github.com/jmckinley/snapper.git
cd snapper
docker compose up -d
```

Wait for all containers to start (~30 seconds), then open http://localhost:8000.

For production deployment on an Ubuntu VPS, see [Installation Guide](INSTALL.md#production-deployment-ubuntu-vps).

## Setup Wizard (3 minutes)

On first visit, Snapper automatically redirects you to the **setup wizard**. It walks through four steps:

1. **Register your OpenClaw agent** — Give it a name and agent ID (e.g., `openclaw-main`). You'll get an API key (`snp_xxx`).

2. **Pick a security profile** — Choose one:
   - **Recommended** — Blocks dangerous commands, requires approval for sensitive ones, allows common safe commands
   - **Strict** — Deny by default, explicit allowlist only
   - **Permissive** — Learning mode, logs everything but blocks nothing (good for initial setup)

3. **Set up Telegram notifications** (optional) — Enter your bot token and chat ID. Snapper will send you approval requests and blocked-command alerts on your phone.

4. **Get your config snippet** — Copy the generated JSON and paste it into your OpenClaw config to connect the agent.

After the wizard, your agent is protected and rules are applied.

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

## What's Next

- [Telegram Setup](TELEGRAM_SETUP.md) — Approval notifications on your phone
- [OpenClaw Integration Guide](OPENCLAW_INTEGRATION.md) — Plugin vs shell hook details
- [User Guide](USER_GUIDE.md) — Rules, PII vault, approval workflows
- [API Reference](http://localhost:8000/api/docs) — Interactive REST API docs
- [Installation Guide](INSTALL.md) — Production deployment, environment variables, troubleshooting
