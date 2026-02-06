# OpenClaw Integration Guide

Complete guide for integrating Snapper with OpenClaw AI assistant.

## Overview

Snapper acts as a security gateway for OpenClaw, validating every shell command before execution. When OpenClaw tries to run a command:

1. The shell wrapper intercepts the command
2. Snapper evaluates it against security rules
3. Command is allowed, denied, or held for approval

```
OpenClaw Agent
      │
      ▼
SHELL=/app/hooks/snapper-shell.sh
      │
      ▼
Snapper API (/api/v1/rules/evaluate)
      │
      ├── allow → execute command
      ├── deny → block with error
      └── require_approval → wait for human
```

## Quick Setup (VPS with Both Services)

If Snapper and OpenClaw are on the same server:

### 1. Register OpenClaw Agent

```bash
curl -X POST http://localhost:8000/api/v1/agents \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OpenClaw",
    "external_id": "openclaw-main",
    "description": "OpenClaw AI assistant",
    "trust_level": "standard"
  }'
```

Save the returned `api_key` (starts with `snp_`).

### 2. Create Shell Wrapper

Create `/opt/openclaw/hooks/snapper-shell.sh`:

```bash
#!/bin/bash
# Snapper Shell Wrapper for OpenClaw
REAL_SHELL="/bin/bash"

# If interactive or no args, just run shell
[ -t 0 ] && [ $# -eq 0 ] && exec $REAL_SHELL

# Get command
[ "$1" = "-c" ] && CMD="$2" || CMD="$*"
[ -z "$CMD" ] && exec $REAL_SHELL "$@"

# Call Snapper
RESP=$(curl -sf -X POST "http://host.docker.internal:8000/api/v1/rules/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -d "{\"agent_id\": \"openclaw-main\", \"request_type\": \"command\", \"command\": \"$CMD\"}" 2>/dev/null)

# Check decision
if echo "$RESP" | grep -q '"decision":"deny"'; then
  REASON=$(echo "$RESP" | sed 's/.*"reason":"\([^"]*\)".*/\1/')
  echo "BLOCKED by Snapper: $REASON" >&2
  exit 1
fi

if echo "$RESP" | grep -q '"decision":"require_approval"'; then
  echo "Approval required - check Telegram" >&2
  exit 1
fi

# Execute
exec $REAL_SHELL "$@"
```

Make executable:
```bash
chmod +x /opt/openclaw/hooks/snapper-shell.sh
```

### 3. Mount Hook in OpenClaw Container

Add to OpenClaw's `docker-compose.yml`:

```yaml
services:
  openclaw-gateway:
    volumes:
      - ./hooks:/app/hooks:ro
    environment:
      SHELL: /app/hooks/snapper-shell.sh
```

### 4. Add host.docker.internal

Ensure OpenClaw can reach Snapper:

```yaml
services:
  openclaw-gateway:
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

### 5. Restart OpenClaw

```bash
docker compose up -d --force-recreate openclaw-gateway
```

### 6. Verify

Test from inside the container:

```bash
# Should work
docker compose exec openclaw-gateway /app/hooks/snapper-shell.sh -c "ls /tmp"

# Should be blocked
docker compose exec openclaw-gateway /app/hooks/snapper-shell.sh -c "rm -rf /"
```

## Remote Setup (Separate Servers)

If OpenClaw and Snapper are on different machines:

### 1. Configure Network Access

On Snapper server, ensure the API is accessible:

```bash
# In .env
ALLOWED_HOSTS=localhost,127.0.0.1,openclaw-server-ip
ALLOWED_ORIGINS=https://openclaw-server-ip
```

### 2. Update Shell Wrapper

Change the Snapper URL to the remote server:

```bash
RESP=$(curl -sf -X POST "https://snapper-server-ip:8443/api/v1/rules/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY_HERE" \
  -k \  # Skip TLS verification for self-signed certs
  -d "{...}" 2>/dev/null)
```

### 3. Consider Timeout Handling

For remote connections, add timeout handling:

```bash
RESP=$(curl -sf --connect-timeout 5 --max-time 10 \
  -X POST "https://snapper-server:8443/api/v1/rules/evaluate" \
  ...)

# Fail closed if Snapper unreachable
if [ -z "$RESP" ]; then
  echo "BLOCKED: Snapper unreachable" >&2
  exit 1
fi
```

## Security Rules for OpenClaw

### Recommended Starting Rules

Create these rules for a secure OpenClaw deployment:

```bash
# Block dangerous commands
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block Dangerous Commands",
    "rule_type": "command_denylist",
    "action": "deny",
    "priority": 100,
    "parameters": {
      "patterns": [
        "^rm\\s+-rf\\s+/",
        "^dd\\s+if=",
        "^mkfs\\.",
        "^chmod\\s+-R\\s+777",
        ":(\\(\\)\\{.*:\\|:&\\s*\\}\\s*;\\s*:)"
      ]
    }
  }'

# Allow safe read commands
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Allow Safe Commands",
    "rule_type": "command_allowlist",
    "action": "allow",
    "priority": 50,
    "parameters": {
      "patterns": [
        "^(ls|cat|head|tail|grep|find|pwd|whoami|date|uname|echo|env)\\b",
        "^git\\s+(status|log|diff|branch|show)",
        "^docker\\s+(ps|logs|images)"
      ]
    }
  }'

# Require approval for installs
curl -X POST http://localhost:8000/api/v1/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Require Approval for Installs",
    "rule_type": "command_allowlist",
    "action": "require_approval",
    "priority": 75,
    "parameters": {
      "patterns": [
        "^(npm|pip|apt|brew|cargo)\\s+install",
        "^curl.*\\|.*sh",
        "^wget.*&&.*sh"
      ]
    }
  }'
```

### Enable Enforcement Mode

Once rules are configured, disable learning mode:

```bash
# In Snapper's .env
LEARNING_MODE=false
DENY_BY_DEFAULT=true
```

Restart Snapper:
```bash
docker compose up -d --force-recreate app celery-worker celery-beat
```

## Telegram Notifications

Configure Snapper's Telegram bot to receive approval requests:

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Add to Snapper's `.env`:
   ```bash
   TELEGRAM_BOT_TOKEN=your_bot_token
   TELEGRAM_CHAT_ID=your_chat_id
   ```
4. Restart Snapper

When OpenClaw triggers a `require_approval` rule, you'll receive a Telegram message with approve/deny buttons.

## Monitoring

### Check Audit Logs

View all OpenClaw decisions:

```bash
curl "http://localhost:8000/api/v1/audit/logs?agent_id=openclaw-main"
```

### Dashboard

Access the Snapper dashboard to see:
- Real-time command evaluations
- Blocked actions
- Pending approvals
- Agent activity

## Troubleshooting

### Commands not being intercepted

Verify SHELL is set in the container:
```bash
docker compose exec openclaw-gateway sh -c 'echo $SHELL'
# Should output: /app/hooks/snapper-shell.sh
```

### "BLOCKED: Snapper unreachable"

1. Check Snapper is running:
   ```bash
   curl http://localhost:8000/health
   ```

2. Verify network connectivity from OpenClaw container:
   ```bash
   docker compose exec openclaw-gateway curl http://host.docker.internal:8000/health
   ```

3. Check `extra_hosts` is configured in docker-compose.yml

### All commands blocked

1. Check if learning mode is on:
   ```bash
   docker exec snapper-app-1 env | grep LEARNING
   ```

2. Verify rules exist:
   ```bash
   curl http://localhost:8000/api/v1/rules
   ```

3. Test evaluate directly:
   ```bash
   curl -X POST http://localhost:8000/api/v1/rules/evaluate \
     -H "Content-Type: application/json" \
     -d '{"agent_id": "openclaw-main", "request_type": "command", "command": "ls"}'
   ```

### API key issues

If you get 401 errors, verify:
1. API key is correct in the shell wrapper
2. `REQUIRE_API_KEY` setting in Snapper matches your setup

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        VPS Server                                │
│  ┌─────────────────────────┐    ┌─────────────────────────────┐ │
│  │     OpenClaw Stack      │    │      Snapper Stack          │ │
│  │  ┌───────────────────┐  │    │  ┌───────────────────────┐  │ │
│  │  │  openclaw-gateway │  │    │  │    snapper-app        │  │ │
│  │  │                   │  │    │  │    (FastAPI)          │  │ │
│  │  │  SHELL=snapper-   │──────────▶  POST /rules/evaluate │  │ │
│  │  │    shell.sh       │  │    │  │                       │  │ │
│  │  └───────────────────┘  │    │  └───────────────────────┘  │ │
│  │           │             │    │            │                │ │
│  │           ▼             │    │            ▼                │ │
│  │    Telegram Bot         │    │    ┌───────────────┐        │ │
│  │    @redfuzzydog_bot     │    │    │   PostgreSQL  │        │ │
│  │                         │    │    │   + Redis     │        │ │
│  └─────────────────────────┘    │    └───────────────┘        │ │
│                                 │            │                │ │
│                                 │            ▼                │ │
│                                 │    Telegram Bot             │ │
│                                 │    @Snapper_approval_bot    │ │
│                                 └─────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## API Reference

### Evaluate Command

```http
POST /api/v1/rules/evaluate
Content-Type: application/json
X-API-Key: snp_xxx (optional)

{
  "agent_id": "openclaw-main",
  "request_type": "command",
  "command": "ls -la /tmp"
}
```

Response:
```json
{
  "decision": "allow",
  "reason": "Allowed by matching rules",
  "matched_rule_id": null,
  "matched_rule_name": null
}
```

Or when blocked:
```json
{
  "decision": "deny",
  "reason": "Denied by rule: Block Dangerous Commands",
  "matched_rule_id": "uuid",
  "matched_rule_name": "Block Dangerous Commands"
}
```
