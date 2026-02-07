# OpenClaw Integration Guide

Complete guide for integrating Snapper with OpenClaw AI assistant.

## Overview

Snapper acts as a security gateway for OpenClaw, validating tool calls and shell commands before execution. Two integration methods are available:

| Method | Intercepts | Can Modify Tool Input | PII Vault Support |
|--------|-----------|----------------------|-------------------|
| **snapper-guard plugin** (recommended) | All tool calls (browser, exec, etc.) | Yes | Full (token replacement in form fields) |
| **Shell hook** | Shell commands only | No | Partial (stdout only) |

### Plugin Flow (recommended)

```
OpenClaw Agent
      │
      ▼ (before_tool_call hook)
snapper-guard plugin
      │
      ▼
Snapper API (/api/v1/rules/evaluate)
      │
      ├── allow + resolved_data → replace vault tokens in params → execute
      ├── require_approval → poll for decision → replace tokens → execute
      └── deny → block tool call with error
```

### Shell Hook Flow (legacy)

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

## Plugin Setup (Recommended)

The snapper-guard plugin intercepts all tool calls natively through OpenClaw's plugin API. This is required for PII vault token resolution in browser form fills.

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

### 2. Install the Plugin

```bash
# Copy plugin files to OpenClaw's extensions directory
cp -r /opt/snapper/plugins/snapper-guard ~/.openclaw/extensions/snapper-guard
```

### 3. Configure the Plugin

Add to your OpenClaw config (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "snapper-guard": {
        "enabled": true,
        "config": {
          "snapperUrl": "http://127.0.0.1:8000",
          "agentId": "openclaw-main",
          "apiKey": "snp_your_key_here",
          "approvalTimeoutMs": 300000,
          "pollIntervalMs": 5000
        }
      }
    }
  }
}
```

| Config | Default | Description |
|--------|---------|-------------|
| `snapperUrl` | `http://127.0.0.1:8000` | Snapper API URL |
| `agentId` | `openclaw-main` | Agent external_id in Snapper |
| `apiKey` | — | Snapper API key (`snp_...`) |
| `approvalTimeoutMs` | `300000` | Max wait for human approval (5 min) |
| `pollIntervalMs` | `5000` | Approval status poll interval |

### 4. Restart OpenClaw

```bash
cd /opt/openclaw && docker compose restart openclaw-gateway
```

### 5. Verify Plugin Loaded

```bash
docker compose logs openclaw-gateway | grep snapper-guard
# Should show: snapper-guard: registered (snapper=http://127.0.0.1:8000, agent=openclaw-main)
```

### PII Vault Token Flow

1. User stores PII via Telegram `/vault add "My Visa" credit_card`
2. Snapper returns a token: `{{SNAPPER_VAULT:a7f3b2c1}}`
3. User tells OpenClaw: "Fill in my credit card using `{{SNAPPER_VAULT:a7f3b2c1}}`"
4. OpenClaw calls `browser fill` with the token in a field value
5. snapper-guard plugin intercepts → calls Snapper evaluate
6. PII gate detects the vault token → requires approval (or auto-resolves)
7. After approval, Snapper returns `resolved_data` with decrypted value
8. Plugin replaces the token in the browser params with the real card number
9. Browser fills the form field with the actual value

---

## Gateway Listener (Alternative)

The gateway listener connects directly to OpenClaw's WebSocket gateway and intercepts `exec.approval.requested` events in real-time. It evaluates commands against Snapper rules and auto-approves, auto-denies, or leaves them pending for manual Telegram approval.

**When to use:** You want real-time command interception without modifying OpenClaw's shell or installing a plugin. The listener runs as a standalone systemd service alongside your OpenClaw stack.

```
OpenClaw Gateway (WebSocket :18789)
        │
        ▼ exec.approval.requested
snapper-approval-listener.js
        │
        ▼
Snapper API (/api/v1/rules/evaluate)
        │
        ├── allow → auto-resolve (allow-once)
        ├── deny → auto-resolve (deny)
        └── require_approval → leave pending for Telegram
```

### 1. Copy Listener Files

```bash
cp -r /opt/snapper/scripts/snapper-gate ~/.openclaw/hooks/snapper-gate
cd ~/.openclaw/hooks/snapper-gate
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Fill in the required values:

| Variable | Required | Source |
|----------|----------|--------|
| `OPENCLAW_GATEWAY_TOKEN` | Yes | `grep OPENCLAW_GATEWAY_TOKEN /opt/openclaw/.env` |
| `SNAPPER_API_KEY` | Yes | From Snapper agent registration (`snp_xxx`) |
| `SNAPPER_URL` | Yes | Default: `http://127.0.0.1:8000` |
| `SNAPPER_AGENT_ID` | No | Default: `openclaw-main` |
| `OPENCLAW_GATEWAY_URL` | No | Default: `ws://127.0.0.1:18789` |

### 3. Install Dependencies

```bash
npm install
```

### 4. Install Systemd Service

```bash
cp snapper-listener.service /etc/systemd/system/
# Edit WorkingDirectory if you used a different path:
#   sed -i 's|/root/.openclaw/hooks/snapper-gate|/your/path|g' /etc/systemd/system/snapper-listener.service
systemctl daemon-reload
systemctl enable --now snapper-listener
```

### 5. Verify

```bash
journalctl -u snapper-listener -f
# Should show: "Gateway connect acknowledged" and then event handling
```

### Auth Failure Protection

If the gateway token is missing or wrong, the listener uses exponential backoff (5s → 10s → 20s → 40s → 60s) and exits after 5 consecutive auth failures with clear fix instructions. The `start.sh` wrapper also validates required env vars before launching Node, so a missing token won't even start the reconnect loop.

---

## Shell Hook Setup (Legacy)

The shell hook method intercepts shell commands only. Use this if you don't need browser/PII features.

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

### Telegram notifications not appearing

1. Check `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set:
   ```bash
   docker exec snapper-celery-worker-1 env | grep TELEGRAM
   ```

2. Verify celery-worker has the env vars (check docker-compose.yml):
   ```yaml
   celery-worker:
     environment:
       - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN:-}
       - TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID:-}
   ```

3. Check celery logs for notification errors:
   ```bash
   docker compose logs celery-worker --tail 50 | grep -i telegram
   ```

4. Restart with `--force-recreate` to pick up env changes.

### rclone/sync permissions

If sync commands fail with "read-only file system":

1. Check volume mounts aren't `:ro`:
   ```bash
   grep rclone docker-compose.yml
   # Should NOT have :ro at the end
   ```

2. Fix ownership on host:
   ```bash
   chown -R 1000:1000 /opt/openclaw/rclone-mount
   ```

3. Recreate containers:
   ```bash
   docker compose up -d --force-recreate
   ```

### Sync filter excluding files

If files aren't syncing, check the filter file:
```bash
cat /opt/openclaw/rclone-mount/gdrive-sync-filters.txt
```

Add `+ *.md` or other patterns as needed. The `- *` at the end excludes everything not explicitly included.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          VPS Server                              │
│  ┌──────────────────────────┐    ┌────────────────────────────┐ │
│  │      OpenClaw Stack      │    │      Snapper Stack         │ │
│  │  ┌────────────────────┐  │    │  ┌──────────────────────┐  │ │
│  │  │  openclaw-gateway  │  │    │  │    snapper-app       │  │ │
│  │  │                    │  │    │  │    (FastAPI)         │  │ │
│  │  │  snapper-guard     │─────────▶ POST /rules/evaluate  │  │ │
│  │  │  plugin (native)   │  │    │  │                      │  │ │
│  │  │                    │  │    │  │  PII Vault (AES)     │  │ │
│  │  │  SHELL=snapper-    │─────────▶ (shell hook fallback) │  │ │
│  │  │    shell.sh        │  │    │  └──────────────────────┘  │ │
│  │  └────────────────────┘  │    │            │               │ │
│  │           │              │    │            ▼               │ │
│  │           ▼              │    │    ┌──────────────┐        │ │
│  │    Telegram Bot          │    │    │  PostgreSQL  │        │ │
│  │    @redfuzzydog_bot      │    │    │  + Redis     │        │ │
│  └──────────────────────────┘    │    └──────────────┘        │ │
│                                  │            │               │ │
│                                  │            ▼               │ │
│                                  │    Telegram Bot            │ │
│                                  │    @Snapper_approval_bot   │ │
│                                  └────────────────────────────┘ │
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

### Evaluate Browser Action (with PII)

```http
POST /api/v1/rules/evaluate
Content-Type: application/json
X-API-Key: snp_xxx

{
  "agent_id": "openclaw-main",
  "request_type": "browser_action",
  "tool_name": "browser",
  "tool_input": {
    "action": "fill",
    "fields": [{"ref": "15", "value": "{{SNAPPER_VAULT:a7f3b2c1}}"}],
    "url": "https://expedia.com/checkout"
  }
}
```

Response (protected mode):
```json
{
  "decision": "require_approval",
  "reason": "Requires approval: PII Gate Protection",
  "matched_rule_id": "uuid",
  "matched_rule_name": "PII Gate Protection",
  "approval_request_id": "uuid",
  "approval_timeout_seconds": 300
}
```

Response (auto mode with resolved tokens):
```json
{
  "decision": "allow",
  "reason": "Allowed by matching rules",
  "resolved_data": {
    "{{SNAPPER_VAULT:a7f3b2c1}}": {
      "value": "4111111111111234",
      "category": "credit_card",
      "label": "My Visa",
      "masked_value": "****-****-****-1234"
    }
  }
}
```

### Response Decisions

| Decision | Description |
|----------|-------------|
| `allow` | Request permitted. May include `resolved_data` with decrypted vault tokens. |
| `deny` | Request blocked. `reason` explains why. |
| `require_approval` | Waiting for human. `approval_request_id` used to poll status. |
