# Snapper Hook for Claude Code

Integrates [Claude Code](https://claude.ai/claude-code) with Snapper's Agent Application Firewall. Every tool call (Bash, Read, Write, WebFetch, etc.) is checked against Snapper's rule engine before execution.

## Quick Setup

```bash
bash scripts/claude-code-setup.sh
```

## Manual Setup

1. Copy the hook:

```bash
mkdir -p ~/.claude/hooks
cp plugins/claude-code/snapper_hook.sh ~/.claude/hooks/pre_tool_use.sh
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

3. Set environment variables (in your shell profile):

```bash
export SNAPPER_URL="http://localhost:8000"       # Snapper API URL
export SNAPPER_AGENT_ID="claude-code-$(hostname)" # Agent ID registered in Snapper
export SNAPPER_API_KEY="snp_xxx"                  # Agent API key (from Snapper dashboard)
export SNAPPER_FAIL_MODE="closed"                 # "closed" (deny on error) or "open" (allow on error)
export SNAPPER_APPROVAL_TIMEOUT="300"             # Seconds to wait for approval (default: 300)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SNAPPER_URL` | `http://localhost:8000` | Snapper API base URL |
| `SNAPPER_AGENT_ID` | `claude-code-$(hostname)` | Agent identifier (must exist in Snapper) |
| `SNAPPER_API_KEY` | (none) | API key for authenticated requests |
| `SNAPPER_FAIL_MODE` | `closed` | Behavior when Snapper is unreachable: `closed` = block, `open` = allow |
| `SNAPPER_APPROVAL_TIMEOUT` | `300` | Max seconds to wait for human approval |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Tool allowed |
| `2` | Tool blocked (Claude Code shows the reason) |
| `1` | Non-blocking error (tool still proceeds) |

## Tool Mapping

| Claude Code Tool | Snapper request_type | Key Fields |
|------------------|---------------------|------------|
| Bash | `command` | `command` |
| Read | `file_access` | `file_path`, `file_operation=read` |
| Write, Edit, NotebookEdit | `file_access` | `file_path`, `file_operation=write` |
| WebFetch | `network` | `url` |
| WebSearch | `network` | — |
| Grep, Glob, LSP | `file_access` | `path`, `file_operation=read` |
| Task, Skill | `tool` | `tool_name` |

## Security Profiles

### Strict (recommended for production)

- `SNAPPER_FAIL_MODE=closed`
- Rules: command_allowlist (explicit allow), credential_protection, network_egress, pii_gate
- All unmatched requests denied

### Recommended (balanced)

- `SNAPPER_FAIL_MODE=closed`
- Rules: command_denylist (block dangerous), credential_protection, network_egress
- Unmatched requests allowed if deny-by-default is off

### Permissive (development)

- `SNAPPER_FAIL_MODE=open`
- Rules: credential_protection only
- Most requests pass through; credentials still protected

## Testing

```bash
# Run hook E2E tests (requires Snapper running)
SNAPPER_URL=http://localhost:8000 bash scripts/e2e_claude_code_test.sh
```
