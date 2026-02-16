# AI Provider Integration Guide

Snapper protects AI applications through two mechanisms:

1. **Python SDK wrappers** — For applications using OpenAI, Anthropic, or Gemini APIs
2. **Browser extension** — For employees using ChatGPT, Claude.ai, or Gemini web UIs

## Overview

| Method | Use Case | How It Works |
|--------|----------|-------------|
| SDK Wrapper | Your app calls AI APIs | Drop-in replacement intercepts tool calls |
| Browser Extension | Employees chat in browser | Content scripts intercept tool execution |

---

## Python SDK

Install the Snapper SDK:

```bash
pip install snapper-sdk[openai]     # OpenAI
pip install snapper-sdk[anthropic]  # Anthropic
pip install snapper-sdk[gemini]     # Gemini
pip install snapper-sdk[all]        # All providers
```

### OpenAI Setup

```python
# Before (unprotected):
from openai import OpenAI
client = OpenAI()

# After (Snapper-protected):
from snapper.openai_wrapper import SnapperOpenAI

client = SnapperOpenAI(
    snapper_url="https://snapper.example.com",
    snapper_api_key="snp_xxx",
    agent_id="myapp-openai",
)

# Use exactly like openai.OpenAI — tool calls are automatically evaluated
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "What's the weather in NYC?"}],
    tools=[{
        "type": "function",
        "function": {
            "name": "get_weather",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
        },
    }],
)
```

**What happens:**
- `client.chat.completions.create()` works normally
- When the response contains `tool_calls`, each one is sent to Snapper's evaluate endpoint
- Allowed calls pass through unchanged
- Denied calls raise `SnapperDenied` (or are silently filtered in `filter` mode)

### Anthropic Setup

```python
from snapper.anthropic_wrapper import SnapperAnthropic

client = SnapperAnthropic(
    snapper_url="https://snapper.example.com",
    snapper_api_key="snp_xxx",
    agent_id="myapp-anthropic",
)

response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Search for recent news"}],
    tools=[{
        "name": "web_search",
        "description": "Search the web",
        "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}},
    }],
)
```

**What happens:**
- `tool_use` content blocks in the response are evaluated against Snapper policy
- Same deny/allow/approval behavior as OpenAI wrapper

### Gemini Setup

```python
from snapper.gemini_wrapper import SnapperGemini

model = SnapperGemini(
    model_name="gemini-pro",
    snapper_url="https://snapper.example.com",
    snapper_api_key="snp_xxx",
    agent_id="myapp-gemini",
)

response = model.generate_content(
    "What's the weather?",
    tools=[...],
)
```

**What happens:**
- `function_call` parts in the response are evaluated
- Also works with `model.start_chat()` sessions

### Configuration

All wrappers accept these parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `snapper_url` | `$SNAPPER_URL` | Snapper server URL |
| `snapper_api_key` | `$SNAPPER_API_KEY` | API key for authentication |
| `agent_id` | `$SNAPPER_AGENT_ID` | Agent ID registered in Snapper |
| `on_deny` | `"raise"` | `"raise"` to throw exception, `"filter"` to silently remove |
| `snapper_fail_mode` | `"closed"` | `"closed"` blocks on error, `"open"` allows |

Environment variables are used as fallbacks when parameters are not provided.

### Error Handling

```python
from snapper.base import SnapperDenied, SnapperApprovalTimeout

try:
    response = client.chat.completions.create(...)
except SnapperDenied as e:
    print(f"Blocked: {e.reason}")
    print(f"Rule: {e.rule_name}")
except SnapperApprovalTimeout as e:
    print(f"Approval timed out after {e.timeout}s")
```

### Using with PII Vault

Vault tokens work automatically with SDK wrappers:

```python
# In your tool implementation, use vault tokens instead of raw PII:
tool_input = {
    "email": "{{SNAPPER_VAULT:abcdef0123456789abcdef0123456789}}",
    "message": "Hello {{SNAPPER_VAULT:fedcba9876543210fedcba9876543210}}",
}

# When Snapper evaluates and approves, resolved_data contains decrypted values
result = snapper_client.evaluate(
    tool_name="send_email",
    tool_input=tool_input,
)
if "resolved_data" in result:
    # Use resolved values for the actual API call
    actual_email = result["resolved_data"]["abcdef0123456789abcdef0123456789"]
```

---

## Browser Extension

The Snapper browser extension intercepts AI tool execution in ChatGPT, Claude.ai, and Gemini web UIs.

### Installation

**Chrome:**
1. Download the extension from Releases or build from `extension/`
2. Go to `chrome://extensions` > Enable Developer Mode
3. Click "Load unpacked" and select the `extension/` directory

**Firefox:**
1. Go to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on" and select `extension/manifest.json`

### Configuration

Click the Snapper extension icon > Settings:

- **Snapper URL** — Your Snapper server address
- **API Key** — Agent API key
- **Agent ID** — Registered agent ID (default: `browser-extension`)
- **Fail Mode** — `closed` (block when unreachable) or `open`

### What Gets Intercepted

| AI Service | Action | Snapper Request Type |
|-----------|--------|---------------------|
| ChatGPT | Code Interpreter | `command` |
| ChatGPT | Web browsing | `network` |
| ChatGPT | File upload | `file_access` |
| ChatGPT | Plugin/GPT tool | `tool` |
| Claude.ai | Computer use | `tool` |
| Claude.ai | Artifact execution | `command` |
| Claude.ai | File analysis | `file_access` |
| Gemini | Extensions (Search, Maps) | `tool` |
| Gemini | Code execution | `command` |
| All | User input PII scan | Pre-submission warning |

### PII Scanning

The extension scans user input before submission for:
- Credit card numbers
- Social Security Numbers
- Email addresses
- Phone numbers
- API keys and tokens
- Private keys
- AWS access keys

When PII is detected, a warning modal appears before the message is sent.

### Enterprise Deployment

Deploy via Chrome Enterprise policy:

```json
{
  "ExtensionInstallForcelist": [
    "EXTENSION_ID;https://snapper.example.com/extension/updates.xml"
  ],
  "3rdparty": {
    "extensions": {
      "EXTENSION_ID": {
        "snapper_url": "https://snapper.example.com",
        "snapper_api_key": "snp_enterprise_key",
        "agent_id": "browser-fleet",
        "fail_mode": "closed",
        "pii_scanning": true
      }
    }
  }
}
```

When managed storage is configured:
- Users cannot change the Snapper URL or API key
- Settings page shows "Managed by your organization"
- All AI chat sessions are automatically protected

### How It Works

1. Content scripts inject into ChatGPT/Claude/Gemini pages
2. DOM MutationObservers detect tool execution blocks
3. Each detected tool call is sent to the background service worker
4. The service worker calls Snapper's evaluate endpoint
5. Results are displayed inline:
   - **Allow** — Normal page behavior
   - **Deny** — Red overlay with rule name and reason
   - **Approval** — Yellow "waiting" banner, polls until resolved

---

## Common Patterns

### Monitoring

All SDK and extension evaluations appear in:
- Snapper dashboard audit logs
- Telegram/Slack notifications (if configured)
- SIEM events (if configured)
- Prometheus metrics

### Registering AI Provider Agents

Use the setup wizard or CLI:

```bash
# Via CLI
python scripts/snapper-cli.py init --agent openai
python scripts/snapper-cli.py init --agent anthropic
python scripts/snapper-cli.py init --agent gemini

# Via wizard
# Navigate to /wizard and select your AI provider
```

### Recommended Rules

For API-based agents, apply these rule templates:
- `credential-protection` — Block credential file access
- `rate-limit-standard` — Prevent runaway tool calls
- `pii-gate-protection` — Detect and gate PII in tool inputs
- `human-approval-sensitive` — Require approval for destructive actions
