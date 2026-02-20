# Snapper SDK

Python SDK for the [Snapper Agent Application Firewall](https://github.com/jmckinley/snapper).

## Installation

```bash
pip install snapper-sdk

# With provider wrappers (optional)
pip install snapper-sdk[openai]      # OpenAI
pip install snapper-sdk[anthropic]   # Anthropic
pip install snapper-sdk[gemini]      # Google Gemini
pip install snapper-sdk[all]         # All providers
```

## Quick Start

### Basic Client

```python
from snapper import SnapperClient, SnapperDenied

client = SnapperClient(
    snapper_url="http://localhost:8000",
    snapper_api_key="snp_your_key",
    agent_id="my-agent",
)

# Evaluate a tool call
result = client.evaluate(
    request_type="command",
    command="git status",
)
print(result["decision"])  # "allow", "deny", or "require_approval"
```

### Async Client

```python
from snapper import AsyncSnapperClient

client = AsyncSnapperClient(
    snapper_url="http://localhost:8000",
    snapper_api_key="snp_your_key",
    agent_id="my-agent",
)

result = await client.evaluate(request_type="command", command="ls -la")
```

### Provider Wrappers

Provider wrappers intercept tool calls and enforce Snapper policy before execution.

**OpenAI:**

```python
from snapper import SnapperOpenAI

client = SnapperOpenAI()  # reads SNAPPER_URL, SNAPPER_API_KEY, OPENAI_API_KEY from env

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "List files in /tmp"}],
    tools=[...],
)
```

**Anthropic:**

```python
from snapper import SnapperAnthropic

client = SnapperAnthropic()
# Tool calls are automatically evaluated against Snapper policy
```

**Google Gemini:**

```python
from snapper import SnapperGemini

client = SnapperGemini()
```

## Error Handling

```python
from snapper import SnapperClient, SnapperDenied, SnapperApprovalTimeout

client = SnapperClient()

try:
    result = client.evaluate(request_type="command", command="rm -rf /")
except SnapperDenied as e:
    print(f"Blocked: {e.reason}")  # "Command blocked by rule: ..."
    print(f"Rule: {e.rule_name}")
except SnapperApprovalTimeout as e:
    print(f"Approval {e.approval_id} timed out after {e.timeout}s")
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SNAPPER_URL` | Snapper server URL | — |
| `SNAPPER_API_KEY` | Agent API key (`snp_...`) | — |
| `SNAPPER_AGENT_ID` | Agent identifier | — |
| `SNAPPER_FAIL_MODE` | `closed` (deny on error) or `open` (allow on error) | `closed` |
| `SNAPPER_TIMEOUT` | HTTP timeout in seconds | `30` |
| `SNAPPER_APPROVAL_TIMEOUT` | Max wait for human approval in seconds | `300` |

## Documentation

- [Public API Reference](https://github.com/jmckinley/snapper/blob/main/docs/PUBLIC-API.md)
- [AI Provider Integration Guide](https://github.com/jmckinley/snapper/blob/main/docs/AI_PROVIDERS.md)
