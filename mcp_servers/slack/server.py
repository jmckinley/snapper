#!/usr/bin/env python3
"""Slack MCP Server for Snapper testing.

This MCP server provides tools to interact with Slack, allowing AI agents
to read channels, post messages, and manage reactions - all governed by
Snapper security rules.
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from typing import Any, Optional, Tuple

# Configuration
SNAPPER_URL = os.environ.get("SNAPPER_URL", "http://localhost:8000")
SNAPPER_AGENT_ID = os.environ.get("SNAPPER_AGENT_ID", "slack-mcp-server")


def log_stderr(message: str):
    """Log to stderr for debugging."""
    sys.stderr.write(f"[slack-mcp] {message}\n")
    sys.stderr.flush()


# MCP Protocol implementation
def send_response(response: dict):
    """Send a JSON-RPC response."""
    print(json.dumps(response), flush=True)


def send_error(id: Any, code: int, message: str):
    """Send a JSON-RPC error response."""
    send_response({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })


def send_result(id: Any, result: Any):
    """Send a JSON-RPC result response."""
    send_response({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })


class SnapperClient:
    """Client for Snapper rule evaluation."""

    def __init__(self, base_url: str, agent_id: str):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id

    def check_permission(self, tool_name: str, tool_input: dict) -> Tuple[str, str]:
        """
        Check with Snapper if the tool call is allowed.

        Returns: (decision, reason) tuple
        - decision: "allow", "deny", or "require_approval"
        - reason: explanation of the decision
        """
        url = f"{self.base_url}/api/v1/rules/evaluate"

        payload = {
            "agent_id": self.agent_id,
            "request_type": "command",
            "command": tool_name,
            "tool_name": tool_name,
            "tool_input": tool_input,
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )

            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.loads(response.read().decode())
                decision = result.get("decision", "deny")
                reason = result.get("reason", "Unknown")
                log_stderr(f"Snapper decision for {tool_name}: {decision} - {reason}")
                return decision, reason

        except urllib.error.URLError as e:
            log_stderr(f"Snapper connection error: {e}")
            # If Snapper is unreachable, deny by default for safety
            return "deny", f"Snapper unreachable: {e}"
        except Exception as e:
            log_stderr(f"Snapper check error: {e}")
            return "deny", f"Error checking permissions: {e}"


class SlackClient:
    """Simple Slack API client."""

    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://slack.com/api"

    def _request(self, method: str, data: dict = None) -> dict:
        """Make a Slack API request."""
        url = f"{self.base_url}/{method}"

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode() if data else None,
            headers=headers,
            method="POST"
        )

        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())

    def list_channels(self, limit: int = 20) -> dict:
        """List public channels."""
        return self._request("conversations.list", {
            "types": "public_channel",
            "limit": limit
        })

    def get_channel_history(self, channel: str, limit: int = 10) -> dict:
        """Get message history for a channel."""
        return self._request("conversations.history", {
            "channel": channel,
            "limit": limit
        })

    def post_message(self, channel: str, text: str) -> dict:
        """Post a message to a channel."""
        return self._request("chat.postMessage", {
            "channel": channel,
            "text": text
        })

    def add_reaction(self, channel: str, timestamp: str, emoji: str) -> dict:
        """Add a reaction to a message."""
        return self._request("reactions.add", {
            "channel": channel,
            "timestamp": timestamp,
            "name": emoji
        })

    def list_users(self, limit: int = 20) -> dict:
        """List workspace users."""
        return self._request("users.list", {"limit": limit})

    def search_messages(self, query: str) -> dict:
        """Search messages (requires search:read scope)."""
        return self._request("search.messages", {"query": query})


# Tool definitions
TOOLS = [
    {
        "name": "slack_list_channels",
        "description": "List public channels in the Slack workspace",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of channels to return (default: 20)",
                    "default": 20
                }
            }
        }
    },
    {
        "name": "slack_read_channel",
        "description": "Read recent messages from a Slack channel",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Channel ID (e.g., C1234567890)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Number of messages to retrieve (default: 10)",
                    "default": 10
                }
            },
            "required": ["channel"]
        }
    },
    {
        "name": "slack_post_message",
        "description": "Post a message to a Slack channel",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Channel ID or name (e.g., C1234567890 or #general)"
                },
                "text": {
                    "type": "string",
                    "description": "Message text to post"
                }
            },
            "required": ["channel", "text"]
        }
    },
    {
        "name": "slack_add_reaction",
        "description": "Add an emoji reaction to a message",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {
                    "type": "string",
                    "description": "Channel ID where the message is"
                },
                "timestamp": {
                    "type": "string",
                    "description": "Message timestamp (e.g., 1234567890.123456)"
                },
                "emoji": {
                    "type": "string",
                    "description": "Emoji name without colons (e.g., thumbsup)"
                }
            },
            "required": ["channel", "timestamp", "emoji"]
        }
    },
    {
        "name": "slack_list_users",
        "description": "List users in the Slack workspace",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of users to return (default: 20)",
                    "default": 20
                }
            }
        }
    },
    {
        "name": "slack_search",
        "description": "Search for messages in Slack",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                }
            },
            "required": ["query"]
        }
    }
]


def handle_tool_call(slack_client: SlackClient, name: str, arguments: dict) -> dict:
    """Handle a tool call and return the result."""
    try:
        if name == "slack_list_channels":
            result = slack_client.list_channels(arguments.get("limit", 20))
            if result.get("ok"):
                channels = [
                    {"id": c["id"], "name": c["name"], "topic": c.get("topic", {}).get("value", "")}
                    for c in result.get("channels", [])
                ]
                return {"channels": channels}
            return {"error": result.get("error", "Unknown error")}

        elif name == "slack_read_channel":
            result = slack_client.get_channel_history(
                arguments["channel"],
                arguments.get("limit", 10)
            )
            if result.get("ok"):
                messages = [
                    {"user": m.get("user", "bot"), "text": m.get("text", ""), "ts": m.get("ts", "")}
                    for m in result.get("messages", [])
                ]
                return {"messages": messages}
            return {"error": result.get("error", "Unknown error")}

        elif name == "slack_post_message":
            result = slack_client.post_message(arguments["channel"], arguments["text"])
            if result.get("ok"):
                return {"success": True, "ts": result.get("ts"), "channel": result.get("channel")}
            return {"error": result.get("error", "Unknown error")}

        elif name == "slack_add_reaction":
            result = slack_client.add_reaction(
                arguments["channel"],
                arguments["timestamp"],
                arguments["emoji"]
            )
            if result.get("ok"):
                return {"success": True}
            return {"error": result.get("error", "Unknown error")}

        elif name == "slack_list_users":
            result = slack_client.list_users(arguments.get("limit", 20))
            if result.get("ok"):
                users = [
                    {"id": u["id"], "name": u.get("name", ""), "real_name": u.get("real_name", "")}
                    for u in result.get("members", [])
                    if not u.get("is_bot") and not u.get("deleted")
                ]
                return {"users": users}
            return {"error": result.get("error", "Unknown error")}

        elif name == "slack_search":
            result = slack_client.search_messages(arguments["query"])
            if result.get("ok"):
                return {"matches": result.get("messages", {}).get("matches", [])}
            return {"error": result.get("error", "Unknown error")}

        else:
            return {"error": f"Unknown tool: {name}"}

    except Exception as e:
        return {"error": str(e)}


def main():
    """Main MCP server loop."""
    token = os.environ.get("SLACK_BOT_TOKEN")
    if not token:
        sys.stderr.write("Error: SLACK_BOT_TOKEN environment variable not set\n")
        sys.exit(1)

    slack_client = SlackClient(token)
    snapper_client = SnapperClient(SNAPPER_URL, SNAPPER_AGENT_ID)

    # Check if Snapper enforcement is enabled
    enforce_rules = os.environ.get("SNAPPER_ENFORCE", "true").lower() == "true"
    log_stderr(f"Snapper enforcement: {'enabled' if enforce_rules else 'disabled'}")

    # Read JSON-RPC messages from stdin
    for line in sys.stdin:
        try:
            request = json.loads(line.strip())
        except json.JSONDecodeError:
            continue

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            send_result(request_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "slack-mcp-server",
                    "version": "1.0.0"
                }
            })

        elif method == "notifications/initialized":
            # No response needed for notifications
            pass

        elif method == "tools/list":
            send_result(request_id, {"tools": TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})

            # Check with Snapper before executing
            if enforce_rules:
                decision, reason = snapper_client.check_permission(tool_name, arguments)

                if decision == "deny":
                    send_result(request_id, {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({
                                    "error": "Permission denied by Snapper",
                                    "reason": reason,
                                    "tool": tool_name
                                }, indent=2)
                            }
                        ],
                        "isError": True
                    })
                    continue

                elif decision == "require_approval":
                    send_result(request_id, {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps({
                                    "error": "Action requires approval",
                                    "reason": reason,
                                    "tool": tool_name,
                                    "status": "pending_approval"
                                }, indent=2)
                            }
                        ],
                        "isError": True
                    })
                    continue

            # Permission granted - execute the tool
            result = handle_tool_call(slack_client, tool_name, arguments)

            send_result(request_id, {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2)
                    }
                ]
            })

        else:
            send_error(request_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()
