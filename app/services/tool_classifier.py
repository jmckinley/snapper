"""Tool Classification Engine for MCP tools.

Classifies MCP tools into read/write/destructive categories using verb
extraction and description analysis. Used by the catalog rule generator
to produce tailored rules with actual tool names instead of generic verb
guessing.
"""

import re
from dataclasses import dataclass
from typing import List, Optional


# ---------------------------------------------------------------------------
# Verb dictionaries
# ---------------------------------------------------------------------------

READ_VERBS = frozenset({
    "read", "get", "list", "search", "query", "describe", "fetch", "view",
    "find", "show", "status", "info", "count", "retrieve", "check", "browse",
    "export", "download", "lookup", "inspect", "watch", "monitor", "scan",
    "resolve", "verify", "validate", "preview", "summarize",
})

WRITE_VERBS = frozenset({
    "create", "update", "write", "send", "post", "set", "put", "add", "edit",
    "modify", "upsert", "insert", "comment", "reply", "push", "commit",
    "upload", "move", "rename", "append", "assign", "enable", "configure",
    "run", "execute", "invoke", "start", "trigger", "submit", "publish",
    "deploy", "merge", "approve", "request", "fork", "clone", "apply",
    "patch", "transfer", "schedule", "subscribe", "register",
})

DELETE_VERBS = frozenset({
    "delete", "drop", "destroy", "remove", "purge", "truncate", "kill",
    "force", "archive", "ban", "kick", "revoke", "disable", "close",
    "terminate", "cancel", "unsubscribe", "deactivate", "wipe", "reset",
    "rollback", "revert", "reject", "dismiss",
})

# Description keywords for fallback classification
_READ_KEYWORDS = re.compile(
    r"\b(retriev|fetch|get|list|search|read|query|look up|check|view|show"
    r"|inspect|monitor|download|export)\b", re.IGNORECASE
)
_WRITE_KEYWORDS = re.compile(
    r"\b(creat|updat|modif|edit|send|post|write|add|set|configur|deploy"
    r"|execut|run|invoke|trigger|submit|publish|upload)\b", re.IGNORECASE
)
_DELETE_KEYWORDS = re.compile(
    r"\b(delet|remov|destroy|drop|purg|truncat|kill|terminat|cancel"
    r"|revok|disabl|wipe|reset|rollback)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedTool:
    """A tool classified into a security category."""
    name: str
    category: str  # "read" | "write" | "delete" | "unknown"
    description: str = ""


# ---------------------------------------------------------------------------
# Classification engine
# ---------------------------------------------------------------------------

def classify_tools(tools: list) -> List[ClassifiedTool]:
    """Classify a list of MCP tools into read/write/delete categories.

    Args:
        tools: List of tool definitions. Each can be:
          - A string (tool name only)
          - A dict with "name" and optional "description" / "inputSchema"

    Returns:
        List of ClassifiedTool with category assignment.
    """
    results = []
    for tool in tools:
        if isinstance(tool, str):
            name = tool
            description = ""
        elif isinstance(tool, dict):
            name = tool.get("name", "")
            description = tool.get("description", "")
        else:
            continue

        if not name:
            continue

        category = _classify_single(name, description)
        results.append(ClassifiedTool(
            name=name,
            category=category,
            description=description,
        ))

    return results


def _classify_single(name: str, description: str = "") -> str:
    """Classify a single tool by name and description.

    Strategy:
    1. Extract leading verb from tool name (split on _ or camelCase)
    2. Check verb against dictionaries
    3. If ambiguous, scan description for intent keywords
    """
    # Extract leading verb
    verb = _extract_verb(name)

    if verb:
        verb_lower = verb.lower()
        if verb_lower in DELETE_VERBS:
            return "delete"
        if verb_lower in WRITE_VERBS:
            return "write"
        if verb_lower in READ_VERBS:
            return "read"

    # Fallback: scan description
    if description:
        return _classify_by_description(description)

    return "unknown"


def _extract_verb(name: str) -> Optional[str]:
    """Extract the leading verb from a tool name.

    Handles formats:
      - snake_case: "create_issue" → "create"
      - camelCase: "createIssue" → "create"
      - kebab-case: "create-issue" → "create"
      - Plain: "search" → "search"
    """
    # Remove common prefixes (server name might be prepended)
    # e.g., "github_create_issue" — but we classify the action part,
    # so assume the caller already stripped the server prefix

    # Try snake_case / kebab-case first
    parts = re.split(r"[_\-]", name, maxsplit=1)
    if parts:
        verb = parts[0].lower()
        if verb:
            return verb

    # Try camelCase
    m = re.match(r"^([a-z]+)", name)
    if m:
        return m.group(1).lower()

    return None


def _classify_by_description(description: str) -> str:
    """Classify based on description keywords when verb extraction is ambiguous."""
    # Check delete first (most dangerous)
    if _DELETE_KEYWORDS.search(description):
        return "delete"
    if _WRITE_KEYWORDS.search(description):
        return "write"
    if _READ_KEYWORDS.search(description):
        return "read"
    return "unknown"
