"""Traffic discovery service — detects MCP servers and tools from live audit data.

Parses tool_name and command fields from evaluate requests, groups them by
service/server, checks rule coverage, and suggests rules for uncovered commands.
"""

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_logs import AuditLog, AuditAction
from app.models.rules import Rule, RuleType, RuleAction

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known MCP server registry — maps server name fragments to display info.
# Used by parse_tool_name() to produce a friendly display_name even when the
# raw server key is abbreviated (e.g. "gh" → "GitHub").
# ---------------------------------------------------------------------------
KNOWN_MCP_SERVERS: dict[str, dict] = {
    # Developer
    "github": {"display": "GitHub", "icon": "🐙", "category": "developer", "template_id": "github"},
    "gh": {"display": "GitHub", "icon": "🐙", "category": "developer", "template_id": "github"},
    "gitlab": {"display": "GitLab", "icon": "🦊", "category": "developer", "template_id": None},
    "git": {"display": "Git", "icon": "📦", "category": "developer", "template_id": None},
    "linear": {"display": "Linear", "icon": "📋", "category": "developer", "template_id": None},
    "sentry": {"display": "Sentry", "icon": "🐛", "category": "developer", "template_id": None},
    # Communication
    "slack": {"display": "Slack", "icon": "💬", "category": "communication", "template_id": "slack"},
    "gmail": {"display": "Gmail", "icon": "📧", "category": "communication", "template_id": "gmail"},
    "google-mail": {"display": "Gmail", "icon": "📧", "category": "communication", "template_id": "gmail"},
    "telegram": {"display": "Telegram", "icon": "✈️", "category": "communication", "template_id": None},
    "discord": {"display": "Discord", "icon": "🎮", "category": "communication", "template_id": None},
    # Cloud
    "aws": {"display": "AWS", "icon": "☁️", "category": "cloud", "template_id": "aws"},
    "docker": {"display": "Docker", "icon": "🐳", "category": "cloud", "template_id": None},
    "kubernetes": {"display": "Kubernetes", "icon": "⎈", "category": "cloud", "template_id": None},
    "k8s": {"display": "Kubernetes", "icon": "⎈", "category": "cloud", "template_id": None},
    "cloudflare": {"display": "Cloudflare", "icon": "🔶", "category": "cloud", "template_id": None},
    "cf": {"display": "Cloudflare", "icon": "🔶", "category": "cloud", "template_id": None},
    "vercel": {"display": "Vercel", "icon": "▲", "category": "cloud", "template_id": None},
    # Database
    "postgres": {"display": "PostgreSQL", "icon": "🐘", "category": "cloud", "template_id": "database"},
    "postgresql": {"display": "PostgreSQL", "icon": "🐘", "category": "cloud", "template_id": "database"},
    "sqlite": {"display": "SQLite", "icon": "🗃️", "category": "cloud", "template_id": "database"},
    "mongo": {"display": "MongoDB", "icon": "🍃", "category": "cloud", "template_id": "database"},
    "mongodb": {"display": "MongoDB", "icon": "🍃", "category": "cloud", "template_id": "database"},
    "supabase": {"display": "Supabase", "icon": "⚡", "category": "cloud", "template_id": None},
    "neon": {"display": "Neon", "icon": "🌙", "category": "cloud", "template_id": None},
    # Filesystem / System
    "filesystem": {"display": "Filesystem", "icon": "📂", "category": "system", "template_id": "filesystem"},
    "fs": {"display": "Filesystem", "icon": "📂", "category": "system", "template_id": "filesystem"},
    # Browser / Network
    "puppeteer": {"display": "Puppeteer", "icon": "🎭", "category": "network", "template_id": "browser"},
    "playwright": {"display": "Playwright", "icon": "🎭", "category": "network", "template_id": "browser"},
    "fetch": {"display": "Fetch", "icon": "🌐", "category": "network", "template_id": "network"},
    "brave-search": {"display": "Brave Search", "icon": "🦁", "category": "network", "template_id": None},
    "exa": {"display": "Exa Search", "icon": "🔍", "category": "network", "template_id": None},
    # Productivity
    "notion": {"display": "Notion", "icon": "📝", "category": "communication", "template_id": None},
    "google-calendar": {"display": "Google Calendar", "icon": "📅", "category": "communication", "template_id": None},
    "gcal": {"display": "Google Calendar", "icon": "📅", "category": "communication", "template_id": None},
    "gdrive": {"display": "Google Drive", "icon": "📁", "category": "communication", "template_id": None},
    "google-drive": {"display": "Google Drive", "icon": "📁", "category": "communication", "template_id": None},
    "google-maps": {"display": "Google Maps", "icon": "🗺️", "category": "network", "template_id": None},
    # AI
    "memory": {"display": "Memory", "icon": "🧠", "category": "system", "template_id": None},
    "openai": {"display": "OpenAI", "icon": "🤖", "category": "network", "template_id": None},
}

# Built-in agent tools (OpenClaw, Claude Code) — bare names without prefix
BUILTIN_TOOLS = {
    "browser": {"display": "Browser", "icon": "🌐", "category": "network"},
    "exec": {"display": "Shell Exec", "icon": "💻", "category": "system"},
    "read": {"display": "File Read", "icon": "📄", "category": "system"},
    "write": {"display": "File Write", "icon": "✏️", "category": "system"},
    "bash": {"display": "Bash", "icon": "💻", "category": "system"},
    "web_fetch": {"display": "Web Fetch", "icon": "🌐", "category": "network"},
    "web_search": {"display": "Web Search", "icon": "🔍", "category": "network"},
}

# CLI tool prefixes detected from shell commands
CLI_TOOL_PATTERNS = [
    (re.compile(r"^git\s+"), "git", "Git", "📦"),
    (re.compile(r"^curl\b"), "curl", "curl", "🌐"),
    (re.compile(r"^wget\b"), "wget", "wget", "🌐"),
    (re.compile(r"^docker\b"), "docker", "Docker CLI", "🐳"),
    (re.compile(r"^npm\b"), "npm", "npm", "📦"),
    (re.compile(r"^pip\b"), "pip", "pip", "🐍"),
    (re.compile(r"^kubectl\b"), "kubectl", "kubectl", "⎈"),
    (re.compile(r"^aws\s+"), "aws-cli", "AWS CLI", "☁️"),
    (re.compile(r"^python\b"), "python", "Python", "🐍"),
    (re.compile(r"^node\b"), "node", "Node.js", "🟢"),
]

# Regex for Claude-style MCP prefix: mcp__<server>__<tool>
_MCP_DOUBLE_RE = re.compile(r"^mcp__([^_]+(?:_[^_]+)*)__(.+)$")
# Regex for mcp__plugin_<name>_<server>__<tool>  (Claude Code plugins)
_MCP_PLUGIN_RE = re.compile(r"^mcp__plugin_\w+_(\w+)__(.+)$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ParsedToolName:
    """Result of parsing a raw tool/command string."""
    raw: str
    server_key: str        # normalised key, e.g. "github", "git", "browser"
    tool_name: str         # the action part, e.g. "create_issue", "status"
    display_name: str      # human-friendly, e.g. "GitHub (MCP)"
    icon: str
    category: str          # system | developer | network | cloud | communication
    source_type: str       # "mcp" | "builtin" | "cli" | "unknown"
    template_id: str | None = None


@dataclass
class DiscoveredCommand:
    command: str
    tool_name: str
    count: int
    last_seen: str  # ISO format
    decisions: dict[str, int] = field(default_factory=dict)
    has_matching_rule: bool = False
    matching_rule_names: list[str] = field(default_factory=list)


@dataclass
class ServiceGroup:
    server_key: str
    display_name: str
    icon: str
    category: str
    source_type: str
    commands: list[DiscoveredCommand] = field(default_factory=list)
    total_count: int = 0
    uncovered_count: int = 0
    has_template: bool = False
    template_id: str | None = None


@dataclass
class TrafficInsights:
    period_hours: int
    service_groups: list[ServiceGroup]
    total_unique_commands: int = 0
    total_uncovered: int = 0
    total_evaluations: int = 0


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def parse_tool_name(raw: str) -> ParsedToolName:
    """Parse a raw tool_name or command into structured parts.

    Handles formats:
      - mcp__github__create_issue          (Claude Desktop / Code / Agent SDK)
      - mcp__plugin_name_server__tool      (Claude Code plugins)
      - github_create_issue                (OpenClaw MCP with toolPrefix)
      - slack_list_channels                (tool has baked-in prefix)
      - browser                            (built-in tool)
      - git status                         (CLI command)
    """
    if not raw:
        return ParsedToolName(
            raw=raw, server_key="unknown", tool_name="",
            display_name="Unknown", icon="❓", category="system",
            source_type="unknown",
        )

    # 1. Claude Code plugin prefix: mcp__plugin_<name>_<server>__<tool>
    m = _MCP_PLUGIN_RE.match(raw)
    if m:
        server_key = m.group(1).lower()
        tool = m.group(2)
        info = KNOWN_MCP_SERVERS.get(server_key, {})
        return ParsedToolName(
            raw=raw, server_key=server_key, tool_name=tool,
            display_name=f"{info.get('display', _titleize(server_key))} (MCP Plugin)",
            icon=info.get("icon", "🔌"),
            category=info.get("category", "system"),
            source_type="mcp",
            template_id=info.get("template_id"),
        )

    # 2. Standard MCP prefix: mcp__<server>__<tool>
    m = _MCP_DOUBLE_RE.match(raw)
    if m:
        server_key = m.group(1).lower()
        tool = m.group(2)
        # Handle hyphens in server names (e.g., "brave-search")
        info = KNOWN_MCP_SERVERS.get(server_key, {})
        return ParsedToolName(
            raw=raw, server_key=server_key, tool_name=tool,
            display_name=f"{info.get('display', _titleize(server_key))} (MCP)",
            icon=info.get("icon", "🔧"),
            category=info.get("category", "system"),
            source_type="mcp",
            template_id=info.get("template_id"),
        )

    # 3. Built-in tool (exact match)
    if raw in BUILTIN_TOOLS:
        info = BUILTIN_TOOLS[raw]
        return ParsedToolName(
            raw=raw, server_key=raw, tool_name=raw,
            display_name=info["display"],
            icon=info["icon"], category=info["category"],
            source_type="builtin",
        )

    # 4. CLI command (space-separated, e.g. "git status")
    for pattern, key, display, icon in CLI_TOOL_PATTERNS:
        if pattern.match(raw):
            # tool_name is the subcommand portion
            parts = raw.split(None, 1)
            tool = parts[1] if len(parts) > 1 else parts[0]
            return ParsedToolName(
                raw=raw, server_key=key, tool_name=tool,
                display_name=f"{display} (CLI)",
                icon=icon, category="system",
                source_type="cli",
            )

    # 5. OpenClaw-style single-underscore prefix: <server>_<tool>
    #    Try longest known-server prefix match first.
    raw_lower = raw.lower()
    best_match = None
    best_len = 0
    for known_key in KNOWN_MCP_SERVERS:
        prefix = known_key + "_"
        if raw_lower.startswith(prefix) and len(prefix) > best_len:
            best_match = known_key
            best_len = len(prefix)

    if best_match and best_len < len(raw):
        info = KNOWN_MCP_SERVERS[best_match]
        tool = raw[best_len:]
        return ParsedToolName(
            raw=raw, server_key=best_match, tool_name=tool,
            display_name=f"{info['display']} (MCP)",
            icon=info["icon"], category=info["category"],
            source_type="mcp",
            template_id=info.get("template_id"),
        )

    # 6. Unknown tool
    return ParsedToolName(
        raw=raw, server_key="other", tool_name=raw,
        display_name="Other",
        icon="❓", category="system",
        source_type="unknown",
    )


def _titleize(s: str) -> str:
    """Convert 'brave-search' or 'google_calendar' to 'Brave Search'."""
    return s.replace("-", " ").replace("_", " ").title()


# ---------------------------------------------------------------------------
# Coverage checking
# ---------------------------------------------------------------------------

async def check_coverage(
    db: AsyncSession,
    command: str,
    agent_id: str | None = None,
) -> dict:
    """Check if a command is covered by any active rule.

    Returns dict with:
      covered: bool
      matching_rules: list of {id, name, action}
    """
    query = select(Rule).where(
        Rule.is_active == True,
        Rule.is_deleted == False,
        Rule.rule_type.in_([
            RuleType.COMMAND_ALLOWLIST.value,
            RuleType.COMMAND_DENYLIST.value,
        ]),
    )
    if agent_id:
        query = query.where(
            or_(Rule.agent_id == agent_id, Rule.agent_id.is_(None))
        )

    result = await db.execute(query)
    rules = result.scalars().all()

    matching = []
    for rule in rules:
        patterns = rule.parameters.get("patterns", [])
        for pat in patterns:
            try:
                if re.search(pat, command):
                    matching.append({
                        "id": str(rule.id),
                        "name": rule.name,
                        "action": rule.action.value if hasattr(rule.action, "value") else rule.action,
                    })
                    break
            except re.error:
                continue

    return {
        "covered": len(matching) > 0,
        "matching_rules": matching,
    }


# ---------------------------------------------------------------------------
# Traffic discovery
# ---------------------------------------------------------------------------

async def discover_traffic(
    db: AsyncSession,
    agent_id: str | None = None,
    hours: int = 168,
    redis_client=None,
) -> TrafficInsights:
    """Analyse audit logs to discover tool/command usage patterns.

    Groups commands by detected MCP server, checks rule coverage,
    and links to templates where available.
    """
    # Check cache
    cache_key = f"traffic_insights:{agent_id or 'global'}:{hours}"
    if redis_client:
        try:
            cached = await redis_client.get(cache_key)
            if cached:
                data = json.loads(cached)
                return _insights_from_dict(data)
        except Exception:
            pass

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Query audit logs for evaluate-related actions
    actions = [
        AuditAction.REQUEST_ALLOWED.value,
        AuditAction.REQUEST_DENIED.value,
        AuditAction.REQUEST_PENDING_APPROVAL.value,
    ]
    query = select(AuditLog).where(
        AuditLog.action.in_(actions),
        AuditLog.created_at >= cutoff,
    )
    if agent_id:
        query = query.where(AuditLog.agent_id == agent_id)

    result = await db.execute(query)
    logs = result.scalars().all()

    # Extract commands & tool_names, group by service
    # key = (command_or_tool_raw) → accumulator
    command_map: dict[str, dict] = {}  # raw → {count, last_seen, decisions}
    total_evals = 0

    for log in logs:
        total_evals += 1
        nv = log.new_value or {}
        details = log.details or {}

        # Prefer command, fall back to tool_name
        raw = nv.get("command") or nv.get("tool_name") or details.get("command") or details.get("tool_name") or ""
        if not raw:
            continue

        if raw not in command_map:
            command_map[raw] = {
                "count": 0,
                "last_seen": log.created_at,
                "decisions": {},
            }

        entry = command_map[raw]
        entry["count"] += 1
        if log.created_at > entry["last_seen"]:
            entry["last_seen"] = log.created_at

        # Map action to decision bucket
        action_str = log.action.value if hasattr(log.action, "value") else str(log.action)
        if "allowed" in action_str:
            bucket = "allow"
        elif "denied" in action_str:
            bucket = "deny"
        elif "pending" in action_str:
            bucket = "pending"
        else:
            bucket = "other"
        entry["decisions"][bucket] = entry["decisions"].get(bucket, 0) + 1

    # Check coverage for each command
    coverage_cache: dict[str, dict] = {}
    for raw in command_map:
        cov = await check_coverage(db, raw, agent_id)
        coverage_cache[raw] = cov

    # Group by parsed server_key
    groups_map: dict[str, ServiceGroup] = {}
    for raw, info in command_map.items():
        parsed = parse_tool_name(raw)
        key = parsed.server_key

        if key not in groups_map:
            groups_map[key] = ServiceGroup(
                server_key=key,
                display_name=parsed.display_name,
                icon=parsed.icon,
                category=parsed.category,
                source_type=parsed.source_type,
                template_id=parsed.template_id,
                has_template=parsed.template_id is not None,
            )

        group = groups_map[key]
        cov = coverage_cache.get(raw, {"covered": False, "matching_rules": []})
        cmd = DiscoveredCommand(
            command=raw,
            tool_name=parsed.tool_name,
            count=info["count"],
            last_seen=info["last_seen"].isoformat() if isinstance(info["last_seen"], datetime) else str(info["last_seen"]),
            decisions=info["decisions"],
            has_matching_rule=cov["covered"],
            matching_rule_names=[r["name"] for r in cov["matching_rules"]],
        )
        group.commands.append(cmd)
        group.total_count += cmd.count
        if not cmd.has_matching_rule:
            group.uncovered_count += 1

    # Sort groups by total_count descending, commands within each group too
    service_groups = sorted(groups_map.values(), key=lambda g: g.total_count, reverse=True)
    for g in service_groups:
        g.commands.sort(key=lambda c: c.count, reverse=True)

    insights = TrafficInsights(
        period_hours=hours,
        service_groups=service_groups,
        total_unique_commands=len(command_map),
        total_uncovered=sum(g.uncovered_count for g in service_groups),
        total_evaluations=total_evals,
    )

    # Cache result
    if redis_client:
        try:
            await redis_client.set(
                cache_key,
                json.dumps(_insights_to_dict(insights)),
                expire=300,  # 5 min
            )
        except Exception:
            pass

    return insights


# ---------------------------------------------------------------------------
# Rule generation from discovered traffic
# ---------------------------------------------------------------------------

def generate_rules_for_server(server_name: str) -> list[dict]:
    """Generate three default rules for an MCP server: allow reads, approve writes, deny destructive.

    Works for any server name — known or unknown.
    """
    if not server_name or not server_name.strip():
        raise ValueError("server_name must not be empty")

    sn = server_name.strip().lower().replace("-", "_")
    info = KNOWN_MCP_SERVERS.get(sn, {})
    display = info.get("display", _titleize(sn))

    # Build patterns that match both Claude (mcp__server__tool) and OpenClaw (server_tool) formats
    # Also handle the server name as-is
    read_verbs = "read|get|list|search|query|describe|fetch|view|find|show|status|info|count"
    write_verbs = "create|update|write|send|post|set|put|add|edit|modify|upsert|insert|comment|reply|push|commit|upload|move|rename|append"
    delete_verbs = "delete|drop|destroy|remove|purge|truncate|kill|force|archive|ban|kick"

    rules = [
        {
            "id": f"{sn}-auto-allow-reads",
            "name": f"{display} - Allow Read Operations (auto)",
            "description": f"Allow read-only operations for {display}",
            "rule_type": "command_allowlist",
            "action": "allow",
            "priority": 100,
            "parameters": {
                "patterns": [
                    f"^mcp__(?:{re.escape(sn)}|{re.escape(server_name)})__(?:{read_verbs}).*",
                    f"^{re.escape(sn)}_(?:{read_verbs}).*",
                ],
            },
        },
        {
            "id": f"{sn}-auto-approve-writes",
            "name": f"{display} - Approve Write Operations (auto)",
            "description": f"Require approval for write operations on {display}",
            "rule_type": "command_allowlist",
            "action": "require_approval",
            "priority": 90,
            "parameters": {
                "patterns": [
                    f"^mcp__(?:{re.escape(sn)}|{re.escape(server_name)})__(?:{write_verbs}).*",
                    f"^{re.escape(sn)}_(?:{write_verbs}).*",
                ],
            },
        },
        {
            "id": f"{sn}-auto-deny-destructive",
            "name": f"{display} - Block Destructive Operations (auto)",
            "description": f"Block destructive operations on {display}",
            "rule_type": "command_denylist",
            "action": "deny",
            "priority": 200,
            "parameters": {
                "patterns": [
                    f"^mcp__(?:{re.escape(sn)}|{re.escape(server_name)})__(?:{delete_verbs}).*",
                    f"^{re.escape(sn)}_(?:{delete_verbs}).*",
                ],
            },
        },
    ]
    return rules


def generate_rule_from_command(
    command: str,
    action: str = "allow",
    pattern_mode: str = "prefix",
    name: str | None = None,
) -> dict:
    """Generate a single rule definition from a discovered command.

    pattern_mode:
      - "prefix" — match the server prefix broadly (e.g., ^mcp__github__.*)
      - "exact"  — match this exact command only
      - "verb"   — match the specific verb across the server
    """
    if not command or not command.strip():
        raise ValueError("command must not be empty")

    parsed = parse_tool_name(command)

    if pattern_mode == "exact":
        pattern = f"^{re.escape(command)}$"
    elif pattern_mode == "prefix":
        if parsed.source_type == "mcp":
            # Match all tools from this server
            pattern = f"^mcp__{re.escape(parsed.server_key)}__.*"
        elif parsed.source_type == "cli":
            pattern = f"^{re.escape(parsed.server_key)}\\b.*"
        else:
            pattern = f"^{re.escape(command)}$"
    else:  # verb mode
        pattern = f"^mcp__{re.escape(parsed.server_key)}__{re.escape(parsed.tool_name)}$"

    auto_name = name or f"{parsed.display_name} - {parsed.tool_name} (auto)"

    rule_type = "command_denylist" if action == "deny" else "command_allowlist"
    return {
        "name": auto_name,
        "description": f"Auto-generated rule for {command}",
        "rule_type": rule_type,
        "action": action,
        "priority": 200 if action == "deny" else (90 if action == "require_approval" else 100),
        "parameters": {"patterns": [pattern]},
    }


# ---------------------------------------------------------------------------
# Serialisation helpers (for Redis caching)
# ---------------------------------------------------------------------------

def _insights_to_dict(ins: TrafficInsights) -> dict:
    return {
        "period_hours": ins.period_hours,
        "total_unique_commands": ins.total_unique_commands,
        "total_uncovered": ins.total_uncovered,
        "total_evaluations": ins.total_evaluations,
        "service_groups": [
            {
                "server_key": g.server_key,
                "display_name": g.display_name,
                "icon": g.icon,
                "category": g.category,
                "source_type": g.source_type,
                "total_count": g.total_count,
                "uncovered_count": g.uncovered_count,
                "has_template": g.has_template,
                "template_id": g.template_id,
                "commands": [
                    {
                        "command": c.command,
                        "tool_name": c.tool_name,
                        "count": c.count,
                        "last_seen": c.last_seen,
                        "decisions": c.decisions,
                        "has_matching_rule": c.has_matching_rule,
                        "matching_rule_names": c.matching_rule_names,
                    }
                    for c in g.commands
                ],
            }
            for g in ins.service_groups
        ],
    }


def _insights_from_dict(d: dict) -> TrafficInsights:
    groups = []
    for gd in d.get("service_groups", []):
        cmds = [
            DiscoveredCommand(**cd)
            for cd in gd.get("commands", [])
        ]
        g = ServiceGroup(
            server_key=gd["server_key"],
            display_name=gd["display_name"],
            icon=gd["icon"],
            category=gd["category"],
            source_type=gd["source_type"],
            total_count=gd["total_count"],
            uncovered_count=gd["uncovered_count"],
            has_template=gd["has_template"],
            template_id=gd.get("template_id"),
            commands=cmds,
        )
        groups.append(g)
    return TrafficInsights(
        period_hours=d["period_hours"],
        service_groups=groups,
        total_unique_commands=d["total_unique_commands"],
        total_uncovered=d["total_uncovered"],
        total_evaluations=d["total_evaluations"],
    )
