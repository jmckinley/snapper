"""Setup and onboarding API endpoints."""

import json
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.agents import Agent, AgentStatus, TrustLevel, generate_api_key
from app.models.rules import Rule

router = APIRouter(prefix="/api/v1/setup", tags=["setup"])


# ============================================================================
# Schemas
# ============================================================================


class SetupStatus(BaseModel):
    """Current setup status."""

    is_first_run: bool
    agents_count: int
    rules_count: int
    has_global_rules: bool
    setup_complete: bool
    config: Optional[dict] = None


class DiscoveredInstance(BaseModel):
    """A discovered AI agent instance."""

    pid: Optional[int] = None
    port: int
    host: str = "localhost"
    version: Optional[str] = None
    status: str = "detected"


class DiscoveryResult(BaseModel):
    """Result of AI agent discovery."""

    instances: list[DiscoveredInstance]
    scan_method: str
    message: str


class QuickRegisterRequest(BaseModel):
    """Request to quickly register a discovered instance."""

    host: str = "localhost"
    port: int = 8080
    name: Optional[str] = None
    agent_type: str = "custom"  # openclaw, claude-code, custom
    security_profile: str = "recommended"  # strict, recommended, permissive


class InstallConfigRequest(BaseModel):
    """Request to install agent config to disk."""

    agent_type: str  # openclaw, claude-code
    agent_id: str
    api_key: str
    snapper_url: str = "http://localhost:8000"


class InstallConfigResponse(BaseModel):
    """Response from config installation attempt."""

    installed: bool
    message: str
    config_snippet: str


class QuickRegisterResponse(BaseModel):
    """Response from quick registration."""

    agent_id: str
    name: str
    external_id: str
    api_key: str
    rules_applied: int
    config_snippet: str


class ConfigSnippet(BaseModel):
    """AI agent configuration snippet."""

    yaml_config: str
    env_config: str
    instructions: str


class SecurityProfile(BaseModel):
    """A security profile option."""

    id: str
    name: str
    description: str
    rule_count: int
    recommended: bool = False


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/status", response_model=SetupStatus)
async def get_setup_status(db: AsyncSession = Depends(get_db)):
    """Check if this is a first-run setup.

    Returns setup status including whether any agents are registered.
    """
    # Count agents
    agents_result = await db.execute(
        select(func.count(Agent.id)).where(Agent.deleted_at.is_(None))
    )
    agents_count = agents_result.scalar() or 0

    # Count rules
    rules_result = await db.execute(
        select(func.count(Rule.id)).where(Rule.deleted_at.is_(None))
    )
    rules_count = rules_result.scalar() or 0

    # Check for global rules
    global_rules_result = await db.execute(
        select(func.count(Rule.id)).where(
            Rule.agent_id.is_(None),
            Rule.deleted_at.is_(None),
        )
    )
    global_rules_count = global_rules_result.scalar() or 0

    is_first_run = agents_count == 0
    setup_complete = agents_count > 0 and rules_count > 0

    # Expose non-secret config for settings page
    from app.config import get_settings
    s = get_settings()
    config = {
        "deny_by_default": s.DENY_BY_DEFAULT,
        "learning_mode": s.LEARNING_MODE,
        "require_api_key": s.REQUIRE_API_KEY,
        "validate_websocket_origin": s.VALIDATE_WEBSOCKET_ORIGIN,
        "require_localhost_only": s.REQUIRE_LOCALHOST_ONLY,
        "rate_limit_enabled": s.RATE_LIMIT_ENABLED,
        # Boolean flags for configured channels (no secrets exposed)
        "smtp_host": bool(s.SMTP_HOST),
        "smtp_user": bool(s.SMTP_USER),
        "slack_webhook_url": bool(s.SLACK_WEBHOOK_URL),
        "telegram_bot_token": bool(s.TELEGRAM_BOT_TOKEN),
        "pagerduty_api_key": bool(s.PAGERDUTY_API_KEY),
    }

    return SetupStatus(
        is_first_run=is_first_run,
        agents_count=agents_count,
        rules_count=rules_count,
        has_global_rules=global_rules_count > 0,
        setup_complete=setup_complete,
        config=config,
    )


@router.get("/discover", response_model=DiscoveryResult)
async def discover_snapper_instances():
    """Auto-discover running AI agent instances on this machine.

    Scans common ports and processes to find AI agent instances.
    """
    instances = []
    scan_methods_used = []

    # Method 1: Check common AI agent ports
    common_ports = [8080, 8000, 3000, 5000, 9000]
    scan_methods_used.append("port_scan")

    for port in common_ports:
        if _is_port_open("localhost", port):
            instances.append(
                DiscoveredInstance(
                    port=port,
                    host="localhost",
                    status="port_open",
                )
            )

    # Method 2: Check for AI agent processes (Unix-like systems)
    try:
        result = subprocess.run(
            ["pgrep", "-f", "snapper"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            scan_methods_used.append("process_scan")
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                if pid:
                    # Try to get port from process
                    port_info = _get_process_port(int(pid))
                    if port_info and not any(
                        i.port == port_info for i in instances
                    ):
                        instances.append(
                            DiscoveredInstance(
                                pid=int(pid),
                                port=port_info,
                                host="localhost",
                                status="process_found",
                            )
                        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Method 3: Check environment variable
    snapper_url = os.environ.get("OPENCLAW_URL")
    if snapper_url:
        scan_methods_used.append("env_var")
        # Parse URL to extract host and port
        try:
            from urllib.parse import urlparse

            parsed = urlparse(snapper_url)
            port = parsed.port or 8080
            host = parsed.hostname or "localhost"
            if not any(i.port == port and i.host == host for i in instances):
                instances.append(
                    DiscoveredInstance(
                        port=port,
                        host=host,
                        status="env_configured",
                    )
                )
        except Exception:
            pass

    message = (
        f"Found {len(instances)} potential AI agent instance(s)"
        if instances
        else "No AI agent instances detected. You can register manually."
    )

    return DiscoveryResult(
        instances=instances,
        scan_method="+".join(scan_methods_used),
        message=message,
    )


@router.post("/quick-register", response_model=QuickRegisterResponse)
async def quick_register_agent(
    request: QuickRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """Quickly register a discovered AI agent instance.

    Creates an agent with appropriate security rules based on the selected profile.
    """
    agent_id = uuid4()
    api_key = generate_api_key()
    hostname = platform.node() or "local"

    # Set identifiers based on agent type
    if request.agent_type == "openclaw":
        external_id = "openclaw-main"
        name = request.name or "OpenClaw"
        description = "OpenClaw AI assistant"
    elif request.agent_type == "claude-code":
        external_id = f"claude-code-{hostname}"
        name = request.name or f"Claude Code on {hostname}"
        description = f"Claude Code agent on {hostname}"
    elif request.agent_type == "cursor":
        external_id = f"cursor-{hostname}"
        name = request.name or f"Cursor on {hostname}"
        description = f"Cursor AI editor on {hostname}"
    elif request.agent_type == "windsurf":
        external_id = f"windsurf-{hostname}"
        name = request.name or f"Windsurf on {hostname}"
        description = f"Windsurf AI IDE on {hostname}"
    elif request.agent_type == "cline":
        external_id = f"cline-{hostname}"
        name = request.name or f"Cline on {hostname}"
        description = f"Cline coding agent on {hostname}"
    else:
        external_id = f"snapper-{request.host}-{request.port}"
        name = request.name or f"AI agent @ {request.host}:{request.port}"
        description = (
            f"Auto-registered AI agent instance at {request.host}:{request.port}"
        )

    # Determine trust level based on profile
    trust_levels = {
        "strict": TrustLevel.UNTRUSTED,
        "recommended": TrustLevel.STANDARD,
        "permissive": TrustLevel.ELEVATED,
    }
    trust_level = trust_levels.get(request.security_profile, TrustLevel.STANDARD)

    # Check if already registered
    existing_result = await db.execute(
        select(Agent).where(Agent.external_id == external_id)
    )
    existing_agent = existing_result.scalar_one_or_none()
    if existing_agent:
        if existing_agent.deleted_at is None:
            raise HTTPException(
                status_code=409,
                detail=f"Agent with external_id '{external_id}' already registered",
            )
        # Re-use the soft-deleted row: reactivate it
        existing_agent.deleted_at = None
        existing_agent.is_deleted = False
        existing_agent.name = name
        existing_agent.description = description
        existing_agent.agent_type = (
            request.agent_type if request.agent_type != "custom" else None
        )
        existing_agent.status = AgentStatus.ACTIVE
        existing_agent.trust_level = trust_level
        existing_agent.api_key = api_key
        existing_agent.agent_metadata = {"api_key_hash": _hash_api_key(api_key)}

        rules_applied = await _apply_security_profile(
            db, existing_agent.id, request.security_profile
        )
        await db.commit()

        config_snippet = _generate_config_snippet(
            agent_id=str(existing_agent.id),
            api_key=api_key,
            rules_manager_url="http://localhost:8000",
            agent_type=request.agent_type,
        )
        return QuickRegisterResponse(
            agent_id=str(existing_agent.id),
            name=name,
            external_id=external_id,
            api_key=api_key,
            rules_applied=rules_applied,
            config_snippet=config_snippet,
        )

    # Create agent
    agent = Agent(
        id=agent_id,
        name=name,
        external_id=external_id,
        description=description,
        agent_type=request.agent_type if request.agent_type != "custom" else None,
        status=AgentStatus.ACTIVE,
        trust_level=trust_level,
        allowed_origins=[
            f"http://{request.host}:{request.port}",
            f"https://{request.host}:{request.port}",
        ],
        require_localhost_only=request.host in ["localhost", "127.0.0.1"],
        agent_metadata={"api_key_hash": _hash_api_key(api_key)},
    )
    db.add(agent)

    # Apply security profile rules
    rules_applied = await _apply_security_profile(
        db, agent_id, request.security_profile
    )

    await db.commit()

    # Generate config snippet
    config_snippet = _generate_config_snippet(
        agent_id=str(agent_id),
        api_key=api_key,
        rules_manager_url="http://localhost:8000",
        agent_type=request.agent_type,
    )

    return QuickRegisterResponse(
        agent_id=str(agent_id),
        name=name,
        external_id=external_id,
        api_key=api_key,
        rules_applied=rules_applied,
        config_snippet=config_snippet,
    )


@router.get("/profiles", response_model=list[SecurityProfile])
async def list_security_profiles():
    """List available security profiles for quick setup."""
    return [
        SecurityProfile(
            id="strict",
            name="🔒 Strict",
            description="Maximum security. Deny-by-default with approval required for sensitive operations. Best for production environments.",
            rule_count=12,
            recommended=False,
        ),
        SecurityProfile(
            id="recommended",
            name="⚖️ Recommended",
            description="Balanced security and usability. Blocks known threats while allowing normal operations. Best for most users.",
            rule_count=8,
            recommended=True,
        ),
        SecurityProfile(
            id="permissive",
            name="🔓 Permissive",
            description="Logging only with minimal blocking. Good for development and testing environments.",
            rule_count=4,
            recommended=False,
        ),
    ]


@router.get("/config/{agent_id}", response_model=ConfigSnippet)
async def get_config_snippet(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get AI agent configuration snippet for an agent.

    Returns YAML and environment variable configs to add to AI agent.
    """
    # Verify agent exists
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    yaml_config = f"""# Add to your AI agent configuration file (.snapper/config.yaml)
rules_manager:
  enabled: true
  url: http://localhost:8000
  agent_id: {agent_id}

  # Automatically check rules before executing commands
  enforce_rules: true

  # What to do when Rules Manager is unreachable
  # Options: deny (safest), allow (permissive), cache (use last known rules)
  fallback_policy: deny

  # Log all rule evaluations for debugging
  verbose_logging: false
"""

    env_config = f"""# Add to your environment or .env file
OPENCLAW_RULES_MANAGER_URL=http://localhost:8000
OPENCLAW_RULES_MANAGER_AGENT_ID={agent_id}
OPENCLAW_RULES_MANAGER_ENABLED=true
"""

    instructions = """## Setup Instructions

1. **Copy the configuration** above to your AI agent config file or environment

2. **Restart AI agent** to apply the changes:
   ```bash
   snapper restart
   ```

3. **Verify connection** by checking the agent status in the Rules Manager dashboard

4. **Test a command** to ensure rules are being enforced:
   ```bash
   snapper run "echo hello"  # Should be allowed
   snapper run "rm -rf /"    # Should be blocked
   ```

Need help? Visit the documentation at http://localhost:8000/docs
"""

    return ConfigSnippet(
        yaml_config=yaml_config,
        env_config=env_config,
        instructions=instructions,
    )


@router.post("/complete")
async def mark_setup_complete(db: AsyncSession = Depends(get_db)):
    """Mark the initial setup as complete.

    Called when user finishes the setup wizard.
    """
    # Could store a flag in the database or a config table
    # For now, just return success if at least one agent exists
    result = await db.execute(
        select(func.count(Agent.id)).where(Agent.deleted_at.is_(None))
    )
    agents_count = result.scalar() or 0

    if agents_count == 0:
        raise HTTPException(
            status_code=400,
            detail="Cannot complete setup without at least one registered agent",
        )

    return {"status": "complete", "message": "Setup completed successfully"}


@router.post("/install-config", response_model=InstallConfigResponse)
async def install_config(request: InstallConfigRequest):
    """Attempt to write agent config directly to disk.

    For known agent types (OpenClaw, Claude Code), writes config files
    to the expected locations. Falls back to a copyable snippet if the
    write fails (missing directory, permissions, etc.).
    """
    snippet = _generate_config_snippet(
        agent_id=request.agent_id,
        api_key=request.api_key,
        rules_manager_url=request.snapper_url,
        agent_type=request.agent_type,
    )

    if request.agent_type == "openclaw":
        return _install_openclaw_config(request, snippet)
    elif request.agent_type == "claude-code":
        return _install_claude_code_config(request, snippet)
    elif request.agent_type == "cursor":
        return _install_cursor_config(request, snippet)
    elif request.agent_type == "windsurf":
        return _install_windsurf_config(request, snippet)
    elif request.agent_type == "cline":
        return _install_cline_config(request, snippet)
    else:
        return InstallConfigResponse(
            installed=False,
            message="Manual configuration required for custom agents.",
            config_snippet=snippet,
        )


# ============================================================================
# Helper Functions
# ============================================================================


def _is_port_open(host: str, port: int) -> bool:
    """Check if a port is open on the given host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _get_process_port(pid: int) -> Optional[int]:
    """Try to get the listening port for a process."""
    try:
        # Use lsof to find listening ports
        result = subprocess.run(
            ["lsof", "-Pan", "-p", str(pid), "-iTCP", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "LISTEN" in line:
                    # Extract port from output like "TCP *:8080 (LISTEN)"
                    parts = line.split(":")
                    for part in parts:
                        if part.strip().split()[0].isdigit():
                            return int(part.strip().split()[0])
    except Exception:
        pass
    return None


def _hash_api_key(api_key: str) -> str:
    """Hash an API key for storage."""
    import hashlib

    return hashlib.sha256(api_key.encode()).hexdigest()


def _generate_config_snippet(
    agent_id: str,
    api_key: str,
    rules_manager_url: str,
    agent_type: str = "custom",
) -> str:
    """Generate an agent-specific config snippet for display."""
    if agent_type == "openclaw":
        return json.dumps(
            {
                "plugins": {
                    "entries": {
                        "snapper-guard": {
                            "enabled": True,
                            "config": {
                                "snapperUrl": rules_manager_url,
                                "agentId": agent_id,
                                "apiKey": api_key,
                            },
                        }
                    }
                }
            },
            indent=2,
        )
    elif agent_type == "claude-code":
        hook_path = "~/.claude/hooks/snapper_pre_tool_use.sh"
        settings_block = json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": hook_path,
                                }
                            ],
                        }
                    ]
                }
            },
            indent=2,
        )
        return (
            f"# 1. Add to ~/.claude/.env.snapper (sourced by hook)\n"
            f"SNAPPER_URL={rules_manager_url}\n"
            f"SNAPPER_AGENT_ID={agent_id}\n"
            f"SNAPPER_API_KEY={api_key}\n"
            f"\n"
            f"# 2. Merge into ~/.claude/settings.json\n"
            f"{settings_block}"
        )
    elif agent_type == "cursor":
        hook_path = "~/.cursor/hooks/snapper_pre_tool_use.sh"
        hooks_block = json.dumps(
            {
                "preToolUse": [
                    {"command": hook_path}
                ]
            },
            indent=2,
        )
        return (
            f"# 1. Add to ~/.cursor/.env.snapper (sourced by hook)\n"
            f"SNAPPER_URL={rules_manager_url}\n"
            f"SNAPPER_AGENT_ID={agent_id}\n"
            f"SNAPPER_API_KEY={api_key}\n"
            f"\n"
            f"# 2. Merge into ~/.cursor/hooks/hooks.json\n"
            f"{hooks_block}"
        )
    elif agent_type == "windsurf":
        hook_path = "~/.codeium/windsurf/hooks/snapper_pre_tool_use.sh"
        hooks_block = json.dumps(
            {
                "pre_run_command": [{"command": hook_path}],
                "pre_write_code": [{"command": hook_path}],
                "pre_mcp_tool_use": [{"command": hook_path}],
            },
            indent=2,
        )
        return (
            f"# 1. Add to ~/.codeium/windsurf/.env.snapper (sourced by hook)\n"
            f"SNAPPER_URL={rules_manager_url}\n"
            f"SNAPPER_AGENT_ID={agent_id}\n"
            f"SNAPPER_API_KEY={api_key}\n"
            f"\n"
            f"# 2. Merge into ~/.codeium/windsurf/hooks/hooks.json\n"
            f"{hooks_block}"
        )
    elif agent_type == "cline":
        return (
            f"# 1. Add to ~/.cline/.env.snapper (sourced by hook)\n"
            f"SNAPPER_URL={rules_manager_url}\n"
            f"SNAPPER_AGENT_ID={agent_id}\n"
            f"SNAPPER_API_KEY={api_key}\n"
            f"\n"
            f"# 2. Copy hook to ~/.cline/hooks/pre_tool_use\n"
            f"# Cline auto-discovers executable scripts in the hooks directory\n"
            f"# chmod +x ~/.cline/hooks/pre_tool_use"
        )
    else:
        return (
            f"# Add to your agent's config\n"
            f"rules_manager:\n"
            f"  enabled: true\n"
            f"  url: {rules_manager_url}\n"
            f"  agent_id: {agent_id}\n"
            f"  api_key: {api_key}\n"
        )


def _install_openclaw_config(
    request: InstallConfigRequest, snippet: str
) -> InstallConfigResponse:
    """Write Snapper config into OpenClaw's openclaw.json and copy plugin files."""
    oc_dir = Path.home() / ".openclaw"
    config_path = oc_dir / "openclaw.json"

    if not oc_dir.is_dir():
        return InstallConfigResponse(
            installed=False,
            message=f"{oc_dir} not found. Merge this into your openclaw.json:",
            config_snippet=snippet,
        )

    try:
        # Read existing config or start fresh
        if config_path.exists():
            config = json.loads(config_path.read_text())
        else:
            config = {}

        # Merge plugin config
        plugins = config.setdefault("plugins", {})
        entries = plugins.setdefault("entries", {})
        sg = entries.setdefault("snapper-guard", {})
        sg["enabled"] = True
        sg_config = sg.setdefault("config", {})
        sg_config["snapperUrl"] = request.snapper_url
        sg_config["agentId"] = request.agent_id
        sg_config["apiKey"] = request.api_key

        config_path.write_text(json.dumps(config, indent=2) + "\n")

        # Copy plugin files if missing
        ext_dir = oc_dir / "extensions" / "snapper-guard"
        plugin_src = Path(__file__).resolve().parent.parent.parent / "plugins" / "snapper-guard"
        if plugin_src.is_dir() and not ext_dir.exists():
            shutil.copytree(plugin_src, ext_dir)

        return InstallConfigResponse(
            installed=True,
            message=f"Config written to {config_path}. Restart OpenClaw to activate.",
            config_snippet=snippet,
        )
    except Exception as exc:
        return InstallConfigResponse(
            installed=False,
            message=f"Could not write config: {exc}",
            config_snippet=snippet,
        )


def _install_claude_code_config(
    request: InstallConfigRequest, snippet: str
) -> InstallConfigResponse:
    """Write Snapper hook + env + settings for Claude Code."""
    claude_dir = Path.home() / ".claude"

    if not claude_dir.is_dir():
        return InstallConfigResponse(
            installed=False,
            message=f"{claude_dir} not found. Create it or install Claude Code first.",
            config_snippet=snippet,
        )

    try:
        # 1. Write env file
        env_path = claude_dir / ".env.snapper"
        env_path.write_text(
            f"SNAPPER_URL={request.snapper_url}\n"
            f"SNAPPER_AGENT_ID={request.agent_id}\n"
            f"SNAPPER_API_KEY={request.api_key}\n"
        )

        # 2. Copy hook script
        hooks_dir = claude_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_dest = hooks_dir / "snapper_pre_tool_use.sh"
        hook_src = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts"
            / "claude-code-hook.sh"
        )
        if hook_src.exists():
            shutil.copy2(hook_src, hook_dest)
            hook_dest.chmod(0o755)
        else:
            return InstallConfigResponse(
                installed=False,
                message=f"Hook source not found at {hook_src}.",
                config_snippet=snippet,
            )

        # Patch hook to source env file instead of using hardcoded defaults
        hook_text = hook_dest.read_text()
        env_source_line = (
            '# Source Snapper env\n'
            '[ -f ~/.claude/.env.snapper ] && set -a && . ~/.claude/.env.snapper && set +a\n\n'
        )
        if ".env.snapper" not in hook_text:
            hook_text = hook_text.replace(
                "#!/bin/bash\n",
                f"#!/bin/bash\n{env_source_line}",
                1,
            )
            hook_dest.write_text(hook_text)

        # 3. Merge PreToolUse hook into settings.json
        settings_path = claude_dir / "settings.json"
        if settings_path.exists():
            settings = json.loads(settings_path.read_text())
        else:
            settings = {}

        hooks = settings.setdefault("hooks", {})
        pre_tool_use = hooks.setdefault("PreToolUse", [])

        hook_command = str(hook_dest)
        # Check if our hook is already registered
        already_registered = any(
            any(
                h.get("command", "").endswith("snapper_pre_tool_use.sh")
                for h in entry.get("hooks", [])
            )
            for entry in pre_tool_use
        )

        if not already_registered:
            pre_tool_use.append(
                {
                    "matcher": "",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                        }
                    ],
                }
            )

        settings_path.write_text(json.dumps(settings, indent=2) + "\n")

        return InstallConfigResponse(
            installed=True,
            message=(
                f"Hook installed to {hook_dest}, env written to {env_path}, "
                f"settings updated at {settings_path}. "
                f"Restart Claude Code to activate."
            ),
            config_snippet=snippet,
        )
    except Exception as exc:
        return InstallConfigResponse(
            installed=False,
            message=f"Could not write config: {exc}",
            config_snippet=snippet,
        )


def _install_cursor_config(
    request: InstallConfigRequest, snippet: str
) -> InstallConfigResponse:
    """Write Snapper hook + env + hooks.json for Cursor."""
    cursor_dir = Path.home() / ".cursor"

    if not cursor_dir.is_dir():
        return InstallConfigResponse(
            installed=False,
            message=f"{cursor_dir} not found. Install Cursor first.",
            config_snippet=snippet,
        )

    try:
        # 1. Write env file
        env_path = cursor_dir / ".env.snapper"
        env_path.write_text(
            f"SNAPPER_URL={request.snapper_url}\n"
            f"SNAPPER_AGENT_ID={request.agent_id}\n"
            f"SNAPPER_API_KEY={request.api_key}\n"
        )

        # 2. Copy hook script
        hooks_dir = cursor_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_dest = hooks_dir / "snapper_pre_tool_use.sh"
        hook_src = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts"
            / "cursor-hook.sh"
        )
        if hook_src.exists():
            shutil.copy2(hook_src, hook_dest)
            hook_dest.chmod(0o755)
        else:
            return InstallConfigResponse(
                installed=False,
                message=f"Hook source not found at {hook_src}.",
                config_snippet=snippet,
            )

        # 3. Merge preToolUse into hooks.json
        hooks_json_path = hooks_dir / "hooks.json"
        if hooks_json_path.exists():
            hooks_config = json.loads(hooks_json_path.read_text())
        else:
            hooks_config = {}

        pre_tool_use = hooks_config.setdefault("preToolUse", [])
        hook_command = str(hook_dest)

        already_registered = any(
            e.get("command", "").endswith("snapper_pre_tool_use.sh")
            for e in pre_tool_use
        )
        if not already_registered:
            pre_tool_use.append({"command": hook_command})

        hooks_json_path.write_text(json.dumps(hooks_config, indent=2) + "\n")

        return InstallConfigResponse(
            installed=True,
            message=(
                f"Hook installed to {hook_dest}, env written to {env_path}, "
                f"hooks.json updated at {hooks_json_path}. "
                f"Restart Cursor to activate."
            ),
            config_snippet=snippet,
        )
    except Exception as exc:
        return InstallConfigResponse(
            installed=False,
            message=f"Could not write config: {exc}",
            config_snippet=snippet,
        )


def _install_windsurf_config(
    request: InstallConfigRequest, snippet: str
) -> InstallConfigResponse:
    """Write Snapper hook + env + hooks.json for Windsurf."""
    windsurf_dir = Path.home() / ".codeium" / "windsurf"

    if not windsurf_dir.is_dir():
        return InstallConfigResponse(
            installed=False,
            message=f"{windsurf_dir} not found. Install Windsurf first.",
            config_snippet=snippet,
        )

    try:
        # 1. Write env file
        env_path = windsurf_dir / ".env.snapper"
        env_path.write_text(
            f"SNAPPER_URL={request.snapper_url}\n"
            f"SNAPPER_AGENT_ID={request.agent_id}\n"
            f"SNAPPER_API_KEY={request.api_key}\n"
        )

        # 2. Copy hook script
        hooks_dir = windsurf_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_dest = hooks_dir / "snapper_pre_tool_use.sh"
        hook_src = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts"
            / "windsurf-hook.sh"
        )
        if hook_src.exists():
            shutil.copy2(hook_src, hook_dest)
            hook_dest.chmod(0o755)
        else:
            return InstallConfigResponse(
                installed=False,
                message=f"Hook source not found at {hook_src}.",
                config_snippet=snippet,
            )

        # 3. Merge hooks into hooks.json
        hooks_json_path = hooks_dir / "hooks.json"
        if hooks_json_path.exists():
            hooks_config = json.loads(hooks_json_path.read_text())
        else:
            hooks_config = {}

        hook_command = str(hook_dest)
        for hook_type in ("pre_run_command", "pre_write_code", "pre_mcp_tool_use"):
            entries = hooks_config.setdefault(hook_type, [])
            already_registered = any(
                e.get("command", "").endswith("snapper_pre_tool_use.sh")
                for e in entries
            )
            if not already_registered:
                entries.append({"command": hook_command})

        hooks_json_path.write_text(json.dumps(hooks_config, indent=2) + "\n")

        return InstallConfigResponse(
            installed=True,
            message=(
                f"Hook installed to {hook_dest}, env written to {env_path}, "
                f"hooks.json updated at {hooks_json_path}. "
                f"Restart Windsurf to activate."
            ),
            config_snippet=snippet,
        )
    except Exception as exc:
        return InstallConfigResponse(
            installed=False,
            message=f"Could not write config: {exc}",
            config_snippet=snippet,
        )


def _install_cline_config(
    request: InstallConfigRequest, snippet: str
) -> InstallConfigResponse:
    """Write Snapper hook + env for Cline."""
    cline_dir = Path.home() / ".cline"

    try:
        # Create dir if needed (Cline uses global dir)
        cline_dir.mkdir(exist_ok=True)

        # 1. Write env file
        env_path = cline_dir / ".env.snapper"
        env_path.write_text(
            f"SNAPPER_URL={request.snapper_url}\n"
            f"SNAPPER_AGENT_ID={request.agent_id}\n"
            f"SNAPPER_API_KEY={request.api_key}\n"
        )

        # 2. Copy hook script (no extension — Cline auto-discovers executables)
        hooks_dir = cline_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        hook_dest = hooks_dir / "pre_tool_use"
        hook_src = (
            Path(__file__).resolve().parent.parent.parent
            / "scripts"
            / "cline-hook.sh"
        )
        if hook_src.exists():
            shutil.copy2(hook_src, hook_dest)
            hook_dest.chmod(0o755)
        else:
            return InstallConfigResponse(
                installed=False,
                message=f"Hook source not found at {hook_src}.",
                config_snippet=snippet,
            )

        return InstallConfigResponse(
            installed=True,
            message=(
                f"Hook installed to {hook_dest}, env written to {env_path}. "
                f"Restart VS Code / Cline to activate."
            ),
            config_snippet=snippet,
        )
    except Exception as exc:
        return InstallConfigResponse(
            installed=False,
            message=f"Could not write config: {exc}",
            config_snippet=snippet,
        )


async def _apply_security_profile(
    db: AsyncSession, agent_id, profile: str
) -> int:
    """Apply security profile rules to an agent.

    Returns the number of rules applied.
    """
    from app.models.rules import Rule, RuleAction, RuleType

    profiles = {
        "strict": [
            {
                "name": "Strict Command Control",
                "rule_type": RuleType.COMMAND_DENYLIST,
                "action": RuleAction.DENY,
                "priority": 100,
                "parameters": {
                    "patterns": [
                        r"^rm\s",
                        r"^sudo\s",
                        r"^chmod\s",
                        r"^chown\s",
                        r"curl.*\|.*sh",
                        r"wget.*\|.*sh",
                    ]
                },
            },
            {
                "name": "Strict File Protection",
                "rule_type": RuleType.CREDENTIAL_PROTECTION,
                "action": RuleAction.DENY,
                "priority": 100,
                "parameters": {
                    "protected_patterns": [r"\.env", r"\.pem", r"\.key", r"id_rsa"],
                    "block_plaintext_secrets": True,
                },
            },
            {
                "name": "Strict Human Approval",
                "rule_type": RuleType.HUMAN_IN_LOOP,
                "action": RuleAction.REQUIRE_APPROVAL,
                "priority": 90,
                "parameters": {
                    "require_approval_for": [
                        "file_write",
                        "file_delete",
                        "command_execute",
                    ],
                    "timeout_seconds": 300,
                },
            },
            {
                "name": "Strict Rate Limit",
                "rule_type": RuleType.RATE_LIMIT,
                "action": RuleAction.DENY,
                "priority": 80,
                "parameters": {"max_requests": 100, "window_seconds": 60},
            },
        ],
        "recommended": [
            {
                "name": "Block Dangerous Commands",
                "rule_type": RuleType.COMMAND_DENYLIST,
                "action": RuleAction.DENY,
                "priority": 100,
                "parameters": {
                    "patterns": [
                        r"^rm\s+-rf\s+/",
                        r"curl.*\|.*sh",
                        r"wget.*\|.*sh",
                        r":(){:|:&};:",
                    ]
                },
            },
            {
                "name": "Credential Protection",
                "rule_type": RuleType.CREDENTIAL_PROTECTION,
                "action": RuleAction.DENY,
                "priority": 100,
                "parameters": {
                    "protected_patterns": [r"\.env$", r"\.pem$", r"id_rsa$"],
                },
            },
            {
                "name": "Standard Rate Limit",
                "rule_type": RuleType.RATE_LIMIT,
                "action": RuleAction.DENY,
                "priority": 80,
                "parameters": {"max_requests": 500, "window_seconds": 60},
            },
        ],
        "permissive": [
            {
                "name": "Log All Commands",
                "rule_type": RuleType.COMMAND_DENYLIST,
                "action": RuleAction.LOG_ONLY,
                "priority": 50,
                "parameters": {"patterns": [".*"]},
            },
            {
                "name": "Permissive Rate Limit",
                "rule_type": RuleType.RATE_LIMIT,
                "action": RuleAction.DENY,
                "priority": 80,
                "parameters": {"max_requests": 2000, "window_seconds": 60},
            },
        ],
    }

    rules_to_apply = profiles.get(profile, profiles["recommended"])
    count = 0

    for rule_data in rules_to_apply:
        rule = Rule(
            id=uuid4(),
            name=rule_data["name"],
            agent_id=agent_id,
            rule_type=rule_data["rule_type"],
            action=rule_data["action"],
            priority=rule_data["priority"],
            parameters=rule_data["parameters"],
            is_active=True,
        )
        db.add(rule)
        count += 1

    return count
