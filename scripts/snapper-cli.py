#!/usr/bin/env python3
"""
Snapper CLI - Agent Application Firewall

Usage:
    snapper init               # Auto-detect agent, register, install hooks (recommended)
    snapper init --agent cursor # Specify agent type explicitly
    snapper security-check     # Assess security posture of deployment
    snapper setup              # Legacy: full setup for OpenClaw only
    snapper integrate          # Legacy: just configure OpenClaw hooks
    snapper status             # Check Snapper and agent status
    snapper test               # Test the integration
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SNAPPER_URL = os.environ.get("SNAPPER_URL", "http://localhost:8000")
SNAPPER_DIR = Path.home() / "snapper"

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_banner():
    print(f"""
{BLUE}╔══════════════════════════════════════════════════════════════╗
║  🐢 Snapper - Security for AI Agents                         ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")


def check_snapper_running():
    """Check if Snapper is running."""
    try:
        import urllib.request
        req = urllib.request.Request(f"{SNAPPER_URL}/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_agent_id():
    """Generate a unique agent ID for this machine."""
    import socket
    hostname = socket.gethostname()
    return f"openclaw-{hostname}"


def detect_openclaw():
    """Detect OpenClaw installation."""
    locations = [
        Path.home() / ".openclaw",
        Path.home() / ".config" / "openclaw",
        Path("/etc/openclaw"),
    ]

    for loc in locations:
        if loc.exists():
            return loc

    # Check if openclaw command exists
    if shutil.which("openclaw"):
        # Create config dir
        config_dir = Path.home() / ".openclaw"
        config_dir.mkdir(exist_ok=True)
        return config_dir

    return None


def detect_claude_code():
    """Detect Claude Code installation."""
    claude_dir = Path.home() / ".claude"
    if claude_dir.is_dir():
        return claude_dir
    return None


def detect_cursor():
    """Detect Cursor installation."""
    cursor_dir = Path.home() / ".cursor"
    if cursor_dir.is_dir():
        return cursor_dir
    return None


def detect_windsurf():
    """Detect Windsurf (Codeium) installation."""
    windsurf_dir = Path.home() / ".codeium" / "windsurf"
    if windsurf_dir.is_dir():
        return windsurf_dir
    return None


def detect_cline():
    """Detect Cline installation."""
    # Check global config
    cline_dir = Path.home() / ".cline"
    if cline_dir.is_dir():
        return cline_dir
    # Check project-level config
    cwd_rules = Path.cwd() / ".clinerules"
    if cwd_rules.is_dir():
        return cwd_rules
    return None


# All supported agent types with their detection functions and labels
AGENT_TYPES = {
    "openclaw": {"detect": detect_openclaw, "label": "OpenClaw"},
    "claude-code": {"detect": detect_claude_code, "label": "Claude Code"},
    "cursor": {"detect": detect_cursor, "label": "Cursor"},
    "windsurf": {"detect": detect_windsurf, "label": "Windsurf"},
    "cline": {"detect": detect_cline, "label": "Cline"},
}


def register_agent(agent_id: str, name: str = None):
    """Register agent with Snapper."""
    import urllib.request

    if not name:
        import socket
        name = f"OpenClaw on {socket.gethostname()}"

    payload = json.dumps({
        "name": name,
        "external_id": agent_id,
        "description": "Auto-registered by snapper-cli",
        "require_localhost_only": True,
    }).encode()

    req = urllib.request.Request(
        f"{SNAPPER_URL}/api/v1/agents",
        data=payload,
        headers={
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("id")
    except urllib.error.HTTPError as e:
        if e.code == 409:  # Conflict - agent already exists
            print(f"{YELLOW}Agent already registered{RESET}")
            # Get existing agent
            return get_existing_agent(agent_id)
        raise


def get_existing_agent(external_id: str):
    """Get existing agent by external_id."""
    import urllib.request

    req = urllib.request.Request(
        f"{SNAPPER_URL}/api/v1/agents?external_id={external_id}",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("items"):
                return data["items"][0]["id"]
    except Exception:
        pass
    return None


def apply_security_profile(agent_id: str, profile: str = "recommended", agent_type: str = None):
    """Apply security profile to agent."""
    import urllib.request

    templates = {
        "recommended": [
            "cve-2026-25253-mitigation",
            "credential-protection",
            "malicious-skill-blocker",
            "rate-limit-standard",
        ],
        "strict": [
            "cve-2026-25253-mitigation",
            "credential-protection",
            "malicious-skill-blocker",
            "rate-limit-standard",
            "localhost-only",
            "human-approval-sensitive",
        ],
        "permissive": [
            "credential-protection",
        ],
    }

    # Add OpenClaw-specific templates
    if agent_type == "openclaw":
        for profile_rules in templates.values():
            profile_rules.extend([
                "openclaw-safe-commands",
                "openclaw-block-dangerous",
                "openclaw-require-approval",
                "pii-gate-protection",
            ])

    rules_to_apply = templates.get(profile, templates["recommended"])

    for template_id in rules_to_apply:
        payload = json.dumps({"agent_id": agent_id}).encode()
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/rules/templates/{template_id}/apply",
            data=payload,
            headers={
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                print(f"  {GREEN}✓{RESET} {data.get('name', template_id)}")
        except urllib.error.HTTPError as e:
            if e.code == 409:  # Rule already exists
                print(f"  {YELLOW}○{RESET} {template_id} (already applied)")
            else:
                print(f"  {RED}✗{RESET} {template_id} ({e.code})")
        except Exception as e:
            print(f"  {RED}✗{RESET} {template_id} ({e})")


def activate_agent(agent_uuid: str):
    """Activate the agent."""
    import urllib.request

    payload = json.dumps({"status": "active"}).encode()
    req = urllib.request.Request(
        f"{SNAPPER_URL}/api/v1/agents/{agent_uuid}",
        data=payload,
        headers={
            "Content-Type": "application/json",
        },
        method="PUT",
    )

    try:
        with urllib.request.urlopen(req, timeout=10):
            return True
    except Exception:
        return False


def install_hook(openclaw_dir: Path, agent_id: str):
    """Install the PreToolUse hook for OpenClaw."""
    hooks_dir = openclaw_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre_tool_use.sh"

    # Get the hook script from Snapper installation
    snapper_hook = SNAPPER_DIR / "scripts" / "openclaw-hook.sh"

    if snapper_hook.exists():
        shutil.copy(snapper_hook, hook_path)
    else:
        # Download from GitHub
        import urllib.request
        url = "https://raw.githubusercontent.com/jmckinley/snapper/main/scripts/openclaw-hook.sh"
        try:
            urllib.request.urlretrieve(url, hook_path)
        except Exception:
            # Write inline version
            hook_content = f'''#!/bin/bash
# Snapper PreToolUse Hook
SNAPPER_URL="{SNAPPER_URL}"
SNAPPER_AGENT_ID="{agent_id}"
INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"')
RESPONSE=$(curl -sf -X POST "$SNAPPER_URL/api/v1/rules/evaluate" \\
    -H "Content-Type: application/json" \\
    -H "Origin: http://localhost:8000" \\
    -d "{{\\"agent_id\\": \\"$SNAPPER_AGENT_ID\\", \\"request_type\\": \\"tool\\", \\"tool_name\\": \\"$TOOL_NAME\\"}}" 2>/dev/null)
[ $? -ne 0 ] && exit 1
DECISION=$(echo "$RESPONSE" | jq -r '.decision')
[ "$DECISION" = "allow" ] && exit 0
echo "BLOCKED: $(echo "$RESPONSE" | jq -r '.reason')" >&2
exit 1
'''
            hook_path.write_text(hook_content)

    # Make executable
    hook_path.chmod(0o755)

    # Create/update env file
    env_file = openclaw_dir / ".env"
    env_content = f"""# Snapper Integration
SNAPPER_URL={SNAPPER_URL}
SNAPPER_AGENT_ID={agent_id}
"""

    if env_file.exists():
        existing = env_file.read_text()
        if "SNAPPER_URL" not in existing:
            env_file.write_text(existing + "\n" + env_content)
    else:
        env_file.write_text(env_content)

    return hook_path


def _quick_register(agent_type, profile, name=None):
    """Register agent via the quick-register API and install config.

    Returns (agent_id, api_key) on success, or exits on failure.
    """
    import urllib.request

    payload = json.dumps({
        "agent_type": agent_type,
        "name": name or "",
        "security_profile": profile,
    }).encode()

    req = urllib.request.Request(
        f"{SNAPPER_URL}/api/v1/setup/quick-register",
        data=payload,
        headers={
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data["agent_id"], data["api_key"], data["name"], data["rules_applied"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = body
        print(f"  {RED}✗{RESET} Registration failed: {detail}")
        sys.exit(1)


def _install_config(agent_type, agent_id, api_key):
    """Call install-config API and return (installed: bool, message: str)."""
    import urllib.request

    payload = json.dumps({
        "agent_type": agent_type,
        "agent_id": agent_id,
        "api_key": api_key,
        "snapper_url": SNAPPER_URL,
    }).encode()

    req = urllib.request.Request(
        f"{SNAPPER_URL}/api/v1/setup/install-config",
        data=payload,
        headers={
            "Content-Type": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            return data.get("installed", False), data.get("message", ""), data.get("config_snippet", "")
    except Exception as e:
        return False, str(e), ""


def cmd_init(args):
    """Auto-detect agent, register, apply profile, install config."""
    print_banner()

    # Step 1: Check Snapper
    print(f"{BOLD}Step 1: Checking Snapper...{RESET}")
    if check_snapper_running():
        print(f"  {GREEN}✓{RESET} Snapper is running at {SNAPPER_URL}")
    else:
        print(f"  {RED}✗{RESET} Snapper is not running at {SNAPPER_URL}")
        print(f"    Start it with: docker compose up -d")
        print(f"    Or set SNAPPER_URL to point to your instance.")
        sys.exit(1)

    # Step 2: Detect agents
    agent_type = getattr(args, "agent", None)

    if agent_type:
        # Explicit agent type provided
        label = AGENT_TYPES.get(agent_type, {}).get("label", agent_type)
        print(f"\n{BOLD}Step 2: Using specified agent type: {label}{RESET}")
    else:
        print(f"\n{BOLD}Step 2: Detecting AI agents...{RESET}")
        found = []
        for atype, info in AGENT_TYPES.items():
            result = info["detect"]()
            if result:
                found.append((atype, info["label"], result))
                print(f"  {GREEN}✓{RESET} {info['label']} found at {result}")

        if len(found) == 0:
            print(f"  {YELLOW}○{RESET} No agents detected.")
            print(f"\n  Available agent types:")
            for i, (atype, info) in enumerate(AGENT_TYPES.items(), 1):
                print(f"    {i}. {info['label']} ({atype})")
            print(f"    6. Custom agent")

            try:
                choice = input(f"\n  Select agent type [1-6]: ").strip()
                idx = int(choice) - 1
                if idx == 5:
                    agent_type = "custom"
                else:
                    agent_type = list(AGENT_TYPES.keys())[idx]
            except (ValueError, IndexError, KeyboardInterrupt):
                print(f"\n{RED}Cancelled.{RESET}")
                sys.exit(1)
        elif len(found) == 1:
            agent_type = found[0][0]
            print(f"  Auto-selected: {found[0][1]}")
        else:
            print(f"\n  Multiple agents found. Select one:")
            for i, (atype, label, path) in enumerate(found, 1):
                print(f"    {i}. {label} ({path})")
            try:
                choice = input(f"\n  Select [1-{len(found)}]: ").strip()
                idx = int(choice) - 1
                agent_type = found[idx][0]
            except (ValueError, IndexError, KeyboardInterrupt):
                print(f"\n{RED}Cancelled.{RESET}")
                sys.exit(1)

    profile = getattr(args, "profile", "recommended")

    # Step 3: Register
    print(f"\n{BOLD}Step 3: Registering agent ({profile} profile)...{RESET}")
    agent_id, api_key, name, rules_applied = _quick_register(agent_type, profile)
    print(f"  {GREEN}✓{RESET} Registered: {name}")
    print(f"  {GREEN}✓{RESET} {rules_applied} security rules applied")

    # Step 4: Install config
    print(f"\n{BOLD}Step 4: Installing configuration...{RESET}")
    if agent_type == "custom":
        print(f"  {YELLOW}○{RESET} Manual configuration required for custom agents.")
        snippet = (
            f"# Add to your agent's config\n"
            f"SNAPPER_URL={SNAPPER_URL}\n"
            f"SNAPPER_AGENT_ID={agent_id}\n"
            f"SNAPPER_API_KEY={api_key}\n"
        )
        print(f"\n{BOLD}Config snippet:{RESET}")
        print(f"  {snippet.replace(chr(10), chr(10) + '  ')}")
    else:
        installed, message, snippet = _install_config(agent_type, agent_id, api_key)
        if installed:
            print(f"  {GREEN}✓{RESET} {message}")
        else:
            print(f"  {YELLOW}○{RESET} {message}")
            if snippet:
                print(f"\n{BOLD}Manual config:{RESET}")
                for line in snippet.split("\n"):
                    print(f"  {line}")

    # Done
    label = AGENT_TYPES.get(agent_type, {}).get("label", agent_type)
    print(f"""
{GREEN}╔══════════════════════════════════════════════════════════════╗
║  Setup Complete!                                             ║
╚══════════════════════════════════════════════════════════════╝{RESET}

Your {label} agent is now protected by Snapper!

{BOLD}Agent ID:{RESET}  {agent_id}
{BOLD}API Key:{RESET}   {api_key}

{BOLD}Quick links:{RESET}
  Dashboard:  {BLUE}{SNAPPER_URL}{RESET}
  Rules:      {BLUE}{SNAPPER_URL}/rules{RESET}
  Audit logs: {BLUE}{SNAPPER_URL}/audit{RESET}

{BOLD}Next:{RESET}
  1. Restart {label} to activate the hook
  2. Run: python {sys.argv[0]} test
""")


def cmd_setup(args):
    """Full setup: install Snapper + integrate with OpenClaw."""
    print_banner()

    # Step 1: Check if Snapper is running
    print(f"{BOLD}Step 1: Checking Snapper...{RESET}")
    if check_snapper_running():
        print(f"  {GREEN}✓{RESET} Snapper is running at {SNAPPER_URL}")
    else:
        print(f"  {YELLOW}○{RESET} Snapper not running. Starting...")
        # Run install script
        install_script = SNAPPER_DIR / "install.sh"
        if install_script.exists():
            subprocess.run(["bash", str(install_script)], check=True)
        else:
            print(f"  {RED}✗{RESET} Please install Snapper first:")
            print(f"    curl -fsSL https://raw.githubusercontent.com/jmckinley/snapper/main/install.sh | bash")
            sys.exit(1)

    # Step 2: Detect OpenClaw
    print(f"\n{BOLD}Step 2: Detecting OpenClaw...{RESET}")
    openclaw_dir = detect_openclaw()
    if openclaw_dir:
        print(f"  {GREEN}✓{RESET} Found OpenClaw at {openclaw_dir}")
    else:
        print(f"  {YELLOW}○{RESET} OpenClaw not detected. Creating config directory...")
        openclaw_dir = Path.home() / ".openclaw"
        openclaw_dir.mkdir(exist_ok=True)

    # Step 3: Register agent
    print(f"\n{BOLD}Step 3: Registering agent...{RESET}")
    agent_id = get_agent_id()
    try:
        agent_uuid = register_agent(agent_id)
        if agent_uuid:
            print(f"  {GREEN}✓{RESET} Agent registered: {agent_id}")
            activate_agent(agent_uuid)
        else:
            print(f"  {YELLOW}○{RESET} Using existing agent: {agent_id}")
            agent_uuid = agent_id
    except Exception as e:
        print(f"  {RED}✗{RESET} Failed to register: {e}")
        sys.exit(1)

    # Step 4: Apply security profile
    print(f"\n{BOLD}Step 4: Applying security rules ({args.profile})...{RESET}")
    apply_security_profile(agent_uuid, args.profile)

    # Step 5: Install hook
    print(f"\n{BOLD}Step 5: Installing OpenClaw hook...{RESET}")
    hook_path = install_hook(openclaw_dir, agent_id)
    print(f"  {GREEN}✓{RESET} Hook installed at {hook_path}")

    # Done!
    print(f"""
{GREEN}╔══════════════════════════════════════════════════════════════╗
║  ✅ Setup Complete!                                          ║
╚══════════════════════════════════════════════════════════════╝{RESET}

Your OpenClaw is now protected by Snapper!

{BOLD}What's protected:{RESET}
  • Credential files (.env, .pem, SSH keys)
  • Known malicious ClawHub skills
  • WebSocket RCE attacks (CVE-2026-25253)
  • Rate limiting to prevent runaway agents

{BOLD}Quick links:{RESET}
  Dashboard:  {BLUE}http://localhost:8000{RESET}
  Rules:      {BLUE}http://localhost:8000/rules{RESET}
  Audit logs: {BLUE}http://localhost:8000/audit{RESET}

{BOLD}Test it:{RESET}
  snapper test

{BOLD}Get notifications:{RESET}
  Set up Telegram alerts at {BLUE}http://localhost:8000/settings{RESET}
""")


def cmd_integrate(args):
    """Just integrate with OpenClaw (Snapper already running)."""
    print_banner()

    if not check_snapper_running():
        print(f"{RED}Error: Snapper is not running.{RESET}")
        print(f"Start it first or run: snapper setup")
        sys.exit(1)

    openclaw_dir = detect_openclaw()
    if not openclaw_dir:
        openclaw_dir = Path.home() / ".openclaw"
        openclaw_dir.mkdir(exist_ok=True)

    agent_id = get_agent_id()
    agent_uuid = register_agent(agent_id)
    if agent_uuid:
        activate_agent(agent_uuid)
        apply_security_profile(agent_uuid, args.profile)

    hook_path = install_hook(openclaw_dir, agent_id)
    print(f"{GREEN}✓ OpenClaw integrated with Snapper{RESET}")
    print(f"  Hook: {hook_path}")


def cmd_status(args):
    """Check status of Snapper and agents."""
    print_banner()

    print(f"{BOLD}Snapper Status:{RESET}")
    if check_snapper_running():
        print(f"  {GREEN}● Running{RESET} at {SNAPPER_URL}")
    else:
        print(f"  {RED}● Not running{RESET}")
        return

    agent_id = get_agent_id()
    print(f"\n{BOLD}Agent: {agent_id}{RESET}")

    # Check if agent is registered
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/agents?external_id={agent_id}",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("items"):
                agent = data["items"][0]
                status_color = GREEN if agent["status"] == "active" else YELLOW
                print(f"  Status: {status_color}{agent['status']}{RESET}")
                print(f"  Trust level: {agent['trust_level']}")
            else:
                print(f"  {YELLOW}Not registered{RESET}")
    except Exception as e:
        print(f"  {RED}Error checking status: {e}{RESET}")


def _set_env_var(env_file: Path, key: str, value: str):
    """Set a variable in .env file. Updates existing or appends new."""
    content = env_file.read_text()
    lines = content.splitlines()
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(f"{key}=") or stripped.startswith(f"# {key}="):
            lines[i] = f"{key}={value}"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}")
    env_file.write_text("\n".join(lines) + "\n")


def _detect_server_ip():
    """Try to detect the server's public IP."""
    import urllib.request
    try:
        req = urllib.request.Request("https://ifconfig.me", headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode().strip()
    except Exception:
        pass
    # Fallback: hostname -I
    import subprocess as sp
    try:
        result = sp.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().split()[0]
    except Exception:
        pass
    return None


# Docs base URL for help links
DOCS_URL = "https://github.com/jmckinley/snapper/blob/main/docs"


def cmd_security_check(args):
    """Assess the security posture of the Snapper deployment."""
    print_banner()
    fix_mode = getattr(args, "fix", False)

    if fix_mode:
        print(f"{BOLD}Security Posture Assessment + Auto-Fix{RESET}\n")
    else:
        print(f"{BOLD}Security Posture Assessment{RESET}\n")

    pass_count = 0
    warn_count = 0
    fail_count = 0
    fixed_count = 0
    needs_restart = False

    def sec_pass(msg):
        nonlocal pass_count
        print(f"  {GREEN}PASS{RESET}  {msg}")
        pass_count += 1

    def sec_warn(msg, action=None, help_url=None, severity=None):
        nonlocal warn_count
        sev = f" [{severity}]" if severity else ""
        print(f"  {YELLOW}WARN{RESET}  {msg}{sev}")
        if action:
            print(f"         {action}")
        if help_url:
            print(f"         See: {BLUE}{help_url}{RESET}")
        warn_count += 1

    def sec_fail(msg, fix=None, help_url=None, severity=None):
        nonlocal fail_count
        sev = f" [{severity}]" if severity else ""
        print(f"  {RED}FAIL{RESET}  {msg}{sev}")
        if fix:
            print(f"         Fix: {fix}")
        if help_url:
            print(f"         See: {BLUE}{help_url}{RESET}")
        fail_count += 1

    def sec_fixed(msg):
        nonlocal fixed_count, needs_restart
        print(f"  {GREEN}FIXED{RESET} {msg}")
        fixed_count += 1
        needs_restart = True

    # 1. Snapper running
    if check_snapper_running():
        sec_pass(f"Snapper is running at {SNAPPER_URL}")
    else:
        sec_fail(f"Snapper is not running at {SNAPPER_URL}",
                 fix="Start with: docker compose up -d",
                 help_url=f"{DOCS_URL}/GETTING_STARTED.md",
                 severity="mandatory")
        print(f"\n  {RED}Cannot continue checks without Snapper running.{RESET}")
        return

    # 2. HTTPS vs HTTP
    if SNAPPER_URL.startswith("https://"):
        sec_pass("SNAPPER_URL uses HTTPS")
    else:
        sec_warn("SNAPPER_URL uses HTTP — traffic is unencrypted",
                 action="Configure Caddy reverse proxy with TLS, then set SNAPPER_URL=https://...",
                 help_url=f"{DOCS_URL}/SECURITY.md#reverse-proxy-caddy-required-for-production",
                 severity="mandatory for production")

    # 3. Check health/ready for DB + Redis
    import urllib.request
    try:
        req = urllib.request.Request(f"{SNAPPER_URL}/health/ready")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            if data.get("status") == "ready":
                sec_pass("Database and Redis connected")
            else:
                sec_warn(f"Health check returned: {data.get('status', 'unknown')}")
    except Exception:
        sec_warn("Could not reach /health/ready endpoint")

    # 4. Check Docker
    docker_check = shutil.which("docker")
    if docker_check:
        import subprocess as sp
        try:
            result = sp.run(["docker", "compose", "ps", "--format", "json"],
                            capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and "app" in result.stdout:
                sec_pass("Running in Docker containers")
            else:
                sec_warn("Docker detected but Snapper containers not found",
                         help_url=f"{DOCS_URL}/SECURITY.md#docker-is-mandatory",
                         severity="mandatory")
        except Exception:
            sec_warn("Could not verify Docker container status")
    else:
        sec_fail("Docker not found on this host",
                 fix="Snapper must run in Docker — DB and Redis have no auth without it",
                 help_url=f"{DOCS_URL}/SECURITY.md#docker-is-mandatory",
                 severity="mandatory")

    # 5. Check .env file for security settings
    env_file = Path.cwd() / ".env"
    if not env_file.exists():
        env_file = Path("/opt/snapper/.env")

    if env_file.exists():
        env_content = env_file.read_text()
        env_vars = {}
        for line in env_content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                env_vars[key.strip()] = val.strip()

        # SECRET_KEY
        sk = env_vars.get("SECRET_KEY", "")
        if not sk or sk == "development-secret-key-change-in-production":
            if fix_mode:
                import subprocess as sp
                try:
                    result = sp.run(["openssl", "rand", "-hex", "32"],
                                    capture_output=True, text=True, timeout=5)
                    new_key = result.stdout.strip()
                    if len(new_key) >= 32:
                        _set_env_var(env_file, "SECRET_KEY", new_key)
                        sec_fixed(f"SECRET_KEY generated ({len(new_key)} chars)")
                        print(f"         {RED}WARNING: If vault entries exist, they will be unrecoverable!{RESET}")
                    else:
                        sec_fail("Could not generate SECRET_KEY")
                except Exception:
                    sec_fail("Could not generate SECRET_KEY (openssl not found)")
            else:
                sec_fail("SECRET_KEY is empty or default",
                         fix="Run with --fix to auto-generate, or: openssl rand -hex 32",
                         help_url=f"{DOCS_URL}/SECURITY.md#secret_key-is-immutable-after-vault-use",
                         severity="mandatory")
        elif len(sk) < 32:
            sec_fail(f"SECRET_KEY too short ({len(sk)} chars, need 32+)",
                     help_url=f"{DOCS_URL}/SECURITY.md#secret_key-is-immutable-after-vault-use",
                     severity="mandatory")
        else:
            sec_pass(f"SECRET_KEY is set ({len(sk)} chars)")

        # --- Auto-fixable .env settings ---

        # LEARNING_MODE
        lm = env_vars.get("LEARNING_MODE", "true").lower()
        if lm == "true":
            if fix_mode:
                _set_env_var(env_file, "LEARNING_MODE", "false")
                sec_fixed("LEARNING_MODE=false (rules now enforced)")
            else:
                sec_warn("Learning mode is ON — violations logged but not blocked",
                         action="Run with --fix to set LEARNING_MODE=false",
                         severity="recommended")
        else:
            sec_pass("Learning mode is OFF — rules are enforced")

        # DENY_BY_DEFAULT
        dbd = env_vars.get("DENY_BY_DEFAULT", "false").lower()
        if dbd == "true":
            sec_pass("Deny-by-default is ON")
        else:
            if fix_mode:
                _set_env_var(env_file, "DENY_BY_DEFAULT", "true")
                sec_fixed("DENY_BY_DEFAULT=true (unknown requests now denied)")
            else:
                sec_warn("Deny-by-default is OFF — unknown requests are allowed",
                         action="Run with --fix to set DENY_BY_DEFAULT=true",
                         severity="recommended")

        # REQUIRE_API_KEY
        rak = env_vars.get("REQUIRE_API_KEY", "false").lower()
        if rak == "true":
            sec_pass("API key authentication required")
        else:
            if fix_mode:
                _set_env_var(env_file, "REQUIRE_API_KEY", "true")
                sec_fixed("REQUIRE_API_KEY=true (agents must authenticate)")
            else:
                sec_warn("API key authentication not required",
                         action="Run with --fix to set REQUIRE_API_KEY=true",
                         severity="recommended")

        # REQUIRE_VAULT_AUTH
        rva = env_vars.get("REQUIRE_VAULT_AUTH", "false").lower()
        if rva == "true":
            sec_pass("Vault write authentication required")
        else:
            if fix_mode:
                _set_env_var(env_file, "REQUIRE_VAULT_AUTH", "true")
                sec_fixed("REQUIRE_VAULT_AUTH=true (vault writes require API key)")
            else:
                sec_warn("Vault writes don't require authentication",
                         action="Run with --fix to set REQUIRE_VAULT_AUTH=true",
                         severity="recommended")

        # DEBUG
        debug = env_vars.get("DEBUG", "false").lower()
        if debug == "true":
            if fix_mode:
                _set_env_var(env_file, "DEBUG", "false")
                sec_fixed("DEBUG=false")
            else:
                sec_fail("DEBUG mode is ON in production!",
                         fix="Run with --fix to set DEBUG=false",
                         severity="mandatory")
        else:
            sec_pass("DEBUG mode is OFF")

        # ALLOWED_HOSTS
        ah = env_vars.get("ALLOWED_HOSTS", "")
        if ah and ah not in ("localhost", "localhost,127.0.0.1"):
            sec_pass(f"ALLOWED_HOSTS configured ({ah})")
        else:
            if fix_mode:
                ip = _detect_server_ip()
                if ip:
                    new_hosts = f"{ip},localhost,127.0.0.1,app"
                    _set_env_var(env_file, "ALLOWED_HOSTS", new_hosts)
                    sec_fixed(f"ALLOWED_HOSTS={new_hosts}")
                else:
                    sec_warn("ALLOWED_HOSTS needs your server IP (could not auto-detect)",
                             action="Manually set: ALLOWED_HOSTS=<your-ip>,localhost,127.0.0.1,app",
                             severity="mandatory for remote access")
            else:
                sec_warn("ALLOWED_HOSTS may need your server IP",
                         action="Run with --fix to auto-detect, or set manually",
                         help_url=f"{DOCS_URL}/SECURITY.md#request-security-middleware",
                         severity="mandatory for remote access")

        # ALLOWED_ORIGINS
        ao = env_vars.get("ALLOWED_ORIGINS", "")
        if ao and ao != "http://localhost:8000":
            sec_pass(f"ALLOWED_ORIGINS configured")
        else:
            if fix_mode:
                ip = _detect_server_ip()
                if ip:
                    # Try to detect the HTTPS port from SNAPPER_URL or default to 8443
                    port = "8443"
                    if SNAPPER_URL.startswith("https://"):
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(SNAPPER_URL)
                            if parsed.port:
                                port = str(parsed.port)
                        except Exception:
                            pass
                    new_origins = f"https://{ip}:{port}"
                    _set_env_var(env_file, "ALLOWED_ORIGINS", new_origins)
                    sec_fixed(f"ALLOWED_ORIGINS={new_origins}")
                else:
                    sec_warn("ALLOWED_ORIGINS needs your server URL (could not auto-detect)",
                             action="Manually set: ALLOWED_ORIGINS=https://<your-ip>:8443",
                             severity="mandatory for remote access")
            else:
                sec_warn("ALLOWED_ORIGINS may need your server URL",
                         action="Run with --fix to auto-detect, or set manually",
                         help_url=f"{DOCS_URL}/SECURITY.md#request-security-middleware",
                         severity="mandatory for remote access")

        # --- Not auto-fixable ---

        # Telegram
        tg = env_vars.get("TELEGRAM_BOT_TOKEN", "")
        if tg:
            sec_pass("Telegram bot configured for approval alerts")
        else:
            sec_warn("Telegram not configured — no approval notifications",
                     action="Create a bot via @BotFather, add TELEGRAM_BOT_TOKEN to .env",
                     help_url=f"{DOCS_URL}/TELEGRAM_SETUP.md",
                     severity="highly recommended")

    else:
        sec_warn(f"Could not find .env file to check settings")

    # 6. Check if rules exist
    try:
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/rules?page_size=1",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            total = data.get("total", 0)
            if total > 0:
                sec_pass(f"{total} security rules configured")
            else:
                sec_warn("No security rules configured",
                         action="Run: python scripts/snapper-cli.py init",
                         severity="mandatory")
    except Exception:
        sec_warn("Could not check rules")

    # 7. Check if agents exist
    try:
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/agents?page_size=1",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            total = data.get("total", 0)
            if total > 0:
                sec_pass(f"{total} agent(s) registered")
            else:
                sec_warn("No agents registered",
                         action="Run: python scripts/snapper-cli.py init",
                         severity="mandatory")
    except Exception:
        sec_warn("Could not check agents")

    # Summary
    print(f"\n  ─────────────────────────────────────")
    parts = [f"{GREEN}{pass_count} passed{RESET}"]
    if fixed_count > 0:
        parts.append(f"{GREEN}{fixed_count} fixed{RESET}")
    parts.append(f"{YELLOW}{warn_count} warnings{RESET}")
    parts.append(f"{RED}{fail_count} failed{RESET}")
    print(f"  {'  '.join(parts)}")

    if needs_restart:
        print(f"\n  {YELLOW}Restart containers to apply changes:{RESET}")
        print(f"    docker compose up -d --force-recreate")

    if fail_count > 0:
        print(f"\n  {RED}Fix the failures above before exposing Snapper to the network.{RESET}")
    elif warn_count > 0:
        if not fix_mode:
            print(f"\n  {YELLOW}Run with --fix to auto-fix settings:{RESET}")
            print(f"    python scripts/snapper-cli.py security-check --fix")
        print(f"\n  {YELLOW}See docs/SECURITY.md for manual fixes.{RESET}")
    else:
        print(f"\n  {GREEN}All security checks passed!{RESET}")
    print()


def cmd_test(args):
    """Test the integration."""
    print_banner()
    print(f"{BOLD}Testing Snapper Integration...{RESET}\n")

    if not check_snapper_running():
        print(f"{RED}✗ Snapper is not running{RESET}")
        sys.exit(1)
    print(f"{GREEN}✓{RESET} Snapper is running")

    agent_id = get_agent_id()
    import urllib.request

    # Test 1: Safe file access
    print(f"\n{BOLD}Test 1: Safe file read (should ALLOW){RESET}")
    payload = json.dumps({
        "agent_id": agent_id,
        "request_type": "file_access",
        "file_path": "/tmp/test.txt",
        "file_operation": "read",
    }).encode()

    try:
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/rules/evaluate",
            data=payload,
            headers={
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result["decision"] == "allow":
                print(f"  {GREEN}✓ ALLOWED{RESET} - {result.get('reason', 'OK')}")
            else:
                print(f"  {YELLOW}○ {result['decision'].upper()}{RESET} - {result.get('reason', '')}")
    except Exception as e:
        print(f"  {RED}✗ Error: {e}{RESET}")

    # Test 2: Credential file access (should DENY)
    print(f"\n{BOLD}Test 2: Credential file read (should DENY){RESET}")
    payload = json.dumps({
        "agent_id": agent_id,
        "request_type": "file_access",
        "file_path": "/home/user/.env",
        "file_operation": "read",
    }).encode()

    try:
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/rules/evaluate",
            data=payload,
            headers={
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if result["decision"] == "deny":
                print(f"  {GREEN}✓ DENIED{RESET} - {result.get('reason', 'Blocked')}")
            else:
                print(f"  {RED}✗ {result['decision'].upper()}{RESET} - Should have been denied!")
    except Exception as e:
        print(f"  {RED}✗ Error: {e}{RESET}")

    print(f"\n{GREEN}Integration test complete!{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Snapper CLI - Security for AI Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  snapper init                     Auto-detect agent, register, install hooks
  snapper init --agent cursor      Specify agent type explicitly
  snapper init --profile strict    Use strict security profile
  snapper security-check           Assess security posture of deployment
  snapper setup                    Legacy: full setup for OpenClaw only
  snapper status                   Check status
  snapper test                     Test the integration
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # init command (recommended)
    init_parser = subparsers.add_parser(
        "init",
        help="Auto-detect agent, register, and install config (recommended)",
    )
    init_parser.add_argument(
        "--agent", "-a",
        choices=["openclaw", "claude-code", "cursor", "windsurf", "cline", "custom"],
        default=None,
        help="Agent type (auto-detected if not specified)",
    )
    init_parser.add_argument(
        "--profile", "-p",
        choices=["recommended", "strict", "permissive"],
        default="recommended",
        help="Security profile to apply",
    )
    init_parser.add_argument(
        "--url",
        default=None,
        help="Override SNAPPER_URL",
    )

    # setup command (legacy)
    setup_parser = subparsers.add_parser("setup", help="Legacy: full setup for OpenClaw")
    setup_parser.add_argument(
        "--profile", "-p",
        choices=["recommended", "strict", "permissive"],
        default="recommended",
        help="Security profile to apply",
    )

    # integrate command (legacy)
    integrate_parser = subparsers.add_parser("integrate", help="Legacy: integrate with OpenClaw")
    integrate_parser.add_argument(
        "--profile", "-p",
        choices=["recommended", "strict", "permissive"],
        default="recommended",
        help="Security profile to apply",
    )

    # security-check command
    sec_check_parser = subparsers.add_parser("security-check", help="Assess security posture")
    sec_check_parser.add_argument("--fix", action="store_true", help="Auto-fix settings that can be corrected automatically")

    # status command
    subparsers.add_parser("status", help="Check status")

    # test command
    subparsers.add_parser("test", help="Test integration")

    args = parser.parse_args()

    # Handle --url override
    if hasattr(args, "url") and args.url:
        global SNAPPER_URL
        SNAPPER_URL = args.url

    if args.command == "init":
        cmd_init(args)
    elif args.command == "setup":
        cmd_setup(args)
    elif args.command == "integrate":
        cmd_integrate(args)
    elif args.command == "security-check":
        cmd_security_check(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "test":
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
