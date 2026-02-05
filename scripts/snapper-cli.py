#!/usr/bin/env python3
"""
Snapper CLI - Easy integration for OpenClaw users

Usage:
    snapper setup          # One-command setup (install + configure OpenClaw)
    snapper integrate      # Just configure OpenClaw hooks
    snapper status         # Check Snapper and agent status
    snapper test           # Test the integration
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
            "Origin": "http://localhost:8000",
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
        headers={"Origin": "http://localhost:8000"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("items"):
                return data["items"][0]["id"]
    except Exception:
        pass
    return None


def apply_security_profile(agent_id: str, profile: str = "recommended"):
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

    rules_to_apply = templates.get(profile, templates["recommended"])

    for template_id in rules_to_apply:
        payload = json.dumps({"agent_id": agent_id}).encode()
        req = urllib.request.Request(
            f"{SNAPPER_URL}/api/v1/rules/templates/{template_id}/apply",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Origin": "http://localhost:8000",
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
            "Origin": "http://localhost:8000",
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
            headers={"Origin": "http://localhost:8000"},
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
                "Origin": "http://localhost:8000",
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
                "Origin": "http://localhost:8000",
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
  snapper setup              Full setup (install + configure OpenClaw)
  snapper setup --strict     Setup with strict security profile
  snapper integrate          Just configure OpenClaw hooks
  snapper status             Check status
  snapper test               Test the integration
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # setup command
    setup_parser = subparsers.add_parser("setup", help="Full setup")
    setup_parser.add_argument(
        "--profile", "-p",
        choices=["recommended", "strict", "permissive"],
        default="recommended",
        help="Security profile to apply",
    )

    # integrate command
    integrate_parser = subparsers.add_parser("integrate", help="Integrate with OpenClaw")
    integrate_parser.add_argument(
        "--profile", "-p",
        choices=["recommended", "strict", "permissive"],
        default="recommended",
        help="Security profile to apply",
    )

    # status command
    subparsers.add_parser("status", help="Check status")

    # test command
    subparsers.add_parser("test", help="Test integration")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args)
    elif args.command == "integrate":
        cmd_integrate(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "test":
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
