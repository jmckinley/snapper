"""Setup and onboarding API endpoints."""

import os
import socket
import subprocess
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.agents import Agent, AgentStatus, TrustLevel
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
    security_profile: str = "recommended"  # strict, recommended, permissive


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

    return SetupStatus(
        is_first_run=is_first_run,
        agents_count=agents_count,
        rules_count=rules_count,
        has_global_rules=global_rules_count > 0,
        setup_complete=setup_complete,
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
    # Generate identifiers
    agent_id = uuid4()
    external_id = f"snapper-{request.host}-{request.port}"
    api_key = f"oc_{uuid4().hex}"
    name = request.name or f"AI agent @ {request.host}:{request.port}"

    # Check if already registered
    existing = await db.execute(
        select(Agent).where(Agent.external_id == external_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"Agent with external_id '{external_id}' already registered",
        )

    # Determine trust level based on profile
    trust_levels = {
        "strict": TrustLevel.UNTRUSTED,
        "recommended": TrustLevel.STANDARD,
        "permissive": TrustLevel.ELEVATED,
    }
    trust_level = trust_levels.get(request.security_profile, TrustLevel.STANDARD)

    # Create agent
    agent = Agent(
        id=agent_id,
        name=name,
        external_id=external_id,
        description=f"Auto-registered AI agent instance at {request.host}:{request.port}",
        status=AgentStatus.ACTIVE,
        trust_level=trust_level,
        allowed_origins=[
            f"http://{request.host}:{request.port}",
            f"https://{request.host}:{request.port}",
        ],
        require_localhost_only=request.host in ["localhost", "127.0.0.1"],
        metadata={"api_key_hash": _hash_api_key(api_key)},
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
    agent_id: str, api_key: str, rules_manager_url: str
) -> str:
    """Generate a quick config snippet for display."""
    return f"""# Add to .snapper/config.yaml
rules_manager:
  enabled: true
  url: {rules_manager_url}
  agent_id: {agent_id}
  api_key: {api_key}
"""


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
