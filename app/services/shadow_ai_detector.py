"""Shadow AI detection: discover unauthorized AI tools on the host.

Three detection methods:
  1. Network egress — resolve known AI API domains to IPs, check active TCP
     connections against them.
  2. Process scanning — scan /proc or ``ps`` output for known AI tool
     process signatures.
  3. Container scanning — query the Docker socket for running containers
     with known AI tool images.

All scanners are async, best-effort, and log warnings on failure rather
than raising.  They are designed to run inside a Docker container that has
host networking or the Docker socket mounted.
"""

import asyncio
import logging
import re
import socket
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# ---------------------------------------------------------------------------
# Known AI domains (network egress detection)
# ---------------------------------------------------------------------------

KNOWN_AI_DOMAINS: List[str] = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api.together.xyz",
    "api.replicate.com",
    "api-inference.huggingface.co",
    "api.groq.com",
    "api.perplexity.ai",
    "api.deepseek.com",
    "api.fireworks.ai",
    "api.cerebras.ai",
    "api.sambanova.ai",
]

# Regex patterns for wildcard domains
KNOWN_AI_DOMAIN_PATTERNS: List[str] = [
    r"bedrock-runtime\..*\.amazonaws\.com",
    r"aiplatform\.googleapis\.com",
    r".*\.openai\.azure\.com",
]

# ---------------------------------------------------------------------------
# Known AI process signatures (process scanning)
# ---------------------------------------------------------------------------

AI_PROCESS_SIGNATURES: List[str] = [
    "ollama",
    "llama.cpp",
    "llama-server",
    "text-generation-launcher",
    "vllm",
    "localai",
    "koboldcpp",
    "oobabooga",
    "lm-studio",
    "lmstudio",
    "claude",
    "copilot-agent",
    "cursor",
    "aider",
    "continue",
    "tabby",
    "mlx_lm",
]

# ---------------------------------------------------------------------------
# Known AI container images (container scanning)
# ---------------------------------------------------------------------------

AI_CONTAINER_IMAGES: List[str] = [
    "ollama",
    "localai",
    "vllm",
    "text-generation-inference",
    "llama-cpp-python",
    "oobabooga",
    "koboldcpp",
    "open-webui",
    "langchain",
    "langserve",
    "flowise",
    "dify",
    "litellm",
    "anythingllm",
    "chatgpt-next-web",
    "lobe-chat",
    "jan-ai",
    "llama.cpp",
    "mlflow",
    "bentoml",
    "triton",
    "ray-ml",
]


def _get_extra_domains() -> List[str]:
    """Parse comma-separated extra domains from config."""
    raw = settings.SHADOW_AI_KNOWN_AI_DOMAINS
    if not raw:
        return []
    return [d.strip() for d in raw.split(",") if d.strip()]


def _resolve_domain(domain: str) -> List[str]:
    """Resolve a domain to IP addresses (best-effort, sync)."""
    try:
        results = socket.getaddrinfo(domain, 443, socket.AF_INET)
        return list({r[4][0] for r in results})
    except Exception:
        return []


async def scan_network_connections() -> List[Dict[str, Any]]:
    """Detect outbound connections to known AI API endpoints.

    Parses ``ss -tnp`` output (Linux) or ``netstat`` (macOS fallback)
    and checks destination IPs against resolved AI domain IPs.
    """
    findings: List[Dict[str, Any]] = []

    # Build IP -> domain lookup
    all_domains = KNOWN_AI_DOMAINS + _get_extra_domains()
    ip_to_domain: Dict[str, str] = {}
    for domain in all_domains:
        for ip in _resolve_domain(domain):
            ip_to_domain[ip] = domain

    if not ip_to_domain:
        return findings

    # Get active connections
    try:
        if platform.system() == "Linux":
            proc = await asyncio.create_subprocess_exec(
                "ss", "-tnp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                "netstat", "-an", "-p", "tcp",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        lines = stdout.decode(errors="replace").splitlines()
    except Exception as e:
        logger.debug(f"Shadow AI network scan failed: {e}")
        return findings

    for line in lines:
        for ip, domain in ip_to_domain.items():
            if ip in line:
                # Extract process info if available
                process_match = re.search(r'users:\(\("([^"]+)"', line)
                process_name = process_match.group(1) if process_match else None

                findings.append({
                    "detection_type": "network",
                    "destination": f"{ip}:443 ({domain})",
                    "process_name": process_name,
                    "details": {"raw_line": line.strip()[:500], "domain": domain, "ip": ip},
                })
                break

    return findings


async def scan_processes() -> List[Dict[str, Any]]:
    """Detect running AI tool processes."""
    findings: List[Dict[str, Any]] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "ps", "aux",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        lines = stdout.decode(errors="replace").splitlines()
    except Exception as e:
        logger.debug(f"Shadow AI process scan failed: {e}")
        return findings

    for line in lines:
        line_lower = line.lower()
        for sig in AI_PROCESS_SIGNATURES:
            if sig.lower() in line_lower:
                parts = line.split()
                if len(parts) < 11:
                    continue

                pid_str = parts[1]
                cmd_line = " ".join(parts[10:])

                # Skip ourselves and known-safe entries
                if "shadow_ai" in cmd_line.lower() or "grep" in cmd_line.lower():
                    continue

                findings.append({
                    "detection_type": "process",
                    "process_name": sig,
                    "pid": int(pid_str) if pid_str.isdigit() else None,
                    "command_line": cmd_line[:1000],
                    "details": {"signature_matched": sig},
                })
                break  # One match per line

    return findings


async def scan_containers() -> List[Dict[str, Any]]:
    """Detect Docker containers running AI tool images.

    Requires ``/var/run/docker.sock`` to be mounted into the
    scanning container.
    """
    findings: List[Dict[str, Any]] = []

    try:
        import aiohttp
    except ImportError:
        logger.debug("aiohttp not available for Docker socket scan")
        # Fallback: try docker CLI
        return await _scan_containers_cli()

    try:
        connector = aiohttp.UnixConnector(path="/var/run/docker.sock")
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                "http://localhost/containers/json",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return findings
                containers = await resp.json()
    except Exception as e:
        logger.debug(f"Docker socket scan failed: {e}")
        return await _scan_containers_cli()

    for container in containers:
        image = container.get("Image", "")
        image_lower = image.lower()

        for known_image in AI_CONTAINER_IMAGES:
            if known_image.lower() in image_lower:
                names = container.get("Names", [])
                name = names[0].lstrip("/") if names else "unknown"
                cid = container.get("Id", "")[:12]

                findings.append({
                    "detection_type": "container",
                    "container_id": cid,
                    "container_image": image,
                    "process_name": name,
                    "details": {
                        "state": container.get("State"),
                        "status": container.get("Status"),
                        "ports": str(container.get("Ports", []))[:500],
                    },
                })
                break

    return findings


async def _scan_containers_cli() -> List[Dict[str, Any]]:
    """Fallback: use ``docker ps`` CLI for container scanning."""
    findings: List[Dict[str, Any]] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        lines = stdout.decode(errors="replace").splitlines()
    except Exception:
        return findings

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        cid, image, name, status = parts[0], parts[1], parts[2], parts[3]
        image_lower = image.lower()

        for known_image in AI_CONTAINER_IMAGES:
            if known_image.lower() in image_lower:
                findings.append({
                    "detection_type": "container",
                    "container_id": cid[:12],
                    "container_image": image,
                    "process_name": name,
                    "details": {"status": status},
                })
                break

    return findings


async def run_full_scan(host_identifier: Optional[str] = None) -> List[Dict[str, Any]]:
    """Run all detection methods and return combined findings.

    Parameters
    ----------
    host_identifier : str, optional
        Identifier for the host being scanned. Defaults to the hostname.

    Returns
    -------
    list of dict
        Each dict has keys matching :class:`ShadowAIDetection` columns.
    """
    if host_identifier is None:
        host_identifier = socket.gethostname()

    # Run all scans in parallel
    network_task = asyncio.create_task(scan_network_connections())
    process_task = asyncio.create_task(scan_processes())
    container_task = asyncio.create_task(scan_containers())

    results = await asyncio.gather(
        network_task, process_task, container_task,
        return_exceptions=True,
    )

    all_findings: List[Dict[str, Any]] = []
    for result in results:
        if isinstance(result, list):
            all_findings.extend(result)
        elif isinstance(result, Exception):
            logger.warning(f"Shadow AI scan error: {result}")

    # Attach host identifier
    for finding in all_findings:
        finding["host_identifier"] = host_identifier

    return all_findings
