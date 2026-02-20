"""Heuristic-based threat signal extraction and Redis bridge.

Hot-path signal extraction runs synchronously on every request (<2ms).
Signals are published to Redis Streams for async background analysis.
Threat scores are read from Redis to override rule engine decisions.
"""

import json
import logging
import math
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


# ---------------------------------------------------------------------------
# Signal types
# ---------------------------------------------------------------------------

class SignalType(str, Enum):
    """Types of threat signals extracted from requests."""

    FILE_READ = "file_read"
    NETWORK_SEND = "network_send"
    CREDENTIAL_ACCESS = "credential_access"
    PII_OUTBOUND = "pii_outbound"
    PII_ACCUMULATION = "pii_accumulation"
    ENCODING_DETECTED = "encoding_detected"
    VAULT_TOKEN_PROBE = "vault_token_probe"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    STEGANOGRAPHIC_CONTENT = "steganographic_content"
    TOOL_ANOMALY = "tool_anomaly"
    HIGH_ENTROPY_PAYLOAD = "high_entropy_payload"
    NEW_DESTINATION = "new_destination"
    VOLUME_SPIKE = "volume_spike"


class ThreatLevel(str, Enum):
    """Classified threat level from composite score."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# ThreatSignal
# ---------------------------------------------------------------------------

@dataclass
class ThreatSignal:
    """A single threat signal extracted from a request.

    All fields are flat primitives for Redis XADD compatibility.
    """

    signal_type: str
    agent_id: str
    timestamp: float = field(default_factory=time.time)
    tool_name: str = ""
    command: str = ""
    destination: str = ""
    payload_bytes: int = 0
    has_pii: bool = False
    has_encoding: bool = False
    has_credential_path: bool = False
    file_path: str = ""
    request_type: str = ""
    metadata: str = ""  # JSON string, max 500 chars

    def to_stream_fields(self) -> Dict[str, str]:
        """Serialize to flat string dict for XADD."""
        return {
            "signal_type": self.signal_type,
            "agent_id": self.agent_id,
            "timestamp": str(self.timestamp),
            "tool_name": self.tool_name,
            "command": self.command[:500] if self.command else "",
            "destination": self.destination,
            "payload_bytes": str(self.payload_bytes),
            "has_pii": "1" if self.has_pii else "0",
            "has_encoding": "1" if self.has_encoding else "0",
            "has_credential_path": "1" if self.has_credential_path else "0",
            "file_path": self.file_path,
            "request_type": self.request_type,
            "metadata": self.metadata[:500] if self.metadata else "",
        }

    @classmethod
    def from_stream_fields(cls, fields: Dict[str, str]) -> "ThreatSignal":
        """Deserialize from Redis stream entry."""
        return cls(
            signal_type=fields.get("signal_type", ""),
            agent_id=fields.get("agent_id", ""),
            timestamp=float(fields.get("timestamp", 0)),
            tool_name=fields.get("tool_name", ""),
            command=fields.get("command", ""),
            destination=fields.get("destination", ""),
            payload_bytes=int(fields.get("payload_bytes", 0)),
            has_pii=fields.get("has_pii") == "1",
            has_encoding=fields.get("has_encoding") == "1",
            has_credential_path=fields.get("has_credential_path") == "1",
            file_path=fields.get("file_path", ""),
            request_type=fields.get("request_type", ""),
            metadata=fields.get("metadata", ""),
        )


# ---------------------------------------------------------------------------
# Compiled regex patterns (module-level for performance)
# ---------------------------------------------------------------------------

# Credential file patterns
CREDENTIAL_PATTERNS = [
    re.compile(r"\.env(?:\.|$)", re.IGNORECASE),
    re.compile(r"\.pem$", re.IGNORECASE),
    re.compile(r"\.key$", re.IGNORECASE),
    re.compile(r"\.p12$", re.IGNORECASE),
    re.compile(r"\.pfx$", re.IGNORECASE),
    re.compile(r"\.jks$", re.IGNORECASE),
    re.compile(r"\.keystore$", re.IGNORECASE),
    re.compile(r"credentials\.json$", re.IGNORECASE),
    re.compile(r"\.aws/credentials", re.IGNORECASE),
    re.compile(r"\.ssh/", re.IGNORECASE),
    re.compile(r"\.netrc$", re.IGNORECASE),
    re.compile(r"\.pgpass$", re.IGNORECASE),
    re.compile(r"kubeconfig", re.IGNORECASE),
    re.compile(r"\.npmrc$", re.IGNORECASE),
    re.compile(r"\.pypirc$", re.IGNORECASE),
    re.compile(r"id_rsa|id_ed25519|id_ecdsa", re.IGNORECASE),
]

# Base64 detection (at least 20 chars of valid base64, suggesting encoded data)
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

# Hex string detection (at least 32 hex chars, suggesting encoded data)
HEX_PATTERN = re.compile(r"(?:0x)?[0-9a-fA-F]{32,}")

# Zero-width / steganographic characters
STEGO_PATTERN = re.compile(r"[\u200b-\u200d\ufeff\u00ad\u2060\u2061-\u2064\u206a-\u206f]")

# Vault token probe patterns
VAULT_TOKEN_PATTERN = re.compile(r"\{\{SNAPPER_VAULT:[0-9a-f]+\}\}")
VAULT_PROBE_PATTERN = re.compile(
    r"SNAPPER_VAULT|vault.*token|grep.*vault|find.*vault.*token",
    re.IGNORECASE,
)

# Privilege escalation patterns
PRIVESC_PATTERNS = [
    re.compile(r"\bsudo\b"),
    re.compile(r"\bsu\s+-?\s*\w"),
    re.compile(r"\bdocker\s+exec\b"),
    re.compile(r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b"),  # setuid/setgid
    re.compile(r"\bchmod\s+[+]?[ugo]*s"),
    re.compile(r"\bchown\b"),
    re.compile(r"\bnsenter\b"),
    re.compile(r"\bunshare\b"),
    re.compile(r"\bmount\b"),
    re.compile(r"\biptables\b"),
    re.compile(r"\bpasswd\b"),
]

# Living-off-the-land patterns (legitimate tools misused for exfiltration)
LOTL_PATTERNS = [
    re.compile(r"\btar\b.*\|\s*curl\b", re.IGNORECASE),
    re.compile(r"\bgrep\b.*(?:secret|password|token|key|credential)", re.IGNORECASE),
    re.compile(r"\bcat\b.*(?:\.env|\.pem|credentials|\.key).*\|", re.IGNORECASE),
    re.compile(r"\bbase64\b.*\|\s*(?:curl|wget|nc)\b", re.IGNORECASE),
    re.compile(r"\bfind\b.*-exec\s+(?:curl|wget|nc)\b", re.IGNORECASE),
    re.compile(r"\bxxd\b.*\|\s*(?:curl|wget|nc)\b", re.IGNORECASE),
]

# Network tool patterns (for identifying outbound requests)
NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync",
    "fetch", "httpie", "http", "ftp", "sftp",
}

NETWORK_TOOL_PATTERN = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|ssh|scp|rsync|fetch|ftp|sftp)\b"
)

# URL extraction for destination detection
URL_PATTERN = re.compile(r"https?://([^/\s:]+)")


# ---------------------------------------------------------------------------
# Signal extraction (HOT PATH - must be <2ms)
# ---------------------------------------------------------------------------

def extract_signals(
    agent_id: str,
    request_type: str = "",
    command: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_input: Optional[Dict[str, Any]] = None,
    file_path: Optional[str] = None,
    target_host: Optional[str] = None,
    url: Optional[str] = None,
    pii_detected: Optional[Dict[str, Any]] = None,
) -> List[ThreatSignal]:
    """Extract threat signals from a request.

    This runs in the hot path. Must be sync and complete in <2ms.
    Uses pre-compiled regexes and avoids any I/O.
    """
    if not settings.THREAT_DETECTION_ENABLED:
        return []

    signals: List[ThreatSignal] = []
    now = time.time()
    cmd = command or ""
    tool = tool_name or ""
    fp = file_path or ""
    ti_str = json.dumps(tool_input)[:1000] if tool_input else ""

    # Combined text for pattern scanning
    scan_text = f"{cmd} {ti_str} {fp}"

    # Estimate payload bytes
    payload_bytes = len(cmd) + len(ti_str)

    # Detect destination
    destination = target_host or ""
    if not destination and url:
        m = URL_PATTERN.search(url)
        if m:
            destination = m.group(1)
    if not destination and cmd:
        m = URL_PATTERN.search(cmd)
        if m:
            destination = m.group(1)

    # --- File read detection ---
    if request_type == "file_access" or fp:
        signals.append(ThreatSignal(
            signal_type=SignalType.FILE_READ,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            file_path=fp,
            request_type=request_type,
        ))

    # --- Credential file access ---
    cred_path = fp or cmd
    if cred_path:
        for pat in CREDENTIAL_PATTERNS:
            if pat.search(cred_path):
                signals.append(ThreatSignal(
                    signal_type=SignalType.CREDENTIAL_ACCESS,
                    agent_id=agent_id,
                    timestamp=now,
                    tool_name=tool,
                    file_path=fp,
                    command=cmd[:500],
                    has_credential_path=True,
                    request_type=request_type,
                ))
                break

    # --- Network send detection ---
    is_network = (
        request_type == "network"
        or destination
        or (cmd and NETWORK_TOOL_PATTERN.search(cmd))
        or tool in NETWORK_TOOLS
    )
    if is_network:
        signals.append(ThreatSignal(
            signal_type=SignalType.NETWORK_SEND,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            command=cmd[:500],
            destination=destination,
            payload_bytes=payload_bytes,
            request_type=request_type,
        ))

    # --- PII outbound detection ---
    if pii_detected:
        signals.append(ThreatSignal(
            signal_type=SignalType.PII_OUTBOUND,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            command=cmd[:500],
            destination=destination,
            has_pii=True,
            request_type=request_type,
            metadata=json.dumps({
                "pii_types": list(pii_detected.get("categories", {}).keys())[:5],
            })[:500],
        ))

    # --- Encoding detection ---
    encoding_types = []
    if BASE64_PATTERN.search(scan_text):
        encoding_types.append("base64")
    if HEX_PATTERN.search(scan_text):
        encoding_types.append("hex")
    if encoding_types:
        signals.append(ThreatSignal(
            signal_type=SignalType.ENCODING_DETECTED,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            command=cmd[:500],
            has_encoding=True,
            request_type=request_type,
            metadata=json.dumps({"encoding_types": encoding_types})[:500],
        ))

    # --- Vault token probe ---
    if VAULT_TOKEN_PATTERN.search(scan_text) or VAULT_PROBE_PATTERN.search(scan_text):
        signals.append(ThreatSignal(
            signal_type=SignalType.VAULT_TOKEN_PROBE,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            command=cmd[:500],
            request_type=request_type,
        ))

    # --- Privilege escalation ---
    if cmd:
        for pat in PRIVESC_PATTERNS:
            if pat.search(cmd):
                signals.append(ThreatSignal(
                    signal_type=SignalType.PRIVILEGE_ESCALATION,
                    agent_id=agent_id,
                    timestamp=now,
                    tool_name=tool,
                    command=cmd[:500],
                    request_type=request_type,
                ))
                break

    # --- Steganographic content ---
    if STEGO_PATTERN.search(scan_text):
        signals.append(ThreatSignal(
            signal_type=SignalType.STEGANOGRAPHIC_CONTENT,
            agent_id=agent_id,
            timestamp=now,
            tool_name=tool,
            command=cmd[:500],
            request_type=request_type,
        ))

    # --- Living-off-the-land ---
    if cmd:
        for pat in LOTL_PATTERNS:
            if pat.search(cmd):
                signals.append(ThreatSignal(
                    signal_type=SignalType.TOOL_ANOMALY,
                    agent_id=agent_id,
                    timestamp=now,
                    tool_name=tool,
                    command=cmd[:500],
                    request_type=request_type,
                    metadata=json.dumps({"sub_type": "lotl"})[:500],
                ))
                break

    # --- High entropy payload ---
    if payload_bytes > 100:
        entropy = _shannon_entropy(scan_text[:2000])
        if entropy > 7.5:
            signals.append(ThreatSignal(
                signal_type=SignalType.HIGH_ENTROPY_PAYLOAD,
                agent_id=agent_id,
                timestamp=now,
                tool_name=tool,
                payload_bytes=payload_bytes,
                request_type=request_type,
                metadata=json.dumps({"entropy": round(entropy, 2)})[:500],
            ))

    return signals


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per character).

    Returns 0.0 for empty strings.  Maximum theoretical value for
    printable ASCII is ~6.6; compressed / encrypted data approaches 8.0.
    """
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Redis bridge
# ---------------------------------------------------------------------------

async def publish_signals(redis, signals: List[ThreatSignal]) -> None:
    """Publish signals to Redis Streams (fire-and-forget).

    Each agent gets its own stream: threat:signals:{agent_id}
    """
    if not signals:
        return

    maxlen = settings.THREAT_SIGNAL_STREAM_MAXLEN

    for signal in signals:
        try:
            stream_key = f"threat:signals:{signal.agent_id}"
            await redis.xadd(
                stream_key,
                signal.to_stream_fields(),
                maxlen=maxlen,
                approximate=True,
            )
        except Exception as e:
            logger.debug(f"Failed to publish threat signal: {e}")


async def get_threat_score(redis, agent_id: str) -> float:
    """Get current threat score for an agent from Redis.

    Returns 0.0 if no score is set.
    """
    try:
        score = await redis.get(f"threat:score:{agent_id}")
        if score is not None:
            return float(score)
    except Exception:
        pass
    return 0.0


async def set_threat_score(redis, agent_id: str, score: float) -> None:
    """Set threat score for an agent in Redis with TTL."""
    ttl = settings.THREAT_SCORE_TTL_SECONDS
    try:
        await redis.set(f"threat:score:{agent_id}", str(round(score, 2)), expire=ttl)
    except Exception as e:
        logger.debug(f"Failed to set threat score: {e}")


def classify_threat_level(score: float) -> ThreatLevel:
    """Classify a numeric threat score into a threat level."""
    if score >= 80:
        return ThreatLevel.CRITICAL
    if score >= 60:
        return ThreatLevel.HIGH
    if score >= 40:
        return ThreatLevel.MEDIUM
    if score >= 20:
        return ThreatLevel.LOW
    return ThreatLevel.NONE
