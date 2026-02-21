"""Pluggable event publishing for SIEM integration.

Supports CEF/syslog output, webhook delivery with HMAC-SHA256 signatures,
and Splunk HTTP Event Collector (HEC).
Events are derived from audit log entries and published asynchronously.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import socket
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)


class SiemOutput(str, Enum):
    NONE = "none"
    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    SPLUNK = "splunk"
    BOTH = "both"       # syslog + webhook (legacy)
    ALL = "all"         # syslog + webhook + splunk


# Map AuditAction → CEF event class ID and name
CEF_EVENT_MAP = {
    # Rule enforcement
    "rule_evaluated": ("100", "Rule Evaluated"),
    "rule_matched": ("101", "Rule Matched"),
    "request_allowed": ("102", "Request Allowed"),
    "request_denied": ("103", "Request Denied"),
    "request_pending_approval": ("104", "Approval Required"),
    # Rule management
    "rule_created": ("200", "Rule Created"),
    "rule_updated": ("201", "Rule Updated"),
    "rule_deleted": ("202", "Rule Deleted"),
    "rule_activated": ("203", "Rule Activated"),
    "rule_deactivated": ("204", "Rule Deactivated"),
    # Agent management
    "agent_registered": ("300", "Agent Registered"),
    "agent_updated": ("301", "Agent Updated"),
    "agent_deleted": ("302", "Agent Deleted"),
    "agent_suspended": ("303", "Agent Suspended"),
    "agent_activated": ("304", "Agent Activated"),
    "agent_quarantined": ("305", "Agent Quarantined"),
    # Security events
    "rate_limit_exceeded": ("400", "Rate Limit Exceeded"),
    "origin_violation": ("401", "Origin Violation"),
    "host_violation": ("402", "Host Violation"),
    "credential_access_blocked": ("403", "Credential Access Blocked"),
    "malicious_skill_blocked": ("404", "Malicious Skill Blocked"),
    "cve_mitigation_triggered": ("405", "CVE Mitigation Triggered"),
    "security_alert": ("406", "Security Alert"),
    "pii_purge": ("407", "PII Data Purged"),
    # User actions
    "user_login": ("500", "User Login"),
    "user_logout": ("501", "User Logout"),
    "approval_granted": ("502", "Approval Granted"),
    "approval_denied": ("503", "Approval Denied"),
    # PII vault events
    "pii_vault_created": ("600", "PII Vault Entry Created"),
    "pii_vault_accessed": ("601", "PII Vault Entry Accessed"),
    "pii_vault_deleted": ("602", "PII Vault Entry Deleted"),
    "pii_gate_triggered": ("603", "PII Gate Triggered"),
    "pii_submission_approved": ("604", "PII Submission Approved"),
    "pii_submission_denied": ("605", "PII Submission Denied"),
    # System events
    "system_startup": ("700", "System Startup"),
    "system_shutdown": ("701", "System Shutdown"),
    "config_changed": ("702", "Configuration Changed"),
    "security_scan_completed": ("703", "Security Scan Completed"),
    # Threat detection events
    "threat_detected": ("800", "Threat Detected"),
    "threat_score_elevated": ("801", "Threat Score Elevated"),
    "threat_kill_chain_completed": ("802", "Kill Chain Completed"),
    "threat_agent_quarantined": ("803", "Agent Quarantined by Threat Engine"),
    "threat_resolved": ("804", "Threat Resolved"),
    "threat_false_positive": ("805", "Threat Marked False Positive"),
    # Unknown agent protection events
    "unknown_agent_attempt": ("810", "Unknown Agent Attempt"),
    "unknown_agent_lockout": ("811", "Unknown Agent IP Lockout"),
    # Shadow AI detection events
    "shadow_ai_detected": ("820", "Shadow AI Detected"),
    "shadow_ai_resolved": ("821", "Shadow AI Resolved"),
}

# Map severity to CEF severity (0-10)
SEVERITY_MAP = {
    "debug": 1,
    "info": 3,
    "warning": 5,
    "error": 7,
    "critical": 10,
}


def format_cef(
    action: str,
    severity: str,
    message: str,
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
    organization_id: Optional[str] = None,
) -> str:
    """Format an audit event as a CEF (Common Event Format) string.

    CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Event Class ID|Name|Severity|Extensions
    """
    settings = get_settings()
    event_class_id, event_name = CEF_EVENT_MAP.get(action, ("999", action))
    cef_severity = SEVERITY_MAP.get(severity, 3)

    # Build extensions
    extensions = []
    if agent_id:
        extensions.append(f"dvchost={_cef_escape(agent_id)}")
    if rule_id:
        extensions.append(f"cs1={_cef_escape(rule_id)} cs1Label=RuleID")
    if ip_address:
        extensions.append(f"src={ip_address}")
    if user_id:
        extensions.append(f"duser={_cef_escape(user_id)}")
    if request_id:
        extensions.append(f"externalId={_cef_escape(request_id)}")
    if message:
        extensions.append(f"msg={_cef_escape(message)}")
    if timestamp:
        # CEF date format: MMM dd yyyy HH:mm:ss
        extensions.append(f"rt={timestamp.strftime('%b %d %Y %H:%M:%S')}")
    if organization_id:
        extensions.append(f"cs7={_cef_escape(organization_id)} cs7Label=OrganizationID")
    if details:
        # Add select details as custom string fields
        cs_index = 2
        for key in ("command", "tool_name", "rule_type", "decision"):
            if key in details and cs_index <= 6:
                extensions.append(
                    f"cs{cs_index}={_cef_escape(str(details[key]))} cs{cs_index}Label={key}"
                )
                cs_index += 1
        # Enrich approval events with decision_source for SIEM filtering
        if "decision_source" in details and cs_index <= 6:
            extensions.append(
                f"cs{cs_index}={_cef_escape(str(details['decision_source']))} cs{cs_index}Label=DecisionSource"
            )
            cs_index += 1

    ext_str = " ".join(extensions)
    return (
        f"CEF:0|Snapper|AAF|{settings.APP_VERSION}|"
        f"{event_class_id}|{event_name}|{cef_severity}|{ext_str}"
    )


def _cef_escape(value: str) -> str:
    """Escape special characters for CEF format."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def _build_webhook_payload(
    action: str,
    severity: str,
    message: str,
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
    organization_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a JSON webhook payload for an audit event."""
    ts = timestamp or datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "event": action,
        "severity": severity,
        "message": message,
        "timestamp": ts.isoformat(),
        "source": "snapper",
    }
    if agent_id:
        payload["agent_id"] = agent_id
    if rule_id:
        payload["rule_id"] = rule_id
    if ip_address:
        payload["ip_address"] = ip_address
    if user_id:
        payload["user_id"] = user_id
    if request_id:
        payload["request_id"] = request_id
    if organization_id:
        payload["organization_id"] = organization_id
    if details:
        payload["details"] = details
    return payload


def _sign_payload(payload: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for a webhook payload."""
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def _record_siem_metric(output: str, success: bool) -> None:
    """Record a SIEM event metric (best-effort)."""
    try:
        from app.middleware.metrics import record_siem_event
        record_siem_event(output, success)
    except Exception:
        pass


async def send_to_syslog(cef_message: str) -> None:
    """Send a CEF message to a syslog server."""
    settings = get_settings()
    host = settings.SIEM_SYSLOG_HOST
    port = settings.SIEM_SYSLOG_PORT
    protocol = settings.SIEM_SYSLOG_PROTOCOL

    if not host:
        return

    success = False
    try:
        # RFC 5424 priority: facility=16 (local0) + severity
        priority = 16 * 8 + 6  # local0.info
        syslog_msg = f"<{priority}>1 {datetime.now(timezone.utc).isoformat()} snapper snapper - - - {cef_message}"

        if protocol == "tcp":
            reader, writer = await asyncio.open_connection(host, port)
            writer.write((syslog_msg + "\n").encode())
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(syslog_msg.encode()[:65507], (host, port))
            finally:
                sock.close()
        success = True
    except Exception as e:
        logger.warning(f"Failed to send syslog message: {e}")
    finally:
        _record_siem_metric("syslog", success)


async def send_to_webhook(payload: Dict[str, Any]) -> bool:
    """Send an event to the configured webhook URL with HMAC signature.

    Returns True on success, False on failure.
    """
    settings = get_settings()
    url = settings.SIEM_WEBHOOK_URL
    secret = settings.SIEM_WEBHOOK_SECRET

    if not url:
        return False

    success = False
    try:
        body = json.dumps(payload, default=str).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Snapper-Event": payload.get("event", "unknown"),
            "X-Snapper-Timestamp": str(int(time.time())),
        }
        if secret:
            headers["X-Snapper-Signature"] = f"sha256={_sign_payload(body, secret)}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, content=body, headers=headers)
            if response.status_code >= 400:
                logger.warning(
                    f"Webhook delivery failed: {response.status_code} {response.text[:200]}"
                )
                _record_siem_metric("webhook", False)
                return False
            success = True
            _record_siem_metric("webhook", True)
            return True
    except Exception as e:
        logger.warning(f"Webhook delivery error: {e}")
        _record_siem_metric("webhook", False)
        return False


async def send_to_splunk_hec(payload: Dict[str, Any]) -> bool:
    """Send an event to Splunk via HTTP Event Collector (HEC).

    Builds the Splunk HEC JSON envelope and POSTs it with the
    ``Authorization: Splunk <token>`` header.

    Returns True on success, False on failure.
    """
    settings = get_settings()
    url = settings.SIEM_SPLUNK_HEC_URL
    token = settings.SIEM_SPLUNK_HEC_TOKEN

    if not url or not token:
        return False

    try:
        # Build Splunk HEC envelope
        hec_event = {
            "time": time.time(),
            "host": "snapper",
            "source": "snapper:aaf",
            "sourcetype": settings.SIEM_SPLUNK_SOURCETYPE,
            "index": settings.SIEM_SPLUNK_INDEX,
            "event": payload,
        }

        body = json.dumps(hec_event, default=str).encode()
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Splunk {token}",
        }

        async with httpx.AsyncClient(
            timeout=10.0,
            verify=settings.SIEM_SPLUNK_VERIFY_SSL,
        ) as client:
            response = await client.post(url, content=body, headers=headers)
            if response.status_code >= 400:
                logger.warning(
                    f"Splunk HEC delivery failed: {response.status_code} {response.text[:200]}"
                )
                _record_siem_metric("splunk", False)
                return False
            _record_siem_metric("splunk", True)
            return True
    except Exception as e:
        logger.warning(f"Splunk HEC delivery error: {e}")
        _record_siem_metric("splunk", False)
        return False


async def get_org_notification_config(
    org_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Load notification config from an organization's settings.

    Returns org-scoped values for telegram/slack/email, falling back
    to global env vars when org settings are empty or org_id is None.
    """
    settings = get_settings()
    result: Dict[str, Any] = {
        "telegram_bot_token": settings.TELEGRAM_BOT_TOKEN,
        "telegram_chat_id": settings.TELEGRAM_CHAT_ID,
        "slack_webhook_url": settings.SLACK_WEBHOOK_URL,
        "email_enabled": bool(settings.SMTP_HOST),
        "notification_channels": [],
    }

    if not org_id:
        return result

    try:
        from app.database import get_db_context
        from app.models.organizations import Organization

        async with get_db_context() as db:
            from sqlalchemy import select
            row = await db.execute(
                select(Organization).where(Organization.id == org_id)
            )
            org = row.scalar_one_or_none()
            if org and org.settings:
                s = org.settings
                channels = s.get("notification_channels", [])
                if channels:
                    result["notification_channels"] = channels
                if s.get("telegram_bot_token"):
                    result["telegram_bot_token"] = s["telegram_bot_token"]
                if s.get("telegram_chat_id"):
                    result["telegram_chat_id"] = s["telegram_chat_id"]
                if s.get("slack_webhook_url"):
                    result["slack_webhook_url"] = s["slack_webhook_url"]
                if "email_enabled" in s:
                    result["email_enabled"] = s["email_enabled"]
    except Exception as e:
        logger.warning(f"Failed to load org notification config: {e}")

    return result


async def publish_event(
    action: str,
    severity: str,
    message: str,
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_id: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
    organization_id: Optional[str] = None,
) -> None:
    """Publish an event to configured SIEM outputs.

    This is the primary entry point. Call this after creating an audit log entry.
    It's fire-and-forget — failures are logged but don't propagate.
    """
    settings = get_settings()
    output = settings.SIEM_OUTPUT.lower()

    if output == SiemOutput.NONE:
        return

    try:
        # Determine which transports to use
        send_syslog = output in (SiemOutput.SYSLOG, SiemOutput.BOTH, SiemOutput.ALL)
        send_webhook = output in (SiemOutput.WEBHOOK, SiemOutput.BOTH, SiemOutput.ALL)
        send_splunk = output in (SiemOutput.SPLUNK, SiemOutput.ALL)

        if send_syslog:
            cef = format_cef(
                action=action,
                severity=severity,
                message=message,
                agent_id=agent_id,
                rule_id=rule_id,
                ip_address=ip_address,
                user_id=user_id,
                request_id=request_id,
                details=details,
                timestamp=timestamp,
                organization_id=organization_id,
            )
            await send_to_syslog(cef)

        # Build shared JSON payload for webhook and splunk
        json_payload = None
        if send_webhook or send_splunk:
            json_payload = _build_webhook_payload(
                action=action,
                severity=severity,
                message=message,
                agent_id=agent_id,
                rule_id=rule_id,
                ip_address=ip_address,
                user_id=user_id,
                request_id=request_id,
                details=details,
                timestamp=timestamp,
                organization_id=organization_id,
            )

        if send_webhook and json_payload is not None:
            await send_to_webhook(json_payload)

        if send_splunk and json_payload is not None:
            await send_to_splunk_hec(json_payload)

    except Exception as e:
        logger.warning(f"Event publishing failed (non-fatal): {e}")


async def publish_from_audit_log(audit_log, organization_id: Optional[str] = None) -> None:
    """Convenience wrapper that extracts fields from an AuditLog and calls publish_event().

    Use this at every AuditLog creation site to avoid duplicating 10+ kwargs.
    """
    try:
        action = audit_log.action
        if not isinstance(action, str):
            action = action.value
        severity = audit_log.severity
        if not isinstance(severity, str):
            severity = severity.value

        org_id = organization_id
        if org_id is None and hasattr(audit_log, "organization_id") and audit_log.organization_id:
            org_id = str(audit_log.organization_id)

        await publish_event(
            action=action,
            severity=severity,
            message=audit_log.message or "",
            agent_id=str(audit_log.agent_id) if audit_log.agent_id else None,
            rule_id=str(audit_log.rule_id) if audit_log.rule_id else None,
            ip_address=audit_log.ip_address,
            user_id=str(audit_log.user_id) if audit_log.user_id else None,
            request_id=audit_log.request_id,
            details=audit_log.details if audit_log.details else None,
            timestamp=audit_log.created_at,
            organization_id=org_id,
        )
    except Exception as e:
        logger.warning(f"publish_from_audit_log failed (non-fatal): {e}")
