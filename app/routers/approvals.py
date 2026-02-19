"""Approval workflow API endpoints."""

import asyncio
import json
import logging
import time as _time
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import RedisDep, approval_status_rate_limit, approval_decide_rate_limit
from app.config import get_settings
from app.database import get_db

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/approvals", tags=["approvals"])

# Redis key prefix for pending approvals
APPROVAL_PREFIX = "approval:"
TEST_APPROVAL_PREFIX = "test_approval:"
DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes

# Safety defaults
MAX_AUTOMATED_APPROVALS_PER_HOUR = 200
ANOMALY_WINDOW_SECONDS = 600  # 10 minutes
ANOMALY_THRESHOLD = 50  # max auto-approvals per agent in window


class ApprovalRequest(BaseModel):
    """Pending approval request stored in Redis."""
    id: str
    agent_id: str
    agent_name: str
    request_type: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[dict] = None
    rule_id: str
    rule_name: str
    status: str = "pending"  # pending, approved, denied, expired
    created_at: str
    expires_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    organization_id: Optional[str] = None
    # PII vault fields
    pii_context: Optional[dict] = None  # Detection details from PII gate
    vault_tokens: Optional[list] = None  # Vault tokens to resolve on approval
    owner_chat_id: Optional[str] = None  # Vault entry owner for ownership enforcement


class ApprovalStatusResponse(BaseModel):
    """Response for approval status check."""
    id: str
    status: str  # pending, approved, denied, expired
    reason: Optional[str] = None
    wait_seconds: Optional[int] = None  # How long to wait before next poll
    resolved_data: Optional[dict] = None  # Decrypted vault values (one-time retrieval)


class ApprovalDecisionRequest(BaseModel):
    """Request to approve or deny."""
    decision: str  # "approve" or "deny"
    decided_by: Optional[str] = None
    reason: Optional[str] = None  # Why the bot approved/denied


async def create_approval_request(
    redis: RedisDep,
    agent_id: str,
    agent_name: str,
    request_type: str,
    rule_id: str,
    rule_name: str,
    command: Optional[str] = None,
    file_path: Optional[str] = None,
    tool_name: Optional[str] = None,
    tool_input: Optional[dict] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    pii_context: Optional[dict] = None,
    vault_tokens: Optional[list] = None,
    owner_chat_id: Optional[str] = None,
    organization_id: Optional[str] = None,
) -> str:
    """Create a new pending approval request in Redis."""
    approval_id = str(uuid4())
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=timeout_seconds)

    approval = ApprovalRequest(
        id=approval_id,
        agent_id=agent_id,
        agent_name=agent_name,
        request_type=request_type,
        command=command,
        file_path=file_path,
        tool_name=tool_name,
        tool_input=tool_input,
        rule_id=rule_id,
        rule_name=rule_name,
        status="pending",
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
        pii_context=pii_context,
        vault_tokens=vault_tokens,
        owner_chat_id=owner_chat_id,
        organization_id=organization_id,
    )

    # Store in Redis with TTL
    key = f"{APPROVAL_PREFIX}{approval_id}"
    await redis.set(key, approval.model_dump_json(), expire=timeout_seconds + 60)  # Extra buffer for status checks

    logger.info(f"Created approval request {approval_id} for agent {agent_name}")
    return approval_id


async def get_approval_request(redis: RedisDep, approval_id: str) -> Optional[ApprovalRequest]:
    """Get approval request from Redis. Checks both real and test approval prefixes."""
    key = f"{APPROVAL_PREFIX}{approval_id}"
    data = await redis.get(key)
    if not data and approval_id.startswith("test_"):
        # Try test approval prefix
        key = f"{TEST_APPROVAL_PREFIX}{approval_id.removeprefix('test_')}"
        data = await redis.get(key)
    if not data:
        return None
    return ApprovalRequest.model_validate_json(data)


async def update_approval_status(
    redis: RedisDep,
    approval_id: str,
    status: str,
    decided_by: Optional[str] = None,
) -> bool:
    """Update approval request status."""
    approval = await get_approval_request(redis, approval_id)
    if not approval:
        return False

    approval.status = status
    approval.decided_at = datetime.utcnow().isoformat()
    approval.decided_by = decided_by

    key = f"{APPROVAL_PREFIX}{approval_id}"
    # Keep for a bit longer so status can be retrieved
    await redis.set(key, approval.model_dump_json(), expire=300)

    logger.info(f"Approval {approval_id} {status} by {decided_by}")
    return True


@router.get(
    "/{approval_id}/status",
    response_model=ApprovalStatusResponse,
    dependencies=[Depends(approval_status_rate_limit)],
    tags=["Core"],
)
async def check_approval_status(
    approval_id: str,
    redis: RedisDep,
):
    """
    Check the status of a pending approval request.

    This endpoint is polled by hooks waiting for approval decisions.
    Returns the current status and how long to wait before next poll.
    """
    approval = await get_approval_request(redis, approval_id)

    if not approval:
        # Could be expired or never existed
        return ApprovalStatusResponse(
            id=approval_id,
            status="expired",
            reason="Approval request not found or expired",
        )

    # Check if expired
    expires_at = datetime.fromisoformat(approval.expires_at)
    now = datetime.utcnow()

    if now > expires_at and approval.status == "pending":
        # Mark as expired
        await update_approval_status(redis, approval_id, "expired")
        return ApprovalStatusResponse(
            id=approval_id,
            status="expired",
            reason="Approval request timed out",
        )

    if approval.status == "pending":
        # Still waiting - tell client to poll again
        seconds_remaining = int((expires_at - now).total_seconds())
        return ApprovalStatusResponse(
            id=approval_id,
            status="pending",
            wait_seconds=min(5, seconds_remaining),  # Poll every 5 seconds
        )

    # Decision made
    reason = "Approved" if approval.status == "approved" else "Denied"
    if approval.decided_by:
        reason += f" by {approval.decided_by}"

    resolved_data = None

    # If approved and vault tokens present, resolve them
    if approval.status == "approved" and approval.vault_tokens:
        resolved_key = f"resolved_pii:{approval_id}"
        resolved_json = await redis.get(resolved_key)

        if resolved_json:
            # One-time retrieval: decrypt, return, and delete
            try:
                from app.services.pii_vault import decrypt_value as vault_decrypt
                decrypted_json = vault_decrypt(resolved_json if isinstance(resolved_json, bytes) else resolved_json.encode("latin-1"))
                resolved_data = json.loads(decrypted_json)
            except Exception:
                # Fallback for unencrypted legacy data
                resolved_data = json.loads(resolved_json)
            await redis.delete(resolved_key)
        else:
            # Resolve tokens now
            try:
                from app.database import async_session_factory
                from app.services.pii_vault import resolve_tokens, resolve_placeholders

                destination_domain = None
                placeholder_matches = {}
                label_matches = {}
                if approval.pii_context:
                    destination_domain = approval.pii_context.get("destination_domain")
                    placeholder_matches = approval.pii_context.get("placeholder_matches", {})
                    label_matches = approval.pii_context.get("label_matches", {})

                async with async_session_factory() as db:
                    resolved_data = await resolve_tokens(
                        db=db,
                        tokens=approval.vault_tokens,
                        destination_domain=destination_domain,
                        requester_chat_id=approval.owner_chat_id,
                    )

                    # Also resolve placeholder-mapped entries (re-key by placeholder value)
                    if placeholder_matches:
                        placeholder_resolved = await resolve_placeholders(
                            db=db,
                            placeholder_map=placeholder_matches,
                            destination_domain=destination_domain,
                            requester_chat_id=approval.owner_chat_id,
                        )
                        if placeholder_resolved:
                            if resolved_data is None:
                                resolved_data = {}
                            resolved_data.update(placeholder_resolved)

                    # Also resolve label-mapped entries (re-key by vault:Label ref)
                    if label_matches:
                        label_resolved = await resolve_placeholders(
                            db=db,
                            placeholder_map=label_matches,
                            destination_domain=destination_domain,
                            requester_chat_id=approval.owner_chat_id,
                        )
                        if label_resolved:
                            if resolved_data is None:
                                resolved_data = {}
                            resolved_data.update(label_resolved)

                    await db.commit()

                if resolved_data:
                    # Encrypt before storing in Redis for one-time retrieval
                    from app.services.pii_vault import encrypt_value as vault_encrypt
                    from app.config import get_settings
                    vault_settings = get_settings()
                    encrypted_resolved = vault_encrypt(json.dumps(resolved_data))
                    await redis.set(
                        resolved_key,
                        encrypted_resolved,
                        expire=vault_settings.PII_VAULT_TOKEN_TTL_SECONDS,
                    )

                    # Log the access
                    from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
                    async with async_session_factory() as audit_db:
                        audit_log = AuditLog(
                            action=AuditAction.PII_VAULT_ACCESSED,
                            severity=AuditSeverity.WARNING,
                            message=f"Vault tokens resolved for approved request {approval_id}",
                            details={
                                "approval_id": approval_id,
                                "tokens_resolved": list(resolved_data.keys()),
                                "destination_domain": destination_domain,
                                "approved_by": approval.decided_by,
                            },
                        )
                        audit_db.add(audit_log)
                        await audit_db.commit()
                        try:
                            from app.services.event_publisher import publish_from_audit_log
                            asyncio.ensure_future(publish_from_audit_log(audit_log))
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"Failed to resolve vault tokens for approval {approval_id}: {e}")

    return ApprovalStatusResponse(
        id=approval_id,
        status=approval.status,
        reason=reason,
        resolved_data=resolved_data,
    )


async def _check_auto_approve_rate_cap(redis: RedisDep, org_id: str) -> None:
    """Check per-org hourly automated approval rate cap. Raises 429 if exceeded."""
    cap = MAX_AUTOMATED_APPROVALS_PER_HOUR

    # Check for per-org override
    try:
        from app.database import get_db_context
        from app.models.organizations import Organization
        from sqlalchemy import select
        import uuid

        async with get_db_context() as db:
            stmt = select(Organization).where(Organization.id == uuid.UUID(org_id))
            result = await db.execute(stmt)
            org = result.scalar_one_or_none()
            if org and org.settings:
                cap = org.settings.get("max_auto_approvals_per_hour", cap)
    except Exception:
        pass

    key = f"auto_approve_hourly:{org_id}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, 3600)

    if count > cap:
        ttl = await redis.ttl(key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Automated approval rate cap exceeded ({cap}/hour)",
            headers={"Retry-After": str(max(ttl, 60))},
        )


async def _check_anomaly_detection(redis: RedisDep, agent_id: str, agent_name: str) -> None:
    """Detect rapid auto-approvals by a single agent. Fires alert if threshold exceeded."""
    key = f"auto_approve_window:{agent_id}"
    now = _time.time()
    window_start = now - ANOMALY_WINDOW_SECONDS

    # Add current approval and trim old entries
    await redis.zadd(key, {str(now): now})
    await redis.zremrangebyscore(key, 0, window_start)
    await redis.expire(key, ANOMALY_WINDOW_SECONDS + 60)

    count = await redis.zcard(key)
    if count > ANOMALY_THRESHOLD:
        logger.warning(f"Anomaly: agent {agent_name} ({agent_id}) approved {count} requests in {ANOMALY_WINDOW_SECONDS // 60}min")
        try:
            from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
            from app.database import async_session_factory

            async with async_session_factory() as db:
                audit_log = AuditLog(
                    action=AuditAction.SECURITY_ALERT,
                    severity=AuditSeverity.WARNING,
                    message=f"Rapid automated approvals detected: agent {agent_name} approved {count} requests in {ANOMALY_WINDOW_SECONDS // 60} minutes",
                    details={
                        "type": "rapid_auto_approve",
                        "agent_id": agent_id,
                        "agent_name": agent_name,
                        "count": count,
                        "window_minutes": ANOMALY_WINDOW_SECONDS // 60,
                    },
                )
                db.add(audit_log)
                await db.commit()
                try:
                    from app.services.event_publisher import publish_from_audit_log
                    asyncio.ensure_future(publish_from_audit_log(audit_log))
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to log anomaly alert: {e}")


@router.post(
    "/{approval_id}/decide",
    response_model=ApprovalStatusResponse,
    dependencies=[Depends(approval_decide_rate_limit)],
    tags=["Core"],
)
async def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    redis: RedisDep,
    fastapi_request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve or deny a pending request.

    Called by Telegram/Slack bots, the dashboard, or external automation bots.
    When called with an API key, the calling agent must belong to the same
    organization as the approval request.
    """
    # --- Determine caller identity ---
    calling_agent = None
    decision_source = "human"
    channel = "api"

    # Try API key auth
    raw_key = x_api_key
    if not raw_key and authorization and authorization.startswith("Bearer "):
        raw_key = authorization[7:]

    if raw_key and raw_key.startswith("snp_"):
        from app.models.agents import Agent
        from sqlalchemy import select

        stmt = select(Agent).where(Agent.api_key == raw_key, Agent.is_deleted == False)
        result = await db.execute(stmt)
        calling_agent = result.scalar_one_or_none()
        if not calling_agent:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        if calling_agent.status in ("suspended", "quarantined"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Agent is {calling_agent.status}")
        decision_source = "automation"
        channel = "api"
    elif not raw_key and settings.REQUIRE_API_KEY:
        # Check for user session (JWT cookie) set by auth middleware
        user_id = getattr(fastapi_request.state, "user_id", None)
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key or user session required",
            )
        decision_source = "human"
        channel = "dashboard"
    # else: no auth + REQUIRE_API_KEY=false → backward compat (localhost dev)

    # --- Load and validate approval ---
    is_test = approval_id.startswith("test_")
    approval = await get_approval_request(redis, approval_id)

    if not approval:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Approval request not found or expired",
        )

    if approval.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval already {approval.status}",
        )

    # --- Org scoping ---
    if calling_agent and approval.organization_id:
        agent_org = str(calling_agent.organization_id) if calling_agent.organization_id else None
        if agent_org != approval.organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Agent does not belong to the approval's organization",
            )

    # Validate decision
    if request.decision not in ("approve", "deny"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision must be 'approve' or 'deny'",
        )

    # --- Safety checks for automated decisions ---
    if decision_source == "automation" and not is_test:
        if approval.organization_id:
            await _check_auto_approve_rate_cap(redis, approval.organization_id)
        if calling_agent:
            await _check_anomaly_detection(redis, str(calling_agent.id), calling_agent.name)

    # --- Apply decision ---
    decided_by = request.decided_by
    if calling_agent and not decided_by:
        decided_by = f"bot:{calling_agent.name}"

    new_status = "approved" if request.decision == "approve" else "denied"

    if not is_test:
        await update_approval_status(redis, approval_id, new_status, decided_by)
    else:
        # Sandboxed: update the test approval but don't affect real workflows
        approval.status = new_status
        approval.decided_at = datetime.utcnow().isoformat()
        approval.decided_by = decided_by
        key = f"{TEST_APPROVAL_PREFIX}{approval_id.removeprefix('test_')}"
        await redis.set(key, approval.model_dump_json(), expire=60)

    try:
        from app.middleware.metrics import record_approval_decision
        record_approval_decision(new_status)
    except Exception:
        pass

    # --- Audit log ---
    try:
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
        from app.database import async_session_factory

        created_at = datetime.fromisoformat(approval.created_at)
        response_time_ms = int((datetime.utcnow() - created_at).total_seconds() * 1000)
        client_ip = getattr(fastapi_request, "client", None)
        client_ip = client_ip.host if client_ip else None

        audit_details = {
            "request_id": approval_id,
            "action": request.decision,
            "approved_by": decided_by,
            "channel": channel,
            "decision_source": decision_source,
            "reason": request.reason,
            "ip_address": client_ip,
            "response_time_ms": response_time_ms,
        }
        if is_test:
            audit_details["test"] = True
        if calling_agent:
            audit_details["automation_agent_id"] = str(calling_agent.id)
            audit_details["automation_agent_name"] = calling_agent.name

        async with async_session_factory() as audit_db:
            audit_log = AuditLog(
                action=AuditAction.APPROVAL_GRANTED if request.decision == "approve" else AuditAction.APPROVAL_DENIED,
                severity=AuditSeverity.INFO,
                message=f"Request {approval_id} {request.decision}d via {channel} by {decided_by or 'user'}",
                new_value=audit_details,
            )
            audit_db.add(audit_log)
            await audit_db.commit()
            try:
                from app.services.event_publisher import publish_from_audit_log
                asyncio.ensure_future(publish_from_audit_log(audit_log))
            except Exception:
                pass
    except Exception as e:
        logger.warning(f"Failed to write approval audit log: {e}")

    return ApprovalStatusResponse(
        id=approval_id,
        status=new_status,
        reason=f"{new_status.capitalize()} by {decided_by or 'user'}",
    )


@router.get("/pending", tags=["Core"])
async def list_pending_approvals(
    redis: RedisDep,
    fastapi_request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """
    List pending approval requests.

    When called with an API key, results are filtered to the calling agent's organization.
    """
    # Determine caller's org for filtering
    caller_org_id = None

    raw_key = x_api_key
    if not raw_key and authorization and authorization.startswith("Bearer "):
        raw_key = authorization[7:]

    if raw_key and raw_key.startswith("snp_"):
        from app.models.agents import Agent
        from sqlalchemy import select

        stmt = select(Agent).where(Agent.api_key == raw_key, Agent.is_deleted == False)
        result = await db.execute(stmt)
        calling_agent = result.scalar_one_or_none()
        if calling_agent and calling_agent.organization_id:
            caller_org_id = str(calling_agent.organization_id)
    else:
        # Check user session
        org_id = getattr(fastapi_request.state, "org_id", None)
        if org_id:
            caller_org_id = str(org_id)

    # Scan for all approval keys
    pending = []
    cursor = 0

    while True:
        cursor, keys = await redis.scan(cursor, match=f"{APPROVAL_PREFIX}*", count=100)
        for key in keys:
            data = await redis.get(key)
            if data:
                approval = ApprovalRequest.model_validate_json(data)
                if approval.status == "pending":
                    # Check if expired
                    expires_at = datetime.fromisoformat(approval.expires_at)
                    if datetime.utcnow() <= expires_at:
                        # Org filter
                        if caller_org_id and approval.organization_id and approval.organization_id != caller_org_id:
                            continue
                        pending.append(approval)

        if cursor == 0:
            break

    return {"pending": pending, "count": len(pending)}


# --- Test Mode ---

class ApprovalTestRequest(BaseModel):
    """Simulate an approval webhook without creating a real approval."""
    agent_id: str
    request_type: str = "command"
    command: Optional[str] = "echo test"
    tool_name: Optional[str] = None
    tool_input: Optional[dict] = None


class ApprovalTestResponse(BaseModel):
    approval_request_id: str
    payload: dict
    webhooks_delivered: int


@router.post("/test", response_model=ApprovalTestResponse, tags=["Core"])
async def test_approval_webhook(
    data: ApprovalTestRequest,
    fastapi_request: Request,
    redis: RedisDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Simulate the full approval webhook flow without creating a real approval.

    Creates a temporary test approval in Redis (60s TTL), delivers a realistic
    `request_pending_approval` webhook payload to org webhooks with `X-Snapper-Test: true`
    header and `"test": true` in payload, and returns the test approval_request_id.

    Bot developers can use the returned ID to call `/decide` and verify their round-trip.
    """
    org_id = getattr(fastapi_request.state, "org_id", None)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Look up agent
    from app.models.agents import Agent
    from sqlalchemy import select
    import uuid as _uuid

    try:
        agent_uuid = _uuid.UUID(data.agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")

    stmt = select(Agent).where(Agent.id == agent_uuid, Agent.is_deleted == False)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Create test approval in Redis
    test_id = f"test_{uuid4()}"
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=60)

    test_approval = ApprovalRequest(
        id=test_id,
        agent_id=data.agent_id,
        agent_name=agent.name,
        request_type=data.request_type,
        command=data.command,
        tool_name=data.tool_name,
        tool_input=data.tool_input,
        rule_id="test-rule",
        rule_name="Test Rule",
        status="pending",
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
        organization_id=str(org_id),
    )

    key = f"{TEST_APPROVAL_PREFIX}{test_id.removeprefix('test_')}"
    await redis.set(key, test_approval.model_dump_json(), expire=60)

    # Build webhook payload
    webhook_payload = {
        "event": "request_pending_approval",
        "test": True,
        "severity": "warning",
        "message": f"[TEST] Agent '{agent.name}' requires approval: {data.command or data.tool_name or data.request_type}",
        "timestamp": now.isoformat(),
        "source": "snapper",
        "organization_id": str(org_id),
        "details": {
            "approval_request_id": test_id,
            "approval_expires_at": expires_at.isoformat(),
            "agent_id": data.agent_id,
            "agent_name": agent.name,
            "rule_name": "Test Rule",
            "rule_id": "test-rule",
            "request_type": data.request_type,
            "command": data.command,
            "tool_name": data.tool_name,
            "tool_input": data.tool_input,
            "trust_score": getattr(agent, "trust_score", 1.0),
            "pii_detected": False,
        },
    }

    # Deliver to org webhooks with test header
    webhooks_delivered = 0
    try:
        from app.models.organizations import Organization

        stmt = select(Organization).where(Organization.id == _uuid.UUID(str(org_id)))
        result = await db.execute(stmt)
        org = result.scalar_one_or_none()

        if org and org.settings:
            webhooks = org.settings.get("webhooks", [])
            from app.services.webhook_delivery import deliver_webhook

            for wh in webhooks:
                url = wh.get("url")
                if not url or not wh.get("active", True):
                    continue

                event_filters = wh.get("event_filters", [])
                if event_filters and "request_pending_approval" not in event_filters:
                    continue

                result = await deliver_webhook(
                    url=url,
                    payload=webhook_payload,
                    secret=wh.get("secret"),
                    event_type="request_pending_approval",
                )
                if result.success:
                    webhooks_delivered += 1
    except Exception as e:
        logger.warning(f"Test webhook delivery failed: {e}")

    # Audit
    try:
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
        from app.database import async_session_factory

        async with async_session_factory() as audit_db:
            audit_log = AuditLog(
                action=AuditAction.RULE_EVALUATED,
                severity=AuditSeverity.INFO,
                message=f"Test approval webhook simulated for agent {agent.name}",
                details={"test": True, "approval_request_id": test_id, "webhooks_delivered": webhooks_delivered},
            )
            audit_db.add(audit_log)
            await audit_db.commit()
    except Exception:
        pass

    return ApprovalTestResponse(
        approval_request_id=test_id,
        payload=webhook_payload,
        webhooks_delivered=webhooks_delivered,
    )
