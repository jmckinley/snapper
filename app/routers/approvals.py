"""Approval workflow API endpoints."""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.dependencies import RedisDep, approval_status_rate_limit, approval_decide_rate_limit
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/approvals", tags=["approvals"])

# Redis key prefix for pending approvals
APPROVAL_PREFIX = "approval:"
DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes


class ApprovalRequest(BaseModel):
    """Pending approval request stored in Redis."""
    id: str
    agent_id: str
    agent_name: str
    request_type: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    tool_name: Optional[str] = None
    rule_id: str
    rule_name: str
    status: str = "pending"  # pending, approved, denied, expired
    created_at: str
    expires_at: str
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
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
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    pii_context: Optional[dict] = None,
    vault_tokens: Optional[list] = None,
    owner_chat_id: Optional[str] = None,
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
        rule_id=rule_id,
        rule_name=rule_name,
        status="pending",
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
        pii_context=pii_context,
        vault_tokens=vault_tokens,
        owner_chat_id=owner_chat_id,
    )

    # Store in Redis with TTL
    key = f"{APPROVAL_PREFIX}{approval_id}"
    await redis.set(key, approval.model_dump_json(), expire=timeout_seconds + 60)  # Extra buffer for status checks

    logger.info(f"Created approval request {approval_id} for agent {agent_name}")
    return approval_id


async def get_approval_request(redis: RedisDep, approval_id: str) -> Optional[ApprovalRequest]:
    """Get approval request from Redis."""
    key = f"{APPROVAL_PREFIX}{approval_id}"
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
                if approval.pii_context:
                    destination_domain = approval.pii_context.get("destination_domain")
                    placeholder_matches = approval.pii_context.get("placeholder_matches", {})

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
            except Exception as e:
                logger.error(f"Failed to resolve vault tokens for approval {approval_id}: {e}")

    return ApprovalStatusResponse(
        id=approval_id,
        status=approval.status,
        reason=reason,
        resolved_data=resolved_data,
    )


@router.post(
    "/{approval_id}/decide",
    response_model=ApprovalStatusResponse,
    dependencies=[Depends(approval_decide_rate_limit)],
)
async def decide_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    redis: RedisDep,
):
    """
    Approve or deny a pending request.

    This endpoint is called by Telegram bot or dashboard when user makes a decision.
    """
    approval = await get_approval_request(redis, approval_id)

    if not approval:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Approval request not found or expired",
        )

    if approval.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Approval already {approval.status}",
        )

    # Validate decision
    if request.decision not in ("approve", "deny"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision must be 'approve' or 'deny'",
        )

    new_status = "approved" if request.decision == "approve" else "denied"
    await update_approval_status(redis, approval_id, new_status, request.decided_by)

    return ApprovalStatusResponse(
        id=approval_id,
        status=new_status,
        reason=f"{new_status.capitalize()} by {request.decided_by or 'user'}",
    )


@router.get("/pending")
async def list_pending_approvals(redis: RedisDep):
    """List all pending approval requests."""
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
                        pending.append(approval)

        if cursor == 0:
            break

    return {"pending": pending, "count": len(pending)}
