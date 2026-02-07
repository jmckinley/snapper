"""PII Vault REST API endpoints."""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import DbSessionDep, RedisDep, default_rate_limit, vault_write_rate_limit
from app.models.audit_logs import AuditAction, AuditLog, AuditSeverity
from app.models.pii_vault import PIICategory, PIIVaultEntry
from app.services import pii_vault

logger = logging.getLogger(__name__)


async def verify_vault_access(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    x_internal_source: Optional[str] = Header(None, alias="X-Internal-Source"),
):
    """
    Verify access for vault write operations.

    When REQUIRE_VAULT_AUTH is True:
    - Telegram-originated requests pass via X-Internal-Source: telegram
    - External API callers must provide X-API-Key
    """
    from app.config import get_settings
    settings = get_settings()

    if not settings.REQUIRE_VAULT_AUTH:
        return

    # Internal Telegram requests are trusted
    if x_internal_source == "telegram":
        return

    # Require API key for external callers
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required for vault operations. Provide X-API-Key header.",
        )

    # Validate API key format
    if not x_api_key.startswith("snp_"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format",
        )

    # Validate against known agent keys
    from sqlalchemy import select as sa_select
    from app.database import async_session_factory
    from app.models.agents import Agent

    async with async_session_factory() as db:
        stmt = sa_select(Agent).where(Agent.api_key == x_api_key, Agent.is_deleted == False)
        result = await db.execute(stmt)
        agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )


router = APIRouter(prefix="/vault", dependencies=[Depends(default_rate_limit)])


# --- Request/Response Models ---


class VaultEntryCreate(BaseModel):
    """Request to create a vault entry."""
    owner_chat_id: str = Field(..., description="Telegram chat ID of the PII owner")
    owner_name: Optional[str] = Field(None, description="Display name")
    label: str = Field(..., min_length=1, max_length=255, description="Human-readable label")
    category: PIICategory
    raw_value: str = Field(..., min_length=1, description="The raw PII value to encrypt")
    agent_id: Optional[str] = Field(None, description="Restrict to specific agent (UUID or null)")
    allowed_domains: Optional[List[str]] = Field(None, description="Domain whitelist patterns")
    max_uses: Optional[int] = Field(None, ge=1, description="Max number of uses")


class VaultEntryResponse(BaseModel):
    """Response for a vault entry (never includes decrypted value)."""
    id: str
    owner_chat_id: str
    label: str
    category: str
    token: str
    masked_value: str
    allowed_domains: List[str]
    max_uses: Optional[int]
    use_count: int
    created_at: str
    expires_at: Optional[str] = None


class VaultDomainUpdate(BaseModel):
    """Request to update allowed domains."""
    allowed_domains: List[str]


# --- Endpoints ---


@router.post(
    "/entries",
    response_model=VaultEntryResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(vault_write_rate_limit), Depends(verify_vault_access)],
)
async def create_vault_entry(
    request: VaultEntryCreate,
    db: DbSessionDep,
):
    """
    Create a new encrypted vault entry.

    Accepts the raw PII value, encrypts it, and returns the vault token
    and masked display value. The raw value is never stored in plaintext.
    """
    entry = await pii_vault.create_entry(
        db=db,
        owner_chat_id=request.owner_chat_id,
        owner_name=request.owner_name,
        label=request.label,
        category=request.category,
        raw_value=request.raw_value,
        agent_id=request.agent_id,
        allowed_domains=request.allowed_domains,
        max_uses=request.max_uses,
    )

    # Audit log
    audit_log = AuditLog(
        action=AuditAction.PII_VAULT_CREATED,
        severity=AuditSeverity.INFO,
        message=f"Vault entry created: {request.label} ({request.category.value})",
        details={
            "entry_id": str(entry.id),
            "owner_chat_id": request.owner_chat_id,
            "category": request.category.value,
            "label": request.label,
        },
    )
    db.add(audit_log)
    await db.commit()

    return VaultEntryResponse(
        id=str(entry.id),
        owner_chat_id=entry.owner_chat_id,
        label=entry.label,
        category=entry.category.value if hasattr(entry.category, "value") else entry.category,
        token=entry.token,
        masked_value=entry.masked_value,
        allowed_domains=entry.allowed_domains or [],
        max_uses=entry.max_uses,
        use_count=entry.use_count,
        created_at=entry.created_at.isoformat() if entry.created_at else "",
        expires_at=entry.expires_at.isoformat() if entry.expires_at else None,
    )


@router.get("/entries", response_model=List[VaultEntryResponse])
async def list_vault_entries(
    db: DbSessionDep,
    owner_chat_id: str = Query(..., description="Telegram chat ID of the owner"),
):
    """
    List vault entries for a specific owner.

    Returns masked values only - decrypted values are never exposed via this endpoint.
    """
    entries = await pii_vault.list_entries(db=db, owner_chat_id=owner_chat_id)

    return [
        VaultEntryResponse(
            id=str(e.id),
            owner_chat_id=e.owner_chat_id,
            label=e.label,
            category=e.category.value if hasattr(e.category, "value") else e.category,
            token=e.token,
            masked_value=e.masked_value,
            allowed_domains=e.allowed_domains or [],
            max_uses=e.max_uses,
            use_count=e.use_count,
            created_at=e.created_at.isoformat() if e.created_at else "",
            expires_at=e.expires_at.isoformat() if e.expires_at else None,
        )
        for e in entries
    ]


@router.delete(
    "/entries/{entry_id}",
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(vault_write_rate_limit), Depends(verify_vault_access)],
)
async def delete_vault_entry(
    entry_id: str,
    db: DbSessionDep,
    owner_chat_id: str = Query(..., description="Chat ID for ownership verification"),
):
    """
    Soft-delete a vault entry.

    Only the owner (by chat_id) can delete their entries.
    """
    success = await pii_vault.delete_entry(
        db=db,
        entry_id=entry_id,
        requester_chat_id=owner_chat_id,
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entry not found or not owned by this user",
        )

    # Audit log
    audit_log = AuditLog(
        action=AuditAction.PII_VAULT_DELETED,
        severity=AuditSeverity.WARNING,
        message=f"Vault entry deleted: {entry_id}",
        details={
            "entry_id": entry_id,
            "deleted_by_chat_id": owner_chat_id,
        },
    )
    db.add(audit_log)
    await db.commit()

    return {"status": "deleted", "entry_id": entry_id}


@router.put("/entries/{entry_id}/domains")
async def update_vault_domains(
    entry_id: str,
    request: VaultDomainUpdate,
    db: DbSessionDep,
    owner_chat_id: str = Query(..., description="Chat ID for ownership verification"),
):
    """Update the allowed domains for a vault entry."""
    from uuid import UUID as UUIDType

    try:
        entry_uuid = UUIDType(entry_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid entry ID")

    from sqlalchemy import select
    stmt = select(PIIVaultEntry).where(
        PIIVaultEntry.id == entry_uuid,
        PIIVaultEntry.is_deleted == False,
    )
    result = await db.execute(stmt)
    entry = result.scalar_one_or_none()

    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    if entry.owner_chat_id != str(owner_chat_id):
        raise HTTPException(status_code=403, detail="Not authorized to modify this entry")

    entry.allowed_domains = request.allowed_domains
    await db.commit()

    return {
        "status": "updated",
        "entry_id": entry_id,
        "allowed_domains": request.allowed_domains,
    }
