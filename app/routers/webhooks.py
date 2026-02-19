"""Webhook endpoint management API.

CRUD for per-org webhook endpoints with event filters, HMAC signing,
and delivery log. Uses Organization.settings["webhooks"] JSONB storage.
"""

import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.organizations import Organization

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


# --- Schemas ---

class WebhookCreate(BaseModel):
    url: str = Field(..., description="Webhook delivery URL")
    secret: Optional[str] = Field(None, description="HMAC-SHA256 signing secret (auto-generated if empty)")
    event_filters: List[str] = Field(
        default_factory=list,
        description="Event types to deliver. Empty = all events.",
    )
    description: Optional[str] = None
    active: bool = True


class WebhookUpdate(BaseModel):
    url: Optional[str] = None
    secret: Optional[str] = None
    event_filters: Optional[List[str]] = None
    description: Optional[str] = None
    active: Optional[bool] = None


class WebhookResponse(BaseModel):
    id: str
    url: str
    description: Optional[str] = None
    event_filters: List[str] = []
    active: bool = True
    created_at: str
    has_secret: bool = False


class WebhookTestResponse(BaseModel):
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


# --- Helpers ---

def _get_org_id(request: Request) -> Optional[str]:
    """Extract org_id from request.state (set by auth middleware)."""
    return getattr(request.state, "org_id", None)


async def _get_org(db: AsyncSession, org_id: str) -> Organization:
    stmt = select(Organization).where(
        Organization.id == uuid.UUID(org_id),
        Organization.is_active == True,
    )
    result = await db.execute(stmt)
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


def _get_webhooks(org: Organization) -> List[Dict[str, Any]]:
    return (org.settings or {}).get("webhooks", [])


def _save_webhooks(org: Organization, webhooks: List[Dict[str, Any]]) -> None:
    settings = dict(org.settings or {})
    settings["webhooks"] = webhooks
    org.settings = settings


# --- Endpoints ---

@router.get("")
async def list_webhooks(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """List all webhook endpoints for the organization."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)

    return [
        WebhookResponse(
            id=wh["id"],
            url=wh["url"],
            description=wh.get("description"),
            event_filters=wh.get("event_filters", []),
            active=wh.get("active", True),
            created_at=wh.get("created_at", ""),
            has_secret=bool(wh.get("secret")),
        )
        for wh in webhooks
    ]


@router.post("", status_code=201)
async def create_webhook(
    data: WebhookCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Create a new webhook endpoint."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)

    webhook = {
        "id": str(uuid.uuid4()),
        "url": data.url,
        "secret": data.secret or secrets.token_hex(32),
        "event_filters": data.event_filters,
        "description": data.description,
        "active": data.active,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    webhooks.append(webhook)
    _save_webhooks(org, webhooks)
    await db.flush()

    return WebhookResponse(
        id=webhook["id"],
        url=webhook["url"],
        description=webhook.get("description"),
        event_filters=webhook.get("event_filters", []),
        active=webhook.get("active", True),
        created_at=webhook.get("created_at", ""),
        has_secret=True,
    )


@router.get("/{webhook_id}")
async def get_webhook(
    webhook_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific webhook endpoint."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)

    for wh in webhooks:
        if wh["id"] == webhook_id:
            return WebhookResponse(
                id=wh["id"],
                url=wh["url"],
                description=wh.get("description"),
                event_filters=wh.get("event_filters", []),
                active=wh.get("active", True),
                created_at=wh.get("created_at", ""),
                has_secret=bool(wh.get("secret")),
            )

    raise HTTPException(status_code=404, detail="Webhook not found")


@router.put("/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    data: WebhookUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Update a webhook endpoint."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)

    for wh in webhooks:
        if wh["id"] == webhook_id:
            if data.url is not None:
                wh["url"] = data.url
            if data.secret is not None:
                wh["secret"] = data.secret
            if data.event_filters is not None:
                wh["event_filters"] = data.event_filters
            if data.description is not None:
                wh["description"] = data.description
            if data.active is not None:
                wh["active"] = data.active

            _save_webhooks(org, webhooks)
            await db.flush()

            return WebhookResponse(
                id=wh["id"],
                url=wh["url"],
                description=wh.get("description"),
                event_filters=wh.get("event_filters", []),
                active=wh.get("active", True),
                created_at=wh.get("created_at", ""),
                has_secret=bool(wh.get("secret")),
            )

    raise HTTPException(status_code=404, detail="Webhook not found")


@router.delete("/{webhook_id}", status_code=204)
async def delete_webhook(
    webhook_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook endpoint."""
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)
    original_len = len(webhooks)
    webhooks = [wh for wh in webhooks if wh["id"] != webhook_id]

    if len(webhooks) == original_len:
        raise HTTPException(status_code=404, detail="Webhook not found")

    _save_webhooks(org, webhooks)
    await db.flush()
    return None


class WebhookTestRequest(BaseModel):
    event_type: str = Field(default="test", description="Event type to simulate: 'test' or 'request_pending_approval'")


@router.post("/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    body: Optional[WebhookTestRequest] = None,
):
    """Send a test event to a webhook endpoint.

    Supports event_type parameter to simulate different event payloads:
    - "test": generic ping (default)
    - "request_pending_approval": realistic approval event for bot testing
    """
    org_id = _get_org_id(request)
    if not org_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    org = await _get_org(db, org_id)
    webhooks = _get_webhooks(org)

    target = None
    for wh in webhooks:
        if wh["id"] == webhook_id:
            target = wh
            break

    if not target:
        raise HTTPException(status_code=404, detail="Webhook not found")

    from app.services.webhook_delivery import deliver_webhook

    event_type = (body.event_type if body else None) or "test"
    now = datetime.now(timezone.utc)

    if event_type == "request_pending_approval":
        import uuid as _uuid
        from datetime import timedelta as _td
        test_id = f"test_{_uuid.uuid4()}"
        expires_at = now + _td(seconds=300)
        test_payload = {
            "event": "request_pending_approval",
            "test": True,
            "severity": "warning",
            "message": "[TEST] Agent 'test-agent' requires approval: echo hello",
            "timestamp": now.isoformat(),
            "source": "snapper",
            "organization_id": org_id,
            "details": {
                "approval_request_id": test_id,
                "approval_expires_at": expires_at.isoformat(),
                "agent_id": "00000000-0000-0000-0000-000000000000",
                "agent_name": "test-agent",
                "rule_name": "Test Rule",
                "rule_id": "test-rule",
                "request_type": "command",
                "command": "echo hello",
                "tool_name": None,
                "tool_input": None,
                "trust_score": 1.0,
                "pii_detected": False,
            },
        }
    else:
        test_payload = {
            "event": "test",
            "message": "This is a test event from Snapper",
            "organization_id": org_id,
            "timestamp": now.isoformat(),
        }

    result = await deliver_webhook(
        url=target["url"],
        payload=test_payload,
        secret=target.get("secret"),
        event_type=event_type,
    )

    return WebhookTestResponse(
        success=result.success,
        status_code=result.status_code,
        error=result.error,
    )
