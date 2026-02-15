"""Billing API endpoints for subscription management and Stripe integration."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import DbSessionDep, default_rate_limit
from app.services import stripe_billing
from app.services.plans import get_plan, get_usage

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/billing", dependencies=[Depends(default_rate_limit)])


# ---------------------------------------------------------------------------
# Auth helpers (same pattern as org router)
# ---------------------------------------------------------------------------


async def get_current_user_id(request: Request) -> UUID:
    """Extract authenticated user ID from request state (set by AuthMiddleware)."""
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return UUID(user_id)


async def get_current_org_id(request: Request) -> UUID:
    """Extract current organization ID from request state (set by AuthMiddleware)."""
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization context")
    return UUID(org_id)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class CheckoutRequest(BaseModel):
    """Request body for creating a Stripe Checkout session."""

    plan_id: str
    interval: str = "monthly"


class UrlResponse(BaseModel):
    """Response containing a redirect URL."""

    url: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/plan")
async def get_current_plan(
    request: Request,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    org_id: UUID = Depends(get_current_org_id),
):
    """
    Return the current plan details, usage statistics, and subscription info.

    Fetches the organization's active plan, counts resource usage against plan
    limits, and includes Stripe subscription metadata when available.
    """
    from sqlalchemy import select

    from app.models.organizations import Organization

    # Load org for subscription fields
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Load plan
    plan = await get_plan(db, org.plan_id)

    # Load usage
    usage = await get_usage(db, org_id)

    return {
        "plan": {
            "id": plan.id,
            "name": plan.name,
            "price_monthly_cents": plan.price_monthly_cents,
            "price_yearly_cents": plan.price_yearly_cents,
            "features": plan.features or {},
            "limits": {
                "agents": plan.max_agents,
                "rules": plan.max_rules,
                "vault_entries": plan.max_vault_entries,
                "team_members": plan.max_team_members,
                "teams": plan.max_teams,
            },
        },
        "usage": {
            "agents": usage["agents"],
            "rules": usage["rules"],
            "vault_entries": usage["vault_entries"],
            "team_members": usage["team_members"],
            "teams": usage["teams"],
        },
        "subscription_status": org.subscription_status,
        "plan_period_end": org.plan_period_end.isoformat() if org.plan_period_end else None,
        "stripe_publishable_key": settings.STRIPE_PUBLISHABLE_KEY,
    }


@router.post("/checkout", response_model=UrlResponse)
async def create_checkout(
    body: CheckoutRequest,
    request: Request,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    org_id: UUID = Depends(get_current_org_id),
):
    """
    Create a Stripe Checkout session for upgrading to a paid plan.

    Returns a URL that the frontend should redirect the user to for payment.
    Requires Stripe to be configured (STRIPE_SECRET_KEY set).
    """
    try:
        checkout_url = await stripe_billing.create_checkout_session(
            db=db,
            org_id=org_id,
            plan_id=body.plan_id,
            interval=body.interval,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not checkout_url:
        raise HTTPException(
            status_code=503,
            detail="Stripe billing is not configured. Set STRIPE_SECRET_KEY to enable payments.",
        )

    return {"url": checkout_url}


@router.post("/portal", response_model=UrlResponse)
async def create_portal(
    request: Request,
    db: DbSessionDep,
    user_id: UUID = Depends(get_current_user_id),
    org_id: UUID = Depends(get_current_org_id),
):
    """
    Create a Stripe Customer Portal session for managing an existing subscription.

    Returns a URL to the Stripe-hosted portal where users can update payment
    methods, change plans, or cancel their subscription. Requires the
    organization to have a Stripe customer on file.
    """
    portal_url = await stripe_billing.create_portal_session(
        db=db,
        org_id=org_id,
    )

    if not portal_url:
        raise HTTPException(
            status_code=404,
            detail="No Stripe customer found. Subscribe to a paid plan first.",
        )

    return {"url": portal_url}


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: DbSessionDep,
):
    """
    Handle incoming Stripe webhook events.

    This endpoint is called directly by Stripe and does NOT require user
    authentication. The request is verified using the Stripe webhook signature.

    Handled events:
    - checkout.session.completed: activates a new subscription
    - customer.subscription.updated: syncs plan/status changes
    - customer.subscription.deleted: downgrades to free plan
    - invoice.payment_failed: marks subscription as past_due
    """
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")

    if not signature:
        raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

    try:
        result = await stripe_billing.handle_webhook(
            db=db,
            payload=payload,
            signature=signature,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Stripe webhook processing error: {e}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")

    return {"received": True, "event_type": result.get("event_type")}
