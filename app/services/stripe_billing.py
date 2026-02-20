"""Stripe billing integration for subscription management."""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models.organizations import Organization, Plan

logger = logging.getLogger(__name__)
settings = get_settings()


def get_stripe():
    """Lazy-import stripe to avoid errors when not installed or not configured."""
    try:
        import stripe
        if settings.STRIPE_SECRET_KEY:
            stripe.api_key = settings.STRIPE_SECRET_KEY
        return stripe
    except ImportError:
        return None


async def create_checkout_session(
    db: AsyncSession,
    org_id: UUID,
    plan_id: str,
    interval: str = "monthly",
    success_url: str = "/billing?session_id={CHECKOUT_SESSION_ID}",
    cancel_url: str = "/billing",
) -> Optional[str]:
    """Create a Stripe Checkout session for plan upgrade.

    Returns the checkout URL, or None if Stripe is not configured.
    """
    stripe = get_stripe()
    if not stripe or not settings.STRIPE_SECRET_KEY:
        return None

    # Load org
    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org:
        raise ValueError("Organization not found")

    # Load target plan
    result = await db.execute(select(Plan).where(Plan.id == plan_id))
    plan = result.scalar_one_or_none()
    if not plan:
        raise ValueError(f"Plan '{plan_id}' not found")

    # Get price ID
    price_id = plan.stripe_price_id_monthly if interval == "monthly" else plan.stripe_price_id_yearly
    if not price_id:
        # Use config fallback
        if plan_id == "pro":
            price_id = settings.STRIPE_PRICE_PRO_MONTHLY if interval == "monthly" else settings.STRIPE_PRICE_PRO_YEARLY
    if not price_id:
        raise ValueError(f"No Stripe price configured for plan '{plan_id}' ({interval})")

    # Create or retrieve Stripe customer
    if not org.stripe_customer_id:
        customer = stripe.Customer.create(
            name=org.name,
            metadata={"org_id": str(org.id), "org_slug": org.slug},
        )
        org.stripe_customer_id = customer.id
        await db.flush()

    # Create checkout session
    session = stripe.checkout.Session.create(
        customer=org.stripe_customer_id,
        payment_method_types=["card"],
        line_items=[{"price": price_id, "quantity": 1}],
        mode="subscription",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"org_id": str(org.id), "plan_id": plan_id},
    )

    return session.url


async def create_portal_session(
    db: AsyncSession,
    org_id: UUID,
    return_url: str = "/billing",
) -> Optional[str]:
    """Create a Stripe Customer Portal session.

    Returns the portal URL, or None if Stripe is not configured or no customer exists.
    """
    stripe = get_stripe()
    if not stripe or not settings.STRIPE_SECRET_KEY:
        return None

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org or not org.stripe_customer_id:
        return None

    session = stripe.billing_portal.Session.create(
        customer=org.stripe_customer_id,
        return_url=return_url,
    )

    return session.url


async def handle_webhook(
    db: AsyncSession,
    payload: bytes,
    signature: str,
) -> dict:
    """Process Stripe webhook events.

    Returns a dict with event type and processing result.
    """
    stripe = get_stripe()
    if not stripe or not settings.STRIPE_WEBHOOK_SECRET:
        raise ValueError("Stripe not configured")

    # Verify webhook signature
    event = stripe.Webhook.construct_event(
        payload, signature, settings.STRIPE_WEBHOOK_SECRET
    )

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(db, data)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(db, data)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(db, data)
    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(db, data)

    return {"event_type": event_type, "processed": True}


async def _handle_checkout_completed(db: AsyncSession, session_data: dict) -> None:
    """Handle successful checkout -- activate subscription."""
    org_id = session_data.get("metadata", {}).get("org_id")
    plan_id = session_data.get("metadata", {}).get("plan_id")
    subscription_id = session_data.get("subscription")

    if not org_id:
        logger.warning("Checkout completed without org_id metadata")
        return

    result = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        logger.warning(f"Organization {org_id} not found for checkout")
        return

    org.plan_id = plan_id or org.plan_id
    org.stripe_subscription_id = subscription_id
    org.subscription_status = "active"
    await db.flush()

    logger.info(f"Organization {org_id} upgraded to {plan_id}")


async def _handle_subscription_updated(db: AsyncSession, subscription: dict) -> None:
    """Handle subscription changes (plan changes, renewals)."""
    customer_id = subscription.get("customer")
    if not customer_id:
        return

    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        return

    org.subscription_status = subscription.get("status", org.subscription_status)
    org.stripe_subscription_id = subscription.get("id", org.stripe_subscription_id)

    # Update period end
    period_end = subscription.get("current_period_end")
    if period_end:
        from datetime import datetime, timezone
        org.plan_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)

    # Check if plan changed via price
    items = subscription.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")
        if price_id:
            plan_result = await db.execute(
                select(Plan).where(
                    (Plan.stripe_price_id_monthly == price_id) |
                    (Plan.stripe_price_id_yearly == price_id)
                )
            )
            plan = plan_result.scalar_one_or_none()
            if plan:
                org.plan_id = plan.id

    await db.flush()


async def _handle_subscription_deleted(db: AsyncSession, subscription: dict) -> None:
    """Handle subscription cancellation -- downgrade to free."""
    customer_id = subscription.get("customer")
    if not customer_id:
        return

    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        return

    org.plan_id = "free"
    org.subscription_status = "canceled"
    org.stripe_subscription_id = None
    await db.flush()

    logger.info(f"Organization {org.id} downgraded to free (subscription canceled)")


async def _handle_payment_failed(db: AsyncSession, invoice: dict) -> None:
    """Handle failed payment -- mark subscription as past_due."""
    customer_id = invoice.get("customer")
    if not customer_id:
        return

    result = await db.execute(
        select(Organization).where(Organization.stripe_customer_id == customer_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        return

    org.subscription_status = "past_due"
    await db.flush()

    logger.warning(f"Payment failed for organization {org.id}")


async def sync_subscription_status(db: AsyncSession, org_id: UUID) -> None:
    """Sync org subscription status from Stripe."""
    stripe = get_stripe()
    if not stripe or not settings.STRIPE_SECRET_KEY:
        return

    result = await db.execute(select(Organization).where(Organization.id == org_id))
    org = result.scalar_one_or_none()
    if not org or not org.stripe_subscription_id:
        return

    try:
        subscription = stripe.Subscription.retrieve(org.stripe_subscription_id)
        org.subscription_status = subscription.status

        if subscription.current_period_end:
            from datetime import datetime, timezone
            org.plan_period_end = datetime.fromtimestamp(
                subscription.current_period_end, tz=timezone.utc
            )

        await db.flush()
    except Exception as e:
        logger.error(f"Failed to sync subscription for org {org_id}: {e}")
