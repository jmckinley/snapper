"""Tests for POST /api/v1/setup/save-notifications endpoint.

Validates notification channel persistence in org settings JSONB,
input validation, and preservation of existing settings.
"""

import pytest
import pytest_asyncio
from uuid import uuid4

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.organizations import Organization, Plan


@pytest_asyncio.fixture
async def seed_plans(db_session: AsyncSession):
    """Seed the free plan required for Organization FK."""
    plan = Plan(
        id="free",
        name="Free",
        max_agents=1,
        max_rules=10,
        max_vault_entries=5,
        max_team_members=1,
        max_teams=1,
        price_monthly_cents=0,
        price_yearly_cents=0,
        features={},
    )
    db_session.add(plan)
    await db_session.flush()
    return plan


class TestSaveNotificationsTelegram:
    """Test saving Telegram notification config."""

    @pytest.mark.asyncio
    async def test_save_notifications_telegram(
        self, client: AsyncClient, db_session: AsyncSession, seed_plans
    ):
        """Saves telegram config and verifies org.settings."""
        response = await client.post(
            "/api/v1/setup/save-notifications",
            json={
                "telegram_enabled": True,
                "telegram_bot_token": "123:ABC",
                "telegram_chat_id": "456",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "saved"
        assert "telegram" in data["channels"]

        # Verify persisted in org settings
        result = await db_session.execute(
            select(Organization).where(Organization.deleted_at.is_(None))
        )
        org = result.scalar_one()
        assert org.settings["telegram_bot_token"] == "123:ABC"
        assert org.settings["telegram_chat_id"] == "456"
        assert "telegram" in org.settings["notification_channels"]


class TestSaveNotificationsSlack:
    """Test saving Slack notification config."""

    @pytest.mark.asyncio
    async def test_save_notifications_slack(
        self, client: AsyncClient, db_session: AsyncSession, seed_plans
    ):
        """Saves slack config and verifies org.settings."""
        response = await client.post(
            "/api/v1/setup/save-notifications",
            json={
                "slack_enabled": True,
                "slack_webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "saved"
        assert "slack" in data["channels"]

        result = await db_session.execute(
            select(Organization).where(Organization.deleted_at.is_(None))
        )
        org = result.scalar_one()
        assert org.settings["slack_webhook_url"] == "https://hooks.slack.com/services/T00/B00/xxx"
        assert "slack" in org.settings["notification_channels"]


class TestSaveNotificationsValidation:
    """Test input validation for notification config."""

    @pytest.mark.asyncio
    async def test_save_notifications_validates_telegram(self, client: AsyncClient, seed_plans):
        """telegram_enabled=true without token returns 400."""
        response = await client.post(
            "/api/v1/setup/save-notifications",
            json={
                "telegram_enabled": True,
                # Missing bot_token and chat_id
            },
        )
        assert response.status_code == 400
        assert "bot_token" in response.json()["detail"].lower() or "chat_id" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_save_notifications_validates_slack(self, client: AsyncClient, seed_plans):
        """slack_enabled=true without webhook_url returns 400."""
        response = await client.post(
            "/api/v1/setup/save-notifications",
            json={
                "slack_enabled": True,
                # Missing webhook_url
            },
        )
        assert response.status_code == 400
        assert "webhook_url" in response.json()["detail"].lower()


class TestSaveNotificationsPreservesExisting:
    """Test that saving notifications doesn't overwrite other org settings."""

    @pytest.mark.asyncio
    async def test_save_notifications_preserves_existing(
        self, client: AsyncClient, db_session: AsyncSession, seed_plans
    ):
        """Existing SSO keys in org settings are not overwritten."""
        # Pre-create org with SSO settings
        org = Organization(
            name="Test Org",
            slug="test-org",
            settings={
                "oidc_issuer": "https://dev.okta.com",
                "oidc_client_id": "abc123",
            },
        )
        db_session.add(org)
        await db_session.commit()

        # Save notification config
        response = await client.post(
            "/api/v1/setup/save-notifications",
            json={
                "telegram_enabled": True,
                "telegram_bot_token": "999:XYZ",
                "telegram_chat_id": "111",
            },
        )
        assert response.status_code == 200

        # Verify SSO keys preserved
        await db_session.refresh(org)
        assert org.settings["oidc_issuer"] == "https://dev.okta.com"
        assert org.settings["oidc_client_id"] == "abc123"
        # And notification keys are added
        assert org.settings["telegram_bot_token"] == "999:XYZ"
        assert "telegram" in org.settings["notification_channels"]
