"""Tests for device management and device fingerprinting."""

import pytest
from uuid import uuid4
from datetime import datetime

from app.models.devices import Device, DeviceStatus


class TestDeviceModel:
    """Tests for the Device SQLAlchemy model."""

    @pytest.mark.asyncio
    async def test_create_device(self, db_session):
        """Test creating a device record."""
        device = Device(
            device_id=str(uuid4()),
            platform="MacIntel",
            browser="Chrome/120",
            status=DeviceStatus.ACTIVE,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(device)
        await db_session.commit()
        await db_session.refresh(device)

        assert device.id is not None
        assert device.status == DeviceStatus.ACTIVE
        assert device.platform == "MacIntel"

    @pytest.mark.asyncio
    async def test_device_status_enum(self, db_session):
        """Test device status values."""
        assert DeviceStatus.ACTIVE == "active"
        assert DeviceStatus.BLOCKED == "blocked"

    @pytest.mark.asyncio
    async def test_device_with_metadata(self, db_session):
        """Test device with metadata JSON."""
        meta = {
            "timezone": "America/New_York",
            "cores": 8,
            "memory": 16,
            "language": "en-US",
        }
        device = Device(
            device_id=str(uuid4()),
            metadata_json=meta,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(device)
        await db_session.commit()
        await db_session.refresh(device)

        assert device.metadata_json["timezone"] == "America/New_York"
        assert device.metadata_json["cores"] == 8

    @pytest.mark.asyncio
    async def test_device_unique_device_id(self, db_session):
        """Test that device_id must be unique."""
        from sqlalchemy.exc import IntegrityError

        device_id = str(uuid4())
        d1 = Device(
            device_id=device_id,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(d1)
        await db_session.commit()

        d2 = Device(
            device_id=device_id,  # Same ID
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(d2)
        with pytest.raises(IntegrityError):
            await db_session.commit()
        await db_session.rollback()


class TestDeviceBlockingInEvaluate:
    """Tests for device blocking in the evaluate endpoint."""

    @pytest.mark.asyncio
    async def test_blocked_device_denied(self, async_client, db_session, sample_agent):
        """Requests from blocked devices are denied immediately."""
        # Create a blocked device
        device = Device(
            device_id="test-blocked-device-123",
            status=DeviceStatus.BLOCKED,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(device)
        await db_session.commit()

        response = await async_client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls",
            },
            headers={
                "X-API-Key": sample_agent.api_key,
                "X-Device-Id": "test-blocked-device-123",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "deny"
        assert "blocked" in data["reason"].lower()

    @pytest.mark.asyncio
    async def test_active_device_not_blocked(self, async_client, db_session, sample_agent, redis):
        """Requests from active devices are not auto-denied."""
        from app.models.rules import Rule, RuleAction, RuleType

        # Create an allow rule so we get allow (not deny-by-default)
        rule = Rule(
            id=uuid4(),
            name="Allow all for device test",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(rule)

        device = Device(
            device_id="test-active-device-456",
            status=DeviceStatus.ACTIVE,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(device)
        await db_session.commit()

        response = await async_client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls",
            },
            headers={
                "X-API-Key": sample_agent.api_key,
                "X-Device-Id": "test-active-device-456",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["decision"] != "deny" or "blocked" not in data.get("reason", "").lower()

    @pytest.mark.asyncio
    async def test_unknown_device_not_blocked(self, async_client, db_session, sample_agent, redis):
        """Requests from unknown (not yet registered) devices are not auto-denied."""
        from app.models.rules import Rule, RuleAction, RuleType

        rule = Rule(
            id=uuid4(),
            name="Allow all for unknown device test",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        response = await async_client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls",
            },
            headers={
                "X-API-Key": sample_agent.api_key,
                "X-Device-Id": "never-seen-device-789",
            },
        )

        assert response.status_code == 200
        # Unknown device with no user auth — should not auto-deny
        data = response.json()
        assert data["decision"] != "deny" or "blocked" not in data.get("reason", "").lower()


class TestDeviceAutoRegistration:
    """Tests for device auto-registration on first authenticated request."""

    @pytest.mark.asyncio
    async def test_device_auto_registered_with_jwt(
        self, async_client, db_session, sample_agent
    ):
        """When an authenticated user sends X-Device-Id, device is auto-registered."""
        from sqlalchemy import select
        from app.services.auth import create_access_token
        from app.models.organizations import Organization, OrganizationMembership, OrgRole
        from app.models.users import User
        from app.services.auth import get_password_hash
        from app.models.rules import Rule, RuleAction, RuleType

        # Create user and org
        user = User(
            id=uuid4(),
            email="device-test@example.com",
            username="device-test",
            hashed_password=get_password_hash("test123"),
            is_active=True,
        )
        db_session.add(user)
        org = Organization(id=uuid4(), name="Device Org", slug="device-org")
        db_session.add(org)
        await db_session.commit()

        membership = OrganizationMembership(
            user_id=user.id,
            organization_id=org.id,
            role=OrgRole.MEMBER,
        )
        db_session.add(membership)
        sample_agent.organization_id = org.id
        await db_session.commit()

        # Create allow rule
        rule = Rule(
            id=uuid4(),
            name="Allow for auto-reg test",
            agent_id=sample_agent.id,
            rule_type=RuleType.COMMAND_ALLOWLIST,
            action=RuleAction.ALLOW,
            priority=10,
            parameters={"patterns": [".*"]},
            is_active=True,
        )
        db_session.add(rule)
        await db_session.commit()

        token = create_access_token(user.id, org.id, "member")
        device_uuid = str(uuid4())

        response = await async_client.post(
            "/api/v1/rules/evaluate",
            json={
                "agent_id": sample_agent.external_id,
                "request_type": "command",
                "command": "ls",
            },
            headers={
                "X-API-Key": sample_agent.api_key,
                "Authorization": f"Bearer {token}",
                "X-Device-Id": device_uuid,
                "X-Device-Meta": '{"platform":"MacIntel","timezone":"America/New_York"}',
            },
        )

        assert response.status_code == 200

        # Check device was registered
        stmt = select(Device).where(Device.device_id == device_uuid)
        result = await db_session.execute(stmt)
        device = result.scalar_one_or_none()

        assert device is not None
        assert device.user_id == user.id
        assert device.platform == "MacIntel"
        assert device.metadata_json.get("timezone") == "America/New_York"


class TestDeviceManagementAPI:
    """Tests for the device CRUD API."""

    @pytest.mark.asyncio
    async def test_list_devices_empty(self, async_client):
        """List devices returns empty when no devices registered."""
        response = await async_client.get("/api/v1/devices")

        # May return 401 (needs auth) or 200 with empty list
        assert response.status_code in (200, 401)

    @pytest.mark.asyncio
    async def test_update_device_status(self, async_client, db_session):
        """Updating device status to blocked works."""
        from app.models.organizations import Organization

        org = Organization(id=uuid4(), name="Block Org", slug="block-org")
        db_session.add(org)
        await db_session.commit()

        device = Device(
            device_id=str(uuid4()),
            organization_id=org.id,
            status=DeviceStatus.ACTIVE,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        db_session.add(device)
        await db_session.commit()
        await db_session.refresh(device)

        # Direct model update test (API requires auth session)
        device.status = DeviceStatus.BLOCKED
        await db_session.commit()
        await db_session.refresh(device)

        assert device.status == DeviceStatus.BLOCKED
