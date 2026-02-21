"""Device management API for browser extension endpoint tracking."""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.devices import Device, DeviceStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/devices", tags=["Devices"])


# --- Schemas ---

class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    device_id: str
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
    name: Optional[str] = None
    platform: Optional[str] = None
    browser: Optional[str] = None
    status: str
    first_seen_at: str
    last_seen_at: str
    metadata: Optional[dict] = Field(None, alias="metadata_json")


class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    status: Optional[DeviceStatus] = None


class DeviceListResponse(BaseModel):
    items: list[DeviceResponse]
    total: int


# --- Endpoints ---

@router.get("", response_model=DeviceListResponse)
async def list_devices(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """List all devices for the current user's organization."""
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        return DeviceListResponse(items=[], total=0)

    stmt = (
        select(Device)
        .where(Device.organization_id == UUID(str(org_id)))
        .order_by(Device.last_seen_at.desc())
    )
    result = await db.execute(stmt)
    devices = result.scalars().all()

    return DeviceListResponse(
        items=[DeviceResponse.model_validate(d) for d in devices],
        total=len(devices),
    )


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Get device details."""
    org_id = getattr(request.state, "org_id", None)
    stmt = select(Device).where(
        Device.id == device_id,
        Device.organization_id == UUID(str(org_id)) if org_id else True,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    return DeviceResponse.model_validate(device)


@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: UUID,
    body: DeviceUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Update device name or status (block/unblock)."""
    org_id = getattr(request.state, "org_id", None)
    stmt = select(Device).where(
        Device.id == device_id,
        Device.organization_id == UUID(str(org_id)) if org_id else True,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    if body.name is not None:
        device.name = body.name
    if body.status is not None:
        device.status = body.status
        logger.info(
            f"Device {device.device_id} status changed to {body.status.value} "
            f"by user {user.id}"
        )

    await db.commit()
    await db.refresh(device)
    return DeviceResponse.model_validate(device)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_device(
    device_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Remove a device registration."""
    org_id = getattr(request.state, "org_id", None)
    stmt = select(Device).where(
        Device.id == device_id,
        Device.organization_id == UUID(str(org_id)) if org_id else True,
    )
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    await db.delete(device)
    await db.commit()
