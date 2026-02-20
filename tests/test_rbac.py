"""Tests for RBAC enforcement."""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.dependencies import RoleChecker, get_current_user
from app.models.users import User, UserRole, ROLE_PERMISSIONS


def test_role_permissions_defined():
    """All three roles should have permissions defined."""
    assert UserRole.ADMIN in ROLE_PERMISSIONS
    assert UserRole.OPERATOR in ROLE_PERMISSIONS
    assert UserRole.VIEWER in ROLE_PERMISSIONS


def test_admin_has_all_permissions():
    """Admin should have the most permissions."""
    admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]
    assert "agents:read" in admin_perms
    assert "agents:write" in admin_perms
    assert "agents:delete" in admin_perms
    assert "rules:read" in admin_perms
    assert "rules:write" in admin_perms
    assert "rules:delete" in admin_perms
    assert "users:write" in admin_perms
    assert "settings:write" in admin_perms


def test_operator_limited_permissions():
    """Operator should have CRUD but not delete users."""
    op_perms = ROLE_PERMISSIONS[UserRole.OPERATOR]
    assert "agents:read" in op_perms
    assert "agents:write" in op_perms
    assert "rules:read" in op_perms
    assert "rules:write" in op_perms
    # Should NOT have delete
    assert "agents:delete" not in op_perms
    assert "rules:delete" not in op_perms
    assert "users:delete" not in op_perms


def test_viewer_read_only():
    """Viewer should only have read permissions."""
    viewer_perms = ROLE_PERMISSIONS[UserRole.VIEWER]
    assert "agents:read" in viewer_perms
    assert "rules:read" in viewer_perms
    assert "audit:read" in viewer_perms
    # Should NOT have write
    assert "agents:write" not in viewer_perms
    assert "rules:write" not in viewer_perms
    assert "agents:delete" not in viewer_perms


def test_has_permission_admin():
    """Admin has_permission should return True for everything."""
    user = MagicMock(spec=User)
    user.role = UserRole.ADMIN
    user.is_admin = True
    user.permissions = []
    # Call the actual method
    assert User.has_permission(user, "anything") is True
    assert User.has_permission(user, "agents:delete") is True


def test_has_permission_with_explicit():
    """User with explicit permissions should have them."""
    user = MagicMock(spec=User)
    user.role = UserRole.VIEWER
    user.is_admin = False
    user.permissions = ["custom:action"]
    assert User.has_permission(user, "custom:action") is True
    assert User.has_permission(user, "agents:write") is False


def test_role_checker_init():
    """RoleChecker should store the required permission."""
    checker = RoleChecker("rules:delete")
    assert checker.required_permission == "rules:delete"


def test_role_checker_is_callable():
    """RoleChecker instance should be callable."""
    checker = RoleChecker("rules:delete")
    assert callable(checker)


@pytest.mark.asyncio
async def test_role_checker_admin_allowed():
    """Admin should pass any RoleChecker."""
    checker = RoleChecker("rules:delete")

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.is_active = True
    user.is_admin = True
    user.role = UserRole.ADMIN
    user.permissions = []
    user._effective_permissions = set(ROLE_PERMISSIONS[UserRole.ADMIN])
    user.deleted_at = None

    request = MagicMock()
    request.state.user_id = str(user.id)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user

    db = AsyncMock()
    db.execute = AsyncMock(return_value=mock_result)

    with patch("app.dependencies.get_current_user", return_value=user):
        result = await checker(request, db)
    assert result == user


@pytest.mark.asyncio
async def test_role_checker_viewer_denied():
    """Viewer should fail rules:delete check."""
    from fastapi import HTTPException

    checker = RoleChecker("rules:delete")

    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.is_active = True
    user.is_admin = False
    user.role = UserRole.VIEWER
    user.permissions = []
    user._effective_permissions = set(ROLE_PERMISSIONS[UserRole.VIEWER])
    user.deleted_at = None

    request = MagicMock()
    request.state.user_id = str(user.id)

    db = AsyncMock()

    with patch("app.dependencies.get_current_user", return_value=user):
        with pytest.raises(HTTPException) as exc_info:
            await checker(request, db)
    assert exc_info.value.status_code == 403
    assert "Insufficient permissions" in exc_info.value.detail
