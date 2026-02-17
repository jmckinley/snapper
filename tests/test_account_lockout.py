"""Tests for account lockout enforcement."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.users import User
from app.services.auth import authenticate_user


@pytest.fixture
def mock_db():
    db = AsyncMock(spec=AsyncSession)
    return db


def _make_user(
    email="test@example.com",
    password_hash="$2b$12$fakehash",
    failed_attempts=0,
    locked_until=None,
    is_active=True,
):
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.email = email
    user.password_hash = password_hash
    user.failed_login_attempts = failed_attempts
    user.locked_until = locked_until
    user.is_active = is_active
    user.is_locked = (
        locked_until is not None
        and datetime.now(locked_until.tzinfo) < locked_until
    )
    user.last_login_at = None
    return user


@pytest.mark.asyncio
async def test_lockout_after_max_attempts(mock_db):
    """Account should lock after MAX_LOGIN_ATTEMPTS failures."""
    user = _make_user(failed_attempts=4)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    with patch("app.services.auth.verify_password", return_value=False):
        with patch("app.services.auth.get_settings") as mock_settings:
            mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
            mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

            with pytest.raises(ValueError, match="Invalid email or password"):
                await authenticate_user(mock_db, "test@example.com", "wrong")

    assert user.failed_login_attempts == 5
    assert user.locked_until is not None


@pytest.mark.asyncio
async def test_locked_account_rejected(mock_db):
    """Locked accounts should be rejected immediately."""
    future_lock = datetime.now(timezone.utc) + timedelta(minutes=20)
    user = _make_user(locked_until=future_lock, failed_attempts=5)
    user.is_locked = True

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)

    with patch("app.services.auth.get_settings") as mock_settings:
        mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
        mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

        with pytest.raises(ValueError, match="Account is locked"):
            await authenticate_user(mock_db, "test@example.com", "anything")


@pytest.mark.asyncio
async def test_successful_login_resets_attempts(mock_db):
    """Successful login should reset failed_login_attempts and locked_until."""
    user = _make_user(failed_attempts=3)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    with patch("app.services.auth.verify_password", return_value=True):
        with patch("app.services.auth.get_settings") as mock_settings:
            mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
            mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

            result = await authenticate_user(mock_db, "test@example.com", "correct")

    assert result == user
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


@pytest.mark.asyncio
async def test_expired_lockout_allows_login(mock_db):
    """Expired lockout should allow login."""
    past_lock = datetime.now(timezone.utc) - timedelta(minutes=5)
    user = _make_user(locked_until=past_lock, failed_attempts=5)
    user.is_locked = False  # Lock has expired

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    with patch("app.services.auth.verify_password", return_value=True):
        with patch("app.services.auth.get_settings") as mock_settings:
            mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
            mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

            result = await authenticate_user(mock_db, "test@example.com", "correct")

    assert result == user
    assert user.failed_login_attempts == 0


@pytest.mark.asyncio
async def test_invalid_user_raises(mock_db):
    """Non-existent email should raise ValueError."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_db.execute = AsyncMock(return_value=mock_result)

    with patch("app.services.auth.get_settings") as mock_settings:
        mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
        mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

        with pytest.raises(ValueError, match="Invalid email or password"):
            await authenticate_user(mock_db, "noone@example.com", "password")


@pytest.mark.asyncio
async def test_disabled_account_rejected(mock_db):
    """Inactive accounts should be rejected."""
    user = _make_user(is_active=False)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    with patch("app.services.auth.verify_password", return_value=True):
        with patch("app.services.auth.get_settings") as mock_settings:
            mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
            mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

            with pytest.raises(ValueError, match="Account is disabled"):
                await authenticate_user(mock_db, "test@example.com", "correct")


@pytest.mark.asyncio
async def test_increment_below_threshold(mock_db):
    """Failed attempts below threshold should not set locked_until."""
    user = _make_user(failed_attempts=1)

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.flush = AsyncMock()

    with patch("app.services.auth.verify_password", return_value=False):
        with patch("app.services.auth.get_settings") as mock_settings:
            mock_settings.return_value.MAX_LOGIN_ATTEMPTS = 5
            mock_settings.return_value.LOCKOUT_DURATION_MINUTES = 30

            with pytest.raises(ValueError, match="Invalid email or password"):
                await authenticate_user(mock_db, "test@example.com", "wrong")

    assert user.failed_login_attempts == 2
    assert user.locked_until is None


def test_is_locked_property():
    """Test the is_locked logic."""
    # No lockout
    user = MagicMock(spec=User)
    user.locked_until = None
    # Call the actual property logic
    user.is_locked = User.is_locked.fget(user)
    assert user.is_locked is False

    # Future lockout
    user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    assert User.is_locked.fget(user) is True

    # Past lockout
    user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
    assert User.is_locked.fget(user) is False
