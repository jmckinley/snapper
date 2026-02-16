"""
Tests for the email service (app/services/email.py).

Covers configuration detection, graceful fallback when SMTP is not configured,
and URL construction in email templates.
"""

import pytest
from unittest.mock import patch, MagicMock


class TestEmailConfiguration:
    def test_is_configured_false_no_smtp(self, monkeypatch):
        """_is_configured() returns False when SMTP vars are not set."""
        monkeypatch.delenv("SMTP_HOST", raising=False)
        monkeypatch.delenv("SMTP_USER", raising=False)
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)

        from app.config import get_settings
        get_settings.cache_clear()

        from app.services.email import _is_configured
        assert _is_configured() is False

    def test_is_configured_true_all_set(self, monkeypatch):
        """_is_configured() returns True when all SMTP vars are set."""
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "password123")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")

        from app.config import get_settings
        get_settings.cache_clear()

        from app.services.email import _is_configured
        assert _is_configured() is True

    def test_send_returns_false_not_configured(self, monkeypatch):
        """_send() returns False when SMTP is not configured."""
        monkeypatch.delenv("SMTP_HOST", raising=False)
        monkeypatch.delenv("SMTP_USER", raising=False)
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)

        from app.config import get_settings
        get_settings.cache_clear()

        from app.services.email import _send
        result = _send("test@example.com", "Test Subject", "<p>Body</p>")
        assert result is False


class TestEmailFunctions:
    def test_password_reset_false_no_smtp(self, monkeypatch):
        """send_password_reset() returns False when SMTP is not configured."""
        monkeypatch.delenv("SMTP_HOST", raising=False)

        from app.config import get_settings
        get_settings.cache_clear()

        from app.services.email import send_password_reset
        result = send_password_reset("user@example.com", "fake-token-123")
        assert result is False

    def test_password_reset_url_construction(self, monkeypatch):
        """send_password_reset constructs correct reset URL in HTML body."""
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "pass")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")

        from app.config import get_settings
        get_settings.cache_clear()

        sent_html = {}

        def mock_send(to, subject, html_body, text_body=None):
            sent_html["html"] = html_body
            return True

        with patch("app.services.email._send", side_effect=mock_send):
            from app.services.email import send_password_reset
            result = send_password_reset(
                "user@example.com", "my-reset-token", base_url="https://app.example.com"
            )
            assert result is True
            assert "https://app.example.com/reset-password?token=my-reset-token" in sent_html["html"]

    def test_invitation_false_no_smtp(self, monkeypatch):
        """send_invitation() returns False when SMTP is not configured."""
        monkeypatch.delenv("SMTP_HOST", raising=False)

        from app.config import get_settings
        get_settings.cache_clear()

        from app.services.email import send_invitation
        result = send_invitation(
            "new@example.com", "My Org", "John", "invite-token-123"
        )
        assert result is False

    def test_invitation_url_construction(self, monkeypatch):
        """send_invitation constructs correct accept URL in HTML body."""
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "pass")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")

        from app.config import get_settings
        get_settings.cache_clear()

        sent_data = {}

        def mock_send(to, subject, html_body, text_body=None):
            sent_data["html"] = html_body
            sent_data["subject"] = subject
            return True

        with patch("app.services.email._send", side_effect=mock_send):
            from app.services.email import send_invitation
            result = send_invitation(
                "new@example.com",
                "My Org",
                "John",
                "invite-token-456",
                base_url="https://app.example.com",
            )
            assert result is True
            assert "https://app.example.com/invitations/accept?token=invite-token-456" in sent_data["html"]

    def test_invitation_includes_org_name(self, monkeypatch):
        """send_invitation includes the org name in subject and body."""
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_USER", "user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "pass")
        monkeypatch.setenv("SMTP_PORT", "587")
        monkeypatch.setenv("SMTP_FROM_EMAIL", "noreply@example.com")

        from app.config import get_settings
        get_settings.cache_clear()

        sent_data = {}

        def mock_send(to, subject, html_body, text_body=None):
            sent_data["html"] = html_body
            sent_data["subject"] = subject
            return True

        with patch("app.services.email._send", side_effect=mock_send):
            from app.services.email import send_invitation
            send_invitation(
                "new@example.com",
                "Acme Corp",
                "Alice",
                "tok",
            )
            assert "Acme Corp" in sent_data["subject"]
            assert "Acme Corp" in sent_data["html"]
