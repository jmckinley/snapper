"""Email service for transactional emails (password reset, invitations)."""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)


def _is_configured() -> bool:
    """Check if SMTP is configured."""
    settings = get_settings()
    return bool(settings.SMTP_HOST and settings.SMTP_USER and settings.SMTP_PASSWORD)


def _send(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """Send an email via SMTP. Returns True on success, False on failure."""
    settings = get_settings()

    if not _is_configured():
        logger.warning("SMTP not configured — email not sent to %s", to)
        return False

    msg = MIMEMultipart("alternative")
    msg["From"] = settings.SMTP_FROM_EMAIL
    msg["To"] = to
    msg["Subject"] = subject

    if text_body:
        msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
            server.ehlo()
            if settings.SMTP_PORT != 25:
                server.starttls()
                server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_FROM_EMAIL, to, msg.as_string())
        logger.info("Email sent to %s: %s", to, subject)
        return True
    except Exception:
        logger.exception("Failed to send email to %s", to)
        return False


def send_password_reset(to: str, token: str, base_url: str = "") -> bool:
    """Send a password-reset email containing the reset link."""
    if not base_url:
        base_url = "https://localhost:8443"

    reset_url = f"{base_url}/reset-password?token={token}"

    html = f"""\
<html><body>
<h2>Password Reset</h2>
<p>You requested a password reset for your Snapper account.</p>
<p><a href="{reset_url}" style="display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;">Reset Password</a></p>
<p>Or copy this link: <code>{reset_url}</code></p>
<p>This link expires in 1 hour. If you didn't request this, ignore this email.</p>
</body></html>"""

    text = (
        f"Password Reset\n\n"
        f"Reset your Snapper password: {reset_url}\n\n"
        f"This link expires in 1 hour."
    )

    return _send(to, "Snapper — Password Reset", html, text)


def send_invitation(to: str, org_name: str, inviter_name: str, token: str, base_url: str = "") -> bool:
    """Send an organization-invitation email."""
    if not base_url:
        base_url = "https://localhost:8443"

    accept_url = f"{base_url}/invitations/accept?token={token}"

    html = f"""\
<html><body>
<h2>You've been invited to {org_name}</h2>
<p>{inviter_name} invited you to join <strong>{org_name}</strong> on Snapper.</p>
<p><a href="{accept_url}" style="display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;border-radius:6px;text-decoration:none;">Accept Invitation</a></p>
<p>Or copy this link: <code>{accept_url}</code></p>
<p>This invitation expires in 7 days.</p>
</body></html>"""

    text = (
        f"You've been invited to {org_name}\n\n"
        f"{inviter_name} invited you to join {org_name} on Snapper.\n\n"
        f"Accept: {accept_url}\n\n"
        f"This invitation expires in 7 days."
    )

    return _send(to, f"Snapper — Invitation to {org_name}", html, text)
