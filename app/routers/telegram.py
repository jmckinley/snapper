"""Telegram bot webhook for approval handling."""

import logging
from typing import Optional

import httpx
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from app.config import get_settings
from app.database import async_session_factory
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/telegram", tags=["telegram"])


class TelegramUpdate(BaseModel):
    """Telegram webhook update."""
    update_id: int
    callback_query: Optional[dict] = None
    message: Optional[dict] = None


@router.post("/webhook")
async def telegram_webhook(request: Request):
    """
    Handle Telegram bot webhook callbacks.

    Processes approval/denial button presses from Telegram inline keyboards.
    """
    if not settings.TELEGRAM_BOT_TOKEN:
        raise HTTPException(status_code=503, detail="Telegram not configured")

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    # Handle callback queries (button presses)
    callback_query = data.get("callback_query")
    if callback_query:
        callback_id = callback_query.get("id")
        callback_data = callback_query.get("data", "")
        user = callback_query.get("from", {})
        username = user.get("username", user.get("first_name", "Unknown"))

        # Parse callback data: "approve:request_id" or "deny:request_id"
        if ":" in callback_data:
            action, request_id = callback_data.split(":", 1)

            if action in ("approve", "deny"):
                # Process the approval/denial
                result = await _process_approval(
                    request_id=request_id,
                    action=action,
                    approved_by=username,
                )

                # Answer the callback and update the message
                await _answer_callback(
                    callback_id=callback_id,
                    text=f"Request {action}d by @{username}",
                )

                # Edit the original message to show the result
                message = callback_query.get("message", {})
                chat_id = message.get("chat", {}).get("id")
                message_id = message.get("message_id")

                if chat_id and message_id:
                    emoji = "✅" if action == "approve" else "❌"
                    await _edit_message(
                        chat_id=chat_id,
                        message_id=message_id,
                        text=f"{emoji} Request *{action.upper()}D* by @{username}\n\nRequest ID: `{request_id}`",
                    )

                return {"ok": True, "action": action, "request_id": request_id}

    # Handle /start and /help commands
    message = data.get("message", {})
    text = message.get("text", "")
    chat_id = message.get("chat", {}).get("id")

    if text.startswith("/start"):
        await _send_message(
            chat_id=chat_id,
            text=(
                "🐢 *Welcome to Snapper Bot!*\n\n"
                "I'll notify you when AI agents need approval for sensitive actions.\n\n"
                "*Commands:*\n"
                "/status - Check Snapper connection\n"
                "/pending - List pending approvals\n"
                "/help - Show this message\n\n"
                f"Your Chat ID: `{chat_id}`\n"
                "_Add this to your Snapper settings._"
            ),
        )
    elif text.startswith("/help"):
        await _send_message(
            chat_id=chat_id,
            text=(
                "*Snapper Bot Commands:*\n\n"
                "/status - Check connection to Snapper\n"
                "/pending - List pending approval requests\n"
                "/approve <id> - Approve a request\n"
                "/deny <id> - Deny a request\n"
                "/help - Show this message"
            ),
        )
    elif text.startswith("/status"):
        await _send_message(
            chat_id=chat_id,
            text="✅ *Snapper is connected and running!*\n\nI'll notify you when actions need approval.",
        )
    elif text.startswith("/pending"):
        # TODO: Fetch pending approvals from database
        await _send_message(
            chat_id=chat_id,
            text="📋 *Pending Approvals:*\n\nNo pending approvals at this time.",
        )
    elif text.startswith("/approve ") or text.startswith("/deny "):
        parts = text.split(" ", 1)
        if len(parts) == 2:
            action = "approve" if text.startswith("/approve") else "deny"
            request_id = parts[1].strip()
            result = await _process_approval(
                request_id=request_id,
                action=action,
                approved_by=message.get("from", {}).get("username", "Unknown"),
            )
            emoji = "✅" if action == "approve" else "❌"
            await _send_message(
                chat_id=chat_id,
                text=f"{emoji} Request `{request_id}` has been *{action}d*.",
            )

    return {"ok": True}


async def _process_approval(request_id: str, action: str, approved_by: str) -> dict:
    """Process an approval or denial request."""
    logger.info(f"Processing {action} for request {request_id} by {approved_by}")

    # Log the approval action
    async with async_session_factory() as db:
        audit_log = AuditLog(
            action=AuditAction.APPROVAL_GRANTED if action == "approve" else AuditAction.APPROVAL_DENIED,
            severity=AuditSeverity.INFO,
            message=f"Request {request_id} {action}d via Telegram by {approved_by}",
            metadata={
                "request_id": request_id,
                "action": action,
                "approved_by": approved_by,
                "channel": "telegram",
            },
        )
        db.add(audit_log)
        await db.commit()

    # TODO: Update the pending request in database and notify the waiting agent

    return {"status": "processed", "action": action, "request_id": request_id}


async def _send_message(chat_id: int, text: str):
    """Send a message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        await client.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            },
            timeout=30.0,
        )


async def _answer_callback(callback_id: str, text: str):
    """Answer a callback query."""
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/answerCallbackQuery"
    async with httpx.AsyncClient() as client:
        await client.post(
            url,
            json={
                "callback_query_id": callback_id,
                "text": text,
            },
            timeout=30.0,
        )


async def _edit_message(chat_id: int, message_id: int, text: str):
    """Edit a message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/editMessageText"
    async with httpx.AsyncClient() as client:
        await client.post(
            url,
            json={
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "parse_mode": "Markdown",
            },
            timeout=30.0,
        )
