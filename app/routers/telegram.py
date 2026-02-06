"""Telegram bot webhook for approval handling and rule testing."""

import logging
from typing import Optional
from uuid import UUID

import httpx
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

from app.config import get_settings
from app.database import async_session_factory
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/telegram", tags=["telegram"])

# Store test agent IDs per chat (in-memory for simplicity)
_test_agents: dict[int, UUID] = {}


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
                "/test - Test rule enforcement\n"
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
                "/test - Test rule enforcement (try `/test help`)\n"
                "/help - Show this message"
            ),
        )
    elif text.startswith("/status"):
        await _send_message(
            chat_id=chat_id,
            text="✅ *Snapper is connected and running!*\n\nI'll notify you when actions need approval.",
        )
    elif text.startswith("/pending"):
        # Fetch pending approvals from Redis
        from app.redis_client import redis_client
        from app.routers.approvals import APPROVAL_PREFIX, ApprovalRequest
        from datetime import datetime

        pending_list = []
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match=f"{APPROVAL_PREFIX}*", count=100)
            for key in keys:
                data = await redis_client.get(key)
                if data:
                    approval = ApprovalRequest.model_validate_json(data)
                    if approval.status == "pending":
                        expires_at = datetime.fromisoformat(approval.expires_at)
                        if datetime.utcnow() <= expires_at:
                            pending_list.append(approval)
            if cursor == 0:
                break

        if not pending_list:
            await _send_message(
                chat_id=chat_id,
                text="📋 *Pending Approvals:*\n\nNo pending approvals at this time.",
            )
        else:
            lines = ["📋 *Pending Approvals:*\n"]
            for p in pending_list[:10]:  # Limit to 10
                action_desc = p.command or p.file_path or p.tool_name or p.request_type
                lines.append(f"• `{p.id[:8]}` - {p.agent_name}: {action_desc[:30]}")
            lines.append(f"\n_Total: {len(pending_list)}_")
            await _send_message(chat_id=chat_id, text="\n".join(lines))
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
    elif text.startswith("/test"):
        await _handle_test_command(chat_id, text, message)

    return {"ok": True}


async def _process_approval(request_id: str, action: str, approved_by: str) -> dict:
    """Process an approval or denial request."""
    logger.info(f"Processing {action} for request {request_id} by {approved_by}")

    # Update the approval status in Redis
    from app.redis_client import redis_client
    from app.routers.approvals import update_approval_status

    new_status = "approved" if action == "approve" else "denied"
    success = await update_approval_status(
        redis=redis_client,
        approval_id=request_id,
        status=new_status,
        decided_by=approved_by,
    )

    if not success:
        logger.warning(f"Could not update approval {request_id} - may be expired")

    # Log the approval action
    async with async_session_factory() as db:
        audit_log = AuditLog(
            action=AuditAction.APPROVAL_GRANTED if action == "approve" else AuditAction.APPROVAL_DENIED,
            severity=AuditSeverity.INFO,
            message=f"Request {request_id} {action}d via Telegram by {approved_by}",
            old_value=None,
            new_value={
                "request_id": request_id,
                "action": action,
                "approved_by": approved_by,
                "channel": "telegram",
            },
        )
        db.add(audit_log)
        await db.commit()

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


async def _handle_test_command(chat_id: int, text: str, message: dict):
    """
    Handle /test command for simulating agent actions against rule engine.

    Usage:
        /test run <command>      - Test a shell command
        /test install <skill>    - Test installing a ClawHub skill
        /test access <file>      - Test file access
        /test network <host>     - Test network egress
        /test help               - Show test command help
    """
    parts = text.split(maxsplit=2)

    if len(parts) < 2 or parts[1] == "help":
        await _send_message(
            chat_id=chat_id,
            text=(
                "🧪 *Test Rule Enforcement*\n\n"
                "Simulate agent actions to test Snapper rules:\n\n"
                "*Commands:*\n"
                "`/test run <cmd>` - Test shell command\n"
                "`/test install <skill>` - Test skill install\n"
                "`/test access <file>` - Test file access\n"
                "`/test network <host>` - Test network egress\n\n"
                "*Examples:*\n"
                "`/test run ls -la`\n"
                "`/test run rm -rf /`\n"
                "`/test run cat ~/.ssh/id_rsa`\n"
                "`/test install malware-deployer`\n"
                "`/test access /etc/passwd`\n"
                "`/test network evil.com`"
            ),
        )
        return

    subcommand = parts[1].lower()
    arg = parts[2] if len(parts) > 2 else ""

    if not arg:
        await _send_message(
            chat_id=chat_id,
            text=f"❓ Missing argument. Usage: `/test {subcommand} <value>`",
        )
        return

    # Get or create test agent for this chat
    agent_id = await _get_or_create_test_agent(chat_id)

    # Build evaluation context based on subcommand
    from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine
    from app.redis_client import redis_client

    context = EvaluationContext(
        agent_id=agent_id,
        request_type="command",  # Default
        origin="https://telegram.org",
        metadata={"source": "telegram_test", "chat_id": chat_id},
    )

    if subcommand == "run":
        context.request_type = "command"
        context.command = arg
    elif subcommand == "install":
        context.request_type = "skill"
        context.skill_id = arg
    elif subcommand == "access":
        context.request_type = "file_access"
        context.file_path = arg
        context.file_operation = "read"
    elif subcommand == "network":
        context.request_type = "network"
        context.target_host = arg
        context.target_port = 443
    else:
        await _send_message(
            chat_id=chat_id,
            text=f"❓ Unknown test type: `{subcommand}`\n\nTry `/test help`",
        )
        return

    # Run evaluation
    async with async_session_factory() as db:
        engine = RuleEngine(db, redis_client)
        result = await engine.evaluate(context)

    # Format response
    if result.decision == EvaluationDecision.ALLOW:
        emoji = "✅"
        status = "ALLOWED"
    elif result.decision == EvaluationDecision.DENY:
        emoji = "❌"
        status = "BLOCKED"
    elif result.decision == EvaluationDecision.REQUIRE_APPROVAL:
        emoji = "⏳"
        status = "REQUIRES APPROVAL"
    else:
        emoji = "❓"
        status = result.decision.value.upper()

    # Build response message
    response_lines = [
        f"{emoji} *{status}*\n",
        f"*Test:* `{subcommand} {arg}`",
    ]

    if result.reason:
        response_lines.append(f"*Reason:* {result.reason}")

    if result.blocking_rule:
        response_lines.append(f"*Rule ID:* `{str(result.blocking_rule)[:8]}...`")

    if result.evaluation_time_ms:
        response_lines.append(f"*Eval time:* {result.evaluation_time_ms:.1f}ms")

    await _send_message(chat_id=chat_id, text="\n".join(response_lines))


async def _get_or_create_test_agent(chat_id: int) -> UUID:
    """Get or create a test agent for a Telegram chat."""
    global _test_agents

    if chat_id in _test_agents:
        # Verify agent still exists
        from app.models.agents import Agent
        from sqlalchemy import select

        async with async_session_factory() as db:
            stmt = select(Agent).where(
                Agent.id == _test_agents[chat_id],
                Agent.is_deleted == False,
            )
            result = await db.execute(stmt)
            agent = result.scalar_one_or_none()
            if agent:
                return agent.id

    # Create new test agent
    from app.models.agents import Agent, AgentStatus, TrustLevel
    from uuid import uuid4

    agent_id = uuid4()
    async with async_session_factory() as db:
        # Check if agent with this external_id already exists
        external_id = f"telegram-test-{chat_id}"
        from sqlalchemy import select
        stmt = select(Agent).where(Agent.external_id == external_id)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            _test_agents[chat_id] = existing.id
            return existing.id

        agent = Agent(
            id=agent_id,
            external_id=external_id,
            name=f"Telegram Test Agent ({chat_id})",
            description="Test agent for Telegram rule testing",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
        )
        db.add(agent)
        await db.commit()

    _test_agents[chat_id] = agent_id
    return agent_id
