"""
@module telegram
@description Telegram bot webhook for approval handling and rule testing.
"""

import json
import logging
import re
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, update

from app.config import get_settings
from app.database import async_session_factory
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
from app.models.rules import Rule, RuleType, RuleAction

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/telegram", tags=["telegram"])

# Bot commands to register with Telegram
BOT_COMMANDS = [
    {"command": "start", "description": "Start the bot and show help"},
    {"command": "help", "description": "Show available commands"},
    {"command": "status", "description": "Check Snapper connection"},
    {"command": "rules", "description": "View active security rules"},
    {"command": "pending", "description": "List pending approvals"},
    {"command": "test", "description": "Test rule enforcement"},
    {"command": "purge", "description": "Purge PII from agent data"},
    {"command": "vault", "description": "Manage PII vault entries"},
    {"command": "pii", "description": "Toggle PII protection mode"},
    {"command": "block", "description": "Emergency block ALL actions"},
    {"command": "unblock", "description": "Resume normal operation"},
]

# Store test agent IDs per chat (in-memory for simplicity)
_test_agents: dict[int, UUID] = {}

# Pending emergency block confirmations (chat_id -> timestamp)
_pending_emergency_blocks: dict[int, datetime] = {}


class TelegramUpdate(BaseModel):
    """Telegram webhook update."""
    update_id: int
    callback_query: Optional[dict] = None
    message: Optional[dict] = None


async def register_bot_commands() -> bool:
    """
    Register bot commands with Telegram for autocomplete menu.

    This enables the typedown list when users type '/' in the chat.
    Called automatically at startup and can be triggered via API.
    """
    if not settings.TELEGRAM_BOT_TOKEN:
        logger.warning("Cannot register commands: TELEGRAM_BOT_TOKEN not set")
        return False

    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/setMyCommands"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"commands": BOT_COMMANDS},
                timeout=30.0,
            )
            result = response.json()

            if result.get("ok"):
                logger.info(f"Registered {len(BOT_COMMANDS)} bot commands with Telegram")
                return True
            else:
                logger.error(f"Failed to register commands: {result.get('description')}")
                return False
    except Exception as e:
        logger.error(f"Error registering bot commands: {e}")
        return False


@router.post("/register-commands")
async def trigger_register_commands():
    """Manually trigger bot command registration with Telegram."""
    success = await register_bot_commands()
    if success:
        return {"status": "success", "commands": len(BOT_COMMANDS)}
    raise HTTPException(status_code=500, detail="Failed to register commands")


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

        # Parse callback data: "action:data"
        if ":" in callback_data:
            action, data = callback_data.split(":", 1)
            cb_message = callback_query.get("message", {})
            cb_chat_id = cb_message.get("chat", {}).get("id")
            cb_message_id = cb_message.get("message_id")

            if action in ("approve", "deny"):
                # Process the approval/denial
                result = await _process_approval(
                    request_id=data,
                    action=action,
                    approved_by=username,
                )

                await _answer_callback(callback_id=callback_id, text=f"Request {action}d by @{username}")

                if cb_chat_id and cb_message_id:
                    emoji = "✅" if action == "approve" else "❌"
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"{emoji} Request *{action.upper()}D* by @{username}\n\nRequest ID: `{data}`",
                    )

                return {"ok": True, "action": action, "request_id": data}

            elif action == "once":
                # Allow once - store temporary approval in Redis (5 min TTL)
                from app.redis_client import redis_client
                context_json = await redis_client.get(f"tg_ctx:{data}")
                if not context_json:
                    await _answer_callback(callback_id=callback_id, text="❌ Context expired")
                    return {"ok": False, "error": "context_expired"}

                # Store one-time approval with 5 minute TTL
                # Key format: once_allow:{agent_id}:{command_hash}
                import hashlib
                context = json.loads(context_json)
                cmd = context.get("value", "")
                agent_id = context.get("agent_id", "")
                cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
                approval_key = f"once_allow:{agent_id}:{cmd_hash}"
                await redis_client.set(approval_key, "1", expire=300)  # 5 minutes

                await _answer_callback(callback_id=callback_id, text="✅ Allowed once (5 min)")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"✅ ALLOWED ONCE by @{username}\n\nCommand: {cmd[:50]}...\nValid for 5 minutes.",
                    )
                return {"ok": True, "action": "allow_once", "expires_in": 300}

            elif action == "always":
                # Allow always - create a persistent allow rule
                # Retrieve context from Redis
                from app.redis_client import redis_client
                context_json = await redis_client.get(f"tg_ctx:{data}")
                if not context_json:
                    await _answer_callback(callback_id=callback_id, text="❌ Context expired")
                    return {"ok": False, "error": "context_expired"}

                result = await _create_allow_rule_from_context(context_json, username)
                await _answer_callback(callback_id=callback_id, text="✅ Rule created!")
                if cb_chat_id and cb_message_id:
                    rule_id_short = result.get('rule_id', 'N/A')[:8]
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"✅ ALLOW RULE CREATED by @{username}\n\nRule ID: {rule_id_short}",
                    )
                return {"ok": True, "action": "allow_always", "rule_id": result.get("rule_id")}

            elif action == "rule":
                # View rule details - data is first 12 chars of UUID
                rule_info = await _get_rule_info(data)
                await _answer_callback(callback_id=callback_id, text="📋 Rule details shown")
                if cb_chat_id:
                    await _send_message(chat_id=cb_chat_id, text=rule_info)
                return {"ok": True, "action": "view_rule"}

            elif action == "confirm_block":
                # Confirm emergency block
                result = await _activate_emergency_block(int(data), username)
                await _answer_callback(callback_id=callback_id, text="🚨 Emergency block activated!")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"🚨 *EMERGENCY BLOCK ACTIVATED* by @{username}\n\n⚠️ ALL agent actions are now BLOCKED.\n\nUse /unblock to resume normal operation.",
                    )
                return {"ok": True, "action": "emergency_block"}

            elif action == "cancel_block":
                # Cancel emergency block
                _pending_emergency_blocks.pop(int(data), None)
                await _answer_callback(callback_id=callback_id, text="Cancelled")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text="✅ Emergency block cancelled. Normal operation continues.",
                    )
                return {"ok": True, "action": "cancel_block"}

            elif action == "confirm_purge":
                # Confirm PII purge - data is agent_id
                result = await _execute_pii_purge(data, username)
                await _answer_callback(callback_id=callback_id, text="🗑️ PII purge complete!")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"🗑️ *PII PURGE COMPLETE* by @{username}\n\n{result['message']}",
                    )
                return {"ok": True, "action": "purge", "agent_id": data}

            elif action == "cancel_purge":
                # Cancel PII purge
                await _answer_callback(callback_id=callback_id, text="Cancelled")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text="✅ PII purge cancelled. No data was deleted.",
                    )
                return {"ok": True, "action": "cancel_purge"}

            elif action == "vault_delall":
                from app.services import pii_vault as vault_service

                if data == "cancel":
                    await _answer_callback(callback_id=callback_id, text="Cancelled")
                    if cb_chat_id and cb_message_id:
                        await _edit_message(
                            chat_id=cb_chat_id,
                            message_id=cb_message_id,
                            text="✅ Vault delete cancelled. No entries were deleted.",
                        )
                    return {"ok": True, "action": "cancel_vault_delall"}

                # data is the owner_chat_id
                owner_chat_id = data
                async with async_session_factory() as db:
                    entries = await vault_service.list_entries(db=db, owner_chat_id=owner_chat_id)
                    deleted_count = 0
                    for entry in entries:
                        success = await vault_service.delete_entry(
                            db=db, entry_id=str(entry.id), requester_chat_id=owner_chat_id,
                        )
                        if success:
                            deleted_count += 1

                    audit_log = AuditLog(
                        action=AuditAction.PII_VAULT_DELETED,
                        severity=AuditSeverity.WARNING,
                        message=f"All vault entries ({deleted_count}) deleted via Telegram by {username}",
                        details={"owner_chat_id": owner_chat_id, "deleted_by": username, "count": deleted_count},
                    )
                    db.add(audit_log)
                    await db.commit()

                await _answer_callback(callback_id=callback_id, text=f"Deleted {deleted_count} entries")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"🗑️ *Deleted {deleted_count} vault entries.*",
                    )
                return {"ok": True, "action": "vault_delall", "count": deleted_count}

    # Handle messages
    message = data.get("message", {})
    text = message.get("text", "")
    chat_id = message.get("chat", {}).get("id")

    # Check for pending vault value input (user replying with PII to encrypt)
    if text and not text.startswith("/"):
        user = message.get("from", {})
        user_chat_id = str(user.get("id", chat_id))
        from app.redis_client import redis_client as _redis
        pending_json = await _redis.get(f"vault_pending:{user_chat_id}")
        if pending_json:
            await _handle_vault_value_reply(chat_id, text, message, user_chat_id, pending_json)
            return {"ok": True}

    # Handle /start and /help commands

    if text.startswith("/start"):
        await _send_message(
            chat_id=chat_id,
            text=(
                "🐢 *Welcome to Snapper Bot!*\n\n"
                "I'll notify you when AI agents need approval for sensitive actions.\n\n"
                "*Commands:*\n"
                "/status - Check Snapper connection\n"
                "/rules - View active security rules\n"
                "/pending - List pending approvals\n"
                "/test - Test rule enforcement\n"
                "/block - ⚠️ Emergency block all actions\n"
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
                "*Approvals:*\n"
                "/pending - List pending approval requests\n"
                "/approve <id> - Approve a request\n"
                "/deny <id> - Deny a request\n\n"
                "*Rules:*\n"
                "/rules - View active security rules\n"
                "/test - Test rule enforcement\n\n"
                "*PII Vault:*\n"
                "/vault - Manage encrypted PII storage\n"
                "/vault add <label> <category> - Add entry\n"
                "/vault list - View your entries\n\n"
                "*PII Protection:*\n"
                "/pii - Show current PII gate mode\n"
                "/pii protected - Require approval for PII\n"
                "/pii auto - Auto-resolve vault tokens\n\n"
                "*Data:*\n"
                "/purge - 🗑️ Purge PII from agent data\n\n"
                "*Emergency:*\n"
                "/block - ⚠️ Block ALL agent actions\n"
                "/unblock - Resume normal operation\n\n"
                "/status - Check Snapper connection\n"
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
    elif text.startswith("/rules"):
        await _handle_rules_command(chat_id, text)
    elif text.startswith("/block"):
        await _handle_block_command(chat_id, message)
    elif text.startswith("/unblock"):
        await _handle_unblock_command(chat_id, message)
    elif text.startswith("/test"):
        await _handle_test_command(chat_id, text, message)
    elif text.startswith("/vault"):
        await _handle_vault_command(chat_id, text, message)
    elif text.startswith("/pii"):
        await _handle_pii_command(chat_id, text, message)
    elif text.startswith("/purge"):
        await _handle_purge_command(chat_id, text, message)

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


def _escape_markdown(text: str) -> str:
    """Escape special Markdown characters in text."""
    # Characters that need escaping in Telegram Markdown
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text


async def _send_message(chat_id: int, text: str):
    """Send a message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            },
            timeout=30.0,
        )
        if response.status_code != 200:
            logger.error(f"Telegram sendMessage failed: {response.status_code} - {response.text}")
            # Retry without Markdown if parsing failed
            if "parse" in response.text.lower() or "markdown" in response.text.lower():
                logger.info("Retrying without Markdown parsing")
                await client.post(
                    url,
                    json={"chat_id": chat_id, "text": text},
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

    # Add inline keyboard for blocked results
    reply_markup = None
    if result.decision == EvaluationDecision.DENY:
        # Store context in Redis with short key for callback_data (64 byte limit)
        import hashlib
        context_data = json.dumps({
            "type": subcommand,
            "value": arg,
            "agent_id": str(agent_id),
        })
        # Create a short hash key for the context
        context_key = hashlib.sha256(context_data.encode()).hexdigest()[:12]

        # Store context in Redis with 1 hour expiry
        await redis_client.set(f"tg_ctx:{context_key}", context_data, expire=3600)

        buttons = [
            [
                {"text": "✅ Allow Once", "callback_data": f"once:{context_key}"},
                {"text": "📝 Allow Always", "callback_data": f"always:{context_key}"},
            ],
        ]

        if result.blocking_rule:
            rule_id_short = str(result.blocking_rule)[:12]
            buttons.append([{"text": "📋 View Rule", "callback_data": f"rule:{rule_id_short}"}])

        reply_markup = {"inline_keyboard": buttons}

    await _send_message_with_keyboard(
        chat_id=chat_id,
        text="\n".join(response_lines),
        reply_markup=reply_markup,
    )


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


async def _send_message_with_keyboard(chat_id: int, text: str, reply_markup: Optional[dict] = None):
    """Send a message with optional inline keyboard via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup

    async with httpx.AsyncClient() as client:
        response = await client.post(url, json=payload, timeout=30.0)
        if response.status_code != 200:
            logger.error(f"Telegram sendMessage failed: {response.status_code} - {response.text}")
            # Retry without Markdown if parsing failed
            if "parse" in response.text.lower() or "markdown" in response.text.lower():
                logger.info("Retrying without Markdown parsing")
                payload.pop("parse_mode", None)
                await client.post(url, json=payload, timeout=30.0)


async def _handle_rules_command(chat_id: int, text: str):
    """Handle /rules command - list active security rules."""
    # Get test agent for this chat
    agent_id = await _get_or_create_test_agent(chat_id)

    async with async_session_factory() as db:
        # Get rules for this agent (and global rules)
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        ).order_by(Rule.priority.desc()).limit(15)

        result = await db.execute(stmt)
        rules = result.scalars().all()

    if not rules:
        await _send_message(
            chat_id=chat_id,
            text="📋 *Active Rules:*\n\nNo rules configured for your agent.\n\n_Use the Snapper dashboard to create rules._",
        )
        return

    lines = ["📋 *Active Rules:*\n"]
    for rule in rules:
        emoji = "🔴" if rule.action == RuleAction.DENY else "🟢" if rule.action == RuleAction.ALLOW else "🟡"
        scope = "🌍" if rule.agent_id is None else "👤"
        lines.append(f"{emoji} {scope} *{rule.name}*")
        lines.append(f"   _{rule.rule_type.value}_ | Priority: {rule.priority}")

    lines.append(f"\n_Total: {len(rules)} rule(s)_")
    lines.append("_View full details in Snapper dashboard_")

    await _send_message(chat_id=chat_id, text="\n".join(lines))


async def _handle_block_command(chat_id: int, message: dict):
    """Handle /block command - emergency block all with confirmation."""
    _pending_emergency_blocks[chat_id] = datetime.utcnow()

    reply_markup = {
        "inline_keyboard": [
            [
                {"text": "🚨 CONFIRM BLOCK ALL", "callback_data": f"confirm_block:{chat_id}"},
                {"text": "❌ Cancel", "callback_data": f"cancel_block:{chat_id}"},
            ]
        ]
    }

    await _send_message_with_keyboard(
        chat_id=chat_id,
        text=(
            "⚠️ *EMERGENCY BLOCK ALL*\n\n"
            "This will create a high-priority DENY rule that blocks ALL agent actions.\n\n"
            "Are you sure you want to proceed?\n\n"
            "_Use /unblock to resume normal operation._"
        ),
        reply_markup=reply_markup,
    )


async def _handle_unblock_command(chat_id: int, message: dict):
    """Handle /unblock command - resume normal operation."""
    username = message.get("from", {}).get("username", "Unknown")
    agent_id = await _get_or_create_test_agent(chat_id)

    async with async_session_factory() as db:
        # Find and deactivate emergency block rules
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            Rule.name == "🚨 EMERGENCY BLOCK ALL",
            (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        )
        result = await db.execute(stmt)
        emergency_rules = result.scalars().all()

        if not emergency_rules:
            await _send_message(
                chat_id=chat_id,
                text="ℹ️ No emergency block is currently active.",
            )
            return

        for rule in emergency_rules:
            rule.is_active = False

        # Log the action
        audit_log = AuditLog(
            action=AuditAction.RULE_UPDATED,
            severity=AuditSeverity.WARNING,
            agent_id=agent_id,
            message=f"Emergency block deactivated via Telegram by {username}",
            old_value={"is_active": True},
            new_value={"is_active": False, "deactivated_by": username},
        )
        db.add(audit_log)
        await db.commit()

    await _send_message(
        chat_id=chat_id,
        text=f"✅ *Emergency block deactivated* by @{username}\n\nNormal operation resumed. Rules are now evaluated normally.",
    )


async def _activate_emergency_block(chat_id: int, username: str) -> dict:
    """Activate emergency block by creating a high-priority deny-all rule."""
    _pending_emergency_blocks.pop(chat_id, None)
    agent_id = await _get_or_create_test_agent(chat_id)

    async with async_session_factory() as db:
        # Check if emergency block already exists
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.name == "🚨 EMERGENCY BLOCK ALL",
            Rule.agent_id == agent_id,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.is_active = True
            rule_id = existing.id
        else:
            # Create new emergency block rule
            rule = Rule(
                id=uuid4(),
                name="🚨 EMERGENCY BLOCK ALL",
                description=f"Emergency block activated via Telegram by {username}",
                rule_type=RuleType.COMMAND_DENYLIST,
                action=RuleAction.DENY,
                priority=10000,  # Highest priority
                parameters={"patterns": [".*"]},  # Match everything
                agent_id=agent_id,
                is_active=True,
            )
            db.add(rule)
            rule_id = rule.id

        # Log the action
        audit_log = AuditLog(
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.CRITICAL,
            agent_id=agent_id,
            message=f"Emergency block activated via Telegram by {username}",
            new_value={
                "rule_id": str(rule_id),
                "activated_by": username,
                "source": "telegram",
            },
        )
        db.add(audit_log)
        await db.commit()

    return {"rule_id": str(rule_id), "status": "activated"}


async def _create_allow_rule_from_context(context_json: str, username: str) -> dict:
    """Create an allow rule from context JSON string."""
    try:
        context = json.loads(context_json)
    except Exception as e:
        logger.warning(f"Failed to parse context: {e}")
        return {"message": "Failed to parse context", "rule_id": None}

    test_type = context.get("type", "run")
    value = context.get("value", "")
    agent_id_str = context.get("agent_id", "")

    # Try to parse as UUID first, otherwise look up by external_id/name
    agent_id = None
    try:
        agent_id = UUID(agent_id_str)
    except (ValueError, TypeError):
        # Look up agent by external_id or name
        from app.models.agents import Agent
        async with async_session_factory() as db:
            stmt = select(Agent).where(
                (Agent.external_id == agent_id_str) | (Agent.name == agent_id_str),
                Agent.is_deleted == False,
            ).limit(1)
            result = await db.execute(stmt)
            agent = result.scalar_one_or_none()
            if agent:
                agent_id = agent.id
            else:
                return {"message": f"Agent not found: {agent_id_str}", "rule_id": None}

    # Build rule based on test type
    if test_type == "run":
        # Escape regex special chars in the command for exact match
        import re
        escaped = re.escape(value)
        rule_type = RuleType.COMMAND_ALLOWLIST
        parameters = {"patterns": [f"^{escaped}$"]}
        rule_name = f"Allow: {value[:30]}..."
    elif test_type == "install":
        rule_type = RuleType.SKILL_ALLOWLIST
        parameters = {"skills": [value]}
        rule_name = f"Allow skill: {value}"
    elif test_type == "access":
        rule_type = RuleType.FILE_ACCESS
        parameters = {"allowed_paths": [f"^{value}$"]}
        rule_name = f"Allow file: {value[:30]}..."
    elif test_type == "network":
        rule_type = RuleType.NETWORK_EGRESS
        parameters = {"allowed_hosts": [f"^{value}$"]}
        rule_name = f"Allow host: {value}"
    else:
        return {"message": f"Unknown test type: {test_type}", "rule_id": None}

    async with async_session_factory() as db:
        rule = Rule(
            id=uuid4(),
            name=rule_name,
            description=f"Created via Telegram by {username}",
            rule_type=rule_type,
            action=RuleAction.ALLOW,
            priority=500,  # Medium priority
            parameters=parameters,
            agent_id=agent_id,
            is_active=True,
        )
        db.add(rule)

        # Log the action
        audit_log = AuditLog(
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.INFO,
            agent_id=agent_id,
            message=f"Allow rule created via Telegram by {username}",
            new_value={
                "rule_id": str(rule.id),
                "rule_name": rule_name,
                "created_by": username,
                "source": "telegram",
            },
        )
        db.add(audit_log)
        await db.commit()

    return {
        "message": f"Rule created: *{rule_name}*\n\nType: {rule_type.value}\nPriority: 500",
        "rule_id": str(rule.id),
    }


async def _get_rule_info(rule_id_partial: str) -> str:
    """Get detailed information about a rule by partial ID."""
    from sqlalchemy import cast, String

    async with async_session_factory() as db:
        # Search for rule where ID starts with the partial
        stmt = select(Rule).where(
            cast(Rule.id, String).like(f"{rule_id_partial}%")
        ).limit(1)
        result = await db.execute(stmt)
        rule = result.scalar_one_or_none()

    if not rule:
        return f"❓ Rule `{rule_id_partial}...` not found"

    rule_id = str(rule.id)

    emoji = "🔴" if rule.action == RuleAction.DENY else "🟢" if rule.action == RuleAction.ALLOW else "🟡"
    scope = "Global" if rule.agent_id is None else "Agent-specific"

    lines = [
        f"📋 *Rule Details*\n",
        f"*Name:* {rule.name}",
        f"*ID:* `{rule_id[:8]}...`",
        f"*Type:* {rule.rule_type.value if hasattr(rule.rule_type, 'value') else rule.rule_type}",
        f"*Action:* {emoji} {(rule.action.value if hasattr(rule.action, 'value') else rule.action).upper()}",
        f"*Priority:* {rule.priority}",
        f"*Scope:* {scope}",
        f"*Active:* {'Yes' if rule.is_active else 'No'}",
    ]

    if rule.description:
        lines.append(f"\n*Description:*\n{rule.description}")

    if rule.parameters:
        params_str = json.dumps(rule.parameters, indent=2)
        if len(params_str) > 200:
            params_str = params_str[:200] + "..."
        lines.append(f"\n*Parameters:*\n```\n{params_str}\n```")

    return "\n".join(lines)


async def _handle_vault_value_reply(chat_id: int, text: str, message: dict, user_chat_id: str, pending_json: str):
    """Handle a plain text reply that contains the PII value for a pending vault add."""
    from app.models.pii_vault import PIICategory
    from app.services import pii_vault as vault_service
    from app.redis_client import redis_client

    username = message.get("from", {}).get("username", message.get("from", {}).get("first_name", "Unknown"))

    if text.strip() == "/cancel":
        await redis_client.delete(f"vault_pending:{user_chat_id}")
        await _send_message(chat_id=chat_id, text="Vault entry creation cancelled.")
        return

    pending = json.loads(pending_json)
    raw_value = text.strip()

    # Delete the user's message containing raw PII immediately
    await _delete_user_message(chat_id, message)

    # Handle multi-step flows
    step = pending.get("step")
    if step:
        cat = pending["category"]

        # --- Credit Card: number → exp → cvc ---
        if cat == "credit_card":
            if step == "number":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
                    await _send_message(
                        chat_id=chat_id,
                        text="That doesn't look like a valid card number. Please enter 13-19 digits.\n_Type /cancel to abort._",
                    )
                    return
                pending["card_number"] = digits
                pending["step"] = "exp"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 2/3: Reply with the *expiration date*\n(e.g., `12/27` or `12/2027`)\n\n_Type /cancel to abort._",
                )
                return
            elif step == "exp":
                exp_clean = raw_value.strip().replace("-", "/")
                if not re.match(r"^\d{1,2}/\d{2,4}$", exp_clean):
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter expiration as `MM/YY` or `MM/YYYY`.\n_Type /cancel to abort._",
                    )
                    return
                pending["card_exp"] = exp_clean
                pending["step"] = "cvc"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 3/3: Reply with the *CVC/CVV*\n(3 or 4 digit security code)\n\n_Type /cancel to abort._",
                )
                return
            elif step == "cvc":
                cvc_clean = raw_value.strip()
                if not re.match(r"^\d{3,4}$", cvc_clean):
                    await _send_message(
                        chat_id=chat_id,
                        text="CVC should be 3 or 4 digits.\n_Type /cancel to abort._",
                    )
                    return
                raw_value = json.dumps({
                    "number": pending["card_number"],
                    "exp": pending["card_exp"],
                    "cvc": cvc_clean,
                })
                # Fall through to create entry

        # --- Address: street → city → state → zip ---
        elif cat == "address":
            if step == "street":
                if len(raw_value) < 3:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a valid street address.\n_Type /cancel to abort._",
                    )
                    return
                pending["addr_street"] = raw_value
                pending["step"] = "city"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 2/4: Reply with the *city*\n\n_Type /cancel to abort._",
                )
                return
            elif step == "city":
                if len(raw_value) < 2:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a valid city name.\n_Type /cancel to abort._",
                    )
                    return
                pending["addr_city"] = raw_value
                pending["step"] = "state"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 3/4: Reply with the *state* (e.g., `CA`, `NY`)\n\n_Type /cancel to abort._",
                )
                return
            elif step == "state":
                state_clean = raw_value.strip().upper()
                if len(state_clean) < 2:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a valid state abbreviation.\n_Type /cancel to abort._",
                    )
                    return
                pending["addr_state"] = state_clean
                pending["step"] = "zip"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 4/4: Reply with the *ZIP code*\n\n_Type /cancel to abort._",
                )
                return
            elif step == "zip":
                zip_clean = raw_value.strip()
                if not re.match(r"^\d{5}(-\d{4})?$", zip_clean):
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a valid ZIP code (e.g., `90210` or `90210-1234`).\n_Type /cancel to abort._",
                    )
                    return
                raw_value = json.dumps({
                    "street": pending["addr_street"],
                    "city": pending["addr_city"],
                    "state": pending["addr_state"],
                    "zip": zip_clean,
                })
                # Fall through to create entry

        # --- Name: first → last ---
        elif cat == "name":
            if step == "first":
                if len(raw_value) < 1:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a first name.\n_Type /cancel to abort._",
                    )
                    return
                pending["name_first"] = raw_value
                pending["step"] = "last"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 2/2: Reply with the *last name*\n\n_Type /cancel to abort._",
                )
                return
            elif step == "last":
                if len(raw_value) < 1:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a last name.\n_Type /cancel to abort._",
                    )
                    return
                raw_value = json.dumps({
                    "first": pending["name_first"],
                    "last": raw_value,
                })
                # Fall through to create entry

        # --- Bank Account: routing → account ---
        elif cat == "bank_account":
            if step == "routing":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) != 9:
                    await _send_message(
                        chat_id=chat_id,
                        text="Routing number should be exactly 9 digits.\n_Type /cancel to abort._",
                    )
                    return
                pending["bank_routing"] = digits
                pending["step"] = "account"
                await redis_client.set(f"vault_pending:{user_chat_id}", json.dumps(pending), expire=300)
                await _send_message(
                    chat_id=chat_id,
                    text="Step 2/2: Reply with the *account number*\n\n_Type /cancel to abort._",
                )
                return
            elif step == "account":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) < 4:
                    await _send_message(
                        chat_id=chat_id,
                        text="Please enter a valid account number (digits only).\n_Type /cancel to abort._",
                    )
                    return
                raw_value = json.dumps({
                    "routing": pending["bank_routing"],
                    "account": digits,
                })
                # Fall through to create entry

    category = PIICategory(pending["category"])

    async with async_session_factory() as db:
        entry = await vault_service.create_entry(
            db=db,
            owner_chat_id=pending["owner_chat_id"],
            owner_name=pending["owner_name"],
            label=pending["label"],
            category=category,
            raw_value=raw_value,
        )

        audit_log = AuditLog(
            action=AuditAction.PII_VAULT_CREATED,
            severity=AuditSeverity.INFO,
            message=f"Vault entry '{pending['label']}' created via Telegram by {username}",
            details={
                "entry_id": str(entry.id),
                "category": pending["category"],
                "owner_chat_id": pending["owner_chat_id"],
            },
        )
        db.add(audit_log)
        await db.commit()

    await redis_client.delete(f"vault_pending:{user_chat_id}")

    await _send_message(
        chat_id=chat_id,
        text=(
            f"🔐 *Vault entry created!*\n\n"
            f"*Label:* {entry.label}\n"
            f"*Category:* `{pending['category']}`\n"
            f"*Masked:* `{entry.masked_value}`\n"
            f"*Token:* `{entry.token}`\n\n"
            "Give this token to your AI agent instead of the real value.\n"
            "Snapper will intercept and require approval before it's submitted."
        ),
    )


async def _delete_user_message(chat_id: int, message: dict):
    """Try to delete a user's message containing sensitive data."""
    try:
        msg_id = message.get("message_id")
        if msg_id:
            delete_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/deleteMessage"
            async with httpx.AsyncClient() as client:
                await client.post(delete_url, json={"chat_id": chat_id, "message_id": msg_id}, timeout=10.0)
    except Exception as e:
        logger.warning(f"Could not delete PII message: {e}")


async def _handle_pii_command(chat_id: int, text: str, message: dict):
    """Handle /pii command to toggle PII gate mode between protected and auto."""
    username = message.get("from", {}).get("username", "Unknown")
    parts = text.strip().split(None, 1)
    subcommand = parts[1].strip().lower() if len(parts) > 1 else ""

    async with async_session_factory() as db:
        # Find the PII gate rule
        stmt = select(Rule).where(
            Rule.rule_type == RuleType.PII_GATE,
            Rule.is_active == True,
        )
        result = await db.execute(stmt)
        pii_rule = result.scalar_one_or_none()

        if not pii_rule:
            await _send_message(
                chat_id=chat_id,
                text=(
                    "No active PII gate rule found.\n\n"
                    "Create one first via the dashboard or API using "
                    "the `pii-gate-protection` template."
                ),
            )
            return

        current_mode = pii_rule.parameters.get("pii_mode", "protected")

        if not subcommand:
            # Show current mode
            mode_emoji = "🛡️" if current_mode == "protected" else "⚡"
            await _send_message(
                chat_id=chat_id,
                text=(
                    f"*PII Gate Mode:* {mode_emoji} `{current_mode}`\n\n"
                    f"🛡️ *protected* — Vault tokens require human approval\n"
                    f"⚡ *auto* — Vault tokens resolved automatically\n\n"
                    f"Use `/pii protected` or `/pii auto` to change."
                ),
            )
            return

        if subcommand not in ("protected", "auto"):
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/pii protected` or `/pii auto`",
            )
            return

        if subcommand == current_mode:
            mode_emoji = "🛡️" if current_mode == "protected" else "⚡"
            await _send_message(
                chat_id=chat_id,
                text=f"PII gate is already in {mode_emoji} `{current_mode}` mode.",
            )
            return

        # Update the rule parameters
        new_params = dict(pii_rule.parameters)
        new_params["pii_mode"] = subcommand
        pii_rule.parameters = new_params

        # Log the change
        audit_log = AuditLog(
            action=AuditAction.RULE_UPDATED,
            severity=AuditSeverity.WARNING,
            message=f"PII gate mode changed to '{subcommand}' via Telegram by {username}",
            old_value={"pii_mode": current_mode},
            new_value={"pii_mode": subcommand},
        )
        db.add(audit_log)
        await db.commit()

        mode_emoji = "🛡️" if subcommand == "protected" else "⚡"
        if subcommand == "protected":
            desc = "Vault tokens will require human approval before being resolved."
        else:
            desc = "Vault tokens will be resolved automatically without approval."

        await _send_message(
            chat_id=chat_id,
            text=f"{mode_emoji} PII gate mode set to *{subcommand}*\n\n{desc}",
        )


async def _handle_vault_command(chat_id: int, text: str, message: dict):
    """
    Handle /vault command - manage PII vault entries.

    Usage:
        /vault              - Show help and list entries
        /vault add <label> <category> - Start adding a new entry (prompts for value)
        /vault list         - List your vault entries (masked)
        /vault delete <token> - Delete a vault entry
        /vault domains <token> add <domain> - Add allowed domain
        /vault domains <token> remove <domain> - Remove allowed domain
    """
    from app.models.pii_vault import PIICategory
    from app.services import pii_vault as vault_service

    user = message.get("from", {})
    user_chat_id = str(user.get("id", chat_id))
    username = user.get("username", user.get("first_name", "Unknown"))

    parts = text.split(maxsplit=3)
    subcommand = parts[1].lower() if len(parts) > 1 else "help"

    if subcommand == "help" or (subcommand == "list" and len(parts) == 2) or len(parts) == 1:
        if subcommand == "list" or len(parts) == 1:
            # Show entries + help
            async with async_session_factory() as db:
                entries = await vault_service.list_entries(db=db, owner_chat_id=user_chat_id)

            if entries:
                lines = ["🔐 *Your PII Vault*\n"]
                for e in entries[:15]:
                    cat = e.category.value if hasattr(e.category, "value") else e.category
                    lines.append(f"  `{cat}`: *{e.label}*")
                    lines.append(f"    `{e.token}`")
                    lines.append(f"    Masked: `{e.masked_value}`")
                    if e.allowed_domains:
                        lines.append(f"    Domains: {', '.join(e.allowed_domains)}")
                    if e.use_count > 0:
                        lines.append(f"    Used: {e.use_count} time(s)")
                    lines.append("")
                lines.append(f"_Total: {len(entries)} entry(ies)_")
            else:
                lines = ["🔐 *Your PII Vault*\n", "_No entries yet._\n"]

            lines.append("\n*Commands:*")
            lines.append("`/vault add <label> <category>`")
            lines.append("  Categories: cc, name, address, phone, email, ssn, passport, bank\\_account, custom")
            lines.append("`/vault list` - List your entries")
            lines.append("`/vault delete <token>` - Remove entry")
            lines.append("`/vault domains <token> add <domain>`")

            await _send_message(chat_id=chat_id, text="\n".join(lines))
            return

        # Explicit /vault help
        await _send_message(
            chat_id=chat_id,
            text=(
                "🔐 *PII Vault Help*\n\n"
                "Store sensitive data (credit cards, addresses, etc.) encrypted in Snapper.\n"
                "Get a token to give to your AI agent instead of raw data.\n\n"
                "*Add entry:*\n"
                "`/vault add \"My Visa\" credit_card`\n"
                "Then reply with the value when prompted.\n\n"
                "*List entries:*\n"
                "`/vault list`\n\n"
                "*Delete entry:*\n"
                '`/vault delete {{SNAPPER_VAULT:a7f3b2c1}}`\n\n'
                "*Manage domains:*\n"
                '`/vault domains {{SNAPPER_VAULT:a7f3b2c1}} add *.expedia.com`\n\n'
                "*Categories:*\n"
                "credit\\_card, name, address, phone, email, ssn, passport, bank\\_account, custom"
            ),
        )
        return

    elif subcommand == "add":
        # /vault add <label> <category>
        # Parse: /vault add "My Visa" credit_card  OR  /vault add My-Visa credit_card
        remaining = text[len("/vault add"):].strip()

        if not remaining:
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/vault add <label> <category>`\n\nExample: `/vault add \"My Visa\" credit_card`",
            )
            return

        # Try to parse label and category
        # Support quoted labels: /vault add "My Visa Card" credit_card
        import shlex
        try:
            tokens = shlex.split(remaining)
        except ValueError:
            tokens = remaining.split()

        if len(tokens) < 2:
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/vault add <label> <category>`\n\nExample: `/vault add \"My Visa\" credit_card`",
            )
            return

        category_str = tokens[-1].lower()
        label = " ".join(tokens[:-1])

        # Category aliases for user-friendly input
        category_aliases = {
            "cc": "credit_card",
            "card": "credit_card",
            "creditcard": "credit_card",
            "credit": "credit_card",
            "addr": "address",
            "tel": "phone",
            "telephone": "phone",
            "mobile": "phone",
            "mail": "email",
            "social": "ssn",
            "bank": "bank_account",
            "account": "bank_account",
        }
        category_str = category_aliases.get(category_str, category_str)

        # Validate category
        valid_categories = [c.value for c in PIICategory]
        if category_str not in valid_categories:
            friendly = "credit\\_card (or cc), name, address, phone, email, ssn, passport, bank\\_account, custom"
            await _send_message(
                chat_id=chat_id,
                text=f"Unknown category: `{category_str}`\n\nValid: {friendly}",
            )
            return

        # Store pending add in Redis so we can receive the value in next message
        from app.redis_client import redis_client

        # Multi-step categories
        multi_step_categories = {
            "credit_card": {
                "step": "number",
                "total_steps": 3,
                "prompt": (
                    f"🔐 *Adding credit card:* {label}\n\n"
                    "Step 1/3: Reply with the *card number*\n"
                    "(e.g., `4111111111111234`)\n\n"
                    "⚠️ Your message will be deleted after processing.\n"
                    "_Type /cancel to abort._"
                ),
            },
            "address": {
                "step": "street",
                "total_steps": 4,
                "prompt": (
                    f"🔐 *Adding address:* {label}\n\n"
                    "Step 1/4: Reply with the *street address*\n"
                    "(e.g., `123 Main St, Apt 4B`)\n\n"
                    "⚠️ Your message will be deleted after processing.\n"
                    "_Type /cancel to abort._"
                ),
            },
            "name": {
                "step": "first",
                "total_steps": 2,
                "prompt": (
                    f"🔐 *Adding name:* {label}\n\n"
                    "Step 1/2: Reply with the *first name*\n\n"
                    "⚠️ Your message will be deleted after processing.\n"
                    "_Type /cancel to abort._"
                ),
            },
            "bank_account": {
                "step": "routing",
                "total_steps": 2,
                "prompt": (
                    f"🔐 *Adding bank account:* {label}\n\n"
                    "Step 1/2: Reply with the *routing number* (9 digits)\n\n"
                    "⚠️ Your message will be deleted after processing.\n"
                    "_Type /cancel to abort._"
                ),
            },
        }

        if category_str in multi_step_categories:
            ms = multi_step_categories[category_str]
            pending_data = json.dumps({
                "label": label,
                "category": category_str,
                "owner_chat_id": user_chat_id,
                "owner_name": username,
                "step": ms["step"],
            })
            await redis_client.set(f"vault_pending:{user_chat_id}", pending_data, expire=300)
            await _send_message(chat_id=chat_id, text=ms["prompt"])
        else:
            pending_data = json.dumps({
                "label": label,
                "category": category_str,
                "owner_chat_id": user_chat_id,
                "owner_name": username,
            })
            await redis_client.set(f"vault_pending:{user_chat_id}", pending_data, expire=300)

            category_hints = {
                "phone": "phone number (e.g., `+15551234567`)",
                "email": "email address",
                "ssn": "SSN (e.g., `123-45-6789`)",
                "passport": "passport number",
                "custom": "value",
            }
            hint = category_hints.get(category_str, "value")

            await _send_message(
                chat_id=chat_id,
                text=(
                    f"🔐 *Adding vault entry:* {label} (`{category_str}`)\n\n"
                    f"Please reply with your {hint}.\n\n"
                    "⚠️ The value will be encrypted immediately and the message should be deleted.\n"
                    "_Type /cancel to abort._"
                ),
            )
        return

    elif subcommand == "delete":
        # /vault delete * — delete all entries (with confirm)
        # /vault delete {{SNAPPER_VAULT:a7f3b2c1}} — delete specific entry
        if len(parts) < 3:
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/vault delete <token>` or `/vault delete *`",
            )
            return

        target = parts[2].strip()

        if target == "*":
            # Count entries first
            async with async_session_factory() as db:
                entries = await vault_service.list_entries(db=db, owner_chat_id=user_chat_id)
                if not entries:
                    await _send_message(chat_id=chat_id, text="You have no vault entries to delete.")
                    return

                await _send_message_with_keyboard(
                    chat_id=chat_id,
                    text=f"⚠️ This will delete *all {len(entries)}* vault entries. Are you sure?",
                    reply_markup={
                        "inline_keyboard": [
                            [
                                {"text": "🗑️ DELETE ALL", "callback_data": f"vault_delall:{user_chat_id}"},
                                {"text": "❌ Cancel", "callback_data": "vault_delall:cancel"},
                            ]
                        ]
                    },
                )
            return

        # Single token delete
        async with async_session_factory() as db:
            entry = await vault_service.get_entry_by_token(db=db, token=target)
            if not entry:
                await _send_message(chat_id=chat_id, text=f"Entry not found for token: `{target}`")
                return

            success = await vault_service.delete_entry(
                db=db,
                entry_id=str(entry.id),
                requester_chat_id=user_chat_id,
            )

            if success:
                audit_log = AuditLog(
                    action=AuditAction.PII_VAULT_DELETED,
                    severity=AuditSeverity.WARNING,
                    message=f"Vault entry '{entry.label}' deleted via Telegram by {username}",
                    details={"entry_id": str(entry.id), "deleted_by": username},
                )
                db.add(audit_log)
                await db.commit()
                await _send_message(chat_id=chat_id, text=f"🗑️ Vault entry *{entry.label}* deleted.")
            else:
                await _send_message(chat_id=chat_id, text="Failed to delete entry. You may not own it.")
        return

    elif subcommand == "domains":
        # /vault domains <token> add|remove <domain>
        if len(parts) < 4:
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/vault domains <token> add|remove <domain>`",
            )
            return

        remaining = text[len("/vault domains"):].strip()
        domain_parts = remaining.split(maxsplit=2)

        if len(domain_parts) < 3:
            await _send_message(
                chat_id=chat_id,
                text="Usage: `/vault domains <token> add|remove <domain>`",
            )
            return

        token = domain_parts[0]
        domain_action = domain_parts[1].lower()
        domain = domain_parts[2].strip()

        async with async_session_factory() as db:
            entry = await vault_service.get_entry_by_token(db=db, token=token)
            if not entry:
                await _send_message(chat_id=chat_id, text=f"Entry not found for token: `{token}`")
                return

            if entry.owner_chat_id != user_chat_id:
                await _send_message(chat_id=chat_id, text="You don't own this entry.")
                return

            domains = list(entry.allowed_domains or [])

            if domain_action == "add":
                if domain not in domains:
                    domains.append(domain)
                    entry.allowed_domains = domains
                    await db.commit()
                    await _send_message(chat_id=chat_id, text=f"Added domain `{domain}` to *{entry.label}*")
                else:
                    await _send_message(chat_id=chat_id, text=f"Domain `{domain}` already in list.")
            elif domain_action == "remove":
                if domain in domains:
                    domains.remove(domain)
                    entry.allowed_domains = domains
                    await db.commit()
                    await _send_message(chat_id=chat_id, text=f"Removed domain `{domain}` from *{entry.label}*")
                else:
                    await _send_message(chat_id=chat_id, text=f"Domain `{domain}` not in list.")
            else:
                await _send_message(chat_id=chat_id, text="Usage: `/vault domains <token> add|remove <domain>`")
        return

    else:
        # Check if this might be a value reply for a pending vault add
        from app.redis_client import redis_client
        pending_json = await redis_client.get(f"vault_pending:{user_chat_id}")

        if pending_json:
            # This is a value reply to a /vault add
            pending = json.loads(pending_json)

            if text.strip() == "/cancel":
                await redis_client.delete(f"vault_pending:{user_chat_id}")
                await _send_message(chat_id=chat_id, text="Vault entry creation cancelled.")
                return

            raw_value = text.strip()
            category = PIICategory(pending["category"])

            async with async_session_factory() as db:
                entry = await vault_service.create_entry(
                    db=db,
                    owner_chat_id=pending["owner_chat_id"],
                    owner_name=pending["owner_name"],
                    label=pending["label"],
                    category=category,
                    raw_value=raw_value,
                )

                # Audit log
                audit_log = AuditLog(
                    action=AuditAction.PII_VAULT_CREATED,
                    severity=AuditSeverity.INFO,
                    message=f"Vault entry '{pending['label']}' created via Telegram by {username}",
                    details={
                        "entry_id": str(entry.id),
                        "category": pending["category"],
                        "owner_chat_id": pending["owner_chat_id"],
                    },
                )
                db.add(audit_log)
                await db.commit()

            # Clean up pending state
            await redis_client.delete(f"vault_pending:{user_chat_id}")

            # Try to delete the user's message containing the raw PII
            try:
                msg_id = message.get("message_id")
                if msg_id:
                    delete_url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/deleteMessage"
                    async with httpx.AsyncClient() as client:
                        await client.post(delete_url, json={"chat_id": chat_id, "message_id": msg_id}, timeout=10.0)
            except Exception as e:
                logger.warning(f"Could not delete PII message: {e}")

            await _send_message(
                chat_id=chat_id,
                text=(
                    f"🔐 *Vault entry created!*\n\n"
                    f"*Label:* {entry.label}\n"
                    f"*Category:* `{pending['category']}`\n"
                    f"*Masked:* {entry.masked_value}\n"
                    f"*Token:* `{entry.token}`\n\n"
                    "Give this token to your AI agent instead of the real value.\n"
                    "Snapper will intercept and require approval before it's submitted."
                ),
            )
            return

        await _send_message(
            chat_id=chat_id,
            text=f"Unknown vault command: `{subcommand}`\n\nTry `/vault help`",
        )


async def _handle_purge_command(chat_id: int, text: str, message: dict):
    """
    Handle /purge command - purge PII from agent data with confirmation.

    Usage:
        /purge              - Show agents and purge options
        /purge <agent_id>   - Purge specific agent (with confirm)
        /purge *            - Purge ALL agents (with confirm)
    """
    from app.models.agents import Agent

    parts = text.split(maxsplit=1)

    # Get test agent for this chat (to show as default option)
    test_agent_id = await _get_or_create_test_agent(chat_id)

    if len(parts) > 1:
        arg = parts[1].strip()

        # Check for purge all
        if arg in ("*", "all"):
            async with async_session_factory() as db:
                stmt = select(Agent).where(Agent.is_deleted == False)
                result = await db.execute(stmt)
                agents = result.scalars().all()

            if not agents:
                await _send_message(
                    chat_id=chat_id,
                    text="📋 No agents found to purge.",
                )
                return

            reply_markup = {
                "inline_keyboard": [
                    [
                        {"text": f"🗑️ PURGE ALL ({len(agents)} agents)", "callback_data": "confirm_purge:*"},
                        {"text": "❌ Cancel", "callback_data": "cancel_purge:0"},
                    ]
                ]
            }

            agent_list = "\n".join([f"• {a.name} (`{str(a.id)[:8]}...`)" for a in agents[:10]])
            if len(agents) > 10:
                agent_list += f"\n_...and {len(agents) - 10} more_"

            await _send_message_with_keyboard(
                chat_id=chat_id,
                text=(
                    f"⚠️ *PURGE ALL AGENTS*\n\n"
                    f"This will purge PII from *{len(agents)} agents*:\n\n"
                    f"{agent_list}\n\n"
                    "⚠️ *This action is IRREVERSIBLE.*\n\n"
                    "Are you sure?"
                ),
                reply_markup=reply_markup,
            )
            return

        # Specific agent ID provided
        agent_id_partial = arg

        # Look up agent by partial ID
        from sqlalchemy import cast, String
        async with async_session_factory() as db:
            stmt = select(Agent).where(
                cast(Agent.id, String).like(f"{agent_id_partial}%"),
                Agent.is_deleted == False,
            ).limit(1)
            result = await db.execute(stmt)
            agent = result.scalar_one_or_none()

        if not agent:
            await _send_message(
                chat_id=chat_id,
                text=f"❓ Agent `{agent_id_partial}...` not found.\n\nUse `/purge` to see available agents.",
            )
            return

        # Show confirmation for this specific agent
        agent_id_str = str(agent.id)
        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "🗑️ CONFIRM PURGE", "callback_data": f"confirm_purge:{agent_id_str[:12]}"},
                    {"text": "❌ Cancel", "callback_data": "cancel_purge:0"},
                ]
            ]
        }

        await _send_message_with_keyboard(
            chat_id=chat_id,
            text=(
                f"⚠️ *PII PURGE - {agent.name}*\n\n"
                f"Agent ID: `{agent_id_str[:8]}...`\n\n"
                "This will permanently delete:\n"
                "• Conversation history with PII\n"
                "• Memory files (SOUL.md, MEMORY.md)\n"
                "• Cached session data\n"
                "• Audit logs containing PII patterns\n\n"
                "⚠️ *This action is IRREVERSIBLE.*\n\n"
                "Are you sure?"
            ),
            reply_markup=reply_markup,
        )
        return

    # No agent specified - show list of agents
    async with async_session_factory() as db:
        stmt = select(Agent).where(Agent.is_deleted == False).limit(10)
        result = await db.execute(stmt)
        agents = result.scalars().all()

    if not agents:
        await _send_message(
            chat_id=chat_id,
            text="📋 *PII Purge*\n\nNo agents found.\n\n_Create an agent first using the Snapper dashboard._",
        )
        return

    lines = [
        "🗑️ *PII Purge*\n",
        "Select an agent to purge PII data:\n",
    ]
    for agent in agents:
        agent_id_str = str(agent.id)[:8]
        lines.append(f"• `{agent_id_str}` - {agent.name}")

    lines.append("\n*Usage:* `/purge <agent_id>`")
    lines.append("_Example:_ `/purge " + str(agents[0].id)[:8] + "`")

    await _send_message(chat_id=chat_id, text="\n".join(lines))


async def _execute_pii_purge(agent_id_partial: str, username: str) -> dict:
    """Execute PII purge for an agent or all agents."""
    from app.models.agents import Agent
    from app.redis_client import redis_client
    from sqlalchemy import cast, String
    from app.utils.pii_patterns import PII_PATTERNS_FULL, redact_pii
    from app.models.audit_logs import AuditLog

    # Handle purge all
    if agent_id_partial == "*":
        async with async_session_factory() as db:
            stmt = select(Agent).where(Agent.is_deleted == False)
            result = await db.execute(stmt)
            agents = result.scalars().all()

            if not agents:
                return {"message": "No agents found"}

            total_redacted = 0
            total_cache_deleted = 0
            agent_count = len(agents)

            for agent in agents:
                # Redact PII in audit logs for this agent
                stmt = select(AuditLog).where(AuditLog.agent_id == agent.id)
                result = await db.execute(stmt)
                audit_logs = result.scalars().all()

                for log in audit_logs:
                    if log.message:
                        log.message, count = redact_pii(log.message, PII_PATTERNS_FULL)
                        if count > 0:
                            total_redacted += 1

                # Clear Redis cache
                patterns = [
                    f"agent:{agent.id}:*",
                    f"rate_limit:agent:{agent.id}:*",
                    f"session:{agent.id}:*",
                ]
                for pattern in patterns:
                    keys = await redis_client.keys(pattern)
                    for key in keys:
                        await redis_client.delete(key)
                        total_cache_deleted += 1

            # Log the purge action
            purge_log = AuditLog(
                action=AuditAction.PII_PURGE,
                severity=AuditSeverity.CRITICAL,
                message=f"PII purge ALL ({agent_count} agents) executed via Telegram by {username}",
                new_value={
                    "agent_count": agent_count,
                    "purged_by": username,
                    "source": "telegram",
                    "audit_logs_redacted": total_redacted,
                    "cache_keys_deleted": total_cache_deleted,
                },
            )
            db.add(purge_log)
            await db.commit()

        return {
            "message": (
                f"*Agents purged:* {agent_count}\n"
                f"*Audit logs redacted:* {total_redacted}\n"
                f"*Cache keys deleted:* {total_cache_deleted}\n\n"
                "_For complete PII removal from OpenClaw, also run:_\n"
                "`openclaw agent --purge-pii`"
            ),
            "agent_count": agent_count,
            "redacted_count": total_redacted,
            "cache_keys_deleted": total_cache_deleted,
        }

    # Single agent purge
    async with async_session_factory() as db:
        stmt = select(Agent).where(
            cast(Agent.id, String).like(f"{agent_id_partial}%"),
            Agent.is_deleted == False,
        ).limit(1)
        result = await db.execute(stmt)
        agent = result.scalar_one_or_none()

        if not agent:
            return {"message": f"Agent `{agent_id_partial}...` not found"}

        agent_id = agent.id
        agent_name = agent.name

        # Redact PII in audit logs for this agent
        stmt = select(AuditLog).where(AuditLog.agent_id == agent_id)
        result = await db.execute(stmt)
        audit_logs = result.scalars().all()

        redacted_count = 0
        for log in audit_logs:
            if log.message:
                log.message, count = redact_pii(log.message, PII_PATTERNS_FULL)
                if count > 0:
                    redacted_count += 1

        # Log the purge action
        purge_log = AuditLog(
            action=AuditAction.PII_PURGE,
            severity=AuditSeverity.WARNING,
            agent_id=agent_id,
            message=f"PII purge executed via Telegram by {username}",
            new_value={
                "agent_id": str(agent_id),
                "agent_name": agent_name,
                "purged_by": username,
                "source": "telegram",
                "audit_logs_redacted": redacted_count,
            },
        )
        db.add(purge_log)
        await db.commit()

    # Clear Redis cache for this agent
    cache_keys_deleted = 0
    patterns = [
        f"agent:{agent_id}:*",
        f"rate_limit:agent:{agent_id}:*",
        f"session:{agent_id}:*",
    ]
    for pattern in patterns:
        keys = await redis_client.keys(pattern)
        for key in keys:
            await redis_client.delete(key)
            cache_keys_deleted += 1

    return {
        "message": (
            f"*Agent:* {agent_name}\n"
            f"*Audit logs redacted:* {redacted_count}\n"
            f"*Cache keys deleted:* {cache_keys_deleted}\n\n"
            "_For complete PII removal from OpenClaw, also run:_\n"
            "`openclaw agent --purge-pii`"
        ),
        "agent_id": str(agent_id),
        "redacted_count": redacted_count,
        "cache_keys_deleted": cache_keys_deleted,
    }
