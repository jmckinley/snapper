"""Telegram bot webhook for approval handling and rule testing."""

import json
import logging
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

# Store test agent IDs per chat (in-memory for simplicity)
_test_agents: dict[int, UUID] = {}

# Pending emergency block confirmations (chat_id -> timestamp)
_pending_emergency_blocks: dict[int, datetime] = {}


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

            elif action == "allow_once":
                # Allow once - just acknowledge, no persistent rule created
                await _answer_callback(callback_id=callback_id, text="✅ Allowed once (no rule created)")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"✅ *ALLOWED ONCE* by @{username}\n\n_No permanent rule created. This action would be allowed this time only._",
                    )
                return {"ok": True, "action": "allow_once"}

            elif action == "allow_always":
                # Allow always - create a persistent allow rule
                result = await _create_allow_rule_from_context(data, username)
                await _answer_callback(callback_id=callback_id, text="✅ Rule created!")
                if cb_chat_id and cb_message_id:
                    await _edit_message(
                        chat_id=cb_chat_id,
                        message_id=cb_message_id,
                        text=f"✅ *ALLOW RULE CREATED* by @{username}\n\n{result['message']}\n\n_Rule ID: `{result.get('rule_id', 'N/A')[:8]}...`_",
                    )
                return {"ok": True, "action": "allow_always", "rule_id": result.get("rule_id")}

            elif action == "view_rule":
                # View rule details
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

    # Add inline keyboard for blocked results
    reply_markup = None
    if result.decision == EvaluationDecision.DENY:
        # Encode context for allow_always callback
        context_data = json.dumps({
            "type": subcommand,
            "value": arg,
            "agent_id": str(agent_id),
        })
        # Base64-ish encode to fit in callback_data (max 64 bytes)
        import base64
        encoded_context = base64.urlsafe_b64encode(context_data.encode()).decode()[:60]

        reply_markup = {
            "inline_keyboard": [
                [
                    {"text": "✅ Allow Once", "callback_data": f"allow_once:{encoded_context}"},
                    {"text": "📝 Allow Always", "callback_data": f"allow_always:{encoded_context}"},
                ],
                [
                    {"text": "📋 View Rule", "callback_data": f"view_rule:{result.blocking_rule}"},
                ] if result.blocking_rule else [],
            ]
        }
        # Clean up empty rows
        reply_markup["inline_keyboard"] = [row for row in reply_markup["inline_keyboard"] if row]

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


async def _create_allow_rule_from_context(encoded_context: str, username: str) -> dict:
    """Create an allow rule from encoded context data."""
    import base64

    try:
        # Decode context - may be truncated, so be lenient
        padding = 4 - len(encoded_context) % 4
        if padding != 4:
            encoded_context += "=" * padding
        context_json = base64.urlsafe_b64decode(encoded_context.encode()).decode()
        context = json.loads(context_json)
    except Exception as e:
        logger.warning(f"Failed to decode context: {e}")
        return {"message": "Failed to decode context", "rule_id": None}

    test_type = context.get("type", "run")
    value = context.get("value", "")
    agent_id = UUID(context.get("agent_id"))

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


async def _get_rule_info(rule_id: str) -> str:
    """Get detailed information about a rule."""
    try:
        rule_uuid = UUID(rule_id)
    except ValueError:
        return "❓ Invalid rule ID format"

    async with async_session_factory() as db:
        stmt = select(Rule).where(Rule.id == rule_uuid)
        result = await db.execute(stmt)
        rule = result.scalar_one_or_none()

    if not rule:
        return f"❓ Rule `{rule_id[:8]}...` not found"

    emoji = "🔴" if rule.action == RuleAction.DENY else "🟢" if rule.action == RuleAction.ALLOW else "🟡"
    scope = "Global" if rule.agent_id is None else "Agent-specific"

    lines = [
        f"📋 *Rule Details*\n",
        f"*Name:* {rule.name}",
        f"*ID:* `{rule_id[:8]}...`",
        f"*Type:* {rule.rule_type.value}",
        f"*Action:* {emoji} {rule.action.value.upper()}",
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
