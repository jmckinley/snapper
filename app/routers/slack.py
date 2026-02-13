"""
@module slack
@description Slack bot (Socket Mode) for approval handling, rule testing, PII vault,
trust scoring, and emergency controls. Full parity with Telegram bot.
"""

import asyncio
import hashlib
import json
import logging
import re
import shlex
import time
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from fastapi import APIRouter

from app.config import get_settings
from app.database import async_session_factory
from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
from app.models.rules import Rule, RuleType, RuleAction

logger = logging.getLogger(__name__)
settings = get_settings()
router = APIRouter(prefix="/slack", tags=["slack"])

# Module-level Slack app (initialized lazily)
slack_app = None
socket_handler = None

# Store test agent IDs per Slack user (in-memory)
_test_agents: dict[str, UUID] = {}

# Pending emergency block confirmations (user_id -> timestamp)
_pending_emergency_blocks: dict[str, datetime] = {}


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

async def start_slack_bot():
    """Called from main.py lifespan. Starts Socket Mode in background."""
    global slack_app, socket_handler

    if not settings.SLACK_BOT_TOKEN or not settings.SLACK_APP_TOKEN:
        logger.warning("Slack bot tokens not configured, skipping Slack bot start")
        return

    try:
        from slack_bolt.async_app import AsyncApp
        from slack_bolt.adapter.socket_mode.async_handler import AsyncSocketModeHandler

        slack_app = AsyncApp(token=settings.SLACK_BOT_TOKEN)

        # Register all handlers
        _register_commands(slack_app)
        _register_actions(slack_app)
        _register_messages(slack_app)

        socket_handler = AsyncSocketModeHandler(slack_app, settings.SLACK_APP_TOKEN)
        await socket_handler.connect_async()
        logger.info("Slack bot started (Socket Mode)")
    except Exception as e:
        logger.exception(f"Failed to start Slack bot: {e}")


async def stop_slack_bot():
    """Called from main.py lifespan shutdown."""
    global socket_handler
    if socket_handler:
        try:
            await socket_handler.close_async()
            logger.info("Slack bot stopped")
        except Exception as e:
            logger.warning(f"Error stopping Slack bot: {e}")


# ---------------------------------------------------------------------------
# Health endpoint (REST)
# ---------------------------------------------------------------------------

@router.get("/health")
async def slack_health():
    """Check Slack bot health."""
    connected = socket_handler is not None and slack_app is not None
    return {"status": "connected" if connected else "not_configured"}


# ---------------------------------------------------------------------------
# Command registration
# ---------------------------------------------------------------------------

def _register_commands(app):
    """Register all slash command handlers."""

    @app.command("/snapper-status")
    async def handle_status(ack, command, say):
        await ack()
        await _cmd_status(command, say)

    @app.command("/snapper-rules")
    async def handle_rules(ack, command, say):
        await ack()
        await _cmd_rules(command, say)

    @app.command("/snapper-test")
    async def handle_test(ack, command, say):
        await ack()
        await _cmd_test(command, say)

    @app.command("/snapper-pending")
    async def handle_pending(ack, command, say):
        await ack()
        await _cmd_pending(command, say)

    @app.command("/snapper-vault")
    async def handle_vault(ack, command, say):
        await ack()
        await _cmd_vault(command, say)

    @app.command("/snapper-trust")
    async def handle_trust(ack, command, say):
        await ack()
        await _cmd_trust(command, say)

    @app.command("/snapper-block")
    async def handle_block(ack, command, say):
        await ack()
        await _cmd_block(command, say)

    @app.command("/snapper-unblock")
    async def handle_unblock(ack, command, say):
        await ack()
        await _cmd_unblock(command, say)

    @app.command("/snapper-pii")
    async def handle_pii(ack, command, say):
        await ack()
        await _cmd_pii(command, say)

    @app.command("/snapper-purge")
    async def handle_purge(ack, command, say):
        await ack()
        await _cmd_purge(command, say)

    @app.command("/snapper-help")
    async def handle_help(ack, command, say):
        await ack()
        await _cmd_help(command, say)


def _register_actions(app):
    """Register all interactive button action handlers."""

    @app.action("approve_action")
    async def handle_approve(ack, body, respond):
        await ack()
        await _action_approval(body, respond, "approve")

    @app.action("deny_action")
    async def handle_deny(ack, body, respond):
        await ack()
        await _action_approval(body, respond, "deny")

    @app.action("once_action")
    async def handle_once(ack, body, respond):
        await ack()
        await _action_allow_once(body, respond)

    @app.action("always_action")
    async def handle_always(ack, body, respond):
        await ack()
        await _action_allow_always(body, respond)

    @app.action("view_rule_action")
    async def handle_view_rule(ack, body, respond):
        await ack()
        await _action_view_rule(body, respond)

    @app.action("confirm_block_action")
    async def handle_confirm_block(ack, body, respond):
        await ack()
        await _action_confirm_block(body, respond)

    @app.action("cancel_block_action")
    async def handle_cancel_block(ack, body, respond):
        await ack()
        user_id = body["user"]["id"]
        _pending_emergency_blocks.pop(user_id, None)
        await respond(replace_original=True, text="Emergency block cancelled. Normal operation continues.")

    @app.action("vault_delall_action")
    async def handle_vault_delall(ack, body, respond):
        await ack()
        await _action_vault_delall(body, respond)

    @app.action("vault_delall_cancel")
    async def handle_vault_delall_cancel(ack, body, respond):
        await ack()
        await respond(replace_original=True, text="Vault delete cancelled. No entries were deleted.")

    @app.action("vph_auto_action")
    async def handle_vph_auto(ack, body, respond):
        await ack()
        await _action_vph_auto(body, respond)

    @app.action("vph_custom_action")
    async def handle_vph_custom(ack, body, respond):
        await ack()
        await _action_vph_custom(body, respond)

    @app.action("vph_skip_action")
    async def handle_vph_skip(ack, body, respond):
        await ack()
        await respond(replace_original=True, text="No placeholder set.")


def _register_messages(app):
    """Register DM message handlers for multi-step flows (vault add, placeholder)."""

    @app.event("message")
    async def handle_dm(event, say):
        # Only handle DMs (channel_type == "im")
        if event.get("channel_type") != "im":
            return
        # Ignore bot messages
        if event.get("bot_id") or event.get("subtype"):
            return

        text = event.get("text", "").strip()
        user_id = event.get("user", "")
        channel = event.get("channel", "")

        if not text or not user_id:
            return

        from app.redis_client import redis_client

        # Check for pending custom placeholder input
        placeholder_entry_id = await redis_client.get(f"slack_vault_placeholder_pending:{user_id}")
        if placeholder_entry_id:
            await redis_client.delete(f"slack_vault_placeholder_pending:{user_id}")
            await _handle_custom_placeholder(user_id, channel, text, placeholder_entry_id, say)
            return

        # Check for pending vault value input
        pending_json = await redis_client.get(f"slack_vault_pending:{user_id}")
        if pending_json:
            await _handle_vault_value_reply(user_id, channel, text, pending_json, say)
            return


# ---------------------------------------------------------------------------
# Slack message helpers
# ---------------------------------------------------------------------------

def _section(text: str) -> dict:
    """Build a Slack Block Kit section block."""
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def _header(text: str) -> dict:
    """Build a Slack Block Kit header block."""
    return {"type": "header", "text": {"type": "plain_text", "text": text, "emoji": True}}


def _divider() -> dict:
    return {"type": "divider"}


def _context(text: str) -> dict:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text}]}


def _actions(elements: list) -> dict:
    return {"type": "actions", "elements": elements}


def _button(text: str, action_id: str, value: str, style: Optional[str] = None) -> dict:
    btn = {
        "type": "button",
        "text": {"type": "plain_text", "text": text, "emoji": True},
        "action_id": action_id,
        "value": value,
    }
    if style:
        btn["style"] = style
    return btn


async def _delete_slack_message(channel: str, ts: str):
    """Try to delete a Slack message (for PII cleanup)."""
    try:
        if slack_app:
            await slack_app.client.chat_delete(channel=channel, ts=ts)
    except Exception as e:
        logger.warning(f"Could not delete Slack message: {e}")


async def _track_bot_message(channel: str, ts: str):
    """Track a bot message TS in Redis sorted set for later purge."""
    try:
        from app.redis_client import redis_client
        key = f"slack_bot_messages:{channel}"
        await redis_client.zadd(key, {ts: time.time()})
        await redis_client.expire(key, 30 * 86400)
    except Exception as e:
        logger.debug(f"Failed to track Slack bot message: {e}")


async def _say_and_track(say, **kwargs):
    """Send message via say() and track the TS for purge."""
    result = await say(**kwargs)
    if result and isinstance(result, dict):
        ts = result.get("ts")
        channel = result.get("channel")
        if ts and channel:
            await _track_bot_message(channel, ts)
    return result


# ---------------------------------------------------------------------------
# /snapper-status
# ---------------------------------------------------------------------------

async def _cmd_status(command, say):
    """Check Snapper health (DB + Redis)."""
    from sqlalchemy import text as sa_text
    from app.redis_client import redis_client as _redis

    pg_ok = False
    redis_ok = False

    try:
        async with async_session_factory() as db:
            await db.execute(sa_text("SELECT 1"))
        pg_ok = True
    except Exception as e:
        logger.warning(f"PostgreSQL health check failed: {e}")

    try:
        redis_ok = await _redis.check_health()
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")

    pg_icon = ":white_check_mark:" if pg_ok else ":x:"
    redis_icon = ":white_check_mark:" if redis_ok else ":x:"
    overall = ":white_check_mark:" if (pg_ok and redis_ok) else ":warning:"

    await _say_and_track(
        say,
        blocks=[
            _header(f"{overall} Snapper Status"),
            _section(
                f"{pg_icon} *PostgreSQL:* {'connected' if pg_ok else 'UNREACHABLE'}\n"
                f"{redis_icon} *Redis:* {'connected' if redis_ok else 'UNREACHABLE'}"
            ),
            _context("I'll notify you when actions need approval."),
        ],
        text="Snapper Status",
    )


# ---------------------------------------------------------------------------
# /snapper-help
# ---------------------------------------------------------------------------

async def _cmd_help(command, say):
    user_id = command.get("user_id", "")
    await _say_and_track(
        say,
        blocks=[
            _header(":turtle: Snapper Bot Commands"),
            _section(
                "*Approvals:*\n"
                "`/snapper-pending` — List pending requests\n\n"
                "*Rules:*\n"
                "`/snapper-rules` — View active security rules\n"
                "`/snapper-test run <cmd>` — Test if command allowed\n\n"
                "*PII Vault:*\n"
                "`/snapper-vault list` — View your entries\n"
                "`/snapper-vault add <label> <type>` — Add entry\n"
                "  Types: `cc`, `name`, `addr`, `phone`, `email`, `ssn`, `passport`, `bank`, `custom`\n"
                "`/snapper-vault delete <token>` — Delete one entry\n"
                "`/snapper-vault delete *` — Delete all (with confirm)\n"
                "`/snapper-vault domains <token> add/remove <domain>`\n\n"
                "*PII Protection:*\n"
                "`/snapper-pii` — Show current PII gate mode\n"
                "`/snapper-pii protected` — Require approval for PII\n"
                "`/snapper-pii auto` — Auto-resolve vault tokens\n\n"
                "*Trust:*\n"
                "`/snapper-trust` — View agent trust scores\n"
                "`/snapper-trust reset [name]` — Reset trust to 1.0\n"
                "`/snapper-trust enable [name]` — Enable enforcement\n"
                "`/snapper-trust disable [name]` — Disable enforcement\n\n"
                "*Emergency:*\n"
                "`/snapper-block` — Block ALL agent actions\n"
                "`/snapper-unblock` — Resume normal operation\n\n"
                "`/snapper-status` — Check Snapper connection\n"
                "`/snapper-purge` — Clean up bot messages"
            ),
            _context(f"Your Slack User ID: `{user_id}` — enter this when connecting agents in the dashboard."),
        ],
        text="Snapper Bot Commands",
    )


# ---------------------------------------------------------------------------
# /snapper-rules
# ---------------------------------------------------------------------------

async def _cmd_rules(command, say):
    from sqlalchemy import func as sa_func, select

    user_id = command.get("user_id", "")
    agent_id = await _get_or_create_test_agent(user_id)

    async with async_session_factory() as db:
        count_stmt = select(sa_func.count()).select_from(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        )
        total_count = (await db.execute(count_stmt)).scalar() or 0

        from sqlalchemy import select as sa_select
        stmt = sa_select(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            (Rule.agent_id == agent_id) | (Rule.agent_id == None),
        ).order_by(Rule.priority.desc()).limit(15)

        result = await db.execute(stmt)
        rules = list(result.scalars().all())

    if not rules:
        await _say_and_track(
            say,
            blocks=[
                _header(":clipboard: Active Rules"),
                _section("No rules configured for your agent.\n_Use the Snapper dashboard to create rules._"),
            ],
            text="No active rules",
        )
        return

    lines = []
    for rule in rules:
        emoji = ":red_circle:" if rule.action == RuleAction.DENY else ":large_green_circle:" if rule.action == RuleAction.ALLOW else ":large_yellow_circle:"
        scope = ":globe_with_meridians:" if rule.agent_id is None else ":bust_in_silhouette:"
        rt = rule.rule_type.value if hasattr(rule.rule_type, 'value') else rule.rule_type
        lines.append(f"{emoji} {scope} *{rule.name}*\n   _{rt}_ | Priority: {rule.priority}")

    footer = f"_Showing {len(rules)} of {total_count} rule(s)_" if total_count > len(rules) else f"_Total: {total_count} rule(s)_"
    lines.append(f"\n{footer}\n_View full details in Snapper dashboard_")

    await _say_and_track(
        say,
        blocks=[
            _header(":clipboard: Active Rules"),
            _section("\n".join(lines)),
        ],
        text=f"{total_count} active rules",
    )


# ---------------------------------------------------------------------------
# /snapper-test
# ---------------------------------------------------------------------------

async def _cmd_test(command, say):
    text = (command.get("text") or "").strip()
    user_id = command.get("user_id", "")

    parts = text.split(maxsplit=1)
    subcommand = parts[0].lower() if parts else "help"
    arg = parts[1] if len(parts) > 1 else ""

    if subcommand == "help" or not text:
        await _say_and_track(
            say,
            blocks=[
                _header(":test_tube: Test Rule Enforcement"),
                _section(
                    "Simulate agent actions to test Snapper rules:\n\n"
                    "*Commands:*\n"
                    "`/snapper-test run <cmd>` — Test shell command\n"
                    "`/snapper-test install <skill>` — Test skill install\n"
                    "`/snapper-test access <file>` — Test file access\n"
                    "`/snapper-test network <host>` — Test network egress\n\n"
                    "*Examples:*\n"
                    "`/snapper-test run ls -la`\n"
                    "`/snapper-test run rm -rf /`\n"
                    "`/snapper-test install malware-deployer`\n"
                    "`/snapper-test access /etc/passwd`\n"
                    "`/snapper-test network evil.com`"
                ),
            ],
            text="Test Rule Enforcement help",
        )
        return

    if not arg:
        await _say_and_track(say, text=f"Missing argument. Usage: `/snapper-test {subcommand} <value>`")
        return

    agent_id = await _get_or_create_test_agent(user_id)

    from app.services.rule_engine import EvaluationContext, EvaluationDecision, RuleEngine
    from app.redis_client import redis_client

    context = EvaluationContext(
        agent_id=agent_id,
        request_type="command",
        origin="https://slack.com",
        metadata={"source": "slack_test", "user_id": user_id},
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
        await _say_and_track(say, text=f"Unknown test type: `{subcommand}`\n\nTry `/snapper-test help`")
        return

    async with async_session_factory() as db:
        engine = RuleEngine(db, redis_client)
        result = await engine.evaluate(context)

    if result.decision == EvaluationDecision.ALLOW:
        emoji = ":white_check_mark:"
        status = "ALLOWED"
    elif result.decision == EvaluationDecision.DENY:
        emoji = ":x:"
        status = "BLOCKED"
    elif result.decision == EvaluationDecision.REQUIRE_APPROVAL:
        emoji = ":hourglass_flowing_sand:"
        status = "REQUIRES APPROVAL"
    else:
        emoji = ":question:"
        status = result.decision.value.upper()

    blocks = [
        _section(f"{emoji} *{status}*\n*Test:* `{subcommand} {arg}`"),
    ]

    detail_lines = []
    if result.reason:
        detail_lines.append(f"*Reason:* {result.reason}")
    if result.blocking_rule:
        detail_lines.append(f"*Rule ID:* `{str(result.blocking_rule)[:8]}...`")
    if result.evaluation_time_ms:
        detail_lines.append(f"*Eval time:* {result.evaluation_time_ms:.1f}ms")
    if detail_lines:
        blocks.append(_section("\n".join(detail_lines)))

    # Add buttons for blocked results
    if result.decision == EvaluationDecision.DENY:
        context_data = json.dumps({
            "type": subcommand,
            "value": arg,
            "agent_id": str(agent_id),
        })
        context_key = hashlib.sha256(context_data.encode()).hexdigest()[:12]
        await redis_client.set(f"slack_ctx:{context_key}", context_data, expire=3600)

        elements = [
            _button(":white_check_mark: Allow Once", "once_action", context_key, "primary"),
            _button(":memo: Allow Always", "always_action", context_key),
        ]
        if result.blocking_rule:
            rule_id_short = str(result.blocking_rule)[:12]
            elements.append(_button(":clipboard: View Rule", "view_rule_action", rule_id_short))

        blocks.append(_actions(elements))

    await _say_and_track(say, blocks=blocks, text=f"Test result: {status}")


# ---------------------------------------------------------------------------
# /snapper-pending
# ---------------------------------------------------------------------------

async def _cmd_pending(command, say):
    from app.redis_client import redis_client
    from app.routers.approvals import APPROVAL_PREFIX, ApprovalRequest

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
        await _say_and_track(
            say,
            blocks=[
                _header(":clipboard: Pending Approvals"),
                _section("No pending approvals at this time."),
            ],
            text="No pending approvals",
        )
        return

    lines = []
    for p in pending_list[:10]:
        action_desc = p.command or p.file_path or p.tool_name or p.request_type
        lines.append(f"• `{p.id[:8]}` — {p.agent_name}: {(action_desc or '')[:30]}")

    blocks = [
        _header(":clipboard: Pending Approvals"),
        _section("\n".join(lines)),
        _context(f"Total: {len(pending_list)}"),
    ]
    await _say_and_track(say, blocks=blocks, text=f"{len(pending_list)} pending approvals")


# ---------------------------------------------------------------------------
# /snapper-vault
# ---------------------------------------------------------------------------

async def _cmd_vault(command, say):
    from app.models.pii_vault import PIICategory
    from app.services import pii_vault as vault_service

    user_id = command.get("user_id", "")
    text = (command.get("text") or "").strip()
    parts = text.split(maxsplit=2)
    subcommand = parts[0].lower() if parts else "list"

    if subcommand in ("list", "") or not text:
        # List entries
        async with async_session_factory() as db:
            entries = await vault_service.list_entries(db=db, owner_chat_id=user_id)

        if entries:
            lines = []
            for e in entries[:15]:
                cat = e.category.value if hasattr(e.category, "value") else e.category
                entry_line = f"`{cat}`: *{e.label}*\n"
                entry_line += f"    Use: `vault:{e.label}`\n"
                entry_line += f"    Token: `{e.token}`\n"
                entry_line += f"    Masked: `{e.masked_value}`"
                if e.placeholder_value:
                    entry_line += f"\n    Placeholder: `{e.placeholder_value}`"
                if e.allowed_domains:
                    entry_line += f"\n    Domains: {', '.join(e.allowed_domains)}"
                if e.use_count > 0:
                    entry_line += f"\n    Used: {e.use_count} time(s)"
                lines.append(entry_line)

            blocks = [
                _header(":lock: Your PII Vault"),
                _section("\n\n".join(lines)),
                _context(f"Total: {len(entries)} entry(ies)"),
            ]
        else:
            blocks = [
                _header(":lock: Your PII Vault"),
                _section("_No entries yet._"),
            ]

        blocks.append(_section(
            "*Commands:*\n"
            "`/snapper-vault add <label> <category>` — Add entry\n"
            "`/snapper-vault list` — List entries\n"
            "`/snapper-vault delete <token>` — Remove entry\n"
            "`/snapper-vault domains <token> add <domain>`\n\n"
            "Categories: cc, name, address, phone, email, ssn, passport, bank_account, custom"
        ))

        await _say_and_track(say, blocks=blocks, text="PII Vault")
        return

    elif subcommand == "help":
        await _say_and_track(
            say,
            blocks=[
                _header(":lock: PII Vault Help"),
                _section(
                    "Store sensitive data encrypted in Snapper.\n"
                    "Tell your agent to use `vault:Label-Name` and Snapper handles the rest.\n\n"
                    "*Add entry:*\n"
                    '`/snapper-vault add "My Visa" credit_card`\n'
                    "Then reply in DM with the value.\n\n"
                    "*Use with agent:*\n"
                    'Tell your agent: "Fill CC with `vault:My-Visa`"\n\n'
                    "*List/Delete:*\n"
                    "`/snapper-vault list` | `/snapper-vault delete <token>`\n\n"
                    "*Domains:*\n"
                    "`/snapper-vault domains <token> add *.expedia.com`"
                ),
            ],
            text="PII Vault Help",
        )
        return

    elif subcommand == "add":
        remaining = text[len("add"):].strip()
        if not remaining:
            await _say_and_track(
                say,
                text='Usage: `/snapper-vault add <label> <category>`\nExample: `/snapper-vault add "My Visa" credit_card`',
            )
            return

        try:
            tokens = shlex.split(remaining)
        except ValueError:
            tokens = remaining.split()

        if len(tokens) < 2:
            await _say_and_track(
                say,
                text='Usage: `/snapper-vault add <label> <category>`\nExample: `/snapper-vault add "My Visa" credit_card`',
            )
            return

        category_str = tokens[-1].lower()
        label = " ".join(tokens[:-1])

        category_aliases = {
            "cc": "credit_card", "card": "credit_card", "creditcard": "credit_card",
            "credit": "credit_card", "addr": "address", "tel": "phone",
            "telephone": "phone", "mobile": "phone", "mail": "email",
            "social": "ssn", "bank": "bank_account", "account": "bank_account",
        }
        category_str = category_aliases.get(category_str, category_str)

        valid_categories = [c.value for c in PIICategory]
        if category_str not in valid_categories:
            await _say_and_track(
                say,
                text=f"Unknown category: `{category_str}`\nValid: credit_card (cc), name, address, phone, email, ssn, passport, bank_account, custom",
            )
            return

        from app.redis_client import redis_client

        # Multi-step categories
        multi_step_prompts = {
            "credit_card": ("number", "Step 1/3: Send me the *card number* (e.g., `4111111111111234`)"),
            "address": ("street", "Step 1/4: Send me the *street address* (e.g., `123 Main St, Apt 4B`)"),
            "name": ("first", "Step 1/2: Send me the *first name*"),
            "bank_account": ("routing", "Step 1/2: Send me the *routing number* (9 digits)"),
        }

        if category_str in multi_step_prompts:
            step, prompt = multi_step_prompts[category_str]
            pending_data = json.dumps({
                "label": label,
                "category": category_str,
                "owner_chat_id": user_id,
                "owner_name": command.get("user_name", "Unknown"),
                "step": step,
            })
            await redis_client.set(f"slack_vault_pending:{user_id}", pending_data, expire=300)

            # Open DM and send prompt
            try:
                dm = await slack_app.client.conversations_open(users=user_id)
                dm_channel = dm["channel"]["id"]
                await slack_app.client.chat_postMessage(
                    channel=dm_channel,
                    text=f":lock: *Adding {category_str}:* {label}\n\n{prompt}\n\n:warning: Your message will be deleted after processing.\n_Type `cancel` to abort._",
                )
            except Exception as e:
                logger.error(f"Failed to open DM with {user_id}: {e}")
                await _say_and_track(say, text="Failed to open DM. Please message me directly to continue.")
                return
        else:
            pending_data = json.dumps({
                "label": label,
                "category": category_str,
                "owner_chat_id": user_id,
                "owner_name": command.get("user_name", "Unknown"),
            })
            await redis_client.set(f"slack_vault_pending:{user_id}", pending_data, expire=300)

            category_hints = {
                "phone": "phone number (e.g., `+15551234567`)",
                "email": "email address",
                "ssn": "SSN (e.g., `123-45-6789`)",
                "passport": "passport number",
                "custom": "value",
            }
            hint = category_hints.get(category_str, "value")

            try:
                dm = await slack_app.client.conversations_open(users=user_id)
                dm_channel = dm["channel"]["id"]
                await slack_app.client.chat_postMessage(
                    channel=dm_channel,
                    text=f":lock: *Adding vault entry:* {label} (`{category_str}`)\n\nPlease reply with your {hint}.\n\n:warning: The value will be encrypted immediately and the message deleted.\n_Type `cancel` to abort._",
                )
            except Exception as e:
                logger.error(f"Failed to open DM with {user_id}: {e}")
                await _say_and_track(say, text="Failed to open DM. Please message me directly to continue.")
                return

        await _say_and_track(
            say,
            text=f":lock: Check your DMs — I'll ask for the sensitive value there.",
        )
        return

    elif subcommand == "delete":
        target = parts[1] if len(parts) > 1 else ""
        if not target:
            await _say_and_track(say, text="Usage: `/snapper-vault delete <token>` or `/snapper-vault delete *`")
            return

        if target == "*":
            async with async_session_factory() as db:
                entries = await vault_service.list_entries(db=db, owner_chat_id=user_id)
                if not entries:
                    await _say_and_track(say, text="You have no vault entries to delete.")
                    return

                await _say_and_track(
                    say,
                    blocks=[
                        _section(f":warning: This will delete *all {len(entries)}* vault entries. Are you sure?"),
                        _actions([
                            _button(":wastebasket: DELETE ALL", "vault_delall_action", user_id, "danger"),
                            _button(":x: Cancel", "vault_delall_cancel", "cancel"),
                        ]),
                    ],
                    text="Confirm delete all vault entries",
                )
            return

        # Single token delete
        async with async_session_factory() as db:
            entry = await vault_service.get_entry_by_token(db=db, token=target)
            if not entry:
                await _say_and_track(say, text=f"Entry not found for token: `{target}`")
                return

            success = await vault_service.delete_entry(
                db=db, entry_id=str(entry.id), requester_chat_id=user_id,
            )
            if success:
                audit_log = AuditLog(
                    action=AuditAction.PII_VAULT_DELETED,
                    severity=AuditSeverity.WARNING,
                    message=f"Vault entry '{entry.label}' deleted via Slack by {user_id}",
                    details={"entry_id": str(entry.id), "deleted_by": user_id},
                )
                db.add(audit_log)
                await db.commit()
                await _say_and_track(say, text=f":wastebasket: Vault entry *{entry.label}* deleted.")
            else:
                await _say_and_track(say, text="Failed to delete entry. You may not own it.")
        return

    elif subcommand == "domains":
        remaining = text[len("domains"):].strip()
        domain_parts = remaining.split(maxsplit=2)

        if len(domain_parts) < 3:
            await _say_and_track(say, text="Usage: `/snapper-vault domains <token> add|remove <domain>`")
            return

        token = domain_parts[0]
        domain_action = domain_parts[1].lower()
        domain = domain_parts[2].strip()

        async with async_session_factory() as db:
            entry = await vault_service.get_entry_by_token(db=db, token=token)
            if not entry:
                await _say_and_track(say, text=f"Entry not found for token: `{token}`")
                return

            if entry.owner_chat_id != user_id:
                await _say_and_track(say, text="You don't own this entry.")
                return

            domains = list(entry.allowed_domains or [])
            if domain_action == "add":
                if domain not in domains:
                    domains.append(domain)
                    entry.allowed_domains = domains
                    await db.commit()
                    await _say_and_track(say, text=f"Added domain `{domain}` to *{entry.label}*")
                else:
                    await _say_and_track(say, text=f"Domain `{domain}` already in list.")
            elif domain_action == "remove":
                if domain in domains:
                    domains.remove(domain)
                    entry.allowed_domains = domains
                    await db.commit()
                    await _say_and_track(say, text=f"Removed domain `{domain}` from *{entry.label}*")
                else:
                    await _say_and_track(say, text=f"Domain `{domain}` not in list.")
            else:
                await _say_and_track(say, text="Usage: `/snapper-vault domains <token> add|remove <domain>`")
        return

    else:
        await _say_and_track(say, text=f"Unknown vault command: `{subcommand}`\nTry `/snapper-vault help`")


# ---------------------------------------------------------------------------
# /snapper-trust
# ---------------------------------------------------------------------------

async def _cmd_trust(command, say):
    from app.models.agents import Agent
    from app.redis_client import redis_client
    from sqlalchemy import select

    user_id = command.get("user_id", "")
    text = (command.get("text") or "").strip()
    parts = text.split()
    subcommand = parts[0].lower() if parts else ""
    target_name = " ".join(parts[1:]) if len(parts) > 1 else None

    async with async_session_factory() as db:
        stmt = select(Agent).where(
            Agent.owner_chat_id == user_id,
            Agent.is_deleted == False,
        )
        result = await db.execute(stmt)
        agents = list(result.scalars().all())

        if not agents:
            await _say_and_track(
                say,
                text="No agents found for your account.\nMake sure your agents have `owner_chat_id` set to your Slack user ID.",
            )
            return

        if target_name:
            matched = [a for a in agents if a.name.lower() == target_name.lower()
                       or a.external_id.lower() == target_name.lower()]
            if not matched:
                names = ", ".join(f"`{a.name}`" for a in agents)
                await _say_and_track(say, text=f"Agent `{target_name}` not found. Your agents: {names}")
                return
            agents = matched

        if subcommand == "reset":
            names = []
            for agent in agents:
                trust_key = f"trust:rate:{agent.id}"
                await redis_client.delete(trust_key)
                agent.trust_score = 1.0
                names.append(agent.name)
            await db.commit()
            label = ", ".join(f"`{n}`" for n in names)
            await _say_and_track(say, text=f":arrows_counterclockwise: Trust score reset to *1.0* for: {label}")

        elif subcommand == "enable":
            names = []
            for agent in agents:
                agent.auto_adjust_trust = True
                names.append(agent.name)
            await db.commit()
            label = ", ".join(f"`{n}`" for n in names)
            await _say_and_track(
                say,
                text=f":white_check_mark: Trust enforcement *enabled* for: {label}\nTrust score will now actively scale rate limits.",
            )

        elif subcommand == "disable":
            names = []
            for agent in agents:
                agent.auto_adjust_trust = False
                names.append(agent.name)
            await db.commit()
            label = ", ".join(f"`{n}`" for n in names)
            await _say_and_track(
                say,
                text=f":information_source: Trust enforcement *disabled* for: {label}\nTrust score is still tracked but does not affect rate limits.",
            )

        else:
            # Show trust scores
            lines = []
            for agent in agents:
                trust_key = f"trust:rate:{agent.id}"
                score_raw = await redis_client.get(trust_key)
                score = float(score_raw) if score_raw else 1.0
                icon = ":large_green_circle:" if agent.auto_adjust_trust else ":white_circle:"
                mode = "Enforced" if agent.auto_adjust_trust else "Info-only"
                lines.append(f"{icon} `{agent.name}` — *{score:.3f}* ({mode})")

            lines.append(
                "\n*Commands:*\n"
                "`/snapper-trust reset [name]` — reset to 1.0\n"
                "`/snapper-trust enable [name]` — enforce\n"
                "`/snapper-trust disable [name]` — info-only"
            )

            await _say_and_track(
                say,
                blocks=[
                    _header(":bar_chart: Trust Scores"),
                    _section("\n".join(lines)),
                ],
                text="Trust Scores",
            )


# ---------------------------------------------------------------------------
# /snapper-block
# ---------------------------------------------------------------------------

async def _cmd_block(command, say):
    user_id = command.get("user_id", "")
    _pending_emergency_blocks[user_id] = datetime.utcnow()

    await _say_and_track(
        say,
        blocks=[
            _section(
                ":warning: *EMERGENCY BLOCK ALL*\n\n"
                "This will create a high-priority DENY rule that blocks ALL agent actions.\n\n"
                "Are you sure you want to proceed?\n_Use `/snapper-unblock` to resume normal operation._"
            ),
            _actions([
                _button(":rotating_light: CONFIRM BLOCK ALL", "confirm_block_action", user_id, "danger"),
                _button(":x: Cancel", "cancel_block_action", user_id),
            ]),
        ],
        text="Emergency Block confirmation",
    )


# ---------------------------------------------------------------------------
# /snapper-unblock
# ---------------------------------------------------------------------------

async def _cmd_unblock(command, say):
    user_id = command.get("user_id", "")
    username = command.get("user_name", "Unknown")
    from sqlalchemy import select

    async with async_session_factory() as db:
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.is_active == True,
            Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
        )
        result = await db.execute(stmt)
        emergency_rules = result.scalars().all()

        if not emergency_rules:
            await _say_and_track(say, text=":information_source: No emergency block is currently active.")
            return

        deactivated_count = 0
        for rule in emergency_rules:
            rule.is_active = False
            deactivated_count += 1

        audit_log = AuditLog(
            action=AuditAction.RULE_UPDATED,
            severity=AuditSeverity.WARNING,
            agent_id=None,
            message=f"Emergency block deactivated via Slack by {username} ({deactivated_count} rules)",
            old_value={"is_active": True},
            new_value={"is_active": False, "deactivated_by": username, "rules_deactivated": deactivated_count},
        )
        db.add(audit_log)
        await db.commit()

    await _say_and_track(
        say,
        text=f":white_check_mark: *Emergency block deactivated* by @{username}\n\n{deactivated_count} block rule(s) disabled. Normal operation resumed.",
    )


# ---------------------------------------------------------------------------
# /snapper-pii
# ---------------------------------------------------------------------------

async def _cmd_pii(command, say):
    from sqlalchemy import select

    user_id = command.get("user_id", "")
    username = command.get("user_name", "Unknown")
    text = (command.get("text") or "").strip().lower()

    async with async_session_factory() as db:
        stmt = select(Rule).where(
            Rule.rule_type == RuleType.PII_GATE,
            Rule.is_active == True,
        ).limit(1)
        result = await db.execute(stmt)
        pii_rule = result.scalars().first()

        if not pii_rule:
            await _say_and_track(
                say,
                text="No active PII gate rule found.\nCreate one via the dashboard using the `pii-gate-protection` template.",
            )
            return

        current_mode = pii_rule.parameters.get("pii_mode", "protected")

        if not text:
            mode_emoji = ":shield:" if current_mode == "protected" else ":zap:"
            await _say_and_track(
                say,
                text=(
                    f"*PII Gate Mode:* {mode_emoji} `{current_mode}`\n\n"
                    ":shield: *protected* — Vault tokens require human approval\n"
                    ":zap: *auto* — Vault tokens resolved automatically\n\n"
                    "Use `/snapper-pii protected` or `/snapper-pii auto` to change."
                ),
            )
            return

        if text not in ("protected", "auto"):
            await _say_and_track(say, text="Usage: `/snapper-pii protected` or `/snapper-pii auto`")
            return

        if text == current_mode:
            mode_emoji = ":shield:" if current_mode == "protected" else ":zap:"
            await _say_and_track(say, text=f"PII gate is already in {mode_emoji} `{current_mode}` mode.")
            return

        new_params = dict(pii_rule.parameters)
        new_params["pii_mode"] = text
        pii_rule.parameters = new_params

        audit_log = AuditLog(
            action=AuditAction.RULE_UPDATED,
            severity=AuditSeverity.WARNING,
            message=f"PII gate mode changed to '{text}' via Slack by {username}",
            old_value={"pii_mode": current_mode},
            new_value={"pii_mode": text},
        )
        db.add(audit_log)
        await db.commit()

        mode_emoji = ":shield:" if text == "protected" else ":zap:"
        desc = "Vault tokens will require human approval before being resolved." if text == "protected" else "Vault tokens will be resolved automatically without approval."
        await _say_and_track(say, text=f"{mode_emoji} PII gate mode set to *{text}*\n\n{desc}")


# ---------------------------------------------------------------------------
# /snapper-purge
# ---------------------------------------------------------------------------

async def _cmd_purge(command, say):
    from app.redis_client import redis_client

    user_id = command.get("user_id", "")
    channel_id = command.get("channel_id", "")
    text = (command.get("text") or "").strip().lower()

    if text == "all":
        cutoff_ts = time.time()
    elif text:
        match = re.match(r'^(\d+)([dhm])$', text)
        if not match:
            await _say_and_track(
                say,
                text=(
                    "Usage: `/snapper-purge [duration|all]`\n\n"
                    "Examples:\n"
                    "`/snapper-purge` — older than 24h\n"
                    "`/snapper-purge 7d` — older than 7 days\n"
                    "`/snapper-purge all` — delete all tracked messages"
                ),
            )
            return
        amount = int(match.group(1))
        unit = match.group(2)
        multiplier = {"d": 86400, "h": 3600, "m": 60}[unit]
        cutoff_ts = time.time() - (amount * multiplier)
    else:
        cutoff_ts = time.time() - 86400

    key = f"slack_bot_messages:{channel_id}"

    if text == "all":
        message_tss = await redis_client.zrangebyscore(key, "-inf", "+inf")
    else:
        message_tss = await redis_client.zrangebyscore(key, "-inf", str(cutoff_ts))

    if not message_tss:
        await _say_and_track(say, text="No tracked bot messages to delete.")
        return

    deleted = 0
    failed = 0

    for ts in message_tss:
        try:
            if slack_app:
                await slack_app.client.chat_delete(channel=channel_id, ts=ts)
                deleted += 1
        except Exception:
            failed += 1
        await redis_client.zrem(key, ts)
        if deleted % 20 == 0 and deleted > 0:
            await asyncio.sleep(1)

    lines = [":wastebasket: *Purge Complete*"]
    if deleted:
        lines.append(f"Deleted: {deleted} message(s)")
    if failed:
        lines.append(f"Failed: {failed}")
    if not deleted and not failed:
        lines.append("No messages needed deletion.")

    await _say_and_track(say, text="\n".join(lines))


# ---------------------------------------------------------------------------
# Interactive action handlers
# ---------------------------------------------------------------------------

async def _action_approval(body, respond, action: str):
    """Handle Approve/Deny button clicks."""
    approval_id = body["actions"][0]["value"]
    username = body["user"]["username"]

    result = await _process_approval(request_id=approval_id, action=action, approved_by=username)

    if not result.get("success"):
        await respond(replace_original=True, text=f"Request `{approval_id}` has expired or was not found.")
        return

    emoji = ":white_check_mark:" if action == "approve" else ":x:"
    action_past = "APPROVED" if action == "approve" else "DENIED"
    await respond(
        replace_original=True,
        text=f"{emoji} Request *{action_past}* by @{username}\nRequest ID: `{approval_id}`",
    )


async def _action_allow_once(body, respond):
    """Handle Allow Once button."""
    from app.redis_client import redis_client

    context_key = body["actions"][0]["value"]
    username = body["user"]["username"]

    context_json = await redis_client.get(f"slack_ctx:{context_key}")
    if not context_json:
        await respond(replace_original=True, text=":x: Context expired")
        return

    context = json.loads(context_json)
    cmd = context.get("value", "")
    agent_id = context.get("agent_id", "")
    cmd_hash = hashlib.sha256(cmd.encode()).hexdigest()[:16]
    approval_key = f"once_allow:{agent_id}:{cmd_hash}"
    await redis_client.set(approval_key, "1", expire=300)

    await respond(
        replace_original=True,
        text=f":white_check_mark: ALLOWED ONCE by @{username}\nCommand: {cmd[:50]}...\nValid for 5 minutes.",
    )


async def _action_allow_always(body, respond):
    """Handle Allow Always button — creates persistent allow rule."""
    from app.redis_client import redis_client

    context_key = body["actions"][0]["value"]
    username = body["user"]["username"]

    context_json = await redis_client.get(f"slack_ctx:{context_key}")
    if not context_json:
        await respond(replace_original=True, text=":x: Context expired")
        return

    result = await _create_allow_rule_from_context(context_json, username)
    rule_id_short = result.get('rule_id', 'N/A')[:8]
    await respond(
        replace_original=True,
        text=f":white_check_mark: ALLOW RULE CREATED by @{username}\nRule ID: {rule_id_short}",
    )


async def _action_view_rule(body, respond):
    """Handle View Rule button."""
    rule_id_partial = body["actions"][0]["value"]
    rule_info = await _get_rule_info(rule_id_partial)
    await respond(replace_original=False, text=rule_info)


async def _action_confirm_block(body, respond):
    """Handle emergency block confirmation."""
    user_id = body["user"]["id"]
    username = body["user"]["username"]

    result = await _activate_emergency_block(user_id, username)
    await respond(
        replace_original=True,
        text=(
            ":rotating_light: *EMERGENCY BLOCK ACTIVATED* by @{username}\n\n"
            ":warning: ALL agent actions are now BLOCKED.\n\n"
            "Use `/snapper-unblock` to resume normal operation."
        ).format(username=username),
    )


async def _action_vault_delall(body, respond):
    """Handle Delete All vault entries."""
    from app.services import pii_vault as vault_service

    user_id = body["actions"][0]["value"]
    username = body["user"]["username"]

    async with async_session_factory() as db:
        entries = await vault_service.list_entries(db=db, owner_chat_id=user_id)
        deleted_count = 0
        for entry in entries:
            success = await vault_service.delete_entry(
                db=db, entry_id=str(entry.id), requester_chat_id=user_id,
            )
            if success:
                deleted_count += 1

        audit_log = AuditLog(
            action=AuditAction.PII_VAULT_DELETED,
            severity=AuditSeverity.WARNING,
            message=f"All vault entries ({deleted_count}) deleted via Slack by {username}",
            details={"owner_chat_id": user_id, "deleted_by": username, "count": deleted_count},
        )
        db.add(audit_log)
        await db.commit()

    await respond(replace_original=True, text=f":wastebasket: *Deleted {deleted_count} vault entries.*")


async def _action_vph_auto(body, respond):
    """Set auto-suggested placeholder on vault entry."""
    from app.models.pii_vault import PIIVaultEntry
    from sqlalchemy import select as sa_select, cast, String as SAString

    entry_id_short = body["actions"][0]["value"]

    async with async_session_factory() as db:
        stmt = sa_select(PIIVaultEntry).where(
            cast(PIIVaultEntry.id, SAString).like(f"{entry_id_short}%"),
            PIIVaultEntry.is_deleted == False,
        ).limit(1)
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if entry:
            suggestions = {
                "credit_card": "4242424242424242",
                "email": "user@example.com",
                "phone": "555-555-0100",
                "ssn": "000-00-0000",
            }
            cat = entry.category.value if hasattr(entry.category, "value") else entry.category
            placeholder = suggestions.get(cat, "test-placeholder")
            entry.placeholder_value = placeholder
            await db.commit()
            await respond(
                replace_original=True,
                text=(
                    f":lock: *Vault entry updated!*\n\n"
                    f"*Label:* {entry.label}\n"
                    f"*Token:* `{entry.token}`\n"
                    f"*Placeholder:* `{placeholder}`\n\n"
                    "Agents can now use this placeholder value."
                ),
            )
        else:
            await respond(replace_original=True, text="Entry not found.")


async def _action_vph_custom(body, respond):
    """Prompt user for custom placeholder value via DM."""
    from app.redis_client import redis_client

    entry_id_short = body["actions"][0]["value"]
    user_id = body["user"]["id"]

    await redis_client.set(
        f"slack_vault_placeholder_pending:{user_id}",
        entry_id_short,
        expire=300,
    )

    # Open DM to ask for placeholder
    try:
        dm = await slack_app.client.conversations_open(users=user_id)
        dm_channel = dm["channel"]["id"]
        await slack_app.client.chat_postMessage(
            channel=dm_channel,
            text=(
                "Enter a *placeholder value* for this vault entry.\n\n"
                "This is a safe dummy value the agent can use (e.g., `4242424242424242` for a test card).\n\n"
                "_Type `cancel` to skip._"
            ),
        )
    except Exception as e:
        logger.error(f"Failed to open DM for placeholder: {e}")

    await respond(replace_original=True, text="Check your DMs — enter the placeholder value there.")


# ---------------------------------------------------------------------------
# DM conversation handlers (vault value entry, placeholder)
# ---------------------------------------------------------------------------

async def _handle_vault_value_reply(user_id: str, channel: str, text: str, pending_json: str, say):
    """Handle a DM reply containing PII for a pending vault add."""
    from app.models.pii_vault import PIICategory
    from app.services import pii_vault as vault_service
    from app.redis_client import redis_client

    if text.strip().lower() == "cancel":
        await redis_client.delete(f"slack_vault_pending:{user_id}")
        await say(text="Vault entry creation cancelled.")
        return

    pending = json.loads(pending_json)
    raw_value = text.strip()

    # Handle multi-step flows
    step = pending.get("step")
    if step:
        cat = pending["category"]

        # Credit Card: number -> exp -> cvc
        if cat == "credit_card":
            if step == "number":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) < 13 or len(digits) > 19:
                    await say(text="That doesn't look like a valid card number. Please enter 13-19 digits.\n_Type `cancel` to abort._")
                    return
                pending["card_number"] = digits
                pending["step"] = "exp"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 2/3: Reply with the *expiration date* (e.g., `12/27` or `12/2027`)\n_Type `cancel` to abort._")
                return
            elif step == "exp":
                exp_clean = raw_value.strip().replace("-", "/")
                if not re.match(r"^\d{1,2}/\d{2,4}$", exp_clean):
                    await say(text="Please enter expiration as `MM/YY` or `MM/YYYY`.\n_Type `cancel` to abort._")
                    return
                pending["card_exp"] = exp_clean
                pending["step"] = "cvc"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 3/3: Reply with the *CVC/CVV* (3 or 4 digit security code)\n_Type `cancel` to abort._")
                return
            elif step == "cvc":
                cvc_clean = raw_value.strip()
                if not re.match(r"^\d{3,4}$", cvc_clean):
                    await say(text="CVC should be 3 or 4 digits.\n_Type `cancel` to abort._")
                    return
                raw_value = json.dumps({
                    "number": pending["card_number"],
                    "exp": pending["card_exp"],
                    "cvc": cvc_clean,
                })

        # Address: street -> city -> state -> zip
        elif cat == "address":
            if step == "street":
                if len(raw_value) < 3:
                    await say(text="Please enter a valid street address.\n_Type `cancel` to abort._")
                    return
                pending["addr_street"] = raw_value
                pending["step"] = "city"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 2/4: Reply with the *city*\n_Type `cancel` to abort._")
                return
            elif step == "city":
                if len(raw_value) < 2:
                    await say(text="Please enter a valid city name.\n_Type `cancel` to abort._")
                    return
                pending["addr_city"] = raw_value
                pending["step"] = "state"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 3/4: Reply with the *state* (e.g., `CA`, `NY`)\n_Type `cancel` to abort._")
                return
            elif step == "state":
                state_clean = raw_value.strip().upper()
                if len(state_clean) < 2:
                    await say(text="Please enter a valid state abbreviation.\n_Type `cancel` to abort._")
                    return
                pending["addr_state"] = state_clean
                pending["step"] = "zip"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 4/4: Reply with the *ZIP code*\n_Type `cancel` to abort._")
                return
            elif step == "zip":
                zip_clean = raw_value.strip()
                if not re.match(r"^\d{5}(-\d{4})?$", zip_clean):
                    await say(text="Please enter a valid ZIP code (e.g., `90210` or `90210-1234`).\n_Type `cancel` to abort._")
                    return
                raw_value = json.dumps({
                    "street": pending["addr_street"],
                    "city": pending["addr_city"],
                    "state": pending["addr_state"],
                    "zip": zip_clean,
                })

        # Name: first -> last
        elif cat == "name":
            if step == "first":
                if len(raw_value) < 1:
                    await say(text="Please enter a first name.\n_Type `cancel` to abort._")
                    return
                pending["name_first"] = raw_value
                pending["step"] = "last"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 2/2: Reply with the *last name*\n_Type `cancel` to abort._")
                return
            elif step == "last":
                if len(raw_value) < 1:
                    await say(text="Please enter a last name.\n_Type `cancel` to abort._")
                    return
                raw_value = json.dumps({
                    "first": pending["name_first"],
                    "last": raw_value,
                })

        # Bank Account: routing -> account
        elif cat == "bank_account":
            if step == "routing":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) != 9:
                    await say(text="Routing number should be exactly 9 digits.\n_Type `cancel` to abort._")
                    return
                pending["bank_routing"] = digits
                pending["step"] = "account"
                await redis_client.set(f"slack_vault_pending:{user_id}", json.dumps(pending), expire=300)
                await say(text="Step 2/2: Reply with the *account number*\n_Type `cancel` to abort._")
                return
            elif step == "account":
                digits = re.sub(r"[\s\-]", "", raw_value)
                if not digits.isdigit() or len(digits) < 4:
                    await say(text="Please enter a valid account number (digits only).\n_Type `cancel` to abort._")
                    return
                raw_value = json.dumps({
                    "routing": pending["bank_routing"],
                    "account": digits,
                })

    # --- Create the vault entry ---
    from app.models.pii_vault import PIICategory
    category = PIICategory(pending["category"])
    placeholder_value = pending.get("placeholder_value")

    async with async_session_factory() as db:
        entry = await vault_service.create_entry(
            db=db,
            owner_chat_id=pending["owner_chat_id"],
            owner_name=pending["owner_name"],
            label=pending["label"],
            category=category,
            raw_value=raw_value,
            placeholder_value=placeholder_value,
        )

        audit_log = AuditLog(
            action=AuditAction.PII_VAULT_CREATED,
            severity=AuditSeverity.INFO,
            message=f"Vault entry '{pending['label']}' created via Slack by {user_id}",
            details={
                "entry_id": str(entry.id),
                "category": pending["category"],
                "owner_chat_id": pending["owner_chat_id"],
                "has_placeholder": placeholder_value is not None,
            },
        )
        db.add(audit_log)
        await db.commit()

    await redis_client.delete(f"slack_vault_pending:{user_id}")

    # Auto-suggest placeholder
    placeholder_suggestions = {
        "credit_card": "4242424242424242",
        "email": "user@example.com",
        "phone": "555-555-0100",
        "ssn": "000-00-0000",
    }
    suggested = placeholder_suggestions.get(pending["category"])

    entry_id_short = str(entry.id)[:12]

    placeholder_msg = ""
    if entry.placeholder_value:
        placeholder_msg = f"*Placeholder:* `{entry.placeholder_value}`\n"

    text_msg = (
        f":lock: *Vault entry created!*\n\n"
        f"*Label:* {entry.label}\n"
        f"*Category:* `{pending['category']}`\n"
        f"*Masked:* `{entry.masked_value}`\n"
        f"*Token:* `{entry.token}`\n"
        f"{placeholder_msg}\n"
        "Give this token to your AI agent instead of the real value.\n"
        "Snapper will intercept and require approval before it's submitted."
    )

    # Build placeholder buttons
    elements = []
    if not placeholder_value and suggested:
        elements = [
            _button(f"Use {suggested}", "vph_auto_action", entry_id_short, "primary"),
            _button("Custom...", "vph_custom_action", entry_id_short),
            _button("Skip", "vph_skip_action", entry_id_short),
        ]
    elif not placeholder_value:
        elements = [
            _button("Set placeholder", "vph_custom_action", entry_id_short),
            _button("Skip", "vph_skip_action", entry_id_short),
        ]

    blocks = [_section(text_msg)]
    if elements:
        blocks.append(_actions(elements))
        blocks.append(_context("Optional: Set a placeholder value agents can use instead of the vault token."))

    await say(blocks=blocks, text="Vault entry created")


async def _handle_custom_placeholder(user_id: str, channel: str, placeholder_text: str, entry_id_short: str, say):
    """Handle user's reply with a custom placeholder value for a vault entry."""
    from app.models.pii_vault import PIIVaultEntry
    from sqlalchemy import select as sa_select, cast, String as SAString

    if placeholder_text.lower() == "cancel":
        await say(text="Placeholder setup skipped.")
        return

    if len(placeholder_text) > 255:
        await say(text="Placeholder value too long (max 255 chars). Skipped.")
        return

    async with async_session_factory() as db:
        stmt = sa_select(PIIVaultEntry).where(
            cast(PIIVaultEntry.id, SAString).like(f"{entry_id_short}%"),
            PIIVaultEntry.is_deleted == False,
        ).limit(1)
        result = await db.execute(stmt)
        entry = result.scalar_one_or_none()

        if not entry:
            await say(text="Vault entry not found. Placeholder not set.")
            return

        entry.placeholder_value = placeholder_text
        await db.commit()

    await say(
        text=(
            f":lock: *Placeholder set!*\n\n"
            f"*Entry:* {entry.label}\n"
            f"*Placeholder:* `{placeholder_text}`\n\n"
            "Agents can now use this placeholder value. "
            "Snapper will detect it and map it to the real encrypted value."
        ),
    )


# ---------------------------------------------------------------------------
# Shared helpers (reused from Telegram logic, adapted for Slack)
# ---------------------------------------------------------------------------

async def _process_approval(request_id: str, action: str, approved_by: str) -> dict:
    """Process an approval or denial request."""
    logger.info(f"Processing {action} for request {request_id} by {approved_by}")

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
        logger.warning(f"Could not update approval {request_id}")
        return {"status": "failed", "success": False, "action": action, "request_id": request_id}

    async with async_session_factory() as db:
        audit_log = AuditLog(
            action=AuditAction.APPROVAL_GRANTED if action == "approve" else AuditAction.APPROVAL_DENIED,
            severity=AuditSeverity.INFO,
            message=f"Request {request_id} {action}d via Slack by {approved_by}",
            old_value=None,
            new_value={
                "request_id": request_id,
                "action": action,
                "approved_by": approved_by,
                "channel": "slack",
            },
        )
        db.add(audit_log)
        await db.commit()

    return {"status": "processed", "success": True, "action": action, "request_id": request_id}


async def _get_or_create_test_agent(user_id: str) -> UUID:
    """Get or create a test agent for a Slack user."""
    global _test_agents
    from app.models.agents import Agent, AgentStatus, TrustLevel
    from sqlalchemy import select

    if user_id in _test_agents:
        async with async_session_factory() as db:
            stmt = select(Agent).where(
                Agent.id == _test_agents[user_id],
                Agent.is_deleted == False,
            )
            result = await db.execute(stmt)
            agent = result.scalar_one_or_none()
            if agent:
                return agent.id

    agent_id = uuid4()
    external_id = f"slack-test-{user_id}"

    async with async_session_factory() as db:
        stmt = select(Agent).where(Agent.external_id == external_id)
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            if not existing.owner_chat_id:
                existing.owner_chat_id = user_id
                await db.commit()
            _test_agents[user_id] = existing.id
            return existing.id

        agent = Agent(
            id=agent_id,
            external_id=external_id,
            name=f"Slack Test Agent ({user_id})",
            description="Test agent for Slack rule testing",
            status=AgentStatus.ACTIVE,
            trust_level=TrustLevel.STANDARD,
            owner_chat_id=user_id,
        )
        db.add(agent)
        await db.commit()

    _test_agents[user_id] = agent_id
    return agent_id


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

    agent_id = None
    try:
        agent_id = UUID(agent_id_str)
    except (ValueError, TypeError):
        from app.models.agents import Agent
        from sqlalchemy import select
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

    if test_type == "run":
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
            description=f"Created via Slack by {username}",
            rule_type=rule_type,
            action=RuleAction.ALLOW,
            priority=500,
            parameters=parameters,
            agent_id=agent_id,
            is_active=True,
        )
        db.add(rule)

        audit_log = AuditLog(
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.INFO,
            agent_id=agent_id,
            message=f"Allow rule created via Slack by {username}",
            new_value={
                "rule_id": str(rule.id),
                "rule_name": rule_name,
                "created_by": username,
                "source": "slack",
            },
        )
        db.add(audit_log)
        await db.commit()

    return {
        "message": f"Rule created: *{rule_name}*\nType: {rule_type.value}\nPriority: 500",
        "rule_id": str(rule.id),
    }


async def _activate_emergency_block(user_id: str, username: str) -> dict:
    """Activate emergency block by creating high-priority deny-all rules."""
    _pending_emergency_blocks.pop(user_id, None)

    block_rules = [
        {"rule_type": RuleType.COMMAND_DENYLIST, "parameters": {"patterns": [".*"]}},
        {"rule_type": RuleType.SKILL_DENYLIST, "parameters": {"skills": [".*"], "blocked_patterns": [".*"]}},
        {"rule_type": RuleType.FILE_ACCESS, "parameters": {"denied_paths": [".*"]}},
        {"rule_type": RuleType.NETWORK_EGRESS, "parameters": {"denied_hosts": [".*"]}},
    ]

    rule_ids = []
    from sqlalchemy import select

    async with async_session_factory() as db:
        stmt = select(Rule).where(
            Rule.is_deleted == False,
            Rule.name == "\U0001f6a8 EMERGENCY BLOCK ALL",
            Rule.agent_id == None,
        )
        result = await db.execute(stmt)
        existing_rules = list(result.scalars().all())

        if existing_rules:
            for rule in existing_rules:
                rule.is_active = True
                rule_ids.append(rule.id)
        else:
            for block_def in block_rules:
                rule = Rule(
                    id=uuid4(),
                    name="\U0001f6a8 EMERGENCY BLOCK ALL",
                    description=f"Emergency block activated via Slack by {username}",
                    rule_type=block_def["rule_type"],
                    action=RuleAction.DENY,
                    priority=10000,
                    parameters=block_def["parameters"],
                    agent_id=None,
                    is_active=True,
                )
                db.add(rule)
                rule_ids.append(rule.id)

        audit_log = AuditLog(
            action=AuditAction.RULE_CREATED,
            severity=AuditSeverity.CRITICAL,
            agent_id=None,
            message=f"Emergency block activated via Slack by {username}",
            new_value={
                "rule_ids": [str(rid) for rid in rule_ids],
                "activated_by": username,
                "source": "slack",
                "scope": "global",
            },
        )
        db.add(audit_log)
        await db.commit()

    return {"rule_id": str(rule_ids[0]) if rule_ids else "unknown", "status": "activated"}


async def _get_rule_info(rule_id_partial: str) -> str:
    """Get detailed information about a rule by partial ID."""
    from sqlalchemy import cast, String, select

    async with async_session_factory() as db:
        stmt = select(Rule).where(
            cast(Rule.id, String).like(f"{rule_id_partial}%")
        ).limit(1)
        result = await db.execute(stmt)
        rule = result.scalar_one_or_none()

    if not rule:
        return f"Rule `{rule_id_partial}...` not found"

    rule_id = str(rule.id)
    emoji = ":red_circle:" if rule.action == RuleAction.DENY else ":large_green_circle:" if rule.action == RuleAction.ALLOW else ":large_yellow_circle:"
    scope = "Global" if rule.agent_id is None else "Agent-specific"

    lines = [
        f":clipboard: *Rule Details*\n",
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
        lines.append(f"\n*Parameters:*\n```{params_str}```")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API: send_slack_approval (called from alerts.py)
# ---------------------------------------------------------------------------

async def send_slack_approval(
    target_user_id: str,
    title: str,
    message: str,
    severity: str,
    metadata: Optional[dict] = None,
):
    """Send an approval alert to a Slack user or channel with interactive buttons.

    Called from alerts.py when the target is a Slack user (U... prefix in owner_chat_id).
    """
    # If slack_app is not available (e.g., in Celery worker), create a
    # standalone async web client using the bot token.
    if not slack_app:
        if not settings.SLACK_BOT_TOKEN:
            logger.warning("Slack bot token not configured, cannot send approval")
            return
        from slack_sdk.web.async_client import AsyncWebClient
        _standalone_client = AsyncWebClient(token=settings.SLACK_BOT_TOKEN)
    else:
        _standalone_client = None

    severity_emojis = {
        "critical": ":rotating_light:",
        "error": ":x:",
        "warning": ":warning:",
        "info": ":information_source:",
    }
    emoji = severity_emojis.get(severity, ":loudspeaker:")

    # Build blocks
    pii_context = metadata.get("pii_context") if metadata else None

    if pii_context:
        text_lines = [":lock: *PII SUBMISSION DETECTED*\n"]
        text_lines.append(f"*Agent:* {metadata.get('agent_name', 'Unknown')}")

        action = pii_context.get("action") or metadata.get("tool_name") or "tool call"
        text_lines.append(f"*Action:* {action}")

        dest = pii_context.get("destination_url") or pii_context.get("destination_domain")
        if dest:
            text_lines.append(f"*Site:* {dest}")

        amounts = pii_context.get("amounts", [])
        if amounts:
            text_lines.append(f"*Amount:* `{', '.join(amounts)}`")

        vault_token_details = pii_context.get("vault_token_details", [])
        vault_tokens = pii_context.get("vault_tokens", [])
        raw_pii = pii_context.get("raw_pii", [])

        if vault_token_details or vault_tokens or raw_pii:
            text_lines.append("\n*Data being sent:*")
            if vault_token_details:
                for detail in vault_token_details:
                    label_val = detail.get("label")
                    category = detail.get("category", "").replace("_", " ").title()
                    masked = detail.get("masked_value")
                    if label_val and masked:
                        text_lines.append(f"  • {category}: `{masked}` ({label_val})")
                    elif label_val:
                        text_lines.append(f"  • {label_val}")
                    else:
                        token = detail.get("token", "unknown")
                        text_lines.append(f"  • Vault Token: `{token[:20]}...`")
            elif vault_tokens:
                for token in vault_tokens:
                    text_lines.append(f"  • Vault Token: `{token[:20]}...`")
            for pii_item in raw_pii:
                pii_type = pii_item.get("type", "unknown").replace("_", " ").title()
                masked = pii_item.get("masked", "****")
                text_lines.append(f"  • {pii_type}: `{masked}`")

        body_text = "\n".join(text_lines)
    else:
        body_text = f"{emoji} *{severity.upper()}: {title}*\n\n{message}"

    # Add metadata footer (non-PII)
    if metadata and not pii_context:
        agent = metadata.get("agent_id", "Unknown")
        command = metadata.get("command", "")
        if command:
            body_text += f"\n\n:clipboard: *Agent:* `{agent}`\n:wrench: *Command:* `{command[:100]}`"

    body_text += "\n\n_Snapper Security_"

    blocks = [_section(body_text)]

    # Add approval buttons if this is an approval request
    if metadata and metadata.get("request_id") and metadata.get("requires_approval"):
        request_id = metadata["request_id"]
        blocks.append(_actions([
            _button(":white_check_mark: Approve", "approve_action", request_id, "primary"),
            _button(":x: Deny", "deny_action", request_id, "danger"),
        ]))
    # Add Allow Once/Always for blocked commands
    elif metadata and metadata.get("command") and metadata.get("agent_id"):
        context_data = json.dumps({
            "type": "run",
            "value": metadata["command"],
            "agent_id": metadata.get("agent_name", metadata["agent_id"]),
        })
        context_key = hashlib.sha256(context_data.encode()).hexdigest()[:12]

        try:
            from app.redis_client import redis_client
            await redis_client.set(f"slack_ctx:{context_key}", context_data, expire=3600)

            elements = [
                _button(":white_check_mark: Allow Once", "once_action", context_key, "primary"),
                _button(":memo: Allow Always", "always_action", context_key),
            ]
            if metadata.get("rule_name"):
                rule_id = metadata.get("rule_id", "")[:12] if metadata.get("rule_id") else ""
                if rule_id:
                    elements.append(_button(":clipboard: View Rule", "view_rule_action", rule_id))

            blocks.append(_actions(elements))
        except Exception as e:
            logger.exception(f"Failed to store Slack context for buttons: {e}")

    # Pick the API client: prefer slack_app.client, fall back to standalone
    client = slack_app.client if slack_app else _standalone_client

    # Determine target channel: DM to user, or fallback to alert channel
    try:
        if target_user_id.startswith("U"):
            dm = await client.conversations_open(users=target_user_id)
            channel = dm["channel"]["id"]
        else:
            channel = target_user_id

        await client.chat_postMessage(
            channel=channel,
            blocks=blocks,
            text=title,
        )
        logger.info(f"Slack approval sent to {target_user_id}: {title}")
    except Exception as e:
        logger.exception(f"Failed to send Slack approval: {e}")
        # Fallback to alert channel
        if settings.SLACK_ALERT_CHANNEL:
            try:
                await client.chat_postMessage(
                    channel=settings.SLACK_ALERT_CHANNEL,
                    blocks=blocks,
                    text=title,
                )
            except Exception as e2:
                logger.exception(f"Failed to send to fallback channel: {e2}")
