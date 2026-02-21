"""Background threat analysis worker.

Consumes signals from Redis Streams, runs them through behavioral
baseline updates, kill chain detection, and anomaly scoring.
Computes composite threat scores and fires alerts.
"""

import asyncio
import json
import logging
import time
from typing import Any, Dict, List

from app.config import get_settings
from app.tasks import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

# Consumer group name for threat signal streams
CONSUMER_GROUP = "threat_analyzers"
CONSUMER_NAME = "worker-1"


def _run_async(coro):
    """Run async coroutine in sync Celery context.

    Uses asyncio.run() to ensure a clean event loop in forked workers.
    The old get_event_loop() approach inherits a stale loop from the
    parent process, causing asyncio.Lock deadlocks in the circuit breaker.
    """
    return asyncio.run(coro)


async def _make_redis():
    """Create a fresh Redis client for Celery task use.

    Avoids the module-level redis_client singleton whose CircuitBreaker
    asyncio.Lock was created in the parent process before fork.
    A fresh RedisClient gets its Lock bound to the current event loop.
    """
    from app.redis_client import RedisClient
    client = RedisClient()
    await client.connect()
    return client


# ---------------------------------------------------------------------------
# Anomaly scoring weights
# ---------------------------------------------------------------------------

ANOMALY_WEIGHTS = {
    "bytes_out_zscore": 8,
    "new_destination": 6,
    "encoding_frequency": 5,
    "pii_frequency": 4,
    "tool_anomaly": 4,
    "hour_anomaly": 3,
}

# Max contribution per anomaly = 3x weight
ANOMALY_CAP_MULTIPLIER = 3


def compute_composite_score(
    kill_chain_boosts: List[int],
    anomaly_scores: Dict[str, float],
    signal_count: int,
) -> float:
    """Compute composite threat score (0-100).

    Formula:
      score = max(kill_chain_boosts)       # 0-60
            + weighted_anomaly_sum         # 0-30
            + signal_frequency_penalty     # 0-10
    """
    # Kill chain component (take the highest boost)
    kc_score = max(kill_chain_boosts) if kill_chain_boosts else 0

    # Anomaly component (weighted, capped per anomaly)
    anomaly_total = 0.0
    for key, weight in ANOMALY_WEIGHTS.items():
        raw = anomaly_scores.get(key, 0.0)
        capped = min(raw * weight, weight * ANOMALY_CAP_MULTIPLIER)
        anomaly_total += capped
    # Cap anomaly total at 30
    anomaly_total = min(anomaly_total, 30.0)

    # Signal frequency penalty (many signals in short time)
    freq_penalty = min(signal_count * 0.5, 10.0)

    # Total capped at 100
    return min(kc_score + anomaly_total + freq_penalty, 100.0)


# ---------------------------------------------------------------------------
# Main analysis task (runs every 2 seconds via Celery beat)
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, max_retries=0, time_limit=30)
def analyze_threat_signals(self):
    """Consume signals from Redis Streams and analyze."""
    if not settings.THREAT_DETECTION_ENABLED:
        return

    _run_async(_analyze_signals_async())


async def _analyze_signals_async():
    """Async implementation of signal analysis."""
    from app.services.threat_detector import (
        ThreatSignal,
        set_threat_score,
        get_threat_score,
        classify_threat_level,
        SignalType,
    )
    from app.services.behavioral_baseline import BehavioralBaseline
    from app.services.kill_chain_detector import KillChainDetector

    # Reset the module-level DB engine's connection pool so connections
    # are bound to the current event loop (created by asyncio.run()).
    from app.database import engine
    await engine.dispose()

    try:
        redis = await _make_redis()
    except Exception as e:
        logger.warning(f"Threat analysis: Redis connect failed: {e}")
        return

    try:
        baseline = BehavioralBaseline(redis)
        kill_chain = KillChainDetector(redis)

        # Discover all agent signal streams
        try:
            stream_keys = await redis.keys("threat:signals:*")
        except Exception as e:
            logger.warning(f"Failed to discover signal streams: {e}")
            return

        for stream_key in stream_keys:
            agent_id = stream_key.replace("threat:signals:", "")

            # Ensure consumer group exists
            try:
                await redis.xgroup_create(stream_key, CONSUMER_GROUP, id="0", mkstream=True)
            except Exception:
                pass

            # Read pending and new messages
            try:
                messages = await redis.xreadgroup(
                    CONSUMER_GROUP,
                    CONSUMER_NAME,
                    {stream_key: ">"},
                    count=100,
                    block=100,  # 100ms timeout; block=0 means block forever!
                )
            except Exception as e:
                logger.debug(f"Failed to read stream {stream_key}: {e}")
                continue

            if not messages:
                continue

            kill_chain_boosts = []
            anomaly_scores: Dict[str, float] = {}
            signal_count = 0
            contributing_signals = []

            for stream_name, entries in messages:
                for msg_id, fields in entries:
                    try:
                        signal = ThreatSignal.from_stream_fields(fields)
                        signal_count += 1

                        # 1. Update behavioral baseline
                        await baseline.update(signal)

                        # 2. Evaluate kill chains
                        completed = await kill_chain.evaluate(signal)
                        for result in completed:
                            kill_chain_boosts.append(result["score_boost"])
                            contributing_signals.extend(result.get("signals", []))

                            # Create threat event for completed chain
                            await _create_threat_event(
                                agent_id=agent_id,
                                chain_result=result,
                                signal=signal,
                            )

                        # 3. Compute anomaly scores
                        if signal.signal_type == SignalType.NETWORK_SEND and signal.payload_bytes > 0:
                            zscore = await baseline.get_bytes_out_zscore(
                                agent_id, signal.payload_bytes
                            )
                            anomaly_scores["bytes_out_zscore"] = max(
                                anomaly_scores.get("bytes_out_zscore", 0), abs(zscore)
                            )

                        if signal.signal_type == SignalType.NETWORK_SEND and signal.destination:
                            is_new = await baseline.is_new_destination(agent_id, signal.destination)
                            if is_new:
                                anomaly_scores["new_destination"] = anomaly_scores.get("new_destination", 0) + 1

                        if signal.signal_type == SignalType.ENCODING_DETECTED:
                            anomaly_scores["encoding_frequency"] = anomaly_scores.get("encoding_frequency", 0) + 1

                        if signal.signal_type == SignalType.PII_OUTBOUND:
                            anomaly_scores["pii_frequency"] = anomaly_scores.get("pii_frequency", 0) + 1

                        if signal.signal_type == SignalType.TOOL_ANOMALY:
                            anomaly_scores["tool_anomaly"] = anomaly_scores.get("tool_anomaly", 0) + 1

                        # Hour anomaly
                        import datetime
                        hour = datetime.datetime.fromtimestamp(signal.timestamp).hour
                        hour_score = await baseline.get_hour_anomaly_score(agent_id, hour)
                        if hour_score > 0:
                            anomaly_scores["hour_anomaly"] = max(
                                anomaly_scores.get("hour_anomaly", 0), hour_score
                            )

                        # ACK the message
                        await redis.xack(stream_key, CONSUMER_GROUP, msg_id)

                    except Exception as e:
                        logger.debug(f"Failed to process signal: {e}")

            # 4. Compute composite score
            if signal_count > 0:
                new_score = compute_composite_score(
                    kill_chain_boosts, anomaly_scores, signal_count
                )

                # Blend with existing score (decay old, add new)
                current_score = await get_threat_score(redis, agent_id)
                # Weighted blend: 60% new, 40% decayed old
                blended = max(new_score, current_score * 0.4 + new_score * 0.6)
                blended = min(blended, 100.0)

                await set_threat_score(redis, agent_id, blended)

                # 5. Auto-quarantine on very high threat score
                if (
                    settings.THREAT_AUTO_QUARANTINE
                    and blended >= settings.QUARANTINE_ON_THREAT_SCORE
                ):
                    try:
                        from app.services.auto_quarantine import quarantine_agent as _quarantine
                        from app.database import get_db_context
                        from uuid import UUID as _UUID

                        async with get_db_context() as qdb:
                            await _quarantine(
                                qdb,
                                _UUID(agent_id),
                                reason=f"Auto-quarantined: threat score {blended:.0f} >= {settings.QUARANTINE_ON_THREAT_SCORE}",
                                triggered_by="threat_score",
                            )
                    except Exception as e:
                        logger.warning(f"Auto-quarantine failed for {agent_id}: {e}")

                # 6. Fire alert if threshold crossed
                if blended >= settings.THREAT_ALERT_THRESHOLD:
                    threat_level = classify_threat_level(blended)
                    await _fire_threat_alert(
                        agent_id=agent_id,
                        score=blended,
                        level=threat_level,
                        kill_chain_boosts=kill_chain_boosts,
                        anomaly_scores=anomaly_scores,
                        signal_count=signal_count,
                    )
    finally:
        await redis.close()


async def _create_threat_event(
    agent_id: str,
    chain_result: Dict[str, Any],
    signal: Any,
) -> None:
    """Persist a threat event to the database."""
    try:
        from app.database import get_db_context
        from app.models.threat_events import ThreatEvent, ThreatSeverity
        from app.models.agents import Agent
        from uuid import UUID
        from sqlalchemy import select

        async with get_db_context() as db:
            # Look up agent for org_id
            agent = (await db.execute(
                select(Agent).where(Agent.id == UUID(agent_id))
            )).scalar_one_or_none()

            severity = ThreatSeverity.HIGH
            if chain_result["score_boost"] >= 55:
                severity = ThreatSeverity.CRITICAL
            elif chain_result["score_boost"] >= 40:
                severity = ThreatSeverity.HIGH
            elif chain_result["score_boost"] >= 25:
                severity = ThreatSeverity.MEDIUM

            # Extract trigger signal info (signal is a ThreatSignal dataclass)
            trigger_info = {}
            try:
                sig_type = getattr(signal, "signal_type", None)
                trigger_info = {
                    "type": sig_type.value if hasattr(sig_type, "value") else str(sig_type),
                    "tool": getattr(signal, "tool_name", None),
                    "dest": getattr(signal, "destination", None),
                }
            except Exception:
                pass

            event = ThreatEvent(
                agent_id=UUID(agent_id),
                organization_id=agent.organization_id if agent else None,
                threat_type=chain_result["chain"],
                severity=severity,
                threat_score=float(chain_result["score_boost"]),
                kill_chain=chain_result["chain"],
                signals=chain_result.get("signals", []),
                description=chain_result.get("description", f"Kill chain completed: {chain_result['chain']}"),
                details={
                    "chain_name": chain_result["chain"],
                    "score_boost": chain_result["score_boost"],
                    "trigger_signal": trigger_info,
                },
                status="active",
            )
            db.add(event)

            # Also create audit log
            from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity
            audit = AuditLog(
                action=AuditAction.THREAT_KILL_CHAIN_COMPLETED,
                severity=AuditSeverity.CRITICAL if severity == ThreatSeverity.CRITICAL else AuditSeverity.ERROR,
                agent_id=UUID(agent_id),
                organization_id=agent.organization_id if agent else None,
                message=f"Kill chain '{chain_result['chain']}' completed (score boost +{chain_result['score_boost']})",
                details={
                    "chain": chain_result["chain"],
                    "score_boost": chain_result["score_boost"],
                    "signals": chain_result.get("signals", []),
                },
            )
            db.add(audit)

    except Exception as e:
        logger.warning(f"Failed to create threat event for chain '{chain_result.get('chain')}': {e}", exc_info=True)


async def _fire_threat_alert(
    agent_id: str,
    score: float,
    level: str,
    kill_chain_boosts: List[int],
    anomaly_scores: Dict[str, float],
    signal_count: int,
) -> None:
    """Send threat alert via Telegram/Slack."""
    try:
        from app.tasks.alerts import send_alert

        severity = "critical" if score >= 80 else "error" if score >= 60 else "warning"

        # Build summary
        chains = [f"+{b}" for b in kill_chain_boosts] if kill_chain_boosts else ["none"]
        anomalies = ", ".join(f"{k}={v:.1f}" for k, v in anomaly_scores.items()) or "none"

        message = (
            f"Threat score: *{score:.0f}/100* ({level})\n"
            f"Kill chains: {', '.join(chains)}\n"
            f"Anomalies: {anomalies}\n"
            f"Signals in batch: {signal_count}\n\n"
        )

        if score >= 80:
            message += "Action: Requests will be *DENIED* until score decays."
        elif score >= 60:
            message += "Action: Requests will require *APPROVAL* until score decays."
        else:
            message += "Action: Monitoring only. Score below enforcement threshold."

        # Get agent name
        agent_name = agent_id[:8]
        try:
            from app.database import get_db_context
            from app.models.agents import Agent
            from uuid import UUID
            from sqlalchemy import select

            async with get_db_context() as db:
                agent = (await db.execute(
                    select(Agent).where(Agent.id == UUID(agent_id))
                )).scalar_one_or_none()
                if agent:
                    agent_name = agent.name

                    send_alert.delay(
                        title=f"Threat Detected: {agent_name}",
                        message=message,
                        severity=severity,
                        metadata={
                            "agent_id": agent_id,
                            "agent_name": agent_name,
                            "threat_score": score,
                            "threat_level": level,
                            "agent_owner_chat_id": getattr(agent, "owner_chat_id", None),
                        },
                    )
        except Exception:
            send_alert.delay(
                title=f"Threat Detected: Agent {agent_name}",
                message=message,
                severity=severity,
                metadata={
                    "agent_id": agent_id,
                    "threat_score": score,
                    "threat_level": level,
                },
            )
    except Exception as e:
        logger.warning(f"Failed to fire threat alert: {e}")


# ---------------------------------------------------------------------------
# Periodic tasks
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, max_retries=0, time_limit=300)
def prune_baselines(self):
    """Prune old baseline data (daily task)."""
    if not settings.THREAT_DETECTION_ENABLED:
        return

    _run_async(_prune_baselines_async())


async def _prune_baselines_async():
    """Async implementation of baseline pruning."""
    from app.services.behavioral_baseline import BehavioralBaseline

    redis = await _make_redis()
    try:
        baseline = BehavioralBaseline(redis)
        agent_ids = await baseline.get_all_agent_ids()

        pruned = 0
        for agent_id in agent_ids:
            try:
                await baseline.prune_old_data(agent_id)
                pruned += 1
            except Exception as e:
                logger.debug(f"Failed to prune baseline for {agent_id}: {e}")

        logger.info(f"Pruned baselines for {pruned}/{len(agent_ids)} agents")
    finally:
        await redis.close()


@celery_app.task(bind=True, max_retries=0, time_limit=120)
def detect_slow_drip(self):
    """Detect slow-drip exfiltration patterns (15-minute task).

    Queries bytes_out sorted sets and looks for monotonically
    increasing outbound volume over 15+ minutes.
    """
    if not settings.THREAT_DETECTION_ENABLED:
        return

    _run_async(_detect_slow_drip_async())


async def _detect_slow_drip_async():
    """Async implementation of slow-drip detection."""
    from app.services.behavioral_baseline import BehavioralBaseline
    from app.services.threat_detector import set_threat_score, get_threat_score

    redis = await _make_redis()
    try:
        baseline = BehavioralBaseline(redis)
        agent_ids = await baseline.get_all_agent_ids()

        now = time.time()
        window_15m = now - 900  # 15 minutes
        window_30m = now - 1800  # 30 minutes

        for agent_id in agent_ids:
            try:
                bytes_key = f"baseline:bytes_out:{agent_id}"

                # Get recent bytes_out entries
                entries = await redis.zrangebyscore(bytes_key, str(window_30m), str(now))
                if len(entries) < 5:
                    continue

                # Check for sustained outbound pattern
                values = []
                for member in entries:
                    score = await redis.zscore(bytes_key, member)
                    if score is not None:
                        values.append(float(score))

                if len(values) < 5:
                    continue

                # Check if trend is increasing (simple: later half > earlier half)
                mid = len(values) // 2
                first_half_avg = sum(values[:mid]) / max(mid, 1)
                second_half_avg = sum(values[mid:]) / max(len(values) - mid, 1)

                if second_half_avg > first_half_avg * 1.5 and sum(values) > 10000:
                    # Sustained increasing outbound — suspicious
                    duration_minutes = (now - float(entries[0])) / 60.0 if entries else 0

                    boost = 20 if duration_minutes >= 15 else 0
                    if duration_minutes >= 30:
                        boost = 35

                    if boost > 0:
                        current = await get_threat_score(redis, agent_id)
                        new_score = min(current + boost * 0.5, 100.0)  # Additive, halved
                        await set_threat_score(redis, agent_id, new_score)

                        logger.info(
                            f"Slow-drip detected for agent {agent_id}: "
                            f"{duration_minutes:.0f}min, {sum(values):.0f} bytes total"
                        )
            except Exception as e:
                logger.debug(f"Slow-drip check failed for {agent_id}: {e}")
    finally:
        await redis.close()
