"""Per-agent behavioral profiling with rolling window.

Maintains lightweight per-agent baselines in Redis:
- Tool usage histograms
- Destination frequency maps
- Bytes out moving averages
- Time-of-day patterns

All operations are O(1) Redis commands. Baseline data is pruned
daily to maintain a rolling window (default 7 days).
"""

import logging
import math
import time
from typing import Optional

from app.config import get_settings
from app.services.threat_detector import ThreatSignal

logger = logging.getLogger(__name__)
settings = get_settings()

# Redis key prefixes
_TOOLS_KEY = "baseline:tools:{agent_id}"
_DEST_KEY = "baseline:destinations:{agent_id}"
_BYTES_KEY = "baseline:bytes_out:{agent_id}"
_HOURS_KEY = "baseline:hours:{agent_id}"
_STATS_KEY = "baseline:stats:{agent_id}"

# Seconds in one day of the baseline window
_WINDOW_SECONDS = settings.THREAT_BASELINE_WINDOW_DAYS * 86400


def _key(template: str, agent_id: str) -> str:
    return template.replace("{agent_id}", agent_id)


class BehavioralBaseline:
    """Per-agent behavioral baseline backed by Redis."""

    def __init__(self, redis):
        self.redis = redis

    async def update(self, signal: ThreatSignal) -> None:
        """Update baseline from a new signal. O(1) Redis ops."""
        agent_id = signal.agent_id
        try:
            # Tool usage histogram
            if signal.tool_name:
                await self.redis.hincrby(
                    _key(_TOOLS_KEY, agent_id), signal.tool_name, 1
                )

            # Destination frequency
            if signal.destination:
                await self.redis.hincrby(
                    _key(_DEST_KEY, agent_id), signal.destination, 1
                )

            # Bytes out sorted set (timestamp → bytes)
            if signal.payload_bytes > 0:
                await self.redis.zadd(
                    _key(_BYTES_KEY, agent_id),
                    {str(signal.timestamp): signal.payload_bytes},
                )

            # Time-of-day histogram (hour 0-23)
            import datetime
            hour = datetime.datetime.fromtimestamp(signal.timestamp).hour
            await self.redis.hincrby(
                _key(_HOURS_KEY, agent_id), str(hour), 1
            )

            # Update total request count in stats
            await self.redis.hincrby(
                _key(_STATS_KEY, agent_id), "total_requests_7d", 1
            )
            await self.redis.hset(
                _key(_STATS_KEY, agent_id), "last_updated", str(time.time())
            )

        except Exception as e:
            logger.debug(f"Baseline update failed for {agent_id}: {e}")

    async def is_new_destination(self, agent_id: str, destination: str) -> bool:
        """Check if a destination has never been seen by this agent."""
        if not destination:
            return False
        try:
            return not await self.redis.hexists(
                _key(_DEST_KEY, agent_id), destination
            )
        except Exception:
            return False

    async def get_bytes_out_zscore(self, agent_id: str, current_bytes: int) -> float:
        """Compute Z-score of current bytes vs rolling average.

        Returns 0.0 if insufficient data for a meaningful comparison.
        """
        try:
            stats = await self.redis.hgetall(_key(_STATS_KEY, agent_id))
            if not stats:
                return 0.0

            avg = float(stats.get("avg_bytes_out", 0))
            stddev = float(stats.get("stddev_bytes_out", 0))

            if stddev < 1.0:
                return 0.0

            return (current_bytes - avg) / stddev
        except Exception:
            return 0.0

    async def get_tool_frequency(self, agent_id: str, tool_name: str) -> float:
        """Get normalized frequency (0.0-1.0) for a tool.

        Returns 0.0 if the tool has never been used.
        """
        if not tool_name:
            return 0.0
        try:
            all_tools = await self.redis.hgetall(_key(_TOOLS_KEY, agent_id))
            if not all_tools:
                return 0.0
            total = sum(int(v) for v in all_tools.values())
            if total == 0:
                return 0.0
            count = int(all_tools.get(tool_name, 0))
            return count / total
        except Exception:
            return 0.0

    async def get_hour_anomaly_score(self, agent_id: str, hour: int) -> float:
        """Score how anomalous the current hour is for this agent.

        Returns 0.0 (normal) to 1.0 (never seen this hour).
        """
        try:
            hours = await self.redis.hgetall(_key(_HOURS_KEY, agent_id))
            if not hours:
                return 0.0

            total = sum(int(v) for v in hours.values())
            if total < 10:
                return 0.0  # Not enough data

            hour_count = int(hours.get(str(hour), 0))
            expected = total / 24.0

            if expected < 1:
                return 0.0

            # Deviation ratio: 0 = exactly average, 1 = never seen
            ratio = max(0.0, 1.0 - (hour_count / expected))
            return min(ratio, 1.0)
        except Exception:
            return 0.0

    async def recompute_stats(self, agent_id: str) -> None:
        """Recompute rolling avg/stddev from bytes_out sorted set.

        Called after pruning old data or periodically.
        """
        try:
            bytes_key = _key(_BYTES_KEY, agent_id)
            stats_key = _key(_STATS_KEY, agent_id)

            # Get all bytes values
            all_entries = await self.redis.zrangebyscore(bytes_key, "-inf", "+inf")
            if not all_entries:
                await self.redis.hset(stats_key, "avg_bytes_out", "0")
                await self.redis.hset(stats_key, "stddev_bytes_out", "0")
                return

            # The sorted set stores timestamp as member and bytes as score
            # We need to read scores
            values = []
            for member in all_entries:
                score = await self.redis.zscore(bytes_key, member)
                if score is not None:
                    values.append(float(score))

            if not values:
                return

            avg = sum(values) / len(values)
            variance = sum((v - avg) ** 2 for v in values) / max(len(values), 1)
            stddev = math.sqrt(variance)

            # Count unique destinations and tools
            dest_count = 0
            tool_count = 0
            try:
                dests = await self.redis.hgetall(_key(_DEST_KEY, agent_id))
                dest_count = len(dests)
                tools = await self.redis.hgetall(_key(_TOOLS_KEY, agent_id))
                tool_count = len(tools)
            except Exception:
                pass

            await self.redis.hset(stats_key, "avg_bytes_out", str(round(avg, 2)))
            await self.redis.hset(stats_key, "stddev_bytes_out", str(round(stddev, 2)))
            await self.redis.hset(stats_key, "unique_destinations", str(dest_count))
            await self.redis.hset(stats_key, "unique_tools", str(tool_count))
            await self.redis.hset(stats_key, "data_points", str(len(values)))
            await self.redis.hset(stats_key, "last_updated", str(time.time()))

        except Exception as e:
            logger.debug(f"Recompute stats failed for {agent_id}: {e}")

    async def prune_old_data(self, agent_id: str) -> None:
        """Remove data older than the baseline window.

        Should be called daily via Celery beat.
        """
        try:
            cutoff = time.time() - _WINDOW_SECONDS
            bytes_key = _key(_BYTES_KEY, agent_id)
            await self.redis.zremrangebyscore(bytes_key, "-inf", str(cutoff))
            await self.recompute_stats(agent_id)
        except Exception as e:
            logger.debug(f"Prune failed for {agent_id}: {e}")

    async def get_all_agent_ids(self) -> list:
        """Get all agent IDs that have baseline data.

        Scans for baseline:stats:* keys.
        """
        try:
            keys = await self.redis.keys("baseline:stats:*")
            return [k.replace("baseline:stats:", "") for k in keys]
        except Exception:
            return []
