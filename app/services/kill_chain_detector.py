"""Multi-step attack pattern correlation using state machines.

Detects kill chains by tracking sequences of threat signals that
match predefined attack patterns within sliding time windows.

Each chain is a state machine: signal types must appear in order
within configured time gaps. State is persisted in Redis so chains
can span multiple analysis cycles.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.services.threat_detector import SignalType, ThreatSignal

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Kill chain definitions
# ---------------------------------------------------------------------------

@dataclass
class KillChainStage:
    """One stage of a kill chain."""
    signal_type: str
    max_gap_seconds: float = 60.0  # Max time since previous stage
    min_count: int = 1  # Minimum signals of this type needed


@dataclass
class KillChainDefinition:
    """A complete kill chain pattern."""
    name: str
    stages: List[KillChainStage]
    score_boost: int
    description: str = ""


# Predefined kill chains
KILL_CHAINS: List[KillChainDefinition] = [
    KillChainDefinition(
        name="data_exfiltration",
        stages=[
            KillChainStage(signal_type=SignalType.FILE_READ, max_gap_seconds=60),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=60),
        ],
        score_boost=40,
        description="File read followed by network send within 60s",
    ),
    KillChainDefinition(
        name="credential_theft",
        stages=[
            KillChainStage(signal_type=SignalType.CREDENTIAL_ACCESS, max_gap_seconds=120),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=120),
        ],
        score_boost=50,
        description="Credential file access followed by network send",
    ),
    KillChainDefinition(
        name="pii_harvest_exfil",
        stages=[
            KillChainStage(
                signal_type=SignalType.PII_OUTBOUND,
                max_gap_seconds=300,
                min_count=3,
            ),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=300),
        ],
        score_boost=45,
        description="3+ PII detections followed by network send",
    ),
    KillChainDefinition(
        name="encoded_exfil",
        stages=[
            KillChainStage(signal_type=SignalType.FILE_READ, max_gap_seconds=30),
            KillChainStage(signal_type=SignalType.ENCODING_DETECTED, max_gap_seconds=30),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=30),
        ],
        score_boost=50,
        description="File read, then encoding, then network send",
    ),
    KillChainDefinition(
        name="privesc_to_exfil",
        stages=[
            KillChainStage(signal_type=SignalType.PRIVILEGE_ESCALATION, max_gap_seconds=120),
            KillChainStage(signal_type=SignalType.FILE_READ, max_gap_seconds=60),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=60),
        ],
        score_boost=55,
        description="Privilege escalation, file read, then network send",
    ),
    KillChainDefinition(
        name="vault_token_extraction",
        stages=[
            KillChainStage(signal_type=SignalType.VAULT_TOKEN_PROBE, max_gap_seconds=180),
            KillChainStage(signal_type=SignalType.PII_OUTBOUND, max_gap_seconds=180),
        ],
        score_boost=60,
        description="Vault token probing followed by PII outbound",
    ),
    KillChainDefinition(
        name="lotl_exfil",
        stages=[
            KillChainStage(signal_type=SignalType.TOOL_ANOMALY, max_gap_seconds=60),
            KillChainStage(signal_type=SignalType.NETWORK_SEND, max_gap_seconds=60),
        ],
        score_boost=35,
        description="Living-off-the-land tool use followed by network send",
    ),
]

# Build lookup by name
KILL_CHAIN_MAP: Dict[str, KillChainDefinition] = {kc.name: kc for kc in KILL_CHAINS}


# ---------------------------------------------------------------------------
# Kill chain state (Redis-backed)
# ---------------------------------------------------------------------------

def _state_key(agent_id: str, chain_name: str) -> str:
    return f"killchain:{agent_id}:{chain_name}"


class KillChainDetector:
    """Evaluate signals against kill chain state machines.

    State is stored in Redis hashes per agent per chain:
      killchain:{agent_id}:{chain_name} → {
          stage: <int>,
          stage_ts: <float>,
          stage_count: <int>,        # count within current stage
          signals: <json array>,
      }
    """

    def __init__(self, redis):
        self.redis = redis

    async def evaluate(
        self, signal: ThreatSignal
    ) -> List[Dict[str, Any]]:
        """Evaluate a signal against all kill chains.

        Returns a list of completed chain results:
        [{"chain": name, "score_boost": int, "signals": [...]}]
        """
        completed = []

        for chain in KILL_CHAINS:
            result = await self._evaluate_chain(signal, chain)
            if result:
                completed.append(result)

        return completed

    async def _evaluate_chain(
        self, signal: ThreatSignal, chain: KillChainDefinition
    ) -> Optional[Dict[str, Any]]:
        """Evaluate a signal against a single kill chain."""
        agent_id = signal.agent_id
        key = _state_key(agent_id, chain.name)

        try:
            state = await self._load_state(key)
            current_stage_idx = state.get("stage", 0)
            stage_ts = state.get("stage_ts", 0.0)
            stage_count = state.get("stage_count", 0)
            recorded_signals = state.get("signals", [])

            # Check if signal matches the expected stage
            if current_stage_idx >= len(chain.stages):
                # Already completed, reset
                await self._reset_state(key)
                current_stage_idx = 0
                stage_ts = 0.0
                stage_count = 0
                recorded_signals = []

            expected_stage = chain.stages[current_stage_idx]

            # Does the signal type match the expected stage?
            if signal.signal_type != expected_stage.signal_type:
                # Check if signal matches stage 0 (restart chain)
                if current_stage_idx > 0 and signal.signal_type == chain.stages[0].signal_type:
                    # Restart chain from stage 0
                    await self._save_state(key, {
                        "stage": 0,
                        "stage_ts": signal.timestamp,
                        "stage_count": 1,
                        "signals": [self._signal_summary(signal)],
                    })
                return None

            # Signal matches expected type — check time gap
            if current_stage_idx > 0:
                gap = signal.timestamp - stage_ts
                if gap > expected_stage.max_gap_seconds:
                    # Gap expired — reset to stage 0
                    # But check if this signal starts a new chain
                    if signal.signal_type == chain.stages[0].signal_type:
                        await self._save_state(key, {
                            "stage": 0,
                            "stage_ts": signal.timestamp,
                            "stage_count": 1,
                            "signals": [self._signal_summary(signal)],
                        })
                    else:
                        await self._reset_state(key)
                    return None

            # Increment count for this stage
            stage_count += 1
            recorded_signals.append(self._signal_summary(signal))

            # Check if stage min_count met
            if stage_count < expected_stage.min_count:
                # Stay at same stage, waiting for more signals
                await self._save_state(key, {
                    "stage": current_stage_idx,
                    "stage_ts": signal.timestamp,
                    "stage_count": stage_count,
                    "signals": recorded_signals,
                })
                return None

            # Stage complete — advance
            next_stage = current_stage_idx + 1

            if next_stage >= len(chain.stages):
                # Chain complete!
                await self._reset_state(key)
                return {
                    "chain": chain.name,
                    "score_boost": chain.score_boost,
                    "description": chain.description,
                    "signals": recorded_signals,
                }

            # Advance to next stage
            await self._save_state(key, {
                "stage": next_stage,
                "stage_ts": signal.timestamp,
                "stage_count": 0,
                "signals": recorded_signals,
            })
            return None

        except Exception as e:
            logger.debug(f"Kill chain eval failed for {chain.name}: {e}")
            return None

    async def _load_state(self, key: str) -> Dict[str, Any]:
        """Load kill chain state from Redis."""
        try:
            data = await self.redis.hgetall(key)
            if not data:
                return {"stage": 0, "stage_ts": 0.0, "stage_count": 0, "signals": []}
            return {
                "stage": int(data.get("stage", 0)),
                "stage_ts": float(data.get("stage_ts", 0.0)),
                "stage_count": int(data.get("stage_count", 0)),
                "signals": json.loads(data.get("signals", "[]")),
            }
        except Exception:
            return {"stage": 0, "stage_ts": 0.0, "stage_count": 0, "signals": []}

    async def _save_state(self, key: str, state: Dict[str, Any]) -> None:
        """Save kill chain state to Redis."""
        try:
            await self.redis.hset(key, "stage", str(state["stage"]))
            await self.redis.hset(key, "stage_ts", str(state["stage_ts"]))
            await self.redis.hset(key, "stage_count", str(state["stage_count"]))
            await self.redis.hset(key, "signals", json.dumps(state["signals"]))
            # TTL = max gap of all stages * 2
            await self.redis.expire(key, 600)
        except Exception as e:
            logger.debug(f"Failed to save kill chain state: {e}")

    async def _reset_state(self, key: str) -> None:
        """Reset kill chain state."""
        try:
            await self.redis.delete(key)
        except Exception:
            pass

    @staticmethod
    def _signal_summary(signal: ThreatSignal) -> Dict[str, Any]:
        """Create a compact summary dict from a signal."""
        return {
            "type": signal.signal_type,
            "ts": round(signal.timestamp, 2),
            "tool": signal.tool_name,
            "dest": signal.destination,
            "cmd": signal.command[:100] if signal.command else "",
        }

    async def reset_all(self, agent_id: str) -> None:
        """Reset all kill chain states for an agent."""
        for chain in KILL_CHAINS:
            await self._reset_state(_state_key(agent_id, chain.name))
