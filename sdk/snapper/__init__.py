"""Snapper SDK — Python wrappers for AI provider APIs with Snapper policy enforcement."""

from snapper.base import (
    SnapperClient,
    AsyncSnapperClient,
    SnapperDenied,
    SnapperApprovalTimeout,
)

__version__ = "1.0.0"

__all__ = [
    "SnapperClient",
    "AsyncSnapperClient",
    "SnapperDenied",
    "SnapperApprovalTimeout",
    "SnapperOpenAI",
    "SnapperAnthropic",
    "SnapperGemini",
]


def __getattr__(name: str):
    """Lazy-load optional provider wrappers to avoid requiring their dependencies."""
    if name == "SnapperOpenAI":
        from snapper.openai_wrapper import SnapperOpenAI
        return SnapperOpenAI
    if name == "SnapperAnthropic":
        from snapper.anthropic_wrapper import SnapperAnthropic
        return SnapperAnthropic
    if name == "SnapperGemini":
        from snapper.gemini_wrapper import SnapperGemini
        return SnapperGemini
    raise AttributeError(f"module 'snapper' has no attribute {name}")
