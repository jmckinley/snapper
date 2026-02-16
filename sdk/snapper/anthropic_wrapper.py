"""Snapper-protected wrapper for Anthropic's Python SDK.

Usage:
    from snapper.anthropic_wrapper import SnapperAnthropic

    client = SnapperAnthropic(
        snapper_url="https://snapper.example.com",
        snapper_api_key="snp_xxx",
        agent_id="myapp-anthropic",
    )
    response = client.messages.create(model="claude-sonnet-4-5-20250929", messages=[...], tools=[...])
    # tool_use blocks are automatically evaluated against Snapper policy.
"""

import json
from typing import Any, Optional

from snapper.base import SnapperClient, SnapperDenied


class _SnapperMessages:
    """Wraps anthropic.messages to intercept tool_use blocks."""

    def __init__(self, original_messages, snapper: SnapperClient, on_deny: str):
        self._original = original_messages
        self._snapper = snapper
        self._on_deny = on_deny

    def create(self, **kwargs) -> Any:
        """Intercept messages.create() and evaluate tool_use blocks."""
        stream = kwargs.get("stream", False)

        if stream:
            return self._create_stream(**kwargs)

        response = self._original.create(**kwargs)
        return self._process_response(response)

    def _create_stream(self, **kwargs):
        """Handle streaming responses by collecting and evaluating tool calls."""
        kwargs["stream"] = True
        stream = self._original.create(**kwargs)
        events = list(stream)

        tool_uses = self._extract_tool_uses_from_events(events)
        for tu in tool_uses:
            self._evaluate_tool_use(tu)

        return iter(events)

    def _process_response(self, response) -> Any:
        """Evaluate tool_use blocks in a non-streaming response."""
        if not hasattr(response, "content") or not response.content:
            return response

        denied_indices = []
        for i, block in enumerate(response.content):
            if not hasattr(block, "type") or block.type != "tool_use":
                continue

            tool_name = block.name
            tool_input = block.input if hasattr(block, "input") else {}

            try:
                self._snapper.evaluate(
                    tool_name=tool_name,
                    tool_input=tool_input if isinstance(tool_input, dict) else {"value": tool_input},
                )
            except SnapperDenied:
                if self._on_deny == "raise":
                    raise
                denied_indices.append(i)

        if denied_indices and self._on_deny == "filter":
            remaining = [
                block for i, block in enumerate(response.content)
                if i not in denied_indices
            ]
            response.content = remaining
            if not any(
                hasattr(b, "type") and b.type == "tool_use"
                for b in remaining
            ):
                response.stop_reason = "end_turn"

        return response

    def _evaluate_tool_use(self, tool_use_info: dict):
        """Evaluate a single tool_use block."""
        try:
            self._snapper.evaluate(
                tool_name=tool_use_info["name"],
                tool_input=tool_use_info["input"],
            )
        except SnapperDenied:
            if self._on_deny == "raise":
                raise

    def _extract_tool_uses_from_events(self, events) -> list:
        """Reassemble tool_use blocks from streaming events."""
        blocks = {}
        for event in events:
            if hasattr(event, "type"):
                if event.type == "content_block_start":
                    if hasattr(event, "content_block") and hasattr(event.content_block, "type"):
                        if event.content_block.type == "tool_use":
                            blocks[event.index] = {
                                "name": event.content_block.name,
                                "input": "",
                            }
                elif event.type == "content_block_delta":
                    if hasattr(event, "delta") and hasattr(event.delta, "type"):
                        if event.delta.type == "input_json_delta":
                            idx = event.index
                            if idx in blocks:
                                blocks[idx]["input"] += event.delta.partial_json

        result = []
        for idx in sorted(blocks.keys()):
            block = blocks[idx]
            try:
                block["input"] = json.loads(block["input"]) if block["input"] else {}
            except json.JSONDecodeError:
                block["input"] = {"raw": block["input"]}
            result.append(block)
        return result

    def __getattr__(self, name):
        return getattr(self._original, name)


class SnapperAnthropic:
    """Drop-in replacement for anthropic.Anthropic with Snapper policy enforcement.

    Args:
        snapper_url: Snapper server URL.
        snapper_api_key: Snapper API key.
        agent_id: Agent ID registered with Snapper.
        on_deny: "raise" (default) to raise SnapperDenied, or "filter" to silently remove denied blocks.
        snapper_fail_mode: "closed" (default) or "open".
        **anthropic_kwargs: Passed to anthropic.Anthropic().
    """

    def __init__(
        self,
        snapper_url: Optional[str] = None,
        snapper_api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        on_deny: str = "raise",
        snapper_fail_mode: str = "closed",
        **anthropic_kwargs,
    ):
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install snapper-sdk[anthropic]"
            )

        self._snapper = SnapperClient(
            snapper_url=snapper_url,
            snapper_api_key=snapper_api_key,
            agent_id=agent_id,
            fail_mode=snapper_fail_mode,
        )
        self._anthropic = Anthropic(**anthropic_kwargs)
        self._on_deny = on_deny
        self.messages = _SnapperMessages(self._anthropic.messages, self._snapper, on_deny)

    def close(self):
        self._snapper.close()
        self._anthropic.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getattr__(self, name):
        if name == "messages":
            return self.messages
        return getattr(self._anthropic, name)
