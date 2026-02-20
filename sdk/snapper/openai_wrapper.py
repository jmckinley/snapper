"""Snapper-protected wrapper for OpenAI's Python SDK.

Usage:
    from snapper.openai_wrapper import SnapperOpenAI

    client = SnapperOpenAI(
        snapper_url="https://snapper.example.com",
        snapper_api_key="snp_xxx",
        agent_id="myapp-openai",
    )
    response = client.chat.completions.create(model="gpt-4", messages=[...], tools=[...])
    # Tool calls are automatically evaluated against Snapper policy.
"""

import json
from typing import Any, Optional

from snapper.base import SnapperClient, SnapperDenied


class _SnapperCompletions:
    """Wraps openai.chat.completions to intercept tool calls."""

    def __init__(self, original_completions, snapper: SnapperClient, on_deny: str):
        self._original = original_completions
        self._snapper = snapper
        self._on_deny = on_deny

    def create(self, **kwargs) -> Any:
        """Intercept chat.completions.create() and evaluate tool calls."""
        stream = kwargs.get("stream", False)

        if stream:
            return self._create_stream(**kwargs)

        response = self._original.create(**kwargs)
        return self._process_response(response)

    def _create_stream(self, **kwargs):
        """Handle streaming responses by buffering tool call chunks."""
        stream = self._original.create(**kwargs)
        chunks = list(stream)

        # Reassemble tool calls from chunks
        tool_calls = self._extract_tool_calls_from_chunks(chunks)

        if tool_calls:
            for tc in tool_calls:
                self._evaluate_tool_call(tc)

        # Yield original chunks
        return iter(chunks)

    def _process_response(self, response) -> Any:
        """Evaluate tool calls in a non-streaming response."""
        if not hasattr(response, "choices") or not response.choices:
            return response

        for choice in response.choices:
            message = choice.message
            if not hasattr(message, "tool_calls") or not message.tool_calls:
                continue

            denied_indices = []
            for i, tool_call in enumerate(message.tool_calls):
                fn = tool_call.function
                tool_name = fn.name
                try:
                    tool_input = json.loads(fn.arguments) if fn.arguments else {}
                except json.JSONDecodeError:
                    tool_input = {"raw": fn.arguments}

                try:
                    self._snapper.evaluate(
                        tool_name=tool_name,
                        tool_input=tool_input,
                    )
                except SnapperDenied:
                    if self._on_deny == "raise":
                        raise
                    denied_indices.append(i)

            # Remove denied tool calls (filter mode)
            if denied_indices and self._on_deny == "filter":
                remaining = [
                    tc for i, tc in enumerate(message.tool_calls)
                    if i not in denied_indices
                ]
                message.tool_calls = remaining if remaining else None
                if not remaining:
                    choice.finish_reason = "stop"

        return response

    def _evaluate_tool_call(self, tool_call_info: dict):
        """Evaluate a single tool call."""
        try:
            self._snapper.evaluate(
                tool_name=tool_call_info["name"],
                tool_input=tool_call_info["arguments"],
            )
        except SnapperDenied:
            if self._on_deny == "raise":
                raise

    def _extract_tool_calls_from_chunks(self, chunks) -> list:
        """Reassemble tool calls from streaming chunks."""
        calls = {}
        for chunk in chunks:
            if not hasattr(chunk, "choices") or not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if not hasattr(delta, "tool_calls") or not delta.tool_calls:
                continue
            for tc_delta in delta.tool_calls:
                idx = tc_delta.index
                if idx not in calls:
                    calls[idx] = {"name": "", "arguments": ""}
                if hasattr(tc_delta, "function") and tc_delta.function:
                    if tc_delta.function.name:
                        calls[idx]["name"] = tc_delta.function.name
                    if tc_delta.function.arguments:
                        calls[idx]["arguments"] += tc_delta.function.arguments

        result = []
        for idx in sorted(calls.keys()):
            tc = calls[idx]
            try:
                tc["arguments"] = json.loads(tc["arguments"])
            except (json.JSONDecodeError, TypeError):
                tc["arguments"] = {"raw": tc["arguments"]}
            result.append(tc)
        return result

    def __getattr__(self, name):
        return getattr(self._original, name)


class _SnapperChat:
    """Wraps openai.chat to intercept completions."""

    def __init__(self, original_chat, snapper: SnapperClient, on_deny: str):
        self.completions = _SnapperCompletions(
            original_chat.completions, snapper, on_deny
        )
        self._original = original_chat

    def __getattr__(self, name):
        if name == "completions":
            return self.completions
        return getattr(self._original, name)


class SnapperOpenAI:
    """Drop-in replacement for openai.OpenAI with Snapper policy enforcement.

    Args:
        snapper_url: Snapper server URL.
        snapper_api_key: Snapper API key.
        agent_id: Agent ID registered with Snapper.
        on_deny: "raise" (default) to raise SnapperDenied, or "filter" to silently remove denied calls.
        snapper_fail_mode: "closed" (default) or "open".
        **openai_kwargs: Passed to openai.OpenAI().
    """

    def __init__(
        self,
        snapper_url: Optional[str] = None,
        snapper_api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        on_deny: str = "raise",
        snapper_fail_mode: str = "closed",
        **openai_kwargs,
    ):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package required. Install with: pip install snapper-sdk[openai]"
            )

        self._snapper = SnapperClient(
            snapper_url=snapper_url,
            snapper_api_key=snapper_api_key,
            agent_id=agent_id,
            fail_mode=snapper_fail_mode,
        )
        self._openai = OpenAI(**openai_kwargs)
        self._on_deny = on_deny
        self.chat = _SnapperChat(self._openai.chat, self._snapper, on_deny)

    def close(self):
        self._snapper.close()
        self._openai.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getattr__(self, name):
        if name == "chat":
            return self.chat
        return getattr(self._openai, name)
