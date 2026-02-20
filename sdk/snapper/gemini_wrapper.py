"""Snapper-protected wrapper for Google's Generative AI SDK (Gemini).

Usage:
    from snapper.gemini_wrapper import SnapperGemini

    model = SnapperGemini(
        model_name="gemini-pro",
        snapper_url="https://snapper.example.com",
        snapper_api_key="snp_xxx",
        agent_id="myapp-gemini",
    )
    response = model.generate_content("What's the weather?", tools=[...])
    # function_call parts are automatically evaluated against Snapper policy.
"""

from typing import Any, Optional

from snapper.base import SnapperClient, SnapperDenied


class SnapperGemini:
    """Drop-in replacement for google.generativeai.GenerativeModel with Snapper enforcement.

    Args:
        model_name: Gemini model name (e.g., "gemini-pro").
        snapper_url: Snapper server URL.
        snapper_api_key: Snapper API key.
        agent_id: Agent ID registered with Snapper.
        on_deny: "raise" (default) to raise SnapperDenied, or "filter" to silently remove denied calls.
        snapper_fail_mode: "closed" (default) or "open".
        **gemini_kwargs: Passed to GenerativeModel().
    """

    def __init__(
        self,
        model_name: str = "gemini-pro",
        snapper_url: Optional[str] = None,
        snapper_api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        on_deny: str = "raise",
        snapper_fail_mode: str = "closed",
        **gemini_kwargs,
    ):
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError(
                "google-generativeai package required. Install with: pip install snapper-sdk[gemini]"
            )

        self._snapper = SnapperClient(
            snapper_url=snapper_url,
            snapper_api_key=snapper_api_key,
            agent_id=agent_id,
            fail_mode=snapper_fail_mode,
        )
        self._model = genai.GenerativeModel(model_name, **gemini_kwargs)
        self._on_deny = on_deny

    def generate_content(self, *args, **kwargs) -> Any:
        """Intercept generate_content() and evaluate function_call parts."""
        stream = kwargs.get("stream", False)

        if stream:
            return self._generate_content_stream(*args, **kwargs)

        response = self._model.generate_content(*args, **kwargs)
        return self._process_response(response)

    def _generate_content_stream(self, *args, **kwargs):
        """Handle streaming responses."""
        kwargs["stream"] = True
        stream = self._model.generate_content(*args, **kwargs)
        chunks = list(stream)

        function_calls = self._extract_function_calls_from_chunks(chunks)
        for fc in function_calls:
            self._evaluate_function_call(fc)

        return iter(chunks)

    def _process_response(self, response) -> Any:
        """Evaluate function_call parts in a non-streaming response."""
        if not hasattr(response, "candidates") or not response.candidates:
            return response

        for candidate in response.candidates:
            if not hasattr(candidate, "content") or not candidate.content:
                continue
            if not hasattr(candidate.content, "parts") or not candidate.content.parts:
                continue

            denied_indices = []
            for i, part in enumerate(candidate.content.parts):
                if not hasattr(part, "function_call") or not part.function_call:
                    continue

                fc = part.function_call
                tool_name = fc.name
                tool_input = dict(fc.args) if hasattr(fc, "args") and fc.args else {}

                try:
                    self._snapper.evaluate(
                        tool_name=tool_name,
                        tool_input=tool_input,
                    )
                except SnapperDenied:
                    if self._on_deny == "raise":
                        raise
                    denied_indices.append(i)

            if denied_indices and self._on_deny == "filter":
                remaining = [
                    part for i, part in enumerate(candidate.content.parts)
                    if i not in denied_indices
                ]
                candidate.content.parts = remaining

        return response

    def _evaluate_function_call(self, fc_info: dict):
        """Evaluate a single function call."""
        try:
            self._snapper.evaluate(
                tool_name=fc_info["name"],
                tool_input=fc_info["args"],
            )
        except SnapperDenied:
            if self._on_deny == "raise":
                raise

    def _extract_function_calls_from_chunks(self, chunks) -> list:
        """Extract function calls from streaming chunks."""
        result = []
        for chunk in chunks:
            if not hasattr(chunk, "candidates") or not chunk.candidates:
                continue
            for candidate in chunk.candidates:
                if not hasattr(candidate, "content") or not candidate.content:
                    continue
                if not hasattr(candidate.content, "parts"):
                    continue
                for part in candidate.content.parts:
                    if hasattr(part, "function_call") and part.function_call:
                        fc = part.function_call
                        result.append({
                            "name": fc.name,
                            "args": dict(fc.args) if hasattr(fc, "args") and fc.args else {},
                        })
        return result

    def start_chat(self, **kwargs):
        """Return a wrapped chat session."""
        chat = self._model.start_chat(**kwargs)
        return _SnapperChatSession(chat, self._snapper, self._on_deny)

    def close(self):
        self._snapper.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __getattr__(self, name):
        return getattr(self._model, name)


class _SnapperChatSession:
    """Wraps a Gemini ChatSession to intercept function calls."""

    def __init__(self, chat, snapper: SnapperClient, on_deny: str):
        self._chat = chat
        self._snapper = snapper
        self._on_deny = on_deny

    def send_message(self, *args, **kwargs) -> Any:
        """Send a message and evaluate any function calls in the response."""
        response = self._chat.send_message(*args, **kwargs)

        if not hasattr(response, "candidates") or not response.candidates:
            return response

        for candidate in response.candidates:
            if not hasattr(candidate, "content") or not candidate.content:
                continue
            if not hasattr(candidate.content, "parts"):
                continue
            for part in candidate.content.parts:
                if hasattr(part, "function_call") and part.function_call:
                    fc = part.function_call
                    tool_name = fc.name
                    tool_input = dict(fc.args) if hasattr(fc, "args") and fc.args else {}
                    try:
                        self._snapper.evaluate(
                            tool_name=tool_name,
                            tool_input=tool_input,
                        )
                    except SnapperDenied:
                        if self._on_deny == "raise":
                            raise

        return response

    def __getattr__(self, name):
        return getattr(self._chat, name)
