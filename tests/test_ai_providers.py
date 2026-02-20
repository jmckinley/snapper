"""Tests for AI provider SDK wrappers (OpenAI, Anthropic, Gemini).

All tests use unittest.mock — no real API calls or provider SDKs required.
"""

import os
import sys

# Add the sdk/ directory to sys.path so `import snapper` resolves to sdk/snapper/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

import json
from unittest.mock import MagicMock, Mock, patch, PropertyMock

import pytest

# We test the SDK by mocking the provider libraries


# ============================================================================
# Base Client Tests
# ============================================================================


class TestSnapperBase:
    """Test the core SnapperClient."""

    def test_evaluate_payload_format(self):
        """Evaluate sends correct payload to Snapper."""
        from snapper.base import SnapperClient

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "decision": "allow",
                "reason": "Allowed by policy",
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            client = SnapperClient(
                snapper_url="http://localhost:8000",
                snapper_api_key="snp_test",
                agent_id="test-agent",
            )

            result = client.evaluate(
                tool_name="get_weather",
                tool_input={"city": "NYC"},
            )

            call_args = mock_client.post.call_args
            payload = call_args.kwargs["json"]
            assert payload["agent_id"] == "test-agent"
            assert payload["tool_name"] == "get_weather"
            assert payload["tool_input"] == {"city": "NYC"}
            assert payload["request_type"] == "tool"
            assert result["decision"] == "allow"

    def test_evaluate_deny_raises(self):
        """Denied tool calls raise SnapperDenied."""
        from snapper.base import SnapperClient, SnapperDenied

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "decision": "deny",
                "reason": "Blocked by denylist",
                "matched_rule_name": "block-dangerous",
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            client = SnapperClient(
                snapper_url="http://localhost:8000",
                agent_id="test-agent",
            )

            with pytest.raises(SnapperDenied) as exc_info:
                client.evaluate(tool_name="rm", tool_input={"path": "/"})

            assert "Blocked by denylist" in str(exc_info.value)
            assert exc_info.value.rule_name == "block-dangerous"

    def test_evaluate_allow_returns_data(self):
        """Allowed tool calls return the full response."""
        from snapper.base import SnapperClient

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "decision": "allow",
                "reason": "OK",
                "resolved_data": {"token1": "secret"},
            }
            mock_response.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            client = SnapperClient(
                snapper_url="http://localhost:8000",
                agent_id="test-agent",
            )

            result = client.evaluate(tool_name="read", tool_input={"file": "a.txt"})
            assert result["decision"] == "allow"
            assert result["resolved_data"] == {"token1": "secret"}

    def test_fail_closed_on_connection_error(self):
        """Fail-closed mode raises SnapperDenied on connection failure."""
        import httpx
        from snapper.base import SnapperClient, SnapperDenied

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            client = SnapperClient(
                snapper_url="http://localhost:8000",
                agent_id="test-agent",
                fail_mode="closed",
            )

            with pytest.raises(SnapperDenied, match="unreachable"):
                client.evaluate(tool_name="test", tool_input={})

    def test_fail_open_on_connection_error(self):
        """Fail-open mode returns allow on connection failure."""
        import httpx
        from snapper.base import SnapperClient

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            client = SnapperClient(
                snapper_url="http://localhost:8000",
                agent_id="test-agent",
                fail_mode="open",
            )

            result = client.evaluate(tool_name="test", tool_input={})
            assert result["decision"] == "allow"


# ============================================================================
# OpenAI Wrapper Tests
# ============================================================================


class TestOpenAIWrapper:
    """Test SnapperOpenAI wrapper."""

    def _make_tool_call(self, name="get_weather", arguments='{"city": "NYC"}'):
        tc = MagicMock()
        tc.function = MagicMock()
        tc.function.name = name
        tc.function.arguments = arguments
        return tc

    def _make_response(self, tool_calls=None, finish_reason="tool_calls"):
        response = MagicMock()
        choice = MagicMock()
        choice.message = MagicMock()
        choice.message.tool_calls = tool_calls
        choice.finish_reason = finish_reason
        response.choices = [choice]
        return response

    @patch("snapper.base.SnapperClient")
    def test_function_call_intercept(self, mock_snapper_cls):
        """Tool calls are sent to Snapper for evaluation."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.openai_wrapper import _SnapperCompletions

        tc = self._make_tool_call()
        response = self._make_response(tool_calls=[tc])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")
        result = completions.create(model="gpt-4", messages=[])

        mock_snapper.evaluate.assert_called_once_with(
            tool_name="get_weather",
            tool_input={"city": "NYC"},
        )
        assert result.choices[0].message.tool_calls == [tc]

    @patch("snapper.base.SnapperClient")
    def test_allow_passes_through(self, mock_snapper_cls):
        """Allowed tool calls pass through unchanged."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.openai_wrapper import _SnapperCompletions

        tc = self._make_tool_call()
        response = self._make_response(tool_calls=[tc])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")
        result = completions.create(model="gpt-4", messages=[])

        assert len(result.choices[0].message.tool_calls) == 1

    @patch("snapper.base.SnapperClient")
    def test_deny_raises(self, mock_snapper_cls):
        """Denied tool calls raise SnapperDenied in raise mode."""
        from snapper.base import SnapperDenied
        from snapper.openai_wrapper import _SnapperCompletions

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        tc = self._make_tool_call(name="dangerous_tool")
        response = self._make_response(tool_calls=[tc])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")

        with pytest.raises(SnapperDenied):
            completions.create(model="gpt-4", messages=[])

    @patch("snapper.base.SnapperClient")
    def test_deny_filter_mode(self, mock_snapper_cls):
        """Denied tool calls are silently removed in filter mode."""
        from snapper.base import SnapperDenied
        from snapper.openai_wrapper import _SnapperCompletions

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        tc = self._make_tool_call(name="dangerous_tool")
        response = self._make_response(tool_calls=[tc])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "filter")
        result = completions.create(model="gpt-4", messages=[])

        assert result.choices[0].message.tool_calls is None
        assert result.choices[0].finish_reason == "stop"

    @patch("snapper.base.SnapperClient")
    def test_partial_deny(self, mock_snapper_cls):
        """Only denied tool calls are removed; allowed ones remain."""
        from snapper.base import SnapperDenied
        from snapper.openai_wrapper import _SnapperCompletions

        mock_snapper = MagicMock()
        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if kwargs["tool_name"] == "dangerous":
                raise SnapperDenied("blocked")
            return {"decision": "allow"}

        mock_snapper.evaluate.side_effect = side_effect
        mock_snapper_cls.return_value = mock_snapper

        tc_safe = self._make_tool_call(name="safe_tool")
        tc_dangerous = self._make_tool_call(name="dangerous")
        response = self._make_response(tool_calls=[tc_safe, tc_dangerous])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "filter")
        result = completions.create(model="gpt-4", messages=[])

        assert len(result.choices[0].message.tool_calls) == 1
        assert result.choices[0].message.tool_calls[0].function.name == "safe_tool"

    @patch("snapper.base.SnapperClient")
    def test_no_tool_calls_passthrough(self, mock_snapper_cls):
        """Responses without tool calls pass through without evaluation."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.openai_wrapper import _SnapperCompletions

        response = self._make_response(tool_calls=None, finish_reason="stop")

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")
        result = completions.create(model="gpt-4", messages=[])

        mock_snapper.evaluate.assert_not_called()
        assert result.choices[0].finish_reason == "stop"

    @patch("snapper.base.SnapperClient")
    def test_invalid_json_arguments(self, mock_snapper_cls):
        """Handles malformed JSON in function arguments."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.openai_wrapper import _SnapperCompletions

        tc = self._make_tool_call(name="test", arguments="not valid json")
        response = self._make_response(tool_calls=[tc])

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")
        result = completions.create(model="gpt-4", messages=[])

        # Should still call evaluate with raw arguments
        mock_snapper.evaluate.assert_called_once()
        call_args = mock_snapper.evaluate.call_args
        assert "raw" in call_args.kwargs["tool_input"]

    @patch("snapper.base.SnapperClient")
    def test_empty_choices(self, mock_snapper_cls):
        """Handles response with empty choices."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.openai_wrapper import _SnapperCompletions

        response = MagicMock()
        response.choices = []

        original = MagicMock()
        original.create.return_value = response

        completions = _SnapperCompletions(original, mock_snapper, "raise")
        result = completions.create(model="gpt-4", messages=[])

        mock_snapper.evaluate.assert_not_called()


# ============================================================================
# Anthropic Wrapper Tests
# ============================================================================


class TestAnthropicWrapper:
    """Test SnapperAnthropic wrapper."""

    def _make_tool_use_block(self, name="get_weather", input_data=None):
        block = MagicMock()
        block.type = "tool_use"
        block.name = name
        block.input = input_data or {"city": "NYC"}
        return block

    def _make_text_block(self, text="Hello"):
        block = MagicMock()
        block.type = "text"
        block.text = text
        return block

    def _make_response(self, content=None, stop_reason="tool_use"):
        response = MagicMock()
        response.content = content or []
        response.stop_reason = stop_reason
        return response

    @patch("snapper.base.SnapperClient")
    def test_tool_use_intercept(self, mock_snapper_cls):
        """tool_use blocks are sent to Snapper for evaluation."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.anthropic_wrapper import _SnapperMessages

        block = self._make_tool_use_block()
        response = self._make_response(content=[block])

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "raise")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        mock_snapper.evaluate.assert_called_once_with(
            tool_name="get_weather",
            tool_input={"city": "NYC"},
        )

    @patch("snapper.base.SnapperClient")
    def test_allow_passes_through(self, mock_snapper_cls):
        """Allowed tool_use blocks remain in response."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.anthropic_wrapper import _SnapperMessages

        text = self._make_text_block()
        tool = self._make_tool_use_block()
        response = self._make_response(content=[text, tool])

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "raise")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        assert len(result.content) == 2

    @patch("snapper.base.SnapperClient")
    def test_deny_raises(self, mock_snapper_cls):
        """Denied tool_use raises SnapperDenied in raise mode."""
        from snapper.base import SnapperDenied
        from snapper.anthropic_wrapper import _SnapperMessages

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        block = self._make_tool_use_block(name="dangerous")
        response = self._make_response(content=[block])

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "raise")

        with pytest.raises(SnapperDenied):
            messages.create(model="claude-sonnet-4-5-20250929", messages=[])

    @patch("snapper.base.SnapperClient")
    def test_deny_filter_mode(self, mock_snapper_cls):
        """Denied tool_use blocks removed in filter mode."""
        from snapper.base import SnapperDenied
        from snapper.anthropic_wrapper import _SnapperMessages

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        block = self._make_tool_use_block(name="dangerous")
        response = self._make_response(content=[block])

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "filter")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        assert len(result.content) == 0
        assert result.stop_reason == "end_turn"

    @patch("snapper.base.SnapperClient")
    def test_partial_deny(self, mock_snapper_cls):
        """Only denied tool_use blocks are removed."""
        from snapper.base import SnapperDenied
        from snapper.anthropic_wrapper import _SnapperMessages

        mock_snapper = MagicMock()

        def side_effect(**kwargs):
            if kwargs["tool_name"] == "dangerous":
                raise SnapperDenied("blocked")
            return {"decision": "allow"}

        mock_snapper.evaluate.side_effect = side_effect
        mock_snapper_cls.return_value = mock_snapper

        text = self._make_text_block()
        safe = self._make_tool_use_block(name="safe")
        dangerous = self._make_tool_use_block(name="dangerous")
        response = self._make_response(content=[text, safe, dangerous])

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "filter")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        assert len(result.content) == 2  # text + safe tool

    @patch("snapper.base.SnapperClient")
    def test_no_tool_use_passthrough(self, mock_snapper_cls):
        """Responses without tool_use pass through without evaluation."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.anthropic_wrapper import _SnapperMessages

        text = self._make_text_block()
        response = self._make_response(content=[text], stop_reason="end_turn")

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "raise")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        mock_snapper.evaluate.assert_not_called()

    @patch("snapper.base.SnapperClient")
    def test_empty_content(self, mock_snapper_cls):
        """Handles response with no content."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.anthropic_wrapper import _SnapperMessages

        response = self._make_response(content=None)

        original = MagicMock()
        original.create.return_value = response

        messages = _SnapperMessages(original, mock_snapper, "raise")
        result = messages.create(model="claude-sonnet-4-5-20250929", messages=[])

        mock_snapper.evaluate.assert_not_called()


# ============================================================================
# Gemini Wrapper Tests
# ============================================================================


class TestGeminiWrapper:
    """Test SnapperGemini wrapper."""

    def _make_function_call(self, name="get_weather", args=None):
        fc = MagicMock()
        fc.name = name
        fc.args = args or {"city": "NYC"}
        return fc

    def _make_part(self, function_call=None, text=None):
        part = MagicMock()
        if function_call:
            part.function_call = function_call
        else:
            part.function_call = None
        if text:
            part.text = text
        return part

    def _make_response(self, parts=None):
        response = MagicMock()
        candidate = MagicMock()
        content = MagicMock()
        content.parts = parts or []
        candidate.content = content
        response.candidates = [candidate]
        return response

    @patch("snapper.base.SnapperClient")
    def test_function_call_intercept(self, mock_snapper_cls):
        """function_call parts are sent to Snapper for evaluation."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.gemini_wrapper import SnapperGemini

        fc = self._make_function_call()
        part = self._make_part(function_call=fc)
        response = self._make_response(parts=[part])

        mock_model = MagicMock()
        mock_model.generate_content.return_value = response

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = mock_model
        model._on_deny = "raise"

        result = model.generate_content("test")

        mock_snapper.evaluate.assert_called_once_with(
            tool_name="get_weather",
            tool_input={"city": "NYC"},
        )

    @patch("snapper.base.SnapperClient")
    def test_allow_passes_through(self, mock_snapper_cls):
        """Allowed function calls pass through unchanged."""
        mock_snapper = MagicMock()
        mock_snapper.evaluate.return_value = {"decision": "allow"}
        mock_snapper_cls.return_value = mock_snapper

        from snapper.gemini_wrapper import SnapperGemini

        fc = self._make_function_call()
        part = self._make_part(function_call=fc)
        response = self._make_response(parts=[part])

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "raise"

        result = model.generate_content("test")
        assert len(result.candidates[0].content.parts) == 1

    @patch("snapper.base.SnapperClient")
    def test_deny_raises(self, mock_snapper_cls):
        """Denied function calls raise SnapperDenied."""
        from snapper.base import SnapperDenied
        from snapper.gemini_wrapper import SnapperGemini

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        fc = self._make_function_call(name="dangerous")
        part = self._make_part(function_call=fc)
        response = self._make_response(parts=[part])

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "raise"

        with pytest.raises(SnapperDenied):
            model.generate_content("test")

    @patch("snapper.base.SnapperClient")
    def test_deny_filter_mode(self, mock_snapper_cls):
        """Denied function calls removed in filter mode."""
        from snapper.base import SnapperDenied
        from snapper.gemini_wrapper import SnapperGemini

        mock_snapper = MagicMock()
        mock_snapper.evaluate.side_effect = SnapperDenied("blocked")
        mock_snapper_cls.return_value = mock_snapper

        fc = self._make_function_call(name="dangerous")
        part = self._make_part(function_call=fc)
        response = self._make_response(parts=[part])

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "filter"

        result = model.generate_content("test")
        assert len(result.candidates[0].content.parts) == 0

    @patch("snapper.base.SnapperClient")
    def test_partial_deny(self, mock_snapper_cls):
        """Only denied function calls are removed."""
        from snapper.base import SnapperDenied
        from snapper.gemini_wrapper import SnapperGemini

        mock_snapper = MagicMock()

        def side_effect(**kwargs):
            if kwargs["tool_name"] == "dangerous":
                raise SnapperDenied("blocked")
            return {"decision": "allow"}

        mock_snapper.evaluate.side_effect = side_effect
        mock_snapper_cls.return_value = mock_snapper

        safe_fc = self._make_function_call(name="safe")
        safe_part = self._make_part(function_call=safe_fc)
        dangerous_fc = self._make_function_call(name="dangerous")
        dangerous_part = self._make_part(function_call=dangerous_fc)
        text_part = self._make_part(text="Hello")
        response = self._make_response(parts=[text_part, safe_part, dangerous_part])

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "filter"

        result = model.generate_content("test")
        assert len(result.candidates[0].content.parts) == 2  # text + safe

    @patch("snapper.base.SnapperClient")
    def test_no_function_calls_passthrough(self, mock_snapper_cls):
        """Responses without function calls pass through."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.gemini_wrapper import SnapperGemini

        text_part = self._make_part(text="Hello world")
        response = self._make_response(parts=[text_part])

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "raise"

        result = model.generate_content("test")
        mock_snapper.evaluate.assert_not_called()

    @patch("snapper.base.SnapperClient")
    def test_empty_candidates(self, mock_snapper_cls):
        """Handles response with no candidates."""
        mock_snapper = MagicMock()
        mock_snapper_cls.return_value = mock_snapper

        from snapper.gemini_wrapper import SnapperGemini

        response = MagicMock()
        response.candidates = []

        model = SnapperGemini.__new__(SnapperGemini)
        model._snapper = mock_snapper
        model._model = MagicMock()
        model._model.generate_content.return_value = response
        model._on_deny = "raise"

        result = model.generate_content("test")
        mock_snapper.evaluate.assert_not_called()


# ============================================================================
# Configuration Tests
# ============================================================================


class TestWrapperConfig:
    """Test wrapper configuration and error handling."""

    def test_missing_url_raises(self):
        """Missing Snapper URL raises ValueError."""
        from snapper.base import SnapperClient

        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="snapper_url is required"):
                SnapperClient(agent_id="test")

    def test_custom_timeout(self):
        """Custom timeout is passed to httpx client."""
        from snapper.base import SnapperClient

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value = MagicMock()
            client = SnapperClient(
                snapper_url="http://localhost:8000",
                agent_id="test",
                timeout=60.0,
            )
            call_kwargs = mock_client_cls.call_args.kwargs
            assert call_kwargs["timeout"] == 60.0

    def test_env_var_fallback(self):
        """Client reads from environment variables."""
        from snapper.base import SnapperClient

        env = {
            "SNAPPER_URL": "http://env-host:8000",
            "SNAPPER_API_KEY": "snp_env_key",
            "SNAPPER_AGENT_ID": "env-agent",
        }
        with patch.dict("os.environ", env):
            with patch("httpx.Client") as mock_client_cls:
                mock_client_cls.return_value = MagicMock()
                client = SnapperClient()

                assert client.snapper_url == "http://env-host:8000"
                assert client.snapper_api_key == "snp_env_key"
                assert client.agent_id == "env-agent"
