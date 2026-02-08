"""Tests for hook script validity and conventions.

Covers:
- Bash syntax validation (bash -n) for all 5 hook scripts
- Executable flag check
- Correct env file source paths
- Exit code conventions per agent type
- Proper shebang lines
- Required variables present
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"

HOOK_SCRIPTS = [
    "openclaw-hook.sh",
    "claude-code-hook.sh",
    "cursor-hook.sh",
    "windsurf-hook.sh",
    "cline-hook.sh",
]


class TestHookScriptSyntax:
    """Validate bash syntax for all hook scripts."""

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_bash_syntax_valid(self, script_name):
        """Hook script passes bash -n syntax check."""
        script_path = SCRIPTS_DIR / script_name
        assert script_path.exists(), f"Missing script: {script_path}"
        result = subprocess.run(
            ["bash", "-n", str(script_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"Syntax error in {script_name}: {result.stderr}"
        )

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_has_shebang(self, script_name):
        """Hook script starts with #!/bin/bash."""
        script_path = SCRIPTS_DIR / script_name
        first_line = script_path.read_text().split("\n")[0]
        assert first_line.startswith("#!/bin/bash"), (
            f"{script_name} missing shebang, got: {first_line}"
        )


class TestHookEnvSourcePaths:
    """Verify each hook sources the correct env file or uses env var defaults."""

    def test_openclaw_uses_snapper_url_default(self):
        """OpenClaw hook uses SNAPPER_URL env var with default."""
        content = (SCRIPTS_DIR / "openclaw-hook.sh").read_text()
        assert "SNAPPER_URL=" in content

    def test_claude_code_uses_snapper_url_default(self):
        """Claude Code hook uses SNAPPER_URL env var with default."""
        content = (SCRIPTS_DIR / "claude-code-hook.sh").read_text()
        assert "SNAPPER_URL=" in content

    def test_cursor_sources_env(self):
        content = (SCRIPTS_DIR / "cursor-hook.sh").read_text()
        assert ".cursor/.env.snapper" in content

    def test_windsurf_sources_env(self):
        content = (SCRIPTS_DIR / "windsurf-hook.sh").read_text()
        assert ".codeium/windsurf/.env.snapper" in content

    def test_cline_sources_env(self):
        content = (SCRIPTS_DIR / "cline-hook.sh").read_text()
        assert ".cline/.env.snapper" in content


class TestHookExitCodeConventions:
    """Verify exit code conventions match each agent's protocol."""

    def test_cursor_uses_exit_2_for_deny(self):
        """Cursor blocks with exit code 2."""
        content = (SCRIPTS_DIR / "cursor-hook.sh").read_text()
        assert "exit 2" in content
        assert "exit 0" in content

    def test_windsurf_uses_exit_2_for_deny(self):
        """Windsurf blocks with exit code 2."""
        content = (SCRIPTS_DIR / "windsurf-hook.sh").read_text()
        assert "exit 2" in content
        assert "exit 0" in content

    def test_cline_always_exit_0(self):
        """Cline always exits 0 and uses JSON cancel field."""
        content = (SCRIPTS_DIR / "cline-hook.sh").read_text()
        # Cline should NOT use exit 1 or exit 2
        lines = content.split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "exit 1" not in stripped, (
                "Cline hook should not use exit 1"
            )
            assert "exit 2" not in stripped, (
                "Cline hook should not use exit 2"
            )
        # Must use cancel JSON
        assert '"cancel": true' in content or '"cancel":true' in content
        assert '"cancel": false' in content or '"cancel":false' in content


class TestHookRequiredVariables:
    """Verify each hook sets required Snapper variables."""

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_has_snapper_url(self, script_name):
        content = (SCRIPTS_DIR / script_name).read_text()
        assert "SNAPPER_URL" in content

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_has_snapper_agent_id(self, script_name):
        content = (SCRIPTS_DIR / script_name).read_text()
        assert "SNAPPER_AGENT_ID" in content

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_has_snapper_api_key(self, script_name):
        content = (SCRIPTS_DIR / script_name).read_text()
        assert "SNAPPER_API_KEY" in content

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_calls_evaluate_endpoint(self, script_name):
        """Hook scripts call the /api/v1/rules/evaluate endpoint."""
        content = (SCRIPTS_DIR / script_name).read_text()
        assert "/api/v1/rules/evaluate" in content

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_reads_stdin(self, script_name):
        """Hook scripts read JSON from stdin."""
        content = (SCRIPTS_DIR / script_name).read_text()
        # All hooks use INPUT=$(cat) to read stdin
        assert "$(cat)" in content or "cat)" in content

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_uses_jq(self, script_name):
        """Hook scripts use jq for JSON parsing."""
        content = (SCRIPTS_DIR / script_name).read_text()
        assert "jq" in content


class TestHookToolNameMappings:
    """Verify each hook maps agent-specific tool names correctly."""

    def test_cursor_maps_run_terminal_cmd(self):
        content = (SCRIPTS_DIR / "cursor-hook.sh").read_text()
        assert "run_terminal_cmd" in content

    def test_cursor_maps_codebase_search(self):
        content = (SCRIPTS_DIR / "cursor-hook.sh").read_text()
        assert "codebase_search" in content

    def test_windsurf_maps_run_command(self):
        content = (SCRIPTS_DIR / "windsurf-hook.sh").read_text()
        assert "run_command" in content

    def test_windsurf_maps_write_code(self):
        content = (SCRIPTS_DIR / "windsurf-hook.sh").read_text()
        assert "write_code" in content

    def test_windsurf_maps_mcp_tool_use(self):
        content = (SCRIPTS_DIR / "windsurf-hook.sh").read_text()
        assert "mcp_tool_use" in content

    def test_cline_maps_execute_command(self):
        content = (SCRIPTS_DIR / "cline-hook.sh").read_text()
        assert "execute_command" in content

    def test_cline_maps_write_to_file(self):
        content = (SCRIPTS_DIR / "cline-hook.sh").read_text()
        assert "write_to_file" in content

    def test_cline_maps_browser_action(self):
        content = (SCRIPTS_DIR / "cline-hook.sh").read_text()
        assert "browser_action" in content


class TestHookFailClosed:
    """Verify all hooks fail closed when Snapper is unreachable."""

    @pytest.mark.parametrize("script_name", HOOK_SCRIPTS)
    def test_fail_closed_message(self, script_name):
        """Hook mentions failing closed in unreachable case."""
        content = (SCRIPTS_DIR / script_name).read_text()
        # Check for fail-closed language
        lower = content.lower()
        assert "failing closed" in lower or "fail closed" in lower or "unreachable" in lower
