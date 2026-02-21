"""Tests for shadow AI detection service and API."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.shadow_ai import ShadowAIDetection, ShadowAIStatus
from app.services.shadow_ai_detector import (
    AI_CONTAINER_IMAGES,
    AI_PROCESS_SIGNATURES,
    KNOWN_AI_DOMAINS,
    run_full_scan,
    scan_containers,
    scan_network_connections,
    scan_processes,
)


# ---------------------------------------------------------------------------
# Network scan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_network_scan_detects_ai_connections():
    """Network scan finds connections to known AI API domains."""
    fake_ss_output = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n"
        'ESTAB  0      0      10.0.0.5:44322     104.18.6.192:443   users:(("python3",pid=1234,fd=5))\n'
    )

    with patch("app.services.shadow_ai_detector._resolve_domain") as mock_resolve, \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_resolve.return_value = ["104.18.6.192"]

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(fake_ss_output.encode(), b"")
        )
        mock_exec.return_value = mock_proc

        findings = await scan_network_connections()

    assert len(findings) >= 1
    assert findings[0]["detection_type"] == "network"
    assert "104.18.6.192" in findings[0]["destination"]


@pytest.mark.asyncio
async def test_network_scan_no_matches():
    """Network scan returns empty when no AI connections found."""
    fake_ss_output = (
        "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port  Process\n"
        "ESTAB  0      0      10.0.0.5:44322     8.8.8.8:443\n"
    )

    with patch("app.services.shadow_ai_detector._resolve_domain") as mock_resolve, \
         patch("asyncio.create_subprocess_exec") as mock_exec:

        mock_resolve.return_value = ["1.2.3.4"]

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(fake_ss_output.encode(), b"")
        )
        mock_exec.return_value = mock_proc

        findings = await scan_network_connections()

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Process scan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_scan_detects_ai_processes():
    """Process scan finds known AI tool processes."""
    fake_ps_output = (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root      5678  2.0  3.0 123456 78900 ?        Sl   10:00   1:00 /usr/bin/ollama serve\n"
        "john      9012  0.5  1.0  54321 12345 ?        S    10:05   0:30 python3 /home/john/app.py\n"
    )

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(fake_ps_output.encode(), b"")
        )
        mock_exec.return_value = mock_proc

        findings = await scan_processes()

    assert len(findings) == 1
    assert findings[0]["detection_type"] == "process"
    assert findings[0]["process_name"] == "ollama"
    assert findings[0]["pid"] == 5678


@pytest.mark.asyncio
async def test_process_scan_skips_grep_and_self():
    """Process scan ignores grep and shadow_ai scanner entries."""
    fake_ps_output = (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root      1111  0.1  0.1  10000  5000 ?        S    10:00   0:00 grep ollama\n"
        "root      2222  0.1  0.1  10000  5000 ?        S    10:00   0:00 python3 shadow_ai_scan.py\n"
    )

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(fake_ps_output.encode(), b"")
        )
        mock_exec.return_value = mock_proc

        findings = await scan_processes()

    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Container scan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_container_scan_detects_ai_images():
    """Container scan (CLI fallback) detects known AI container images."""
    fake_docker_output = (
        "abc123456789\tollama/ollama:latest\tmy-ollama\tUp 2 hours\n"
        "def456789012\tnginx:latest\tproxy\tUp 2 hours\n"
    )

    with patch("asyncio.create_subprocess_exec") as mock_exec:
        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(
            return_value=(fake_docker_output.encode(), b"")
        )
        mock_exec.return_value = mock_proc

        # Force CLI fallback by making aiohttp import fail
        with patch.dict("sys.modules", {"aiohttp": None}):
            findings = await scan_containers()

    assert len(findings) == 1
    assert findings[0]["detection_type"] == "container"
    assert findings[0]["container_image"] == "ollama/ollama:latest"
    assert findings[0]["container_id"] == "abc123456789"


# ---------------------------------------------------------------------------
# Full scan tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_scan_combines_results():
    """run_full_scan combines findings from all methods."""
    with patch("app.services.shadow_ai_detector.scan_network_connections") as mock_net, \
         patch("app.services.shadow_ai_detector.scan_processes") as mock_proc, \
         patch("app.services.shadow_ai_detector.scan_containers") as mock_cont:

        mock_net.return_value = [{"detection_type": "network", "destination": "api.openai.com:443"}]
        mock_proc.return_value = [{"detection_type": "process", "process_name": "ollama"}]
        mock_cont.return_value = []

        findings = await run_full_scan("test-host")

    assert len(findings) == 2
    assert all(f["host_identifier"] == "test-host" for f in findings)


@pytest.mark.asyncio
async def test_full_scan_handles_scanner_errors():
    """run_full_scan tolerates individual scanner failures."""
    with patch("app.services.shadow_ai_detector.scan_network_connections") as mock_net, \
         patch("app.services.shadow_ai_detector.scan_processes") as mock_proc, \
         patch("app.services.shadow_ai_detector.scan_containers") as mock_cont:

        mock_net.side_effect = RuntimeError("ss not found")
        mock_proc.return_value = [{"detection_type": "process", "process_name": "vllm"}]
        mock_cont.return_value = []

        findings = await run_full_scan("test-host")

    assert len(findings) == 1
    assert findings[0]["process_name"] == "vllm"


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


def test_scan_disabled_by_default():
    """SHADOW_AI_DETECTION_ENABLED defaults to False."""
    from app.config import get_settings
    s = get_settings()
    assert s.SHADOW_AI_DETECTION_ENABLED is False


def test_known_ai_domains_populated():
    """Built-in AI domain list is non-empty."""
    assert len(KNOWN_AI_DOMAINS) >= 10


def test_known_ai_processes_populated():
    """Built-in AI process signature list is non-empty."""
    assert len(AI_PROCESS_SIGNATURES) >= 10


def test_known_ai_images_populated():
    """Built-in AI container image list is non-empty."""
    assert len(AI_CONTAINER_IMAGES) >= 10
