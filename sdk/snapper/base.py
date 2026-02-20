"""Core Snapper client for evaluating tool calls against policy."""

import os
import time
from typing import Any, Dict, Optional

import httpx


class SnapperDenied(Exception):
    """Raised when Snapper denies a tool call."""

    def __init__(self, reason: str, rule_name: Optional[str] = None):
        self.reason = reason
        self.rule_name = rule_name
        super().__init__(f"Snapper denied: {reason}" + (f" (rule: {rule_name})" if rule_name else ""))


class SnapperApprovalTimeout(Exception):
    """Raised when an approval request times out."""

    def __init__(self, approval_id: str, timeout: int):
        self.approval_id = approval_id
        self.timeout = timeout
        super().__init__(f"Approval {approval_id[:8]}... timed out after {timeout}s")


class SnapperClient:
    """Synchronous Snapper client for evaluating tool calls.

    Args:
        snapper_url: Base URL of the Snapper server.
        snapper_api_key: API key for authentication.
        agent_id: Agent identifier registered with Snapper.
        fail_mode: "closed" (default, deny on error) or "open" (allow on error).
        timeout: HTTP request timeout in seconds.
        approval_timeout: Max seconds to wait for human approval.
    """

    def __init__(
        self,
        snapper_url: Optional[str] = None,
        snapper_api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        fail_mode: str = "closed",
        timeout: float = 30.0,
        approval_timeout: int = 300,
    ):
        self.snapper_url = (snapper_url or os.environ.get("SNAPPER_URL", "")).rstrip("/")
        self.snapper_api_key = snapper_api_key or os.environ.get("SNAPPER_API_KEY", "")
        self.agent_id = agent_id or os.environ.get("SNAPPER_AGENT_ID", "")
        self.fail_mode = fail_mode
        self.approval_timeout = approval_timeout

        if not self.snapper_url:
            raise ValueError("snapper_url is required (or set SNAPPER_URL env var)")

        self._client = httpx.Client(
            base_url=self.snapper_url,
            timeout=timeout,
            verify=False,
        )

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.snapper_api_key:
            headers["X-API-Key"] = self.snapper_api_key
        return headers

    def evaluate(
        self,
        tool_name: str,
        tool_input: Any,
        command: Optional[str] = None,
        request_type: str = "tool",
    ) -> Dict[str, Any]:
        """Evaluate a tool call against Snapper policy.

        Returns the full response dict on allow.
        Raises SnapperDenied on deny.
        Raises SnapperApprovalTimeout if approval times out.
        """
        payload = {
            "agent_id": self.agent_id,
            "request_type": request_type,
            "tool_name": tool_name,
            "tool_input": tool_input if isinstance(tool_input, dict) else {"value": tool_input},
        }
        if command:
            payload["command"] = command

        try:
            resp = self._client.post(
                "/api/v1/rules/evaluate",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            if self.fail_mode == "open":
                return {"decision": "allow", "reason": f"Snapper unreachable (fail-open): {e}"}
            raise SnapperDenied(reason=f"Snapper unreachable (fail-closed): {e}")

        decision = data.get("decision", "deny")

        if decision == "allow":
            return data

        if decision == "deny":
            raise SnapperDenied(
                reason=data.get("reason", "Denied by policy"),
                rule_name=data.get("matched_rule_name"),
            )

        if decision == "require_approval":
            approval_id = data.get("approval_request_id")
            if not approval_id:
                raise SnapperDenied(reason="Approval required but no request ID returned")
            return self._poll_approval(approval_id)

        raise SnapperDenied(reason=f"Unknown decision: {decision}")

    def _poll_approval(self, approval_id: str) -> Dict[str, Any]:
        """Poll for approval status until resolved or timeout."""
        start = time.monotonic()

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= self.approval_timeout:
                raise SnapperApprovalTimeout(approval_id, self.approval_timeout)

            try:
                resp = self._client.get(
                    f"/api/v1/approvals/{approval_id}/status",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                status_data = resp.json()
            except httpx.HTTPError:
                time.sleep(5)
                continue

            status = status_data.get("status", "pending")

            if status == "approved":
                return status_data

            if status == "denied":
                raise SnapperDenied(
                    reason=status_data.get("reason", "Approval denied"),
                )

            if status == "expired":
                raise SnapperApprovalTimeout(approval_id, self.approval_timeout)

            wait = min(status_data.get("wait_seconds", 5), 10)
            time.sleep(wait)


class AsyncSnapperClient:
    """Async Snapper client for evaluating tool calls.

    Same interface as SnapperClient but uses httpx.AsyncClient.
    """

    def __init__(
        self,
        snapper_url: Optional[str] = None,
        snapper_api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        fail_mode: str = "closed",
        timeout: float = 30.0,
        approval_timeout: int = 300,
    ):
        self.snapper_url = (snapper_url or os.environ.get("SNAPPER_URL", "")).rstrip("/")
        self.snapper_api_key = snapper_api_key or os.environ.get("SNAPPER_API_KEY", "")
        self.agent_id = agent_id or os.environ.get("SNAPPER_AGENT_ID", "")
        self.fail_mode = fail_mode
        self.approval_timeout = approval_timeout

        if not self.snapper_url:
            raise ValueError("snapper_url is required (or set SNAPPER_URL env var)")

        self._client = httpx.AsyncClient(
            base_url=self.snapper_url,
            timeout=timeout,
            verify=False,
        )

    async def close(self):
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.snapper_api_key:
            headers["X-API-Key"] = self.snapper_api_key
        return headers

    async def evaluate(
        self,
        tool_name: str,
        tool_input: Any,
        command: Optional[str] = None,
        request_type: str = "tool",
    ) -> Dict[str, Any]:
        """Evaluate a tool call against Snapper policy (async)."""
        payload = {
            "agent_id": self.agent_id,
            "request_type": request_type,
            "tool_name": tool_name,
            "tool_input": tool_input if isinstance(tool_input, dict) else {"value": tool_input},
        }
        if command:
            payload["command"] = command

        try:
            resp = await self._client.post(
                "/api/v1/rules/evaluate",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            if self.fail_mode == "open":
                return {"decision": "allow", "reason": f"Snapper unreachable (fail-open): {e}"}
            raise SnapperDenied(reason=f"Snapper unreachable (fail-closed): {e}")

        decision = data.get("decision", "deny")

        if decision == "allow":
            return data

        if decision == "deny":
            raise SnapperDenied(
                reason=data.get("reason", "Denied by policy"),
                rule_name=data.get("matched_rule_name"),
            )

        if decision == "require_approval":
            approval_id = data.get("approval_request_id")
            if not approval_id:
                raise SnapperDenied(reason="Approval required but no request ID returned")
            return await self._poll_approval(approval_id)

        raise SnapperDenied(reason=f"Unknown decision: {decision}")

    async def _poll_approval(self, approval_id: str) -> Dict[str, Any]:
        """Poll for approval status until resolved or timeout (async)."""
        import asyncio

        start = time.monotonic()

        while True:
            elapsed = time.monotonic() - start
            if elapsed >= self.approval_timeout:
                raise SnapperApprovalTimeout(approval_id, self.approval_timeout)

            try:
                resp = await self._client.get(
                    f"/api/v1/approvals/{approval_id}/status",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                status_data = resp.json()
            except httpx.HTTPError:
                await asyncio.sleep(5)
                continue

            status = status_data.get("status", "pending")

            if status == "approved":
                return status_data

            if status == "denied":
                raise SnapperDenied(
                    reason=status_data.get("reason", "Approval denied"),
                )

            if status == "expired":
                raise SnapperApprovalTimeout(approval_id, self.approval_timeout)

            wait = min(status_data.get("wait_seconds", 5), 10)
            await asyncio.sleep(wait)
