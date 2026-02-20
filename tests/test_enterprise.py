"""Tests for enterprise features: SIEM, metrics, policy-as-code, SSO, SCIM, webhooks."""

import asyncio
import base64
import json
import socket
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# ============================================================================
# SIEM / Event Publisher Tests
# ============================================================================


class TestCEFFormatter:
    """Test CEF event formatting for SIEM integration."""

    def test_format_basic_cef(self):
        from app.services.event_publisher import format_cef

        cef = format_cef(
            action="request_denied",
            severity="warning",
            message="Agent blocked by denylist",
            agent_id="test-agent-123",
        )
        assert cef.startswith("CEF:0|Snapper|AAF|")
        assert "|103|Request Denied|5|" in cef
        assert "dvchost=test-agent-123" in cef
        assert "msg=Agent blocked by denylist" in cef

    def test_format_cef_with_all_fields(self):
        from app.services.event_publisher import format_cef

        ts = datetime(2026, 2, 16, 12, 0, 0, tzinfo=timezone.utc)
        cef = format_cef(
            action="request_allowed",
            severity="info",
            message="Request allowed",
            agent_id="agent-1",
            rule_id="rule-1",
            ip_address="192.168.1.1",
            user_id="user-1",
            request_id="req-123",
            details={"command": "ls -la", "decision": "allow"},
            timestamp=ts,
        )
        assert "src=192.168.1.1" in cef
        assert "duser=user-1" in cef
        assert "externalId=req-123" in cef
        assert "cs1=rule-1 cs1Label=RuleID" in cef
        assert "Feb 16 2026 12:00:00" in cef

    def test_format_cef_unknown_action(self):
        from app.services.event_publisher import format_cef

        cef = format_cef(
            action="custom_action",
            severity="debug",
            message="Custom event",
        )
        assert "|999|custom_action|1|" in cef

    def test_cef_escaping(self):
        from app.services.event_publisher import _cef_escape

        assert _cef_escape("hello|world") == "hello\\|world"
        assert _cef_escape("key=value") == "key\\=value"
        assert _cef_escape("line1\nline2") == "line1\\nline2"

    def test_format_cef_severity_mapping(self):
        from app.services.event_publisher import format_cef

        cef_critical = format_cef(action="security_alert", severity="critical", message="test")
        assert "|10|" in cef_critical

        cef_debug = format_cef(action="rule_evaluated", severity="debug", message="test")
        assert "|1|" in cef_debug

    def test_format_cef_pii_event(self):
        """Test CEF formatting for PII vault events."""
        from app.services.event_publisher import format_cef

        cef = format_cef(
            action="pii_gate_triggered",
            severity="warning",
            message="PII detected in tool input",
            agent_id="agent-pii",
            details={"tool_name": "browser_navigate", "rule_type": "pii_gate"},
        )
        assert "|603|PII Gate Triggered|5|" in cef
        assert "dvchost=agent-pii" in cef
        assert "cs2=browser_navigate cs2Label=tool_name" in cef
        assert "cs3=pii_gate cs3Label=rule_type" in cef

    def test_format_cef_rate_limit_event(self):
        """Test CEF formatting for rate limit events."""
        from app.services.event_publisher import format_cef

        cef = format_cef(
            action="rate_limit_exceeded",
            severity="warning",
            message="Agent exceeded rate limit",
            agent_id="agent-fast",
            ip_address="10.0.0.1",
        )
        assert "|400|Rate Limit Exceeded|5|" in cef
        assert "src=10.0.0.1" in cef

    def test_cef_escaping_multiline(self):
        """Test CEF escaping handles multiline messages and backslashes."""
        from app.services.event_publisher import _cef_escape

        assert _cef_escape("line1\r\nline2") == "line1\\r\\nline2"
        assert _cef_escape("path\\to\\file") == "path\\\\to\\\\file"
        assert _cef_escape("a|b=c\nd") == "a\\|b\\=c\\nd"


class TestWebhookPayload:
    """Test webhook payload construction and signing."""

    def test_build_webhook_payload(self):
        from app.services.event_publisher import _build_webhook_payload

        payload = _build_webhook_payload(
            action="request_denied",
            severity="warning",
            message="Blocked",
            agent_id="agent-1",
            organization_id="org-1",
        )
        assert payload["event"] == "request_denied"
        assert payload["severity"] == "warning"
        assert payload["agent_id"] == "agent-1"
        assert payload["organization_id"] == "org-1"
        assert "timestamp" in payload

    def test_sign_payload(self):
        from app.services.event_publisher import _sign_payload

        sig = _sign_payload(b'{"test": true}', "secret123")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA256 hex digest

    def test_sign_payload_consistency(self):
        from app.services.event_publisher import _sign_payload

        sig1 = _sign_payload(b"same data", "same_secret")
        sig2 = _sign_payload(b"same data", "same_secret")
        assert sig1 == sig2

    def test_sign_payload_different_secret(self):
        from app.services.event_publisher import _sign_payload

        sig1 = _sign_payload(b"data", "secret1")
        sig2 = _sign_payload(b"data", "secret2")
        assert sig1 != sig2

    def test_build_webhook_payload_with_details(self):
        """Test webhook payload includes details dict."""
        from app.services.event_publisher import _build_webhook_payload

        payload = _build_webhook_payload(
            action="request_denied",
            severity="warning",
            message="Blocked",
            details={"command": "rm -rf /", "rule_name": "Block dangerous"},
        )
        assert payload["details"]["command"] == "rm -rf /"
        assert payload["details"]["rule_name"] == "Block dangerous"
        assert payload["source"] == "snapper"

    def test_build_webhook_payload_with_timestamp(self):
        """Test webhook payload uses provided timestamp."""
        from app.services.event_publisher import _build_webhook_payload

        ts = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        payload = _build_webhook_payload(
            action="rule_created",
            severity="info",
            message="Rule created",
            timestamp=ts,
        )
        assert payload["timestamp"] == ts.isoformat()

    def test_build_webhook_payload_minimal(self):
        """Test webhook payload with only required fields."""
        from app.services.event_publisher import _build_webhook_payload

        payload = _build_webhook_payload(
            action="system_startup",
            severity="info",
            message="System started",
        )
        assert payload["event"] == "system_startup"
        assert "agent_id" not in payload
        assert "organization_id" not in payload
        assert "details" not in payload


# ============================================================================
# Syslog Transport Tests
# ============================================================================


class TestSyslogTransport:
    """Test syslog message formatting and transport."""

    def test_syslog_rfc5424_header(self):
        """Test that syslog messages follow RFC 5424 format."""
        # The send_to_syslog function builds: <priority>1 <ISO timestamp> snapper snapper - - - <CEF>
        # Priority for local0.info = 16*8 + 6 = 134
        priority = 16 * 8 + 6
        assert priority == 134

    def test_syslog_severity_mapping_info(self):
        """Test CEF severity maps correctly for syslog."""
        from app.services.event_publisher import SEVERITY_MAP

        assert SEVERITY_MAP["info"] == 3
        assert SEVERITY_MAP["warning"] == 5
        assert SEVERITY_MAP["error"] == 7
        assert SEVERITY_MAP["critical"] == 10
        assert SEVERITY_MAP["debug"] == 1

    @pytest.mark.asyncio
    async def test_send_to_syslog_udp(self):
        """Test UDP syslog send (mocked)."""
        from app.services.event_publisher import send_to_syslog

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("socket.socket") as mock_socket_cls:
            settings = MagicMock()
            settings.SIEM_SYSLOG_HOST = "syslog.example.com"
            settings.SIEM_SYSLOG_PORT = 514
            settings.SIEM_SYSLOG_PROTOCOL = "udp"
            mock_settings.return_value = settings

            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock

            await send_to_syslog("CEF:0|Snapper|AAF|1.0|103|Request Denied|5|msg=test")

            mock_socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
            mock_sock.sendto.assert_called_once()
            sent_data, addr = mock_sock.sendto.call_args[0]
            assert b"<134>1" in sent_data
            assert b"snapper" in sent_data
            assert b"CEF:0" in sent_data
            assert addr == ("syslog.example.com", 514)
            mock_sock.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_to_syslog_tcp(self):
        """Test TCP syslog send (mocked)."""
        from app.services.event_publisher import send_to_syslog

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("asyncio.open_connection") as mock_open:
            settings = MagicMock()
            settings.SIEM_SYSLOG_HOST = "syslog.example.com"
            settings.SIEM_SYSLOG_PORT = 6514
            settings.SIEM_SYSLOG_PROTOCOL = "tcp"
            mock_settings.return_value = settings

            mock_writer = AsyncMock()
            mock_writer.write = MagicMock()
            mock_reader = AsyncMock()
            mock_open.return_value = (mock_reader, mock_writer)

            await send_to_syslog("CEF:0|test")

            mock_open.assert_called_once_with("syslog.example.com", 6514)
            mock_writer.write.assert_called_once()
            written = mock_writer.write.call_args[0][0]
            assert b"<134>1" in written
            assert b"CEF:0" in written
            assert written.endswith(b"\n")

    @pytest.mark.asyncio
    async def test_send_to_syslog_no_host_skips(self):
        """Test that syslog send is skipped when no host configured."""
        from app.services.event_publisher import send_to_syslog

        with patch("app.services.event_publisher.get_settings") as mock_settings:
            settings = MagicMock()
            settings.SIEM_SYSLOG_HOST = None
            mock_settings.return_value = settings

            # Should not raise
            await send_to_syslog("CEF:0|test")


# ============================================================================
# Prometheus Metrics Tests
# ============================================================================


class TestPrometheusMetrics:
    """Test Prometheus metrics recording and formatting."""

    def test_normalize_path(self):
        from app.middleware.metrics import _normalize_path

        assert _normalize_path("/api/v1/agents/550e8400-e29b-41d4-a716-446655440000") == "/api/v1/agents/{id}"
        assert _normalize_path("/api/v1/rules/123") == "/api/v1/rules/{id}"
        assert _normalize_path("/health") == "/health"

    def test_record_rule_evaluation(self):
        from app.middleware.metrics import record_rule_evaluation

        # Should not raise even if prometheus not available
        record_rule_evaluation("command", "allow", 5.0)

    def test_record_pii_operation(self):
        from app.middleware.metrics import record_pii_operation

        record_pii_operation("create")
        record_pii_operation("resolve")

    def test_record_approval_decision(self):
        from app.middleware.metrics import record_approval_decision

        record_approval_decision("approved", latency_seconds=45.0)
        record_approval_decision("denied")

    def test_set_active_agents(self):
        from app.middleware.metrics import set_active_agents

        set_active_agents(42)

    def test_metrics_response_format(self):
        """Test that get_metrics_response returns correct content type."""
        from app.middleware.metrics import get_metrics_response, PROMETHEUS_AVAILABLE

        response = get_metrics_response()
        if PROMETHEUS_AVAILABLE:
            assert "text/plain" in response.media_type
            assert "version=0.0.4" in response.media_type
        else:
            assert response.status_code == 501

    def test_normalize_path_multiple_uuids(self):
        """Test path normalization with multiple UUID segments."""
        from app.middleware.metrics import _normalize_path

        path = "/api/v1/agents/550e8400-e29b-41d4-a716-446655440000/rules/660e8400-e29b-41d4-a716-446655440001"
        assert _normalize_path(path) == "/api/v1/agents/{id}/rules/{id}"

    def test_record_siem_event(self):
        """Test SIEM event metric recording."""
        from app.middleware.metrics import record_siem_event

        # Should not raise
        record_siem_event("syslog", True)
        record_siem_event("webhook", False)

    def test_record_webhook_delivery(self):
        """Test webhook delivery metric recording."""
        from app.middleware.metrics import record_webhook_delivery

        record_webhook_delivery(True)
        record_webhook_delivery(False)


# ============================================================================
# Webhook Delivery Tests
# ============================================================================


class TestWebhookDelivery:
    """Test webhook delivery service."""

    def test_sign_and_verify(self):
        from app.services.webhook_delivery import sign_payload, verify_signature

        payload = b'{"event": "test"}'
        secret = "test_secret_key"

        sig = sign_payload(payload, secret)
        assert verify_signature(payload, f"sha256={sig}", secret)

    def test_verify_wrong_signature(self):
        from app.services.webhook_delivery import verify_signature

        assert not verify_signature(b"data", "sha256=wrong", "secret")

    @pytest.mark.asyncio
    async def test_deliver_webhook_failure(self):
        from app.services.webhook_delivery import deliver_webhook

        result = await deliver_webhook(
            url="http://localhost:1/nonexistent",
            payload={"test": True},
            timeout=1.0,
        )
        assert not result.success
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_deliver_webhook_success(self):
        """Test successful webhook delivery (mocked)."""
        from app.services.webhook_delivery import deliver_webhook

        with patch("app.services.webhook_delivery.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await deliver_webhook(
                url="https://hooks.example.com/webhook",
                payload={"event": "test", "message": "hello"},
                secret="test_secret",
                event_type="request_denied",
            )

            assert result.success
            assert result.status_code == 200

            # Verify HMAC header was sent
            call_kwargs = mock_client.post.call_args
            headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
            assert "X-Snapper-Signature" in headers
            assert headers["X-Snapper-Signature"].startswith("sha256=")
            assert headers["X-Snapper-Event"] == "request_denied"

    @pytest.mark.asyncio
    async def test_deliver_webhook_5xx_failure(self):
        """Test webhook delivery returns failure on 5xx status."""
        from app.services.webhook_delivery import deliver_webhook

        with patch("app.services.webhook_delivery.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 502
            mock_response.text = "Bad Gateway"

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await deliver_webhook(
                url="https://hooks.example.com/webhook",
                payload={"event": "test"},
            )

            assert not result.success
            assert result.status_code == 502

    @pytest.mark.asyncio
    async def test_deliver_webhook_timeout(self):
        """Test webhook delivery handles timeout."""
        import httpx
        from app.services.webhook_delivery import deliver_webhook

        with patch("app.services.webhook_delivery.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await deliver_webhook(
                url="https://hooks.example.com/webhook",
                payload={"event": "test"},
                timeout=1.0,
            )

            assert not result.success
            assert "timed out" in result.error.lower()

    def test_delivery_result_attributes(self):
        """Test WebhookDeliveryResult has correct attributes."""
        from app.services.webhook_delivery import WebhookDeliveryResult

        result = WebhookDeliveryResult(
            success=True,
            status_code=200,
            response_body="OK",
            attempt=1,
        )
        assert result.success is True
        assert result.status_code == 200
        assert result.response_body == "OK"
        assert result.attempt == 1
        assert result.timestamp is not None
        assert result.error is None

    def test_sign_payload_deterministic(self):
        """Test that sign_payload produces deterministic results."""
        from app.services.webhook_delivery import sign_payload

        sig1 = sign_payload(b'{"event": "test"}', "secret")
        sig2 = sign_payload(b'{"event": "test"}', "secret")
        assert sig1 == sig2
        assert len(sig1) == 64

    def test_verify_signature_missing_prefix(self):
        """Test that verify fails without sha256= prefix."""
        from app.services.webhook_delivery import sign_payload, verify_signature

        sig = sign_payload(b"data", "secret")
        # Without the sha256= prefix, it should not match
        assert not verify_signature(b"data", sig, "secret")


# ============================================================================
# OIDC Service Tests
# ============================================================================


class TestOIDCService:
    """Test OIDC configuration and utility functions."""

    def test_generate_state_and_nonce(self):
        from app.services.oidc import generate_state_and_nonce

        state, nonce = generate_state_and_nonce()
        assert len(state) > 20
        assert len(nonce) > 20
        assert state != nonce

    def test_decode_id_token_unverified(self):
        from app.services.oidc import decode_id_token_unverified

        header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            b'{"email":"user@example.com","name":"Test User","nonce":"abc123"}'
        ).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()

        token = f"{header}.{payload}.{sig}"
        claims = decode_id_token_unverified(token)
        assert claims["email"] == "user@example.com"
        assert claims["name"] == "Test User"
        assert claims["nonce"] == "abc123"

    def test_decode_invalid_jwt(self):
        from app.services.oidc import decode_id_token_unverified

        with pytest.raises(ValueError, match="Invalid JWT format"):
            decode_id_token_unverified("not.a.valid.jwt.too.many.parts")

    def test_is_oidc_configured_false(self):
        from app.services.oidc import is_oidc_configured

        org = MagicMock()
        org.settings = {}
        assert not is_oidc_configured(org)

    def test_is_oidc_configured_true(self):
        from app.services.oidc import is_oidc_configured

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "client123",
            "oidc_client_secret": "secret456",
        }
        assert is_oidc_configured(org)

    def test_get_oidc_config(self):
        from app.services.oidc import get_oidc_config

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "client123",
            "oidc_client_secret": "secret456",
            "oidc_scopes": "openid email",
            "oidc_provider": "okta",
        }

        config = get_oidc_config(org)
        assert config["issuer"] == "https://auth.example.com"
        assert config["client_id"] == "client123"
        assert config["scopes"] == "openid email"
        assert config["provider"] == "okta"

    @pytest.mark.asyncio
    async def test_discover_oidc_endpoints(self):
        """Test OIDC discovery document parsing (mocked)."""
        from app.services.oidc import discover_oidc_endpoints

        discovery_doc = {
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "end_session_endpoint": "https://auth.example.com/logout",
        }

        with patch("app.services.oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = discovery_doc
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            endpoints = await discover_oidc_endpoints("https://auth.example.com")

            assert endpoints["authorization_endpoint"] == "https://auth.example.com/authorize"
            assert endpoints["token_endpoint"] == "https://auth.example.com/token"
            assert endpoints["userinfo_endpoint"] == "https://auth.example.com/userinfo"
            assert endpoints["jwks_uri"] == "https://auth.example.com/.well-known/jwks.json"

    def test_build_authorization_url(self):
        """Test OIDC authorization URL construction."""
        from app.services.oidc import build_authorization_url

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "myapp",
            "oidc_client_secret": "secret",
            "oidc_scopes": "openid email profile",
        }

        endpoints = {
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
        }

        url = build_authorization_url(
            org=org,
            redirect_uri="https://snapper.example.com/auth/oidc/callback",
            state="test-state-123",
            nonce="test-nonce-456",
            endpoints=endpoints,
        )

        assert url.startswith("https://auth.example.com/authorize?")
        assert "client_id=myapp" in url
        assert "response_type=code" in url
        assert "state=test-state-123" in url
        assert "nonce=test-nonce-456" in url
        assert "scope=openid+email+profile" in url or "scope=openid%20email%20profile" in url

    @pytest.mark.asyncio
    async def test_exchange_code_for_tokens(self):
        """Test authorization code exchange (mocked)."""
        from app.services.oidc import exchange_code_for_tokens

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "myapp",
            "oidc_client_secret": "secret",
        }

        endpoints = {
            "token_endpoint": "https://auth.example.com/token",
        }

        token_response = {
            "access_token": "at_123",
            "id_token": "idt_456",
            "token_type": "Bearer",
        }

        with patch("app.services.oidc.httpx.AsyncClient") as mock_client_cls:
            mock_response = MagicMock()
            mock_response.json.return_value = token_response
            mock_response.raise_for_status = MagicMock()

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            tokens = await exchange_code_for_tokens(
                org=org,
                code="auth_code_xyz",
                redirect_uri="https://snapper.example.com/auth/oidc/callback",
                endpoints=endpoints,
            )

            assert tokens["access_token"] == "at_123"
            assert tokens["id_token"] == "idt_456"

    def test_decode_id_token_extracts_claims(self):
        """Test that decoded ID token contains expected OIDC claims."""
        from app.services.oidc import decode_id_token_unverified

        claims_data = json.dumps({
            "sub": "user-uuid-123",
            "email": "admin@corp.com",
            "name": "Admin User",
            "iss": "https://auth.example.com",
            "aud": "myapp",
            "nonce": "nonce-abc",
        }).encode()

        header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(claims_data).rstrip(b"=").decode()
        sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=").decode()

        claims = decode_id_token_unverified(f"{header}.{payload}.{sig}")
        assert claims["sub"] == "user-uuid-123"
        assert claims["email"] == "admin@corp.com"
        assert claims["iss"] == "https://auth.example.com"

    def test_get_oidc_config_defaults(self):
        """Test OIDC config defaults for missing optional fields."""
        from app.services.oidc import get_oidc_config

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "myapp",
            "oidc_client_secret": "secret",
        }

        config = get_oidc_config(org)
        assert config["scopes"] == "openid email profile"
        assert config["provider"] == "generic"

    def test_is_oidc_configured_partial(self):
        """Test OIDC configured returns false with only partial settings."""
        from app.services.oidc import is_oidc_configured

        org = MagicMock()
        org.settings = {
            "oidc_issuer": "https://auth.example.com",
            "oidc_client_id": "myapp",
            # Missing oidc_client_secret
        }
        assert not is_oidc_configured(org)


# ============================================================================
# SAML Service Tests
# ============================================================================


class TestSAMLService:
    """Test SAML configuration and utility functions."""

    def test_is_saml_configured_false(self):
        from app.services.saml import is_saml_configured

        org = MagicMock()
        org.settings = {}
        assert not is_saml_configured(org)

    def test_is_saml_configured_true(self):
        from app.services.saml import is_saml_configured

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        assert is_saml_configured(org)

    def test_get_saml_settings(self):
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        org.slug = "test-org"

        settings = get_saml_settings(org, "https://snapper.example.com")
        assert settings["sp"]["entityId"] == "https://snapper.example.com/auth/saml/metadata/test-org"
        assert settings["idp"]["entityId"] == "https://idp.example.com"
        assert settings["strict"] is True

    def test_get_saml_settings_acs_url(self):
        """Test SAML settings include correct ACS URL."""
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        org.slug = "acme-corp"

        settings = get_saml_settings(org, "https://snapper.example.com")
        assert settings["sp"]["assertionConsumerService"]["url"] == \
            "https://snapper.example.com/auth/saml/acs/acme-corp"
        assert settings["sp"]["assertionConsumerService"]["binding"] == \
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

    def test_get_saml_settings_slo_url(self):
        """Test SAML settings include SLO URL."""
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
            "saml_idp_slo_url": "https://idp.example.com/slo",
        }
        org.slug = "test-org"

        settings = get_saml_settings(org, "https://snapper.example.com")
        assert settings["idp"]["singleLogoutService"]["url"] == "https://idp.example.com/slo"

    def test_get_saml_settings_idp_sso_binding(self):
        """Test SAML IdP SSO uses HTTP-Redirect binding."""
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        org.slug = "test-org"

        settings = get_saml_settings(org, "https://snapper.example.com")
        assert settings["idp"]["singleSignOnService"]["binding"] == \
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

    def test_get_saml_settings_name_id_format(self):
        """Test SAML SP uses email NameID format."""
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        org.slug = "test-org"

        settings = get_saml_settings(org, "https://snapper.example.com")
        assert settings["sp"]["NameIDFormat"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    def test_is_saml_configured_partial(self):
        """Test SAML configured returns false with only partial settings."""
        from app.services.saml import is_saml_configured

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            # Missing sso_url and cert
        }
        assert not is_saml_configured(org)

    def test_get_saml_settings_trailing_slash_stripped(self):
        """Test that trailing slash on request URL is stripped."""
        from app.services.saml import get_saml_settings

        org = MagicMock()
        org.settings = {
            "saml_idp_entity_id": "https://idp.example.com",
            "saml_idp_sso_url": "https://idp.example.com/sso",
            "saml_idp_x509_cert": "MIID...cert...",
        }
        org.slug = "test-org"

        settings = get_saml_settings(org, "https://snapper.example.com/")
        assert settings["sp"]["entityId"] == "https://snapper.example.com/auth/saml/metadata/test-org"


# ============================================================================
# SCIM Tests
# ============================================================================


class TestSCIMHelpers:
    """Test SCIM response helper functions."""

    def test_user_to_scim(self):
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "test@example.com"
        user.full_name = "Test User"
        user.is_active = True
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)

        resource = user_to_scim(user)
        assert resource["userName"] == "test@example.com"
        assert resource["active"] is True
        assert resource["name"]["givenName"] == "Test"
        assert resource["name"]["familyName"] == "User"
        assert len(resource["emails"]) == 1

    def test_user_to_scim_no_name(self):
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "test@example.com"
        user.full_name = None
        user.is_active = True
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)

        resource = user_to_scim(user)
        assert "name" not in resource

    def test_scim_list_response(self):
        from app.routers.scim import scim_list_response

        resp = scim_list_response(
            resources=[{"id": "1"}, {"id": "2"}],
            total=10,
            start_index=1,
            count=2,
        )
        assert resp["totalResults"] == 10
        assert resp["startIndex"] == 1
        assert resp["itemsPerPage"] == 2
        assert len(resp["Resources"]) == 2

    def test_user_to_scim_with_membership(self):
        """Test SCIM user resource includes role when membership provided."""
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "admin@example.com"
        user.full_name = "Admin User"
        user.is_active = True
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)

        membership = MagicMock()
        membership.role = "admin"

        resource = user_to_scim(user, membership)
        assert "roles" in resource
        assert resource["roles"][0]["value"] == "admin"

    def test_user_to_scim_inactive(self):
        """Test SCIM user resource reflects inactive status."""
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "deactivated@example.com"
        user.full_name = "Deactivated User"
        user.is_active = False
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 2, 1, tzinfo=timezone.utc)

        resource = user_to_scim(user)
        assert resource["active"] is False
        assert resource["userName"] == "deactivated@example.com"

    def test_user_to_scim_schemas(self):
        """Test SCIM user resource includes correct schema."""
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "test@example.com"
        user.full_name = None
        user.is_active = True
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

        resource = user_to_scim(user)
        assert "urn:ietf:params:scim:schemas:core:2.0:User" in resource["schemas"]

    def test_user_to_scim_meta(self):
        """Test SCIM user resource includes meta with timestamps."""
        from app.routers.scim import user_to_scim

        created = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        modified = datetime(2026, 2, 15, 8, 30, 0, tzinfo=timezone.utc)

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "test@example.com"
        user.full_name = None
        user.is_active = True
        user.created_at = created
        user.updated_at = modified

        resource = user_to_scim(user)
        assert resource["meta"]["resourceType"] == "User"
        assert resource["meta"]["created"] == created.isoformat()
        assert resource["meta"]["lastModified"] == modified.isoformat()

    def test_scim_list_response_empty(self):
        """Test SCIM list response with no results."""
        from app.routers.scim import scim_list_response

        resp = scim_list_response(
            resources=[],
            total=0,
            start_index=1,
            count=0,
        )
        assert resp["totalResults"] == 0
        assert resp["Resources"] == []
        assert "urn:ietf:params:scim:api:messages:2.0:ListResponse" in resp["schemas"]

    def test_scim_error_format(self):
        """Test SCIM error response format."""
        from app.routers.scim import scim_error

        response = scim_error(400, "userName is required", "invalidValue")
        assert response.status_code == 400
        body = json.loads(response.body)
        assert body["detail"] == "userName is required"
        assert body["scimType"] == "invalidValue"
        assert body["status"] == 400

    def test_scim_error_without_type(self):
        """Test SCIM error response without scimType."""
        from app.routers.scim import scim_error

        response = scim_error(404, "User not found")
        body = json.loads(response.body)
        assert body["detail"] == "User not found"
        assert "scimType" not in body

    def test_user_to_scim_single_name(self):
        """Test SCIM user with single-word name."""
        from app.routers.scim import user_to_scim

        user = MagicMock()
        user.id = uuid.uuid4()
        user.email = "madonna@example.com"
        user.full_name = "Madonna"
        user.is_active = True
        user.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        user.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

        resource = user_to_scim(user)
        assert resource["name"]["givenName"] == "Madonna"
        assert resource["name"]["familyName"] == ""


# ============================================================================
# Audit Log CEF Method Tests
# ============================================================================


class TestAuditLogCEF:
    """Test the to_cef() method on AuditLog."""

    def test_audit_log_to_cef(self):
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

        log = AuditLog()
        log.action = AuditAction.REQUEST_DENIED
        log.severity = AuditSeverity.WARNING
        log.message = "Blocked by denylist"
        log.agent_id = uuid.uuid4()
        log.rule_id = uuid.uuid4()
        log.ip_address = "127.0.0.1"
        log.user_id = None
        log.request_id = "req-001"
        log.details = {"command": "rm -rf /"}
        log.created_at = datetime(2026, 2, 16, 10, 30, 0, tzinfo=timezone.utc)

        cef = log.to_cef()
        assert "CEF:0|Snapper|AAF|" in cef
        assert "|103|Request Denied|5|" in cef
        assert "msg=Blocked by denylist" in cef
        assert "src=127.0.0.1" in cef

    def test_audit_log_to_cef_allowed(self):
        """Test CEF output for allowed request."""
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

        log = AuditLog()
        log.action = AuditAction.REQUEST_ALLOWED
        log.severity = AuditSeverity.INFO
        log.message = "Request allowed"
        log.agent_id = uuid.uuid4()
        log.rule_id = None
        log.ip_address = None
        log.user_id = None
        log.request_id = "req-002"
        log.details = {"command": "ls -la"}
        log.created_at = datetime(2026, 2, 16, 10, 30, 0, tzinfo=timezone.utc)

        cef = log.to_cef()
        assert "|102|Request Allowed|3|" in cef


# ============================================================================
# Policy-as-Code Tests
# ============================================================================


class TestPolicyAsCode:
    """Test policy export/import YAML format."""

    def test_yaml_roundtrip(self):
        import yaml

        rules_yaml = {
            "version": "1",
            "rules": [
                {
                    "name": "Block credential access",
                    "type": "command_denylist",
                    "action": "deny",
                    "priority": 100,
                    "active": True,
                    "parameters": {"patterns": ["**/credentials*", "**/.env"]},
                    "agent": "*",
                },
                {
                    "name": "Allow read commands",
                    "type": "command_allowlist",
                    "action": "allow",
                    "priority": 50,
                    "active": True,
                    "parameters": {"patterns": ["^ls\\b", "^cat\\b"]},
                    "agent": "*",
                },
            ],
        }

        # Serialize and deserialize
        yaml_str = yaml.dump(rules_yaml, default_flow_style=False, sort_keys=False)
        loaded = yaml.safe_load(yaml_str)

        assert loaded["version"] == "1"
        assert len(loaded["rules"]) == 2
        assert loaded["rules"][0]["name"] == "Block credential access"
        assert loaded["rules"][0]["parameters"]["patterns"] == ["**/credentials*", "**/.env"]

    def test_yaml_export_all_rule_types(self):
        """Test YAML export handles all rule types."""
        import yaml

        rules_yaml = {
            "version": "1",
            "rules": [
                {"name": "Deny cmd", "type": "command_denylist", "action": "deny", "priority": 100, "active": True, "parameters": {"patterns": ["^rm"]}, "agent": "*"},
                {"name": "Allow cmd", "type": "command_allowlist", "action": "allow", "priority": 50, "active": True, "parameters": {"patterns": ["^ls"]}, "agent": "*"},
                {"name": "Rate limit", "type": "rate_limit", "action": "deny", "priority": 90, "active": True, "parameters": {"max_requests": 10, "window_seconds": 60}, "agent": "agent-1"},
                {"name": "Time restrict", "type": "time_restriction", "action": "deny", "priority": 80, "active": True, "parameters": {"blocked_hours": [0, 1, 2, 3]}, "agent": "*"},
                {"name": "PII gate", "type": "pii_gate", "action": "require_approval", "priority": 95, "active": True, "parameters": {"mode": "protected"}, "agent": "*"},
            ],
        }

        yaml_str = yaml.dump(rules_yaml, default_flow_style=False, sort_keys=False)
        loaded = yaml.safe_load(yaml_str)

        assert len(loaded["rules"]) == 5
        types = [r["type"] for r in loaded["rules"]]
        assert "command_denylist" in types
        assert "command_allowlist" in types
        assert "rate_limit" in types
        assert "time_restriction" in types
        assert "pii_gate" in types

    def test_yaml_import_preserves_agent_scope(self):
        """Test YAML import preserves agent-scoped rules."""
        import yaml

        rules_yaml = {
            "version": "1",
            "rules": [
                {"name": "Agent-specific deny", "type": "command_denylist", "action": "deny", "priority": 100, "active": True, "parameters": {"patterns": ["^rm"]}, "agent": "openclaw-main"},
                {"name": "Global allow", "type": "command_allowlist", "action": "allow", "priority": 50, "active": True, "parameters": {"patterns": ["^ls"]}, "agent": "*"},
            ],
        }

        yaml_str = yaml.dump(rules_yaml, default_flow_style=False, sort_keys=False)
        loaded = yaml.safe_load(yaml_str)

        assert loaded["rules"][0]["agent"] == "openclaw-main"
        assert loaded["rules"][1]["agent"] == "*"

    def test_yaml_version_validation(self):
        """Test YAML policy format includes version string."""
        import yaml

        rules_yaml = {"version": "1", "rules": []}
        yaml_str = yaml.dump(rules_yaml)
        loaded = yaml.safe_load(yaml_str)

        assert loaded["version"] == "1"
        assert isinstance(loaded["rules"], list)

    def test_yaml_dry_run_format(self):
        """Test dry run output format for policy sync."""
        changes = {
            "to_create": [
                {"name": "New deny rule", "type": "command_denylist"},
            ],
            "to_update": [
                {"name": "Updated allow rule", "type": "command_allowlist", "changes": ["priority: 50 -> 100"]},
            ],
            "to_delete": [],
            "unchanged": 3,
        }

        assert len(changes["to_create"]) == 1
        assert len(changes["to_update"]) == 1
        assert changes["unchanged"] == 3

    def test_yaml_conflict_handling(self):
        """Test that rules with same name are treated as updates, not duplicates."""
        import yaml

        # Original
        original = {
            "version": "1",
            "rules": [
                {"name": "Block dangerous", "type": "command_denylist", "action": "deny", "priority": 100, "active": True, "parameters": {"patterns": ["^rm"]}, "agent": "*"},
            ],
        }

        # Updated with same name but different priority
        updated = {
            "version": "1",
            "rules": [
                {"name": "Block dangerous", "type": "command_denylist", "action": "deny", "priority": 200, "active": True, "parameters": {"patterns": ["^rm", "^dd"]}, "agent": "*"},
            ],
        }

        orig_loaded = yaml.safe_load(yaml.dump(original))
        upd_loaded = yaml.safe_load(yaml.dump(updated))

        # Same name = same rule, should be an update
        assert orig_loaded["rules"][0]["name"] == upd_loaded["rules"][0]["name"]
        assert orig_loaded["rules"][0]["priority"] != upd_loaded["rules"][0]["priority"]
        assert len(upd_loaded["rules"][0]["parameters"]["patterns"]) == 2

    def test_yaml_metadata_preserved(self):
        """Test that policy metadata (description, author) is preserved."""
        import yaml

        rules_yaml = {
            "version": "1",
            "metadata": {
                "description": "Production security policy",
                "author": "security-team@example.com",
                "last_updated": "2026-02-16",
            },
            "rules": [
                {"name": "Block rm", "type": "command_denylist", "action": "deny", "priority": 100, "active": True, "parameters": {"patterns": ["^rm"]}, "agent": "*"},
            ],
        }

        yaml_str = yaml.dump(rules_yaml, default_flow_style=False, sort_keys=False)
        loaded = yaml.safe_load(yaml_str)

        assert loaded["metadata"]["description"] == "Production security policy"
        assert loaded["metadata"]["author"] == "security-team@example.com"

    def test_yaml_empty_rules_valid(self):
        """Test that empty rules list is valid YAML policy."""
        import yaml

        rules_yaml = {"version": "1", "rules": []}
        yaml_str = yaml.dump(rules_yaml)
        loaded = yaml.safe_load(yaml_str)

        assert loaded["version"] == "1"
        assert loaded["rules"] == []


# ============================================================================
# Splunk HEC Transport Tests
# ============================================================================


class TestSplunkHEC:
    """Test Splunk HTTP Event Collector transport."""

    @pytest.mark.asyncio
    async def test_splunk_hec_payload_format(self):
        """Test Splunk HEC JSON envelope structure."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.httpx.AsyncClient") as mock_client_cls:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
            settings.SIEM_SPLUNK_HEC_TOKEN = "test-hec-token-123"
            settings.SIEM_SPLUNK_INDEX = "snapper_events"
            settings.SIEM_SPLUNK_SOURCETYPE = "snapper:security"
            settings.SIEM_SPLUNK_VERIFY_SSL = True
            mock_settings.return_value = settings

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '{"text":"Success","code":0}'

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            payload = {"event": "request_denied", "severity": "warning", "message": "Blocked"}
            result = await send_to_splunk_hec(payload)

            assert result is True
            # Verify the envelope structure
            call_kwargs = mock_client.post.call_args
            sent_body = json.loads(call_kwargs.kwargs.get("content") or call_kwargs[1].get("content"))
            assert sent_body["host"] == "snapper"
            assert sent_body["source"] == "snapper:aaf"
            assert sent_body["sourcetype"] == "snapper:security"
            assert sent_body["index"] == "snapper_events"
            assert "time" in sent_body
            assert sent_body["event"] == payload

    @pytest.mark.asyncio
    async def test_splunk_hec_auth_header(self):
        """Test Splunk HEC uses Authorization: Splunk <token> header."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.httpx.AsyncClient") as mock_client_cls:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
            settings.SIEM_SPLUNK_HEC_TOKEN = "my-secret-token"
            settings.SIEM_SPLUNK_INDEX = "main"
            settings.SIEM_SPLUNK_SOURCETYPE = "snapper:security"
            settings.SIEM_SPLUNK_VERIFY_SSL = False
            mock_settings.return_value = settings

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            await send_to_splunk_hec({"event": "test"})

            call_kwargs = mock_client.post.call_args
            headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
            assert headers["Authorization"] == "Splunk my-secret-token"
            assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_splunk_hec_no_url_skips(self):
        """Test Splunk HEC is skipped when no URL configured."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = None
            settings.SIEM_SPLUNK_HEC_TOKEN = None
            mock_settings.return_value = settings

            result = await send_to_splunk_hec({"event": "test"})
            assert result is False

    @pytest.mark.asyncio
    async def test_splunk_hec_no_token_skips(self):
        """Test Splunk HEC is skipped when no token configured."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
            settings.SIEM_SPLUNK_HEC_TOKEN = None
            mock_settings.return_value = settings

            result = await send_to_splunk_hec({"event": "test"})
            assert result is False

    @pytest.mark.asyncio
    async def test_splunk_hec_failure_returns_false(self):
        """Test Splunk HEC returns False on 4xx/5xx."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.httpx.AsyncClient") as mock_client_cls:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
            settings.SIEM_SPLUNK_HEC_TOKEN = "bad-token"
            settings.SIEM_SPLUNK_INDEX = "main"
            settings.SIEM_SPLUNK_SOURCETYPE = "snapper:security"
            settings.SIEM_SPLUNK_VERIFY_SSL = True
            mock_settings.return_value = settings

            mock_response = MagicMock()
            mock_response.status_code = 403
            mock_response.text = '{"text":"Invalid token","code":4}'
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await send_to_splunk_hec({"event": "test"})
            assert result is False

    @pytest.mark.asyncio
    async def test_splunk_hec_connection_error(self):
        """Test Splunk HEC handles connection errors gracefully."""
        from app.services.event_publisher import send_to_splunk_hec

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.httpx.AsyncClient") as mock_client_cls:
            settings = MagicMock()
            settings.SIEM_SPLUNK_HEC_URL = "https://splunk.example.com:8088/services/collector/event"
            settings.SIEM_SPLUNK_HEC_TOKEN = "test-token"
            settings.SIEM_SPLUNK_INDEX = "main"
            settings.SIEM_SPLUNK_SOURCETYPE = "snapper:security"
            settings.SIEM_SPLUNK_VERIFY_SSL = True
            mock_settings.return_value = settings

            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = await send_to_splunk_hec({"event": "test"})
            assert result is False


class TestPublishEventModes:
    """Test publish_event routing to different SIEM outputs."""

    @pytest.mark.asyncio
    async def test_publish_event_splunk_mode(self):
        """Test publish_event routes to Splunk when SIEM_OUTPUT=splunk."""
        from app.services.event_publisher import publish_event

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.send_to_splunk_hec") as mock_splunk, \
             patch("app.services.event_publisher.send_to_syslog") as mock_syslog, \
             patch("app.services.event_publisher.send_to_webhook") as mock_webhook:
            settings = MagicMock()
            settings.SIEM_OUTPUT = "splunk"
            mock_settings.return_value = settings
            mock_splunk.return_value = True

            await publish_event(
                action="request_denied",
                severity="warning",
                message="Blocked by denylist",
                agent_id="agent-1",
            )

            mock_splunk.assert_called_once()
            mock_syslog.assert_not_called()
            mock_webhook.assert_not_called()

    @pytest.mark.asyncio
    async def test_publish_event_all_mode(self):
        """Test publish_event routes to all three transports when SIEM_OUTPUT=all."""
        from app.services.event_publisher import publish_event

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.send_to_splunk_hec") as mock_splunk, \
             patch("app.services.event_publisher.send_to_syslog") as mock_syslog, \
             patch("app.services.event_publisher.send_to_webhook") as mock_webhook:
            settings = MagicMock()
            settings.SIEM_OUTPUT = "all"
            mock_settings.return_value = settings
            mock_splunk.return_value = True
            mock_webhook.return_value = True

            await publish_event(
                action="rule_created",
                severity="info",
                message="New rule created",
                agent_id="agent-2",
            )

            mock_syslog.assert_called_once()
            mock_webhook.assert_called_once()
            mock_splunk.assert_called_once()

    @pytest.mark.asyncio
    async def test_publish_event_none_mode_skips(self):
        """Test publish_event does nothing when SIEM_OUTPUT=none."""
        from app.services.event_publisher import publish_event

        with patch("app.services.event_publisher.get_settings") as mock_settings, \
             patch("app.services.event_publisher.send_to_splunk_hec") as mock_splunk, \
             patch("app.services.event_publisher.send_to_syslog") as mock_syslog, \
             patch("app.services.event_publisher.send_to_webhook") as mock_webhook:
            settings = MagicMock()
            settings.SIEM_OUTPUT = "none"
            mock_settings.return_value = settings

            await publish_event(
                action="request_denied",
                severity="warning",
                message="Blocked",
            )

            mock_syslog.assert_not_called()
            mock_webhook.assert_not_called()
            mock_splunk.assert_not_called()


class TestPublishFromAuditLog:
    """Test the publish_from_audit_log convenience function."""

    @pytest.mark.asyncio
    async def test_publish_from_audit_log_extracts_fields(self):
        """Test publish_from_audit_log extracts all fields from AuditLog."""
        from app.services.event_publisher import publish_from_audit_log
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

        log = AuditLog()
        log.action = AuditAction.REQUEST_DENIED
        log.severity = AuditSeverity.WARNING
        log.message = "Blocked by denylist"
        log.agent_id = uuid.uuid4()
        log.rule_id = uuid.uuid4()
        log.ip_address = "10.0.0.1"
        log.user_id = None
        log.request_id = "req-test-001"
        log.details = {"command": "rm -rf /"}
        log.created_at = datetime(2026, 2, 16, 12, 0, 0, tzinfo=timezone.utc)

        with patch("app.services.event_publisher.publish_event") as mock_publish:
            await publish_from_audit_log(log)

            mock_publish.assert_called_once()
            call_kwargs = mock_publish.call_args.kwargs
            assert call_kwargs["action"] == "request_denied"
            assert call_kwargs["severity"] == "warning"
            assert call_kwargs["message"] == "Blocked by denylist"
            assert call_kwargs["agent_id"] == str(log.agent_id)
            assert call_kwargs["rule_id"] == str(log.rule_id)
            assert call_kwargs["ip_address"] == "10.0.0.1"
            assert call_kwargs["request_id"] == "req-test-001"
            assert call_kwargs["details"]["command"] == "rm -rf /"
            assert call_kwargs["timestamp"] == log.created_at

    @pytest.mark.asyncio
    async def test_publish_from_audit_log_with_org_id(self):
        """Test publish_from_audit_log passes organization_id."""
        from app.services.event_publisher import publish_from_audit_log
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

        log = AuditLog()
        log.action = AuditAction.RULE_CREATED
        log.severity = AuditSeverity.INFO
        log.message = "Rule created"
        log.agent_id = None
        log.rule_id = None
        log.ip_address = None
        log.user_id = None
        log.request_id = None
        log.details = None
        log.created_at = datetime(2026, 2, 16, 12, 0, 0, tzinfo=timezone.utc)

        with patch("app.services.event_publisher.publish_event") as mock_publish:
            await publish_from_audit_log(log, organization_id="org-123")

            call_kwargs = mock_publish.call_args.kwargs
            assert call_kwargs["organization_id"] == "org-123"

    @pytest.mark.asyncio
    async def test_publish_from_audit_log_handles_errors(self):
        """Test publish_from_audit_log doesn't raise on errors."""
        from app.services.event_publisher import publish_from_audit_log
        from app.models.audit_logs import AuditLog, AuditAction, AuditSeverity

        log = AuditLog()
        log.action = AuditAction.REQUEST_DENIED
        log.severity = AuditSeverity.WARNING
        log.message = "Test"
        log.agent_id = None
        log.rule_id = None
        log.ip_address = None
        log.user_id = None
        log.request_id = None
        log.details = None
        log.created_at = None

        with patch("app.services.event_publisher.publish_event", side_effect=Exception("Connection failed")):
            # Should not raise
            await publish_from_audit_log(log)

    @pytest.mark.asyncio
    async def test_publish_from_audit_log_string_action(self):
        """Test publish_from_audit_log handles string action (not enum)."""
        from app.services.event_publisher import publish_from_audit_log

        log = MagicMock()
        log.action = "custom_action"
        log.severity = "info"
        log.message = "Custom event"
        log.agent_id = None
        log.rule_id = None
        log.ip_address = None
        log.user_id = None
        log.request_id = None
        log.details = None
        log.created_at = None
        log.organization_id = None

        with patch("app.services.event_publisher.publish_event") as mock_publish:
            await publish_from_audit_log(log)

            call_kwargs = mock_publish.call_args.kwargs
            assert call_kwargs["action"] == "custom_action"
            assert call_kwargs["severity"] == "info"


# ============================================================================
# CEF Event Map Coverage
# ============================================================================


class TestCEFEventMap:
    """Test CEF event map completeness and correctness."""

    def test_all_event_ids_unique(self):
        """Test that all CEF event class IDs are unique."""
        from app.services.event_publisher import CEF_EVENT_MAP

        ids = [v[0] for v in CEF_EVENT_MAP.values()]
        assert len(ids) == len(set(ids)), f"Duplicate event IDs found: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_event_names_non_empty(self):
        """Test that all CEF event names are non-empty strings."""
        from app.services.event_publisher import CEF_EVENT_MAP

        for action, (event_id, event_name) in CEF_EVENT_MAP.items():
            assert event_id, f"Empty event ID for action: {action}"
            assert event_name, f"Empty event name for action: {action}"

    def test_security_events_high_ids(self):
        """Test security events have 400-series IDs."""
        from app.services.event_publisher import CEF_EVENT_MAP

        security_actions = ["rate_limit_exceeded", "origin_violation", "host_violation",
                           "credential_access_blocked", "malicious_skill_blocked"]
        for action in security_actions:
            event_id = CEF_EVENT_MAP[action][0]
            assert event_id.startswith("4"), f"Security event {action} should have 400-series ID, got {event_id}"

    def test_pii_events_600_series(self):
        """Test PII events have 600-series IDs."""
        from app.services.event_publisher import CEF_EVENT_MAP

        pii_actions = ["pii_vault_created", "pii_vault_accessed", "pii_vault_deleted",
                       "pii_gate_triggered", "pii_submission_approved", "pii_submission_denied"]
        for action in pii_actions:
            event_id = CEF_EVENT_MAP[action][0]
            assert event_id.startswith("6"), f"PII event {action} should have 600-series ID, got {event_id}"
