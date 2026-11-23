"""Unit and integration tests for WebSocket resilience, input fault tolerance, and rate limiting (Phase 6.2)."""
import json
import time
from unittest.mock import patch, MagicMock, AsyncMock
import pytest
from fastapi.testclient import TestClient

from keenguard.web.app import app
from keenguard.web.ws import ws_manager


def test_ws_malformed_json_fallback():
    """Verify WebSocket server does not crash on malformed JSON and keeps connection alive."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        # Non-JSON string should be gracefully acknowledged
        ws.send_text("this is completely invalid json string {{{")
        resp = ws.receive_json()
        assert resp.get("type") == "ack"
        assert "invalid json" in resp.get("received", "")

        # Plain text 'ping' should return 'pong'
        ws.send_text("ping")
        resp_ping = ws.receive_json()
        assert resp_ping.get("type") == "pong"
        assert "timestamp" in resp_ping

        # Plain text 'health' should also return 'pong'
        ws.send_text("health")
        resp_health = ws.receive_json()
        assert resp_health.get("type") == "pong"

        # Subsequent valid JSON continues to work normally
        ws.send_text(json.dumps({"command": "ping"}))
        resp_valid = ws.receive_json()
        assert resp_valid.get("type") == "pong"


def test_ws_rate_limit_enforcement():
    """Verify rate limiter blocks bursts exceeding MAX_WS_MESSAGES_PER_SECOND."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        rate_limited = False
        # Send 35 messages as fast as possible (limit is 30/s)
        for i in range(35):
            ws.send_text(json.dumps({"command": "ping"}))
            resp = ws.receive_json()
            if resp.get("type") == "error" and "Rate limit exceeded" in resp.get("message", ""):
                rate_limited = True
                break

        assert rate_limited is True


def test_ws_refresh_debounce():
    """Verify refresh commands within debounce window are throttled with debounced status."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        # First refresh triggers polling
        ws.send_text(json.dumps({"command": "refresh"}))
        resp1 = ws.receive_json()
        assert resp1.get("type") == "refresh_ack"
        assert resp1.get("status") in ("polling_started", "debounced")

        # Immediate follow-up refresh must be debounced
        ws.send_text(json.dumps({"command": "refresh"}))
        resp2 = ws.receive_json()
        assert resp2.get("type") == "refresh_ack"
        assert resp2.get("status") == "debounced"


def test_ws_connection_lifecycle_and_cleanup():
    """Verify ws_manager adds connection on open and properly discards it on disconnect."""
    client = TestClient(app)
    initial_count = len(ws_manager.active_connections)

    with client.websocket_connect("/ws/live") as ws:
        assert len(ws_manager.active_connections) == initial_count + 1
        ws.send_text(json.dumps({"command": "ping"}))
        assert ws.receive_json().get("type") == "pong"

    # Context exit closes websocket
    assert len(ws_manager.active_connections) == initial_count


def test_ws_audit_commands_validation():
    """Verify input validation for start_audit and stop_audit commands."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        # Invalid MAC on start_audit
        ws.send_text(json.dumps({"command": "start_audit", "mac": "invalid_mac_addr"}))
        resp_err1 = ws.receive_json()
        assert resp_err1.get("type") == "error"
        assert "Valid MAC" in resp_err1.get("message", "")

        # Missing MAC on start_audit
        ws.send_text(json.dumps({"command": "start_audit"}))
        resp_err2 = ws.receive_json()
        assert resp_err2.get("type") == "error"
        assert "Valid MAC" in resp_err2.get("message", "")

        # Invalid MAC on stop_audit
        ws.send_text(json.dumps({"command": "stop_audit", "mac": "XYZ"}))
        resp_err3 = ws.receive_json()
        assert resp_err3.get("type") == "error"
        assert "Valid MAC" in resp_err3.get("message", "")


def test_ws_audit_start_and_stop_success():
    """Verify valid MAC triggers audit start and stop commands properly."""
    client = TestClient(app)
    valid_mac = "AA:BB:CC:DD:EE:FF"

    mock_audit_mgr = MagicMock()
    mock_audit_mgr.start_audit = AsyncMock()
    mock_audit_mgr.stop_audit = AsyncMock()

    with patch("keenguard.web.ws.get_audit_manager", return_value=mock_audit_mgr):
        with client.websocket_connect("/ws/live") as ws:
            # Valid start_audit
            ws.send_text(json.dumps({"command": "start_audit", "mac": valid_mac, "duration": 180}))
            resp_start = ws.receive_json()
            assert resp_start.get("type") == "audit_started"
            assert resp_start.get("mac") == valid_mac
            assert resp_start.get("duration") == 180
            mock_audit_mgr.start_audit.assert_called_with(mac=valid_mac, duration_seconds=180)

            # Valid stop_audit
            ws.send_text(json.dumps({"command": "stop_audit", "mac": valid_mac}))
            resp_stop = ws.receive_json()
            assert resp_stop.get("type") == "audit_stopped"
            assert resp_stop.get("mac") == valid_mac
            mock_audit_mgr.stop_audit.assert_called_with(valid_mac)


def test_ws_foreign_origin_rejected():
    """Verify CSWSH protection: foreign Origin is rejected with code 1008."""
    from starlette.websockets import WebSocketDisconnect
    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/live", headers={"Origin": "https://evil.example"}):
            pass
    assert exc.value.code == 1008


def test_ws_start_audit_duration_validation():
    """Verify bounds (10..3600) and type validation on start_audit duration."""
    client = TestClient(app)
    valid_mac = "11:22:33:44:55:66"

    mock_audit_mgr = MagicMock()
    mock_audit_mgr.start_audit = AsyncMock()

    with patch("keenguard.web.ws.get_audit_manager", return_value=mock_audit_mgr):
        with client.websocket_connect("/ws/live") as ws:
            # 1. Non-integer duration
            ws.send_text(json.dumps({"command": "start_audit", "mac": valid_mac, "duration": "not_int"}))
            err1 = ws.receive_json()
            assert err1.get("type") == "error"
            assert "Must be an integer" in err1.get("message", "")

            # 2. Too short (< 10)
            ws.send_text(json.dumps({"command": "start_audit", "mac": valid_mac, "duration": 5}))
            err2 = ws.receive_json()
            assert err2.get("type") == "error"
            assert "Duration out of range" in err2.get("message", "")

            # 3. Too long (> 3600)
            ws.send_text(json.dumps({"command": "start_audit", "mac": valid_mac, "duration": 5000}))
            err3 = ws.receive_json()
            assert err3.get("type") == "error"
            assert "Duration out of range" in err3.get("message", "")

            # 4. Valid duration in bounds
            ws.send_text(json.dumps({"command": "start_audit", "mac": valid_mac, "duration": 300}))
            ok_res = ws.receive_json()
            assert ok_res.get("type") == "audit_started"
            assert ok_res.get("duration") == 300


def test_ws_token_query_param_no_longer_accepted():
    """Verify token in query string is not accepted, only HttpOnly cookie."""
    from starlette.websockets import WebSocketDisconnect
    from keenguard.config import settings
    from keenguard.web.auth import create_session, COOKIE_NAME

    orig_auth = settings.web_auth_enabled
    orig_exempt = settings.web_auth_exempt_localhost
    try:
        settings.web_auth_enabled = "true"
        settings.web_auth_exempt_localhost = False

        client = TestClient(app)
        token = create_session()

        # Connecting with query param ?token= must fail with code 1008
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(f"/ws/live?token={token}"):
                pass
        assert exc.value.code == 1008

        # Connecting with HttpOnly cookie must succeed
        with client.websocket_connect("/ws/live", cookies={COOKIE_NAME: token}) as ws:
            ws.send_text(json.dumps({"command": "ping"}))
            resp = ws.receive_json()
            assert resp.get("type") == "pong"
    finally:
        settings.web_auth_enabled = orig_auth
        settings.web_auth_exempt_localhost = orig_exempt


def test_ws_unknown_command_fallback():
    """Verify unknown command returns standard ack fallback."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        ws.send_text(json.dumps({"command": "unsupported_command_xyz"}))
        resp = ws.receive_json()
        assert resp.get("type") == "ack"
        assert resp.get("received") == "unsupported_command_xyz"
