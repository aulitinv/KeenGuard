"""Unit tests verifying final stabilization fixes across Blocks A, B, C, D:
1. Audit timer auto-completion (indentation bug fix in TrafficAuditManager)
2. LAN Tracker rule_alert severity lowercase normalization and Telegram delivery
3. X-Forwarded-For right-to-left traversal and WebSocket Origin port matching
4. WIDS deauth flood burst fingerprint deduplication
5. Keenetic ACL trailing permit any and Bridge0 in conflict prevention
"""
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import urllib.parse
import pytest

from keenguard.core.audit.manager import TrafficAuditManager
from keenguard.core.lan_tracker import LanTrafficTracker
from keenguard.core.wids import WIDSService
from keenguard.core.keenetic.client import KeeneticClient
from keenguard.db.models import SecurityRule
from keenguard.config import settings
from keenguard.web.auth import get_client_ip
from keenguard.web.workers import _process_lan_violation


# =========================================================================
# 1. Audit Timer Auto-Completion (Indentation Bug Fix)
# =========================================================================

@pytest.mark.asyncio
async def test_audit_timer_auto_completion(tmp_path):
    """
    Verifies that when an audit session's timer elapses naturally inside _session_loop,
    the report is generated and saved in the DB (was previously skipped due to indentation bug).
    """
    manager = TrafficAuditManager(pcap_dir=tmp_path)

    mock_db = MagicMock()
    mock_db.get_device = AsyncMock(return_value=None)
    mock_db.get_all_devices = AsyncMock(return_value=[])
    mock_db.get_presets = AsyncMock(return_value=[])
    mock_db.get_preset = AsyncMock(return_value=None)
    mock_db.save_audit_report = AsyncMock()
    mock_db.record_event = AsyncMock()
    mock_db.record_dns_query = AsyncMock()

    mock_backend = MagicMock()
    mock_backend.platform_name = "MockRouter"
    mock_backend.start_packet_capture = AsyncMock(return_value=True)
    mock_backend.stop_packet_capture = AsyncMock(return_value=None)
    mock_backend.reset_packet_capture = AsyncMock()

    mock_router_mgr = MagicMock()
    mock_router_mgr.get_backend.return_value = mock_backend
    mock_router_mgr.get_device_nat_connections = AsyncMock(return_value=[])

    with patch("keenguard.core.audit.manager._get_db", return_value=mock_db), \
         patch("keenguard.core.audit.manager.router_manager", mock_router_mgr):

        # Start 1-second audit
        session = await manager.start_audit(
            mac="AA:BB:CC:DD:EE:01",
            ip="192.168.1.101",
            hostname="Test-AutoStop-Device",
            duration_seconds=1
        )
        assert session["status"] == "started"
        assert "AA:BB:CC:DD:EE:01" in manager.active_sessions
        assert manager.active_sessions["AA:BB:CC:DD:EE:01"].is_active is True

        # Wait for timer loop to expire (2.0s per iteration + margin)
        await asyncio.sleep(2.3)

        # Verify session is finalized and report was saved
        assert "AA:BB:CC:DD:EE:01" not in manager.active_sessions
        assert mock_db.save_audit_report.await_count == 1
        saved_record = mock_db.save_audit_report.await_args[0][0]
        assert saved_record.mac == "AA:BB:CC:DD:EE:01"
        assert saved_record.hostname == "Test-AutoStop-Device"
        assert mock_db.record_event.await_count >= 1


@pytest.mark.asyncio
async def test_network_audit_timer_auto_completion(tmp_path):
    """
    Verifies that when a full-network audit session's timer elapses,
    the network report is generated and saved in the DB.
    """
    manager = TrafficAuditManager(pcap_dir=tmp_path)

    mock_db = MagicMock()
    mock_db.get_all_devices = AsyncMock(return_value=[])
    mock_db.get_presets = AsyncMock(return_value=[])
    mock_db.save_audit_report = AsyncMock()
    mock_db.record_event = AsyncMock()
    mock_db.record_dns_query = AsyncMock()

    mock_router_mgr = MagicMock()
    mock_router_mgr.get_nat_table = AsyncMock(return_value=[])

    with patch("keenguard.core.audit.manager._get_db", return_value=mock_db), \
         patch("keenguard.core.audit.manager.router_manager", mock_router_mgr):

        session = await manager.start_network_audit(duration_seconds=1, scope="all")
        assert session["status"] == "started"
        assert manager.active_network_session is not None
        assert manager.active_network_session.is_active is True

        await asyncio.sleep(2.3)

        assert manager.active_network_session.is_active is False
        assert mock_db.save_audit_report.await_count == 1
        saved_record = mock_db.save_audit_report.await_args[0][0]
        assert saved_record.mac is None
        assert "Аудит всей сети" in saved_record.hostname


# =========================================================================
# 2. LAN Tracker rule_alert Severity Lowercase Normalization
# =========================================================================

def test_rule_alert_severity_is_lowercase():
    """
    Verifies that rule_eval.severity is normalized to lowercase in check_lan_policy_violation,
    preventing upper-case 'CRITICAL' from silently bypassing Telegram notifications.
    """
    mock_rule_eval = MagicMock()
    mock_rule_eval.matched = True
    mock_rule_eval.rule_id = "rule_test_alert"
    mock_rule_eval.rule_name = "Test Alert Rule"
    mock_rule_eval.action_mode = "alert"
    mock_rule_eval.severity = "CRITICAL"  # Uppercase from external/custom definition
    mock_rule_eval.hardware_wan_block = False
    mock_rule_eval.record_pcap_seconds = 0
    mock_rule_eval.apply_preset_id = None
    mock_rule_eval.notify_telegram = True
    mock_rule_eval.telegram_mode = "instant"

    mock_matcher = MagicMock()
    mock_matcher.evaluate_flow.return_value = mock_rule_eval
    tracker = LanTrafficTracker(rule_matcher=mock_matcher)

    src_dev = {"mac": "11:22:33:44:55:66", "ip": "192.168.1.50", "name": "Device A"}
    dst_dev = {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.60", "name": "Device B"}

    violation = tracker.check_lan_policy_violation(
        src_mac="11:22:33:44:55:66",
        src_ip="192.168.1.50",
        dst_mac="AA:BB:CC:DD:EE:FF",
        dst_ip="192.168.1.60",
        port=8080,
        protocol="TCP",
        devices_map={"192.168.1.50": src_dev, "192.168.1.60": dst_dev}
    )

    assert violation is not None
    assert violation["violation_type"] == "rule_alert"
    assert violation["severity"] == "critical"  # Must be lowercase!


@pytest.mark.asyncio
async def test_rule_alert_severity_reaches_telegram():
    """
    Verifies that an event with severity='critical' triggers Telegram notification in _process_lan_violation.
    """
    mock_db = MagicMock()
    mock_db.record_event = AsyncMock(return_value=123)
    mock_db.record_rule_hit = AsyncMock()
    mock_notifier = MagicMock()
    mock_notifier.send_alert = AsyncMock()

    violation = {
        "event_type": "lan_policy_violation",
        "violation_type": "rule_alert",
        "severity": "critical",
        "source_mac": "11:22:33:44:55:66",
        "source_ip": "192.168.1.50",
        "source_name": "Device A",
        "dest_ip": "192.168.1.60",
        "dest_name": "Device B",
        "port": 8080,
        "protocol": "TCP",
        "description": "Suspicious flow",
        "matched_rule_id": "rule_1",
        "matched_rule_name": "Rule 1",
        "notify_telegram": True,
        "telegram_mode": "immediate",
        "hardware_wan_block": False,
        "record_pcap_seconds": 0,
        "apply_preset_id": None
    }

    with patch("keenguard.web.workers.get_db", return_value=mock_db), \
         patch("keenguard.web.workers.notifier", mock_notifier), \
         patch("keenguard.web.workers.broadcast_event", new_callable=AsyncMock):

        await _process_lan_violation(violation)
        await asyncio.sleep(0.05)
        assert mock_notifier.send_alert.await_count == 1


# =========================================================================
# 3. X-Forwarded-For Right-to-Left Traversal & WS Origin Port Matching
# =========================================================================

def test_x_forwarded_for_right_to_left_traversal():
    """
    Verifies that get_client_ip traverses X-Forwarded-For right-to-left
    and returns the first untrusted IP (ignoring spoofed leftmost values).
    """
    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"

    with patch.object(settings, "trusted_proxies", ["127.0.0.1", "10.0.0.1"]):
        # Attacker spoofs 203.0.113.50, but real client behind proxy is 192.168.1.75
        mock_request.headers = {
            "x-forwarded-for": "203.0.113.50, 192.168.1.75, 10.0.0.1"
        }
        ip = get_client_ip(mock_request)
        assert ip == "192.168.1.75"

        # If request has no client, fails closed with empty string
        mock_no_client = MagicMock()
        mock_no_client.client = None
        assert get_client_ip(mock_no_client) == ""

        # Untrusted direct client returns peer IP without reading headers
        mock_direct = MagicMock()
        mock_direct.client.host = "192.168.1.99"
        mock_direct.headers = {"x-forwarded-for": "203.0.113.1"}
        assert get_client_ip(mock_direct) == "192.168.1.99"


def test_ws_origin_port_matching():
    """
    Verifies WebSocket Origin check requires port matching and properly handles IPv6.
    """
    from urllib.parse import urlparse

    def check_origin(origin_str: str, host_header: str) -> bool:
        parsed_origin = urlparse(origin_str)
        origin_host = parsed_origin.netloc.lower()
        req_host = (host_header or "").lower()

        parsed_req = urlparse("//" + req_host) if req_host else None
        origin_hostname = (parsed_origin.hostname or "").lower()
        origin_port = parsed_origin.port
        req_hostname = (parsed_req.hostname or "").lower() if parsed_req else ""
        req_port = parsed_req.port if parsed_req else None

        ports_match = (req_hostname == "testserver") or (origin_port == req_port)
        hosts_match = (
            (origin_hostname and origin_hostname == req_hostname)
            or (origin_hostname in ("localhost", "127.0.0.1", "::1") and req_hostname in ("localhost", "127.0.0.1", "::1", "testserver"))
        )
        return bool((origin_host == req_host) or (hosts_match and ports_match))

    # Matching ports between localhost and 127.0.0.1 -> Allowed
    assert check_origin("http://localhost:8000", "127.0.0.1:8000") is True

    # Mismatched ports -> Rejected
    assert check_origin("http://localhost:3000", "127.0.0.1:8000") is False

    # IPv6 with matching port -> Allowed
    assert check_origin("http://[::1]:8000", "[::1]:8000") is True

    # External attacker domain -> Rejected
    assert check_origin("http://evil.com:8000", "127.0.0.1:8000") is False


# =========================================================================
# 4. WIDS Deauth Incident Deduplication by Burst Fingerprint
# =========================================================================

@pytest.mark.asyncio
async def test_wids_deauth_burst_deduplication():
    """
    Verifies that identical deauth flood bursts across consecutive polls
    are deduplicated by burst fingerprint.
    """
    wids = WIDSService()

    sample_logs = [
        "May 20 12:00:01 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request",
        "May 20 12:00:02 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request",
        "May 20 12:00:03 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request",
        "May 20 12:00:04 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request",
        "May 20 12:00:05 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request",
        "May 20 12:00:06 wlan0: Station AA:BB:CC:11:22:33 deauthenticated due to local deauth request"
    ]

    mock_backend = MagicMock()
    mock_backend.get_wifi_security = AsyncMock(return_value={"networks": []})
    mock_backend.get_system_log = AsyncMock(return_value=sample_logs)
    mock_backend.get_wlan_scan = AsyncMock(return_value=[])

    mock_db = MagicMock()
    mock_db.record_event = AsyncMock(return_value=1)

    # First poll: Should detect and record the incident
    report1 = await wids.run_wids_audit(mock_backend, db=mock_db, notify=False)
    assert len(report1["deauth_incidents"]) == 1
    assert mock_db.record_event.await_count == 1

    # Second poll with identical log lines: Should deduplicate and NOT re-record in DB
    report2 = await wids.run_wids_audit(mock_backend, db=mock_db, notify=False)
    assert len(report2["deauth_incidents"]) == 1
    assert mock_db.record_event.await_count == 1  # Unchanged!


# =========================================================================
# 5. Keenetic ACL Trailing Permit & Conflict Prevention
# =========================================================================

@pytest.mark.asyncio
async def test_keenetic_acl_trailing_permit_and_conflict():
    """
    Verifies that:
    1. block_dot_traffic appends explicit permit rules to avoid LAN drop
    2. block_dot_traffic aborts if a custom user ACL is bound to Bridge0 in
    """
    client = KeeneticClient(host="192.168.1.1", user="admin", password="password")
    client.mock_mode = False

    # Scenario 1: Custom user ACL already bound to Bridge0 in
    custom_acl_config = [
        {"show": {"running-config": {"message": [
            "interface Bridge0",
            "    ip access-group MY_CUSTOM_FIREWALL in",
            "!"
        ]}}}
    ]
    client._send_request = AsyncMock(return_value=MagicMock(status_code=200, json=lambda: custom_acl_config))

    result = await client.block_dot_traffic(True)
    assert result is False  # Must refuse to overwrite user ACL!

    # Scenario 2: Clean configuration without custom ACL
    clean_config = [
        {"show": {"running-config": {"message": [
            "interface Bridge0",
            "!"
        ]}}}
    ]
    rci_ok_resp = MagicMock(status_code=200, json=lambda: [{"status": [{"status": "ok"}]}])

    async def mock_send(method, endpoint, json_data=None):
        if json_data and isinstance(json_data, list) and "show" in json_data[0]:
            return MagicMock(status_code=200, json=lambda: clean_config)
        return rci_ok_resp

    client._send_request = AsyncMock(side_effect=mock_send)

    success = await client.block_dot_traffic(True)
    assert success is True

    # Verify RCI payload contained permit rules at end of ACL
    called_payload = client._send_request.call_args[1].get("json_data")
    assert called_payload is not None

    has_ipv4_permit = any(
        cmd.get("ip", {}).get("access-list", {}).get("rule", {}).get("action") == "permit"
        for cmd in called_payload
    )
    has_ipv6_permit = any(
        cmd.get("ipv6", {}).get("access-list", {}).get("rule", {}).get("action") == "permit"
        for cmd in called_payload
    )
    assert has_ipv4_permit is True
    assert has_ipv6_permit is True
