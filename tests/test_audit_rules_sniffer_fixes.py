"""Unit tests validating runtime fixes for TrafficAuditManager deadlock,
Rules Engine alert preservation for trusted devices, rule category/temporary_until handling,
DoT port 853 BPF filtering, and DNS bypass dispatch.
"""
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import AsyncClient, ASGITransport

from keenguard.core.audit.manager import TrafficAuditManager
from keenguard.core.lan_tracker import LanTrafficTracker, lan_tracker
from keenguard.core.rules.matcher import RuleMatcher, MatchResult
from keenguard.core.rules.linter import RuleLinter, LinterSeverity
from keenguard.core.sniffer import NetworkSniffer
from keenguard.db.database import Database
from keenguard.db.models import (
    SecurityRule,
    RuleSource,
    RuleDestination,
    RuleContext,
    RuleReaction,
    RuleTelemetry,
    SecurityEvent,
)
from keenguard.web.app import app
import keenguard.web.app as web_app
from keenguard.web.workers import _async_sniffer_dispatch, _process_lan_violation


# =========================================================================
# 1. TrafficAuditManager: Deadlock prevention on restart
# =========================================================================

@pytest.mark.asyncio
async def test_audit_manager_restart_no_deadlock(tmp_path):
    """
    Verifies that calling start_audit / start_network_audit when a session
    is already active does NOT deadlock and terminates cleanly within timeout.
    """
    manager = TrafficAuditManager(pcap_dir=tmp_path)

    mock_db = MagicMock()
    mock_db.get_device = AsyncMock(return_value=None)
    mock_db.get_all_devices = AsyncMock(return_value=[])
    mock_db.get_presets = AsyncMock(return_value=[])
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
    mock_router_mgr.get_nat_table = AsyncMock(return_value=[])

    with patch("keenguard.core.audit.manager._get_db", return_value=mock_db), \
         patch("keenguard.core.audit.manager.router_manager", mock_router_mgr):

        mac = "00:11:22:33:44:55"

        # 1. Device audit restart must not deadlock (timeout 2.0s)
        async def run_device_audit_restart():
            res1 = await manager.start_audit(mac=mac, ip="192.168.1.150", duration_seconds=60)
            assert res1["status"] == "started"
            assert mac.upper() in manager.active_sessions

            # Second call while active: invokes _stop_audit_unlocked without deadlocking
            res2 = await manager.start_audit(mac=mac, ip="192.168.1.150", duration_seconds=60)
            assert res2["status"] == "started"
            assert mac.upper() in manager.active_sessions

            await manager.stop_audit(mac)
            assert mac.upper() not in manager.active_sessions

        await asyncio.wait_for(run_device_audit_restart(), timeout=2.0)

        # 2. Network audit restart must not deadlock (timeout 2.0s)
        async def run_network_audit_restart():
            n1 = await manager.start_network_audit(duration_seconds=60, scope="all")
            assert n1["status"] == "started"
            assert manager.active_network_session is not None
            assert manager.active_network_session.is_active is True

            # Second call while active: invokes _stop_network_audit_unlocked without deadlocking
            n2 = await manager.start_network_audit(duration_seconds=60, scope="all")
            assert n2["status"] == "started"
            assert manager.active_network_session is not None

            await manager.stop_network_audit()
            assert manager.active_network_session.is_active is False

        await asyncio.wait_for(run_network_audit_restart(), timeout=2.0)


# =========================================================================
# 2. Audit suspicious callback wiring
# =========================================================================

@pytest.mark.asyncio
async def test_audit_suspicious_callback_invoked(tmp_path):
    """Verifies that set_suspicious_callback registers and triggers on suspicious flows."""
    manager = TrafficAuditManager(pcap_dir=tmp_path)
    callback_calls = []

    async def fake_suspicious_cb(mac: str, ip: str, hostname: str, reason: str):
        callback_calls.append((mac, ip, hostname, reason))

    manager.set_suspicious_callback(fake_suspicious_cb)
    assert manager.suspicious_callback == fake_suspicious_cb

    mac = "AA:BB:CC:11:22:33"
    ip = "192.168.1.80"

    mock_db = MagicMock()
    mock_db.get_device = AsyncMock(return_value=None)
    mock_db.save_audit_report = AsyncMock()
    mock_db.record_event = AsyncMock()
    mock_backend = MagicMock()
    mock_backend.start_packet_capture = AsyncMock(return_value=False)
    mock_backend.stop_packet_capture = AsyncMock(return_value=None)
    mock_router = MagicMock()
    mock_router.get_backend.return_value = mock_backend

    with patch("keenguard.core.audit.manager._get_db", return_value=mock_db), \
         patch("keenguard.core.audit.manager.router_manager", mock_router):

        await manager.start_audit(mac=mac, ip=ip, duration_seconds=60)
        session = manager.get_session(mac)
        assert session is not None

        # Simulate camera connecting to forbidden Telnet port 23 in LAN
        session.profile = "camera"
        nat_entry = {
            "dst": "192.168.1.50",
            "dport": 23,
            "protocol": "tcp",
            "bytes": 500
        }
        session.update_nat_entries([nat_entry], on_suspicious_callback=manager.suspicious_callback)
        await asyncio.sleep(0.05)

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == mac
        assert callback_calls[0][1] == ip
        assert "23" in callback_calls[0][3]

        await manager.stop_audit(mac)


# =========================================================================
# 3. Rules Engine: Rule Alert on Trusted Profile Device
# =========================================================================

def test_rule_alert_triggers_for_trusted_profile_device():
    """
    Verifies that when a custom security rule evaluates to 'alert' (rule_alert),
    LanTracker does NOT drop it with an early return None for trusted devices.
    """
    tracker = LanTrafficTracker()
    tracker._use_rules_engine = True

    # Custom rule alerting on internal port 4444
    rule = SecurityRule(
        id="rule_alert_4444",
        order_index=50,
        name="Flag Port 4444 backdoor",
        enabled=True,
        destination=RuleDestination(
            direction="lan_to_lan",
            ports=[4444],
            protocols=["TCP"]
        ),
        reaction=RuleReaction(
            action_mode="alert",
            severity="CRITICAL",
            notify_telegram=False,
            telegram_mode="digest"
        )
    )

    matcher = RuleMatcher([rule])
    tracker._custom_rule_matcher = matcher

    trusted_device = {
        "mac": "11:22:33:44:55:66",
        "ip": "192.168.1.10",
        "name": "Alex Trusted Laptop",
        "profile": "trusted",
        "preset_id": "preset_trusted"
    }

    target_device = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.1.20",
        "name": "File Server",
        "profile": "trusted"
    }

    devices_map = {
        "192.168.1.10": trusted_device,
        "192.168.1.20": target_device,
    }

    violation = tracker.check_lan_policy_violation(
        src_mac="11:22:33:44:55:66",
        src_ip="192.168.1.10",
        dst_mac="AA:BB:CC:DD:EE:FF",
        dst_ip="192.168.1.20",
        port=4444,
        protocol="TCP",
        devices_map=devices_map,
        bytes_count=1024
    )

    assert violation is not None, "Rule alert was erroneously suppressed for trusted profile"
    assert violation["violation_type"] == "rule_alert"
    assert violation["matched_rule_id"] == "rule_alert_4444"
    assert violation["notify_telegram"] is False
    assert violation["telegram_mode"] == "digest"


@pytest.mark.asyncio
async def test_process_lan_violation_respects_notify_telegram_false(monkeypatch):
    """Verifies that _process_lan_violation does not send telegram alert when notify_telegram=False."""
    mock_db = MagicMock()
    mock_db.record_event = AsyncMock()
    mock_db.record_rule_hit = AsyncMock()

    mock_notifier = MagicMock()
    mock_notifier.send_alert = AsyncMock()

    monkeypatch.setattr("keenguard.web.workers.get_db", lambda: mock_db)
    monkeypatch.setattr("keenguard.web.workers.notifier", mock_notifier)

    violation_dict = {
        "event_type": "lan_policy_violation",
        "severity": "CRITICAL",
        "description": "Silent alert test",
        "source_mac": "11:22:33:44:55:66",
        "source_ip": "192.168.1.10",
        "target_ip": "192.168.1.20",
        "port": 4444,
        "matched_rule_id": "rule_test_silent",
        "notify_telegram": False,
        "telegram_mode": "digest"
    }

    await _process_lan_violation(violation_dict)
    await asyncio.sleep(0.05)

    mock_notifier.send_alert.assert_not_called()


# =========================================================================
# 4. Rules Engine: Category Validation & temporary_until Reset to None
# =========================================================================

@pytest.mark.asyncio
async def test_rule_category_validation_and_temporary_until_reset(tmp_path, monkeypatch):
    """
    Verifies:
    1. POST /api/rules rejects category='core' with 400 Bad Request.
    2. PUT /api/rules/{id} resets temporary_until to None.
    3. PUT /api/rules/{id} rejects setting category='core' on custom rules.
    """
    db_file = tmp_path / "test_rules_temp.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    monkeypatch.setattr(web_app, "db", test_db)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # 1. Attempt creating 'core' rule must be rejected with 400
        bad_core = await client.post("/api/rules", json={
            "name": "Rogue Core Rule",
            "category": "core",
            "enabled": True
        })
        assert bad_core.status_code == 400
        assert "запрещено" in bad_core.json()["detail"]

        # 2. Create custom rule with temporary_until set
        expiry = "2026-12-31T23:59:59Z"
        res = await client.post("/api/rules", json={
            "name": "Temporary Security Bypass",
            "category": "security",
            "temporary_until": expiry,
            "enabled": True,
            "reaction": {"action_mode": "pass"}
        })
        assert res.status_code == 201
        created = res.json()
        rule_id = created["id"]
        assert created["category"] == "security"
        assert created["temporary_until"] == expiry

        # 3. Reset temporary_until to None via PUT
        reset_res = await client.put(f"/api/rules/{rule_id}", json={
            "temporary_until": None
        })
        assert reset_res.status_code == 200
        updated = reset_res.json()
        assert updated["temporary_until"] is None

        # Verify in database
        db_rule = await test_db.get_rule(rule_id)
        assert db_rule is not None
        assert db_rule.temporary_until is None

        # 4. Attempting to change category to 'core' on custom rule must be rejected
        bad_update = await client.put(f"/api/rules/{rule_id}", json={
            "category": "core"
        })
        assert bad_update.status_code == 400


def test_rule_matcher_and_linter_unsupported_fields():
    """
    Verifies that RuleMatcher does not match falsely on unsupported fields
    (domains, bandwidth_operator, rate_limit_burst), and RuleLinter reports them.
    """
    rule_domain = SecurityRule(
        id="rule_dom",
        order_index=50,
        name="Domain Match Test",
        enabled=True,
        destination=RuleDestination(domains=["evil.com"])
    )
    rule_bw = SecurityRule(
        id="rule_bw",
        order_index=51,
        name="Bandwidth Match Test",
        enabled=True,
        context=RuleContext(bandwidth_operator=">", bandwidth_kbps=500.0)
    )
    rule_burst = SecurityRule(
        id="rule_burst",
        order_index=52,
        name="Burst Match Test",
        enabled=True,
        context=RuleContext(rate_limit_burst=10)
    )

    matcher = RuleMatcher([rule_domain, rule_bw, rule_burst])

    # Flow should match none of them
    res = matcher.evaluate_flow(
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        port=80,
        protocol="TCP",
        bytes_count=10000
    )
    assert res.matched is False

    # Linter issues
    issues = RuleLinter.validate_rules([rule_domain, rule_bw, rule_burst])
    issue_types = [i.issue_type for i in issues]
    assert "unsupported_field" in issue_types


# =========================================================================
# 5. Sniffer: DoT Port 853 in BPF Filter & DNS Bypass Dispatch
# =========================================================================

def test_sniffer_bpf_filter_contains_port_853():
    """Verifies that NetworkSniffer.DEFAULT_BPF_FILTER contains port 853 for both TCP and UDP."""
    bpf = NetworkSniffer.DEFAULT_BPF_FILTER
    assert "port 853" in bpf
    assert "udp" in bpf and "tcp" in bpf
    # Ensure both UDP and TCP port groups include 853
    udp_part = bpf.split("or (tcp and")[0]
    tcp_part = bpf.split("or (tcp and")[1]
    assert "port 853" in udp_part, "Port 853 missing from UDP BPF filter"
    assert "port 853" in tcp_part, "Port 853 missing from TCP BPF filter"


@pytest.mark.asyncio
async def test_async_sniffer_dispatch_records_dns_bypass_events(monkeypatch):
    """Verifies that _async_sniffer_dispatch records DNS bypass events to DB and sends alerts."""
    recorded_events = []
    alerted_events = []

    mock_db = MagicMock()
    async def fake_record_event(ev):
        recorded_events.append(ev)
    mock_db.record_event = fake_record_event

    mock_notifier = MagicMock()
    async def fake_send_alert(ev):
        alerted_events.append(ev)
    mock_notifier.send_alert = fake_send_alert

    monkeypatch.setattr("keenguard.web.workers.get_db", lambda: mock_db)
    monkeypatch.setattr("keenguard.web.workers.notifier", mock_notifier)

    dot_event = {
        "event_type": "dot_bypass",
        "severity": "warning",
        "source_mac": "11:22:33:44:55:66",
        "source_ip": "192.168.1.100",
        "target_ip": "1.1.1.1",
        "description": "DoT bypass detected to Cloudflare 1.1.1.1:853"
    }

    await _async_sniffer_dispatch(dot_event)
    await asyncio.sleep(0.05)

    assert len(recorded_events) == 1
    assert recorded_events[0].event_type == "dot_bypass"
    assert recorded_events[0].severity == "warning"

    assert len(alerted_events) == 1
    assert alerted_events[0].event_type == "dot_bypass"
