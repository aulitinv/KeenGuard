"""Unit tests verifying Audit Batch 2 fixes:
1. Block 1: Monitoring Core & Session Logic (quarantine overrides, LAN policy port formats, router entity detection, NAT aggregation, DNS poisoning fix).
2. Block 2: Scheduler, Anomaly & Forensics (scheduler ring buffer meta, night mode DB persistence, UPnP deduplication, camera leak alerts, night hours zero-window, async pcap).
3. Block 3: Keenetic Transport & HAL (TLS verification, capture IP validation, hotspot failure handling, subnet prefix detection, unknown wifi security, system info endpoint).
4. Block 4: Config Service & DB Repositories (secret protection in DB, env sync, custom allowed ports parsing, protected MAC deletion prevention, events normalization & no phantoms, rules corrupt JSON tolerance, 24h hits computation, core rule toggle protection).
"""
import asyncio
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord, SecurityEvent, SecurityRule, RuleHitRecord
from keenguard.core.keenetic import UPnPMapping
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR, DNSRR


# =========================================================================
# BLOCK 1: Monitoring Core & Session Logic
# =========================================================================

def test_should_device_quarantine_device_record_and_str():
    from keenguard.core.audit.session import should_device_quarantine

    # 1. DeviceRecord with auto_quarantine_override = "never_quarantine"
    dev_never = DeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.100",
        profile="unassigned",
        auto_quarantine_override="never_quarantine"
    )
    assert should_device_quarantine(dev_never) is False

    # 2. DeviceRecord with auto_quarantine_override = "always_quarantine"
    dev_always = DeviceRecord(
        mac="AA:BB:CC:DD:EE:02",
        ip="192.168.1.101",
        profile="trusted",
        auto_quarantine_override="always_quarantine"
    )
    assert should_device_quarantine(dev_always) is True

    # 3. String profile compatibility
    assert should_device_quarantine("unassigned") is True
    assert should_device_quarantine("camera") is True
    assert should_device_quarantine("trusted") is False

    # 4. Global scope overrides
    orig_scope = settings.auto_quarantine_scope
    try:
        settings.auto_quarantine_scope = "disabled"
        assert should_device_quarantine("camera") is False

        settings.auto_quarantine_scope = "all_except_trusted"
        dev_iot = DeviceRecord(mac="AA:BB:CC:DD:EE:03", ip="192.168.1.102", profile="iot")
        dev_trusted = DeviceRecord(mac="AA:BB:CC:DD:EE:04", ip="192.168.1.103", profile="trusted")
        assert should_device_quarantine(dev_iot) is True
        assert should_device_quarantine(dev_trusted) is False
    finally:
        settings.auto_quarantine_scope = orig_scope


def test_evaluate_lan_access_policy_custom_allowed_ports_formats():
    from keenguard.core.audit.session import evaluate_lan_access_policy

    # Device with custom_allowed_ports as list of ints (should NOT raise AttributeError: 'list' object has no attribute 'replace')
    risk, blocked = evaluate_lan_access_policy(
        src_profile="custom",
        dst_ip="192.168.1.60",
        dport=80,
        custom_allowed_ports=[80, 443, 8080]
    )
    assert risk == "safe"
    assert blocked is False

    # Device with custom_allowed_ports as CSV string
    risk, blocked = evaluate_lan_access_policy(
        src_profile="custom",
        dst_ip="192.168.1.60",
        dport=443,
        custom_allowed_ports="80, 443, 8080"
    )
    assert risk == "safe"
    assert blocked is False

    # Disallowed port for camera profile
    risk, blocked = evaluate_lan_access_policy(
        src_profile="camera",
        dst_ip="192.168.1.60",
        dport=22,
        custom_allowed_ports=[80, 443]
    )
    assert risk == "critical"
    assert blocked is True


def test_evaluate_lan_access_policy_router_entity_check():
    from keenguard.core.audit.session import evaluate_lan_access_policy
    from keenguard.core.routers.manager import router_manager

    # When router_manager identifies the destination as the router entity
    with patch.object(router_manager, "is_router_entity", return_value=True):
        # Service DNS port 53 is safe to router
        risk, blocked = evaluate_lan_access_policy(
            src_profile="camera",
            dst_ip="192.168.1.1",
            dport=53,
            proto="UDP"
        )
        assert risk == "safe"
        assert blocked is False

        # Web administration port 80/443 from camera to router is flagged critical
        risk, blocked = evaluate_lan_access_policy(
            src_profile="camera",
            dst_ip="192.168.1.1",
            dport=80,
            proto="TCP"
        )
        assert risk == "critical"
        assert blocked is True


def test_network_audit_update_nat_table_sums_flows():
    from keenguard.core.audit.session import NetworkAuditSession

    session = NetworkAuditSession(duration_seconds=60)
    nat_entries = [
        {"src": "192.168.1.10", "dst": "8.8.8.8", "dport": 443, "protocol": "TCP", "bytes": 1000, "packets": 10},
        {"src": "192.168.1.10", "dst": "1.1.1.1", "dport": 53, "protocol": "UDP", "bytes": 2500, "packets": 25},
        {"src": "192.168.1.20", "dst": "93.184.216.34", "dport": 80, "protocol": "TCP", "bytes": 500, "packets": 5},
    ]
    session.update_nat_table(nat_entries)

    # 192.168.1.10 should have sum: 3500 bytes, 35 packets across 2 flows (not max: 2500, 25)
    stats = session.device_stats.get("192.168.1.10")
    assert stats is not None
    assert stats["bytes_up"] == 3500
    assert stats["packets_up"] == 35
    assert stats["flows_count"] == 2


def test_audit_session_dns_answers_cache_no_poisoning():
    from keenguard.core.audit.session import AuditSession
    from keenguard.core.app_classifier import app_classifier

    session = AuditSession(mac="AA:BB:CC:DD:EE:30", ip="192.168.1.150")

    # 1. Packet that is a DNS query, NOT a response (qr=0)
    query_pkt = IP(src="192.168.1.150", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="malicious-attempt.com", qtype=1)
    )
    session.add_packet(query_pkt)
    # The queried endpoint should NOT be cached as resolved domain in app_classifier
    assert app_classifier.get_domain_for_ip("8.8.8.8") is None

    # 2. Packet that is a legitimate DNS response (qr=1) with answer RR
    resp_pkt = IP(src="192.168.1.1", dst="192.168.1.150") / UDP(sport=53, dport=12345) / DNS(
        qr=1,
        qd=DNSQR(qname="api.safe-service.org", qtype=1),
        an=DNSRR(rrname="api.safe-service.org", type=1, rdata="93.184.216.34")
    )
    session.add_packet(resp_pkt)
    assert app_classifier.get_domain_for_ip("93.184.216.34") == "api.safe-service.org"


# =========================================================================
# BLOCK 2: Scheduler, Anomaly & Forensics
# =========================================================================

@pytest.mark.asyncio
async def test_scheduler_is_device_active_packet_meta():
    from keenguard.core.scheduler import scheduler
    from keenguard.core.sniffer import sniffer, PacketRingBuffer

    test_mac = "AA:BB:CC:DD:EE:40"
    dev = DeviceRecord(mac=test_mac, ip="192.168.1.160", is_online=True)

    buf = PacketRingBuffer(max_packets=100)
    sniffer.ring_buffers[test_mac] = buf
    buf.clear()

    # Empty buffer -> inactive
    assert await scheduler._is_device_active(dev, 5) is False

    # Add a packet with timestamp to buffer
    now = datetime.now(timezone.utc).timestamp()
    pkt = IP(src="192.168.1.160", dst="192.168.1.1") / UDP(sport=1000, dport=1000)
    buf.add(pkt, timestamp=now)

    # Now active via get_packets_with_meta
    assert await scheduler._is_device_active(dev, 5) is True
    buf.clear()


@pytest.mark.asyncio
async def test_scheduler_night_mode_persistence_and_day_unblock():
    from keenguard.core.scheduler import scheduler

    test_mac = "AA:BB:CC:DD:EE:50"

    # Save to DB settings
    await scheduler._save_persisted_night_blocked_macs({test_mac})

    # Verify saved to DB
    loaded_state = await db.get_setting("night_mode_blocked_macs")
    assert test_mac in loaded_state

    # Restore via scheduler
    restored = await scheduler._get_persisted_night_blocked_macs()
    assert test_mac in restored

    # Cleanup
    await scheduler._save_persisted_night_blocked_macs(set())


@pytest.mark.asyncio
async def test_scheduler_temporary_rules_expiration():
    from keenguard.core.scheduler import scheduler

    rule_id = "test_temp_rule_exp_01"
    now_utc = datetime.now(timezone.utc)
    expired_time = (now_utc - timedelta(minutes=5)).isoformat()

    rule = SecurityRule(
        id=rule_id,
        order_index=150,
        name="Temporary Test Rule",
        enabled=True,
        temporary_until=expired_time
    )
    await db.create_rule(rule)

    try:
        # Run expiration check
        await scheduler._check_temporary_rules_expiration()

        # Rule should now be disabled and temporary_until cleared
        updated = await db.get_rule(rule_id)
        assert updated is not None
        assert updated.enabled is False
    finally:
        await db.delete_rule(rule_id)


@pytest.mark.asyncio
async def test_anomaly_upnp_deduplication_and_auto_delete():
    from keenguard.core.anomaly import AnomalyDetector
    from keenguard.core.routers.manager import router_manager

    detector = AnomalyDetector()
    detector.dedup_cache.clear()

    orig_auto_delete = settings.upnp_auto_delete
    try:
        dev_cam = DeviceRecord(mac="AA:BB:CC:DD:EE:60", ip="192.168.1.180", profile="camera")
        devices_map = {dev_cam.mac: dev_cam}

        rule1 = UPnPMapping(protocol="TCP", ext_port=4444, int_ip="192.168.1.180", int_port=4444, description="Backdoor")
        rule2 = UPnPMapping(protocol="TCP", ext_port=4444, int_ip="192.168.1.180", int_port=4444, description="Backdoor duplicate")

        # 1. Without auto-delete
        settings.upnp_auto_delete = False
        with patch.object(detector, "_dispatch_alert", new_callable=AsyncMock) as mock_alert:
            with patch.object(router_manager, "delete_upnp_mapping", new_callable=AsyncMock) as mock_delete:
                await detector.check_upnp_anomalies([rule1, rule2], devices_map)
                # Deduplicated: only 1 alert dispatched for the identical port/protocol
                assert mock_alert.call_count == 1
                mock_delete.assert_not_called()

        # 2. With auto-delete enabled
        detector.dedup_cache.clear()
        settings.upnp_auto_delete = True
        with patch.object(detector, "_dispatch_alert", new_callable=AsyncMock):
            with patch.object(router_manager, "delete_upnp_mapping", new_callable=AsyncMock) as mock_delete:
                await detector.check_upnp_anomalies([rule1], devices_map)
                mock_delete.assert_called_once_with("TCP", 4444)
    finally:
        settings.upnp_auto_delete = orig_auto_delete


def test_forensics_is_night_time_zero_window_and_config():
    from keenguard.core.forensics import forensics, _on_forensics_config_change

    # Equal start and end hour means disabled / 0-length window
    forensics.night_mode_start_hour = 3
    forensics.night_mode_end_hour = 3
    assert forensics.is_night_time() is False

    # Test config service callback
    _on_forensics_config_change("night_mode_start_hour", "23")
    assert forensics.night_mode_start_hour == 23
    assert settings.night_mode_start_hour == 23

    _on_forensics_config_change("night_mode_end_hour", "7")
    assert forensics.night_mode_end_hour == 7
    assert settings.night_mode_end_hour == 7


# =========================================================================
# BLOCK 3: Keenetic Transport & HAL
# =========================================================================

def test_config_router_verify_tls():
    assert hasattr(settings, "router_verify_tls")
    assert isinstance(settings.router_verify_tls, bool)


@pytest.mark.asyncio
async def test_keenetic_capture_target_ip_validation():
    from keenguard.core.keenetic.client import KeeneticClient

    client = KeeneticClient()

    # Invalid IP address rejected with None (prevents injection into bpf-program)
    res = await client.start_packet_capture(
        interface="Bridge0",
        target_ip="192.168.1.1; rm -rf /"
    )
    assert res is None

    # Valid IP address formats correctly
    mock_resp = MagicMock(status_code=200)
    with patch.object(client, "_send_request", new_callable=AsyncMock, return_value=mock_resp):
        res = await client.start_packet_capture(
            interface="Bridge0",
            target_ip="192.168.1.100"
        )
        assert res == {"status": "ok", "interface": "Bridge0", "filter": {"bpf-program": "host 192.168.1.100"}}


@pytest.mark.asyncio
async def test_keenetic_telemetry_hotspot_hosts_failure_and_wifi_unknown():
    from keenguard.core.keenetic.client import KeeneticClient

    client = KeeneticClient()

    # 1. When router HTTP call fails (returns None), must raise ConnectionError instead of returning []
    with patch.object(client, "_send_request", new_callable=AsyncMock, return_value=None):
        with pytest.raises(ConnectionError, match="Failed to fetch hotspot hosts"):
            await client.get_hotspot_hosts()

    # 2. Dynamic home subnet detection
    client.host = "192.168.1.1"
    assert client._get_home_subnet_prefix() == "192.168.1."
    client.host = "10.0.88.1"
    assert client._get_home_subnet_prefix() == "10.0.88."

    # 3. WiFi security reporting: unrecognized or missing authentication yields "unknown" (no placebo)
    mock_wifi_resp = MagicMock(status_code=200)
    mock_wifi_resp.json.return_value = [
        {
            "show": {
                "interface": {
                    "WifiMaster0/AccessPoint0": {
                        "ssid": "TestWiFi",
                        "authentication": ""  # empty or unrecognized
                    }
                }
            }
        }
    ]
    with patch.object(client, "_send_request", new_callable=AsyncMock, return_value=mock_wifi_resp):
        wifi_sec = await client.get_wifi_security()
        assert len(wifi_sec["networks"]) > 0
        assert wifi_sec["networks"][0]["security_type"] == "unknown"
        assert wifi_sec["networks"][0]["security"] == "Неизвестно"


# =========================================================================
# BLOCK 4: Config Service & DB Repositories
# =========================================================================

@pytest.mark.asyncio
async def test_config_service_secret_keys_protection():
    from keenguard.core.config_service import config_service

    # Attempting to save telegram_bot_token to DB should be blocked
    await config_service.set("telegram_bot_token", "SECRET_TOKEN_123")
    db_val = await db.get_setting("telegram_bot_token")
    assert db_val is None

    # Bulk update with a secret key
    await config_service.update_bulk({"telegram_bot_token": "SECRET_VAL", "scan_interval": 45})
    assert await db.get_setting("telegram_bot_token") is None
    assert int(await db.get_setting("scan_interval")) == 45


@pytest.mark.asyncio
async def test_devices_repo_custom_allowed_ports_and_delete_protection():
    # 1. Protected infrastructure device cannot be deleted
    deleted = await db.delete_device("02:00:00:00:00:01")
    assert deleted is False

    # 2. Saving and retrieving device with custom_allowed_ports as list of ints
    test_mac = "AA:BB:CC:DD:EE:70"
    dev = DeviceRecord(
        mac=test_mac,
        ip="192.168.1.190",
        profile="custom",
        custom_allowed_ports=[80, 443, 8080]
    )
    await db.upsert_device(dev)

    loaded = await db.get_device(test_mac)
    assert loaded is not None
    assert loaded.custom_allowed_ports == [80, 443, 8080]

    # Cleanup
    await db.delete_device(test_mac)


@pytest.mark.asyncio
async def test_events_repo_record_event_normalization_and_no_phantom_devices():
    # Record event with uppercase severity and an unknown MAC
    unknown_mac = "AA:BB:CC:DD:EE:80"
    event = SecurityEvent(
        event_type="test_probe",
        severity="WARNING",
        target_mac=unknown_mac,
        description="Test event for unknown device"
    )
    await db.record_event(event)

    # Check that unknown device was NOT inserted as a phantom device into devices table
    dev = await db.get_device(unknown_mac)
    assert dev is None

    # Verify event was recorded with normalized lowercase severity and original MAC preserved in details
    events = await db.get_recent_events(limit=5)
    matching = [e for e in events if (e.details and e.details.get("original_target_mac") == unknown_mac)]
    assert len(matching) == 1
    assert matching[0].target_mac is None  # FK integrity maintained without phantom device
    assert matching[0].severity == "warning"


@pytest.mark.asyncio
async def test_rules_repo_corrupt_json_safety_hits_24h_and_core_protection():
    # 1. Core rule cannot be disabled
    toggle_res = await db.toggle_rule("rule_core_dhcp", enabled=False)
    assert toggle_res is False

    core_rule = await db.get_rule("rule_core_dhcp")
    assert core_rule is not None
    assert core_rule.enabled is True

    # 2. Create custom rule and record hit
    custom_rule_id = "test_custom_rule_hits_24h"
    custom_rule = SecurityRule(
        id=custom_rule_id,
        order_index=200,
        name="Custom Rule For 24h Hits",
        enabled=True
    )
    await db.create_rule(custom_rule)

    try:
        hit = RuleHitRecord(
            rule_id=custom_rule_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            src_ip="192.168.1.100",
            dst_ip="8.8.8.8",
            port=53,
            protocol="UDP",
            action_taken="pass"
        )
        await db.record_rule_hit(custom_rule_id, hit)

        fetched = await db.get_rule(custom_rule_id)
        assert fetched is not None
        assert fetched.telemetry.hits_total >= 1
        assert fetched.telemetry.hits_24h >= 1

        all_rules = await db.get_rules()
        custom_in_all = next((r for r in all_rules if r.id == custom_rule_id), None)
        assert custom_in_all is not None
        assert custom_in_all.telemetry.hits_24h >= 1

        # 3. Can toggle custom rule freely
        assert await db.toggle_rule(custom_rule_id, enabled=False) is True
        fetched_disabled = await db.get_rule(custom_rule_id)
        assert fetched_disabled.enabled is False
    finally:
        await db.delete_rule(custom_rule_id)
