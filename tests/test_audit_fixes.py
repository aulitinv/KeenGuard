"""Unit tests validating fixes for issues identified in the audit report."""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from keenguard.core.classifier import DeviceClassifier
from keenguard.core.domain_analyzer import DomainAnalyzer
from keenguard.core.sniffer import PacketRingBuffer
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord
from keenguard.web.app import app, create_tracked_task, _background_tasks


def test_classify_iot_trust_tier_generator_fix():
    """Verify BUG 1 fix: generator logic correctly identifies controller vs appliance vs sensor."""
    # Local hub (HomeAssistant)
    d_sprut = DeviceRecord(mac="AA:BB:CC:11:22:33", ip="192.168.1.50", hostname="HomeAssistant-Controller")
    res_sprut = DeviceClassifier.classify_iot_trust_tier(d_sprut)
    assert res_sprut["tier"] == "controller"
    assert res_sprut["wan_needed"] is True

    # Zigbee bridge
    d_zigbee = DeviceRecord(mac="AA:BB:CC:11:22:34", ip="192.168.1.101", custom_name="Zigbee2MQTT Bridge")
    res_zigbee = DeviceClassifier.classify_iot_trust_tier(d_zigbee)
    assert res_zigbee["tier"] == "controller"

    # Cloud appliance (Robot vacuum)
    d_vac = DeviceRecord(mac="AA:BB:CC:11:22:35", ip="192.168.1.102", hostname="smart-vacuum-cleaner")
    res_vac = DeviceClassifier.classify_iot_trust_tier(d_vac)
    assert res_vac["tier"] == "cloud_appliance"

    # Pure local sensor
    d_sensor = DeviceRecord(mac="AA:BB:CC:11:22:36", ip="192.168.1.103", hostname="soil-moisture-sensor")
    res_sensor = DeviceClassifier.classify_iot_trust_tier(d_sensor)
    assert res_sensor["tier"] == "pure_local"


def test_oui_database_expansion():
    """Verify OUI database expansion covers major IoT, camera, and TV vendors."""
    # Tuya
    v_tuya, p_tuya, _ = DeviceClassifier.classify("10:5A:F7:00:11:22")
    assert "Tuya" in v_tuya
    assert p_tuya == "iot"

    # Hikvision
    v_hik, p_hik, _ = DeviceClassifier.classify("C4:2F:90:AA:BB:CC")
    assert "Hikvision" in v_hik
    assert p_hik == "camera"

    # Dahua
    v_dahua, p_dahua, _ = DeviceClassifier.classify("3C:EF:8C:11:22:33")
    assert "Dahua" in v_dahua
    assert p_dahua == "camera"

    # Espressif
    v_esp, p_esp, _ = DeviceClassifier.classify("24:0A:C4:11:22:33")
    assert "Espressif" in v_esp
    assert p_esp == "iot"


@pytest.mark.asyncio
async def test_domain_analyzer_sync_threat_intelligence_streaming():
    """Verify CRITICAL #1 fix: blocklist parser skips header comments and parses real domains."""
    await db.init_db()
    analyzer = DomainAnalyzer()

    mock_blocklist_content = """# Title: Big Blocklist
# Description: Test blocklist
# Version: 2026.01
# More comment lines...
0.0.0.0 malicious-malware-test.org
0.0.0.0 tracking-telemetry.example.com # inline comment
||adserver-popup.net^
# Footer comment
"""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = mock_blocklist_content

    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_resp)):
        res = await analyzer.update_signatures_from_online()
        assert res["success"] is True
        assert res["updated_count"] > 0
        assert "malicious-malware-test.org" in analyzer._db_signatures
        assert "adserver-popup.net" in analyzer._db_signatures
        assert "# title:" not in analyzer._db_signatures


def test_sniffer_per_device_ring_buffer_and_filtering():
    """Verify CRITICAL #2 fix: packet ring buffer supports device-specific storage and filtering."""
    buf = PacketRingBuffer(max_packets=10)

    p1 = {"mac": "AA:11:22:33:44:55", "ip": "192.168.1.10", "proto": "TCP"}
    p2 = {"mac": "BB:11:22:33:44:55", "ip": "192.168.1.20", "proto": "UDP"}
    p3 = {"mac": "AA:11:22:33:44:55", "ip": "192.168.1.10", "proto": "DNS"}

    buf.add(p1)
    buf.add(p2)
    buf.add(p3)

    assert len(buf) == 3
    filtered = buf.get_packets(filter_func=lambda p: p.get("mac") == "AA:11:22:33:44:55")
    assert len(filtered) == 2
    assert all(p["mac"] == "AA:11:22:33:44:55" for p in filtered)


@pytest.mark.asyncio
async def test_database_traffic_summary_and_dns_counts():
    """Verify BUG 4 & QUALITY 3: SQL aggregation and targeted DNS counts query."""
    await db.init_db()

    dummy_mac = "AA:BB:CC:11:22:33"
    dummy_ip = "192.168.1.10"

    # Record traffic snapshot with known rates
    await db.record_traffic_snapshot(dummy_mac, 10000, 5000, 450.0, 160.0)

    # Test get_network_traffic_summary works and aggregates rates
    summary = await db.get_network_traffic_summary(limit=24)
    assert isinstance(summary, list)
    assert len(summary) >= 1
    assert summary[0]["total_rx_kbps"] >= 450.0
    assert summary[0]["total_tx_kbps"] >= 160.0

    # Record targeted DNS queries
    await db.record_dns_query("example.com", mac=dummy_mac, ip=dummy_ip)

    # Test get_dns_device_counts_for_domains
    counts = await db.get_dns_device_counts_for_domains(["test-nonexistent.org", "example.com"])
    assert isinstance(counts, dict)
    assert "example.com" in counts
    assert len(counts["example.com"]) >= 1
    assert counts["example.com"][0]["mac"] == dummy_mac
    assert "test-nonexistent.org" not in counts


@pytest.mark.asyncio
async def test_background_task_retention():
    """Verify BUG 2 fix: create_tracked_task retains reference and removes it on completion."""
    started = asyncio.Event()

    async def sample_coro():
        started.set()
        await asyncio.sleep(0.05)
        return "done"

    task = create_tracked_task(sample_coro())
    assert task in _background_tasks

    await started.wait()
    await task
    # Small yield to let done_callback run
    await asyncio.sleep(0.01)
    assert task not in _background_tasks


def test_smarthome_overview_safe_category():
    """Verify BUG 3 fix: /api/smarthome/overview does not raise KeyError on unknown categories."""
    client = TestClient(app)

    # Inject device with custom profile
    with patch("keenguard.core.classifier.DeviceClassifier.classify_smarthome_device", return_value="novel_smart_gadget"):
        response = client.get("/api/smarthome/overview")
        assert response.status_code == 200
        data = response.json()
        assert "categories" in data
        assert "novel_smart_gadget" in data["categories"]


def test_websocket_live_bidirectional_commands():
    """Verify Issue #6 fix: /ws/live endpoint processes and responds to commands."""
    client = TestClient(app)

    with client.websocket_connect("/ws/live") as ws:
        # Ping
        ws.send_text(json.dumps({"command": "ping"}))
        resp = ws.receive_json()
        assert resp.get("type") == "pong"
        assert "timestamp" in resp

        # Get status
        ws.send_text(json.dumps({"command": "get_status"}))
        resp_status = ws.receive_json()
        assert resp_status.get("type") == "status_response"
        assert "connected" in resp_status

        # Plain text ping
        ws.send_text("ping")
        resp_plain = ws.receive_json()
        assert resp_plain.get("type") == "pong"


@pytest.mark.asyncio
async def test_keenetic_checklist_compatibility():
    """Verify KeeneticClient aliases and checklist models."""
    from keenguard.core.keenetic import keenetic_client, UPnPMapping
    from keenguard.core.checklist import SecurityChecklistEvaluator

    # 1. Test get_upnp_table alias
    assert hasattr(keenetic_client, "get_upnp_table")
    assert keenetic_client.get_upnp_table == keenetic_client.get_upnp_mappings

    # 2. Test Wi-Fi security dual-key compatibility
    wifi = await keenetic_client.get_wifi_security()
    assert "access_points" in wifi
    assert "networks" in wifi
    assert wifi["access_points"] == wifi["networks"]

    # 3. Test Firmware updates dual-key compatibility
    fw = await keenetic_client.check_firmware_updates()
    assert "has_update" in fw
    assert "update_available" in fw
    assert "latest_version" in fw
    assert "available_version" in fw

    # 4. Test Checklist with UPnPMapping object
    mock_mapping = UPnPMapping(
        interface="Bridge0",
        protocol="tcp",
        ext_port=8080,
        int_ip="192.168.1.100",
        int_port=8080,
        description="Test camera rule"
    )
    with patch.object(keenetic_client, "get_upnp_mappings", return_value=[mock_mapping]):
        res = await SecurityChecklistEvaluator.evaluate_checklist()
        assert res["status"] == "ok"
        cam_item = next(i for i in res["items"] if i["id"] == "camera_security_upnp")
        assert cam_item["status"] == "critical"
        assert "КРИТИЧЕСКИЙ РИСК" in cam_item["live_status"]

