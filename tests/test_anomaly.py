"""Tests for anomaly detection: UPnP holes, camera leaks, and ARP sweeps."""
import pytest
import time
from keenguard.core.anomaly import AnomalyDetector
from keenguard.core.keenetic import UPnPMapping, keenetic_client
from keenguard.db.models import DeviceRecord
from keenguard.db.database import Database

@pytest.mark.asyncio
async def test_upnp_camera_detection(tmp_path):
    test_db = Database(db_path=tmp_path / "test.db")
    await test_db.init_db()

    # Enable mock mode for Keenetic
    keenetic_client.mock_mode = True
    keenetic_client._mock_upnp = [
        {"interface": "ISP", "protocol": "tcp", "ext_port": 554, "int_ip": "192.168.1.150", "int_port": 554, "description": "IP-Camera RTSP"}
    ]

    detector = AnomalyDetector(database=test_db)
    devices = {
        "C4:2F:90:11:22:33": DeviceRecord(
            mac="C4:2F:90:11:22:33",
            ip="192.168.1.150",
            hostname="Backyard-Camera",
            profile="camera"
        )
    }

    # Run check
    await detector.check_upnp_anomalies(await keenetic_client.get_upnp_mappings(), devices)

    # After check, UPnP mapping should be deleted from Keenetic client
    remaining = await keenetic_client.get_upnp_mappings()
    assert len(remaining) == 0

@pytest.mark.asyncio
async def test_arp_scan_detection(tmp_path):
    test_db = Database(db_path=tmp_path / "test2.db")
    await test_db.init_db()
    detector = AnomalyDetector(database=test_db)
    src_ip = "192.168.1.75"
    src_mac = "AA:BB:CC:DD:EE:FF"

    # Simulate scanning 12 different IP addresses within 1 second
    for i in range(1, 13):
        await detector.record_arp_probe(src_mac, src_ip, f"192.168.1.{i}")

    # Verify that a lan_scan security event was recorded
    events = await test_db.get_recent_events()
    assert len(events) == 1
    assert events[0].event_type == "lan_scan"
    assert events[0].source_ip == src_ip
    assert events[0].source_mac == src_mac

@pytest.mark.asyncio
async def test_router_gateway_arp_probes_ignored(tmp_path):
    test_db = Database(db_path=tmp_path / "test_router.db")
    await test_db.init_db()
    detector = AnomalyDetector(database=test_db)

    keenetic_client.router_ips.add("192.168.2.1")
    keenetic_client.router_macs.add("52:FF:20:00:00:02")

    # Simulate router probing 15 hosts on Bridge1 (192.168.2.1)
    for i in range(2, 18):
        await detector.record_arp_probe("52:FF:20:00:00:02", "192.168.2.1", f"192.168.2.{i}")

    # Also simulate router probing on Bridge0 (192.168.1.1)
    for i in range(2, 18):
        await detector.record_arp_probe("50:FF:20:00:00:01", "192.168.1.1", f"192.168.1.{i}")

    # Verify NO lan_scan events are created for the router
    events = await test_db.get_recent_events()
    assert len(events) == 0
