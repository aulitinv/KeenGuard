"""Tests for MAC conflict and ARP spoofing detection."""
import pytest
import time
from unittest.mock import AsyncMock
from keenguard.core.anomaly import AnomalyDetector
from keenguard.db.models import SecurityEvent
from keenguard.config import settings

@pytest.mark.asyncio
async def test_arp_spoofing_two_macs_claim_same_ip():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    ip_target = "192.168.1.100"
    mac_legit = "AA:BB:CC:11:22:33"
    mac_attacker = "DE:AD:BE:EF:00:01"

    # 1. Legit device announces IP
    await detector.check_mac_ip_binding(mac=mac_legit, ip=ip_target)
    mock_db.record_event.assert_not_called()

    # 2. Attacker announces same IP 2 seconds later (within 30s window)
    await detector.check_mac_ip_binding(mac=mac_attacker, ip=ip_target)
    mock_db.record_event.assert_called_once()
    event = mock_db.record_event.call_args[0][0]
    assert isinstance(event, SecurityEvent)
    assert event.event_type == "arp_spoofing"
    assert event.severity == "critical"
    assert event.target_mac == mac_attacker
    assert event.target_ip == ip_target
    assert event.details["conflicting_mac"] == mac_legit

@pytest.mark.asyncio
async def test_mac_conflict_one_mac_two_ips():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    mac = "AA:BB:CC:55:66:77"
    ip1 = "192.168.1.101"
    ip2 = "192.168.1.102"

    # 1. MAC on IP1
    await detector.check_mac_ip_binding(mac=mac, ip=ip1)
    mock_db.record_event.assert_not_called()

    # 2. Same MAC on IP2 3 seconds later
    await detector.check_mac_ip_binding(mac=mac, ip=ip2)
    mock_db.record_event.assert_called_once()
    event = mock_db.record_event.call_args[0][0]
    assert event.event_type == "mac_conflict"
    assert event.severity == "warning"
    assert event.target_mac == mac
    assert event.target_ip == ip2
    assert event.details["conflicting_ip"] == ip1

@pytest.mark.asyncio
async def test_mac_conflict_detection_toggle():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    orig_setting = settings.mac_conflict_detection_enabled
    try:
        settings.mac_conflict_detection_enabled = False
        await detector.check_mac_ip_binding(mac="AA:11:22:33:44:55", ip="192.168.1.50")
        await detector.check_mac_ip_binding(mac="BB:11:22:33:44:55", ip="192.168.1.50")
        mock_db.record_event.assert_not_called()
    finally:
        settings.mac_conflict_detection_enabled = orig_setting
