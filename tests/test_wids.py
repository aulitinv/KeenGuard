"""Unit tests for Wireless Intrusion Detection System (WIDS)."""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock

from keenguard.core.wids import (
    DeauthEvent,
    DeauthFloodDetector,
    PmfSecurityAuditor,
    RogueApDetector,
    WIDSService,
    wids_service,
)


def test_deauth_log_parsing():
    detector = DeauthFloodDetector()

    line = "Nov 22 17:30:01 wlan0: Station AA:BB:CC:DD:EE:01 deauthenticated due to local deauth request"
    ev = detector.parse_log_line(line, reference_year=2026)
    assert ev is not None
    assert ev.mac == "AA:BB:CC:DD:EE:01"
    assert ev.interface == "wlan0"

    line2 = "2026-11-22T17:30:05 WifiMaster0: AP-STA-DISCONNECTED 11:22:33:44:55:66"
    ev2 = detector.parse_log_line(line2)
    assert ev2 is not None
    assert ev2.mac == "11:22:33:44:55:66"

    line_ignore = "Nov 22 17:30:02 dhcp: DHCPACK(br0) 192.168.1.50 aa:bb:cc:dd:ee:01"
    assert detector.parse_log_line(line_ignore) is None


def test_deauth_flood_detection():
    detector = DeauthFloodDetector(burst_threshold=5, window_seconds=10)

    base = datetime(2026, 11, 22, 17, 30, 0, tzinfo=timezone.utc)
    # Generate 6 deauth events within 5 seconds
    lines = [
        f"{(base + timedelta(seconds=i)).isoformat()} wlan0: Station AA:BB:CC:DD:EE:{i:02d} deauthenticated due to local deauth request"
        for i in range(6)
    ]

    floods = detector.analyze_logs(lines)
    assert len(floods) == 1
    assert floods[0]["type"] == "wifi_deauth_flood"
    assert floods[0]["event_count"] == 6
    assert floods[0]["severity"] == "critical"
    assert len(floods[0]["affected_macs"]) == 6


def test_deauth_no_flood_below_threshold():
    detector = DeauthFloodDetector(burst_threshold=5, window_seconds=10)

    base = datetime(2026, 11, 22, 17, 30, 0, tzinfo=timezone.utc)
    # Only 2 deauth events 30 seconds apart
    lines = [
        f"{base.isoformat()} wlan0: Station AA:BB:CC:DD:EE:01 deauthenticated due to local deauth request",
        f"{(base + timedelta(seconds=35)).isoformat()} wlan0: Station AA:BB:CC:DD:EE:01 deauthenticated due to local deauth request"
    ]

    floods = detector.analyze_logs(lines)
    assert len(floods) == 0


def test_pmf_auditor_all_required():
    networks = [
        {"ssid": "SecureHome", "band": "5 ГГц", "security": "WPA3-SAE", "pmf": "required"},
        {"ssid": "SecureHome-2G", "band": "2.4 ГГц", "security": "WPA3-SAE", "pmf": "mandatory"}
    ]
    report = PmfSecurityAuditor.audit(networks)
    assert report["status"] == "ok"
    assert report["score"] == 100
    assert report["grade"] == "A+"
    assert report["has_wpa3"] is True


def test_pmf_auditor_optional():
    networks = [
        {"ssid": "Home-Mixed", "band": "2.4 ГГц", "security": "WPA3 / WPA2 mixed", "pmf": "optional"}
    ]
    report = PmfSecurityAuditor.audit(networks)
    assert report["status"] == "warning"
    assert report["grade"] == "B"
    assert report["score"] == 80


def test_pmf_auditor_disabled():
    networks = [
        {"ssid": "LegacyNet", "band": "2.4 ГГц", "security": "WPA2-PSK", "pmf": "disabled"}
    ]
    report = PmfSecurityAuditor.audit(networks)
    assert report["status"] == "critical"
    assert report["grade"] == "D"
    assert report["score"] == 45
    assert len(report["recommendations"]) > 0


def test_rogue_ap_detector_evil_twin():
    local_networks = [
        {"ssid": "Keenetic-Home", "bssid": "AA:BB:CC:00:11:22", "band": "5 ГГц"}
    ]
    scanned_aps = [
        # Normal neighbor
        {"ssid": "Neighbor-Wi-Fi", "bssid": "11:22:33:44:55:66", "channel": 1, "rssi": -85},
        # Evil Twin clone with same SSID but different BSSID!
        {"ssid": "Keenetic-Home", "bssid": "DE:AD:BE:EF:00:01", "channel": 6, "rssi": -55, "security": "WPA2"}
    ]

    incidents = RogueApDetector.detect(scanned_aps, local_networks)
    assert len(incidents) == 1
    assert incidents[0]["type"] == "wifi_evil_twin"
    assert incidents[0]["bssid"] == "DE:AD:BE:EF:00:01"
    assert incidents[0]["severity"] == "critical"
    assert "Keenetic-Home" in incidents[0]["title"]


def test_rogue_ap_detector_authorized_mesh():
    local_networks = [
        {"ssid": "Keenetic-Home", "bssid": "AA:BB:CC:00:11:22"}
    ]
    # Mesh extender BSSID authorized
    authorized = {"AA:BB:CC:00:11:22", "AA:BB:CC:00:11:33"}
    scanned_aps = [
        {"ssid": "Keenetic-Home", "bssid": "AA:BB:CC:00:11:33", "channel": 36, "rssi": -40}
    ]

    incidents = RogueApDetector.detect(scanned_aps, local_networks, authorized_bssids=authorized)
    assert len(incidents) == 0


@pytest.mark.asyncio
async def test_wids_service_integration():
    mock_router = AsyncMock()
    mock_router.get_wifi_security.return_value = {
        "networks": [
            {"ssid": "Keenetic-Home", "bssid": "AA:BB:CC:00:11:22", "pmf": "required", "security": "WPA3"}
        ]
    }
    mock_router.get_system_log.return_value = []
    mock_router.get_wlan_scan.return_value = []

    res = await wids_service.run_wids_audit(mock_router)
    assert res["score"] == 100
    assert res["grade"] == "A+"
    assert res["threats_count"] == 0
