"""Tests for Smart TV Wake Forensics: TTL, Day/Night modes, and PCAP assembly."""
import pytest
import time
from unittest.mock import AsyncMock, patch
from keenguard.core.forensics import ForensicsEngine
from keenguard.db.models import DeviceRecord, SecurityEvent
from scapy.all import Ether, IP

@pytest.mark.asyncio
async def test_tv_trigger_ttl_expiration():
    mock_db = AsyncMock()
    forensics = ForensicsEngine()

    tv_mac = "AA:BB:CC:DD:EE:01"
    tv_ip = "192.168.1.110"

    # Register an old trigger from 300 seconds ago (5 mins ago)
    old_ts = time.time() - 300.0
    forensics.recent_triggers.append({
        "timestamp": "2026-09-12T12:00:00Z",
        "timestamp_float": old_ts,
        "event_type": "wol_wake",
        "source_mac": "11:22:33:44:55:66",
        "source_ip": "192.168.1.50",
        "target_mac": tv_mac,
        "description": "Stale Wake-on-LAN"
    })

    # Device record with 0s post record for fast test
    tv_dev = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="LivingRoom-TV",
        profile="smart_tv",
        tv_pre_record_seconds=10,
        tv_post_record_seconds=0,
        tv_day_mode="all"
    )
    mock_db.get_device = AsyncMock(return_value=tv_dev)

    # Force night mode to ensure event is recorded
    with patch("keenguard.core.forensics.db", mock_db):
        with patch.object(forensics, "is_night_time", return_value=True):
            await forensics._handle_tv_wake(mac=tv_mac, ip=tv_ip, hostname=tv_dev.hostname)

    mock_db.record_event.assert_called_once()
    event = mock_db.record_event.call_args[0][0]
    # The stale trigger must NOT be blamed; it was expired by TTL
    assert event.details["is_autonomous"] is True
    assert event.details["culprit_mac"] is None

@pytest.mark.asyncio
async def test_tv_daytime_autonomous_only_filter():
    mock_db = AsyncMock()
    forensics = ForensicsEngine()

    tv_mac = "AA:BB:CC:DD:EE:02"
    tv_ip = "192.168.1.112"

    tv_dev = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="Kitchen-TV",
        profile="smart_tv",
        tv_day_mode="autonomous_only",
        tv_pre_record_seconds=5,
        tv_post_record_seconds=0
    )
    mock_db.get_device = AsyncMock(return_value=tv_dev)

    # Case 1: Fresh user trigger (AirPlay 5 seconds ago) during day
    now = time.time()
    forensics.recent_triggers.append({
        "timestamp": "2026-09-12T14:00:00Z",
        "timestamp_float": now - 5.0,
        "event_type": "airplay_wake",
        "source_mac": "77:88:99:AA:BB:CC",
        "source_ip": "192.168.1.101",
        "target_mac": tv_mac,
        "description": "AirPlay stream from mobile device"
    })

    with patch("keenguard.core.forensics.db", mock_db):
        with patch.object(forensics, "is_night_time", return_value=False):
            # Daytime user-initiated wake -> MUST NOT generate alert / event
            await forensics._handle_tv_wake(mac=tv_mac, ip=tv_ip, hostname=tv_dev.hostname)
            mock_db.record_event.assert_not_called()

            # Case 2: Autonomous wake during day (no triggers) -> MUST generate alert
            forensics.recent_triggers.clear()
            await forensics._handle_tv_wake(mac=tv_mac, ip=tv_ip, hostname=tv_dev.hostname)
            mock_db.record_event.assert_called_once()
            event = mock_db.record_event.call_args[0][0]
            assert event.details["is_autonomous"] is True

@pytest.mark.asyncio
async def test_tv_combined_pre_post_pcap_dump(tmp_path):
    mock_db = AsyncMock()
    forensics = ForensicsEngine()

    tv_mac = "AA:BB:CC:DD:EE:03"
    tv_ip = "192.168.1.115"

    tv_dev = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="Bedroom-TV",
        profile="smart_tv",
        tv_pre_record_seconds=15,
        tv_post_record_seconds=0
    )
    mock_db.get_device = AsyncMock(return_value=tv_dev)

    from keenguard.core.sniffer import sniffer
    dummy_pkt = Ether(src=tv_mac, dst="FF:FF:FF:FF:FF:FF") / IP(src=tv_ip, dst="255.255.255.255")
    sniffer.global_buffer.add(dummy_pkt)
    
    with patch("keenguard.core.forensics.db", mock_db):
        with patch("keenguard.core.forensics.wrpcap") as mock_wrpcap:
            with patch.object(forensics, "is_night_time", return_value=True):
                await forensics._handle_tv_wake(mac=tv_mac, ip=tv_ip, hostname=tv_dev.hostname)

                assert mock_wrpcap.called
                saved_packets = mock_wrpcap.call_args[0][1]
                assert len(saved_packets) >= 1
