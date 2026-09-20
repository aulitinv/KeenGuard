"""End-to-End integration tests for the full event detection and processing pipeline.

Validates the complete chain:
Raw Packet -> Sniffer -> Dissector/Detector -> Database (SQLite) -> WebSocket Broadcast -> Telegram Notifier
"""
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from scapy.all import Ether, IP, TCP, UDP, ARP, Raw

from keenguard.db.database import db
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.core.sniffer import sniffer
from keenguard.core.lan_tracker import lan_tracker
from keenguard.core.enums import EventType, Severity
from keenguard.web.ws import ws_manager
from keenguard.core.notifier import notifier
from keenguard.web.workers import _handle_sniffer_event, _handle_lan_violation


@pytest.mark.asyncio
async def test_e2e_lan_policy_violation_pipeline():
    """E2E test: packet to blocked port -> detection -> db record -> ws broadcast -> telegram alert."""
    src_mac = "AA:BB:CC:99:88:11"
    src_ip = "192.168.1.55"
    dst_ip = "192.168.1.1"

    # Seed source device in DB as Smart TV
    dev = DeviceRecord(
        mac=src_mac,
        ip=src_ip,
        hostname="LivingRoom-TV",
        profile="smart_tv",
        preset_id="preset_smart_tv",
        is_online=True
    )
    await db.upsert_device(dev)

    # Sync device into lan_tracker cache
    lan_tracker.update_devices_cache({src_mac: dev})

    # Craft synthetic packet: Smart TV connecting to blocked Telnet port 23
    pkt = Ether(src=src_mac, dst="00:11:22:33:44:55") / IP(src=src_ip, dst=dst_ip) / TCP(sport=54321, dport=23)

    broadcast_mock = AsyncMock()
    telegram_mock = AsyncMock()

    with patch.object(ws_manager, "broadcast", new=broadcast_mock), \
         patch.object(notifier, "send_alert", new=telegram_mock):

        # Feed packet to sniffer
        sniffer._process_packet(pkt)

        # Allow background asyncio tasks created by callback to run
        await asyncio.sleep(0.1)

        # 1. Verify DB storage
        recent_events = await db.get_recent_events(limit=5)
        matched_events = [e for e in recent_events if e.event_type == EventType.LAN_POLICY_VIOLATION.value and e.source_mac == src_mac]
        assert len(matched_events) >= 1
        ev = matched_events[0]
        assert ev.severity == Severity.CRITICAL.value
        assert "23" in ev.description

        # 2. Verify WebSocket broadcast occurred
        broadcast_mock.assert_awaited()
        ws_calls = [call.args[0] for call in broadcast_mock.await_args_list if isinstance(call.args[0], dict)]
        assert any(c.get("type") == "sniffer_event" and c.get("event", {}).get("violation_type") == "blocked_service" for c in ws_calls)

        # 3. Verify Telegram alert triggered for CRITICAL event
        telegram_mock.assert_awaited()


@pytest.mark.asyncio
async def test_e2e_wol_magic_packet_pipeline():
    """E2E test: Wake-on-LAN magic packet -> parsed -> event created -> db -> ws -> alert."""
    target_mac = "AA:BB:CC:99:88:22"
    target_ip = "192.168.1.56"

    dev = DeviceRecord(
        mac=target_mac,
        ip=target_ip,
        hostname="Bedroom-Media",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=False
    )
    await db.upsert_device(dev)

    # Build Wake-on-LAN Magic Packet payload: 6 * 0xFF + 16 * MAC bytes
    mac_bytes = bytes.fromhex(target_mac.replace(":", ""))
    magic_payload = (b"\xff" * 6) + (mac_bytes * 16)

    pkt = Ether(src="00:11:22:33:44:55", dst="FF:FF:FF:FF:FF:FF") / \
          IP(src="192.168.1.20", dst="255.255.255.255") / \
          UDP(sport=43210, dport=9) / \
          Raw(load=magic_payload)

    broadcast_mock = AsyncMock()
    telegram_mock = AsyncMock()

    with patch.object(ws_manager, "broadcast", new=broadcast_mock), \
         patch.object(notifier, "send_alert", new=telegram_mock):

        sniffer._process_packet(pkt)
        await asyncio.sleep(0.1)

        # 1. Verify DB event
        recent_events = await db.get_recent_events(limit=10)
        wol_events = [e for e in recent_events if e.event_type == EventType.WOL_WAKE.value and e.target_mac == target_mac]
        assert len(wol_events) >= 1
        ev = wol_events[0]
        assert ev.target_mac == target_mac

        # 2. Verify WebSocket broadcast
        broadcast_mock.assert_awaited()
        ws_calls = [call.args[0] for call in broadcast_mock.await_args_list if isinstance(call.args[0], dict)]
        assert any(c.get("type") == "sniffer_event" and c.get("event", {}).get("event_type") == EventType.WOL_WAKE.value for c in ws_calls)
