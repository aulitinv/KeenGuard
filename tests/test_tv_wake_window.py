import asyncio
import time
import pytest
from scapy.all import Ether, IP, UDP
from httpx import AsyncClient, ASGITransport

from keenguard.core.sniffer import PacketRingBuffer, NetworkSniffer
from keenguard.core.forensics import ForensicsEngine
from keenguard.config import settings
from keenguard.db.database import db
from keenguard.web.app import app, lifespan


def test_packet_ring_buffer_age_pruning_and_cutoff():
    # max_age_seconds = 10s
    buf = PacketRingBuffer(max_packets=100, max_age_seconds=10.0)

    now = time.time()
    pkt_old = Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / UDP(sport=1001, dport=80)
    pkt_old.time = now - 20.0  # 20 seconds ago

    pkt_mid = Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / UDP(sport=1002, dport=80)
    pkt_mid.time = now - 5.0   # 5 seconds ago

    pkt_now = Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / UDP(sport=1003, dport=80)
    pkt_now.time = now

    buf.add(pkt_old)
    # Adding mid will trigger pruning based on current time
    buf.add(pkt_mid)
    buf.add(pkt_now)

    # Old packet should have been evicted since it is older than 10 seconds
    all_pkts = buf.get_packets()
    assert pkt_old not in all_pkts
    assert pkt_mid in all_pkts
    assert pkt_now in all_pkts

    # get_packets_since with cutoff at now - 3s should only return pkt_now
    recent = buf.get_packets_since(now - 3.0)
    assert len(recent) == 1
    assert recent[0] == pkt_now


def test_sniffer_tracks_only_tv_macs_for_ring_buffers():
    sniffer = NetworkSniffer()
    tv_mac = "AA:BB:CC:DD:EE:01"
    phone_mac = "11:22:33:44:55:66"

    sniffer.set_tracked_tvs([tv_mac], pre_record_seconds=45)
    assert tv_mac in sniffer.tracked_tv_macs
    assert phone_mac not in sniffer.tracked_tv_macs

    # Packet from phone (non-TV)
    pkt_phone = Ether(src="11:22:33:44:55:66", dst="FF:FF:FF:FF:FF:FF") / IP(src="192.168.1.100", dst="192.168.1.255") / UDP()
    sniffer._process_packet(pkt_phone)

    # Verify phone MAC is NOT in ring_buffers (user requirement: no memory wasted on non-TV devices)
    assert phone_mac not in sniffer.ring_buffers

    # Packet from TV
    pkt_tv = Ether(src="aa:bb:cc:dd:ee:01", dst="192.168.1.1") / IP(src="192.168.1.50", dst="192.168.1.1") / UDP()
    sniffer._process_packet(pkt_tv)

    # Verify TV MAC IS in ring_buffers
    assert tv_mac in sniffer.ring_buffers
    assert len(sniffer.ring_buffers[tv_mac].get_packets()) == 1


@pytest.mark.asyncio
async def test_forensics_active_wake_collector():
    engine = ForensicsEngine()
    tv_mac = "AA:BB:CC:DD:EE:FF"

    # Register collector for TV
    collector = []
    engine.active_wake_collectors[tv_mac] = collector

    # Send matching packet
    pkt_match = Ether(src=tv_mac, dst="00:11:22:33:44:55") / IP(src="192.168.1.50", dst="8.8.8.8") / UDP()
    engine.on_packet(pkt_match, tv_mac, "00:11:22:33:44:55")

    # Send non-matching packet
    pkt_other = Ether(src="11:11:11:11:11:11", dst="00:11:22:33:44:55") / IP(src="192.168.1.60", dst="8.8.8.8") / UDP()
    engine.on_packet(pkt_other, "11:11:11:11:11:11", "00:11:22:33:44:55")

    assert len(collector) == 1
    assert collector[0] == pkt_match


@pytest.mark.asyncio
async def test_tv_wake_window_settings_api_and_persistence():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "router_host": "192.168.1.1",
            "router_user": "admin",
            "night_mode_start_hour": 2,
            "night_mode_end_hour": 5,
            "tv_wake_pre_record_seconds": 45,
            "tv_wake_post_record_seconds": 60,
        }
        res = await ac.post("/api/settings", json=payload)
        assert res.status_code == 200

        # Check in DB
        assert await db.get_setting("tv_wake_pre_record_seconds") == "45"
        assert await db.get_setting("tv_wake_post_record_seconds") == "60"

        # Check GET /api/settings
        res_get = await ac.get("/api/settings")
        assert res_get.status_code == 200
        data = res_get.json()
        assert data["tv_wake_pre_record_seconds"] == 45
        assert data["tv_wake_post_record_seconds"] == 60

        # Reset memory settings and verify lifespan reloads them
        settings.tv_wake_pre_record_seconds = 10
        settings.tv_wake_post_record_seconds = 15

        async with lifespan(app):
            assert settings.tv_wake_pre_record_seconds == 45
            assert settings.tv_wake_post_record_seconds == 60
