# -*- coding: utf-8 -*-
"""
Tests for LanTrafficTracker, IoT payload database persistence/pruning, and LAN/DPI REST API endpoints.
"""
import pytest
import asyncio
import time
from datetime import datetime, timedelta, timezone
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from fastapi.testclient import TestClient

from keenguard.core.lan_tracker import LanTrafficTracker, lan_tracker
from keenguard.db.database import Database
from keenguard.db.models import IotPayloadRecord
from keenguard.web.app import app
from keenguard.core.sniffer import sniffer


@pytest.fixture
def client():
    return TestClient(app)


def test_lan_tracker_icmp_rtt_and_matrix():
    """Verify ICMP request/reply tracking, RTT calculation, and ping matrix aggregation."""
    tracker = LanTrafficTracker(max_history=50)

    # 1. Host 192.168.1.50 sends ICMP echo request to 192.168.1.1 (id 0x5555, seq 10)
    pkt_req = Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / ICMP(type=8, code=0, id=0x5555, seq=10) / b"TestPing"
    record_req = tracker.process_packet(pkt_req)

    assert record_req is not None
    assert record_req["protocol"] == "ICMP"
    assert record_req["status"] == "waiting"
    assert "Echo Request" in record_req["summary"]

    time.sleep(0.01)

    # 2. Host 192.168.1.1 replies with ICMP echo reply
    pkt_rep = Ether() / IP(src="192.168.1.1", dst="192.168.1.50") / ICMP(type=0, code=0, id=0x5555, seq=10) / b"TestPing"
    record_rep = tracker.process_packet(pkt_rep)

    assert record_rep is not None
    assert record_rep["protocol"] == "ICMP"
    assert record_rep["status"] == "replied"
    assert record_rep["rtt_ms"] is not None
    assert record_rep["rtt_ms"] >= 0.0

    # 3. Check Ping Matrix
    matrix = tracker.get_ping_matrix()
    assert len(matrix) >= 1
    m0 = next((m for m in matrix if m["src_ip"] == "192.168.1.50" and m["dst_ip"] == "192.168.1.1"), None)
    assert m0 is not None
    assert m0["sent_count"] == 1
    assert m0["reply_count"] == 1
    assert m0["loss_count"] == 0
    assert m0["status"] == "OK"

    # 4. Check Stats
    stats = tracker.get_stats()
    assert stats["ping_requests_count"] == 1
    assert stats["ping_replies_count"] == 1


def test_lan_tracker_arp_and_flows():
    """Verify ARP who-has tracking and Unicast IP flow recording."""
    tracker = LanTrafficTracker(max_history=50)

    # ARP Who-has
    arp_pkt = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.77",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.88"
    )
    rec_arp = tracker.process_packet(arp_pkt)
    assert rec_arp is not None
    assert rec_arp["protocol"] == "ARP"
    assert "192.168.1.88" in rec_arp["summary"]

    # Local Unicast TCP flow
    tcp_pkt = Ether() / IP(src="192.168.1.20", dst="192.168.1.30") / TCP(sport=1883, dport=54321) / Raw(b"local-data")
    rec_tcp = tracker.process_packet(tcp_pkt)
    assert rec_tcp is not None
    assert rec_tcp["protocol"] in ("TCP", "MQTT")

    topo = tracker.get_topology()
    assert len(topo["nodes"]) >= 2
    assert len(topo["edges"]) >= 1
    assert any(e["source"] == "192.168.1.20" or e["target"] == "192.168.1.20" for e in topo["edges"])


def test_lan_tracker_conntrack_integration():
    """Verify integrating Keenetic router NAT connections into LAN tracker."""
    tracker = LanTrafficTracker(max_history=50)

    nat_entries = [
        {
            "src": "192.168.1.50:52123",
            "dst": "192.168.1.100:80",
            "protocol": "tcp",
            "bytes": 45000,
            "packets": 120
        },
        {
            # Internet entry, should NOT be classified as intra-LAN
            "src": "192.168.1.50:52124",
            "dst": "8.8.8.8:53",
            "protocol": "udp",
            "bytes": 500,
            "packets": 4
        }
    ]

    added = tracker.integrate_router_conntrack(nat_entries)
    assert added == 1

    stats = tracker.get_stats()
    assert stats["active_flows_count"] >= 1


@pytest.mark.asyncio
async def test_db_iot_payload_storage_and_pruning(tmp_path):
    """Verify database storage, retrieval, and auto-pruning by retention and GB limits."""
    test_db_path = tmp_path / "test_keenguard.db"
    db = Database(db_path=str(test_db_path))
    await db.init_db()

    now = datetime.now(timezone.utc)
    old_date = (now - timedelta(days=10)).isoformat()
    recent_date = now.isoformat()

    rec_old = IotPayloadRecord(
        timestamp=old_date,
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.50",
        hostname="OldSensor",
        protocol="MQTT",
        dst_ip="192.168.1.1",
        dst_port=1883,
        payload_len=256,
        payload_hex="00" * 256,
        decoded_summary="tele/sensor/state",
        is_cloud=False
    )
    rec_recent = IotPayloadRecord(
        timestamp=recent_date,
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.50",
        hostname="ActiveSensor",
        protocol="HTTP",
        dst_ip="192.168.1.10",
        dst_port=80,
        payload_len=512,
        payload_hex="01" * 512,
        decoded_summary="GET /status",
        is_cloud=False
    )

    await db.add_iot_payload(rec_old)
    await db.add_iot_payload(rec_recent)

    payloads = await db.get_iot_payloads(limit=10)
    assert len(payloads) == 2

    stats = await db.get_iot_storage_stats()
    assert stats["total_records"] == 2
    assert stats["total_bytes"] == 256 + 512

    # Prune records older than 7 days
    pruned = await db.prune_iot_payloads(max_storage_gb=1.0, retention_days=7)
    assert pruned >= 1

    remaining = await db.get_iot_payloads(limit=10)
    assert len(remaining) == 1
    assert remaining[0]["hostname"] == "ActiveSensor"

    # Test clear
    cleared = await db.clear_iot_payloads()
    assert cleared == 1
    assert len(await db.get_iot_payloads()) == 0


def test_api_lan_and_iot_endpoints(client):
    """Verify REST endpoints for LAN tracker, IoT payloads, and Packet Inspector."""
    # LAN Stats
    r_stats = client.get("/api/lan/stats")
    assert r_stats.status_code == 200
    assert r_stats.json()["status"] == "ok"

    # LAN Communications
    r_comms = client.get("/api/lan/communications")
    assert r_comms.status_code == 200
    assert "communications" in r_comms.json()

    # LAN Ping Matrix
    r_matrix = client.get("/api/lan/ping_matrix")
    assert r_matrix.status_code == 200
    assert "ping_matrix" in r_matrix.json()

    # LAN Topology
    r_topo = client.get("/api/lan/topology")
    assert r_topo.status_code == 200
    assert "nodes" in r_topo.json()
    assert "edges" in r_topo.json()

    # IoT Storage Settings GET and POST
    r_get_cfg = client.get("/api/settings/iot_storage")
    assert r_get_cfg.status_code == 200
    assert "config" in r_get_cfg.json()

    r_set_cfg = client.post("/api/settings/iot_storage", json={
        "capture_enabled": True,
        "max_storage_gb": 2.5,
        "retention_days": 14
    })
    assert r_set_cfg.status_code == 200
    assert r_set_cfg.json()["config"]["max_storage_gb"] == 2.5
    assert r_set_cfg.json()["config"]["retention_days"] == 14

    # Packets Live list
    test_pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.99", dst="192.168.1.1") / ICMP(type=8) / b"LivePing"
    sniffer.ring_buffer.add(test_pkt)
    new_id = sniffer.ring_buffer.last_pkt_id

    r_live = client.get("/api/packets/live")
    assert r_live.status_code == 200
    pkts = r_live.json()["packets"]
    assert any(p["pkt_id"] == new_id for p in pkts)

    # Inspect packet from sniffer
    r_inspect = client.get(f"/api/packets/inspect/{new_id}")
    assert r_inspect.status_code == 200
    ins_data = r_inspect.json()
    assert ins_data["packet_id"] == new_id
    assert ins_data["protocol"] == "ICMP"
    assert "hexdump" in ins_data
    assert "dissection" in ins_data
    assert len(ins_data["dissection"]["layers"]) >= 3

    # Inspect packet processed by lan_tracker
    lan_pkt = Ether(src="AA:BB:CC:DD:EE:11", dst="AA:BB:CC:DD:EE:22") / IP(src="192.168.1.101", dst="192.168.1.102") / UDP(sport=5353, dport=5353) / b"mDNS-query-bytes"
    lan_event = lan_tracker.process_packet(lan_pkt)
    assert lan_event is not None
    assert lan_event.get("packet_id") is not None
    lan_pkt_id = lan_event["packet_id"]

    # Verify packet is retrievable via sniffer and API
    r_lan_inspect = client.get(f"/api/packets/inspect/{lan_pkt_id}")
    assert r_lan_inspect.status_code == 200
    lan_data = r_lan_inspect.json()
    assert lan_data["packet_id"] == lan_pkt_id
    assert "hexdump" in lan_data
    assert "dissection" in lan_data
    assert len(lan_data["dissection"]["layers"]) >= 3

    # Prune IoT Payloads endpoint
    r_prune = client.post("/api/iot/payloads/prune", json={"max_storage_gb": 1.0, "retention_days": 7})
    assert r_prune.status_code == 200
    assert "pruned_count" in r_prune.json()

    # Clear LAN events
    r_clear = client.post("/api/lan/clear")
    assert r_clear.status_code == 200
