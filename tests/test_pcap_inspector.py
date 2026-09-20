"""
Unit and integration tests for PCAP Inspector:
- Loading saved PCAP files into inspector ring buffer
- Uploading custom PCAP files
- Inspecting packet layers and hexdump for PCAP packets
- Resetting/clearing PCAP inspection mode
"""
import pytest
from pathlib import Path
from scapy.all import IP, TCP, Ether, wrpcap
from fastapi.testclient import TestClient

from keenguard.core.sniffer import NetworkSniffer, PacketRingBuffer
from keenguard.web.app import app, sniffer
from keenguard.config import settings

@pytest.fixture
def client():
    return TestClient(app)

def test_sniffer_pcap_buffer_lifecycle():
    """Verify NetworkSniffer loads PCAP packets and clears them cleanly."""
    sn = NetworkSniffer()
    assert sn.active_pcap_name is None
    assert len(sn.pcap_buffer) == 0

    pkts = [
        Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=12345, dport=80),
        Ether() / IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=80, dport=12345),
    ]

    sn.load_pcap_packets(pkts, source_name="test_dump.pcap")
    assert sn.active_pcap_name == "test_dump.pcap"
    assert len(sn.pcap_buffer) == 2

    # Should find by id
    p0 = sn.get_packet_by_id("pcap_0")
    assert p0 is not None
    assert p0[IP].src == "192.168.1.50"

    p1 = sn.get_packet_by_id("pcap_1")
    assert p1 is not None
    assert p1[IP].src == "192.168.1.1"

    # Non-existent
    assert sn.get_packet_by_id("pcap_999") is None

    # Clear
    sn.clear_pcap()
    assert sn.active_pcap_name is None
    assert len(sn.pcap_buffer) == 0
    assert sn.get_packet_by_id("pcap_0") is None

def test_api_saved_pcaps_list(client):
    """Verify /api/packets/pcap/saved lists dumps properly."""
    res = client.get("/api/packets/pcap/saved")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "pcaps" in data
    assert "files" in data
    assert isinstance(data["pcaps"], list)

def test_api_load_saved_pcap_and_inspect(client):
    """Verify loading an existing PCAP file and inspecting its packets."""
    settings.pcap_dir.mkdir(parents=True, exist_ok=True)
    fixture_file = settings.pcap_dir / "synthetic_test_dump.pcap"
    synthetic_pkts = [
        Ether() / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=12345, dport=80),
        Ether() / IP(src="192.168.1.1", dst="192.168.1.50") / TCP(sport=80, dport=12345),
    ]
    wrpcap(str(fixture_file), synthetic_pkts)

    try:
        sample_pcap = fixture_file.name
        # 1. Load saved PCAP
        load_res = client.post("/api/packets/pcap/load_saved", json={"filename": sample_pcap})
        assert load_res.status_code == 200
        load_data = load_res.json()
        assert load_data["status"] == "ok"
        assert load_data["filename"] == sample_pcap
        assert load_data["loaded_packets"] > 0

        # 2. Check live endpoint returns pcap buffer
        live_res = client.get("/api/packets/live?limit=10")
        assert live_res.status_code == 200
        live_data = live_res.json()
        assert live_data["is_pcap"] is True
        assert live_data["pcap_filename"] == sample_pcap
        assert len(live_data["packets"]) > 0
        assert live_data["packets"][0]["pkt_id"] == "pcap_0"

        # 3. Inspect packet 0
        inspect_res = client.get("/api/packets/inspect/pcap_0")
        assert inspect_res.status_code == 200
        inspect_data = inspect_res.json()
        assert "dissection" in inspect_data
        assert "layers" in inspect_data["dissection"]
        assert len(inspect_data["dissection"]["layers"]) >= 1
        assert "hexdump" in inspect_data

        # 4. Clear PCAP mode
        clear_res = client.post("/api/packets/pcap/clear")
        assert clear_res.status_code == 200
        assert clear_res.json()["status"] == "ok"

        # 5. Verify status returns to live
        stat_res = client.get("/api/packets/pcap/status")
        assert stat_res.status_code == 200
        stat_data = stat_res.json()
        assert stat_data["is_pcap"] is False
        assert stat_data["pcap_filename"] is None
    finally:
        if fixture_file.exists():
            fixture_file.unlink()
