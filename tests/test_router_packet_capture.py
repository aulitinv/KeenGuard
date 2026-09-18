"""
Unit and integration tests for Keenetic RCI Hardware Packet Capture:
- RCI capture start/stop/download/reset/cleanup commands
- Mock mode PCAP generation with realistic packets
- HTTP unencrypted traffic inspection (methods, hosts, URIs, categories)
- Audit session with hardware capture and HTTP dissection
- TV wake forensics with Keenetic hardware packet capture
"""
import pytest
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, Raw, rdpcap, wrpcap

from keenguard.config import settings
from keenguard.core.keenetic import KeeneticClient, keenetic_client
from keenguard.core.audit import extract_http_inspection, audit_manager, AuditSession
from keenguard.core.forensics import forensics, ForensicsEngine
from keenguard.db.database import Database


def test_extract_http_inspection():
    """Verify extract_http_inspection extracts HTTP verbs, headers, and categories accurately."""
    # 1. Telemetry request
    raw_http = (
        b"GET /api/v2/telemetry?device=tv HTTP/1.1\r\n"
        b"Host: telemetry.samsungcloud.com\r\n"
        b"User-Agent: Tizen/7.0 SmartTV\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
    )
    pkt_telemetry = (
        Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") /
        IP(src="192.168.1.105", dst="198.51.100.20") /
        TCP(sport=50123, dport=80, flags="PA") /
        Raw(load=raw_http)
    )

    info = extract_http_inspection(pkt_telemetry)
    assert info is not None
    assert info["method"] == "GET"
    assert info["host"] == "telemetry.samsungcloud.com"
    assert info["path"] == "/api/v2/telemetry?device=tv"
    assert info["user_agent"] == "Tizen/7.0 SmartTV"
    assert info["dst_port"] == 80
    assert "Телеметрия" in info["category"]

    # 2. OCSP Certificate revocation check
    raw_ocsp = (
        b"POST /ocsp/status HTTP/1.1\r\n"
        b"Host: ocsp.digicert.com\r\n"
        b"User-Agent: libcurl/7.88.1\r\n"
        b"\r\n"
    )
    pkt_ocsp = (
        Ether() /
        IP(src="192.168.1.105", dst="198.51.100.21") /
        TCP(sport=50124, dport=80) /
        Raw(load=raw_ocsp)
    )
    info_ocsp = extract_http_inspection(pkt_ocsp)
    assert info_ocsp is not None
    assert info_ocsp["method"] == "POST"
    assert info_ocsp["host"] == "ocsp.digicert.com"
    assert "OCSP" in info_ocsp["category"]

    # 3. Non-HTTP packet (e.g. raw UDP or encrypted TLS) returns None
    pkt_udp = Ether() / IP(src="192.168.1.105", dst="192.168.1.1") / UDP(sport=1234, dport=53)
    assert extract_http_inspection(pkt_udp) is None


@pytest.mark.asyncio
async def test_router_capture_start_stop_mock():
    """Verify start_packet_capture and stop_packet_capture handle parameters and state."""
    client = KeeneticClient()
    client.mock_mode = True

    assert await client.is_packet_capture_supported() is True

    # Start capture with target IP
    res = await client.start_packet_capture(
        interface="Bridge0",
        target_ip="192.168.1.105",
        duration_seconds=60,
        max_size_kb=5120
    )
    assert res is not None
    assert res["status"] == "ok"
    assert res["interface"] == "Bridge0"
    assert res["filter"] == {"bpf-program": "host 192.168.1.105"}

    # Check mock state
    assert "Bridge0" in client._mock_captures
    assert client._mock_captures["Bridge0"]["is_running"] is True

    # Stop capture
    cap_file = await client.stop_packet_capture("Bridge0")
    assert cap_file == "capture_Bridge0.pcap"
    assert client._mock_captures["Bridge0"]["is_running"] is False


@pytest.mark.asyncio
async def test_router_capture_download_mock(tmp_path):
    """Verify download_capture_file creates synthetic PCAP with dissectible packets in mock mode."""
    client = KeeneticClient()
    client.mock_mode = True

    dest_file = tmp_path / "router_dump.pcap"
    ok = await client.download_capture_file("capture_Bridge0.pcap", dest_file)
    assert ok is True
    assert dest_file.exists()
    assert dest_file.stat().st_size > 0

    # Parse with scapy
    pkts = list(rdpcap(str(dest_file)))
    assert len(pkts) >= 2

    # Check HTTP packet presence
    has_http = any(TCP in p and Raw in p for p in pkts)
    assert has_http is True


@pytest.mark.asyncio
async def test_router_capture_reset_and_cleanup():
    """Verify reset_packet_capture and cleanup_orphan_captures clear router capture sessions."""
    client = KeeneticClient()
    client.mock_mode = True

    await client.start_packet_capture("Bridge0", target_ip="192.168.1.100")
    await client.start_packet_capture("Bridge1", target_ip="192.168.2.100")
    assert len(client._mock_captures) == 2

    # Reset single
    ok = await client.reset_packet_capture("Bridge1")
    assert ok is True
    assert "Bridge1" not in client._mock_captures
    assert "Bridge0" in client._mock_captures

    # Cleanup all orphans
    await client.cleanup_orphan_captures()
    assert len(client._mock_captures) == 0


@pytest.mark.asyncio
async def test_audit_session_with_router_capture(tmp_path, monkeypatch):
    """Verify TrafficAuditManager starts router capture, parses HTTP payload, and generates report."""
    test_db = Database(str(tmp_path / "test_keenguard.db"))
    await test_db.init_db()

    monkeypatch.setattr("keenguard.core.audit.db", test_db)
    monkeypatch.setattr("keenguard.core.audit.settings.pcap_dir", tmp_path / "pcaps")
    monkeypatch.setattr(keenetic_client, "mock_mode", True)

    mac = "00:11:22:33:44:55"
    ip = "192.168.1.105"

    # Start audit
    start_res = await audit_manager.start_audit(mac, ip=ip, hostname="Samsung Smart TV", duration_seconds=2)
    assert start_res["status"] == "started"
    assert start_res["capture_source"] == "router_hardware"

    session = audit_manager.get_session(mac)
    assert session is not None
    assert session.capture_source == "router_hardware"
    assert session._hw_capture_active is True

    # Stop audit
    report = await audit_manager.stop_audit(mac)
    assert report is not None
    assert report["capture_source"] == "router_hardware"
    assert report["mac"] == mac
    assert "http_inspections" in report
    assert len(report["http_inspections"]) > 0

    first_http = report["http_inspections"][0]
    assert first_http["method"] == "GET"
    assert "smart-tv-cloud.example.com" in first_http["host"]

    # Verify PCAP was saved and is readable
    pcap_path = tmp_path / "pcaps" / report["pcap_file"]
    assert pcap_path.exists()
    pcap_pkts = list(rdpcap(str(pcap_path)))
    assert len(pcap_pkts) > 0


@pytest.mark.asyncio
async def test_tv_wake_forensics_router_capture(tmp_path, monkeypatch):
    """Verify TV wake forensics triggers router hardware packet capture and records capture_source."""
    test_db = Database(str(tmp_path / "test_wake.db"))
    await test_db.init_db()

    monkeypatch.setattr("keenguard.core.forensics.db", test_db)
    monkeypatch.setattr("keenguard.core.forensics.settings.pcap_dir", tmp_path / "pcaps")
    monkeypatch.setattr(keenetic_client, "mock_mode", True)

    engine = ForensicsEngine()

    tv_mac = "AA:BB:CC:DD:EE:77"
    tv_ip = "192.168.1.155"

    # Configure short post seconds
    monkeypatch.setattr(settings, "tv_wake_pre_record_seconds", 0)
    monkeypatch.setattr(settings, "tv_wake_post_record_seconds", 1)

    # Run _handle_tv_wake
    await engine._handle_tv_wake(tv_mac, tv_ip, hostname="Living Room TV")

    # Check database event
    events = await test_db.get_recent_events(limit=5)
    assert len(events) >= 1

    wake_event = next(e for e in events if e.target_mac == tv_mac)
    assert wake_event.details.get("capture_source") == "router_hardware"
    assert wake_event.details.get("post_packets_count") > 0
    assert wake_event.pcap_file is not None

    saved_pcap = tmp_path / "pcaps" / wake_event.pcap_file
    assert saved_pcap.exists()
