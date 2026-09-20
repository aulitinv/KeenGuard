"""Tests for Wake-on-LAN and sniffer packet parsers."""
import pytest
from scapy.all import IP, UDP, Packet
from keenguard.core.sniffer import NetworkSniffer, PacketRingBuffer

def test_parse_valid_wol_magic_packet():
    target_mac_hex = "001C62AABBCC"
    mac_bytes = bytes.fromhex(target_mac_hex)
    magic_payload = (b"\xff" * 6) + (mac_bytes * 16)

    detected_mac = NetworkSniffer.parse_wol(magic_payload)
    assert detected_mac == "00:1C:62:AA:BB:CC"

def test_parse_wol_with_leading_or_trailing_bytes():
    # Some implementations prefix or suffix passwords (SecureOn)
    target_mac_hex = "AABBCCDDEEFF"
    mac_bytes = bytes.fromhex(target_mac_hex)
    payload = b"PREAMBLE" + (b"\xff" * 6) + (mac_bytes * 16) + b"PASSWORD"

    detected_mac = NetworkSniffer.parse_wol(payload)
    assert detected_mac == "AA:BB:CC:DD:EE:FF"

def test_parse_invalid_wol():
    # Too short
    assert NetworkSniffer.parse_wol(b"\xff" * 10) is None
    # No 6x 0xFF
    assert NetworkSniffer.parse_wol(b"\x00" * 102) is None
    # Corrupted repetition
    corrupted = (b"\xff" * 6) + (b"\x11\x22\x33\x44\x55\x66" * 15) + b"\x99\x99\x99\x99\x99\x99"
    assert NetworkSniffer.parse_wol(corrupted) is None

def test_packet_ring_buffer(tmp_path):
    ring = PacketRingBuffer(max_packets=5)
    for i in range(10):
        pkt = IP(src=f"192.168.1.{i}", dst="192.168.1.1") / UDP(sport=1234, dport=80)
        ring.add(pkt)

    # Buffer length should not exceed max_packets (5)
    assert len(ring.buffer) == 5

    # Dump pcap
    pcap_file = tmp_path / "test_dump.pcap"
    count = ring.dump_pcap(pcap_file)
    assert count == 5
    assert pcap_file.exists()

def test_sniffer_emit_event_without_event_loop_does_not_raise():
    """Verify that emitting an event from a thread with no event loop does not crash or raise."""
    import threading
    from keenguard.core.sniffer import NetworkSniffer
    from keenguard.web.app import _handle_sniffer_event

    s = NetworkSniffer()
    s.register_callback(_handle_sniffer_event)

    exception_raised = None
    def worker():
        nonlocal exception_raised
        try:
            s._emit_event({"event_type": "arp_probe", "source_mac": "00:11:22:33:44:55"})
        except Exception as ex:
            exception_raised = ex

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    assert exception_raised is None

@pytest.mark.asyncio
async def test_sniffer_emit_event_dispatches_to_running_loop():
    """Verify that when main loop is active, background thread events are dispatched cleanly."""
    import asyncio
    import threading
    from keenguard.core.sniffer import NetworkSniffer
    from keenguard.web.app import _handle_sniffer_event, set_main_loop, _main_loop
    from keenguard.web.workers import forensics

    loop = asyncio.get_running_loop()
    set_main_loop(loop)

    received_events = []
    s = NetworkSniffer()
    s.register_callback(_handle_sniffer_event)
    s.register_callback(lambda ev: received_events.append(ev))

    def worker():
        s._emit_event({
            "event_type": "airplay_activity",
            "source_mac": "AA:BB:CC:DD:EE:FF",
            "source_ip": "192.168.1.50",
            "description": "Test airplay"
        })

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    # Yield control to let the threadsafe coroutine execute
    await asyncio.sleep(0.1)

    assert len(received_events) == 1
    assert received_events[0]["event_type"] == "airplay_activity"
    assert received_events[0]["source_mac"] == "AA:BB:CC:DD:EE:FF"
    assert any(
        t.get("event_type") == "airplay_activity" and t.get("source_mac") == "AA:BB:CC:DD:EE:FF"
        for t in forensics.recent_triggers
    )


def test_sniffer_process_ipv6_mdns():
    from scapy.all import Ether, IPv6, UDP, Raw
    s = NetworkSniffer()
    events = []
    s.register_callback(lambda e: events.append(e))

    pkt = Ether(src="00:11:22:33:44:55", dst="33:33:00:00:00:fb") / IPv6(src="fe80::1", dst="ff02::fb") / UDP(sport=5353, dport=5353) / Raw(load=b"test _airplay._tcp local")
    s._process_packet(pkt)

    assert len(events) == 1
    assert events[0]["event_type"] == "airplay_activity"
    assert events[0]["source_ip"] == "fe80::1"
    assert events[0]["source_mac"] == "00:11:22:33:44:55"


def test_sniffer_process_ipv6_ssdp_dial():
    from scapy.all import Ether, IPv6, UDP, Raw
    s = NetworkSniffer()
    events = []
    s.register_callback(lambda e: events.append(e))

    pkt = Ether(src="00:11:22:33:44:66", dst="33:33:00:00:00:0c") / IPv6(src="fe80::2", dst="ff02::c") / UDP(sport=1900, dport=1900) / Raw(load=b"M-SEARCH * HTTP/1.1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n")
    s._process_packet(pkt)

    assert len(events) == 1
    assert events[0]["event_type"] == "dial_activity"
    assert events[0]["source_ip"] == "fe80::2"


