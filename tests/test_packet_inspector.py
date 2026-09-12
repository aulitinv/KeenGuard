# -*- coding: utf-8 -*-
"""
Tests for PacketDissector, Hex dump generation, and protocol dissections (Wireshark-style inspection).
"""
import pytest
import struct
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

from keenguard.core.dissector import PacketDissector
from keenguard.core.sniffer import PacketRingBuffer


def test_hex_dump_generation():
    """Verify 16-byte aligned Hex and ASCII dump formatting."""
    data = b"Hello, KeenGuard Network Inspector! 123\x00\x01\x02\xff"
    lines = PacketDissector.generate_hex_dump(data)

    assert len(lines) >= 3
    # Check first line
    line0 = lines[0]
    assert line0["offset"] == "00000000"
    assert "48 65 6c 6c 6f" in line0["hex"]
    assert "Hello," in line0["ascii"]
    assert line0["byte_start"] == 0
    assert line0["byte_end"] == 15


def test_dissect_arp():
    """Verify ARP Who-has and Is-at dissection."""
    arp_req = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="00:11:22:33:44:55",
        psrc="192.168.1.100",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1"
    )

    d = PacketDissector.dissect(arp_req)
    assert d["protocol"] == "ARP"
    assert "ARP" in d["summary"]
    assert "192.168.1.1" in d["summary"]

    arp_layer = next((l for l in d["layers"] if "ARP" in l["name"]), None)
    assert arp_layer is not None
    assert "Who-has" in arp_layer["fields"]["Opcode"]
    assert arp_layer["fields"]["Sender IP"] == "192.168.1.100"
    assert arp_layer["fields"]["Target IP"] == "192.168.1.1"


def test_dissect_icmp_echo():
    """Verify ICMP Echo Request and Reply dissection."""
    pkt_req = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.100", dst="192.168.1.1") / ICMP(type=8, code=0, id=0x1234, seq=1) / b"PingPayload"
    d_req = PacketDissector.dissect(pkt_req)

    assert d_req["protocol"] == "ICMP"
    assert "Echo Request" in d_req["summary"]
    icmp_layer = next(l for l in d_req["layers"] if "ICMP" in l["name"])
    assert "Echo Request" in icmp_layer["fields"]["Type"]
    assert icmp_layer["fields"]["Sequence"] == 1
    assert "0x1234" in str(icmp_layer["fields"]["Identifier"])

    pkt_reply = Ether(src="00:11:22:33:44:66", dst="00:11:22:33:44:55") / IP(src="192.168.1.1", dst="192.168.1.100") / ICMP(type=0, code=0, id=0x1234, seq=1) / b"PingPayload"
    d_reply = PacketDissector.dissect(pkt_reply)
    assert d_reply["protocol"] == "ICMP"
    assert "Echo Reply" in d_reply["summary"]


def test_dissect_ntp():
    """Verify NTP packet dissection."""
    ntp_data = bytearray(48)
    ntp_data[0] = 0x23  # LI=0, VN=4, Mode=3 (Client)
    ntp_data[1] = 0
    ntp_data[2] = 6
    ntp_data[3] = 0xEC

    pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.50", dst="192.168.1.1") / UDP(sport=123, dport=123) / Raw(bytes(ntp_data))
    d = PacketDissector.dissect(pkt)

    assert d["protocol"] == "NTP"
    assert "NTP" in d["summary"]
    ntp_layer = next(l for l in d["layers"] if "NTP" in l["name"])
    assert ntp_layer["fields"]["Version"] == 4
    assert "Client" in str(ntp_layer["fields"]["Mode"])


def test_dissect_http():
    """Verify HTTP request dissection."""
    http_req = (
        b"GET /api/v1/sensors HTTP/1.1\r\n"
        b"Host: 192.168.1.100\r\n"
        b"User-Agent: SmartSensor/2.0\r\n"
        b"Accept: application/json\r\n\r\n"
    )
    pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.55", dst="192.168.1.100") / TCP(sport=43210, dport=80) / Raw(http_req)
    d = PacketDissector.dissect(pkt)

    assert d["protocol"] == "HTTP"
    assert "GET /api/v1/sensors" in d["summary"]

    http_layer = next(l for l in d["layers"] if "HTTP" in l["name"])
    assert http_layer["fields"]["Method"] == "GET"
    assert http_layer["fields"]["URI"] == "/api/v1/sensors"


def test_dissect_mqtt_publish():
    """Verify MQTT Publish and Connect dissection."""
    mqtt_connect = b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x04test"
    pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.60", dst="192.168.1.10") / TCP(sport=50123, dport=1883) / Raw(mqtt_connect)
    d = PacketDissector.dissect(pkt)

    assert d["protocol"] == "MQTT"
    assert "CONNECT" in d["summary"]
    mqtt_layer = next(l for l in d["layers"] if "MQTT" in l["name"])
    assert mqtt_layer["fields"]["Packet Type"] == "CONNECT"
    assert mqtt_layer["fields"]["Client ID"] == "test"

    # MQTT PUBLISH packet
    topic = b"tele/pow"
    payload = b'{"state":"ON"}'
    mqtt_pub = bytearray([0x30, 2 + len(topic) + len(payload)])
    mqtt_pub.extend(struct.pack("!H", len(topic)))
    mqtt_pub.extend(topic)
    mqtt_pub.extend(payload)

    pkt_pub = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.60", dst="192.168.1.10") / TCP(sport=50123, dport=1883) / Raw(bytes(mqtt_pub))
    d_pub = PacketDissector.dissect(pkt_pub)
    assert d_pub["protocol"] == "MQTT"
    assert "PUBLISH" in d_pub["summary"]
    assert "tele/pow" in d_pub["summary"]


def test_dissect_tls_client_hello():
    """Verify TLS SNI hostname extraction."""
    server_name = b"mqtt.tuyaeu.com"
    sni_ext = struct.pack("!HHHBH", 0x0000, len(server_name) + 5, len(server_name) + 3, 0, len(server_name)) + server_name

    body = struct.pack("!H", 0x0303) + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00" + struct.pack("!H", len(sni_ext)) + sni_ext
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src="192.168.1.70", dst="52.28.10.1") / TCP(sport=49152, dport=443) / Raw(record)
    d = PacketDissector.dissect(pkt)

    assert d["protocol"] == "TLS"
    assert "mqtt.tuyaeu.com" in d["summary"]
    tls_layer = next(l for l in d["layers"] if "TLS" in l["name"])
    assert tls_layer["fields"]["Server Name (SNI)"] == "mqtt.tuyaeu.com"


def test_packet_ring_buffer_ids():
    """Verify deterministic packet indexing in PacketRingBuffer."""
    buf = PacketRingBuffer(max_packets=10)
    for i in range(15):
        pkt = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66") / IP(src=f"192.168.1.{i}", dst="192.168.1.1") / ICMP()
        buf.add(pkt)

    assert len(buf) == 10
    meta_list = buf.get_packets_with_meta()
    assert len(meta_list) == 10
    # Pick last packet id
    last_id = meta_list[-1][2]
    found = buf.find_by_id(last_id)
    assert found is not None
    assert found[IP].src == "192.168.1.14"

    # Non-existent id
    assert buf.find_by_id("non_existent_id") is None
