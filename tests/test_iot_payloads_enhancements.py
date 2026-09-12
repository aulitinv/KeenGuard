import pytest
import asyncio
from unittest.mock import MagicMock, patch
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord, IotPayloadRecord
from keenguard.core.sniffer import NetworkSniffer

@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_iot.db"
    db = Database(db_path=db_file)
    asyncio.run(db.init_db())
    return db

@pytest.mark.asyncio
async def test_get_iot_payloads_enriches_device_names(temp_db):
    # 1. Insert device with custom_name and hostname
    dev = DeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.64",
        hostname="smart-vacuum-cleaner",
        custom_name="Робот-пылесос",
        profile="iot"
    )
    await temp_db.upsert_device(dev)

    # 2. Insert IoT payload with NULL device_name
    rec = IotPayloadRecord(
        timestamp="2026-09-12T12:00:00Z",
        mac="AA:BB:CC:DD:EE:01",
        device_name=None,
        src_ip="192.168.1.64",
        dst_ip="192.168.1.101",
        dst_port=1883,
        protocol="MQTT",
        direction="outbound",
        summary="MQTT: 192.168.1.64 -> 192.168.1.101:1883",
        payload_text="vacuum/state: running",
        payload_hex="76616375756d",
        byte_size=21
    )
    await temp_db.add_iot_payload(rec)

    # 3. Query payloads and verify resolved name
    payloads = await temp_db.get_iot_payloads()
    assert len(payloads) == 1
    p = payloads[0]
    assert p["device_name"] == "Робот-пылесос"
    assert p["hostname"] == "Робот-пылесос"
    assert p["device_hostname"] == "smart-vacuum-cleaner"
    assert p["custom_name"] == "Робот-пылесос"

@pytest.mark.asyncio
async def test_get_iot_payloads_resolves_router_name(temp_db):
    from keenguard.core.keenetic import keenetic_client
    keenetic_client.router_macs.add("50:FF:20:00:00:01")

    rec = IotPayloadRecord(
        timestamp="2026-09-12T12:05:00Z",
        mac="50:FF:20:00:00:01",
        device_name=None,
        src_ip="192.168.1.1",
        dst_ip="192.168.1.102",
        dst_port=80,
        protocol="HTTP",
        direction="inbound",
        summary="HTTP response",
        payload_text="HTTP/1.1 200 OK",
        byte_size=15
    )
    await temp_db.add_iot_payload(rec)

    payloads = await temp_db.get_iot_payloads()
    assert len(payloads) == 1
    assert payloads[0]["device_name"] == "Роутер Keenetic"
    assert payloads[0]["hostname"] == "Роутер Keenetic"

@pytest.mark.asyncio
async def test_api_endpoints_return_storage(temp_db):
    from fastapi.testclient import TestClient
    from keenguard.web.app import app
    import keenguard.web.app as web_app

    orig_db = web_app.db
    web_app.db = temp_db
    try:
        client = TestClient(app)
        
        # Test /api/iot/payloads
        res = client.get("/api/iot/payloads")
        assert res.status_code == 200
        data = res.json()
        assert "storage" in data
        assert "count" in data["storage"]
        assert "max_storage_gb" in data["storage"]

        # Test /api/devices/{mac}/payloads
        res2 = client.get("/api/devices/AA:BB:CC:DD:EE:01/payloads")
        assert res2.status_code == 200
        data2 = res2.json()
        assert "storage" in data2
        assert "payloads" in data2
    finally:
        web_app.db = orig_db

def test_sniffer_router_mac_attribution():
    sniffer = NetworkSniffer()
    from keenguard.core.keenetic import keenetic_client
    router_mac = "50:FF:20:00:00:01"
    client_mac = "70:85:C2:68:EA:16"
    keenetic_client.router_macs.add(router_mac)

    # Inbound packet: from router MAC to client MAC (HTTP port 80)
    pkt_in = Ether(src=router_mac, dst=client_mac) / IP(src="95.181.181.224", dst="192.168.1.102") / TCP(sport=80, dport=52482) / Raw(load=b"HTTP/1.1 200 OK\r\n\r\nhello")
    sniffer._check_and_queue_iot_payload(pkt_in, src_mac=router_mac, dst_mac=client_mac)

    assert not sniffer._db_queue.empty()
    item = sniffer._db_queue.get_nowait()
    # Target MAC must be the client MAC, not the router!
    assert item.mac == client_mac
    assert item.direction == "inbound"

    # Outbound packet: from client MAC to router MAC (MQTT port 1883)
    pkt_out = Ether(src=client_mac, dst=router_mac) / IP(src="192.168.1.102", dst="1.2.3.4") / TCP(sport=52483, dport=1883) / Raw(load=b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c")
    sniffer._check_and_queue_iot_payload(pkt_out, src_mac=client_mac, dst_mac=router_mac)

    assert not sniffer._db_queue.empty()
    item2 = sniffer._db_queue.get_nowait()
    assert item2.mac == client_mac
    assert item2.direction == "outbound"

def test_sniffer_ignores_bulk_ephemeral_tcp():
    sniffer = NetworkSniffer()
    client_mac = "70:85:C2:68:EA:16"
    other_mac = "12:34:56:78:90:AB"

    # Bulk TCP packet on random non-IoT high ports (e.g. 52482 -> 49152)
    pkt_bulk = Ether(src=client_mac, dst=other_mac) / IP(src="192.168.1.102", dst="192.168.1.200") / TCP(sport=52482, dport=49152) / Raw(load=b"random_bulk_data_123456789")
    sniffer._check_and_queue_iot_payload(pkt_bulk, src_mac=client_mac, dst_mac=other_mac)

    # Should be ignored and NOT put into the queue!
    assert sniffer._db_queue.empty()
