"""Tests for Keenetic client mock operations and database layer."""
import pytest
from keenguard.core.keenetic import KeeneticClient, is_host_lan_isolated
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord, SecurityEvent

@pytest.mark.asyncio
async def test_keenetic_client_mock():
    client = KeeneticClient()
    client.mock_mode = True
    client._mock_hosts = [
        {
            "mac": "00:1C:62:33:44:55",
            "ip": "192.168.1.102",
            "name": "Smart-TV",
            "hostname": "Smart-Media-TV",
            "interface": "Bridge0",
            "link": "up",
            "active": True,
            "access": "permit",
            "rxbytes": 1000000,
            "txbytes": 500000
        },
        {
            "mac": "00:1C:62:99:88:77",
            "ip": "10.1.30.55",
            "name": "Guest-Device",
            "hostname": "GuestPhone",
            "interface": "Bridge1",
            "link": "up",
            "active": True,
            "access": "permit"
        }
    ]

    hosts = await client.get_hotspot_hosts()
    assert len(hosts) == 2
    assert hosts[0].mac == "00:1C:62:33:44:55"
    assert hosts[0].ip == "192.168.1.102"
    assert hosts[0].link == "up"
    assert hosts[0].access == "permit"
    assert hosts[0].interface == "Bridge0"
    assert is_host_lan_isolated(hosts[0].interface, hosts[0].ip) is False
    assert is_host_lan_isolated(hosts[1].interface, hosts[1].ip) is True

    # Test state mutation: set_device_policy to deny mutates mock host state
    res = await client.set_device_policy("00:1C:62:33:44:55", access="deny")
    assert res is True
    updated_hosts = await client.get_hotspot_hosts()
    tv_host = next(h for h in updated_hosts if h.mac == "00:1C:62:33:44:55")
    assert tv_host.access == "deny"

    # Test failure mode: isolate_device_to_segment on Bridge0 host must return False
    iso_res = await client.isolate_device_to_segment("00:1C:62:33:44:55", segment_id="Guest")
    assert iso_res is False

@pytest.mark.asyncio
async def test_database_crud(tmp_path):
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()

    # 1. Insert device
    dev = DeviceRecord(
        mac="00:1C:62:AA:BB:CC",
        ip="192.168.1.50",
        hostname="Smart-Media-TV",
        vendor="Smart TV Media",
        profile="smart_tv",
        is_online=True
    )
    await test_db.upsert_device(dev)

    # 2. Query device
    fetched = await test_db.get_device("00:1C:62:AA:BB:CC")
    assert fetched is not None
    assert fetched.hostname == "Smart-Media-TV"
    assert fetched.profile == "smart_tv"

    # 3. Update policy
    await test_db.update_device_policy("00:1C:62:AA:BB:CC", is_isolated_lan=True, night_mode_enabled=True)
    updated = await test_db.get_device("00:1C:62:AA:BB:CC")
    assert updated.is_isolated_lan is True
    assert updated.night_mode_enabled is True

    # 4. Insert Security Event
    event = SecurityEvent(
        event_type="night_wake",
        severity="warning",
        target_mac="00:1C:62:AA:BB:CC",
        target_ip="192.168.1.50",
        description="Smart TV turned on at 03:15 AM"
    )
    event_id = await test_db.record_event(event)
    assert event_id > 0

    events = await test_db.get_recent_events(limit=10)
    assert len(events) == 1
    assert events[0].event_type == "night_wake"
