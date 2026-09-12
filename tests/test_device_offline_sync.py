# -*- coding: utf-8 -*-
"""
Unit tests for Keenetic device offline synchronization and active flag verification in do_keenetic_poll().

Audits two critical issues:
1. Devices present in the database with is_online=True that disappear from Keenetic's get_hotspot_hosts()
   response must be marked as is_online=False.
2. Hosts returned by Keenetic with link='up' but active=False must be treated as is_online=False.
"""

from unittest.mock import AsyncMock
import pytest

from keenguard.core.keenetic import HotspotHost, keenetic_client
from keenguard.db.database import Database, db
from keenguard.db.models import DeviceRecord
from keenguard.web.app import do_keenetic_poll


@pytest.mark.asyncio
async def test_devices_absent_from_keenetic_must_go_offline(tmp_path, monkeypatch):
    """
    Test that devices stored in the database with is_online=True that are no longer
    returned in Keenetic get_hotspot_hosts() are correctly transitioned to is_online=False.
    """
    # 1. Setup isolated database
    test_db = Database(db_path=tmp_path / "test_offline_sync.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.db.database.db", test_db)
    monkeypatch.setattr(db, "db_path", tmp_path / "test_offline_sync.db")
    monkeypatch.setattr("keenguard.web.app._poll_counter", 0)

    # 2. Insert DEV_1 and DEV_2 as online
    dev1_mac = "00:11:22:33:44:01"
    dev2_mac = "00:11:22:33:44:02"

    dev1 = DeviceRecord(
        mac=dev1_mac,
        ip="192.168.1.101",
        hostname="DEV_1",
        vendor="Keenetic-Client-1",
        profile="trusted",
        is_online=True,
    )
    dev2 = DeviceRecord(
        mac=dev2_mac,
        ip="192.168.1.102",
        hostname="DEV_2",
        vendor="Keenetic-Client-2",
        profile="iot",
        is_online=True,
    )
    await test_db.upsert_device(dev1)
    await test_db.upsert_device(dev2)

    # Verify initial database state
    stored_dev1 = await test_db.get_device(dev1_mac)
    stored_dev2 = await test_db.get_device(dev2_mac)
    assert stored_dev1 is not None and stored_dev1.is_online is True
    assert stored_dev2 is not None and stored_dev2.is_online is True

    # 3. Mock Keenetic client so get_hotspot_hosts() returns ONLY DEV_1
    keenetic_client.mock_mode = True
    mock_host_1 = HotspotHost(
        mac=dev1_mac,
        ip="192.168.1.101",
        hostname="DEV_1",
        name="DEV_1",
        interface="Bridge0",
        link="up",
        active=True,
        access="permit",
        rxbytes=5000,
        txbytes=5000,
    )

    monkeypatch.setattr(
        "keenguard.web.app.keenetic_client.get_hotspot_hosts",
        AsyncMock(return_value=[mock_host_1]),
    )
    monkeypatch.setattr(
        "keenguard.core.keenetic.keenetic_client.get_hotspot_hosts",
        AsyncMock(return_value=[mock_host_1]),
    )

    # 4. Trigger router poll
    await do_keenetic_poll()

    # 5. Check resulting device states in the database
    updated_dev1 = await test_db.get_device(dev1_mac)
    updated_dev2 = await test_db.get_device(dev2_mac)

    assert updated_dev1 is not None
    assert updated_dev1.is_online is True, "DEV_1 is reported by Keenetic and must remain online"

    assert updated_dev2 is not None
    assert updated_dev2.is_online is False, (
        "DEV_2 is absent from Keenetic get_hotspot_hosts() and must be marked is_online=False, "
        "but remained is_online=True because do_keenetic_poll() only iterates over reported hosts."
    )


@pytest.mark.asyncio
async def test_device_with_active_false_must_be_offline(tmp_path, monkeypatch):
    """
    Test that a host returned by Keenetic with link='up' but active=False
    is considered offline (is_online=False).
    """
    # 1. Setup isolated database
    test_db = Database(db_path=tmp_path / "test_inactive_sync.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.db.database.db", test_db)
    monkeypatch.setattr(db, "db_path", tmp_path / "test_inactive_sync.db")
    monkeypatch.setattr("keenguard.web.app._poll_counter", 0)

    dev_mac = "00:11:22:33:44:03"
    dev = DeviceRecord(
        mac=dev_mac,
        ip="192.168.1.105",
        hostname="Cached-Inactive-Device",
        vendor="VendorTest",
        profile="trusted",
        is_online=True,
    )
    await test_db.upsert_device(dev)

    # 2. Mock Keenetic client: host has link='up', but active=False
    keenetic_client.mock_mode = True
    mock_host = HotspotHost(
        mac=dev_mac,
        ip="192.168.1.105",
        hostname="Cached-Inactive-Device",
        name="Cached-Inactive-Device",
        interface="Bridge0",
        link="up",
        active=False,
        access="permit",
        rxbytes=1000,
        txbytes=1000,
    )

    monkeypatch.setattr(
        "keenguard.web.app.keenetic_client.get_hotspot_hosts",
        AsyncMock(return_value=[mock_host]),
    )
    monkeypatch.setattr(
        "keenguard.core.keenetic.keenetic_client.get_hotspot_hosts",
        AsyncMock(return_value=[mock_host]),
    )

    # 3. Trigger router poll
    await do_keenetic_poll()

    # 4. Check device state in database
    updated_dev = await test_db.get_device(dev_mac)
    assert updated_dev is not None
    assert updated_dev.is_online is False, (
        "Host with link='up' but active=False must be marked is_online=False, "
        "but do_keenetic_poll() evaluated is_online solely based on (link == 'up')."
    )
