# -*- coding: utf-8 -*-
import pytest
from unittest.mock import AsyncMock, patch
from keenguard.core.routers.models import RouterHost, RouterSystemInfo
from keenguard.db.models import DeviceRecord
from keenguard.db.database import Database
from keenguard.web.workers import do_keenetic_poll


@pytest.mark.asyncio
async def test_mac_rotation_policy_inheritance(tmp_path):
    """
    Verify that when a known device with customized profile/name connects with a new
    randomized MAC address (LAA), it automatically inherits its profile, custom_name,
    and settings without triggering a false-alarm quarantine or alert.
    """
    test_db = Database(db_path=tmp_path / "test_inheritance.db")
    await test_db.init_db()

    # Pre-existing hardware / initial device
    parent = DeviceRecord(
        mac="2C:DA:46:00:00:01",
        ip="192.168.1.101",
        hostname="Alex-Galaxy-Phone",
        custom_name="Phone-Alex",
        vendor="Samsung Electronics (Mobile)",
        profile="trusted",
        custom_allowed_ports=[8080, 9000],
        is_online=False
    )
    await test_db.upsert_device(parent)

    mock_host = RouterHost(
        mac="EA:11:22:33:44:55",  # LAA (bit 1 is 1)
        ip="192.168.1.150",
        hostname="Alex-Galaxy-Phone",
        name="Alex-Galaxy-Phone",
        link="up",
        active=True,
        rxbytes=1000,
        txbytes=1000,
        segment="Home"
    )

    mock_backend = AsyncMock()
    mock_backend.platform_id = "keenetic"
    mock_backend.platform_name = "KeeneticOS"
    mock_backend.get_hosts.return_value = [mock_host]
    mock_backend.get_system_info.return_value = RouterSystemInfo(
        model="Keenetic Extra", firmware_version="4.2", memory_total=256000, memory_free=128000
    )
    mock_backend.get_wan_ip.return_value = "1.2.3.4"
    mock_backend.get_upnp_mappings.return_value = []
    mock_backend.get_interface_stats.return_value = {"rx_bytes": 0, "tx_bytes": 0}

    with patch("keenguard.web.workers.get_db", return_value=test_db), \
         patch("keenguard.web.state.get_db", return_value=test_db), \
         patch("keenguard.core.routers.router_manager.get_backend", return_value=mock_backend), \
         patch("keenguard.web.workers.is_host_lan_isolated", return_value=False), \
         patch("keenguard.web.workers.notifier.send_alert", new_callable=AsyncMock) as mock_alert:

        await do_keenetic_poll()

        # Check the newly created device in DB
        new_dev = await test_db.get_device("EA:11:22:33:44:55")
        assert new_dev is not None
        assert new_dev.profile == "trusted", "New rotated MAC must inherit 'trusted' profile"
        assert new_dev.custom_name == "Phone-Alex", "New rotated MAC must inherit custom_name"
        assert new_dev.custom_allowed_ports == [8080, 9000]
        assert new_dev.is_blocked_wan is False, "Inherited trusted device must not be quarantined"

        # Check recorded event
        events = await test_db.get_recent_events(limit=10)
        rot_events = [e for e in events if e.event_type == "mac_rotation"]
        assert len(rot_events) >= 1, "Must emit 'mac_rotation' event"
        assert rot_events[0].target_mac == "EA:11:22:33:44:55"
        assert "trusted" in rot_events[0].description
        assert "2C:DA:46:00:00:01" in rot_events[0].description
