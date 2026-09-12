# -*- coding: utf-8 -*-
"""Unit tests verifying zero-fiction reality synchronization between Keenetic router and KeenGuard."""
import pytest
from keenguard.core.keenetic import is_host_lan_isolated, HotspotHost
from keenguard.core.profiles import PROFILE_TEMPLATES
from keenguard.core.checklist import SecurityChecklistEvaluator
from keenguard.db.models import DeviceRecord
from keenguard.db.database import db


def test_is_host_lan_isolated():
    """Verify that Bridge0 (home Wi-Fi) is never treated as isolated, but Bridge1/Guest is."""
    # Main home network Bridge0 (192.168.1.x) - MUST be False (Not isolated)
    assert is_host_lan_isolated("Bridge0", "192.168.1.137") is False
    assert is_host_lan_isolated("Bridge0", "192.168.1.101") is False
    assert is_host_lan_isolated(None, "192.168.1.1") is False

    # Guest network Bridge1 or non-home subnet - MUST be True (Isolated)
    assert is_host_lan_isolated("Bridge1", "10.1.30.50") is True
    assert is_host_lan_isolated("guest_wifi", "172.16.1.10") is True
    assert is_host_lan_isolated("Bridge1", None) is True
    assert is_host_lan_isolated(None, "10.1.30.15") is True

    # Empty inputs
    assert is_host_lan_isolated(None, None) is False
    assert is_host_lan_isolated("Bridge0", None) is False



def test_profile_templates_no_fake_isolation():
    """Verify that predefined profiles do not assume devices are isolated by default."""
    for key in ('smart_tv', 'camera', 'iot', 'trusted', 'unassigned'):
        assert PROFILE_TEMPLATES[key]["is_isolated_lan"] is False


@pytest.mark.asyncio
async def test_checklist_smart_tv_reality(tmp_path, monkeypatch):
    """Verify that Smart TV on Bridge0 is truthfully flagged as nuisolated in Home network."""
    monkeypatch.setattr(db, "db_path", tmp_path / "test_keenguard.db")
    await db.init_db()
    tv_mac = "6C:1F:F7:5F:60:4A"
    tv_rec = DeviceRecord(
        mac=tv_mac,
        ip="192.168.1.137",
        hostname="Smart-Media-TV",
        profile="smart_tv",
        is_blocked_wan=False,
        is_isolated_lan=False,
        night_mode_enabled=True,
        is_online=True
    )
    await db.upsert_device(tv_rec)

    res = await SecurityChecklistEvaluator.evaluate_checklist()
    tv_check = next((i for i in res["items"] if i["id"] == "smart_tv_security"), None)
    assert tv_check is not None
    assert tv_check["status"] == "warning"
    assert "Bridge0" in tv_check["live_status"]
    assert "пассивный ночной" in tv_check["live_status"].lower()


@pytest.mark.asyncio
async def test_toggle_lan_cannot_fake_isolation_on_bridge0(tmp_path, monkeypatch):
    """Verify that toggle_lan_isolation refuses to falsely mark a Bridge0 device as isolated."""
    from keenguard.core.profiles import profile_manager
    from keenguard.core.keenetic import keenetic_client

    monkeypatch.setattr(db, "db_path", tmp_path / "test_keenguard.db")
    await db.init_db()
    mac = "AA:11:22:33:44:55"
    # Device in Bridge0 home network
    dev = DeviceRecord(
        mac=mac,
        ip="192.168.1.88",
        hostname="Unprotectable-Device",
        profile="iot",
        is_isolated_lan=False
    )
    await db.upsert_device(dev)

    keenetic_client.mock_mode = True
    keenetic_client._mock_hosts = [
        {"mac": mac, "ip": "192.168.1.88", "interface": "Bridge0", "link": "up", "access": "permit"}
    ]

    # Attempting to isolate a device on Bridge0 MUST return False and leave DB as False
    isolated = await profile_manager.toggle_lan_isolation(mac, isolate=True)
    assert isolated is False

    updated_dev = await db.get_device(mac)
    assert updated_dev.is_isolated_lan is False


@pytest.mark.asyncio
async def test_appliances_checklist_warning_when_on_bridge0(tmp_path, monkeypatch):
    """Verify that Check 3 (appliances) reports warning when devices are on Bridge0."""
    monkeypatch.setattr(db, "db_path", tmp_path / "test_keenguard.db")
    await db.init_db()
    robot_mac = "70:C9:32:57:FD:7F"
    robot = DeviceRecord(
        mac=robot_mac,
        ip="192.168.1.64",
        hostname="smart-vacuum-cleaner",
        profile="iot",
        is_isolated_lan=False,
        is_online=True
    )
    await db.upsert_device(robot)

    res = await SecurityChecklistEvaluator.evaluate_checklist()
    app_check = next((i for i in res["items"] if i["id"] == "appliance_lan_isolation"), None)
    assert app_check is not None
    # Because appliance is in Bridge0, status MUST be warning!
    assert app_check["status"] == "warning"
    assert "Bridge0" in app_check["live_status"]
