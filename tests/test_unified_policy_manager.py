"""Tests for Unified PolicyManager and Network Policy synchronization."""
import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord
from keenguard.core.profiles import policy_manager, PolicyManager, PROFILE_TO_PRESET_MAP, PRESET_TO_PROFILE_MAP
from keenguard.core.keenetic import keenetic_client

@pytest.mark.asyncio
async def test_policy_manager_smart_defaults():
    mac = "02:00:00:11:22:01"
    await db.upsert_device(DeviceRecord(
        mac=mac,
        ip="192.168.1.101",
        hostname="Living-Room-TV",
        profile="unassigned"
    ))

    # 1. Apply 'smart_tv' profile -> auto syncs preset_smart_tv
    updated = await policy_manager.apply_policy(mac, policy_id="smart_tv")
    assert updated is not None
    assert updated.profile == "smart_tv"
    assert updated.preset_id == "preset_smart_tv"
    assert updated.airplay_allowed is True
    assert updated.dlna_allowed is True
    assert updated.night_mode_enabled is True

    # 2. Apply 'camera' profile -> auto syncs preset_camera
    updated_cam = await policy_manager.apply_policy(mac, policy_id="camera")
    assert updated_cam.profile == "camera"
    assert updated_cam.preset_id == "preset_camera"

    # 3. Apply 'iot' profile -> auto syncs preset_iot
    updated_iot = await policy_manager.apply_policy(mac, policy_id="iot")
    assert updated_iot.profile == "iot"
    assert updated_iot.preset_id == "preset_iot"

@pytest.mark.asyncio
async def test_policy_manager_preset_to_profile_reverse_mapping():
    mac = "02:00:00:11:22:02"
    await db.upsert_device(DeviceRecord(
        mac=mac,
        ip="192.168.1.102",
        hostname="Yard-Camera",
        profile="unassigned"
    ))

    # Applying a preset key should resolve the corresponding profile
    updated = await policy_manager.apply_policy(mac, policy_id="preset_camera")
    assert updated is not None
    assert updated.preset_id == "preset_camera"
    assert updated.profile == "camera"

@pytest.mark.asyncio
async def test_policy_manager_custom_preset_and_overrides():
    mac = "02:00:00:11:22:03"
    await db.upsert_device(DeviceRecord(
        mac=mac,
        ip="192.168.1.103",
        hostname="Custom-Server",
        profile="trusted"
    ))

    # Apply policy with granular overrides (accordion settings)
    updated = await policy_manager.apply_policy(
        mac=mac,
        policy_id="custom_nas_backup",
        designated_nvr_ip="192.168.1.250",
        auto_quarantine_override="never_quarantine",
        custom_allowed_ports=[8080, 9000, 5000]
    )
    assert updated is not None
    assert updated.preset_id == "custom_nas_backup"
    assert updated.designated_nvr_ip == "192.168.1.250"
    assert updated.auto_quarantine_override == "never_quarantine"
    assert updated.custom_allowed_ports == [8080, 9000, 5000]
    # Existing profile preserved for custom preset
    assert updated.profile == "trusted"

@pytest.mark.asyncio
async def test_policy_manager_hardware_wan_sync():
    mac = "02:00:00:11:22:04"
    await db.upsert_device(DeviceRecord(
        mac=mac,
        ip="192.168.1.104",
        hostname="Suspicious-IoT",
        profile="trusted",
        is_blocked_wan=False
    ))

    with patch.object(keenetic_client, "set_device_policy", new_callable=AsyncMock) as mock_set_policy:
        # 1. Quarantine -> Keenetic router access="deny"
        await policy_manager.quarantine_device(mac, reason="Suspicious port scanning")
        mock_set_policy.assert_called_with(mac, access="deny")

        dev_quar = await db.get_device(mac)
        assert dev_quar.profile == "quarantine"
        assert dev_quar.is_blocked_wan is True

        # Check security event recorded
        events = await db.get_recent_events(limit=5)
        quar_ev = next((e for e in events if e.target_mac == mac and e.event_type == "quarantine"), None)
        assert quar_ev is not None
        assert "Suspicious port scanning" in quar_ev.description

        # 2. Trust device -> Keenetic router access="permit"
        await policy_manager.trust_device(mac)
        mock_set_policy.assert_called_with(mac, access="permit")

        dev_trusted = await db.get_device(mac)
        assert dev_trusted.profile == "trusted"
        assert dev_trusted.is_blocked_wan is False

@pytest.mark.asyncio
async def test_api_unified_device_policy_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mac = "02:00:00:11:22:05"
        await db.upsert_device(DeviceRecord(
            mac=mac,
            ip="192.168.1.105",
            hostname="Smart-Hub",
            profile="unassigned"
        ))

        # POST /api/devices/{mac}/policy
        payload = {
            "policy_id": "smart_home_hub",
            "custom_allowed_ports": [8123, 1883],
            "auto_quarantine_override": "always_quarantine"
        }
        res = await ac.post(f"/api/devices/{mac}/policy", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        dev = data["device"]
        assert dev["profile"] == "smart_home_hub"
        assert dev["preset_id"] == "preset_iot"
        assert dev["custom_allowed_ports"] == [8123, 1883]
        assert dev["auto_quarantine_override"] == "always_quarantine"

@pytest.mark.asyncio
async def test_api_backward_compatibility():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mac = "02:00:00:11:22:06"
        await db.upsert_device(DeviceRecord(
            mac=mac,
            ip="192.168.1.106",
            hostname="Old-API-Client",
            profile="unassigned"
        ))

        # 1. Legacy /api/devices/{mac}/profile
        res_prof = await ac.post(f"/api/devices/{mac}/profile", json={"profile": "smart_tv"})
        assert res_prof.status_code == 200
        data_prof = res_prof.json()["device"]
        assert data_prof["profile"] == "smart_tv"
        assert data_prof["preset_id"] == "preset_smart_tv"

        # 2. Legacy /api/devices/{mac}/lan-policy
        res_lan = await ac.post(f"/api/devices/{mac}/lan-policy", json={
            "preset_id": "preset_camera",
            "designated_nvr_ip": "192.168.1.222",
            "custom_allowed_ports": [554]
        })
        assert res_lan.status_code == 200
        data_lan = res_lan.json()["device"]
        assert data_lan["preset_id"] == "preset_camera"
        assert data_lan["designated_nvr_ip"] == "192.168.1.222"
        assert data_lan["custom_allowed_ports"] == [554]
