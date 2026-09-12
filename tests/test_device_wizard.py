"""Tests for Adaptive Device Setup Wizard subsystem."""
import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord

@pytest.mark.asyncio
async def test_wizard_context_device_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/wizard/device/00:11:22:33:44:99")
        assert res.status_code == 404

@pytest.mark.asyncio
async def test_wizard_context_and_isolation_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Device on main Bridge0 (192.168.1.102) - NOT isolated physically
        mac_tv = "AA:BB:CC:11:22:33"
        await db.upsert_device(DeviceRecord(
            mac=mac_tv,
            ip="192.168.1.102",
            hostname="Smart-Media-TV",
            profile="smart_tv",
            interface="Bridge0"
        ))

        # Add a NAS / NVR candidate in network
        mac_nas = "AA:BB:CC:44:55:66"
        await db.upsert_device(DeviceRecord(
            mac=mac_nas,
            ip="192.168.1.200",
            hostname="Storage-NAS-NVR",
            profile="nas"
        ))

        res = await ac.get(f"/api/wizard/device/{mac_tv}")
        assert res.status_code == 200
        data = res.json()
        assert data["device"]["mac"] == mac_tv
        assert data["recommended_preset"] == "preset_smart_tv"
        assert data["physically_isolated"] is False
        assert data["requires_guest_wifi_for_isolation"] is True
        assert len(data["presets"]) >= 5
        # Verify NVR/DLNA candidate list contains the NAS
        assert any(c["ip"] == "192.168.1.200" for c in data["nvr_candidates"])
        assert any(c["ip"] == "192.168.1.200" for c in data["dlna_candidates"])

@pytest.mark.asyncio
async def test_wizard_submit_smart_tv():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mac = "11:22:33:44:55:66"
        await db.upsert_device(DeviceRecord(
            mac=mac,
            ip="192.168.1.150",
            hostname="Smart-Media-TV",
            profile="unassigned"
        ))

        payload = {
            "custom_name": "Гостиная ТВ",
            "profile": "smart_tv",
            "preset_id": "preset_smart_tv",
            "auto_quarantine_override": "never_quarantine",
            "tv_pre_record_seconds": 30,
            "tv_post_record_seconds": 60,
            "tv_day_mode": "autonomous_only"
        }
        res = await ac.post(f"/api/wizard/device/{mac}", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        dev = data["device"]
        assert dev["custom_name"] == "Гостиная ТВ"
        assert dev["profile"] == "smart_tv"
        assert dev["preset_id"] == "preset_smart_tv"
        assert dev["auto_quarantine_override"] == "never_quarantine"
        assert dev["tv_pre_record_seconds"] == 30
        assert dev["tv_post_record_seconds"] == 60
        assert dev["tv_day_mode"] == "autonomous_only"
        assert dev["wizard_completed"] is True

        # Verify persisted in database
        db_dev = await db.get_device(mac)
        assert db_dev is not None
        assert db_dev.wizard_completed is True
        assert db_dev.tv_pre_record_seconds == 30

@pytest.mark.asyncio
async def test_wizard_submit_camera_with_nvr():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mac = "33:44:55:66:77:88"
        await db.upsert_device(DeviceRecord(
            mac=mac,
            ip="192.168.1.185",
            hostname="Camera-Entrance",
            profile="camera"
        ))

        payload = {
            "custom_name": "Камера Вход",
            "profile": "camera",
            "preset_id": "preset_camera",
            "designated_nvr_ip": "192.168.1.200",
            "auto_quarantine_override": "always_quarantine",
            "custom_allowed_ports": [554, 80]
        }
        res = await ac.post(f"/api/wizard/device/{mac}", json=payload)
        assert res.status_code == 200
        dev = res.json()["device"]
        assert dev["designated_nvr_ip"] == "192.168.1.200"
        assert dev["auto_quarantine_override"] == "always_quarantine"
        assert dev["custom_allowed_ports"] == [554, 80]
        assert dev["wizard_completed"] is True
