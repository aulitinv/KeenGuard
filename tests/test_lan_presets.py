"""Tests for LAN Policy Presets subsystem."""
import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.db.database import Database, BUILTIN_LAN_PRESETS
from keenguard.db.models import LanPolicyPreset, DeviceRecord

@pytest.mark.asyncio
async def test_builtin_presets_seeded(tmp_path):
    test_db = Database(db_path=tmp_path / "presets.db")
    await test_db.init_db()

    presets = await test_db.get_presets()
    assert len(presets) >= 5

    preset_ids = {p.id for p in presets}
    assert "preset_smart_tv" in preset_ids
    assert "preset_camera" in preset_ids
    assert "preset_iot" in preset_ids
    assert "preset_trusted" in preset_ids
    assert "preset_isolated_guest" in preset_ids

    # Check built-in flag
    tv_preset = await test_db.get_preset("preset_smart_tv")
    assert tv_preset is not None
    assert tv_preset.is_builtin is True
    assert any("8200" in s for s in tv_preset.rules.get("allowed_services", []))

@pytest.mark.asyncio
async def test_custom_preset_crud(tmp_path):
    test_db = Database(db_path=tmp_path / "presets_custom.db")
    await test_db.init_db()

    custom = LanPolicyPreset(
        id="preset_nas_storage",
        name="Сетевое хранилище (NAS)",
        description="Разрешает SMB, NFS, DLNA, запрещает управление роутером",
        is_builtin=False,
        rules={
            "allowed_ports": [445, 2049, 8200],
            "alert_ports": [22, 23],
            "quarantine_ports": [5555]
        }
    )
    saved = await test_db.save_preset(custom)
    assert saved.id == "preset_nas_storage"

    fetched = await test_db.get_preset("preset_nas_storage")
    assert fetched is not None
    assert fetched.name == "Сетевое хранилище (NAS)"
    assert 445 in fetched.rules["allowed_ports"]

    # Delete custom preset
    deleted = await test_db.delete_preset("preset_nas_storage")
    assert deleted is True

    fetched_after = await test_db.get_preset("preset_nas_storage")
    assert fetched_after is None

@pytest.mark.asyncio
async def test_api_presets_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. GET /api/presets
        res = await ac.get("/api/presets")
        assert res.status_code == 200
        data = res.json()
        assert len(data) >= 5

        # 2. GET /api/presets/preset_camera
        res_single = await ac.get("/api/presets/preset_camera")
        assert res_single.status_code == 200
        cam_p = res_single.json()
        assert cam_p["id"] == "preset_camera"
        assert cam_p["is_builtin"] is True

        # 3. POST /api/presets (Create custom)
        new_payload = {
            "id": "custom_iot_test",
            "name": "Custom Test Preset",
            "description": "Custom rules description",
            "rules": {"allowed_ports": [1883, 8883], "alert_ports": [22]}
        }
        res_create = await ac.post("/api/presets", json=new_payload)
        assert res_create.status_code == 200
        created = res_create.json()
        assert created["id"] == "custom_iot_test"
        assert created["is_builtin"] is False

        # 4. PUT /api/presets/preset_camera (Attempt to edit builtin -> 400)
        res_edit_builtin = await ac.put("/api/presets/preset_camera", json={
            "name": "Hacked Camera",
            "rules": {}
        })
        assert res_edit_builtin.status_code == 400

        # 5. PUT /api/presets/custom_iot_test (Edit custom -> 200)
        res_edit_custom = await ac.put("/api/presets/custom_iot_test", json={
            "name": "Updated Test Preset",
            "rules": {"allowed_ports": [1883]}
        })
        assert res_edit_custom.status_code == 200
        assert res_edit_custom.json()["name"] == "Updated Test Preset"

        # 6. DELETE /api/presets/preset_camera (Attempt to delete builtin -> 400)
        res_del_builtin = await ac.delete("/api/presets/preset_camera")
        assert res_del_builtin.status_code == 400

        # 7. DELETE /api/presets/custom_iot_test (Delete custom -> 200)
        res_del_custom = await ac.delete("/api/presets/custom_iot_test")
        assert res_del_custom.status_code == 200

@pytest.mark.asyncio
async def test_api_device_lan_policy_update():
    from keenguard.db.database import db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        mac = "E0:D5:5E:11:22:33"
        await db.upsert_device(DeviceRecord(
            mac=mac,
            ip="192.168.1.180",
            hostname="Front-Camera",
            profile="camera"
        ))

        # Update LAN policy
        policy_payload = {
            "preset_id": "preset_camera",
            "designated_nvr_ip": "192.168.1.200",
            "auto_quarantine_override": "always_quarantine",
            "custom_allowed_ports": [554, 80]
        }
        res = await ac.post(f"/api/devices/{mac}/lan-policy", json=policy_payload)
        assert res.status_code == 200
        updated = res.json()["device"]
        assert updated["preset_id"] == "preset_camera"
        assert updated["designated_nvr_ip"] == "192.168.1.200"
        assert updated["auto_quarantine_override"] == "always_quarantine"
        assert updated["custom_allowed_ports"] == [554, 80]
