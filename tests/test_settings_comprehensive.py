import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app, lifespan
from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord

@pytest.mark.asyncio
async def test_all_settings_end_to_end():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Update settings with full payload
        payload = {
            "router_host": "192.168.1.1",
            "router_user": "admin",
            "night_mode_start_hour": 2,
            "night_mode_end_hour": 5,
            "tv_wake_pre_record_seconds": 45,
            "tv_wake_post_record_seconds": 90,
            "tv_wake_trigger_ttl_seconds": 120,
            "tv_day_tracking_mode": "all",
            "scheduled_audit_enabled": True,
            "scheduled_audit_hour": 4,
            "scheduled_audit_scope": "iot_only",
            "scheduled_audit_duration": 180,
            "camera_upload_threshold_kbps": 2400.0,
            "camera_notify_wan_stream": False,
            "camera_notify_lan_stream": True,
            "auto_quarantine_scope": "all_except_trusted",
            "mac_conflict_detection_enabled": False,
            "notification_dedup_window_seconds": 45,
            "iot_payload_capture_enabled": True,
            "iot_payload_max_storage_gb": 4.5,
            "iot_payload_retention_days": 14,
            "new_device_policy_mode": "category",
            "new_device_category_policies": {
                "trusted": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": False, "audit_duration": 300, "telegram_alert": True},
                "iot": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
                "camera": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
                "random_mac": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
                "unknown": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
            }
        }
        res = await ac.post("/api/settings", json=payload)
        assert res.status_code == 200

        # Verify in memory settings
        assert settings.scheduled_audit_duration == 180
        assert settings.tv_wake_trigger_ttl_seconds == 120
        assert settings.camera_upload_threshold_kbps == 2400.0
        assert settings.camera_notify_wan_stream is False
        assert settings.camera_notify_lan_stream is True
        assert settings.auto_quarantine_scope == "all_except_trusted"
        assert settings.mac_conflict_detection_enabled is False
        assert settings.notification_dedup_window_seconds == 45
        assert settings.iot_payload_max_storage_gb == 4.5
        assert settings.iot_payload_retention_days == 14

        # Verify in DB
        assert await db.get_setting("scheduled_audit_duration") == "180"
        assert await db.get_setting("tv_wake_trigger_ttl_seconds") == "120"
        assert await db.get_setting("camera_upload_threshold_kbps") == "2400.0"
        assert await db.get_setting("iot_payload_max_storage_gb") == "4.5"
        assert await db.get_setting("iot_payload_retention_days") == "14"

        # Verify GET /api/settings returns all fields
        res_get = await ac.get("/api/settings")
        assert res_get.status_code == 200
        data = res_get.json()
        assert data["scheduled_audit_duration"] == 180
        assert data["tv_wake_trigger_ttl_seconds"] == 120
        assert data["camera_upload_threshold_kbps"] == 2400.0
        assert data["iot_payload_max_storage_gb"] == 4.5
        assert data["iot_payload_retention_days"] == 14

        # Reset memory settings and verify lifespan reload
        settings.scheduled_audit_duration = 60
        settings.tv_wake_trigger_ttl_seconds = 60
        settings.camera_upload_threshold_kbps = 1500.0
        settings.iot_payload_max_storage_gb = 1.0
        settings.iot_payload_retention_days = 7

        async with lifespan(app):
            assert settings.scheduled_audit_duration == 180
            assert settings.tv_wake_trigger_ttl_seconds == 120
            assert settings.camera_upload_threshold_kbps == 2400.0
            assert settings.iot_payload_max_storage_gb == 4.5
            assert settings.iot_payload_retention_days == 14

@pytest.mark.asyncio
async def test_device_lan_policy_reset_clears_preset():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        test_mac = "AA:BB:CC:11:22:33"
        await db.upsert_device(DeviceRecord(
            mac=test_mac,
            ip="192.168.1.55",
            hostname="test-device",
            preset_id="preset_camera"
        ))

        dev = await db.get_device(test_mac)
        assert dev.preset_id == "preset_camera"

        # Reset preset by passing empty string
        res = await ac.post(f"/api/devices/{test_mac}/lan-policy", json={"preset_id": ""})
        assert res.status_code == 200

        dev_after = await db.get_device(test_mac)
        assert dev_after.preset_id is None
