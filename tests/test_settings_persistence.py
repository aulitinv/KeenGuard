import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app, lifespan
from keenguard.config import settings
from keenguard.db.database import db

@pytest.mark.asyncio
async def test_settings_saved_and_persisted():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        payload = {
            "router_host": "192.168.1.1",
            "router_user": "admin",
            "night_mode_start_hour": 1,
            "night_mode_end_hour": 6,
            "digest_enabled": True,
            "digest_schedule_hour": 11,
            "digest_condition": "always",
            "scheduled_audit_enabled": True,
            "scheduled_audit_hour": 4,
            "scheduled_audit_scope": "iot_only",
            "scheduled_audit_duration": 120
        }
        res = await ac.post("/api/settings", json=payload)
        assert res.status_code == 200

        assert await db.get_setting("night_mode_start_hour") == "1"
        assert await db.get_setting("night_mode_end_hour") == "6"
        assert await db.get_setting("digest_schedule_hour") == "11"

        storage_payload = {
            "max_storage_gb": 2.5,
            "retention_days": 14,
            "capture_enabled": True
        }
        res_stor = await ac.post("/api/settings/iot_storage", json=storage_payload)
        assert res_stor.status_code == 200

        assert await db.get_setting("iot_payload_max_storage_gb") == "2.5"
        assert await db.get_setting("iot_payload_retention_days") == "14"

        settings.night_mode_start_hour = 0
        settings.night_mode_end_hour = 7
        settings.digest_schedule_hour = 9
        settings.iot_payload_max_storage_gb = 1.0
        settings.iot_payload_retention_days = 7

        async with lifespan(app):
            assert settings.night_mode_start_hour == 1
            assert settings.night_mode_end_hour == 6
            assert settings.digest_schedule_hour == 11
            assert settings.iot_payload_max_storage_gb == 2.5
            assert settings.iot_payload_retention_days == 14

@pytest.mark.asyncio
async def test_empty_strings_do_not_erase_credentials_or_corrupt_settings():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # First save valid credentials
        setup_payload = {
            "router_host": "192.168.1.1",
            "router_user": "admin",
            "telegram_bot_token": "TEST_TOKEN_123",
            "telegram_chat_id": "TEST_CHAT_456"
        }
        res1 = await ac.post("/api/settings", json=setup_payload)
        assert res1.status_code == 200
        assert settings.router_host == "192.168.1.1"
        assert settings.router_user == "admin"
        assert settings.telegram_bot_token == "TEST_TOKEN_123"
        assert settings.telegram_chat_id == "TEST_CHAT_456"

        # Now send empty strings for credentials along with unrelated changes
        bad_payload = {
            "router_host": "   ",
            "router_user": "",
            "telegram_bot_token": "",
            "telegram_chat_id": "   ",
            "night_mode_start_hour": 25,  # Out of range, should be clamped to 23
            "night_mode_end_hour": -5     # Out of range, should be clamped to 0
        }
        res2 = await ac.post("/api/settings", json=bad_payload)
        assert res2.status_code == 200

        # Existing credentials MUST NOT be erased by empty strings!
        assert settings.router_host == "192.168.1.1"
        assert settings.router_user == "admin"
        assert settings.telegram_bot_token == "TEST_TOKEN_123"
        assert settings.telegram_chat_id == "TEST_CHAT_456"

        # Clamped values check
        assert settings.night_mode_start_hour == 23
        assert settings.night_mode_end_hour == 0

        # IoT storage clamping test (negative / zero retention days or storage)
        res_stor = await ac.post("/api/settings/iot_storage", json={
            "max_storage_gb": -10.0,
            "retention_days": 0
        })
        assert res_stor.status_code == 200
        assert settings.iot_payload_max_storage_gb >= 0.1
        assert settings.iot_payload_retention_days >= 1

