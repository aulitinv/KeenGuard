import pytest
from pathlib import Path
from keenguard.config import Settings
from keenguard.core.config_service import ConfigService
from keenguard.core.keenetic import keenetic_client
from keenguard.core.forensics import forensics
from keenguard.core.anomaly import anomaly_detector
from keenguard.db.database import Database


@pytest.mark.asyncio
async def test_config_service_priority(tmp_path):
    test_db_path = tmp_path / "test_cfg.db"
    test_db = Database(test_db_path)
    await test_db.init_db()

    # Seed database with custom settings
    await test_db.set_settings_bulk({
        "night_mode_start_hour": "3",
        "night_mode_end_hour": "6",
        "camera_upload_threshold_kbps": "2500.5",
        "mac_conflict_detection_enabled": "false",
        "tv_day_tracking_mode": "all",
        "new_device_category_policies": '{"iot": {"quarantine_wan": true}}'
    })

    custom_settings = Settings()
    svc = ConfigService(settings_instance=custom_settings)
    await svc.initialize(database=test_db)

    # 1. Database values override Pydantic defaults and .env
    assert svc.get("night_mode_start_hour") == 3
    assert svc.get("night_mode_end_hour") == 6
    assert svc.get("camera_upload_threshold_kbps") == 2500.5
    assert svc.get("mac_conflict_detection_enabled") is False
    assert svc.get("tv_day_tracking_mode") == "all"
    assert svc.get("new_device_category_policies") == {"iot": {"quarantine_wan": True}}

    # 2. Parameters not in DB retain defaults
    assert svc.get("web_port") == 9989
    assert svc.get("scheduled_audit_duration") == 60


@pytest.mark.asyncio
async def test_config_service_reactive_subscription():
    custom_settings = Settings()
    svc = ConfigService(settings_instance=custom_settings)

    events_received = []

    def on_threshold_change(k, v):
        events_received.append((k, v))

    svc.subscribe("camera_upload_threshold_kbps", on_threshold_change)

    # Set value
    await svc.set("camera_upload_threshold_kbps", 3200.0, persist_db=False)
    assert len(events_received) == 1
    assert events_received[0] == ("camera_upload_threshold_kbps", 3200.0)
    assert svc.get("camera_upload_threshold_kbps") == 3200.0
    assert custom_settings.camera_upload_threshold_kbps == 3200.0

    # Unsubscribe
    svc.unsubscribe("camera_upload_threshold_kbps", on_threshold_change)
    await svc.set("camera_upload_threshold_kbps", 4000.0, persist_db=False)
    assert len(events_received) == 1  # No new event
    assert svc.get("camera_upload_threshold_kbps") == 4000.0


@pytest.mark.asyncio
async def test_config_service_wildcard_subscription():
    custom_settings = Settings()
    svc = ConfigService(settings_instance=custom_settings)

    all_changes = []

    def on_any_change(k, v):
        all_changes.append((k, v))

    svc.subscribe("*", on_any_change)

    await svc.update_bulk({
        "night_mode_start_hour": 1,
        "digest_condition": "always"
    }, persist_db=False)

    assert ("night_mode_start_hour", 1) in all_changes
    assert ("digest_condition", "always") in all_changes


def test_config_service_type_coercion():
    svc = ConfigService(settings_instance=Settings())

    # Booleans
    assert svc._coerce_type("telegram_enabled", "true") is True
    assert svc._coerce_type("telegram_enabled", "1") is True
    assert svc._coerce_type("telegram_enabled", "yes") is True
    assert svc._coerce_type("telegram_enabled", "false") is False
    assert svc._coerce_type("telegram_enabled", "0") is False

    # Integers
    assert svc._coerce_type("web_port", "9999") == 9999
    assert svc._coerce_type("night_mode_start_hour", "2") == 2

    # Floats
    assert svc._coerce_type("camera_upload_threshold_kbps", "2200.75") == 2200.75

    # JSON Dicts
    assert svc._coerce_type("new_device_category_policies", '{"trusted": true}') == {"trusted": True}

    # Strings
    assert svc._coerce_type("router_user", "myadmin") == "myadmin"

    # Corrupted / fallback values
    assert svc._coerce_type("web_port", "not_a_number") == 9989


@pytest.mark.asyncio
async def test_runtime_propagation_to_core_singletons():
    from keenguard.core.config_service import config_service

    # 1. KeeneticClient propagation
    await config_service.set("router_host", "192.168.1.222", persist_db=False)
    assert keenetic_client.host == "192.168.1.222"
    assert "192.168.1.222" in keenetic_client.router_ips
    assert keenetic_client.base_url == "http://192.168.1.222:80"

    # 2. ForensicsEngine propagation
    await config_service.set("night_mode_start_hour", 4, persist_db=False)
    await config_service.set("night_mode_end_hour", 8, persist_db=False)
    assert forensics.night_mode_start_hour == 4
    assert forensics.night_mode_end_hour == 8

    # 3. AnomalyDetector propagation
    await config_service.set("camera_upload_threshold_kbps", 2800.0, persist_db=False)
    await config_service.set("notification_dedup_window_seconds", 45, persist_db=False)
    assert anomaly_detector.camera_upload_threshold_kbps == 2800.0
    assert anomaly_detector.notification_dedup_window_seconds == 45


@pytest.mark.asyncio
async def test_database_bulk_persistence(tmp_path):
    test_db_path = tmp_path / "bulk_test.db"
    test_db = Database(test_db_path)
    await test_db.init_db()

    payload = {
        "scheduled_audit_duration": 240,
        "scheduled_audit_scope": "untrusted",
        "custom_key": "custom_value"
    }
    await test_db.set_settings_bulk(payload)

    all_db = await test_db.get_all_settings()
    assert all_db["scheduled_audit_duration"] == "240"
    assert all_db["scheduled_audit_scope"] == "untrusted"
    assert all_db["custom_key"] == "custom_value"

    svc = ConfigService(settings_instance=Settings())
    await svc.initialize(database=test_db)
    assert svc.get("scheduled_audit_duration") == 240
    assert svc.get("scheduled_audit_scope") == "untrusted"
    assert svc.get("custom_key") == "custom_value"
