"""System status, Keenetic connection settings, policies, Telegram, and IoT storage configuration."""
import json
import logging
from typing import Optional, Dict, Any

from fastapi import APIRouter, Body
from pydantic import BaseModel

from keenguard.config import (
    settings,
    save_env_router_credentials,
    save_env_telegram_settings,
)
from keenguard.core.forensics import forensics
from keenguard.core.notifier import notifier
from keenguard.core.profiles import PROFILE_TEMPLATES
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
    get_sniffer,
    get_router_health,
)
from keenguard.web.ws import create_tracked_task
from keenguard.web.workers import do_keenetic_poll

logger = logging.getLogger("keenguard.web.routes.settings")

router = APIRouter(tags=["settings"])


class SettingsUpdate(BaseModel):
    router_host: Optional[str] = None
    router_user: Optional[str] = None
    router_password: Optional[str] = None
    night_mode_start_hour: Optional[int] = None
    night_mode_end_hour: Optional[int] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    telegram_enabled: Optional[bool] = None
    telegram_api_url: Optional[str] = None
    telegram_proxy: Optional[str] = None
    new_device_action: Optional[str] = None
    new_device_policy_mode: Optional[str] = None
    new_device_category_policies: Optional[Dict[str, Any]] = None
    audit_auto_quarantine_suspicious: Optional[bool] = None
    new_device_quarantine_wan: Optional[bool] = None
    new_device_isolate_lan: Optional[bool] = None
    new_device_auto_audit: Optional[bool] = None
    new_device_audit_duration: Optional[int] = None
    digest_enabled: Optional[bool] = None
    digest_schedule_hour: Optional[int] = None
    digest_condition: Optional[str] = None
    scheduled_audit_enabled: Optional[bool] = None
    scheduled_audit_hour: Optional[int] = None
    scheduled_audit_scope: Optional[str] = None
    scheduled_audit_duration: Optional[int] = None
    tv_wake_pre_record_seconds: Optional[int] = None
    tv_wake_post_record_seconds: Optional[int] = None
    tv_day_tracking_mode: Optional[str] = None
    tv_wake_trigger_ttl_seconds: Optional[int] = None
    camera_notify_wan_stream: Optional[bool] = None
    camera_notify_lan_stream: Optional[bool] = None
    camera_upload_threshold_kbps: Optional[float] = None
    auto_quarantine_scope: Optional[str] = None
    mac_conflict_detection_enabled: Optional[bool] = None
    notification_dedup_window_seconds: Optional[int] = None
    iot_payload_capture_enabled: Optional[bool] = None
    iot_payload_max_storage_gb: Optional[float] = None
    iot_payload_retention_days: Optional[int] = None


class TestConnRequest(BaseModel):
    router_host: str
    router_user: str
    router_password: Optional[str] = None


class NewDevicePolicyUpdateRequest(BaseModel):
    mode: Optional[str] = "category"  # "global" or "category"
    policies: Optional[Dict[str, Any]] = None
    categories: Optional[Dict[str, Any]] = None
    global_policy: Optional[Dict[str, Any]] = None
    global_quarantine_wan: Optional[bool] = None
    global_isolate_lan: Optional[bool] = None
    global_auto_audit: Optional[bool] = None
    global_audit_duration: Optional[int] = None
    audit_auto_quarantine_suspicious: Optional[bool] = None


class TelegramTestRequest(BaseModel):
    token: Optional[str] = None
    chat_id: Optional[str] = None
    api_url: Optional[str] = None
    proxy: Optional[str] = None


@router.get("/api/status")
async def get_system_status():
    db = get_db()
    keenetic_client = get_keenetic_client()
    sniffer = get_sniffer()
    router_health = get_router_health()

    devices = await db.get_all_devices()
    recent_events = await db.get_recent_events(limit=5)
    online_count = sum(1 for d in devices if d.is_online)
    critical_events_count = sum(1 for e in recent_events if e.severity == "critical")

    return {
        "router": {
            "status": "ok" if router_health.is_connected else "error",
            "connected": bool(router_health.is_connected),
            "model": router_health.model,
            "version": router_health.version,
            "host": keenetic_client.host,
            "router_ips": list(keenetic_client.router_ips) if keenetic_client.router_ips else [keenetic_client.host, "192.168.1.1", "192.168.2.1"],
            "router_macs": list(keenetic_client.router_macs) if keenetic_client.router_macs else [],
            "has_password": bool(keenetic_client.password or settings.router_password),
            "last_heartbeat": router_health.last_heartbeat.isoformat() if router_health.last_heartbeat else None,
            "error": router_health.last_error
        },
        "online_devices": online_count,
        "total_devices": len(devices),
        "critical_alerts": critical_events_count,
        "sniffer_running": sniffer.running,
        "web_port": settings.web_port,
        "night_mode": forensics.is_night_time()
    }


@router.get("/api/settings")
async def get_app_settings():
    keenetic_client = get_keenetic_client()
    return {
        "router_host": settings.router_host,
        "router_port": settings.router_port,
        "router_user": settings.router_user,
        "has_password": bool(settings.router_password or keenetic_client.password),
        "night_mode_start_hour": settings.night_mode_start_hour,
        "night_mode_end_hour": settings.night_mode_end_hour,
        "tv_wake_pre_record_seconds": getattr(settings, "tv_wake_pre_record_seconds", 30),
        "tv_wake_post_record_seconds": getattr(settings, "tv_wake_post_record_seconds", 30),
        "tv_day_tracking_mode": getattr(settings, "tv_day_tracking_mode", "autonomous_only"),
        "tv_wake_trigger_ttl_seconds": getattr(settings, "tv_wake_trigger_ttl_seconds", 60),
        "camera_notify_wan_stream": getattr(settings, "camera_notify_wan_stream", True),
        "camera_notify_lan_stream": getattr(settings, "camera_notify_lan_stream", False),
        "camera_upload_threshold_kbps": getattr(settings, "camera_upload_threshold_kbps", 1500.0),
        "auto_quarantine_scope": getattr(settings, "auto_quarantine_scope", "iot_camera"),
        "mac_conflict_detection_enabled": getattr(settings, "mac_conflict_detection_enabled", True),
        "notification_dedup_window_seconds": getattr(settings, "notification_dedup_window_seconds", 60),
        "web_port": settings.web_port,
        "profiles": PROFILE_TEMPLATES,
        "telegram_bot_token": settings.telegram_bot_token,
        "telegram_chat_id": settings.telegram_chat_id,
        "telegram_enabled": settings.telegram_enabled,
        "telegram_api_url": settings.telegram_api_url,
        "telegram_proxy": settings.telegram_proxy,
        "new_device_policy_mode": getattr(settings, "new_device_policy_mode", "category"),
        "new_device_category_policies": getattr(settings, "new_device_category_policies", {}),
        "audit_auto_quarantine_suspicious": getattr(settings, "audit_auto_quarantine_suspicious", True),
        "new_device_action": settings.new_device_action,
        "new_device_quarantine_wan": settings.new_device_quarantine_wan,
        "new_device_isolate_lan": settings.new_device_isolate_lan,
        "new_device_auto_audit": settings.new_device_auto_audit,
        "new_device_audit_duration": settings.new_device_audit_duration,
        "digest_enabled": settings.digest_enabled,
        "digest_schedule_hour": settings.digest_schedule_hour,
        "digest_condition": settings.digest_condition,
        "scheduled_audit_enabled": settings.scheduled_audit_enabled,
        "scheduled_audit_hour": settings.scheduled_audit_hour,
        "scheduled_audit_scope": settings.scheduled_audit_scope,
        "scheduled_audit_duration": getattr(settings, "scheduled_audit_duration", 60),
        "iot_payload_capture_enabled": getattr(settings, "iot_payload_capture_enabled", True),
        "iot_payload_max_storage_gb": getattr(settings, "iot_payload_max_storage_gb", 1.0),
        "iot_payload_retention_days": getattr(settings, "iot_payload_retention_days", 7)
    }


@router.post("/api/test_connection")
async def test_keenetic_auth(req: TestConnRequest):
    db = get_db()
    keenetic_client = get_keenetic_client()
    router_health = get_router_health()

    pwd = req.router_password if (req.router_password and req.router_password.strip()) else (keenetic_client.password or settings.router_password)
    res = await keenetic_client.authenticate(
        host=req.router_host,
        user=req.router_user,
        password=pwd
    )
    if res.get("status") == "ok":
        settings.router_host = req.router_host
        settings.router_user = req.router_user
        await db.save_setting("router_host", req.router_host)
        await db.save_setting("router_user", req.router_user)
        if pwd:
            settings.router_password = pwd
            keenetic_client.password = pwd
            await db.save_setting("router_password", pwd)
            save_env_router_credentials(req.router_host, req.router_user, pwd, settings.router_port)
        await router_health.update_status(connected=True, model=res.get("model"), version=res.get("version"))
        create_tracked_task(do_keenetic_poll())
    else:
        await router_health.update_status(connected=False, error=res.get("message"))
    return res


@router.post("/api/settings")
async def save_app_settings(s: SettingsUpdate):
    db = get_db()
    keenetic_client = get_keenetic_client()
    sniffer = get_sniffer()
    router_health = get_router_health()

    router_creds_changed = False
    if s.router_host is not None and s.router_host.strip():
        new_host = s.router_host.strip()
        if new_host != settings.router_host:
            settings.router_host = new_host
            await db.save_setting("router_host", new_host)
            keenetic_client.host = new_host
            router_creds_changed = True

    if s.router_user is not None and s.router_user.strip():
        new_user = s.router_user.strip()
        if new_user != settings.router_user:
            settings.router_user = new_user
            await db.save_setting("router_user", new_user)
            keenetic_client.user = new_user
            router_creds_changed = True

    if s.router_password is not None and s.router_password.strip():
        new_pwd = s.router_password.strip()
        if new_pwd != settings.router_password:
            settings.router_password = new_pwd
            keenetic_client.password = new_pwd
            await db.save_setting("router_password", new_pwd)
            router_creds_changed = True

    if router_creds_changed:
        save_env_router_credentials(settings.router_host, settings.router_user, keenetic_client.password or "", settings.router_port)

    if s.night_mode_start_hour is not None:
        settings.night_mode_start_hour = max(0, min(23, s.night_mode_start_hour))
        await db.save_setting("night_mode_start_hour", str(settings.night_mode_start_hour))
    if s.night_mode_end_hour is not None:
        settings.night_mode_end_hour = max(0, min(23, s.night_mode_end_hour))
        await db.save_setting("night_mode_end_hour", str(settings.night_mode_end_hour))

    if s.tv_wake_pre_record_seconds is not None:
        settings.tv_wake_pre_record_seconds = max(5, min(300, s.tv_wake_pre_record_seconds))
        await db.save_setting("tv_wake_pre_record_seconds", str(settings.tv_wake_pre_record_seconds))
        sniffer.set_tracked_tvs(sniffer.tracked_tv_macs, pre_record_seconds=settings.tv_wake_pre_record_seconds)

    if s.tv_wake_post_record_seconds is not None:
        settings.tv_wake_post_record_seconds = max(0, min(600, s.tv_wake_post_record_seconds))
        await db.save_setting("tv_wake_post_record_seconds", str(settings.tv_wake_post_record_seconds))

    # Telegram settings
    telegram_changed = False
    if s.telegram_bot_token is not None:
        clean_token = s.telegram_bot_token.strip()
        if clean_token or not settings.telegram_bot_token:
            if settings.telegram_bot_token != clean_token:
                settings.telegram_bot_token = clean_token
                await db.save_setting("telegram_bot_token", clean_token)
                telegram_changed = True
    if s.telegram_chat_id is not None:
        clean_chat = s.telegram_chat_id.strip()
        if clean_chat or not settings.telegram_chat_id:
            if settings.telegram_chat_id != clean_chat:
                settings.telegram_chat_id = clean_chat
                await db.save_setting("telegram_chat_id", clean_chat)
                telegram_changed = True
    if s.telegram_enabled is not None and s.telegram_enabled != settings.telegram_enabled:
        settings.telegram_enabled = s.telegram_enabled
        await db.save_setting("telegram_enabled", "true" if s.telegram_enabled else "false")
        telegram_changed = True
    if s.telegram_api_url is not None:
        clean_url = s.telegram_api_url.strip() or "https://api.telegram.org"
        if settings.telegram_api_url != clean_url:
            settings.telegram_api_url = clean_url
            await db.save_setting("telegram_api_url", clean_url)
            telegram_changed = True
    if s.telegram_proxy is not None:
        clean_proxy = s.telegram_proxy.strip() or None
        if settings.telegram_proxy != clean_proxy:
            settings.telegram_proxy = clean_proxy
            await db.save_setting("telegram_proxy", clean_proxy or "")
            telegram_changed = True

    if telegram_changed:
        save_env_telegram_settings(
            settings.telegram_bot_token,
            settings.telegram_chat_id,
            settings.telegram_enabled,
            settings.telegram_api_url,
            settings.telegram_proxy
        )
        from keenguard.core.notifier import telegram_bot_worker
        if settings.telegram_enabled and settings.telegram_bot_token and settings.telegram_chat_id:
            create_tracked_task(telegram_bot_worker.start())
        else:
            create_tracked_task(telegram_bot_worker.stop())

    # New Device Policy
    if s.new_device_policy_mode is not None:
        settings.new_device_policy_mode = s.new_device_policy_mode
        await db.save_setting("new_device_policy_mode", s.new_device_policy_mode)
    if s.new_device_category_policies is not None:
        settings.new_device_category_policies = s.new_device_category_policies
        await db.save_setting("new_device_category_policies", json.dumps(s.new_device_category_policies, ensure_ascii=False))
    if s.audit_auto_quarantine_suspicious is not None:
        settings.audit_auto_quarantine_suspicious = s.audit_auto_quarantine_suspicious
        await db.save_setting("audit_auto_quarantine_suspicious", "true" if s.audit_auto_quarantine_suspicious else "false")
    if s.new_device_action is not None:
        settings.new_device_action = s.new_device_action
        await db.save_setting("new_device_action", s.new_device_action)
    if s.new_device_quarantine_wan is not None:
        settings.new_device_quarantine_wan = s.new_device_quarantine_wan
        await db.save_setting("new_device_quarantine_wan", "true" if s.new_device_quarantine_wan else "false")
    if s.new_device_isolate_lan is not None:
        settings.new_device_isolate_lan = s.new_device_isolate_lan
        await db.save_setting("new_device_isolate_lan", "true" if s.new_device_isolate_lan else "false")
    if s.new_device_auto_audit is not None:
        settings.new_device_auto_audit = s.new_device_auto_audit
        await db.save_setting("new_device_auto_audit", "true" if s.new_device_auto_audit else "false")
    if s.new_device_audit_duration is not None:
        settings.new_device_audit_duration = max(10, min(86400, s.new_device_audit_duration))
        await db.save_setting("new_device_audit_duration", str(settings.new_device_audit_duration))

    # Security Digest
    if s.digest_enabled is not None:
        settings.digest_enabled = s.digest_enabled
        await db.save_setting("digest_enabled", "true" if s.digest_enabled else "false")
    if s.digest_schedule_hour is not None:
        settings.digest_schedule_hour = max(0, min(23, s.digest_schedule_hour))
        await db.save_setting("digest_schedule_hour", str(settings.digest_schedule_hour))
    if s.digest_condition is not None:
        settings.digest_condition = s.digest_condition
        await db.save_setting("digest_condition", s.digest_condition)

    # Scheduled Audits
    if s.scheduled_audit_enabled is not None:
        settings.scheduled_audit_enabled = s.scheduled_audit_enabled
        await db.save_setting("scheduled_audit_enabled", "true" if s.scheduled_audit_enabled else "false")
    if s.scheduled_audit_hour is not None:
        settings.scheduled_audit_hour = max(0, min(23, s.scheduled_audit_hour))
        await db.save_setting("scheduled_audit_hour", str(settings.scheduled_audit_hour))
    if s.scheduled_audit_scope is not None:
        settings.scheduled_audit_scope = s.scheduled_audit_scope
        await db.save_setting("scheduled_audit_scope", s.scheduled_audit_scope)
    if s.scheduled_audit_duration is not None:
        settings.scheduled_audit_duration = max(10, min(86400, s.scheduled_audit_duration))
        await db.save_setting("scheduled_audit_duration", str(settings.scheduled_audit_duration))

    # Network Security Modernization settings
    if s.tv_day_tracking_mode is not None:
        settings.tv_day_tracking_mode = s.tv_day_tracking_mode
        await db.save_setting("tv_day_tracking_mode", s.tv_day_tracking_mode)
    if s.tv_wake_trigger_ttl_seconds is not None:
        settings.tv_wake_trigger_ttl_seconds = max(5, min(3600, s.tv_wake_trigger_ttl_seconds))
        await db.save_setting("tv_wake_trigger_ttl_seconds", str(settings.tv_wake_trigger_ttl_seconds))
    if s.camera_notify_wan_stream is not None:
        settings.camera_notify_wan_stream = s.camera_notify_wan_stream
        await db.save_setting("camera_notify_wan_stream", "true" if s.camera_notify_wan_stream else "false")
    if s.camera_notify_lan_stream is not None:
        settings.camera_notify_lan_stream = s.camera_notify_lan_stream
        await db.save_setting("camera_notify_lan_stream", "true" if s.camera_notify_lan_stream else "false")
    if s.auto_quarantine_scope is not None:
        settings.auto_quarantine_scope = s.auto_quarantine_scope
        await db.save_setting("auto_quarantine_scope", s.auto_quarantine_scope)
    if s.mac_conflict_detection_enabled is not None:
        settings.mac_conflict_detection_enabled = s.mac_conflict_detection_enabled
        await db.save_setting("mac_conflict_detection_enabled", "true" if s.mac_conflict_detection_enabled else "false")
    if s.notification_dedup_window_seconds is not None:
        settings.notification_dedup_window_seconds = max(1, min(86400, s.notification_dedup_window_seconds))
        await db.save_setting("notification_dedup_window_seconds", str(settings.notification_dedup_window_seconds))
    if s.camera_upload_threshold_kbps is not None:
        settings.camera_upload_threshold_kbps = max(50.0, float(s.camera_upload_threshold_kbps))
        await db.save_setting("camera_upload_threshold_kbps", str(settings.camera_upload_threshold_kbps))
    if s.iot_payload_capture_enabled is not None:
        settings.iot_payload_capture_enabled = s.iot_payload_capture_enabled
        await db.save_setting("iot_payload_capture_enabled", "true" if s.iot_payload_capture_enabled else "false")
    if s.iot_payload_max_storage_gb is not None:
        settings.iot_payload_max_storage_gb = max(0.1, min(100.0, float(s.iot_payload_max_storage_gb)))
        await db.save_setting("iot_payload_max_storage_gb", str(settings.iot_payload_max_storage_gb))
    if s.iot_payload_retention_days is not None:
        settings.iot_payload_retention_days = max(1, min(365, int(s.iot_payload_retention_days)))
        await db.save_setting("iot_payload_retention_days", str(settings.iot_payload_retention_days))
        create_tracked_task(db.prune_iot_payloads())

    # Synchronize in-memory reactive config_service cache and notify subscribers
    try:
        from keenguard.core.config_service import config_service
        for field_name in s.model_dump(exclude_unset=True).keys():
            if hasattr(settings, field_name):
                val = getattr(settings, field_name)
                config_service._cache[field_name] = val
                config_service._notify(field_name, val)
    except Exception as ex:
        logger.debug("Failed to sync config_service cache: %s", ex)

    if router_creds_changed:
        keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"
        auth_res = await keenetic_client.authenticate()
        if auth_res.get("status") == "ok":
            await router_health.update_status(connected=True, model=auth_res.get("model"), version=auth_res.get("version"))
            create_tracked_task(do_keenetic_poll())
        else:
            await router_health.update_status(connected=False, error=auth_res.get("message"))
        return {"status": "ok", "message": "Settings updated", "auth": auth_res}

    return {"status": "ok", "message": "Settings updated"}


@router.get("/api/settings/new_device_policy")
async def get_new_device_policy_endpoint():
    db = get_db()
    db_pol = await db.get_new_device_policies()
    pols = db_pol.get("policies") or db_pol.get("categories") or dict(settings.new_device_category_policies)
    return {
        "mode": db_pol.get("mode", "category"),
        "policies": pols,
        "categories": pols,
        "global_policy": {
            "quarantine_wan": settings.new_device_quarantine_wan,
            "isolate_lan": settings.new_device_isolate_lan,
            "auto_audit": settings.new_device_auto_audit,
            "audit_duration": settings.new_device_audit_duration
        },
        "global_quarantine_wan": settings.new_device_quarantine_wan,
        "global_isolate_lan": settings.new_device_isolate_lan,
        "global_auto_audit": settings.new_device_auto_audit,
        "global_audit_duration": settings.new_device_audit_duration,
        "audit_auto_quarantine_suspicious": getattr(settings, "audit_auto_quarantine_suspicious", True)
    }


@router.post("/api/settings/new_device_policy")
async def save_new_device_policy_endpoint(req: NewDevicePolicyUpdateRequest):
    db = get_db()
    if req.mode in ("global", "category"):
        settings.new_device_policy_mode = req.mode
        await db.save_setting("new_device_policy_mode", req.mode)

    cats = req.categories or req.policies
    if cats:
        settings.new_device_category_policies = cats
        await db.save_new_device_policies(settings.new_device_policy_mode, cats)

    if req.global_policy:
        if "quarantine_wan" in req.global_policy:
            settings.new_device_quarantine_wan = req.global_policy["quarantine_wan"]
            await db.save_setting("new_device_quarantine_wan", "true" if settings.new_device_quarantine_wan else "false")
        if "isolate_lan" in req.global_policy:
            settings.new_device_isolate_lan = req.global_policy["isolate_lan"]
            await db.save_setting("new_device_isolate_lan", "true" if settings.new_device_isolate_lan else "false")
        if "auto_audit" in req.global_policy:
            settings.new_device_auto_audit = req.global_policy["auto_audit"]
            await db.save_setting("new_device_auto_audit", "true" if settings.new_device_auto_audit else "false")
        if "audit_duration" in req.global_policy:
            settings.new_device_audit_duration = req.global_policy["audit_duration"]
            await db.save_setting("new_device_audit_duration", str(settings.new_device_audit_duration))

    if req.global_quarantine_wan is not None:
        settings.new_device_quarantine_wan = req.global_quarantine_wan
        await db.save_setting("new_device_quarantine_wan", "true" if req.global_quarantine_wan else "false")

    if req.global_isolate_lan is not None:
        settings.new_device_isolate_lan = req.global_isolate_lan
        await db.save_setting("new_device_isolate_lan", "true" if req.global_isolate_lan else "false")

    if req.global_auto_audit is not None:
        settings.new_device_auto_audit = req.global_auto_audit
        await db.save_setting("new_device_auto_audit", "true" if req.global_auto_audit else "false")

    if req.global_audit_duration is not None:
        settings.new_device_audit_duration = req.global_audit_duration
        await db.save_setting("new_device_audit_duration", str(req.global_audit_duration))

    if req.audit_auto_quarantine_suspicious is not None:
        settings.audit_auto_quarantine_suspicious = req.audit_auto_quarantine_suspicious
        await db.save_setting("audit_auto_quarantine_suspicious", "true" if req.audit_auto_quarantine_suspicious else "false")

    return {"status": "ok", "message": "Политика для новых устройств успешно обновлена"}


@router.post("/api/telegram/test")
async def test_telegram_connection(req: TelegramTestRequest):
    token = (req.token or settings.telegram_bot_token or "").strip()
    chat_id = (req.chat_id or settings.telegram_chat_id or "").strip()
    api_url = (req.api_url or settings.telegram_api_url or "https://api.telegram.org").strip()
    proxy = req.proxy if req.proxy is not None else settings.telegram_proxy
    res = await notifier.send_test_message(token=token, chat_id=chat_id, api_url=api_url, proxy=proxy)
    return res


@router.get("/api/settings/iot_storage")
async def get_iot_storage_settings():
    """Returns current IoT payload storage configuration and disk usage."""
    db = get_db()
    stats = await db.get_iot_storage_stats()
    cfg = {
        "capture_enabled": settings.iot_payload_capture_enabled,
        "max_storage_gb": settings.iot_payload_max_storage_gb,
        "retention_days": settings.iot_payload_retention_days
    }
    return {"status": "ok", "config": cfg, "storage_stats": stats, **stats}


@router.post("/api/settings/iot_storage")
async def save_iot_storage_settings(body: Dict[str, Any] = Body(...)):
    """Updates storage limits (GB), retention days, and capture status."""
    db = get_db()
    if "max_storage_gb" in body and body["max_storage_gb"] is not None:
        try:
            val_gb = max(0.1, min(100.0, float(body["max_storage_gb"])))
            settings.iot_payload_max_storage_gb = val_gb
            await db.save_setting("iot_payload_max_storage_gb", str(settings.iot_payload_max_storage_gb))
        except (ValueError, TypeError) as e:
            logger.warning("Invalid max_storage_gb value %r: %s", body.get("max_storage_gb"), e)
    if "retention_days" in body and body["retention_days"] is not None:
        try:
            val_days = max(1, min(365, int(body["retention_days"])))
            settings.iot_payload_retention_days = val_days
            await db.save_setting("iot_payload_retention_days", str(settings.iot_payload_retention_days))
        except (ValueError, TypeError) as e:
            logger.warning("Invalid retention_days value %r: %s", body.get("retention_days"), e)
    if "capture_enabled" in body and body["capture_enabled"] is not None:
        settings.iot_payload_capture_enabled = bool(body["capture_enabled"])
        await db.save_setting("iot_payload_capture_enabled", "true" if settings.iot_payload_capture_enabled else "false")

    try:
        from keenguard.core.config_service import config_service
        for key in ("iot_payload_max_storage_gb", "iot_payload_retention_days", "iot_payload_capture_enabled"):
            val = getattr(settings, key)
            config_service._cache[key] = val
            config_service._notify(key, val)
    except Exception as ex:
        logger.debug("Failed to sync config_service cache for iot storage: %s", ex)

    create_tracked_task(db.prune_iot_payloads())
    stats = await db.get_iot_storage_stats()
    cfg = {
        "capture_enabled": settings.iot_payload_capture_enabled,
        "max_storage_gb": settings.iot_payload_max_storage_gb,
        "retention_days": settings.iot_payload_retention_days
    }
    return {"status": "ok", "config": cfg, "storage_stats": stats, "message": "Настройки хранилища сохранены", **stats}
