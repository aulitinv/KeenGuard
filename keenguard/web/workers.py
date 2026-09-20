"""Background worker tasks, Keenetic RCI polling, sniffer dispatching, and lifespan management."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import shutil
import sys
import time
from typing import Dict, Optional, Any

from fastapi import FastAPI

from keenguard.config import (
    settings,
    save_env_router_credentials,
)
from keenguard.core.anomaly import anomaly_detector
from keenguard.core.audit import should_device_quarantine
from keenguard.core.classifier import DeviceClassifier
from keenguard.core.dns_providers import dns_security_manager
from keenguard.core.dns_tracker import dns_tracker
from keenguard.core.domain_analyzer import domain_analyzer
from keenguard.core.forensics import forensics
from keenguard.core.keenetic import is_host_lan_isolated
from keenguard.core.lan_tracker import lan_tracker
from keenguard.core.notifier import notifier
from keenguard.core.profiles import profile_manager
from keenguard.core.scheduler import scheduler
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
    get_audit_manager,
    get_sniffer,
)
from keenguard.web.ws import (
    ws_manager,
    create_tracked_task,
    broadcast_event,
    set_main_loop,
)

logger = logging.getLogger("keenguard.web.workers")


class RouterHealthMonitor:
    def __init__(self):
        self.is_connected: Optional[bool] = None
        self.model: str = "Keenetic"
        self.version: str = "KeeneticOS"
        self.host: str = settings.router_host
        self.last_heartbeat: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.failure_count: int = 0

    async def update_status(
        self,
        connected: bool,
        model: Optional[str] = None,
        version: Optional[str] = None,
        error: Optional[str] = None,
    ):
        keenetic_client = get_keenetic_client()
        db = get_db()
        was_connected = self.is_connected
        self.is_connected = connected
        if model:
            self.model = model
        if version:
            self.version = version
        self.host = keenetic_client.host

        if connected:
            self.last_heartbeat = datetime.now(timezone.utc)
            self.last_error = None
            self.failure_count = 0

            # Record event on connection restoration/establishment
            if was_connected is False or was_connected is None:
                logger.info("Router connection ONLINE: %s (%s, %s)", self.host, self.model, self.version)
                await db.record_event(SecurityEvent(
                    event_type="router_online",
                    severity="info",
                    description=f"Связь с роутером Keenetic ({self.host}) установлена. Модель: {self.model}, KeeneticOS {self.version}."
                ))
                await ws_manager.broadcast({
                    "type": "router_status_change",
                    "connected": True,
                    "model": self.model,
                    "version": self.version,
                    "host": self.host
                })
        else:
            self.failure_count += 1
            self.last_error = error or "Шлюз недоступен или тайм-аут"

            # Record critical event on disconnection
            if was_connected is True:
                logger.warning("Router connection LOST: %s. Reason: %s", self.host, self.last_error)
                offline_ev = SecurityEvent(
                    event_type="router_offline",
                    severity="critical",
                    description=f"Внимание: Потеряна связь с роутером Keenetic ({self.host})! Причина: {self.last_error}. Защита переведена в автономный режим."
                )
                await db.record_event(offline_ev)
                create_tracked_task(notifier.send_alert(offline_ev))
                await ws_manager.broadcast({
                    "type": "router_status_change",
                    "connected": False,
                    "error": self.last_error,
                    "host": self.host
                })


router_health = RouterHealthMonitor()

device_traffic_rates: Dict[str, tuple] = {}  # mac -> (timestamp, rx_bytes, tx_bytes)
_poll_counter: int = 0
_poller_running: bool = False
_poller_task: Optional[asyncio.Task] = None
_poll_lock: Optional[asyncio.Lock] = None


def get_poll_lock() -> asyncio.Lock:
    """Returns or lazily creates an asyncio.Lock for synchronizing Keenetic polls."""
    global _poll_lock
    if _poll_lock is None:
        _poll_lock = asyncio.Lock()
    return _poll_lock


async def do_keenetic_poll():
    """Polls Keenetic router for active hosts, synchronizes state with database, and checks security policies."""
    async with get_poll_lock():
        return await _do_keenetic_poll_internal()


async def _do_keenetic_poll_internal():
    global _poll_counter
    # Check if app module has monkeypatched _poll_counter
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "_poll_counter"):
        _poll_counter = app_mod._poll_counter

    keenetic_client = get_keenetic_client()
    db = get_db()
    audit_manager = get_audit_manager()
    sniffer = get_sniffer()

    try:
        hosts = await keenetic_client.get_hotspot_hosts()
        if not hosts and not keenetic_client.mock_mode:
            test_res = await keenetic_client.test_connection()
            if test_res.get("status") != "ok":
                await router_health.update_status(connected=False, error=test_res.get("message"))
                return
            else:
                await router_health.update_status(
                    connected=True,
                    model=test_res.get("model") or keenetic_client.last_model,
                    version=test_res.get("version") or keenetic_client.last_version
                )
        else:
            await router_health.update_status(
                connected=True,
                model=keenetic_client.last_model,
                version=keenetic_client.last_version
            )
    except Exception as e:
        await router_health.update_status(connected=False, error=str(e))
        return

    upnp_rules = await keenetic_client.get_upnp_mappings()
    current_devices_map: Dict[str, DeviceRecord] = {}
    seen_macs = set()

    initial_db_device_count = len(await db.get_all_devices())
    is_initial_ingestion = (initial_db_device_count == 0 and len(hosts) > 0)
    if is_initial_ingestion:
        logger.info("Cold start / Initial network sync: importing %d existing devices from router into DB with safe zero-quarantine policy.", len(hosts))

    for h in hosts:
        mac = h.mac.upper()
        seen_macs.add(mac)
        existing = await db.get_device(mac)

        is_real_wan_blocked = (getattr(h, "access", "permit") == "deny")
        is_real_lan_isolated = is_host_lan_isolated(getattr(h, "interface", None), h.ip)
        is_host_online = (h.link == "up") and bool(getattr(h, "active", False))

        if not existing:
            vendor, prof, is_rand = DeviceClassifier.classify(mac, hostname=h.hostname or h.name)
            record = DeviceRecord(
                mac=mac,
                ip=h.ip,
                hostname=h.hostname or h.name or "Unknown Host",
                vendor=vendor,
                profile=prof,
                is_online=is_host_online,
                rx_bytes=h.rxbytes,
                tx_bytes=h.txbytes,
                is_blocked_wan=is_real_wan_blocked,
                is_isolated_lan=is_real_lan_isolated,
                segment=getattr(h, "segment", "Home") or "Home"
            )

            # User-configured reaction on new device discovery (modular & category-based policy)
            quarantine = False
            isolate = False
            auto_audit = False
            dur = settings.new_device_audit_duration or 3600
            send_telegram = True

            # If this is cold start or initial database seeding, never quarantine existing home devices!
            if is_initial_ingestion:
                quarantine = False
                isolate = False
                auto_audit = False
                send_telegram = False
            else:
                policy_mode = getattr(settings, "new_device_policy_mode", "category")
                if policy_mode == "category":
                    if is_rand:
                        cat_key = "random_mac"
                    elif prof in ("iot", "smart_home_hub"):
                        cat_key = "iot"
                    elif prof == "camera":
                        cat_key = "camera"
                    elif prof == "trusted":
                        cat_key = "trusted"
                    else:
                        cat_key = "unknown"

                    cat_pols = getattr(settings, "new_device_category_policies", {})
                    pol = cat_pols.get(cat_key, {})
                    quarantine = pol.get("quarantine_wan", False)
                    isolate = pol.get("isolate_lan", False)
                    auto_audit = pol.get("auto_audit", False)
                    dur = pol.get("audit_duration", 900)
                    send_telegram = pol.get("telegram_alert", True)
                else:
                    quarantine = settings.new_device_quarantine_wan or ("quarantine" in settings.new_device_action)
                    isolate = settings.new_device_isolate_lan or ("isolate" in settings.new_device_action)
                    auto_audit = settings.new_device_auto_audit or ("audit" in settings.new_device_action)
                    dur = settings.new_device_audit_duration or 3600
                    send_telegram = True

            actions_taken = []
            if quarantine:
                record.is_blocked_wan = True
                await profile_manager.toggle_wan(mac, True)
                actions_taken.append("Карантин WAN (интернет заблокирован)")
            if isolate:
                iso_res = await profile_manager.toggle_lan_isolation(mac, True)
                record.is_isolated_lan = iso_res
                if iso_res:
                    actions_taken.append("Изоляция LAN (локальная сеть заблокирована)")
                else:
                    actions_taken.append("Изоляция LAN (требуется гостевой Wi-Fi)")
            if auto_audit:
                create_tracked_task(audit_manager.start_audit(
                    mac=mac, ip=h.ip, hostname=record.hostname, vendor=vendor, duration_seconds=dur
                ))
                actions_taken.append(f"Аудит трафика ({dur // 60} мин)")

            act_desc = " + ".join(actions_taken) if actions_taken else "Уведомление"

            await db.upsert_device(record)
            existing = record

            # Emit new device security event & send Telegram alert
            new_dev_ev = SecurityEvent(
                event_type="new_device",
                severity="warning" if (quarantine or is_rand) else "info",
                target_mac=mac,
                target_ip=h.ip,
                description=f"Новое устройство в сети: '{record.hostname}' ({vendor}, IP: {h.ip}). Реакция: {act_desc}."
            )
            await db.record_event(new_dev_ev)
            if send_telegram:
                create_tracked_task(notifier.send_alert(new_dev_ev))

            if is_rand:
                rand_ev = SecurityEvent(
                    event_type="random_mac",
                    severity="info",
                    target_mac=mac,
                    target_ip=h.ip,
                    description=f"Устройство '{record.hostname}' использует случайный Wi-Fi MAC (LAA: {mac})"
                )
                await db.record_event(rand_ev)
        else:
            existing.ip = h.ip
            existing.is_online = is_host_online
            existing.rx_bytes = h.rxbytes
            existing.tx_bytes = h.txbytes
            existing.is_blocked_wan = is_real_wan_blocked
            existing.is_isolated_lan = is_real_lan_isolated
            existing.segment = getattr(h, "segment", "Home") or existing.segment or "Home"

            # Upgrade vendor/profile if previously unknown or generic and now identifiable
            if existing.vendor in ("Unknown Vendor", "Unknown", "Locally Administered (Random MAC)", None) or existing.profile == "unassigned" or (h.hostname and h.hostname != existing.hostname):
                new_v, new_p, _ = DeviceClassifier.classify(mac, hostname=h.hostname or existing.hostname)
                if new_v not in ("Unknown Vendor", "Locally Administered (Random MAC)"):
                    existing.vendor = new_v
                if existing.profile == "unassigned" and new_p != "unassigned":
                    existing.profile = new_p
            if h.hostname and h.hostname != existing.hostname:
                existing.hostname = h.hostname

            await db.upsert_device(existing)

        current_devices_map[mac] = existing

        # Traffic rate measurement and history recording
        now_t = time.time()
        prev_data = device_traffic_rates.get(mac)
        device_traffic_rates[mac] = (now_t, h.rxbytes, h.txbytes)
        if prev_data:
            dt = now_t - prev_data[0]
            if dt >= 4.0:
                drx = max(0, h.rxbytes - prev_data[1])
                dtx = max(0, h.txbytes - prev_data[2])
                rx_kbps = (drx * 8) / (dt * 1024)
                tx_kbps = (dtx * 8) / (dt * 1024)
                await db.record_traffic_snapshot(mac, h.rxbytes, h.txbytes, rx_kbps, tx_kbps)

        if existing.profile == "smart_tv":
            await forensics.check_tv_state_transition(
                mac=mac,
                ip=h.ip or "",
                is_active=is_host_online,
                hostname=existing.hostname
            )

        if existing.profile == "camera":
            await anomaly_detector.check_camera_upload_leak(existing, h.txbytes)

    # Mark devices that disappeared from Keenetic active hotspot as offline
    all_db_devices = await db.get_all_devices()
    for d in all_db_devices:
        if d.is_online and d.mac.upper() not in seen_macs:
            d.is_online = False
            await db.upsert_device(d)
            if d.profile == "smart_tv":
                await forensics.check_tv_state_transition(
                    mac=d.mac.upper(),
                    ip=d.ip or "",
                    is_active=False,
                    hostname=d.hostname
                )

    # Sync Smart TV list with sniffer for targeted pre-wake ring buffering
    tv_macs = [d.mac.upper() for d in all_db_devices if d.profile == "smart_tv"]
    sniffer.set_tracked_tvs(tv_macs, pre_record_seconds=settings.tv_wake_pre_record_seconds)

    if upnp_rules:
        await anomaly_detector.check_upnp_anomalies(upnp_rules, current_devices_map)

    lan_tracker.update_devices_cache(current_devices_map)

    # Periodic DNS cache query (~every 30s)
    _poll_counter += 1
    if app_mod:
        app_mod._poll_counter = _poll_counter

    if _poll_counter % 6 == 0:
        try:
            dns_cache = await keenetic_client.get_dns_cache()
            for entry in dns_cache:
                if entry.get("domain"):
                    await db.record_dns_query(entry["domain"], ip=entry.get("ip"))
        except Exception as e:
            logger.debug("Periodic DNS cache poll error: %s", e)

    # Track domain activity and LAN inter-device communications from router conntrack/NAT
    try:
        nat_entries = await keenetic_client.get_nat_table()
        if nat_entries:
            await dns_tracker.track_nat_connections(nat_entries, current_devices_map)
            lan_tracker.integrate_router_conntrack(nat_entries, devices_map=current_devices_map)
    except Exception as e:
        logger.debug("NAT / Conntrack processing error: %s", e)

    # Periodic IoT payload pruning (every ~10 minutes, _poll_counter % 120 == 0)
    if _poll_counter % 120 == 0:
        create_tracked_task(db.prune_iot_payloads())

    await ws_manager.broadcast({"type": "refresh", "device_count": len(hosts)})


async def poll_keenetic_task():
    global _poller_running
    logger.info("Starting Keenetic RCI background poller...")
    while _poller_running:
        try:
            await do_keenetic_poll()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in Keenetic polling task: %s", e)
        try:
            await asyncio.sleep(settings.router_poll_interval)
        except asyncio.CancelledError:
            break


def _handle_sniffer_event(event_dict: Dict):
    try:
        create_tracked_task(_async_sniffer_dispatch(event_dict))
    except Exception as e:
        logger.debug("Could not dispatch sniffer event: %s", e)


async def _async_sniffer_dispatch(event_dict: Dict):
    db = get_db()
    event_type = event_dict.get("event_type")

    if event_type == "mac_ip_binding":
        await anomaly_detector.check_mac_ip_binding(
            mac=event_dict.get("mac"),
            ip=event_dict.get("ip")
        )
        return

    if event_type in ["wol_wake", "airplay_activity", "cast_activity", "dial_activity"]:
        forensics.register_trigger(event_dict)

    if event_type == "arp_probe":
        await anomaly_detector.record_arp_probe(
            src_mac=event_dict.get("source_mac"),
            src_ip=event_dict.get("source_ip"),
            dst_ip=event_dict.get("target_ip")
        )
    elif event_type == "wol_wake":
        ev = SecurityEvent(**event_dict)
        await db.record_event(ev)
        if ev.severity in ("critical", "warning"):
            create_tracked_task(notifier.send_alert(ev))
    elif event_type == "port_probe":
        src_mac = event_dict.get("source_mac")
        if src_mac:
            dev = await db.get_device(src_mac)
            if dev:
                event_dict["source_name"] = dev.custom_name or dev.hostname or dev.ip
                # If device is trusted or configured with trusted preset, do not treat as critical rogue attack
                if dev.profile == "trusted" or dev.preset_id == "preset_trusted":
                    event_dict["severity"] = "info"
        ev = SecurityEvent(**event_dict)
        await db.record_event(ev)
        if ev.severity in ("critical", "warning"):
            create_tracked_task(notifier.send_alert(ev))

    await ws_manager.broadcast({"type": "sniffer_event", "event": event_dict})


# Register callback with sniffer
default_sniffer = get_sniffer()
default_sniffer.register_callback(_handle_sniffer_event)


def _backup_production_database():
    """Creates a safety snapshot of the SQLite database on startup for instant recovery."""
    try:
        prod_db = Path(settings.db_path)
        if prod_db.exists() and prod_db.stat().st_size > 0:
            bak_path = prod_db.with_suffix(".db.bak")
            if bak_path.exists():
                bak1_path = prod_db.with_suffix(".db.bak1")
                shutil.copy2(bak_path, bak1_path)
            shutil.copy2(prod_db, bak_path)
            logger.info("Automatic startup database snapshot created: %s", bak_path)
    except Exception as e:
        logger.warning("Could not create startup DB snapshot: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager controlling startup and graceful shutdown."""
    set_main_loop(asyncio.get_running_loop())
    _backup_production_database()

    db = get_db()
    keenetic_client = get_keenetic_client()
    sniffer = get_sniffer()
    audit_manager = get_audit_manager()

    await db.init_db()
    await domain_analyzer.load_custom_rules_and_signatures()

    # 1. Synchronize credentials between .env and DB
    saved_pass = await db.get_setting("router_password")
    if saved_pass and not settings.router_password:
        settings.router_password = saved_pass
    elif settings.router_password and not saved_pass:
        await db.save_setting("router_password", settings.router_password)

    if settings.router_password:
        keenetic_client.password = settings.router_password
        save_env_router_credentials(settings.router_host, settings.router_user, settings.router_password, settings.router_port)

    saved_host = await db.get_setting("router_host")
    if saved_host:
        settings.router_host = saved_host
        keenetic_client.host = saved_host
        keenetic_client.base_url = f"{keenetic_client.schema}://{saved_host}:{settings.router_port}"
    saved_user = await db.get_setting("router_user")
    if saved_user:
        settings.router_user = saved_user
        keenetic_client.user = saved_user

    # 2. Initial connection test on boot
    auth_res = await keenetic_client.authenticate()
    if auth_res.get("status") == "ok":
        await router_health.update_status(
            connected=True,
            model=auth_res.get("model") or keenetic_client.last_model,
            version=auth_res.get("version") or keenetic_client.last_version
        )
        await keenetic_client.refresh_router_interfaces()
        await db.cleanup_router_false_events()
    else:
        await router_health.update_status(connected=False, error=auth_res.get("message"))

    # 3. Synchronize all settings via reactive ConfigService (SQLite > .env > Pydantic defaults)
    from keenguard.core.config_service import config_service
    await config_service.initialize(database=db)

    # Wire Traffic Audit Guard callback for suspicious device auto-quarantine
    async def on_audit_suspicious_device(mac: str, ip: str, hostname: str, reason: str):
        dev = await db.get_device(mac)
        if not should_device_quarantine(dev, reason):
            logger.info("Auto-quarantine skipped for device %s (%s) per policy/scope rules: %s", hostname, mac, reason)
            return

        logger.warning("AUDIT SUSPICIOUS DETECTED! Auto-quarantining device %s (%s, IP: %s): %s", hostname, mac, ip, reason)
        try:
            await profile_manager.toggle_wan(mac, True)
            iso_res = await profile_manager.toggle_lan_isolation(mac, True)
            if dev:
                dev.is_blocked_wan = True
                dev.is_isolated_lan = iso_res
                await db.upsert_device(dev)
            ev = SecurityEvent(
                event_type="audit_auto_ban",
                severity="critical",
                target_mac=mac,
                target_ip=ip,
                description=f"🚨 Устройство '{hostname}' ({ip}, {mac}) заблокировано и отправлено в карантин во время аудита! Причина: {reason}"
            )
            await db.record_event(ev)
            create_tracked_task(notifier.send_alert(ev))
            create_tracked_task(broadcast_event(ev))
        except Exception as ex:
            logger.error("Error executing audit auto-quarantine for %s: %s", mac, ex)

    audit_manager.on_suspicious_device = on_audit_suspicious_device

    # 11. Start services
    global _poller_running, _poller_task
    _poller_running = True
    sniffer.start()
    scheduler.start()
    _poller_task = create_tracked_task(poll_keenetic_task())

    # Start interactive Telegram bot worker
    from keenguard.core.notifier import telegram_bot_worker
    if settings.telegram_enabled and settings.telegram_bot_token and settings.telegram_chat_id:
        create_tracked_task(telegram_bot_worker.start())

    # Initialize and start DNS security manager worker
    dns_security_manager.set_ws_broadcast(ws_manager.broadcast)
    dns_security_manager.reload_from_config()
    if settings.dns_security_auto_sync and settings.dns_security_provider != "none":
        dns_security_manager.start_background_sync(settings.dns_security_sync_interval)

    yield

    # Shutdown
    _poller_running = False
    if _poller_task and not _poller_task.done():
        _poller_task.cancel()
    dns_security_manager.stop_background_sync()
    await telegram_bot_worker.stop()
    sniffer.stop()
    scheduler.stop()
    set_main_loop(None)
