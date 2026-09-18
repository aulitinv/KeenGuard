"""FastAPI application providing REST endpoints and WebSockets for KeenGuard."""
import asyncio
import csv
from datetime import datetime, timezone
import io
import ipaddress
import json
import logging
from pathlib import Path
import time
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body, UploadFile, File
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from keenguard.config import settings, save_env_router_credentials, save_env_telegram_settings, save_env_dns_provider_settings
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord, SecurityEvent, IotPayloadRecord, LanCommunicationRecord, LanPolicyPreset
from keenguard.core.keenetic import keenetic_client, is_host_lan_isolated, is_unsafe_ip_for_blackhole
from keenguard.core.dns_providers import dns_security_manager
from keenguard.core.classifier import DeviceClassifier
from keenguard.core.profiles import profile_manager, policy_manager, PROFILE_TEMPLATES
from keenguard.core.forensics import forensics
from keenguard.core.anomaly import anomaly_detector
from keenguard.core.sniffer import sniffer
from keenguard.core.audit import audit_manager, should_device_quarantine, identify_geoip
from keenguard.core.notifier import notifier
from keenguard.core.digest import digest_generator
from keenguard.core.scheduler import scheduler
from keenguard.core.dns_tracker import dns_tracker, LOCAL_PREFIXES
from keenguard.core.domain_analyzer import domain_analyzer, TV_BRAND_PRESETS, detect_tv_brand, get_tv_brand_presets
from keenguard.core.checklist import SecurityChecklistEvaluator
from keenguard.core.lan_tracker import lan_tracker
from keenguard.core.dissector import PacketDissector

from contextlib import asynccontextmanager

logger = logging.getLogger("keenguard.web")

# Retain strong references to background tasks so Python's GC does not terminate them
_background_tasks: set[Any] = set()
_main_loop: Optional[asyncio.AbstractEventLoop] = None

def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop

def create_tracked_task(coro) -> Any:
    """Create an asyncio Task and retain a strong reference until completion to prevent GC collection.
    Thread-safe: if called from a background worker thread (like Scapy's sniffer thread),
    it safely schedules the coroutine onto the main event loop using run_coroutine_threadsafe.
    """
    global _main_loop
    try:
        loop = asyncio.get_running_loop()
        _main_loop = loop
        task = loop.create_task(coro)
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return task
    except RuntimeError:
        # No running event loop in current thread (e.g. Scapy sniffer worker thread)
        loop = _main_loop
        if loop is not None and loop.is_running():
            async def _tracked():
                t = asyncio.current_task()
                if t:
                    _background_tasks.add(t)
                    t.add_done_callback(_background_tasks.discard)
                return await coro

            return asyncio.run_coroutine_threadsafe(_tracked(), loop)
        else:
            logger.debug("Cannot schedule background task '%s': main event loop is not active", coro)
            try:
                coro.close()
            except Exception:
                pass
            return None

app = FastAPI(title="KeenGuard", description="Network Security & Monitoring for Keenetic", version="1.0.0")

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for conn in list(self.active_connections):
            try:
                await conn.send_json(message)
            except Exception:
                self.disconnect(conn)

ws_manager = ConnectionManager()

# Router Connection State Watchdog & Health Monitor
class RouterHealthMonitor:
    def __init__(self):
        self.is_connected: Optional[bool] = None
        self.model: str = "Keenetic"
        self.version: str = "KeeneticOS"
        self.host: str = settings.router_host
        self.last_heartbeat: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.failure_count: int = 0

    async def update_status(self, connected: bool, model: Optional[str] = None,
                            version: Optional[str] = None, error: Optional[str] = None):
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

# Traffic rate calculation & polling state
device_traffic_rates: Dict[str, tuple] = {}  # mac -> (timestamp, rx_bytes, tx_bytes)
_poll_counter: int = 0

# Background poller for Keenetic RCI
async def do_keenetic_poll():
    global _poll_counter
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
    if _poll_counter % 6 == 0:
        try:
            dns_cache = await keenetic_client.get_dns_cache()
            for entry in dns_cache:
                if entry.get("domain"):
                    await db.record_dns_query(entry["domain"], ip=entry.get("ip"))
        except Exception:
            pass

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

_poller_running: bool = False
_poller_task: Optional[asyncio.Task] = None

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

# Connect sniffer events to WebSocket & Forensics
def _handle_sniffer_event(event_dict: Dict):
    try:
        create_tracked_task(_async_sniffer_dispatch(event_dict))
    except Exception as e:
        logger.debug("Could not dispatch sniffer event: %s", e)

async def _async_sniffer_dispatch(event_dict: Dict):
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

sniffer.register_callback(_handle_sniffer_event)

def _backup_production_database():
    """Creates a safety snapshot of the SQLite database on startup for instant recovery."""
    try:
        prod_db = Path(settings.db_path)
        if prod_db.exists() and prod_db.stat().st_size > 0:
            bak_path = prod_db.with_suffix(".db.bak")
            if bak_path.exists():
                bak1_path = prod_db.with_suffix(".db.bak1")
                import shutil
                shutil.copy2(bak_path, bak1_path)
            import shutil
            shutil.copy2(prod_db, bak_path)
            logger.info("Automatic startup database snapshot created: %s", bak_path)
    except Exception as e:
        logger.warning("Could not create startup DB snapshot: %s", e)

# Lifespan Context Manager (Startup & Shutdown)
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    _backup_production_database()
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

        # 3. Router interfaces refreshed cleanly (passive read-only mode on startup)
    else:
        await router_health.update_status(connected=False, error=auth_res.get("message"))

    # 4. Load Telegram settings from DB / sync with .env
    saved_tg_token = await db.get_setting("telegram_bot_token")
    if saved_tg_token:
        settings.telegram_bot_token = saved_tg_token
    elif settings.telegram_bot_token and not saved_tg_token:
        await db.save_setting("telegram_bot_token", settings.telegram_bot_token)

    saved_tg_chat = await db.get_setting("telegram_chat_id")
    if saved_tg_chat:
        settings.telegram_chat_id = saved_tg_chat
    elif settings.telegram_chat_id and not saved_tg_chat:
        await db.save_setting("telegram_chat_id", settings.telegram_chat_id)

    saved_tg_enabled = await db.get_setting("telegram_enabled")
    if saved_tg_enabled is not None:
        settings.telegram_enabled = saved_tg_enabled.lower() in ("true", "1")
    saved_tg_url = await db.get_setting("telegram_api_url")
    if saved_tg_url:
        settings.telegram_api_url = saved_tg_url
    saved_tg_proxy = await db.get_setting("telegram_proxy")
    if saved_tg_proxy is not None:
        settings.telegram_proxy = saved_tg_proxy.strip() or None

    # 5. Load New Device Policy settings from DB
    saved_new_dev = await db.get_setting("new_device_action")
    if saved_new_dev:
        settings.new_device_action = saved_new_dev
    saved_dev_quar = await db.get_setting("new_device_quarantine_wan")
    if saved_dev_quar is not None:
        settings.new_device_quarantine_wan = saved_dev_quar.lower() in ("true", "1")
    saved_dev_iso = await db.get_setting("new_device_isolate_lan")
    if saved_dev_iso is not None:
        settings.new_device_isolate_lan = saved_dev_iso.lower() in ("true", "1")
    saved_dev_audit = await db.get_setting("new_device_auto_audit")
    if saved_dev_audit is not None:
        settings.new_device_auto_audit = saved_dev_audit.lower() in ("true", "1")
    saved_dev_dur = await db.get_setting("new_device_audit_duration")
    if saved_dev_dur:
        try:
            settings.new_device_audit_duration = int(saved_dev_dur)
        except ValueError:
            pass

    # 6. Load Digest settings from DB
    saved_digest_en = await db.get_setting("digest_enabled")
    if saved_digest_en is not None:
        settings.digest_enabled = saved_digest_en.lower() in ("true", "1")
    saved_digest_cond = await db.get_setting("digest_condition")
    if saved_digest_cond:
        settings.digest_condition = saved_digest_cond
    saved_digest_hour = await db.get_setting("digest_schedule_hour")
    if saved_digest_hour:
        try:
            settings.digest_schedule_hour = int(saved_digest_hour)
        except ValueError:
            pass

    # 7. Load Scheduled Audit settings from DB
    saved_sa_en = await db.get_setting("scheduled_audit_enabled")
    if saved_sa_en is not None:
        settings.scheduled_audit_enabled = saved_sa_en.lower() in ("true", "1")
    saved_sa_hour = await db.get_setting("scheduled_audit_hour")
    if saved_sa_hour:
        try:
            settings.scheduled_audit_hour = int(saved_sa_hour)
        except ValueError:
            pass
    saved_sa_scope = await db.get_setting("scheduled_audit_scope")
    if saved_sa_scope:
        settings.scheduled_audit_scope = saved_sa_scope
    saved_sa_dur = await db.get_setting("scheduled_audit_duration")
    if saved_sa_dur:
        try:
            settings.scheduled_audit_duration = int(saved_sa_dur)
        except ValueError:
            pass

    saved_policy_mode = await db.get_setting("new_device_policy_mode")
    if saved_policy_mode:
        settings.new_device_policy_mode = saved_policy_mode
    saved_cat_pols = await db.get_setting("new_device_category_policies")
    if saved_cat_pols:
        try:
            settings.new_device_category_policies = json.loads(saved_cat_pols)
        except Exception:
            pass
    saved_auto_quar = await db.get_setting("audit_auto_quarantine_suspicious")
    if saved_auto_quar is not None:
        settings.audit_auto_quarantine_suspicious = saved_auto_quar.lower() in ("true", "1")

    # 8. Load Night Mode hours from DB
    saved_night_start = await db.get_setting("night_mode_start_hour")
    if saved_night_start is not None:
        try:
            settings.night_mode_start_hour = int(saved_night_start)
        except ValueError:
            pass
    saved_night_end = await db.get_setting("night_mode_end_hour")
    if saved_night_end is not None:
        try:
            settings.night_mode_end_hour = int(saved_night_end)
        except ValueError:
            pass

    saved_tv_pre = await db.get_setting("tv_wake_pre_record_seconds")
    if saved_tv_pre is not None:
        try:
            settings.tv_wake_pre_record_seconds = int(saved_tv_pre)
        except ValueError:
            pass
    saved_tv_post = await db.get_setting("tv_wake_post_record_seconds")
    if saved_tv_post is not None:
        try:
            settings.tv_wake_post_record_seconds = int(saved_tv_post)
        except ValueError:
            pass

    # 9. Load IoT Payload storage settings from DB
    saved_iot_cap = await db.get_setting("iot_payload_capture_enabled")
    if saved_iot_cap is not None:
        settings.iot_payload_capture_enabled = saved_iot_cap.lower() in ("true", "1")
    saved_iot_gb = await db.get_setting("iot_payload_max_storage_gb")
    if saved_iot_gb is not None:
        try:
            settings.iot_payload_max_storage_gb = float(saved_iot_gb)
        except ValueError:
            pass
    saved_iot_days = await db.get_setting("iot_payload_retention_days")
    if saved_iot_days is not None:
        try:
            settings.iot_payload_retention_days = int(saved_iot_days)
        except ValueError:
            pass

    # 10. Load fine-grained network security settings
    saved_tv_day = await db.get_setting("tv_day_tracking_mode")
    if saved_tv_day:
        settings.tv_day_tracking_mode = saved_tv_day
    saved_tv_ttl = await db.get_setting("tv_wake_trigger_ttl_seconds")
    if saved_tv_ttl:
        try:
            settings.tv_wake_trigger_ttl_seconds = int(saved_tv_ttl)
        except ValueError:
            pass
    saved_cam_wan = await db.get_setting("camera_notify_wan_stream")
    if saved_cam_wan is not None:
        settings.camera_notify_wan_stream = saved_cam_wan.lower() in ("true", "1")
    saved_cam_lan = await db.get_setting("camera_notify_lan_stream")
    if saved_cam_lan is not None:
        settings.camera_notify_lan_stream = saved_cam_lan.lower() in ("true", "1")
    saved_quar_scope = await db.get_setting("auto_quarantine_scope")
    if saved_quar_scope:
        settings.auto_quarantine_scope = saved_quar_scope
    saved_mac_conf = await db.get_setting("mac_conflict_detection_enabled")
    if saved_mac_conf is not None:
        settings.mac_conflict_detection_enabled = saved_mac_conf.lower() in ("true", "1")
    saved_dedup_win = await db.get_setting("notification_dedup_window_seconds")
    if saved_dedup_win:
        try:
            settings.notification_dedup_window_seconds = int(saved_dedup_win)
        except ValueError:
            pass
    saved_cam_thresh = await db.get_setting("camera_upload_threshold_kbps")
    if saved_cam_thresh is not None:
        try:
            settings.camera_upload_threshold_kbps = float(saved_cam_thresh)
        except ValueError:
            pass

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

    # 11. Load DNS Security Provider settings from DB / sync with settings
    saved_dns_prov = await db.get_setting("dns_security_provider")
    if saved_dns_prov:
        settings.dns_security_provider = saved_dns_prov
    saved_dns_interval = await db.get_setting("dns_security_sync_interval")
    if saved_dns_interval:
        try:
            settings.dns_security_sync_interval = int(saved_dns_interval)
        except ValueError:
            pass
    saved_dns_auto = await db.get_setting("dns_security_auto_sync")
    if saved_dns_auto is not None:
        settings.dns_security_auto_sync = saved_dns_auto.lower() in ("true", "1")
    for key in [
        "nextdns_api_key", "nextdns_profile_id",
        "controld_api_key", "controld_device_id",
        "adguard_url", "adguard_username", "adguard_password",
        "pihole_url", "pihole_api_token", "pihole_password"
    ]:
        val = await db.get_setting(key)
        if val:
            setattr(settings, key, val)

    # 8. Start services
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
    _main_loop = None

app.router.lifespan_context = lifespan

# --- REST Endpoints ---

@app.get("/")
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "KeenGuard backend is active. Web UI index.html not found."}

@app.get("/api/status")
async def get_system_status():
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

@app.get("/api/devices")
async def get_devices():
    devices = await db.get_all_devices()
    rotations = DeviceClassifier.detect_mac_rotations(devices)
    mac_to_group = {}
    for grp in rotations:
        for m in grp["all_macs"]:
            mac_to_group[m] = grp

    res = []
    for d in devices:
        item = d.model_dump()
        is_rand = DeviceClassifier.is_randomized_mac(d.mac)
        item["is_random_mac"] = is_rand
        item["segment_risk"] = keenetic_client.evaluate_segment_risk(d.profile, d.segment or "Home", d.ip or "")
        grp = mac_to_group.get(d.mac.upper())
        if grp:
            is_hw = not is_rand
            is_act = (d.mac.upper() == grp.get("active_mac"))
            if is_hw:
                role = "hardware"
            elif is_act:
                role = "active_random"
            else:
                role = "historical_random"

            item["rotation_group"] = {
                "hostname": grp["hostname"],
                "hardware_mac": grp.get("hardware_mac"),
                "active_mac": grp.get("active_mac"),
                "is_hardware": is_hw,
                "is_active": is_act,
                "role": role,
                "alias_count": grp["count"],
                "other_macs": [m for m in grp["all_macs"] if m != d.mac.upper()]
            }
        else:
            item["rotation_group"] = None
        res.append(item)
    return res

@app.get("/api/devices/{mac}")
async def get_device(mac: str):
    clean_mac = mac.upper()
    dev = await db.get_device(clean_mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    events = await db.get_recent_events(limit=20, target_mac=clean_mac)

    dev_dict = dev.model_dump()
    is_rand = DeviceClassifier.is_randomized_mac(dev.mac)
    dev_dict["is_random_mac"] = is_rand
    dev_dict["segment_risk"] = keenetic_client.evaluate_segment_risk(dev.profile, dev.segment or "Home", dev.ip or "")

    devices = await db.get_all_devices()
    rotations = DeviceClassifier.detect_mac_rotations(devices)
    matched_group = None
    for grp in rotations:
        if clean_mac in grp["all_macs"]:
            matched_group = grp
            break

    if matched_group:
        is_hw = not is_rand
        is_act = (clean_mac == matched_group.get("active_mac"))
        if is_hw:
            role = "hardware"
        elif is_act:
            role = "active_random"
        else:
            role = "historical_random"

        dev_dict["rotation_group"] = {
            "hostname": matched_group["hostname"],
            "hardware_mac": matched_group.get("hardware_mac"),
            "active_mac": matched_group.get("active_mac"),
            "is_hardware": is_hw,
            "is_active": is_act,
            "role": role,
            "alias_count": matched_group["count"],
            "other_macs": [m for m in matched_group["all_macs"] if m != clean_mac]
        }
    else:
        dev_dict["rotation_group"] = None

    return {"device": dev_dict, "events": [e.model_dump() for e in events]}

@app.delete("/api/devices/{mac}")
async def delete_single_device(mac: str):
    clean_mac = mac.upper()
    success = await db.delete_device(clean_mac)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    await ws_manager.broadcast({"type": "device_deleted", "mac": clean_mac})
    return {"status": "ok", "mac": clean_mac}

@app.delete("/api/devices-offline")
async def delete_all_offline_devices():
    deleted_count = await db.delete_offline_devices()
    await ws_manager.broadcast({"type": "devices_pruned", "deleted_count": deleted_count})
    return {"status": "ok", "deleted_count": deleted_count}

class ProfileUpdate(BaseModel):
    profile: str

class DevicePolicyUpdateRequest(BaseModel):
    policy_id: str
    preset_id: Optional[str] = None
    designated_nvr_ip: Optional[str] = None
    auto_quarantine_override: Optional[str] = None
    custom_allowed_ports: Optional[List[int]] = None
    is_blocked_wan: Optional[bool] = None
    tv_pre_record_seconds: Optional[int] = None
    tv_post_record_seconds: Optional[int] = None
    tv_day_mode: Optional[str] = None

@app.post("/api/devices/{mac}/policy")
async def set_device_policy_api(mac: str, req: DevicePolicyUpdateRequest):
    clean_mac = mac.upper()
    updated = await policy_manager.apply_policy(
        mac=clean_mac,
        policy_id=req.policy_id,
        preset_id=req.preset_id,
        designated_nvr_ip=req.designated_nvr_ip,
        auto_quarantine_override=req.auto_quarantine_override,
        custom_allowed_ports=req.custom_allowed_ports,
        is_blocked_wan=req.is_blocked_wan,
        tv_pre_record_seconds=req.tv_pre_record_seconds,
        tv_post_record_seconds=req.tv_post_record_seconds,
        tv_day_mode=req.tv_day_mode,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "device": updated.model_dump()}

@app.post("/api/devices/{mac}/profile")
async def set_profile(mac: str, update: ProfileUpdate):
    clean_mac = mac.upper()
    updated = await policy_manager.apply_policy(clean_mac, policy_id=update.profile)
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "device": updated.model_dump()}

class ToggleRequest(BaseModel):
    enabled: bool

@app.post("/api/devices/{mac}/toggle_wan")
async def toggle_wan(mac: str, req: ToggleRequest):
    success = await profile_manager.toggle_wan(mac, block=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    return {"status": "ok", "blocked_wan": req.enabled, "success": success}

@app.post("/api/devices/{mac}/toggle_lan")
async def toggle_lan(mac: str, req: ToggleRequest):
    success = await profile_manager.toggle_lan_isolation(mac, isolate=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    dev = await db.get_device(mac.upper())
    is_iso = dev.is_isolated_lan if dev else False
    msg = None
    if req.enabled and not is_iso:
        msg = "Для физической изоляции Wi-Fi устройств подключите их к Гостевой Wi-Fi сети Keenetic."
    return {"status": "ok", "isolated_lan": is_iso, "success": success, "message": msg}

@app.post("/api/devices/{mac}/toggle_airplay")
async def toggle_airplay(mac: str, req: ToggleRequest):
    success = await profile_manager.toggle_airplay(mac, allow=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    return {"status": "ok", "airplay_allowed": req.enabled, "success": success}

@app.post("/api/devices/{mac}/toggle_dlna")
async def toggle_dlna(mac: str, req: ToggleRequest):
    success = await profile_manager.toggle_dlna(mac, allow=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    return {"status": "ok", "dlna_allowed": req.enabled, "success": success}

@app.post("/api/devices/{mac}/toggle_night")
async def toggle_night(mac: str, req: ToggleRequest):
    success = await profile_manager.toggle_night_mode(mac, enable=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    return {"status": "ok", "night_mode": req.enabled, "success": success}

class RenameRequest(BaseModel):
    custom_name: str

@app.post("/api/devices/{mac}/rename")
async def rename_device(mac: str, req: RenameRequest):
    success = await db.update_device_policy(mac, custom_name=req.custom_name)
    await ws_manager.broadcast({"type": "device_updated", "mac": mac.upper()})
    return {"status": "ok", "success": success}

# ---------------- LAN Policy Presets & Setup Wizard Endpoints ----------------

class PresetCreateUpdateRequest(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    rules: Dict[str, Any]

@app.get("/api/presets")
async def list_presets():
    presets = await db.get_presets()
    return [p.model_dump() for p in presets]

@app.get("/api/presets/{preset_id}")
async def get_single_preset(preset_id: str):
    preset = await db.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Пресет не найден")
    return preset.model_dump()

@app.post("/api/presets")
async def create_preset(req: PresetCreateUpdateRequest):
    import uuid
    preset_id = req.id.strip() if req.id and req.id.strip() else f"custom_{uuid.uuid4().hex[:8]}"
    existing = await db.get_preset(preset_id)
    if existing:
        raise HTTPException(status_code=400, detail="Пресет с таким идентификатором уже существует")
    now_iso = datetime.now(timezone.utc).isoformat()
    new_preset = LanPolicyPreset(
        id=preset_id,
        name=req.name.strip(),
        description=req.description or "",
        is_builtin=False,
        rules=req.rules,
        created_at=now_iso,
        updated_at=now_iso
    )
    saved = await db.save_preset(new_preset)
    await ws_manager.broadcast({"type": "presets_updated"})
    return saved.model_dump()

@app.put("/api/presets/{preset_id}")
async def update_preset(preset_id: str, req: PresetCreateUpdateRequest):
    preset = await db.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Пресет не найден")
    if preset.is_builtin:
        raise HTTPException(status_code=400, detail="Нельзя изменять системный встроенный пресет")
    now_iso = datetime.now(timezone.utc).isoformat()
    updated_preset = LanPolicyPreset(
        id=preset_id,
        name=req.name.strip(),
        description=req.description or "",
        is_builtin=False,
        rules=req.rules,
        created_at=preset.created_at,
        updated_at=now_iso
    )
    saved = await db.save_preset(updated_preset)
    await ws_manager.broadcast({"type": "presets_updated"})
    return saved.model_dump()

@app.delete("/api/presets/{preset_id}")
async def delete_preset(preset_id: str):
    preset = await db.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Пресет не найден")
    if preset.is_builtin:
        raise HTTPException(status_code=400, detail="Нельзя удалять системный встроенный пресет")
    success = await db.delete_preset(preset_id)
    await ws_manager.broadcast({"type": "presets_updated"})
    return {"status": "ok", "deleted": success, "preset_id": preset_id}

class DeviceLanPolicyRequest(BaseModel):
    preset_id: Optional[str] = None
    designated_nvr_ip: Optional[str] = None
    auto_quarantine_override: Optional[str] = None
    custom_allowed_ports: Optional[List[int]] = None
    tv_pre_record_seconds: Optional[int] = None
    tv_post_record_seconds: Optional[int] = None
    tv_day_mode: Optional[str] = None

@app.post("/api/devices/{mac}/lan-policy")
async def update_device_lan_policy(mac: str, req: DeviceLanPolicyRequest):
    clean_mac = mac.upper()
    dev = await db.get_device(clean_mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    pol_id = req.preset_id or dev.profile or "unassigned"
    updated_dev = await policy_manager.apply_policy(
        mac=clean_mac,
        policy_id=pol_id,
        preset_id=req.preset_id,
        designated_nvr_ip=req.designated_nvr_ip,
        auto_quarantine_override=req.auto_quarantine_override,
        custom_allowed_ports=req.custom_allowed_ports,
        tv_pre_record_seconds=req.tv_pre_record_seconds,
        tv_post_record_seconds=req.tv_post_record_seconds,
        tv_day_mode=req.tv_day_mode,
    )
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "success": True, "device": updated_dev.model_dump() if updated_dev else None}

@app.get("/api/wizard/device/{mac}")
async def get_device_wizard_context(mac: str):
    clean_mac = mac.upper()
    dev = await db.get_device(clean_mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    presets = await db.get_presets()
    all_devices = await db.get_all_devices()

    nvr_candidates = [
        {"ip": d.ip, "name": d.custom_name or d.hostname or d.ip, "mac": d.mac}
        for d in all_devices
        if d.mac != clean_mac and (d.profile in ("nas", "trusted") or (d.hostname and "nvr" in d.hostname.lower()))
    ]

    dlna_candidates = [
        {"ip": d.ip, "name": d.custom_name or d.hostname or d.ip, "mac": d.mac}
        for d in all_devices
        if d.mac != clean_mac and (d.profile in ("nas", "router") or (d.hostname and "nas" in d.hostname.lower()))
    ]

    profile_to_preset = {
        "smart_tv": "preset_smart_tv",
        "camera": "preset_camera",
        "iot": "preset_iot",
        "smart_home_hub": "preset_iot",
        "trusted": "preset_trusted",
        "guest": "preset_isolated_guest",
        "nas": "preset_trusted",
        "printer": "preset_iot"
    }
    recommended_preset = dev.preset_id or profile_to_preset.get(dev.profile, "preset_iot")

    physically_isolated = is_host_lan_isolated(dev.interface, dev.ip)

    return {
        "device": dev.model_dump(),
        "presets": [p.model_dump() for p in presets],
        "recommended_preset": recommended_preset,
        "nvr_candidates": nvr_candidates,
        "dlna_candidates": dlna_candidates,
        "physically_isolated": physically_isolated,
        "current_interface": dev.interface or "Bridge0",
        "requires_guest_wifi_for_isolation": not physically_isolated
    }

class DeviceWizardSubmitRequest(BaseModel):
    custom_name: Optional[str] = None
    profile: Optional[str] = None
    preset_id: Optional[str] = None
    designated_nvr_ip: Optional[str] = None
    auto_quarantine_override: Optional[str] = None
    custom_allowed_ports: Optional[List[int]] = None
    tv_pre_record_seconds: Optional[int] = None
    tv_post_record_seconds: Optional[int] = None
    tv_day_mode: Optional[str] = None
    run_initial_audit: bool = False
    audit_duration_seconds: int = 60

@app.post("/api/wizard/device/{mac}")
async def submit_device_wizard(mac: str, req: DeviceWizardSubmitRequest):
    clean_mac = mac.upper()
    dev = await db.get_device(clean_mac)
    if not dev:
        raise HTTPException(status_code=404, detail="Устройство не найдено")

    if req.custom_name is not None and req.custom_name.strip():
        await db.update_device_policy(clean_mac, custom_name=req.custom_name.strip())

    pol_id = req.profile or req.preset_id or dev.profile or "unassigned"
    updated_dev = await policy_manager.apply_policy(
        mac=clean_mac,
        policy_id=pol_id,
        preset_id=req.preset_id,
        designated_nvr_ip=req.designated_nvr_ip,
        auto_quarantine_override=req.auto_quarantine_override,
        custom_allowed_ports=req.custom_allowed_ports,
        tv_pre_record_seconds=req.tv_pre_record_seconds,
        tv_post_record_seconds=req.tv_post_record_seconds,
        tv_day_mode=req.tv_day_mode,
    )
    await db.update_device_policy(clean_mac, wizard_completed=True)
    updated_dev = await db.get_device(clean_mac)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})

    audit_session = None
    if req.run_initial_audit and updated_dev and updated_dev.ip and updated_dev.ip != "0.0.0.0":
        try:
            dur = max(30, min(600, req.audit_duration_seconds or 60))
            audit_session = await audit_manager.start_audit(
                mac=clean_mac,
                ip=updated_dev.ip,
                hostname=updated_dev.custom_name or updated_dev.hostname,
                vendor=updated_dev.vendor,
                duration_seconds=dur,
                profile=updated_dev.profile
            )
        except Exception as ex:
            logger.error("Failed to launch wizard initial audit for %s: %s", clean_mac, ex)

    return {
        "status": "ok",
        "device": updated_dev.model_dump() if updated_dev else None,
        "audit_started": audit_session is not None,
        "audit_session": audit_session
    }

@app.get("/api/events")
async def get_events(limit: int = 50, event_type: Optional[str] = None, severity: Optional[str] = None):
    events = await db.get_recent_events(limit=limit, event_type=event_type, severity=severity)
    return [e.model_dump() for e in events]

@app.delete("/api/events/{event_id}")
async def delete_single_event(event_id: int):
    success = await db.delete_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await ws_manager.broadcast({"type": "event_deleted", "id": event_id})
    return {"status": "ok", "deleted": True, "id": event_id}

@app.delete("/api/events")
async def clear_events_api(severity: Optional[str] = None, older_than_days: Optional[int] = None):
    count = await db.clear_events(severity=severity, older_than_days=older_than_days)
    await ws_manager.broadcast({"type": "events_cleared", "severity": severity, "older_than_days": older_than_days, "count": count})
    return {"status": "ok", "deleted": count}

@app.get("/api/events/pcap/{filename}")
async def download_pcap(filename: str):
    file_path = settings.pcap_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="PCAP dump file not found")
    return FileResponse(path=str(file_path), filename=filename, media_type="application/vnd.tcpdump.pcap")

# --- Smart Home & IoT Management Endpoints ---

@app.get("/api/smarthome/overview")
async def get_smarthome_overview():
    devices = await db.get_all_devices()

    category_defs = {
        "controllers": {
            "key": "controllers",
            "title": "Хабы и контроллеры",
            "icon": "cpu",
            "badge_color": "text-indigo-400 bg-indigo-500/10 border-indigo-500/20",
            "description": "Центральные шлюзы и серверы автоматизации (SprutHub, Home Assistant, координаторы)",
            "devices": []
        },
        "garden": {
            "key": "garden",
            "title": "Сад и автополив",
            "icon": "sprout",
            "badge_color": "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
            "description": "Датчики влажности почвы, контроллеры автополива, электромагнитные клапаны и садовые сенсоры",
            "devices": []
        },
        "climate": {
            "key": "climate",
            "title": "Климат и воздух",
            "icon": "wind",
            "badge_color": "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
            "description": "Кондиционеры, очистители и увлажнители воздуха, тёплые полы",
            "devices": []
        },
        "sensors": {
            "key": "sensors",
            "title": "Датчики и мониторинг",
            "icon": "thermometer",
            "badge_color": "text-amber-400 bg-amber-500/10 border-amber-500/20",
            "description": "Датчики качества воздуха, температуры, влажности, открытия и протечки",
            "devices": []
        },
        "appliances": {
            "key": "appliances",
            "title": "Бытовая техника",
            "icon": "bot",
            "badge_color": "text-purple-400 bg-purple-500/10 border-purple-500/20",
            "description": "Роботы-пылесосы, посудомоечные машины, автоматические кормушки, умные розетки",
            "devices": []
        },
        "security": {
            "key": "security",
            "title": "Безопасность и камеры",
            "icon": "shield-check",
            "badge_color": "text-rose-400 bg-rose-500/10 border-rose-500/20",
            "description": "IP-камеры наблюдения, видеодомофоны, умные замки и сирены",
            "devices": []
        },
        "other": {
            "key": "other",
            "title": "Другие устройства",
            "icon": "layers",
            "badge_color": "text-slate-400 bg-slate-500/10 border-slate-500/20",
            "description": "Прочие модули умного дома и IoT-девайсы",
            "devices": []
        }
    }

    smarthome_devs = []
    hub_device = None

    for d in devices:
        # Smart Home strictly includes only devices with confirmed smart home profiles:
        # hubs, IoT devices, and cameras. Unassigned devices belong in the Quarantine/Devices tab.
        if d.profile not in ("smart_home_hub", "iot", "camera"):
            continue

        cat = DeviceClassifier.classify_smarthome_device(d)
        d_dict = d.model_dump()
        d_dict["smarthome_category"] = cat

        if cat == "controllers" or d.profile == "smart_home_hub":
            if not hub_device or "sprut" in str(d.hostname).lower():
                hub_device = d_dict

        if cat not in category_defs:
            category_defs[cat] = {
                "key": cat,
                "title": cat.capitalize(),
                "icon": "cpu",
                "badge_color": "text-slate-400 bg-slate-500/10 border-slate-500/20",
                "description": "Устройства умного дома",
                "devices": []
            }
        category_defs[cat]["devices"].append(d_dict)
        smarthome_devs.append(d_dict)

    # Inspect active NAT cloud connections
    cloud_connections = []
    try:
        nat_table = await keenetic_client.get_nat_table()
        dev_by_ip = {d["ip"]: d for d in smarthome_devs if d.get("ip")}
        seen_pairs = set()

        for flow in nat_table:
            src = flow.get("src")
            dst = flow.get("dst")
            proto = flow.get("protocol", "TCP")
            dport = flow.get("dport", 0)

            if src in dev_by_ip and dst and not dst.startswith(LOCAL_PREFIXES):
                pair_key = (src, dst, dport)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                dev = dev_by_ip[src]
                domain = await dns_tracker.resolve_ip(dst)
                analysis = domain_analyzer.analyze_domain(domain or dst, ip=dst)

                cloud_connections.append({
                    "mac": dev["mac"],
                    "device_name": dev.get("custom_name") or dev.get("hostname") or dev["mac"],
                    "category": dev.get("smarthome_category", "other"),
                    "src_ip": src,
                    "dst_ip": dst,
                    "dport": dport,
                    "protocol": proto,
                    "domain": domain or dst,
                    "cloud_vendor": analysis.get("vendor", "Внешний хост"),
                    "category_title": analysis.get("category_title", "Внешняя связь"),
                    "risk_level": analysis.get("risk_level", "warning"),
                    "is_blocked_wan": dev.get("is_blocked_wan", False)
                })
    except Exception as e:
        logger.debug("Error mapping smarthome NAT connections: %s", e)

    total_count = len(smarthome_devs)
    online_count = sum(1 for d in smarthome_devs if d.get("is_online"))
    zero_internet_count = sum(1 for d in smarthome_devs if d.get("is_blocked_wan"))
    isolated_lan_count = sum(1 for d in smarthome_devs if d.get("is_isolated_lan"))

    # Advisory checklist (educational and step-by-step guidance without automatic execution)
    checklist = [
        {
            "id": "hub_isolation",
            "title": "Асимметричная изоляция хаба (SprutHub)",
            "status": "configured" if (hub_device and hub_device.get("is_isolated_lan")) else "recommended",
            "summary": "Односторонний доступ из домашней сети к хабу со встроенной защитой от компрометации.",
            "guide": [
                "1. В KeeneticOS выделите сегмент (например, «Умный дом / IoT») и перенесите туда контроллер.",
                "2. В «Сетевая безопасность» → «Межсетевой экран» создайте 2 правила:",
                "   ✓ Домашняя сеть → Сегмент IoT: Разрешить (любой трафик)",
                "   ✕ Сегмент IoT → Домашняя сеть: Запретить (любой трафик)",
                "3. Результат: смартфоны и ПК свободно управляют умным домом, но взломанный хаб или сторонний плагин не сможет атаковать компьютеры и NAS."
            ],
            "action_mac": hub_device["mac"] if hub_device else None
        },
        {
            "id": "zero_internet_sensors",
            "title": "Режим Zero Internet для локальных датчиков",
            "status": "configured" if zero_internet_count >= max(1, total_count // 3) else "advisory",
            "summary": "Отключение выхода в интернет для датчиков, передающих данные локально в SprutHub.",
            "guide": [
                "1. Датчикам температуры, влажности и воздуха интернет не требуется, если хаб опрашивает их локально по Wi-Fi / Zigbee.",
                "2. Что изменится: датчик перестанет передавать телеметрию на серверы Tuya / Qingping в Китай.",
                "3. Все показания в SprutHub и Apple HomeKit продолжат обновляться штатно без задержек.",
                "4. Вы можете отключить интернет для каждого датчика индивидуально прямо в карточке устройства."
            ]
        },
        {
            "id": "appliance_protection",
            "title": "Сегментация роботов-пылесосов и техники",
            "status": "info",
            "summary": "Изоляция LAN для облачной техники с сохранением работы мобильного приложения.",
            "guide": [
                "1. Роботу-пылесосу Dreame нужен интернет для связи с мобильным приложением и построения карты.",
                "2. Поэтому выход в интернет (WAN) для него оставляют включённым, но включают «Изоляцию LAN».",
                "3. Это позволяет роботу работать через официальное приложение, полностью отрезая его от домашних ПК и медиафайлов."
            ]
        }
    ]

    return {
        "status": "ok",
        "stats": {
            "total_devices": total_count,
            "online_devices": online_count,
            "zero_internet_devices": zero_internet_count,
            "isolated_lan_devices": isolated_lan_count,
            "cloud_connections_count": len(cloud_connections)
        },
        "hub": hub_device,
        "categories": category_defs,
        "cloud_connections": cloud_connections,
        "checklist": checklist
    }

# --- Consolidated Security Checklist & Audit Endpoints ---

@app.get("/api/security/checklist")
async def get_security_checklist():
    """Returns the comprehensive, real-time security posture checklist."""
    return await SecurityChecklistEvaluator.evaluate_checklist()

@app.get("/api/security/segments")
async def get_security_segments():
    """Returns Keenetic hardware network segments and evaluates L2 bypass risks."""
    segments = await keenetic_client.get_network_segments()
    devices = await db.get_all_devices()
    enriched_devices = []
    for d in devices:
        risk = keenetic_client.evaluate_segment_risk(d.profile, d.segment or "Home", d.ip or "")
        enriched_devices.append({
            "mac": d.mac,
            "ip": d.ip,
            "hostname": d.hostname,
            "custom_name": d.custom_name,
            "vendor": d.vendor,
            "profile": d.profile,
            "segment": d.segment or "Home",
            "is_online": d.is_online,
            "risk": risk
        })
    at_risk = [d for d in enriched_devices if d["risk"]["risk_level"] in ("high", "medium") and d["is_online"]]
    return {
        "status": "ok",
        "segments": segments,
        "devices": enriched_devices,
        "devices_at_risk_count": len(at_risk),
        "devices_at_risk": at_risk
    }

class BulkSensorsWanRequest(BaseModel):
    block: bool
    mode: Optional[str] = "autonomous_only"  # "autonomous_only" / "local_capable_only" (preserves weather monitors & cloud IoT) or "all"

@app.post("/api/security/checklist/apply-sensors-zero-internet")
async def apply_sensors_zero_internet(req: BulkSensorsWanRequest):
    """Enables or disables Zero-Internet selectively for devices with local LAN capability, preserving cloud & weather IoT."""
    devices = await db.get_all_devices()
    device_domains = await db.get_device_domains_map()
    updated = []
    for d in devices:
        trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=device_domains.get(d.mac, []))
        # If autonomous_only / local_capable_only, ONLY block pure local sensors (preserve weather stations and cloud devices!)
        if req.mode in ("autonomous_only", "local_capable_only", "local_only"):
            if trust["tier"] == "pure_local":
                await profile_manager.toggle_wan(d.mac, block=req.block)
                updated.append(d.mac)
        else:
            cat = DeviceClassifier.classify_smarthome_device(d)
            if cat in ("sensors", "garden") or trust["tier"] in ("pure_local", "hybrid_weather"):
                await profile_manager.toggle_wan(d.mac, block=req.block)
                updated.append(d.mac)
    await ws_manager.broadcast({"type": "refresh"})
    return {"status": "ok", "updated_count": len(updated), "blocked": req.block, "mode": req.mode}

class BulkAppliancesLanRequest(BaseModel):
    isolate: bool

@app.post("/api/security/checklist/apply-appliances-lan-isolation")
async def apply_appliances_lan_isolation(req: BulkAppliancesLanRequest):
    """Isolates or unisolates smart home appliances and IoT from LAN."""
    devices = await db.get_all_devices()
    device_domains = await db.get_device_domains_map()
    updated = []
    actually_isolated = 0
    for d in devices:
        trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=device_domains.get(d.mac, []))
        cat = DeviceClassifier.classify_smarthome_device(d)
        if cat in ("appliances", "climate", "sensors", "garden") or trust["tier"] in ("cloud_appliance", "pure_local", "hybrid_weather"):
            iso_res = await profile_manager.toggle_lan_isolation(d.mac, isolate=req.isolate)
            updated.append(d.mac)
            if iso_res:
                actually_isolated += 1
    await ws_manager.broadcast({"type": "refresh"})
    msg = None
    if req.isolate and actually_isolated < len(updated):
        msg = f"Физическая изоляция Wi-Fi приборов требует подключения к Гостевой Wi-Fi сети Keenetic (Bridge1). Изолировано: {actually_isolated} из {len(updated)}."
    return {
        "status": "ok",
        "requested_isolate": req.isolate,
        "updated_count": len(updated),
        "actually_isolated": actually_isolated,
        "message": msg
    }

class ChecklistDeviceToggleRequest(BaseModel):
    mac: str
    target: str  # "wan" or "lan"
    enabled: bool

@app.post("/api/security/checklist/device-toggle")
async def toggle_checklist_device(req: ChecklistDeviceToggleRequest):
    """Direct 1-click toggle of WAN or LAN for any device from the checklist card."""
    mac = req.mac.upper()
    if req.target == "wan":
        # enabled means WAN is blocked (True) or allowed (False)
        success = await profile_manager.toggle_wan(mac, block=req.enabled)
        is_active = req.enabled
    elif req.target == "lan":
        # enabled means LAN is isolated (True) or connected (False)
        success = await profile_manager.toggle_lan_isolation(mac, isolate=req.enabled)
        dev = await db.get_device(mac)
        is_active = dev.is_isolated_lan if dev else False
    else:
        raise HTTPException(status_code=400, detail="Invalid target: must be 'wan' or 'lan'")
    await ws_manager.broadcast({"type": "refresh"})
    return {"status": "ok", "mac": mac, "target": req.target, "enabled": is_active, "success": success}

class QuarantineToggleRequest(BaseModel):
    enable: bool

@app.post("/api/security/checklist/toggle-quarantine")
async def toggle_quarantine_policy(req: QuarantineToggleRequest):
    """Toggles new device quarantine policies."""
    settings.new_device_quarantine_wan = req.enable
    settings.new_device_isolate_lan = req.enable
    settings.new_device_continuous_audit = req.enable
    await ws_manager.broadcast({"type": "refresh"})
    return {"status": "ok", "quarantine_active": req.enable}

class ModularQuarantineRequest(BaseModel):
    rule: str  # "wan", "lan", "auto_audit", "continuous_audit", "all"
    enabled: bool

@app.post("/api/security/checklist/toggle-quarantine-rule")
async def toggle_quarantine_rule(req: ModularQuarantineRequest):
    """Modular toggle for individual quarantine and audit rules."""
    if req.rule == "wan":
        settings.new_device_quarantine_wan = req.enabled
    elif req.rule == "lan":
        settings.new_device_isolate_lan = req.enabled
    elif req.rule == "auto_audit":
        settings.new_device_auto_audit = req.enabled
    elif req.rule == "continuous_audit":
        settings.new_device_continuous_audit = req.enabled
    elif req.rule == "all":
        settings.new_device_quarantine_wan = req.enabled
        settings.new_device_isolate_lan = req.enabled
        settings.new_device_auto_audit = req.enabled
        settings.new_device_continuous_audit = req.enabled
    await ws_manager.broadcast({"type": "refresh"})
    return {
        "status": "ok",
        "settings": {
            "quarantine_wan": settings.new_device_quarantine_wan,
            "quarantine_lan": settings.new_device_isolate_lan,
            "auto_audit": settings.new_device_auto_audit,
            "continuous_audit": settings.new_device_continuous_audit
        }
    }

class SecurityWizardApplyRequest(BaseModel):
    tv_night_mode: bool = True
    zero_internet_sensors: bool = True
    quarantine_enabled: bool = True
    quarantine_continuous: bool = True

@app.post("/api/security/wizard/apply")
async def apply_security_wizard(req: SecurityWizardApplyRequest):
    """Applies combined security hardening settings from the Interactive Security Wizard."""
    tv_updated = []
    if req.tv_night_mode:
        devices = await db.get_all_devices()
        for d in devices:
            if d.profile == "smart_tv" or "tv" in str(d.hostname).lower():
                await profile_manager.toggle_night_mode(d.mac, enable=True)
                tv_updated.append(d.mac)

    sensors_updated = []
    if req.zero_internet_sensors:
        devices = await db.get_all_devices()
        device_domains = await db.get_device_domains_map()
        for d in devices:
            trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=device_domains.get(d.mac, []))
            if trust["tier"] == "pure_local":
                await profile_manager.toggle_wan(d.mac, block=True)
                sensors_updated.append(d.mac)

    settings.new_device_quarantine_wan = req.quarantine_enabled
    settings.new_device_isolate_lan = False
    settings.new_device_continuous_audit = req.quarantine_continuous
    settings.new_device_auto_audit = req.quarantine_continuous

    await ws_manager.broadcast({"type": "refresh"})
    return {
        "status": "ok",
        "tv_updated_count": len(tv_updated),
        "sensors_blocked_count": len(sensors_updated),
        "quarantine_active": req.quarantine_enabled,
        "continuous_audit_active": req.quarantine_continuous,
        "message": "Политики безопасности успешно применены к устройствам сети!"
    }

# --- Device Traffic Audit & Forensic Inspection Endpoints ---


class AuditStartRequest(BaseModel):
    duration_seconds: Optional[int] = 300
    scope: Optional[str] = "all"  # "all", "iot_only", "untrusted"

class NetworkAuditStartRequest(BaseModel):
    duration_seconds: Optional[int] = 300
    scope: Optional[str] = "all"  # "all", "iot_only", "untrusted"

@app.post("/api/audit/{mac}/start")
async def start_device_audit(mac: str, req: AuditStartRequest):
    mac_upper = mac.upper()
    dur_sec = req.duration_seconds if req.duration_seconds is not None else 300
    if mac_upper in ("NETWORK", "__ALL_NETWORK__", "__IOT_ONLY__", "__UNTRUSTED__"):
        target_scope = "iot_only" if mac_upper == "__IOT_ONLY__" else ("untrusted" if mac_upper == "__UNTRUSTED__" else (req.scope or "all"))
        res = await audit_manager.start_network_audit(
            duration_seconds=dur_sec,
            scope=target_scope
        )
        await ws_manager.broadcast({"type": "network_audit_started", "session": res})
        return res

    dev = await db.get_device(mac_upper)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    res = await audit_manager.start_audit(
        mac=mac_upper,
        ip=dev.ip,
        hostname=dev.custom_name or dev.hostname,
        vendor=dev.vendor,
        duration_seconds=dur_sec,
        profile=dev.profile
    )
    await ws_manager.broadcast({"type": "audit_started", "mac": mac_upper, "session": res})
    return res

@app.post("/api/audit/{mac}/stop")
async def stop_device_audit(mac: str):
    mac_upper = mac.upper()
    if mac_upper == "NETWORK":
        report = await audit_manager.stop_network_audit()
        if not report:
            raise HTTPException(status_code=404, detail="No active network audit session")
        await ws_manager.broadcast({"type": "network_audit_stopped", "report": report})
        return report

    report = await audit_manager.stop_audit(mac_upper)
    if not report:
        raise HTTPException(status_code=404, detail="No active audit session for this device")
    await ws_manager.broadcast({"type": "audit_stopped", "mac": mac_upper, "report": report})
    return report

@app.post("/api/audit/network/start")
async def start_network_audit_endpoint(req: NetworkAuditStartRequest):
    dur_sec = req.duration_seconds if req.duration_seconds is not None else 300
    res = await audit_manager.start_network_audit(
        duration_seconds=dur_sec,
        scope=req.scope or "all"
    )
    await ws_manager.broadcast({"type": "network_audit_started", "session": res})
    return res

@app.post("/api/audit/network/stop")
async def stop_network_audit_endpoint():
    report = await audit_manager.stop_network_audit()
    if not report:
        raise HTTPException(status_code=400, detail="Нет активной сессии аудита сети")
    await ws_manager.broadcast({"type": "network_audit_stopped", "report": report})
    return report

@app.get("/api/audit/network/status")
async def get_network_audit_status_endpoint():
    status = audit_manager.get_network_audit_status()
    if not status:
        return {"is_active": False}
    return status

@app.get("/api/audit/network/latest_report")
async def get_latest_network_audit_report_endpoint():
    reports = await db.get_audit_reports(limit=50)
    net_reports = [r for r in reports if r.mac == "NETWORK" or r.id.startswith("net_audit_")]
    if not net_reports:
        raise HTTPException(status_code=404, detail="Отчет аудита сети не найден")
    r = net_reports[0]
    try:
        return json.loads(r.report_json)
    except Exception:
        return r.model_dump()

@app.get("/api/audit/{mac}/status")
async def get_audit_status(mac: str):
    if mac.upper() == "NETWORK":
        status = audit_manager.get_network_audit_status()
        if not status:
            return {"is_active": False}
        return status

    session = audit_manager.get_session(mac.upper())
    if not session or not session.is_active:
        return {"is_active": False}
    elapsed = int((datetime.now(timezone.utc) - session.start_time).total_seconds())
    return {
        "is_active": True,
        "session_id": session.session_id,
        "mac": session.mac,
        "ip": session.ip,
        "hostname": session.hostname,
        "elapsed_seconds": elapsed,
        "duration_limit": session.duration_seconds,
        "flows_count": len(session.flows),
        "total_bytes": session.total_bytes_up + session.total_bytes_down,
        "total_packets": session.total_packets_up + session.total_packets_down,
        "top_flows": sorted(list(session.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)[:5],
        "top_domains": list(session.dns_queries.values())[:5]
    }

@app.get("/api/audit/{mac}/latest_report")
async def get_latest_audit_report(mac: str):
    if mac.upper() == "NETWORK":
        reports = await db.get_audit_reports(limit=50)
        net_reports = [r for r in reports if r.mac == "NETWORK" or r.id.startswith("net_audit_")]
        if not net_reports:
            raise HTTPException(status_code=404, detail="No network audit reports found")
        r = net_reports[0]
        try:
            return json.loads(r.report_json)
        except Exception:
            return r.model_dump()

    reports = await db.get_audit_reports(mac=mac.upper(), limit=1)
    if not reports:
        raise HTTPException(status_code=404, detail="No audit reports found for this device")
    r = reports[0]
    try:
        data = json.loads(r.report_json)
        return data
    except Exception:
        return r.model_dump()

@app.get("/api/audit/active")
async def get_active_audits():
    active = []
    now = datetime.now(timezone.utc)

    # Check network session
    net_s = audit_manager.active_network_session
    if net_s and net_s.is_active:
        elapsed = int((now - net_s.start_time).total_seconds())
        active.append({
            "session_id": net_s.session_id,
            "mac": "NETWORK",
            "ip": "0.0.0.0",
            "hostname": f"Вся сеть ({net_s.scope})",
            "vendor": "Keenetic Network",
            "profile": "network",
            "is_network": True,
            "scope": net_s.scope,
            "devices_count": len(net_s.device_stats),
            "elapsed_seconds": elapsed,
            "duration_seconds": net_s.duration_seconds,
            "flows_count": len(net_s.flows),
            "total_bytes": net_s.total_bytes_up + net_s.total_bytes_down,
            "total_packets": len(net_s.packets),
            "quarantined_count": len(net_s.quarantined_devices),
            "lateral_movements_count": len(net_s.lateral_movements),
            "top_flows": sorted(list(net_s.flows.values()), key=lambda x: x.get("bytes_up", 0) + x.get("bytes_down", 0), reverse=True)[:5],
            "top_domains": list(net_s.dns_queries.values())[:5]
        })

    for mac, session in audit_manager.active_sessions.items():
        if session.is_active:
            elapsed = int((now - session.start_time).total_seconds())
            active.append({
                "session_id": session.session_id,
                "mac": session.mac,
                "ip": session.ip,
                "hostname": session.hostname,
                "vendor": session.vendor,
                "profile": session.profile,
                "is_network": False,
                "elapsed_seconds": elapsed,
                "duration_seconds": session.duration_seconds,
                "flows_count": len(session.flows),
                "total_bytes": session.total_bytes_up + session.total_bytes_down,
                "total_packets": session.total_packets_up + session.total_packets_down,
                "top_flows": sorted(list(session.flows.values()), key=lambda x: x.get("bytes_up", 0) + x.get("bytes_down", 0), reverse=True)[:5],
                "top_domains": list(session.dns_queries.values())[:5]
            })
    return active

@app.get("/api/audit/reports")
async def list_audit_reports(limit: int = 50):
    reports = await db.get_audit_reports(limit=limit)
    return [r.model_dump() for r in reports]

@app.delete("/api/audit/reports/{report_id}")
async def delete_single_audit_report(report_id: str):
    pcap_file = await db.delete_audit_report(report_id)
    if pcap_file is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    if pcap_file:
        try:
            dump_path = settings.pcap_dir / pcap_file
            if dump_path.exists():
                dump_path.unlink()
        except Exception as e:
            logger.warning("Could not delete PCAP file %s: %s", pcap_file, e)

    await ws_manager.broadcast({"type": "audit_report_deleted", "id": report_id})
    return {"status": "ok", "id": report_id, "deleted": True}

@app.delete("/api/audit/reports")
async def clear_audit_reports_api(older_than_days: Optional[int] = None):
    pcap_files = await db.clear_audit_reports(older_than_days=older_than_days)
    for pf in pcap_files:
        try:
            dump_path = settings.pcap_dir / pf
            if dump_path.exists():
                dump_path.unlink()
        except Exception:
            pass

    await ws_manager.broadcast({"type": "audit_reports_cleared", "older_than_days": older_than_days, "count": len(pcap_files)})
    return {"status": "ok", "deleted": len(pcap_files)}

@app.get("/api/audit/report/{report_id}")
async def get_audit_report_detail(report_id: str):
    r = await db.get_audit_report_by_id(report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Audit report not found")
    try:
        data = json.loads(r.report_json)
        return data
    except Exception:
        return r.model_dump()

@app.get("/api/audit/pcap/{filename}")
async def download_audit_pcap(filename: str):
    file_path = settings.pcap_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="PCAP file not found")
    return FileResponse(path=str(file_path), filename=filename, media_type="application/vnd.tcpdump.pcap")

@app.get("/api/upnp")
async def get_upnp():
    mappings = await keenetic_client.get_upnp_mappings()
    return [m.model_dump() for m in mappings]

class DeleteUPnPRequest(BaseModel):
    protocol: str
    ext_port: int

@app.post("/api/upnp/delete")
async def delete_upnp(req: DeleteUPnPRequest):
    success = await keenetic_client.delete_upnp_mapping(req.protocol, req.ext_port)
    return {"status": "ok", "success": success}

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

@app.get("/api/settings")
async def get_app_settings():
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

class TestConnRequest(BaseModel):
    router_host: str
    router_user: str
    router_password: Optional[str] = None

@app.post("/api/test_connection")
async def test_keenetic_auth(req: TestConnRequest):
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

@app.post("/api/settings")
async def save_app_settings(s: SettingsUpdate):
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

# --- Granular New Device Policy Endpoints ---
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

@app.get("/api/settings/new_device_policy")
async def get_new_device_policy_endpoint():
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

@app.post("/api/settings/new_device_policy")
async def save_new_device_policy_endpoint(req: NewDevicePolicyUpdateRequest):
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

# --- Telegram Endpoints ---
class TelegramTestRequest(BaseModel):
    token: Optional[str] = None
    chat_id: Optional[str] = None
    api_url: Optional[str] = None
    proxy: Optional[str] = None

@app.post("/api/telegram/test")
async def test_telegram_connection(req: TelegramTestRequest):
    token = (req.token or settings.telegram_bot_token or "").strip()
    chat_id = (req.chat_id or settings.telegram_chat_id or "").strip()
    api_url = (req.api_url or settings.telegram_api_url or "https://api.telegram.org").strip()
    proxy = req.proxy if req.proxy is not None else settings.telegram_proxy
    res = await notifier.send_test_message(token=token, chat_id=chat_id, api_url=api_url, proxy=proxy)
    return res

# --- DNS Monitoring & Domain Reputation Endpoints ---
class CustomRuleRequest(BaseModel):
    domain: str
    category: str
    description: Optional[str] = ""
    risk_level: Optional[str] = "safe"

class ClearDnsRequest(BaseModel):
    domains: Optional[List[str]] = None

@app.get("/api/dns/queries")
async def get_dns_queries(limit: int = 100):
    queries = await db.get_top_dns_queries(limit=limit)
    domains = [q["domain"] for q in queries]
    devices_by_domain = await db.get_dns_device_counts_for_domains(domains)
    all_devs = await db.get_all_devices()
    dev_map = {d.mac: d for d in all_devs}

    # Batch verify router DNS sinkhole status (e.g. NextDNS / AdGuard 0.0.0.0 & Keenetic static hosts)
    sinkhole_map = {}
    active_static_sinkholes = set()
    try:
        active_static_sinkholes = set(await keenetic_client.get_active_sinkholes())
    except Exception as e:
        logger.debug("Keenetic active sinkholes error: %s", e)

    if domains:
        try:
            sinkhole_map = await domain_analyzer.check_sinkholes_batch(domains)
        except Exception as e:
            logger.debug("Sinkhole batch check error: %s", e)

    enriched = []
    for q in queries:
        dom = q["domain"]
        clean_dom = dom.lower().strip().strip(".")
        q_ip = q.get("ip")
        resolved_sink = sinkhole_map.get(dom)

        db_blocked = bool(q.get("is_blocked"))
        db_provider = q.get("blocked_by_provider")
        db_reason = q.get("blocked_reason")
        db_filter = q.get("filter_list")
        db_tracker = q.get("tracker_category")

        is_static_sinkhole = clean_dom in active_static_sinkholes
        is_blocked = is_static_sinkhole or db_blocked or domain_analyzer.is_sinkhole_ip(q_ip) or domain_analyzer.is_sinkhole_ip(resolved_sink)

        devs = devices_by_domain.get(dom, [])
        if not devs and q.get("mac"):
            dev_rec = dev_map.get(q["mac"].upper())
            devs = [{
                "mac": q["mac"],
                "ip": q.get("ip"),
                "count": q.get("count", 1),
                "hostname": getattr(dev_rec, "hostname", None) if dev_rec else None,
                "custom_name": getattr(dev_rec, "custom_name", None) if dev_rec else None,
                "profile": getattr(dev_rec, "profile", None) if dev_rec else None,
                "vendor": getattr(dev_rec, "vendor", None) if dev_rec else None,
            }]

        if not is_blocked and devs:
            for d in devs:
                if domain_analyzer.is_sinkhole_ip(d.get("ip")):
                    is_blocked = True
                    break

        if is_static_sinkhole:
            blocked_reason = "Заблокирован на Keenetic (0.0.0.0)"
            effective_provider = "keenetic_sinkhole"
        elif db_provider and is_blocked:
            effective_provider = db_provider
            blocked_reason = db_reason or f"Заблокирован {db_provider} (0.0.0.0)"
        elif is_blocked:
            effective_provider = ""
            blocked_reason = "Заблокирован DNS-фильтром (0.0.0.0)"
        else:
            effective_provider = ""
            blocked_reason = ""

        effective_ip = "0.0.0.0" if (is_blocked and not q_ip) else q_ip

        analysis = domain_analyzer.analyze_domain(
            dom,
            ip=effective_ip,
            is_blocked=is_blocked,
            blocked_reason=blocked_reason,
            blocked_by_provider=effective_provider,
            filter_list=db_filter,
            tracker_category=db_tracker,
        )

        item = dict(q)
        item["ip"] = effective_ip
        item["is_blocked"] = is_blocked
        item["is_static_sinkhole"] = is_static_sinkhole
        item["blocked_reason"] = blocked_reason
        item["blocked_by_provider"] = effective_provider
        item["filter_list"] = db_filter
        item["tracker_category"] = db_tracker
        item["analysis"] = analysis
        item["devices"] = devs
        enriched.append(item)
    return enriched

@app.get("/api/dns/analyze")
async def analyze_dns_domain(domain: str):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter required")

    clean_dom = domain.lower().strip().strip(".")
    active_static_sinkholes = set()
    try:
        active_static_sinkholes = set(await keenetic_client.get_active_sinkholes())
    except Exception as e:
        logger.debug("Keenetic active sinkholes error: %s", e)

    is_static_sinkhole = clean_dom in active_static_sinkholes

    # Check sinkhole resolution on router
    sinkhole_ip = None
    try:
        sinkhole_ip = await domain_analyzer.check_domain_sinkhole_async(domain)
    except Exception as e:
        logger.debug("Sinkhole check error for %s: %s", domain, e)

    is_blocked = is_static_sinkhole or domain_analyzer.is_sinkhole_ip(sinkhole_ip)
    effective_ip = "0.0.0.0" if is_static_sinkhole else (sinkhole_ip if is_blocked else None)

    devices = await db.get_domain_devices(domain)
    if not is_blocked and devices:
        for d in devices:
            if domain_analyzer.is_sinkhole_ip(d.get("ip")):
                is_blocked = True
                if not effective_ip:
                    effective_ip = "0.0.0.0"
                break

    if is_static_sinkhole:
        blocked_reason = "Заблокирован на Keenetic (0.0.0.0)"
    elif is_blocked:
        blocked_reason = "Заблокирован DNS-фильтром (0.0.0.0)"
    else:
        blocked_reason = ""

    analysis = domain_analyzer.analyze_domain(
        domain,
        ip=effective_ip,
        is_blocked=is_blocked,
        blocked_reason=blocked_reason
    )
    return {
        "domain": domain,
        "is_blocked": is_blocked,
        "is_static_sinkhole": is_static_sinkhole,
        "blocked_reason": blocked_reason,
        "analysis": analysis,
        "devices": devices
    }

@app.post("/api/dns/custom-rule")
async def set_custom_domain_rule_api(req: CustomRuleRequest):
    await db.set_custom_domain_rule(
        domain=req.domain,
        category=req.category,
        description=req.description or "",
        risk_level=req.risk_level or "safe"
    )
    await domain_analyzer.load_custom_rules_and_signatures(database=db)
    return {"status": "ok", "domain": req.domain}

@app.post("/api/dns/update-signatures")
async def update_dns_signatures_api():
    res = await domain_analyzer.update_signatures_from_online(database=db)
    return res

@app.delete("/api/dns/queries/{domain:path}")
async def delete_single_dns_query(domain: str):
    success = await db.delete_dns_query(domain)
    await ws_manager.broadcast({"type": "dns_query_deleted", "domain": domain})
    return {"status": "ok", "domain": domain, "deleted": success}

@app.delete("/api/dns/queries")
async def clear_dns_queries_api(
    category: Optional[str] = None,
    req: Optional[ClearDnsRequest] = Body(default=None)
):
    # 1. If explicit list of domains provided
    if req and req.domains is not None:
        count = await db.clear_dns_queries(domains=req.domains)
        await ws_manager.broadcast({"type": "dns_queries_cleared", "count": count})
        return {"status": "ok", "deleted": count}

    # 2. If category filter provided
    if category and category != "all":
        all_entries = await db.get_all_dns_domains()
        matching_domains = []
        for entry in all_entries:
            dom = entry["domain"]
            analysis = domain_analyzer.analyze_domain(dom, ip=entry.get("ip"))
            cat = analysis.get("category", "unknown")
            risk = analysis.get("risk_level", "neutral")
            if category == "suspicious":
                if cat == "suspicious" or risk == "danger":
                    matching_domains.append(dom)
            elif cat == category:
                matching_domains.append(dom)

        count = await db.clear_dns_queries(domains=matching_domains)
        await ws_manager.broadcast({"type": "dns_queries_cleared", "category": category, "count": count})
        return {"status": "ok", "category": category, "deleted": count}

    # 3. Otherwise full wipe
    count = await db.clear_dns_queries(domains=None)
    await ws_manager.broadcast({"type": "dns_queries_cleared", "count": count})
    return {"status": "ok", "deleted": count}

# --- Smart DNS Sinkhole Management Endpoints (Keenetic Static 0.0.0.0) ---

class DnsSinkholeRequest(BaseModel):
    domain: str

class DnsSinkholeToggleRequest(BaseModel):
    domain: str
    block: bool
    save_config: bool = True

class DnsSinkholePresetRequest(BaseModel):
    preset: str  # "ads" | "tv_telemetry" | "tv_lg" | "tv_samsung" | "tv_android_google" | "tv_xiaomi" | "tv_apple"
    save_config: bool = True

class BlockSelectedSinkholeRequest(BaseModel):
    domains: List[str]

CURATED_DNS_PRESETS = {
    "ads": [
        {"domain": "an.yandex.ru", "vendor": "Яндекс Директ / РСЯ", "description": "Рекламные баннеры и контекстная сеть Яндекса"},
        {"domain": "adfox.ru", "vendor": "Яндекс AdFox", "description": "Система управления медийной рекламой"},
        {"domain": "doubleclick.net", "vendor": "Google DoubleClick", "description": "Глобальная баннерная рекламная сеть Google"},
        {"domain": "adservice.google.com", "vendor": "Google AdService", "description": "Сервис подбора и показа рекламы Google"},
        {"domain": "googleads.g.doubleclick.net", "vendor": "Google Ads", "description": "Серверы доставки рекламы Google"},
        {"domain": "pagead2.googlesyndication.com", "vendor": "Google AdSense", "description": "Контекстные рекламные блоки сайтов"},
        {"domain": "ad.mail.ru", "vendor": "VK / Mail.ru", "description": "Рекламная платформа VK и Mail.ru"},
        {"domain": "criteo.com", "vendor": "Criteo", "description": "Ретаргетинг и отслеживание кликов"},
        {"domain": "applovin.com", "vendor": "AppLovin", "description": "Реклама в мобильных играх и приложениях"},
        {"domain": "unityads.unity3d.com", "vendor": "Unity Ads", "description": "Внутриигровая видеореклама Unity"},
        {"domain": "samsungadhub.com", "vendor": "Samsung AdHub", "description": "Реклама на Smart TV Samsung"}
    ],
    "tv_telemetry": [
        {"domain": "samsungacr.com", "vendor": "Samsung Smart TV", "description": "Распознавание просматриваемого контента (ACR)"},
        {"domain": "samsungcloudsolution.com", "vendor": "Samsung Smart TV", "description": "Служба сбора телеметрии и логов Samsung TV"},
        {"domain": "samsungqbe.com", "vendor": "Samsung Smart TV", "description": "Сбор диагностических логов телевизора"},
        {"domain": "ngfts.lge.com", "vendor": "LG Smart TV", "description": "Телеметрия и краш-репорты LG webOS"},
        {"domain": "lgsmartad.com", "vendor": "LG Smart TV", "description": "Рекламный идентификатор и трекинг LG TV"},
        {"domain": "data.mistat.xiaomi.com", "vendor": "Xiaomi TV / Box", "description": "Сбор статистики использования Xiaomi / Mi Box"},
        {"domain": "tracking.miui.com", "vendor": "Xiaomi MIUI / PatchWall", "description": "Телеметрия оболочки PatchWall и ТВ Xiaomi"},
        {"domain": "pinpu.online", "vendor": "Smart TV Webhook", "description": "Фоновые маяки телеметрии смарт-устройств"},
        {"domain": "mobicont.ru", "vendor": "Mobicont Beacon", "description": "Фоновая телеметрия китайских смарт-ТВ и приставок"}
    ]
}

@app.get("/api/dns/sinkholes")
async def get_dns_sinkholes_api():
    """Returns list of active 0.0.0.0 sinkholes configured on Keenetic router."""
    sinkholes = await keenetic_client.get_active_sinkholes()
    enriched = []
    for d in sinkholes:
        analysis = domain_analyzer.analyze_domain(d)
        enriched.append({
            "domain": d,
            "category": analysis.get("category", "unknown"),
            "category_name": analysis.get("category_name", "Не классифицирован"),
            "safety_label": analysis.get("safety_label", "Нейтрально"),
            "safety_color": analysis.get("safety_color", "slate"),
            "vendor": analysis.get("vendor", ""),
            "description": analysis.get("description", "")
        })
    return {"status": "ok", "sinkholes": sinkholes, "rules": enriched, "count": len(sinkholes)}

@app.get("/api/dns/sinkhole/preset_preview")
async def preview_dns_preset_api(preset: str):
    preset_key = preset.lower().strip()
    if preset_key not in ("ads", "tv_telemetry"):
        raise HTTPException(status_code=400, detail="Поддерживаемые пресеты: 'ads', 'tv_telemetry'")

    active_sinkholes = set(await keenetic_client.get_active_sinkholes())
    all_entries = await db.get_all_dns_domains()

    detected = []
    seen = set()
    for entry in all_entries:
        dom = entry["domain"]
        clean_d = dom.lower().strip().strip(".")
        if clean_d in seen:
            continue
        analysis = domain_analyzer.analyze_domain(dom, ip=entry.get("ip"))
        safety = analysis.get("block_safety", "neutral")
        category = analysis.get("category", "unknown")

        matched = False
        if preset_key == "ads":
            if safety == "safe" or category == "advertising":
                matched = True
        elif preset_key == "tv_telemetry":
            if safety == "telemetry_safe" or (category in ("telemetry", "advertising") and any(x in clean_d for x in ("lg", "samsung", "tv", "acr", "qbe", "hicloud", "xiaomi", "miui", "mobicont", "pinpu"))):
                matched = True

        if matched:
            seen.add(clean_d)
            dev_rows = await db.get_domain_devices(dom)
            device_names = [d.get("custom_name") or d.get("hostname") or d.get("vendor") or d.get("ip") for d in dev_rows[:3]]
            detected.append({
                "domain": clean_d,
                "category": category,
                "safety_label": analysis.get("safety_label", "Безопасно"),
                "safety_color": analysis.get("safety_color", "emerald"),
                "impact_explanation": analysis.get("impact_explanation", ""),
                "vendor": analysis.get("vendor", ""),
                "count": entry.get("count", 1),
                "devices": device_names,
                "is_active": clean_d in active_sinkholes
            })

    curated = []
    for cur in CURATED_DNS_PRESETS.get(preset_key, []):
        d_clean = cur["domain"].lower().strip()
        curated.append({
            "domain": d_clean,
            "vendor": cur["vendor"],
            "description": cur["description"],
            "is_active": d_clean in active_sinkholes
        })

    return {
        "status": "ok",
        "preset": preset_key,
        "title": "Блокировка рекламы" if preset_key == "ads" else "Отключение телеметрии Smart TV",
        "detected": detected,
        "detected_count": len(detected),
        "curated": curated,
        "active_sinkholes_count": len(active_sinkholes)
    }

@app.post("/api/dns/sinkhole/block_selected")
async def block_selected_domains_api(req: BlockSelectedSinkholeRequest):
    domains = [d.lower().strip().strip(".") for d in req.domains if d and "." in d]
    blocked, failed = await keenetic_client.add_dns_sinkholes(domains)
    await ws_manager.broadcast({"type": "dns_sinkhole_updated", "action": "bulk_blocked", "count": len(blocked)})
    return {
        "status": "ok" if not failed else ("partial" if blocked else "error"),
        "blocked": blocked,
        "blocked_count": len(blocked),
        "failed": failed,
        "failed_count": len(failed),
        "message": f"Успешно создано {len(blocked)} правил перехвата (0.0.0.0) на Keenetic"
    }

@app.post("/api/dns/sinkhole/unblock_selected")
async def unblock_selected_domains_api(req: BlockSelectedSinkholeRequest):
    domains = [d.lower().strip().strip(".") for d in req.domains if d and "." in d]
    unblocked, failed = await keenetic_client.remove_dns_sinkholes(domains)
    await ws_manager.broadcast({"type": "dns_sinkhole_updated", "action": "bulk_unblocked", "count": len(unblocked)})
    return {
        "status": "ok" if not failed else ("partial" if unblocked else "error"),
        "unblocked": unblocked,
        "unblocked_count": len(unblocked),
        "failed": failed,
        "failed_count": len(failed),
        "message": f"Успешно удалено {len(unblocked)} правил перехвата с Keenetic"
    }

@app.post("/api/dns/sinkhole/block")
async def block_dns_sinkhole_api(req: DnsSinkholeRequest):
    """Adds a static 0.0.0.0 sinkhole rule on Keenetic for a domain."""
    domain = (req.domain or "").strip().lower().strip(".")
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")
    success = await keenetic_client.add_dns_sinkhole(domain)
    if success:
        await ws_manager.broadcast({"type": "dns_sinkhole_updated", "domain": domain, "action": "blocked"})
        return {"status": "ok", "domain": domain, "action": "blocked", "message": f"Домен {domain} успешно заблокирован на Keenetic (0.0.0.0)"}
    raise HTTPException(status_code=500, detail=f"Не удалось заблокировать домен {domain} на роутере")

@app.post("/api/dns/sinkhole/unblock")
async def unblock_dns_sinkhole_api(req: DnsSinkholeRequest):
    """Removes a static 0.0.0.0 sinkhole rule from Keenetic."""
    domain = (req.domain or "").strip().lower().strip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")
    success = await keenetic_client.remove_dns_sinkhole(domain)
    if success:
        await ws_manager.broadcast({"type": "dns_sinkhole_updated", "domain": domain, "action": "unblocked"})
        return {"status": "ok", "domain": domain, "action": "unblocked", "message": f"Домен {domain} разблокирован на Keenetic"}
    raise HTTPException(status_code=500, detail=f"Не удалось разблокировать домен {domain} на роутере")

@app.post("/api/dns/sinkhole/block_preset")
async def block_dns_preset_api(req: DnsSinkholePresetRequest):
    """Applies a 1-click curated sinkhole preset (ads or tv_telemetry)."""
    preset = req.preset.lower().strip()
    if preset in TV_BRAND_PRESETS:
        target_domains = [item["domain"] for item in TV_BRAND_PRESETS[preset]["domains"]]
        blocked, failed = await keenetic_client.add_dns_sinkholes(target_domains)
        await ws_manager.broadcast({"type": "dns_preset_applied", "preset": preset, "count": len(blocked)})
        return {
            "status": "ok" if not failed else ("partial" if blocked else "error"),
            "preset": preset,
            "blocked_count": len(blocked),
            "failed_count": len(failed),
            "domains": blocked,
            "message": f"Пресет '{TV_BRAND_PRESETS[preset]['name']}' применен: заблокировано {len(blocked)} доменов на Keenetic"
        }

    if preset not in ("ads", "tv_telemetry"):
        valid_options = ["ads", "tv_telemetry"] + list(TV_BRAND_PRESETS.keys())
        raise HTTPException(status_code=400, detail=f"Поддерживаемые пресеты: {', '.join(valid_options)}")

    all_entries = await db.get_all_dns_domains()
    candidates = set()
    for entry in all_entries:
        dom = entry["domain"]
        clean_d = dom.lower().strip().strip(".")
        analysis = domain_analyzer.analyze_domain(dom, ip=entry.get("ip"))
        safety = analysis.get("block_safety", "neutral")
        category = analysis.get("category", "unknown")

        if preset == "ads":
            if safety == "safe" or category == "advertising":
                candidates.add(clean_d)
        elif preset == "tv_telemetry":
            if safety == "telemetry_safe" or category in ("telemetry", "advertising"):
                if any(x in clean_d for x in ("lg", "samsung", "tv", "acr", "qbe", "hicloud", "xiaomi", "miui")):
                    candidates.add(clean_d)

    blocked, failed = await keenetic_client.add_dns_sinkholes(list(candidates))

    await ws_manager.broadcast({"type": "dns_preset_applied", "preset": preset, "count": len(blocked)})
    return {
        "status": "ok" if not failed else ("partial" if blocked else "error"),
        "preset": preset,
        "blocked_count": len(blocked),
        "failed_count": len(failed),
        "domains": blocked,
        "message": f"Пресет '{preset}' применен: заблокировано {len(blocked)} доменов на Keenetic"
    }

@app.post("/api/dns/sinkhole/unblock_all")
async def unblock_all_dns_sinkholes_api():
    """Removes all static sinkhole domains configured by KeenGuard from Keenetic."""
    active = await keenetic_client.get_active_sinkholes()
    unblocked, failed = await keenetic_client.remove_dns_sinkholes(active)
    await ws_manager.broadcast({"type": "dns_all_unblocked", "count": len(unblocked)})
    return {
        "status": "ok",
        "unblocked_count": len(unblocked),
        "failed_count": len(failed),
        "domains": unblocked,
        "message": f"Разблокировано {len(unblocked)} доменов на Keenetic"
    }


# --- External DNS Security Providers Endpoints (NextDNS, Control D, AdGuard Home, Pi-hole) ---

class DnsProviderConfigUpdate(BaseModel):
    provider: Optional[str] = None
    dns_security_provider: Optional[str] = None
    sync_interval: Optional[int] = None
    dns_security_sync_interval: Optional[int] = None
    auto_sync: Optional[bool] = None
    dns_security_auto_sync: Optional[bool] = None
    nextdns_api_key: Optional[str] = None
    nextdns_profile_id: Optional[str] = None
    controld_api_key: Optional[str] = None
    controld_device_id: Optional[str] = None
    adguard_url: Optional[str] = None
    adguard_username: Optional[str] = None
    adguard_password: Optional[str] = None
    pihole_url: Optional[str] = None
    pihole_api_token: Optional[str] = None
    pihole_password: Optional[str] = None

class DnsProviderTestRequest(BaseModel):
    provider: str
    config_override: Optional[Dict[str, Any]] = None

def _mask_secret(val: Optional[str]) -> str:
    if not val:
        return ""
    if len(val) <= 4:
        return "••••"
    return "••••••••"

@app.get("/api/dns/provider/config")
async def get_dns_provider_config_api():
    """Returns the current DNS security provider configuration with masked credentials."""
    return {
        "provider": getattr(settings, "dns_security_provider", "none") or "none",
        "dns_security_provider": getattr(settings, "dns_security_provider", "none") or "none",
        "sync_interval": getattr(settings, "dns_security_sync_interval", 60),
        "dns_security_sync_interval": getattr(settings, "dns_security_sync_interval", 60),
        "auto_sync": getattr(settings, "dns_security_auto_sync", False),
        "dns_security_auto_sync": getattr(settings, "dns_security_auto_sync", False),
        "nextdns_api_key": _mask_secret(getattr(settings, "nextdns_api_key", "")),
        "nextdns_profile_id": getattr(settings, "nextdns_profile_id", "") or "",
        "nextdns_api_key_set": bool(getattr(settings, "nextdns_api_key", "")),
        "controld_api_key": _mask_secret(getattr(settings, "controld_api_key", "")),
        "controld_device_id": getattr(settings, "controld_device_id", "") or "",
        "controld_api_key_set": bool(getattr(settings, "controld_api_key", "")),
        "adguard_url": getattr(settings, "adguard_url", "") or "",
        "adguard_username": getattr(settings, "adguard_username", "") or "",
        "adguard_password": _mask_secret(getattr(settings, "adguard_password", "")),
        "adguard_password_set": bool(getattr(settings, "adguard_password", "")),
        "pihole_url": getattr(settings, "pihole_url", "") or "",
        "pihole_api_token": _mask_secret(getattr(settings, "pihole_api_token", "")),
        "pihole_api_token_set": bool(getattr(settings, "pihole_api_token", "")),
        "pihole_password": _mask_secret(getattr(settings, "pihole_password", "")),
        "pihole_password_set": bool(getattr(settings, "pihole_password", "")),
    }

@app.post("/api/dns/provider/config")
async def save_dns_provider_config_api(req: DnsProviderConfigUpdate):
    """Saves DNS security provider configuration to settings, .env and SQLite."""
    valid_providers = {"none", "nextdns", "controld", "adguard_home", "pihole"}
    raw_prov = req.provider or req.dns_security_provider or settings.dns_security_provider
    prov = (raw_prov or "none").strip().lower()
    if prov not in valid_providers:
        raise HTTPException(status_code=400, detail=f"Недопустимый провайдер: {raw_prov}. Допустимые: {', '.join(valid_providers)}")

    settings.dns_security_provider = prov
    sync_interval = req.sync_interval if req.sync_interval is not None else req.dns_security_sync_interval
    if sync_interval is not None:
        settings.dns_security_sync_interval = max(int(sync_interval), 15)
    auto_sync = req.auto_sync if req.auto_sync is not None else req.dns_security_auto_sync
    if auto_sync is not None:
        settings.dns_security_auto_sync = bool(auto_sync)

    def _is_new_secret(val: Optional[str]) -> bool:
        return val is not None and val.strip() != "" and not val.strip().startswith("••")

    if _is_new_secret(req.nextdns_api_key):
        settings.nextdns_api_key = req.nextdns_api_key.strip()
    if req.nextdns_profile_id is not None:
        settings.nextdns_profile_id = req.nextdns_profile_id.strip()

    if _is_new_secret(req.controld_api_key):
        settings.controld_api_key = req.controld_api_key.strip()
    if req.controld_device_id is not None:
        settings.controld_device_id = req.controld_device_id.strip()

    if req.adguard_url is not None:
        settings.adguard_url = req.adguard_url.strip().rstrip("/")
    if req.adguard_username is not None:
        settings.adguard_username = req.adguard_username.strip()
    if _is_new_secret(req.adguard_password):
        settings.adguard_password = req.adguard_password.strip()

    if req.pihole_url is not None:
        settings.pihole_url = req.pihole_url.strip().rstrip("/")
    if _is_new_secret(req.pihole_api_token):
        settings.pihole_api_token = req.pihole_api_token.strip()
    if _is_new_secret(req.pihole_password):
        settings.pihole_password = req.pihole_password.strip()

    # Save to SQLite app_settings
    await db.save_setting("dns_security_provider", settings.dns_security_provider)
    await db.save_setting("dns_security_sync_interval", str(settings.dns_security_sync_interval))
    await db.save_setting("dns_security_auto_sync", "true" if settings.dns_security_auto_sync else "false")
    await db.save_setting("nextdns_api_key", settings.nextdns_api_key)
    await db.save_setting("nextdns_profile_id", settings.nextdns_profile_id)
    await db.save_setting("controld_api_key", settings.controld_api_key)
    await db.save_setting("controld_device_id", settings.controld_device_id)
    await db.save_setting("adguard_url", settings.adguard_url)
    await db.save_setting("adguard_username", settings.adguard_username)
    await db.save_setting("adguard_password", settings.adguard_password)
    await db.save_setting("pihole_url", settings.pihole_url)
    await db.save_setting("pihole_api_token", settings.pihole_api_token)
    await db.save_setting("pihole_password", settings.pihole_password)

    # Persist to .env
    save_env_dns_provider_settings(
        provider=settings.dns_security_provider,
        sync_interval=settings.dns_security_sync_interval,
        auto_sync=settings.dns_security_auto_sync,
        nextdns_api_key=settings.nextdns_api_key,
        nextdns_profile_id=settings.nextdns_profile_id,
        controld_api_key=settings.controld_api_key,
        controld_device_id=settings.controld_device_id,
        adguard_url=settings.adguard_url,
        adguard_username=settings.adguard_username,
        adguard_password=settings.adguard_password,
        pihole_url=settings.pihole_url,
        pihole_api_token=settings.pihole_api_token,
        pihole_password=settings.pihole_password,
    )

    # Reload manager and restart background worker if necessary
    dns_security_manager.reload_from_config()
    if settings.dns_security_auto_sync and settings.dns_security_provider != "none":
        dns_security_manager.start_background_sync(settings.dns_security_sync_interval)
    else:
        dns_security_manager.stop_background_sync()

    await ws_manager.broadcast({
        "type": "dns_provider_config_saved",
        "provider": settings.dns_security_provider,
        "auto_sync": settings.dns_security_auto_sync,
    })

    return {
        "status": "ok",
        "provider": settings.dns_security_provider,
        "message": f"Настройки провайдера '{settings.dns_security_provider}' сохранены"
    }

@app.post("/api/dns/provider/test")
async def test_dns_provider_api(req: DnsProviderTestRequest):
    """Tests connection to a specified DNS security provider."""
    cfg = dict(req.config_override or {})
    if cfg.get("nextdns_api_key", "").startswith("••"):
        cfg["nextdns_api_key"] = settings.nextdns_api_key
    if cfg.get("controld_api_key", "").startswith("••"):
        cfg["controld_api_key"] = settings.controld_api_key
    if cfg.get("adguard_password", "").startswith("••"):
        cfg["adguard_password"] = settings.adguard_password
    if cfg.get("pihole_api_token", "").startswith("••"):
        cfg["pihole_api_token"] = settings.pihole_api_token

    status = await dns_security_manager.test_provider(req.provider, config_override=cfg if cfg else None)
    return {
        "ok": status.is_connected,
        "is_connected": status.is_connected,
        "provider_name": status.provider_name,
        "profile_or_version": status.profile_or_version,
        "active_filters_count": status.active_filters_count,
        "error_message": status.error_message,
        "message": f"Подключено к {status.provider_name}: {status.profile_or_version}" if status.is_connected else (status.error_message or "Ошибка связи"),
        "error": status.error_message if not status.is_connected else None,
    }

@app.post("/api/dns/provider/sync")
async def sync_dns_provider_now_api():
    """Triggers an immediate synchronization of blocked queries from the active provider."""
    res = await dns_security_manager.sync_blocked_logs()
    return {
        "ok": res.get("success", False),
        "synced": res.get("count", 0),
        **res
    }

@app.get("/api/dns/provider/status")
async def get_dns_provider_status_api():
    """Returns active DNS security provider state, last sync metadata, and connection info."""
    active_prov = dns_security_manager.active_provider_id
    meta = await db.get_dns_provider_sync_meta(active_prov) if active_prov != "none" else None
    provider_obj = dns_security_manager.get_active_provider()

    return {
        "provider": active_prov,
        "active_provider": active_prov,
        "display_name": provider_obj.display_name if provider_obj else "Отключено",
        "is_cloud": provider_obj.is_cloud if provider_obj else False,
        "auto_sync": getattr(settings, "dns_security_auto_sync", False),
        "sync_interval": getattr(settings, "dns_security_sync_interval", 60),
        "last_sync": meta.get("last_sync_time") if meta else None,
        "last_sync_time": meta.get("last_sync_time") if meta else None,
        "total_blocked_queries_synced": meta.get("total_blocked_synced", 0) if meta else 0,
        "total_blocked_synced": meta.get("total_blocked_synced", 0) if meta else 0,
        "status": meta.get("last_status") if meta else "idle",
        "last_status": meta.get("last_status") if meta else "idle",
        "last_error": meta.get("last_error") if meta else None,
    }

@app.get("/api/dns/provider/helpers")
async def get_dns_provider_helpers_api():
    """
    Returns actionable network assistance and remediation guides for the user
    addressing DoH/DoT hardcoded bypass, in-stream video ads, and device attribution.
    """
    return {
        "doh_dot_bypass": {
            "title": "Защита от DoH/DoT обхода на Smart TV и смартфонах",
            "problem": "Некоторые устройства (китайские ТВ-приставки, телевизоры, Chromecast) имеют жестко прошитые DNS-серверы (8.8.8.8) или напрямую отправляют шифрованный DoH/DoT трафик в обход DNS роутера.",
            "solutions": [
                {
                    "step": 1,
                    "title": "Перенаправление стандартного DNS (порт 53)",
                    "description": "В веб-интерфейсе Keenetic перейдите в «Сетевые правила» → «Переадресация портов» и создайте правило перенаправления входящих пакетов UDP/TCP 53 на локальный DNS-прокси роутера.",
                    "cli_cmd": "ip static tcp 53 192.168.1.1 53 !WAN\nip static udp 53 192.168.1.1 53 !WAN"
                },
                {
                    "step": 2,
                    "title": "Аппаратная блокировка DoT (порт 853 TCP)",
                    "description": "Устройства не смогут использовать шифрованный DNS-over-TLS и принудительно переключатся на стандартный фильтруемый DNS роутера.",
                    "cli_cmd": "ip firewall rule deny tcp * * 853"
                },
                {
                    "step": 3,
                    "title": "Включение NextDNS / Control D в профиле Keenetic",
                    "description": "Настройте DoH-профиль в меню «Сетевые правила» → «Интернет-фильтр» KeeneticOS, чтобы все исходящие запросы шли в ваш профиль с шифрованием."
                }
            ]
        },
        "streaming_ads": {
            "title": "Ограничения DNS: реклама внутри видео (YouTube / RuTube)",
            "problem": "Встроенная реклама в видеороликах раздается с тех же самых CDN-серверов, что и сам видеопоток (например, *.googlevideo.com).",
            "technical_realism": "Блокировка таких доменов по DNS физически невозможна без полной остановки воспроизведения видео.",
            "recommended_tools": [
                {
                    "platform": "Android TV / Google TV / Приставки",
                    "tool": "SmartTube (бесплатный open-source клиент с вырезкой рекламы и SponsorBlock)",
                    "link": "https://smarttubeapp.github.io/"
                },
                {
                    "platform": "Браузеры (Chrome, Firefox, Safari)",
                    "tool": "uBlock Origin (блокировка на уровне DOM и HTTP-запросов страницы)",
                    "link": "https://ublockorigin.com/"
                }
            ]
        },
        "device_attribution": {
            "title": "Идентификация устройств в облачных сервисах (NextDNS / Control D)",
            "problem": "Облачные провайдеры по умолчанию видят только ваш внешний WAN IP-адрес провайдера и объединяют все устройства дома в один поток.",
            "solutions": [
                {
                    "provider": "NextDNS",
                    "instruction": "В DoH-ссылке профиля Keenetic укажите имя роутера или используйте CLI NextDNS: https://dns.nextdns.io/{profile_id}/{deviceName}. Имя устройства автоматически сопоставится с базой KeenGuard."
                },
                {
                    "provider": "Control D",
                    "instruction": "Создайте отдельные устройства (Devices) в панели Control D и используйте уникальный Resolver ID для каждой политики или группы."
                },
                {
                    "provider": "AdGuard Home / Pi-hole",
                    "instruction": "При установке в локальной сети (LAN) идентификация происходит автоматически по реальному внутреннему IP-адресу клиента."
                }
            ]
        }
    }


# --- Smart TV Brand Presets Endpoints (0.0.0.0 DNS Sinkhole on Keenetic) ---

@app.get("/api/tv/brand_presets")
async def get_tv_brand_presets_api():
    """
    Returns curated Smart TV brand presets (LG, Samsung, Android/Google TV, Xiaomi, Apple TV)
    enriched with active router sinkhole statuses, detected TV devices in LAN, and ACR hints.
    """
    try:
        active_sinkholes = set(await keenetic_client.get_active_sinkholes())
    except Exception as e:
        logger.debug("Error reading active sinkholes: %s", e)
        active_sinkholes = set()

    presets = get_tv_brand_presets(active_sinkholes=active_sinkholes)

    # Detect TVs present in network
    all_devices = await db.get_all_devices()
    detected_devices_by_brand = {p["id"]: [] for p in presets}
    suggested_brand = None

    for dev in all_devices:
        brand_id = detect_tv_brand(dev)
        if brand_id and brand_id in detected_devices_by_brand:
            detected_devices_by_brand[brand_id].append({
                "mac": dev.get("mac"),
                "ip": dev.get("ip"),
                "hostname": dev.get("hostname"),
                "custom_name": dev.get("custom_name"),
                "vendor": dev.get("vendor"),
                "profile": dev.get("profile"),
                "is_online": dev.get("is_online", False)
            })
            if not suggested_brand and dev.get("profile") == "smart_tv":
                suggested_brand = brand_id

    # If no smart_tv profile matched suggested_brand, pick the first brand with detected device
    if not suggested_brand:
        for p in presets:
            if detected_devices_by_brand[p["id"]]:
                suggested_brand = p["id"]
                break

    for p in presets:
        p["detected_devices"] = detected_devices_by_brand[p["id"]]

    return {
        "status": "ok",
        "presets": presets,
        "suggested_brand": suggested_brand or "tv_lg",
        "active_sinkholes_count": len(active_sinkholes),
        "streaming_ads_note": (
            "Потоковая видеореклама (YouTube, RuTube, Кинопоиск, Иви) раздается с тех же видео-серверов CDN, "
            "что и сам контент фильма. Блокировка по DNS не может удалить её без нарушения воспроизведения видео. "
            "Для Smart TV на Android используйте приложение SmartTube; для браузеров ПК — uBlock Origin."
        )
    }


@app.post("/api/tv/sinkhole/block_preset")
async def block_tv_preset_api(req: DnsSinkholePresetRequest):
    """Batch blocks all domains of a specific Smart TV brand preset on Keenetic (0.0.0.0)."""
    preset_id = req.preset.lower().strip()
    if preset_id not in TV_BRAND_PRESETS:
        raise HTTPException(status_code=400, detail=f"Неизвестный пресет ТВ: {req.preset}")

    target_domains = [item["domain"] for item in TV_BRAND_PRESETS[preset_id]["domains"]]
    blocked, failed = await keenetic_client.add_dns_sinkholes(target_domains)

    await ws_manager.broadcast({
        "type": "dns_sinkhole_updated",
        "preset": preset_id,
        "action": "preset_blocked",
        "blocked_count": len(blocked),
        "failed_count": len(failed)
    })
    return {
        "status": "ok" if not failed else ("partial" if blocked else "error"),
        "preset": preset_id,
        "blocked": blocked,
        "failed": failed,
        "count": len(blocked),
        "message": f"Пресет '{TV_BRAND_PRESETS[preset_id]['name']}' применен: заблокировано {len(blocked)} доменов (0.0.0.0)"
    }


@app.post("/api/tv/sinkhole/unblock_preset")
async def unblock_tv_preset_api(req: DnsSinkholePresetRequest):
    """Batch unblocks all domains of a specific Smart TV brand preset on Keenetic."""
    preset_id = req.preset.lower().strip()
    if preset_id not in TV_BRAND_PRESETS:
        raise HTTPException(status_code=400, detail=f"Неизвестный пресет ТВ: {req.preset}")

    target_domains = [item["domain"] for item in TV_BRAND_PRESETS[preset_id]["domains"]]
    unblocked, failed = await keenetic_client.remove_dns_sinkholes(target_domains)

    await ws_manager.broadcast({
        "type": "dns_sinkhole_updated",
        "preset": preset_id,
        "action": "preset_unblocked",
        "unblocked_count": len(unblocked),
        "failed_count": len(failed)
    })
    return {
        "status": "ok" if not failed else ("partial" if unblocked else "error"),
        "preset": preset_id,
        "unblocked": unblocked,
        "failed": failed,
        "count": len(unblocked),
        "message": f"Пресет '{TV_BRAND_PRESETS[preset_id]['name']}' разблокирован: удалено {len(unblocked)} правил"
    }


@app.post("/api/tv/sinkhole/toggle")
async def toggle_tv_sinkhole_domain_api(req: DnsSinkholeToggleRequest):
    """Toggles a single domain 0.0.0.0 sinkhole rule on Keenetic."""
    clean_d = req.domain.lower().strip().strip(".")
    if not clean_d or "." not in clean_d:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")

    if req.block:
        success = await keenetic_client.add_dns_sinkhole(clean_d)
        action = "blocked"
    else:
        success = await keenetic_client.remove_dns_sinkhole(clean_d)
        action = "unblocked"

    if success:
        await ws_manager.broadcast({
            "type": "dns_sinkhole_updated",
            "domain": clean_d,
            "action": action
        })
        return {
            "status": "ok",
            "domain": clean_d,
            "action": action,
            "is_active": req.block,
            "message": f"Домен {clean_d} {'заблокирован (0.0.0.0)' if req.block else 'разблокирован'} на Keenetic"
        }
    else:
        raise HTTPException(status_code=500, detail=f"Не удалось изменить правило для {clean_d} на роутере")


# --- Traffic Monitoring & Charts Endpoints ---
@app.get("/api/devices/{mac}/traffic")
async def get_device_traffic(mac: str, limit: int = 60):
    history = await db.get_device_traffic_history(mac.upper(), limit=limit)
    return history

@app.get("/api/traffic/live")
async def get_live_traffic():
    summary = await db.get_network_traffic_summary(limit=30)
    return summary

# --- Wi-Fi Security Audit Endpoint ---
@app.get("/api/security/wifi")
async def get_wifi_audit():
    audit = await keenetic_client.get_wifi_security()
    return audit

# --- Firmware & Router Updates Endpoint ---
@app.get("/api/router/updates")
async def get_router_updates():
    updates = await keenetic_client.check_firmware_updates()
    return updates

# --- Security Digest Endpoints ---
@app.get("/api/security/digest")
async def get_security_digest(hours: int = 24):
    digest = await digest_generator.generate_digest(hours=hours)
    return digest

@app.post("/api/security/digest/send")
async def send_security_digest(hours: int = 24):
    res = await digest_generator.send_digest_to_telegram(hours=hours, force=True)
    return res

# --- Data Export Endpoints (CSV / JSON) ---
@app.get("/api/export/devices")
async def export_devices(format: str = "csv"):
    devices = await db.get_all_devices()
    if format == "json":
        return [d.model_dump() for d in devices]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["MAC", "IP", "Hostname", "Vendor", "Profile", "Online", "Blocked WAN", "Isolated LAN", "AirPlay", "DLNA", "First Seen", "Last Seen"])
    for d in devices:
        writer.writerow([d.mac, d.ip, d.custom_name or d.hostname, d.vendor, d.profile, d.is_online, d.is_blocked_wan, d.is_isolated_lan, d.airplay_allowed, d.dlna_allowed, d.first_seen, d.last_seen])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=devices.csv"})

@app.get("/api/export/events")
async def export_events(format: str = "csv", limit: int = 500):
    events = await db.get_recent_events(limit=limit)
    if format == "json":
        return [e.model_dump() for e in events]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Type", "Severity", "Target MAC", "Target IP", "Source", "Description"])
    for e in events:
        writer.writerow([e.id, e.timestamp, e.event_type, e.severity, e.target_mac, e.target_ip, e.source_name or e.source_ip, e.description])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=security_events.csv"})

@app.get("/api/export/audits")
async def export_audits():
    reports = await db.get_audit_reports(limit=50)
    return [r.model_dump() for r in reports]

# ==========================================
# LAN Communications & Ping Tracker Endpoints
# ==========================================

async def _get_devices_dict() -> Dict[str, Any]:
    devs = await db.get_all_devices()
    return {d.mac.upper(): d.model_dump() for d in devs}

@app.get("/api/lan/communications")
async def get_lan_communications(comm_type: Optional[str] = None, ip: Optional[str] = None, limit: int = 100):
    """Returns recent inter-device communications, ping requests/replies, and ARP activity."""
    devs_map = await _get_devices_dict()
    recent = lan_tracker.get_recent_communications(comm_type=comm_type, ip=ip, limit=limit, devices_map=devs_map)
    return {"status": "ok", "communications": recent}

@app.get("/api/lan/ping_matrix")
async def get_lan_ping_matrix():
    """Returns aggregated ping monitoring pairs: who pings whom, RTT latencies, success rate."""
    devs_map = await _get_devices_dict()
    matrix = lan_tracker.get_ping_matrix(devices_map=devs_map)
    return {"status": "ok", "ping_matrix": matrix}

@app.get("/api/lan/topology")
async def get_lan_topology():
    """Returns nodes and edges for the LAN communication graph."""
    devs_map = await _get_devices_dict()
    topo = lan_tracker.get_topology(devices_map=devs_map)
    return {"status": "ok", **topo}

@app.get("/api/lan/stats")
async def get_lan_stats():
    """Returns summary statistics of LAN communications."""
    stats = lan_tracker.get_stats()
    return {"status": "ok", "stats": stats}

@app.post("/api/lan/clear")
async def clear_lan_communications():
    """Clears all in-memory and database LAN events."""
    lan_tracker.clear()
    await db.clear_lan_communications()
    return {"status": "ok", "message": "Журнал локальных коммуникаций очищен"}

# ==========================================
# IoT Payload Logs & Storage Management
# ==========================================

@app.get("/api/iot/payloads")
async def get_iot_payloads(mac: Optional[str] = None, protocol: Optional[str] = None,
                           search: Optional[str] = None, limit: int = 100, offset: int = 0):
    """Returns decoded payload events collected from IoT devices."""
    payloads = await db.get_iot_payloads(mac=mac, protocol=protocol, search=search, limit=limit, offset=offset)
    storage = await db.get_iot_storage_stats()
    return {"status": "ok", "payloads": payloads, "storage": storage}

@app.get("/api/devices/{mac}/payloads")
async def get_device_payloads(mac: str, limit: int = 100):
    """Returns captured payload data specifically for a given device MAC."""
    payloads = await db.get_iot_payloads(mac=mac, limit=limit)
    storage = await db.get_iot_storage_stats()
    return {"status": "ok", "mac": mac.upper(), "payloads": payloads, "storage": storage}

@app.post("/api/iot/payloads/clear")
async def clear_iot_payloads(body: Dict[str, Any] = Body(default={})):
    """Clears IoT payload records for a specific device or all."""
    mac = body.get("mac")
    deleted = await db.clear_iot_payloads(mac=mac)
    return {"status": "ok", "deleted": deleted}

@app.post("/api/iot/payloads/prune")
async def prune_iot_payloads(body: Dict[str, Any] = Body(default={})):
    """Manually triggers pruning of IoT payload logs based on retention days and max GB."""
    max_gb = body.get("max_storage_gb", body.get("max_gb"))
    days = body.get("retention_days")
    res = await db.prune_iot_payloads(max_gb=max_gb, retention_days=days)
    return {"status": "ok", "pruned_count": res.get("pruned_count", res.get("total_deleted", 0)), **res}

@app.get("/api/settings/iot_storage")
async def get_iot_storage_settings():
    """Returns current IoT payload storage configuration and disk usage."""
    stats = await db.get_iot_storage_stats()
    cfg = {
        "capture_enabled": settings.iot_payload_capture_enabled,
        "max_storage_gb": settings.iot_payload_max_storage_gb,
        "retention_days": settings.iot_payload_retention_days
    }
    return {"status": "ok", "config": cfg, "storage_stats": stats, **stats}

@app.post("/api/settings/iot_storage")
async def save_iot_storage_settings(body: Dict[str, Any] = Body(...)):
    """Updates storage limits (GB), retention days, and capture status."""
    if "max_storage_gb" in body and body["max_storage_gb"] is not None:
        try:
            val_gb = max(0.1, min(100.0, float(body["max_storage_gb"])))
            settings.iot_payload_max_storage_gb = val_gb
            await db.save_setting("iot_payload_max_storage_gb", str(settings.iot_payload_max_storage_gb))
        except (ValueError, TypeError):
            pass
    if "retention_days" in body and body["retention_days"] is not None:
        try:
            val_days = max(1, min(365, int(body["retention_days"])))
            settings.iot_payload_retention_days = val_days
            await db.save_setting("iot_payload_retention_days", str(settings.iot_payload_retention_days))
        except (ValueError, TypeError):
            pass
    if "capture_enabled" in body and body["capture_enabled"] is not None:
        settings.iot_payload_capture_enabled = bool(body["capture_enabled"])
        await db.save_setting("iot_payload_capture_enabled", "true" if settings.iot_payload_capture_enabled else "false")

    create_tracked_task(db.prune_iot_payloads())
    stats = await db.get_iot_storage_stats()
    cfg = {
        "capture_enabled": settings.iot_payload_capture_enabled,
        "max_storage_gb": settings.iot_payload_max_storage_gb,
        "retention_days": settings.iot_payload_retention_days
    }
    return {"status": "ok", "config": cfg, "storage_stats": stats, "message": "Настройки хранилища сохранены", **stats}

# ==========================================
# Deep Packet Inspector Endpoints
# ==========================================

@app.get("/api/devices/{mac}/packets")
async def get_device_packets(mac: str, limit: int = 50, protocol: Optional[str] = None):
    """Returns recently captured raw/dissected packets for a specific device."""
    clean_mac = mac.upper()
    ring = sniffer.ring_buffers.get(clean_mac)
    if not ring:
        return {"status": "ok", "mac": clean_mac, "total_buffered": 0, "packets": []}

    items = ring.get_packets_with_meta()
    packets_out = []
    for ts, pkt, pid in reversed(items):
        dissected = PacketDissector.dissect(pkt, pkt_id=pid)
        if protocol and protocol.lower() != "all":
            if dissected.get("protocol", "").lower() != protocol.lower():
                continue
        dissected.pop("layers", None)
        dissected.pop("hex_dump", None)
        packets_out.append(dissected)
        if len(packets_out) >= limit:
            break

    return {
        "status": "ok",
        "mac": clean_mac,
        "total_buffered": len(ring),
        "packets": packets_out
    }

class LoadPcapRequest(BaseModel):
    filename: str

@app.get("/api/packets/live")
async def get_live_packets(limit: int = 100, protocol: Optional[str] = None):
    """Returns recently captured live packets across the entire network, or packets from active PCAP dump."""
    is_pcap = bool(sniffer.active_pcap_name)
    target_buffer = sniffer.pcap_buffer if is_pcap else sniffer.global_buffer

    items = target_buffer.get_packets_with_meta()
    packets_out = []
    iterable = items if is_pcap else reversed(items)
    for ts, pkt, pid in iterable:
        dissected = PacketDissector.dissect(pkt, pkt_id=pid)
        if protocol and protocol.lower() != "all":
            if dissected.get("protocol", "").lower() != protocol.lower():
                continue
        dissected.pop("layers", None)
        dissected.pop("hex_dump", None)
        packets_out.append(dissected)
        if len(packets_out) >= limit:
            break

    return {
        "status": "ok",
        "is_pcap": is_pcap,
        "pcap_filename": sniffer.active_pcap_name,
        "total_buffered": len(target_buffer),
        "packets": packets_out
    }

@app.get("/api/packets/pcap/saved")
async def get_saved_pcaps():
    """Returns a list of all saved PCAP files in data/pcaps/ with metadata."""
    pcap_dir = settings.pcap_dir
    if not pcap_dir.exists():
        return {"status": "ok", "pcaps": []}

    pcaps = []
    for f in pcap_dir.glob("*.pcap*"):
        try:
            stat = f.stat()
            if f.name.startswith("audit_"):
                category = "Аудит устройства"
            elif f.name.startswith("tv_wake_"):
                category = "ТВ-форензика"
            elif f.name.startswith("upload_"):
                category = "Загруженный дамп"
            else:
                category = "Дамп инцидента"
            pcaps.append({
                "filename": f.name,
                "size_bytes": stat.st_size,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "modified_human": datetime.fromtimestamp(stat.st_mtime).strftime("%d.%m.%Y %H:%M:%S"),
                "category": category
            })
        except Exception:
            pass

    pcaps.sort(key=lambda x: x["modified_at"], reverse=True)
    return {"status": "ok", "pcaps": pcaps, "files": pcaps}

@app.post("/api/packets/pcap/load_saved")
async def load_saved_pcap(req: LoadPcapRequest):
    """Loads an existing PCAP file from data/pcaps/ into the Packet Inspector."""
    safe_name = Path(req.filename).name
    file_path = settings.pcap_dir / safe_name
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="PCAP файл не найден")

    try:
        from scapy.all import rdpcap
        pkts = rdpcap(str(file_path))
    except Exception as e:
        logger.error("Failed to parse PCAP file %s: %s", safe_name, e)
        raise HTTPException(status_code=400, detail=f"Ошибка чтения PCAP файла: {e}")

    sniffer.load_pcap_packets(pkts, source_name=safe_name)
    return {
        "status": "ok",
        "filename": safe_name,
        "total_packets": len(pkts),
        "loaded_packets": len(pkts),
        "message": f"Загружено {len(pkts)} пакетов из {safe_name}"
    }

@app.post("/api/packets/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads an external PCAP/PCAPNG file and loads it directly into the Packet Inspector."""
    if not file.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(status_code=400, detail="Поддерживаются только файлы дампов .pcap, .pcapng или .cap")

    contents = await file.read()
    if len(contents) > 25 * 1024 * 1024:  # 25MB limit
        raise HTTPException(status_code=400, detail="Размер PCAP-файла превышает лимит 25 МБ")

    safe_name = f"upload_{int(time.time())}_{Path(file.filename).name}"
    dest = settings.pcap_dir / safe_name
    try:
        dest.write_bytes(contents)
        from scapy.all import rdpcap
        pkts = rdpcap(str(dest))
    except Exception as e:
        logger.error("Failed to parse uploaded PCAP: %s", e)
        raise HTTPException(status_code=400, detail=f"Не удалось разобрать PCAP файл: {e}")

    sniffer.load_pcap_packets(pkts, source_name=file.filename)
    return {
        "status": "ok",
        "filename": file.filename,
        "saved_as": safe_name,
        "total_packets": len(pkts),
        "message": f"Успешно загружен PCAP файл {file.filename} ({len(pkts)} пакетов)"
    }

@app.post("/api/packets/pcap/clear")
async def clear_active_pcap():
    """Clears the PCAP buffer and returns the inspector to live stream mode."""
    sniffer.clear_pcap()
    return {"status": "ok", "message": "Просмотр PCAP завершен. Возврат к живому мониторингу сети."}

@app.get("/api/packets/pcap/status")
async def get_pcap_status():
    """Returns current PCAP inspection status."""
    return {
        "status": "ok",
        "is_pcap": bool(sniffer.active_pcap_name),
        "pcap_filename": sniffer.active_pcap_name,
        "total_buffered": len(sniffer.pcap_buffer) if sniffer.active_pcap_name else 0
    }

@app.get("/api/packets/inspect/{packet_id}")
async def inspect_packet(packet_id: str):
    """Deeply inspects a packet returning OSI layers, byte offsets, and interactive 16-byte hex dump."""
    pkt = sniffer.get_packet_by_id(packet_id)
    if pkt is None:
        raise HTTPException(status_code=404, detail="Пакет не найден в кольцевом буфере или был вытеснен")

    dissected = PacketDissector.dissect(pkt, pkt_id=packet_id)
    return {"status": "ok", "dissection": dissected, **dissected}

# ==========================================
# Incident Investigation Wizard Endpoints
# ==========================================

from keenguard.core.investigator import investigator

class AnalyzeIncidentRequest(BaseModel):
    audit_id: Optional[str] = None
    event_id: Optional[int] = None
    mac: Optional[str] = None
    target_ip: Optional[str] = None
    target_domain: Optional[str] = None
    target_os: Optional[str] = None

class InvestigatorBlockRequest(BaseModel):
    domain: Optional[str] = None
    ip: Optional[str] = None

class IpBlackholeRequest(BaseModel):
    ip: str
    reason: Optional[str] = ""
    force_cdn: Optional[bool] = False

class IpBlackholeUnblockRequest(BaseModel):
    ip: str

@app.get("/api/investigator/incidents")
async def get_investigator_incidents():
    """Returns recent candidate audits, events, and devices ready for interactive investigation."""
    incidents = []
    devices = []

    async with db.get_connection() as db_conn:
        try:
            # 1. Recent audits
            cursor = await db_conn.execute("SELECT id, mac, ip, hostname, created_at, duration_seconds, total_bytes, risk_level, summary FROM audit_reports ORDER BY rowid DESC LIMIT 20")
            for r in await cursor.fetchall():
                incidents.append({
                    "type": "audit",
                    "id": r[0],
                    "mac": r[1],
                    "ip": r[2],
                    "hostname": r[3] or "Unknown Device",
                    "created_at": r[4],
                    "risk_level": r[7],
                    "title": f"Аудит: {r[3] or r[1]} (Риск: {r[7]})",
                    "subtitle": r[8] or f"{r[5]} сек, {r[6]} байт",
                })
        except Exception as e:
            logger.debug("Error fetching investigator audits: %s", e)

        try:
            # 2. Recent warning/critical events
            cursor = await db_conn.execute("SELECT id, timestamp, event_type, severity, target_mac, target_ip, description FROM events WHERE severity IN ('warning', 'critical') ORDER BY id DESC LIMIT 20")
            for r in await cursor.fetchall():
                incidents.append({
                    "type": "event",
                    "id": str(r[0]),
                    "event_id": r[0],
                    "mac": r[4],
                    "ip": r[5],
                    "hostname": r[4] or "Network Event",
                    "created_at": r[1],
                    "risk_level": r[3],
                    "title": f"Инцидент [{r[2]}]: {r[6]}",
                    "subtitle": f"Хост: {r[5] or r[4]}",
                })
        except Exception as e:
            logger.debug("Error fetching investigator events: %s", e)

        try:
            # 3. Active devices for manual ad-hoc investigation
            cursor = await db_conn.execute("SELECT mac, ip, hostname, vendor, profile, is_online FROM devices ORDER BY is_online DESC, last_seen DESC LIMIT 30")
            for r in await cursor.fetchall():
                devices.append({
                    "mac": r[0],
                    "ip": r[1],
                    "hostname": r[2] or "Unknown Device",
                    "vendor": r[3],
                    "profile": r[4],
                    "is_online": bool(r[5])
                })
        except Exception as e:
            logger.debug("Error fetching investigator devices: %s", e)

    return {"status": "ok", "incidents": incidents, "devices": devices}

@app.post("/api/investigator/analyze")
async def analyze_incident(req: AnalyzeIncidentRequest):
    """Deeply analyzes an incident, extracts flows, correlates DNS, generates playbooks."""
    flows = []
    target_mac = req.mac
    target_ip = req.target_ip
    target_host = None

    async with db.get_connection() as db_conn:
        if req.audit_id:
            cursor = await db_conn.execute("SELECT mac, ip, hostname, report_json FROM audit_reports WHERE id = ?", (req.audit_id,))
            row = await cursor.fetchone()
            if row:
                target_mac = row[0]
                target_ip = row[1]
                target_host = row[2]
                try:
                    rep_data = json.loads(row[3])
                    flows = rep_data.get("flows", [])
                except Exception as e:
                    logger.debug("Error parsing audit flows: %s", e)

        elif req.event_id:
            cursor = await db_conn.execute("SELECT target_mac, target_ip, details_json FROM events WHERE id = ?", (req.event_id,))
            row = await cursor.fetchone()
            if row:
                target_mac = row[0] or target_mac
                target_ip = row[1] or target_ip
                try:
                    edata = json.loads(row[2])
                    flows = edata.get("flows", [])
                except Exception as e:
                    logger.debug("Error parsing event flows: %s", e)

        if target_mac:
            cursor = await db_conn.execute("SELECT ip, hostname FROM devices WHERE mac = ?", (target_mac.upper(),))
            drow = await cursor.fetchone()
            if drow:
                target_ip = target_ip or drow[0]
                target_host = target_host or drow[1]

            if not flows:
                cursor = await db_conn.execute(
                    "SELECT report_json FROM audit_reports WHERE mac = ? ORDER BY created_at DESC LIMIT 1",
                    (target_mac.upper(),)
                )
                arow = await cursor.fetchone()
                if arow:
                    try:
                        arep = json.loads(arow[0])
                        flows = arep.get("flows", [])
                    except Exception as e:
                        logger.debug("Error parsing recent audit flows for %s: %s", target_mac, e)

        if not flows and (req.target_ip or req.target_domain):
            flows.append({
                "dst_ip": req.target_ip or "0.0.0.0",
                "dst_port": 80,
                "protocol": "TCP",
                "is_lan": False,
                "is_encrypted": False,
                "provider": "Целевой узел",
                "bytes_up": 0,
                "bytes_down": 0,
                "risk": "warning"
            })

        result = await investigator.analyze_incident(
            target_mac=target_mac,
            target_ip=target_ip,
            target_host=target_host,
            flows=flows,
            db_conn=db_conn,
            audit_id=req.audit_id,
            event_id=req.event_id
        )

    if req.target_os:
        target_ip_focus = flows[0]["dst_ip"] if flows else (req.target_ip or "")
        target_port_focus = flows[0]["dst_port"] if flows else 80
        proto_focus = flows[0].get("protocol", "TCP") if flows else "TCP"
        result["playbook"] = investigator.get_os_diagnostic_playbook(req.target_os, target_ip_focus, target_port_focus, proto_focus)
        result["target"]["os_type"] = req.target_os

    return {"status": "ok", "investigation": result}

FORBIDDEN_SINKHOLE_DOMAINS = {
    "localhost",
    "my.keenetic.net",
    "keenetic.net",
    "router",
    "router.lan",
    "gateway",
}

def is_ip_address_string(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False

def is_forbidden_or_local_domain(domain: str) -> bool:
    d = domain.lower().strip().strip(".")
    if d in FORBIDDEN_SINKHOLE_DOMAINS:
        return True
    if d.endswith((".keenetic.link", ".keenetic.pro", ".local", ".lan", ".home")):
        return True
    return False

@app.post("/api/investigator/block")
async def block_investigator_target(req: InvestigatorBlockRequest):
    """Enforces hardware DNS sinkhole (0.0.0.0) block on Keenetic router."""
    raw_target = (req.domain or req.ip or "").strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="Необходимо указать доменное имя для блокировки")

    clean_target = raw_target.lower().strip(".")

    if is_ip_address_string(clean_target):
        raise HTTPException(
            status_code=400,
            detail="DNS Sinkhole предназначен для блокировки доменных имен (FQDN), а не прямых IP-адресов. "
                   "Для ограничения доступа к IP используйте профиль изоляции устройства или правила межсетевого экрана Keenetic."
        )

    if is_forbidden_or_local_domain(clean_target):
        raise HTTPException(
            status_code=400,
            detail="Запрещено блокировать локальные или системные домены управления роутером Keenetic."
        )

    if "." not in clean_target or len(clean_target) < 3:
        raise HTTPException(
            status_code=400,
            detail="Укажите корректное доменное имя (например, bad-tracker.com)."
        )

    success = await keenetic_client.add_dns_sinkhole(clean_target)
    return {
        "status": "ok" if success else "failed",
        "target": clean_target,
        "message": f"Домен {clean_target} успешно направлен в аппаратный 0.0.0.0 Sinkhole на Keenetic" if success else f"Ошибка добавления правила для {clean_target} на Keenetic"
    }

SHARED_CDN_KEYWORDS = [
    "Cloudflare", "Akamai", "Amazon", "AWS", "Google Cloud", "Fastly", "Microsoft", "Azure"
]

def check_ip_cdn_status(ip_str: str) -> tuple[bool, str, Dict[str, str]]:
    geo = identify_geoip(ip_str)
    provider = geo.get("provider", "")
    for kw in SHARED_CDN_KEYWORDS:
        if kw.lower() in provider.lower():
            return True, provider, geo
    return False, provider, geo

@app.get("/api/firewall/ip_blackholes")
async def get_ip_blackholes_list():
    """Returns active IP blackholes stored in database and running on Keenetic router."""
    rules = await db.get_ip_blackholes(active_only=True)
    router_active = await keenetic_client.get_active_ip_blackholes()

    router_set = set(router_active)
    for r in rules:
        r["hardware_active"] = r["ip"] in router_set

    db_ips = {r["ip"] for r in rules}
    extra_router_rules = []
    for rip in router_active:
        if rip not in db_ips:
            geo = identify_geoip(rip)
            is_cdn, provider, _ = check_ip_cdn_status(rip)
            extra_router_rules.append({
                "ip": rip,
                "mask": "255.255.255.255",
                "created_at": None,
                "reason": "Задано вручную на роутере",
                "provider": provider,
                "country": geo.get("country", "WAN"),
                "flag": geo.get("flag", "🌐"),
                "is_cdn": 1 if is_cdn else 0,
                "status": "active",
                "hardware_active": True
            })

    all_rules = rules + extra_router_rules
    return {
        "status": "ok",
        "rules": all_rules,
        "total_count": len(all_rules),
        "router_active_count": len(router_active)
    }

@app.post("/api/firewall/ip_blackhole/check")
async def check_ip_blackhole_preflight(req: IpBlackholeRequest):
    """Performs safety and CDN check before blocking an IP."""
    clean_ip = req.ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Некорректный IP-адрес: {clean_ip}")

    if ip_obj.version != 4:
        raise HTTPException(status_code=400, detail="Поддерживаются только IPv4 адреса для аппаратной маршрутизации")

    if is_unsafe_ip_for_blackhole(ip_obj):
        raise HTTPException(
            status_code=400,
            detail=f"Запрещено блокировать локальные или служебные адреса ({clean_ip}). Блокировка шлюза или LAN нарушит работу сети!"
        )

    is_cdn, provider, geo = check_ip_cdn_status(clean_ip)
    warning = None
    if is_cdn:
        warning = (
            f"Внимание: IP {clean_ip} принадлежит облачному провайдеру/CDN ({provider}). "
            f"На этом адресе могут одновременно работать сотни других легитимных сайтов и сервисов. "
            f"Блокировка по IP может вызвать сопутствующий ущерб (collateral damage). "
            f"Рекомендуется использовать DNS Sinkhole для точечной блокировки домена."
        )

    return {
        "status": "ok",
        "ip": clean_ip,
        "is_cdn": is_cdn,
        "provider": provider,
        "country": geo.get("country", "WAN"),
        "flag": geo.get("flag", "🌐"),
        "warning": warning
    }

@app.post("/api/firewall/ip_blackhole/block")
async def add_ip_blackhole_endpoint(req: IpBlackholeRequest):
    """Enforces hardware reject route on Keenetic router and records in SQLite."""
    clean_ip = req.ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Некорректный IP-адрес: {clean_ip}")

    if ip_obj.version != 4:
        raise HTTPException(status_code=400, detail="Поддерживаются только IPv4 адреса")

    if is_unsafe_ip_for_blackhole(ip_obj):
        raise HTTPException(
            status_code=400,
            detail=f"Запрещено блокировать локальные или служебные адреса ({clean_ip})"
        )

    is_cdn, provider, geo = check_ip_cdn_status(clean_ip)
    if is_cdn and not req.force_cdn:
        raise HTTPException(
            status_code=409,
            detail=f"IP {clean_ip} принадлежит CDN ({provider}). Блокировка может нарушить работу других сервисов. Подтвердите принудительную блокировку."
        )

    succeeded, failed = await keenetic_client.add_ip_blackholes([clean_ip])
    if clean_ip not in succeeded:
        raise HTTPException(status_code=500, detail=f"Роутер Keenetic отклонил добавление маршрута reject для {clean_ip}")

    reason_text = req.reason.strip() if req.reason else "Ручная блокировка узла"
    await db.add_ip_blackhole_record(
        ip=clean_ip,
        reason=reason_text,
        provider=provider,
        country=geo.get("country", "WAN"),
        flag=geo.get("flag", "🌐"),
        is_cdn=is_cdn
    )

    return {
        "status": "ok",
        "ip": clean_ip,
        "provider": provider,
        "is_cdn": is_cdn,
        "message": f"IP-адрес {clean_ip} успешно заблокирован на Keenetic (маршрут reject в ядре роутера)"
    }

@app.post("/api/firewall/ip_blackhole/unblock")
async def remove_ip_blackhole_endpoint(req: IpBlackholeUnblockRequest):
    """Removes hardware reject route from Keenetic router and SQLite."""
    clean_ip = req.ip.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="Необходимо указать IP для разблокировки")

    succeeded, _ = await keenetic_client.remove_ip_blackholes([clean_ip])
    await db.delete_ip_blackhole_record(clean_ip)

    return {
        "status": "ok",
        "ip": clean_ip,
        "message": f"Маршрут блокировки для {clean_ip} удален с роутера Keenetic"
    }

@app.post("/api/investigator/block_ip")
async def block_investigator_ip_endpoint(req: IpBlackholeRequest):
    """Enforces hardware IP blackhole directly from Incident Investigation Wizard."""
    clean_ip = req.ip.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Некорректный IP-адрес: {clean_ip}")

    if is_unsafe_ip_for_blackhole(ip_obj):
        raise HTTPException(status_code=400, detail="Запрещено блокировать локальные или служебные адреса")

    is_cdn, provider, geo = check_ip_cdn_status(clean_ip)
    if is_cdn and not req.force_cdn:
        return {
            "status": "cdn_warning",
            "ip": clean_ip,
            "provider": provider,
            "message": f"IP-адрес {clean_ip} принадлежит публичному CDN ({provider}). Блокировка может затронуть другие сервисы. Вы уверены, что хотите заблокировать весь IP?"
        }

    succeeded, failed = await keenetic_client.add_ip_blackholes([clean_ip])
    if clean_ip in succeeded:
        await db.add_ip_blackhole_record(
            ip=clean_ip,
            reason=req.reason or "Заблокировано из Мастера расследований",
            provider=provider,
            country=geo.get("country", "WAN"),
            flag=geo.get("flag", "🌐"),
            is_cdn=is_cdn
        )
        return {
            "status": "ok",
            "ip": clean_ip,
            "provider": provider,
            "message": f"IP-адрес {clean_ip} успешно заблокирован на Keenetic (L3 Blackhole Reject)"
        }
    else:
        raise HTTPException(status_code=500, detail=f"Ошибка роутера при блокировке {clean_ip}")


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                msg = json.loads(raw_data)
                cmd = msg.get("command") or msg.get("type")
                if cmd in ("ping", "heartbeat"):
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
                elif cmd == "get_status":
                    await websocket.send_json({
                        "type": "status_response",
                        "connected": router_health.is_connected,
                        "model": router_health.model,
                        "version": router_health.version,
                        "sniffer_active": sniffer.is_running,
                        "scheduler_active": scheduler.is_running,
                        "timestamp": time.time()
                    })
                elif cmd == "refresh":
                    create_tracked_task(do_keenetic_poll())
                    await websocket.send_json({"type": "refresh_ack", "status": "polling_started"})
                elif cmd == "start_audit":
                    mac = msg.get("mac")
                    duration = int(msg.get("duration", 60))
                    if mac:
                        create_tracked_task(audit_manager.start_audit(mac=mac, duration_seconds=duration))
                        await websocket.send_json({"type": "audit_started", "mac": mac, "duration": duration})
                    else:
                        await websocket.send_json({"type": "error", "message": "MAC address is required for start_audit"})
                elif cmd == "stop_audit":
                    mac = msg.get("mac")
                    if mac:
                        audit_manager.stop_audit(mac)
                        await websocket.send_json({"type": "audit_stopped", "mac": mac})
                    else:
                        await websocket.send_json({"type": "error", "message": "MAC address is required for stop_audit"})
                else:
                    await websocket.send_json({"type": "ack", "received": cmd})
            except json.JSONDecodeError:
                if raw_data.strip().lower() in ("ping", "health"):
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
                else:
                    await websocket.send_json({"type": "ack", "received": raw_data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
