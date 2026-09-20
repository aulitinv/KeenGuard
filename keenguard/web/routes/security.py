"""Security events, checklist, segments, UPnP, packet inspection, investigator, and firewall routes."""
from datetime import datetime, timezone
import ipaddress
import json
import logging
from pathlib import Path
import time
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Body, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel

from keenguard.config import settings
from keenguard.core.audit import identify_geoip
from keenguard.core.checklist import SecurityChecklistEvaluator
from keenguard.core.classifier import DeviceClassifier
from keenguard.core.digest import digest_generator
from keenguard.core.dissector import PacketDissector
from keenguard.core.dns_tracker import LOCAL_PREFIXES, dns_tracker
from keenguard.core.domain_analyzer import domain_analyzer
from keenguard.core.investigator import investigator
from keenguard.core.keenetic import is_host_lan_isolated, is_unsafe_ip_for_blackhole
from keenguard.core.lan_tracker import lan_tracker
from keenguard.core.profiles import profile_manager
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
    get_sniffer,
)
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.security")

router = APIRouter(tags=["security"])

# Shared CDN definitions and helper functions
SHARED_CDN_KEYWORDS = [
    "Cloudflare", "Akamai", "Amazon", "AWS", "Google Cloud", "Fastly", "Microsoft", "Azure"
]

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


def check_ip_cdn_status(ip_str: str) -> tuple[bool, str, Dict[str, str]]:
    geo = identify_geoip(ip_str)
    provider = geo.get("provider", "")
    for kw in SHARED_CDN_KEYWORDS:
        if kw.lower() in provider.lower():
            return True, provider, geo
    return False, provider, geo


# --- Pydantic Models ---

class DeleteUPnPRequest(BaseModel):
    protocol: str
    ext_port: int


class BulkSensorsWanRequest(BaseModel):
    block: bool
    mode: Optional[str] = "autonomous_only"


class BulkAppliancesLanRequest(BaseModel):
    isolate: bool


class ChecklistDeviceToggleRequest(BaseModel):
    mac: str
    target: str  # "wan" or "lan"
    enabled: bool


class QuarantineToggleRequest(BaseModel):
    enable: bool


class ModularQuarantineRequest(BaseModel):
    rule: str  # "wan", "lan", "auto_audit", "continuous_audit", "all"
    enabled: bool


class SecurityWizardApplyRequest(BaseModel):
    tv_night_mode: bool = True
    zero_internet_sensors: bool = True
    quarantine_enabled: bool = True
    quarantine_continuous: bool = True


class LoadPcapRequest(BaseModel):
    filename: str


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


# --- Events Endpoints ---

@router.get("/api/events")
async def get_events(limit: int = 50, event_type: Optional[str] = None, severity: Optional[str] = None):
    db = get_db()
    events = await db.get_recent_events(limit=limit, event_type=event_type, severity=severity)
    return [e.model_dump() for e in events]


@router.delete("/api/events/{event_id}")
async def delete_single_event(event_id: int):
    db = get_db()
    success = await db.delete_event(event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Event not found")
    await ws_manager.broadcast({"type": "event_deleted", "id": event_id})
    return {"status": "ok", "deleted": True, "id": event_id}


@router.delete("/api/events")
async def clear_events_api(severity: Optional[str] = None, older_than_days: Optional[int] = None):
    db = get_db()
    count = await db.clear_events(severity=severity, older_than_days=older_than_days)
    await ws_manager.broadcast({"type": "events_cleared", "severity": severity, "older_than_days": older_than_days, "count": count})
    return {"status": "ok", "deleted": count}


@router.get("/api/events/pcap/{filename}")
async def download_pcap(filename: str):
    file_path = settings.pcap_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="PCAP dump file not found")
    return FileResponse(path=str(file_path), filename=filename, media_type="application/vnd.tcpdump.pcap")


# --- Smart Home Overview ---

@router.get("/api/smarthome/overview")
async def get_smarthome_overview():
    db = get_db()
    keenetic_client = get_keenetic_client()
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

@router.get("/api/security/checklist")
async def get_security_checklist():
    """Returns the comprehensive, real-time security posture checklist."""
    return await SecurityChecklistEvaluator.evaluate_checklist()


@router.get("/api/security/segments")
async def get_security_segments():
    """Returns Keenetic hardware network segments and evaluates L2 bypass risks."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/security/checklist/apply-sensors-zero-internet")
async def apply_sensors_zero_internet(req: BulkSensorsWanRequest):
    """Enables or disables Zero-Internet selectively for devices with local LAN capability, preserving cloud & weather IoT."""
    db = get_db()
    devices = await db.get_all_devices()
    device_domains = await db.get_device_domains_map()
    updated = []
    for d in devices:
        trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=device_domains.get(d.mac, []))
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


@router.post("/api/security/checklist/apply-appliances-lan-isolation")
async def apply_appliances_lan_isolation(req: BulkAppliancesLanRequest):
    """Isolates or unisolates smart home appliances and IoT from LAN."""
    db = get_db()
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


@router.post("/api/security/checklist/device-toggle")
async def toggle_checklist_device(req: ChecklistDeviceToggleRequest):
    """Direct 1-click toggle of WAN or LAN for any device from the checklist card."""
    db = get_db()
    mac = req.mac.upper()
    if req.target == "wan":
        success = await profile_manager.toggle_wan(mac, block=req.enabled)
        is_active = req.enabled
    elif req.target == "lan":
        success = await profile_manager.toggle_lan_isolation(mac, isolate=req.enabled)
        dev = await db.get_device(mac)
        is_active = dev.is_isolated_lan if dev else False
    else:
        raise HTTPException(status_code=400, detail="Invalid target: must be 'wan' or 'lan'")
    await ws_manager.broadcast({"type": "refresh"})
    return {"status": "ok", "mac": mac, "target": req.target, "enabled": is_active, "success": success}


@router.post("/api/security/checklist/toggle-quarantine")
async def toggle_quarantine_policy(req: QuarantineToggleRequest):
    """Toggles new device quarantine policies."""
    settings.new_device_quarantine_wan = req.enable
    settings.new_device_isolate_lan = req.enable
    settings.new_device_continuous_audit = req.enable
    await ws_manager.broadcast({"type": "refresh"})
    return {"status": "ok", "quarantine_active": req.enable}


@router.post("/api/security/checklist/toggle-quarantine-rule")
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


@router.post("/api/security/wizard/apply")
async def apply_security_wizard(req: SecurityWizardApplyRequest):
    """Applies combined security hardening settings from the Interactive Security Wizard."""
    db = get_db()
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


# --- Wi-Fi Security Audit Endpoint ---

@router.get("/api/security/wifi")
async def get_wifi_audit():
    keenetic_client = get_keenetic_client()
    audit = await keenetic_client.get_wifi_security()
    return audit


# --- Firmware & Router Updates Endpoint ---

@router.get("/api/router/updates")
async def get_router_updates():
    keenetic_client = get_keenetic_client()
    updates = await keenetic_client.check_firmware_updates()
    return updates


# --- Security Digest Endpoints ---

@router.get("/api/security/digest")
async def get_security_digest(hours: int = 24):
    digest = await digest_generator.generate_digest(hours=hours)
    return digest


@router.post("/api/security/digest/send")
async def send_security_digest(hours: int = 24):
    res = await digest_generator.send_digest_to_telegram(hours=hours, force=True)
    return res


# --- UPnP Port Forwards ---

@router.get("/api/upnp")
async def get_upnp():
    keenetic_client = get_keenetic_client()
    mappings = await keenetic_client.get_upnp_mappings()
    return [m.model_dump() for m in mappings]


@router.post("/api/upnp/delete")
async def delete_upnp(req: DeleteUPnPRequest):
    keenetic_client = get_keenetic_client()
    success = await keenetic_client.delete_upnp_mapping(req.protocol, req.ext_port)
    return {"status": "ok", "success": success}


# --- LAN Communications & Ping Tracker Endpoints ---

async def _get_devices_dict() -> Dict[str, Any]:
    db = get_db()
    devs = await db.get_all_devices()
    return {d.mac.upper(): d.model_dump() for d in devs}


@router.get("/api/lan/communications")
async def get_lan_communications(comm_type: Optional[str] = None, ip: Optional[str] = None, limit: int = 100):
    """Returns recent inter-device communications, ping requests/replies, and ARP activity."""
    devs_map = await _get_devices_dict()
    recent = lan_tracker.get_recent_communications(comm_type=comm_type, ip=ip, limit=limit, devices_map=devs_map)
    return {"status": "ok", "communications": recent}


@router.get("/api/lan/ping_matrix")
async def get_lan_ping_matrix():
    """Returns aggregated ping monitoring pairs: who pings whom, RTT latencies, success rate."""
    devs_map = await _get_devices_dict()
    matrix = lan_tracker.get_ping_matrix(devices_map=devs_map)
    return {"status": "ok", "ping_matrix": matrix}


@router.get("/api/lan/topology")
async def get_lan_topology():
    """Returns nodes and edges for the LAN communication graph."""
    devs_map = await _get_devices_dict()
    topo = lan_tracker.get_topology(devices_map=devs_map)
    return {"status": "ok", **topo}


@router.get("/api/lan/stats")
async def get_lan_stats():
    """Returns summary statistics of LAN communications."""
    stats = lan_tracker.get_stats()
    return {"status": "ok", "stats": stats}


@router.post("/api/lan/clear")
async def clear_lan_communications():
    """Clears all in-memory and database LAN events."""
    db = get_db()
    lan_tracker.clear()
    await db.clear_lan_communications()
    return {"status": "ok", "message": "Журнал локальных коммуникаций очищен"}


# --- IoT Payload Logs & Storage Management ---

@router.get("/api/iot/payloads")
async def get_iot_payloads(
    mac: Optional[str] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Returns decoded payload events collected from IoT devices."""
    db = get_db()
    payloads = await db.get_iot_payloads(mac=mac, protocol=protocol, search=search, limit=limit, offset=offset)
    storage = await db.get_iot_storage_stats()
    return {"status": "ok", "payloads": payloads, "storage": storage}


@router.post("/api/iot/payloads/clear")
async def clear_iot_payloads(body: Dict[str, Any] = Body(default={})):
    """Clears IoT payload records for a specific device or all."""
    db = get_db()
    mac = body.get("mac")
    deleted = await db.clear_iot_payloads(mac=mac)
    return {"status": "ok", "deleted": deleted}


@router.post("/api/iot/payloads/prune")
async def prune_iot_payloads(body: Dict[str, Any] = Body(default={})):
    """Manually triggers pruning of IoT payload logs based on retention days and max GB."""
    db = get_db()
    max_gb = body.get("max_storage_gb", body.get("max_gb"))
    days = body.get("retention_days")
    res = await db.prune_iot_payloads(max_gb=max_gb, retention_days=days)
    return {"status": "ok", "pruned_count": res.get("pruned_count", res.get("total_deleted", 0)), **res}


# --- Deep Packet Inspector Endpoints ---

@router.get("/api/packets/live")
async def get_live_packets(limit: int = 100, protocol: Optional[str] = None):
    """Returns recently captured live packets across the entire network, or packets from active PCAP dump."""
    sniffer = get_sniffer()
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


@router.get("/api/packets/pcap/saved")
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
        except OSError as e:
            logger.debug("Failed to read PCAP metadata for %s: %s", f, e)

    pcaps.sort(key=lambda x: x["modified_at"], reverse=True)
    return {"status": "ok", "pcaps": pcaps, "files": pcaps}


@router.post("/api/packets/pcap/load_saved")
async def load_saved_pcap(req: LoadPcapRequest):
    """Loads an existing PCAP file from data/pcaps/ into the Packet Inspector."""
    sniffer = get_sniffer()
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


@router.post("/api/packets/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Uploads an external PCAP/PCAPNG file and loads it directly into the Packet Inspector."""
    sniffer = get_sniffer()
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


@router.post("/api/packets/pcap/clear")
async def clear_active_pcap():
    """Clears the PCAP buffer and returns the inspector to live stream mode."""
    sniffer = get_sniffer()
    sniffer.clear_pcap()
    return {"status": "ok", "message": "Просмотр PCAP завершен. Возврат к живому мониторингу сети."}


@router.get("/api/packets/pcap/status")
async def get_pcap_status():
    """Returns current PCAP inspection status."""
    sniffer = get_sniffer()
    return {
        "status": "ok",
        "is_pcap": bool(sniffer.active_pcap_name),
        "pcap_filename": sniffer.active_pcap_name,
        "total_buffered": len(sniffer.pcap_buffer) if sniffer.active_pcap_name else 0
    }


@router.get("/api/packets/inspect/{packet_id}")
async def inspect_packet(packet_id: str):
    """Deeply inspects a packet returning OSI layers, byte offsets, and interactive 16-byte hex dump."""
    sniffer = get_sniffer()
    pkt = sniffer.get_packet_by_id(packet_id)
    if pkt is None:
        raise HTTPException(status_code=404, detail="Пакет не найден в кольцевом буфере или был вытеснен")

    dissected = PacketDissector.dissect(pkt, pkt_id=packet_id)
    return {"status": "ok", "dissection": dissected, **dissected}


# --- Incident Investigation Wizard Endpoints ---

@router.get("/api/investigator/incidents")
async def get_investigator_incidents():
    """Returns recent candidate audits, events, and devices ready for interactive investigation."""
    db = get_db()
    incidents = []
    devices = []

    async with db.get_connection() as db_conn:
        try:
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


@router.post("/api/investigator/analyze")
async def analyze_incident(req: AnalyzeIncidentRequest):
    """Deeply analyzes an incident, extracts flows, correlates DNS, generates playbooks."""
    db = get_db()
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


@router.post("/api/investigator/block")
async def block_investigator_target(req: InvestigatorBlockRequest):
    """Enforces hardware DNS sinkhole (0.0.0.0) block on Keenetic router."""
    keenetic_client = get_keenetic_client()
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


# --- Firewall & IP Blackhole Endpoints ---

@router.get("/api/firewall/ip_blackholes")
async def get_ip_blackholes_list():
    """Returns active IP blackholes stored in database and running on Keenetic router."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/firewall/ip_blackhole/check")
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


@router.post("/api/firewall/ip_blackhole/block")
async def add_ip_blackhole_endpoint(req: IpBlackholeRequest):
    """Enforces hardware reject route on Keenetic router and records in SQLite."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/firewall/ip_blackhole/unblock")
async def remove_ip_blackhole_endpoint(req: IpBlackholeUnblockRequest):
    """Removes hardware reject route from Keenetic router and SQLite."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/investigator/block_ip")
async def block_investigator_ip_endpoint(req: IpBlackholeRequest):
    """Enforces hardware IP blackhole directly from Incident Investigation Wizard."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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
