"""DNS query tracking, domain reputation analysis, 0.0.0.0 sinkholes, and DNS security providers."""
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel

from keenguard.config import (
    settings,
    save_env_dns_provider_settings,
)
from keenguard.core.dns_providers import dns_security_manager
from keenguard.core.domain_analyzer import (
    domain_analyzer,
    TV_BRAND_PRESETS,
)
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
)
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.dns")

router = APIRouter(tags=["dns"])


class CustomRuleRequest(BaseModel):
    domain: str
    category: str
    description: Optional[str] = ""
    risk_level: Optional[str] = "safe"


class ClearDnsRequest(BaseModel):
    domains: Optional[List[str]] = None


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


@router.get("/api/dns/queries")
async def get_dns_queries(limit: int = 100):
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.get("/api/dns/analyze")
async def analyze_dns_domain(domain: str):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter required")

    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/dns/custom-rule")
async def set_custom_domain_rule_api(req: CustomRuleRequest):
    db = get_db()
    await db.set_custom_domain_rule(
        domain=req.domain,
        category=req.category,
        description=req.description or "",
        risk_level=req.risk_level or "safe"
    )
    await domain_analyzer.load_custom_rules_and_signatures(database=db)
    return {"status": "ok", "domain": req.domain}


@router.post("/api/dns/update-signatures")
async def update_dns_signatures_api():
    db = get_db()
    res = await domain_analyzer.update_signatures_from_online(database=db)
    return res


@router.delete("/api/dns/queries/{domain:path}")
async def delete_single_dns_query(domain: str):
    db = get_db()
    success = await db.delete_dns_query(domain)
    await ws_manager.broadcast({"type": "dns_query_deleted", "domain": domain})
    return {"status": "ok", "domain": domain, "deleted": success}


@router.delete("/api/dns/queries")
async def clear_dns_queries_api(
    category: Optional[str] = None,
    req: Optional[ClearDnsRequest] = Body(default=None)
):
    db = get_db()
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

@router.get("/api/dns/sinkholes")
async def get_dns_sinkholes_api():
    """Returns list of active 0.0.0.0 sinkholes configured on Keenetic router."""
    keenetic_client = get_keenetic_client()
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


@router.get("/api/dns/sinkhole/preset_preview")
async def preview_dns_preset_api(preset: str):
    preset_key = preset.lower().strip()
    if preset_key not in ("ads", "tv_telemetry"):
        raise HTTPException(status_code=400, detail="Поддерживаемые пресеты: 'ads', 'tv_telemetry'")

    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/dns/sinkhole/block_selected")
async def block_selected_domains_api(req: BlockSelectedSinkholeRequest):
    keenetic_client = get_keenetic_client()
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


@router.post("/api/dns/sinkhole/unblock_selected")
async def unblock_selected_domains_api(req: BlockSelectedSinkholeRequest):
    keenetic_client = get_keenetic_client()
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


@router.post("/api/dns/sinkhole/block")
async def block_dns_sinkhole_api(req: DnsSinkholeRequest):
    """Adds a static 0.0.0.0 sinkhole rule on Keenetic for a domain."""
    keenetic_client = get_keenetic_client()
    domain = (req.domain or "").strip().lower().strip(".")
    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")
    success = await keenetic_client.add_dns_sinkhole(domain)
    if success:
        await ws_manager.broadcast({"type": "dns_sinkhole_updated", "domain": domain, "action": "blocked"})
        return {"status": "ok", "domain": domain, "action": "blocked", "message": f"Домен {domain} успешно заблокирован на Keenetic (0.0.0.0)"}
    raise HTTPException(status_code=500, detail=f"Не удалось заблокировать домен {domain} на роутере")


@router.post("/api/dns/sinkhole/unblock")
async def unblock_dns_sinkhole_api(req: DnsSinkholeRequest):
    """Removes a static 0.0.0.0 sinkhole rule from Keenetic."""
    keenetic_client = get_keenetic_client()
    domain = (req.domain or "").strip().lower().strip(".")
    if not domain:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")
    success = await keenetic_client.remove_dns_sinkhole(domain)
    if success:
        await ws_manager.broadcast({"type": "dns_sinkhole_updated", "domain": domain, "action": "unblocked"})
        return {"status": "ok", "domain": domain, "action": "unblocked", "message": f"Домен {domain} разблокирован на Keenetic"}
    raise HTTPException(status_code=500, detail=f"Не удалось разблокировать домен {domain} на роутере")


@router.post("/api/dns/sinkhole/block_preset")
async def block_dns_preset_api(req: DnsSinkholePresetRequest):
    """Applies a 1-click curated sinkhole preset (ads or tv_telemetry)."""
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.post("/api/dns/sinkhole/unblock_all")
async def unblock_all_dns_sinkholes_api():
    """Removes all static sinkhole domains configured by KeenGuard from Keenetic."""
    keenetic_client = get_keenetic_client()
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


@router.get("/api/dns/provider/config")
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


@router.post("/api/dns/provider/config")
async def save_dns_provider_config_api(req: DnsProviderConfigUpdate):
    """Saves DNS security provider configuration to settings, .env and SQLite."""
    db = get_db()
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


@router.post("/api/dns/provider/test")
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


@router.post("/api/dns/provider/sync")
async def sync_dns_provider_now_api():
    """Triggers an immediate synchronization of blocked queries from the active provider."""
    res = await dns_security_manager.sync_blocked_logs()
    return {
        "ok": res.get("success", False),
        "synced": res.get("count", 0),
        **res
    }


@router.get("/api/dns/provider/status")
async def get_dns_provider_status_api():
    """Returns active DNS security provider state, last sync metadata, and connection info."""
    db = get_db()
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


@router.get("/api/dns/provider/helpers")
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
