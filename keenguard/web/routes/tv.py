"""Smart TV Brand Presets and 0.0.0.0 DNS Sinkhole routes."""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from keenguard.core.domain_analyzer import (
    TV_BRAND_PRESETS,
    detect_tv_brand,
    get_tv_brand_presets,
)
from keenguard.core.routers import router_manager
from keenguard.web.state import (
    get_db,
)
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.tv")

router = APIRouter(tags=["tv"])


class DnsSinkholePresetRequest(BaseModel):
    preset: str
    only_safe: Optional[bool] = False


class DnsSinkholeToggleRequest(BaseModel):
    domain: str
    block: bool


@router.get("/api/tv/brand_presets")
async def get_tv_brand_presets_api():
    """
    Returns curated Smart TV brand presets (LG, Samsung, Android/Google TV, Xiaomi, Apple TV)
    enriched with active router sinkhole statuses, detected TV devices in LAN, and ACR hints.
    """
    db = get_db()
    try:
        active_sinkholes = set(await router_manager.get_active_sinkholes())
    except Exception as e:
        logger.debug("Error reading active sinkholes: %s", e)
        active_sinkholes = set()

    presets = get_tv_brand_presets(active_sinkholes=active_sinkholes)

    # Detect TVs present in network
    all_devices = await db.get_all_devices()
    detected_devices_by_brand = {p["id"]: [] for p in presets}
    suggested_brand = None

    for dev in all_devices:
        dev_data = dev.model_dump() if hasattr(dev, "model_dump") else (dev.to_dict() if hasattr(dev, "to_dict") else dict(dev))
        brand_id = detect_tv_brand(dev_data)
        if brand_id and brand_id in detected_devices_by_brand:
            detected_devices_by_brand[brand_id].append({
                "mac": dev_data.get("mac"),
                "ip": dev_data.get("ip"),
                "hostname": dev_data.get("hostname"),
                "custom_name": dev_data.get("custom_name"),
                "vendor": dev_data.get("vendor"),
                "profile": dev_data.get("profile"),
                "is_online": dev_data.get("is_online", False)
            })
            if not suggested_brand and dev_data.get("profile") == "smart_tv":
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


@router.post("/api/tv/sinkhole/block_preset")
async def block_tv_preset_api(req: DnsSinkholePresetRequest):
    """Batch blocks all domains of a specific Smart TV brand preset on router (0.0.0.0)."""
    preset_id = req.preset.lower().strip()
    if preset_id not in TV_BRAND_PRESETS:
        raise HTTPException(status_code=400, detail=f"Неизвестный пресет ТВ: {req.preset}")

    if req.only_safe:
        target_domains = [
            item["domain"] for item in TV_BRAND_PRESETS[preset_id]["domains"]
            if item.get("safety", "safe") == "safe"
        ]
        msg_title = f"Безопасный фильтр '{TV_BRAND_PRESETS[preset_id]['name']}'"
    else:
        target_domains = [item["domain"] for item in TV_BRAND_PRESETS[preset_id]["domains"]]
        msg_title = f"Пресет '{TV_BRAND_PRESETS[preset_id]['name']}'"

    blocked, failed = await router_manager.add_dns_sinkholes(target_domains)

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
        "message": f"{msg_title} применен: заблокировано {len(blocked)} доменов (0.0.0.0)"
    }


@router.post("/api/tv/sinkhole/unblock_preset")
async def unblock_tv_preset_api(req: DnsSinkholePresetRequest):
    """Batch unblocks all domains of a specific Smart TV brand preset on router."""
    preset_id = req.preset.lower().strip()
    if preset_id not in TV_BRAND_PRESETS:
        raise HTTPException(status_code=400, detail=f"Неизвестный пресет ТВ: {req.preset}")

    target_domains = [item["domain"] for item in TV_BRAND_PRESETS[preset_id]["domains"]]
    unblocked, failed = await router_manager.remove_dns_sinkholes(target_domains)

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


@router.post("/api/tv/sinkhole/toggle")
async def toggle_tv_sinkhole_domain_api(req: DnsSinkholeToggleRequest):
    """Toggles a single domain 0.0.0.0 sinkhole rule on router."""
    clean_d = req.domain.lower().strip().strip(".")
    if not clean_d or "." not in clean_d:
        raise HTTPException(status_code=400, detail="Некорректное доменное имя")

    if req.block:
        success = await router_manager.add_dns_sinkhole(clean_d)
        action = "blocked"
    else:
        success = await router_manager.remove_dns_sinkhole(clean_d)
        action = "unblocked"

    platform_name = router_manager.get_backend().platform_name
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
            "message": f"Домен {clean_d} {'заблокирован (0.0.0.0)' if req.block else 'разблокирован'} на {platform_name}"
        }
    else:
        raise HTTPException(status_code=500, detail=f"Не удалось изменить правило для {clean_d} на роутере")
