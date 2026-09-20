"""Device management, policies, presets, wizard, and per-device traffic routes."""
from datetime import datetime, timezone
import logging
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from keenguard.core.classifier import DeviceClassifier
from keenguard.core.dissector import PacketDissector
from keenguard.core.keenetic import is_host_lan_isolated
from keenguard.core.profiles import policy_manager, profile_manager
from keenguard.db.models import LanPolicyPreset
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
    get_audit_manager,
    get_sniffer,
)
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.devices")

router = APIRouter(tags=["devices"])


def _validate_mac(mac: str) -> str:
    """Validates IEEE 802 MAC format and normalizes to uppercase, raising 400 on invalid input."""
    if not DeviceClassifier.is_valid_mac(mac):
        raise HTTPException(status_code=400, detail=f"Invalid MAC address format: {mac}")
    return mac.upper()


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


class ToggleRequest(BaseModel):
    enabled: bool


class RenameRequest(BaseModel):
    custom_name: str


class PresetCreateUpdateRequest(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = ""
    rules: Dict[str, Any]


class DeviceLanPolicyRequest(BaseModel):
    preset_id: Optional[str] = None
    designated_nvr_ip: Optional[str] = None
    auto_quarantine_override: Optional[str] = None
    custom_allowed_ports: Optional[List[int]] = None
    tv_pre_record_seconds: Optional[int] = None
    tv_post_record_seconds: Optional[int] = None
    tv_day_mode: Optional[str] = None


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


@router.get("/api/devices")
async def get_devices():
    db = get_db()
    keenetic_client = get_keenetic_client()
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


@router.get("/api/devices/{mac}")
async def get_device(mac: str):
    db = get_db()
    keenetic_client = get_keenetic_client()
    clean_mac = _validate_mac(mac)
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


@router.delete("/api/devices/{mac}")
async def delete_single_device(mac: str):
    db = get_db()
    clean_mac = _validate_mac(mac)
    success = await db.delete_device(clean_mac)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    await ws_manager.broadcast({"type": "device_deleted", "mac": clean_mac})
    return {"status": "ok", "mac": clean_mac}


@router.delete("/api/devices-offline")
async def delete_all_offline_devices():
    db = get_db()
    deleted_count = await db.delete_offline_devices()
    await ws_manager.broadcast({"type": "devices_pruned", "deleted_count": deleted_count})
    return {"status": "ok", "deleted_count": deleted_count}


@router.post("/api/devices/{mac}/policy")
async def set_device_policy_api(mac: str, req: DevicePolicyUpdateRequest):
    clean_mac = _validate_mac(mac)
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


@router.post("/api/devices/{mac}/profile")
async def set_profile(mac: str, update: ProfileUpdate):
    clean_mac = _validate_mac(mac)
    updated = await policy_manager.apply_policy(clean_mac, policy_id=update.profile)
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "device": updated.model_dump()}


@router.post("/api/devices/{mac}/toggle_wan")
async def toggle_wan(mac: str, req: ToggleRequest):
    clean_mac = _validate_mac(mac)
    success = await profile_manager.toggle_wan(clean_mac, block=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "blocked_wan": req.enabled, "success": success}


@router.post("/api/devices/{mac}/toggle_lan")
async def toggle_lan(mac: str, req: ToggleRequest):
    db = get_db()
    clean_mac = _validate_mac(mac)
    success = await profile_manager.toggle_lan_isolation(clean_mac, isolate=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    dev = await db.get_device(clean_mac)
    is_iso = dev.is_isolated_lan if dev else False
    msg = None
    if req.enabled and not is_iso:
        msg = "Для физической изоляции Wi-Fi устройств подключите их к Гостевой Wi-Fi сети Keenetic."
    return {"status": "ok", "isolated_lan": is_iso, "success": success, "message": msg}


@router.post("/api/devices/{mac}/toggle_airplay")
async def toggle_airplay(mac: str, req: ToggleRequest):
    clean_mac = _validate_mac(mac)
    success = await profile_manager.toggle_airplay(clean_mac, allow=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "airplay_allowed": req.enabled, "success": success}


@router.post("/api/devices/{mac}/toggle_dlna")
async def toggle_dlna(mac: str, req: ToggleRequest):
    clean_mac = _validate_mac(mac)
    success = await profile_manager.toggle_dlna(clean_mac, allow=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "dlna_allowed": req.enabled, "success": success}


@router.post("/api/devices/{mac}/toggle_night")
async def toggle_night(mac: str, req: ToggleRequest):
    clean_mac = _validate_mac(mac)
    success = await profile_manager.toggle_night_mode(clean_mac, enable=req.enabled)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "night_mode": req.enabled, "success": success}


@router.post("/api/devices/{mac}/rename")
async def rename_device(mac: str, req: RenameRequest):
    db = get_db()
    clean_mac = _validate_mac(mac)
    success = await db.update_device_policy(clean_mac, custom_name=req.custom_name)
    await ws_manager.broadcast({"type": "device_updated", "mac": clean_mac})
    return {"status": "ok", "success": success}


# ---------------- LAN Policy Presets & Setup Wizard Endpoints ----------------

@router.get("/api/presets")
async def list_presets():
    db = get_db()
    presets = await db.get_presets()
    return [p.model_dump() for p in presets]


@router.get("/api/presets/{preset_id}")
async def get_single_preset(preset_id: str):
    db = get_db()
    preset = await db.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Пресет не найден")
    return preset.model_dump()


@router.post("/api/presets")
async def create_preset(req: PresetCreateUpdateRequest):
    import uuid
    db = get_db()
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


@router.put("/api/presets/{preset_id}")
async def update_preset(preset_id: str, req: PresetCreateUpdateRequest):
    db = get_db()
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


@router.delete("/api/presets/{preset_id}")
async def delete_preset(preset_id: str):
    db = get_db()
    preset = await db.get_preset(preset_id)
    if not preset:
        raise HTTPException(status_code=404, detail="Пресет не найден")
    if preset.is_builtin:
        raise HTTPException(status_code=400, detail="Нельзя удалять системный встроенный пресет")
    success = await db.delete_preset(preset_id)
    await ws_manager.broadcast({"type": "presets_updated"})
    return {"status": "ok", "deleted": success, "preset_id": preset_id}


@router.post("/api/devices/{mac}/lan-policy")
async def update_device_lan_policy(mac: str, req: DeviceLanPolicyRequest):
    db = get_db()
    clean_mac = _validate_mac(mac)
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


@router.get("/api/wizard/device/{mac}")
async def get_device_wizard_context(mac: str):
    db = get_db()
    clean_mac = _validate_mac(mac)
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


@router.post("/api/wizard/device/{mac}")
async def submit_device_wizard(mac: str, req: DeviceWizardSubmitRequest):
    db = get_db()
    audit_manager = get_audit_manager()
    clean_mac = _validate_mac(mac)
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


@router.get("/api/devices/{mac}/traffic")
async def get_device_traffic(mac: str, limit: int = 60):
    db = get_db()
    clean_mac = _validate_mac(mac)
    history = await db.get_device_traffic_history(clean_mac, limit=limit)
    return history


@router.get("/api/devices/{mac}/payloads")
async def get_device_payloads(mac: str, limit: int = 100):
    """Returns captured payload data specifically for a given device MAC."""
    db = get_db()
    clean_mac = _validate_mac(mac)
    payloads = await db.get_iot_payloads(mac=clean_mac, limit=limit)
    storage = await db.get_iot_storage_stats()
    return {"status": "ok", "mac": clean_mac, "payloads": payloads, "storage": storage}


@router.get("/api/devices/{mac}/packets")
async def get_device_packets(mac: str, limit: int = 50, protocol: Optional[str] = None):
    """Returns recently captured raw/dissected packets for a specific device."""
    sniffer = get_sniffer()
    clean_mac = _validate_mac(mac)
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
