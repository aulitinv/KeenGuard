"""Security policy and profile manager implementing the Zero-Trust Security Matrix."""
import logging
from typing import Dict, Any, Optional, List

from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.db.database import db
from keenguard.core.keenetic import is_host_lan_isolated

logger = logging.getLogger("keenguard.profiles")

# Predefined templates for Security Matrix
PROFILE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "trusted": {
        "name": "Доверенный (ПК / Смартфон)",
        "is_blocked_wan": False,
        "is_isolated_lan": False,
        "airplay_allowed": True,
        "dlna_allowed": True,
        "night_mode_enabled": False,
        "description": "Полный доступ в интернет и локальную сеть. Разрешено управление медиаустройствами."
    },
    "smart_home_hub": {
        "name": "Хаб умного дома (Контроллер)",
        "is_blocked_wan": False,
        "is_isolated_lan": False,
        "airplay_allowed": False,
        "dlna_allowed": True,
        "night_mode_enabled": False,
        "description": "Контроллер умного дома (SprutHub, Home Assistant). Разрешен локальный опрос и discovery датчиков. Защита от компрометации (контроль чувствительных портов SMB/SSH/RDP и мониторинг облачных соединений)."
    },
    "smart_tv": {
        "name": "Smart TV (Медиаэкран)",
        "is_blocked_wan": False,
        "is_isolated_lan": False,   # Physically in Bridge0 unless connected to Guest Wi-Fi
        "airplay_allowed": True,    # Passthrough
        "dlna_allowed": True,       # Keenetic DLNA Passthrough (port 8200)
        "night_mode_enabled": True, # Silent nights passive forensics
        "description": "Smart TV: пассивный ночной мониторинг (WOL/mDNS форензика). Для физической изоляции подключите к Гостевой Wi-Fi сети Keenetic."
    },
    "camera": {
        "name": "Камера видеонаблюдения",
        "is_blocked_wan": False,    # Internet is permitted by default; user can toggle manually if NVR-only is desired
        "is_isolated_lan": False,   # Physically in Bridge0 unless on Guest Wi-Fi
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Мониторинг видеопотоков и детекция утечек. Блокировка WAN включается вручную при необходимости."
    },
    "iot": {
        "name": "IoT / Умный дом",
        "is_blocked_wan": False,    # Internet is permitted by default for cloud devices (vacuums, climate, etc.)
        "is_isolated_lan": False,   # Physically in Bridge0 unless on Guest Wi-Fi
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Умный дом (IoT): мониторинг трафика и аномалий. Доступ в интернет разрешен."
    },
    "iot_cloud": {
        "name": "IoT / Умный дом (Облачный)",
        "is_blocked_wan": False,
        "is_isolated_lan": False,
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Облачные смарт-устройства (пылесос, климат). Доступ в интернет разрешен, мониторинг аномалий активен."
    },
    "iot_no_internet": {
        "name": "IoT / Умный дом (Без интернета)",
        "is_blocked_wan": True,
        "is_isolated_lan": False,
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Локальные датчики (Local-Only). Выход в интернет заблокирован на уровне роутера Keenetic."
    },
    "guest": {
        "name": "Гостевое устройство",
        "is_blocked_wan": False,
        "is_isolated_lan": True,
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Гостевой сегмент: доступ только в интернет, изолирован от домашней сети LAN."
    },
    "quarantine": {
        "name": "Карантин (Заблокирован)",
        "is_blocked_wan": True,
        "is_isolated_lan": True,
        "airplay_allowed": False,
        "dlna_allowed": False,
        "night_mode_enabled": False,
        "description": "Устройство изолировано и заблокировано при обнаружении инцидента безопасности или неизвестного подключения."
    },
    "unassigned": {
        "name": "Не назначен",
        "is_blocked_wan": False,
        "is_isolated_lan": False,
        "airplay_allowed": True,
        "dlna_allowed": True,
        "night_mode_enabled": False,
        "description": "Стандартная политика сети без ограничений."
    }
}

PROFILE_TO_PRESET_MAP: Dict[str, str] = {
    "smart_tv": "preset_smart_tv",
    "camera": "preset_camera",
    "iot": "preset_iot",
    "iot_cloud": "preset_iot",
    "iot_no_internet": "preset_iot",
    "smart_home_hub": "preset_iot",
    "trusted": "preset_trusted",
    "nas": "preset_trusted",
    "printer": "preset_iot",
    "guest": "preset_isolated_guest",
    "quarantine": "preset_isolated_guest",
    "unassigned": "preset_trusted",
}

PRESET_TO_PROFILE_MAP: Dict[str, str] = {
    "preset_smart_tv": "smart_tv",
    "preset_camera": "camera",
    "preset_iot": "iot",
    "preset_trusted": "trusted",
    "preset_isolated_guest": "guest",
}


class PolicyManager:
    """Unified Network Policy and Security Profile Manager for KeenGuard."""

    @staticmethod
    async def apply_policy(
        mac: str,
        policy_id: str,
        preset_id: Optional[str] = None,
        designated_nvr_ip: Optional[str] = None,
        auto_quarantine_override: Optional[str] = None,
        custom_allowed_ports: Optional[List[int]] = None,
        is_blocked_wan: Optional[bool] = None,
        tv_pre_record_seconds: Optional[int] = None,
        tv_post_record_seconds: Optional[int] = None,
        tv_day_mode: Optional[str] = None,
    ) -> Optional[DeviceRecord]:
        """
        Applies a unified security policy to a device, synchronizing both the high-level
        DeviceRecord.profile and the granular LanPolicyPreset (preset_id) in SQLite,
        and strictly enforcing hardware WAN access rules on the Keenetic router.
        """
        clean_mac = mac.upper()
        pol_key = (policy_id or "").strip()
        existing_dev = await db.get_device(clean_mac)

        # 1. Resolve target profile and preset_id
        if pol_key in PROFILE_TEMPLATES:
            target_profile = pol_key
            target_preset = preset_id or PROFILE_TO_PRESET_MAP.get(pol_key, "preset_trusted")
        elif pol_key in PRESET_TO_PROFILE_MAP:
            target_preset = pol_key
            target_profile = PRESET_TO_PROFILE_MAP[pol_key]
        elif pol_key.startswith("custom_") or pol_key.startswith("preset_"):
            target_preset = pol_key
            target_profile = existing_dev.profile if existing_dev else "unassigned"
        else:
            target_profile = pol_key or "unassigned"
            target_preset = preset_id or "preset_trusted"

        # Explicit preset override has higher priority for granular custom rules
        if preset_id is not None:
            target_preset = preset_id.strip() if preset_id.strip() else None

        tpl = PROFILE_TEMPLATES.get(target_profile, PROFILE_TEMPLATES["unassigned"])
        logger.info(
            "Applying unified security policy [profile=%s, preset=%s] to %s",
            target_profile, target_preset, clean_mac
        )

        # 2. Determine and enforce WAN policy on hardware router
        if is_blocked_wan is not None:
            want_blocked_wan = bool(is_blocked_wan)
        else:
            want_blocked_wan = tpl.get("is_blocked_wan", False)

        # Hardware WAN enforcement on active router
        from keenguard.core.routers import router_manager
        backend = router_manager.get_backend()
        try:
            await backend.set_wan_access(clean_mac, allow=not want_blocked_wan)
        except Exception as e:
            logger.warning("Could not mutate router WAN policy for %s: %s", clean_mac, e)

        # 3. Check real L2 physical isolation status
        is_isolated = False
        if getattr(backend, "mock_mode", False) and backend.platform_id == "keenetic":
            is_isolated = tpl.get("is_isolated_lan", False)
        else:
            hosts = await backend.get_hosts()
            matching_host = next((h for h in hosts if h.mac == clean_mac), None)
            if matching_host:
                is_isolated = is_host_lan_isolated(getattr(matching_host, "interface", None), matching_host.ip)
            elif existing_dev:
                is_isolated = is_host_lan_isolated(None, existing_dev.ip)

        # 4. Atomic update in Database
        update_kwargs: Dict[str, Any] = {
            "mac": clean_mac,
            "profile": target_profile,
            "preset_id": target_preset,
            "is_blocked_wan": want_blocked_wan,
            "is_isolated_lan": is_isolated,
            "airplay_allowed": tpl["airplay_allowed"],
            "dlna_allowed": tpl.get("dlna_allowed", True),
            "night_mode_enabled": tpl["night_mode_enabled"],
        }

        if designated_nvr_ip is not None:
            update_kwargs["designated_nvr_ip"] = designated_nvr_ip.strip() or None
        if auto_quarantine_override is not None:
            update_kwargs["auto_quarantine_override"] = auto_quarantine_override
        if custom_allowed_ports is not None:
            update_kwargs["custom_allowed_ports"] = custom_allowed_ports
        if tv_pre_record_seconds is not None:
            update_kwargs["tv_pre_record_seconds"] = tv_pre_record_seconds
        if tv_post_record_seconds is not None:
            update_kwargs["tv_post_record_seconds"] = tv_post_record_seconds
        if tv_day_mode is not None:
            update_kwargs["tv_day_mode"] = tv_day_mode

        await db.update_device_policy(**update_kwargs)

        # 5. Enforce DLNA router rule if Smart TV
        updated = await db.get_device(clean_mac)
        if updated and updated.ip and target_profile == "smart_tv":
            try:
                await backend.set_dlna_access(clean_mac, updated.ip, allow=tpl.get("dlna_allowed", True))
            except Exception as e:
                logger.debug("DLNA access rule error: %s", e)

        return updated

    # Legacy & backward-compatible aliases
    @staticmethod
    async def apply_profile(mac: str, profile_key: str) -> Optional[DeviceRecord]:
        return await PolicyManager.apply_policy(mac, policy_id=profile_key)

    @staticmethod
    async def assign_profile(mac: str, profile_key: str) -> Optional[DeviceRecord]:
        return await PolicyManager.apply_policy(mac, policy_id=profile_key)

    @staticmethod
    async def quarantine_device(mac: str, reason: str = "") -> bool:
        """Puts a device into complete quarantine (blocks WAN access and assigns quarantine profile)."""
        clean_mac = mac.upper()
        logger.warning("QUARANTINING DEVICE %s (reason: %s)", clean_mac, reason)
        record = await PolicyManager.apply_policy(clean_mac, policy_id="quarantine", is_blocked_wan=True)
        if record:
            ev = SecurityEvent(
                event_type="quarantine",
                severity="critical",
                target_mac=clean_mac,
                target_ip=record.ip,
                description=f"Устройство {record.hostname or clean_mac} переведено в карантин. Причина: {reason or 'Аномальная активность'}"
            )
            await db.record_event(ev)
            return True
        return False

    @staticmethod
    async def trust_device(mac: str) -> bool:
        """Sets device profile to trusted and unblocks WAN on router."""
        clean_mac = mac.upper()
        record = await PolicyManager.apply_policy(clean_mac, policy_id="trusted", is_blocked_wan=False)
        return record is not None

    @staticmethod
    async def toggle_wan(mac: str, block: bool) -> bool:
        clean_mac = mac.upper()
        from keenguard.core.routers import router_manager
        backend = router_manager.get_backend()
        success = await backend.set_wan_access(clean_mac, allow=not block)
        await db.update_device_policy(clean_mac, is_blocked_wan=block)
        return success

    @staticmethod
    async def toggle_lan_isolation(mac: str, isolate: bool) -> bool:
        clean_mac = mac.upper()
        from keenguard.core.routers import router_manager
        backend = router_manager.get_backend()
        hosts = await backend.get_hosts()
        matching_host = next((h for h in hosts if h.mac == clean_mac), None)
        is_really_isolated = False
        if matching_host:
            is_really_isolated = is_host_lan_isolated(getattr(matching_host, "interface", None), matching_host.ip)
        else:
            dev = await db.get_device(clean_mac)
            if dev:
                is_really_isolated = is_host_lan_isolated(None, dev.ip)

        # A device physically connected to Bridge0 (192.168.1.x) cannot be isolated via API.
        if isolate and not is_really_isolated:
            await db.update_device_policy(clean_mac, is_isolated_lan=False)
            return False

        target_state = is_really_isolated if isolate else False
        await db.update_device_policy(clean_mac, is_isolated_lan=target_state)
        return target_state

    @staticmethod
    async def toggle_airplay(mac: str, allow: bool) -> bool:
        clean_mac = mac.upper()
        await db.update_device_policy(clean_mac, airplay_allowed=allow)

        # If enabling AirPlay for an isolated device, ensure mDNS relay is active
        if allow:
            device = await db.get_device(clean_mac)
            if device and device.is_isolated_lan:
                from keenguard.core.routers import router_manager
                await router_manager.enable_mdns_relay()

        return True

    @staticmethod
    async def toggle_dlna(mac: str, allow: bool) -> bool:
        clean_mac = mac.upper()
        await db.update_device_policy(clean_mac, dlna_allowed=allow)

        # Enforce DLNA access on the router
        device = await db.get_device(clean_mac)
        if device and device.ip:
            from keenguard.core.routers import router_manager
            await router_manager.set_dlna_access(clean_mac, device.ip, allow=allow)

        return True

    @staticmethod
    async def toggle_night_mode(mac: str, enable: bool) -> bool:
        clean_mac = mac.upper()
        return await db.update_device_policy(clean_mac, night_mode_enabled=enable)


# Singletons & backwards-compatible aliases
policy_manager = PolicyManager()
profile_manager = policy_manager
ProfileManager = PolicyManager
