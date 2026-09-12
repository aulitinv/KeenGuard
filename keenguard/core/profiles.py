"""Security profile manager implementing the Zero-Trust Security Matrix."""
import logging
from typing import Dict, Any, Optional

from keenguard.db.models import DeviceRecord
from keenguard.db.database import db
from keenguard.core.keenetic import keenetic_client, is_host_lan_isolated

logger = logging.getLogger("keenguard.profiles")

# Predefined templates for Security Matrix
PROFILE_TEMPLATES = {
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

class ProfileManager:
    @staticmethod
    async def apply_profile(mac: str, profile_key: str) -> Optional[DeviceRecord]:
        clean_mac = mac.upper()
        tpl = PROFILE_TEMPLATES.get(profile_key, PROFILE_TEMPLATES["unassigned"])
        logger.info("Applying security profile '%s' to %s", profile_key, clean_mac)

        # Check real isolation status
        is_isolated = False
        if keenetic_client.mock_mode:
            is_isolated = tpl.get("is_isolated_lan", False)
        else:
            hosts = await keenetic_client.get_hotspot_hosts()
            matching_host = next((h for h in hosts if h.mac == clean_mac), None)
            if matching_host:
                is_isolated = is_host_lan_isolated(matching_host.interface, matching_host.ip)
            else:
                dev = await db.get_device(clean_mac)
                if dev:
                    is_isolated = is_host_lan_isolated(None, dev.ip)

        # 1. Update in Database
        await db.update_device_policy(
            mac=clean_mac,
            profile=profile_key,
            is_blocked_wan=tpl["is_blocked_wan"],
            is_isolated_lan=is_isolated,
            airplay_allowed=tpl["airplay_allowed"],
            dlna_allowed=tpl.get("dlna_allowed", True),
            night_mode_enabled=tpl["night_mode_enabled"]
        )

        return await db.get_device(clean_mac)

    @staticmethod
    async def toggle_wan(mac: str, block: bool) -> bool:
        clean_mac = mac.upper()
        access = "deny" if block else "permit"
        success = await keenetic_client.set_device_policy(clean_mac, access=access)
        await db.update_device_policy(clean_mac, is_blocked_wan=block)
        return success

    @staticmethod
    async def toggle_lan_isolation(mac: str, isolate: bool) -> bool:
        clean_mac = mac.upper()
        hosts = await keenetic_client.get_hotspot_hosts()
        matching_host = next((h for h in hosts if h.mac == clean_mac), None)
        is_really_isolated = False
        if matching_host:
            is_really_isolated = is_host_lan_isolated(matching_host.interface, matching_host.ip)
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
                await keenetic_client.enable_mdns_relay()

        return True

    @staticmethod
    async def toggle_dlna(mac: str, allow: bool) -> bool:
        clean_mac = mac.upper()
        await db.update_device_policy(clean_mac, dlna_allowed=allow)

        # Enforce DLNA access on the Keenetic router
        device = await db.get_device(clean_mac)
        if device and device.ip:
            await keenetic_client.set_dlna_access(clean_mac, device.ip, allow=allow)

        return True

    @staticmethod
    async def toggle_night_mode(mac: str, enable: bool) -> bool:
        clean_mac = mac.upper()
        return await db.update_device_policy(clean_mac, night_mode_enabled=enable)

profile_manager = ProfileManager()

