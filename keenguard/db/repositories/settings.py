"""Settings and LAN policy presets repository."""
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import aiosqlite

from keenguard.config import settings
from keenguard.db.models import LanPolicyPreset
from keenguard.db.repositories.base import BaseRepository

logger = logging.getLogger("keenguard.db.settings")


BUILTIN_LAN_PRESETS = [
    {
        "id": "preset_smart_tv",
        "name": "Smart TV / Медиаплеер",
        "description": "Разрешен просмотр видео, DLNA (порт 8200), AirPlay/Cast, mDNS/SSDP. Запрещены или подозрительны SSH, Telnet, SMB, RDP.",
        "is_builtin": 1,
        "rules": {
            "allowed_services": ["DLNA:8200", "HTTP:80", "HTTPS:443", "HTTP_ALT:8080", "mDNS:5353", "SSDP:1900"],
            "alert_services": ["SSH:22", "SMB:445", "SMB_NETBIOS:139"],
            "blocked_services": ["Telnet:23", "RDP:3389"],
            "lan_to_lan_policy": "restricted"
        }
    },
    {
        "id": "preset_camera",
        "name": "IP-камера видеонаблюдения",
        "description": "Разрешены RTSP (554), HTTP-видео (80, 8000, 8080) и трафик к NVR. Запрещен доступ к сетевым папкам и терминалам.",
        "is_builtin": 1,
        "rules": {
            "allowed_services": ["RTSP:554", "HTTP:80", "HTTP_ALT:8080", "DVR:8000"],
            "alert_services": ["SSH:22", "SMB:445"],
            "blocked_services": ["Telnet:23", "RDP:3389"],
            "lan_to_lan_policy": "isolated"
        }
    },
    {
        "id": "preset_iot",
        "name": "IoT / Умный дом",
        "description": "Разрешены MQTT (1883, 8883), CoAP (5683), DNS (53), NTP (123). Запрещен доступ к сетевым папкам, SSH и веб-интерфейсам.",
        "is_builtin": 1,
        "rules": {
            "allowed_services": ["MQTT:1883", "MQTTS:8883", "CoAP:5683", "DNS:53", "NTP:123"],
            "alert_services": ["HTTP:80", "HTTPS:443", "SSH:22"],
            "blocked_services": ["SMB:445", "SMB_NETBIOS:139", "Telnet:23", "RDP:3389"],
            "lan_to_lan_policy": "restricted"
        }
    },
    {
        "id": "preset_trusted",
        "name": "Доверенная рабочая станция",
        "description": "Полный доверенный доступ ко всем локальным сервисам (SMB, SSH, RDP, базы данных). Автокарантин отключен.",
        "is_builtin": 1,
        "rules": {
            "allowed_services": ["*"],
            "alert_services": [],
            "blocked_services": [],
            "lan_to_lan_policy": "allow_all"
        }
    },
    {
        "id": "preset_isolated_guest",
        "name": "Изолированное гостевое устройство",
        "description": "Запрещены любые прямые обращения к сервисам и устройствам локальной сети.",
        "is_builtin": 1,
        "rules": {
            "allowed_services": ["DNS:53", "DHCP:67", "DHCP:68"],
            "alert_services": ["HTTP:80", "HTTPS:443", "SMB:445", "SSH:22"],
            "blocked_services": ["*"],
            "lan_to_lan_policy": "isolated"
        }
    }
]


class SettingsRepository(BaseRepository):
    """Settings and LAN policy presets storage operations."""

    async def save_setting(self, key: str, value: str):
        async with self.get_connection() as conn:
            await conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
            await conn.commit()

    async def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = await cursor.fetchone()
            if row:
                return row[0]
            return default

    async def get_all_settings(self) -> Dict[str, str]:
        """Returns all key-value pairs from app_settings in a single query."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT key, value FROM app_settings")
            rows = await cursor.fetchall()
            return {r[0]: r[1] for r in rows}

    async def set_settings_bulk(self, settings_dict: Dict[str, Any]) -> None:
        """Saves multiple settings to app_settings in a single transaction."""
        if not settings_dict:
            return
        items = []
        for k, v in settings_dict.items():
            if isinstance(v, (dict, list)):
                str_v = json.dumps(v, ensure_ascii=False)
            elif isinstance(v, bool):
                str_v = "true" if v else "false"
            elif v is None:
                str_v = ""
            else:
                str_v = str(v)
            items.append((k, str_v))
        async with self.get_connection() as conn:
            await conn.executemany("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", items)
            await conn.commit()

    async def save_new_device_policies(self, mode: str, policies: Dict[str, Any]):
        await self.save_setting("new_device_policy_mode", mode)
        await self.save_setting("new_device_category_policies", json.dumps(policies, ensure_ascii=False))

    async def get_new_device_policies(self) -> Dict[str, Any]:
        mode = await self.get_setting("new_device_policy_mode", default=getattr(settings, "new_device_policy_mode", "category"))
        policies_json = await self.get_setting("new_device_category_policies")
        if policies_json:
            try:
                policies = json.loads(policies_json)
            except (json.JSONDecodeError, TypeError):
                policies = dict(settings.new_device_category_policies)
        else:
            policies = dict(settings.new_device_category_policies)
        return {"mode": mode, "policies": policies, "categories": policies}

    async def get_presets(self) -> List[LanPolicyPreset]:
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM lan_policy_presets ORDER BY is_builtin DESC, name ASC")
            rows = await cursor.fetchall()
            presets = []
            for r in rows:
                rules = {}
                try:
                    rules = json.loads(r["rules_json"])
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning("Failed to decode rules_json for preset %s: %s", r.get("id"), e)
                presets.append(LanPolicyPreset(
                    id=r["id"],
                    name=r["name"],
                    description=r["description"] or "",
                    is_builtin=bool(r["is_builtin"]),
                    rules=rules,
                    created_at=r["created_at"] or "",
                    updated_at=r["updated_at"] or ""
                ))
            return presets

    async def get_preset(self, preset_id: str) -> Optional[LanPolicyPreset]:
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM lan_policy_presets WHERE id = ?", (preset_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            rules = {}
            try:
                rules = json.loads(row["rules_json"])
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning("Failed to decode rules_json for preset %s: %s", preset_id, e)
            return LanPolicyPreset(
                id=row["id"],
                name=row["name"],
                description=row["description"] or "",
                is_builtin=bool(row["is_builtin"]),
                rules=rules,
                created_at=row["created_at"] or "",
                updated_at=row["updated_at"] or ""
            )

    async def save_preset(self, preset: LanPolicyPreset) -> LanPolicyPreset:
        now_str = datetime.now(timezone.utc).isoformat()
        rules_str = json.dumps(preset.rules, ensure_ascii=False)
        async with self.get_connection() as conn:
            await conn.execute("""
                INSERT INTO lan_policy_presets (id, name, description, is_builtin, rules_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    rules_json = excluded.rules_json,
                    updated_at = excluded.updated_at
            """, (preset.id, preset.name, preset.description, int(preset.is_builtin), rules_str, preset.created_at or now_str, now_str))
            await conn.commit()
            return preset

    async def delete_preset(self, preset_id: str) -> bool:
        async with self.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM lan_policy_presets WHERE id = ? AND is_builtin = 0", (preset_id,))
            await conn.commit()
            return cursor.rowcount > 0
