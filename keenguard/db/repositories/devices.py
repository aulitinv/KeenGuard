"""Device repository handling CRUD and access policies for devices."""
import json
import logging
from typing import Optional, List, Any, Union
import aiosqlite
from keenguard.db.models import DeviceRecord
from keenguard.db.repositories.base import BaseRepository

logger = logging.getLogger("keenguard.db.devices")
_UNSET = object()


class DeviceRepository(BaseRepository):
    """Device storage operations."""

    def _row_to_device(self, r: aiosqlite.Row) -> DeviceRecord:
        keys = r.keys()
        return DeviceRecord(
            mac=r["mac"],
            ip=r["ip"],
            interface=r["interface"] if "interface" in keys else None,
            hostname=r["hostname"],
            vendor=r["vendor"],
            profile=r["profile"],
            is_blocked_wan=bool(r["is_blocked_wan"]),
            is_isolated_lan=bool(r["is_isolated_lan"]),
            airplay_allowed=bool(r["airplay_allowed"]),
            dlna_allowed=bool(r["dlna_allowed"]) if "dlna_allowed" in keys else True,
            night_mode_enabled=bool(r["night_mode_enabled"]),
            first_seen=r["first_seen"],
            last_seen=r["last_seen"],
            is_online=bool(r["is_online"]),
            rx_bytes=r["rx_bytes"],
            tx_bytes=r["tx_bytes"],
            custom_name=r["custom_name"],
            notes=r["notes"],
            preset_id=r["preset_id"] if "preset_id" in keys else None,
            designated_nvr_ip=r["designated_nvr_ip"] if "designated_nvr_ip" in keys else None,
            auto_quarantine_override=r["auto_quarantine_override"] if ("auto_quarantine_override" in keys and r["auto_quarantine_override"]) else "profile_default",
            custom_allowed_ports=json.loads(r["custom_allowed_ports"]) if ("custom_allowed_ports" in keys and r["custom_allowed_ports"] and isinstance(r["custom_allowed_ports"], str)) else (r["custom_allowed_ports"] if "custom_allowed_ports" in keys else None),
            tv_pre_record_seconds=r["tv_pre_record_seconds"] if "tv_pre_record_seconds" in keys else None,
            tv_post_record_seconds=r["tv_post_record_seconds"] if "tv_post_record_seconds" in keys else None,
            tv_day_mode=r["tv_day_mode"] if "tv_day_mode" in keys else None,
            wizard_completed=bool(r["wizard_completed"]) if "wizard_completed" in keys else False,
            segment=r["segment"] if ("segment" in keys and r["segment"]) else "Home"
        )

    async def upsert_device(self, device: DeviceRecord) -> None:
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO devices (
                    mac, ip, hostname, vendor, profile, is_blocked_wan,
                    is_isolated_lan, airplay_allowed, dlna_allowed, night_mode_enabled,
                    first_seen, last_seen, is_online, rx_bytes, tx_bytes,
                    custom_name, notes, preset_id, designated_nvr_ip,
                    auto_quarantine_override, custom_allowed_ports,
                    tv_pre_record_seconds, tv_post_record_seconds, tv_day_mode, wizard_completed, segment
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    ip = excluded.ip,
                    hostname = COALESCE(excluded.hostname, devices.hostname),
                    vendor = CASE
                        WHEN excluded.vendor IS NOT NULL AND excluded.vendor NOT IN ('Unknown Vendor', 'Unknown', '') THEN excluded.vendor
                        ELSE COALESCE(devices.vendor, excluded.vendor)
                    END,
                    profile = CASE
                        WHEN devices.profile IN ('unassigned', '', NULL) AND excluded.profile NOT IN ('unassigned', '', NULL) THEN excluded.profile
                        ELSE devices.profile
                    END,
                    last_seen = excluded.last_seen,
                    is_online = excluded.is_online,
                    rx_bytes = excluded.rx_bytes,
                    tx_bytes = excluded.tx_bytes,
                    is_blocked_wan = excluded.is_blocked_wan,
                    is_isolated_lan = excluded.is_isolated_lan,
                    preset_id = COALESCE(excluded.preset_id, devices.preset_id),
                    designated_nvr_ip = COALESCE(excluded.designated_nvr_ip, devices.designated_nvr_ip),
                    auto_quarantine_override = COALESCE(excluded.auto_quarantine_override, devices.auto_quarantine_override),
                    custom_allowed_ports = COALESCE(excluded.custom_allowed_ports, devices.custom_allowed_ports),
                    tv_pre_record_seconds = COALESCE(excluded.tv_pre_record_seconds, devices.tv_pre_record_seconds),
                    tv_post_record_seconds = COALESCE(excluded.tv_post_record_seconds, devices.tv_post_record_seconds),
                    tv_day_mode = COALESCE(excluded.tv_day_mode, devices.tv_day_mode),
                    wizard_completed = CASE WHEN excluded.wizard_completed = 1 THEN 1 ELSE devices.wizard_completed END,
                    segment = COALESCE(excluded.segment, devices.segment)
            """, (
                device.mac.upper(), device.ip, device.hostname, device.vendor,
                device.profile, int(device.is_blocked_wan), int(device.is_isolated_lan),
                int(device.airplay_allowed), int(device.dlna_allowed), int(device.night_mode_enabled),
                device.first_seen, device.last_seen, int(device.is_online),
                device.rx_bytes, device.tx_bytes, device.custom_name, device.notes,
                device.preset_id, device.designated_nvr_ip, device.auto_quarantine_override,
                json.dumps(device.custom_allowed_ports) if isinstance(device.custom_allowed_ports, list) else device.custom_allowed_ports,
                device.tv_pre_record_seconds, device.tv_post_record_seconds,
                device.tv_day_mode, int(device.wizard_completed), device.segment or "Home"
            ))
            await conn.commit()

    async def update_device_policy(self, mac: str, profile: Optional[str] = None,
                                   is_blocked_wan: Optional[bool] = None,
                                   is_isolated_lan: Optional[bool] = None,
                                   airplay_allowed: Optional[bool] = None,
                                   dlna_allowed: Optional[bool] = None,
                                   night_mode_enabled: Optional[bool] = None,
                                   custom_name: Any = _UNSET,
                                   preset_id: Any = _UNSET,
                                   designated_nvr_ip: Any = _UNSET,
                                   auto_quarantine_override: Optional[str] = None,
                                   custom_allowed_ports: Any = _UNSET,
                                   tv_pre_record_seconds: Any = _UNSET,
                                   tv_post_record_seconds: Any = _UNSET,
                                   tv_day_mode: Any = _UNSET,
                                   wizard_completed: Optional[bool] = None) -> bool:
        updates = []
        params = []
        if profile is not None:
            updates.append("profile = ?")
            params.append(profile)
        if is_blocked_wan is not None:
            updates.append("is_blocked_wan = ?")
            params.append(int(is_blocked_wan))
        if is_isolated_lan is not None:
            updates.append("is_isolated_lan = ?")
            params.append(int(is_isolated_lan))
        if airplay_allowed is not None:
            updates.append("airplay_allowed = ?")
            params.append(int(airplay_allowed))
        if dlna_allowed is not None:
            updates.append("dlna_allowed = ?")
            params.append(int(dlna_allowed))
        if night_mode_enabled is not None:
            updates.append("night_mode_enabled = ?")
            params.append(int(night_mode_enabled))
        if custom_name is not _UNSET:
            updates.append("custom_name = ?")
            params.append(custom_name)
        if preset_id is not _UNSET:
            updates.append("preset_id = ?")
            params.append(preset_id)
        if designated_nvr_ip is not _UNSET:
            updates.append("designated_nvr_ip = ?")
            params.append(designated_nvr_ip)
        if auto_quarantine_override is not None:
            updates.append("auto_quarantine_override = ?")
            params.append(auto_quarantine_override)
        if custom_allowed_ports is not _UNSET:
            updates.append("custom_allowed_ports = ?")
            params.append(json.dumps(custom_allowed_ports) if isinstance(custom_allowed_ports, list) else (str(custom_allowed_ports) if custom_allowed_ports else None))
        if tv_pre_record_seconds is not _UNSET:
            updates.append("tv_pre_record_seconds = ?")
            params.append(tv_pre_record_seconds)
        if tv_post_record_seconds is not _UNSET:
            updates.append("tv_post_record_seconds = ?")
            params.append(tv_post_record_seconds)
        if tv_day_mode is not _UNSET:
            updates.append("tv_day_mode = ?")
            params.append(tv_day_mode)
        if wizard_completed is not None:
            updates.append("wizard_completed = ?")
            params.append(int(wizard_completed))

        if not updates:
            return False

        params.append(mac.upper())
        query = f"UPDATE devices SET {', '.join(updates)} WHERE mac = ?"
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute(query, params)
            await conn.commit()
            return cursor.rowcount > 0

    async def get_device(self, mac: str) -> Optional[DeviceRecord]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM devices WHERE mac = ?", (mac.upper(),))
            row = await cursor.fetchone()
            if row:
                return self._row_to_device(row)
        return None

    async def get_all_devices(self) -> List[DeviceRecord]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC")
            rows = await cursor.fetchall()
            return [self._row_to_device(r) for r in rows]

    async def delete_device(self, mac: str) -> bool:
        """Deletes a device from the database by MAC address."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM devices WHERE mac = ?", (mac,))
            await conn.commit()
            return cursor.rowcount > 0

    async def delete_offline_devices(self) -> int:
        """Deletes all devices that are currently offline (is_online = 0)."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM devices WHERE is_online = 0")
            await conn.commit()
            return cursor.rowcount
