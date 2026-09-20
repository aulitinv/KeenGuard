"""Asynchronous SQLite database operations for KeenGuard."""
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
import aiosqlite

from keenguard.config import settings
from keenguard.db.models import (
    DeviceRecord, SecurityEvent, AuditReportRecord, IotPayloadRecord,
    LanCommunicationRecord, LanPolicyPreset
)

logger = logging.getLogger("keenguard.db")

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


class PruneResult(dict):
    """Dictionary holding prune metrics that also behaves as an integer for backwards compatibility."""
    def __int__(self):
        return int(self.get("total_deleted", 0))
    def __ge__(self, other):
        return self.get("total_deleted", 0) >= (int(other) if isinstance(other, (int, float)) else other)
    def __gt__(self, other):
        return self.get("total_deleted", 0) > (int(other) if isinstance(other, (int, float)) else other)
    def __le__(self, other):
        return self.get("total_deleted", 0) <= (int(other) if isinstance(other, (int, float)) else other)
    def __lt__(self, other):
        return self.get("total_deleted", 0) < (int(other) if isinstance(other, (int, float)) else other)
    def __eq__(self, other):
        if isinstance(other, (int, float)):
            return self.get("total_deleted", 0) == other
        return super().__eq__(other)

_UNSET = object()

class Database:
    def __init__(self, db_path: Optional[Any] = None):
        self.db_path = Path(db_path) if db_path else settings.db_path

    @asynccontextmanager
    async def get_connection(self):
        """Returns an async connection context manager for SQLite with foreign keys enabled."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON;")
            yield conn

    async def init_db(self):
        """Creates tables and indexes if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with self.get_connection() as conn:
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("PRAGMA synchronous=NORMAL;")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    profile TEXT DEFAULT 'unassigned',
                    is_blocked_wan INTEGER DEFAULT 0,
                    is_isolated_lan INTEGER DEFAULT 0,
                    airplay_allowed INTEGER DEFAULT 1,
                    dlna_allowed INTEGER DEFAULT 1,
                    night_mode_enabled INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_online INTEGER DEFAULT 0,
                    rx_bytes INTEGER DEFAULT 0,
                    tx_bytes INTEGER DEFAULT 0,
                    custom_name TEXT,
                    notes TEXT,
                    preset_id TEXT,
                    designated_nvr_ip TEXT,
                    auto_quarantine_override TEXT DEFAULT 'profile_default',
                    custom_allowed_ports TEXT,
                    tv_pre_record_seconds INTEGER,
                    tv_post_record_seconds INTEGER,
                    tv_day_mode TEXT,
                    wizard_completed INTEGER DEFAULT 0,
                    segment TEXT DEFAULT 'Home'
                )
            """)

            # Migrations for existing DB
            for col_def in [
                "dlna_allowed INTEGER DEFAULT 1",
                "preset_id TEXT",
                "designated_nvr_ip TEXT",
                "auto_quarantine_override TEXT DEFAULT 'profile_default'",
                "custom_allowed_ports TEXT",
                "tv_pre_record_seconds INTEGER",
                "tv_post_record_seconds INTEGER",
                "tv_day_mode TEXT",
                "wizard_completed INTEGER DEFAULT 0",
                "segment TEXT DEFAULT 'Home'",
            ]:
                try:
                    await conn.execute(f"ALTER TABLE devices ADD COLUMN {col_def}")
                except aiosqlite.OperationalError:
                    # Column already exists in schema
                    pass
                except Exception as e:
                    logger.warning("Unexpected migration error for column %s: %s", col_def, e)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lan_policy_presets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_builtin INTEGER DEFAULT 0,
                    rules_json TEXT NOT NULL,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)

            cursor = await conn.execute("SELECT COUNT(*) FROM lan_policy_presets")
            cnt_row = await cursor.fetchone()
            if not cnt_row or cnt_row[0] == 0:
                for p in BUILTIN_LAN_PRESETS:
                    await conn.execute("""
                        INSERT OR IGNORE INTO lan_policy_presets (id, name, description, is_builtin, rules_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                    """, (p["id"], p["name"], p["description"], p["is_builtin"], json.dumps(p["rules"], ensure_ascii=False)))


            await conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    severity TEXT,
                    target_mac TEXT,
                    target_ip TEXT,
                    source_mac TEXT,
                    source_ip TEXT,
                    source_name TEXT,
                    description TEXT,
                    details_json TEXT,
                    pcap_file TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_reports (
                    id TEXT PRIMARY KEY,
                    mac TEXT,
                    ip TEXT,
                    hostname TEXT,
                    created_at TEXT,
                    duration_seconds INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    total_packets INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'low',
                    summary TEXT,
                    report_json TEXT,
                    pcap_file TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    mac TEXT,
                    rx_bytes INTEGER,
                    tx_bytes INTEGER,
                    rx_rate_kbps REAL,
                    tx_rate_kbps REAL
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_queries (
                    domain TEXT PRIMARY KEY,
                    mac TEXT,
                    ip TEXT,
                    count INTEGER DEFAULT 1,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_blocked INTEGER DEFAULT 0,
                    blocked_by_provider TEXT,
                    blocked_reason TEXT,
                    filter_list TEXT,
                    tracker_category TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_device_queries (
                    domain TEXT,
                    mac TEXT,
                    ip TEXT,
                    count INTEGER DEFAULT 1,
                    first_seen TEXT,
                    last_seen TEXT,
                    is_blocked INTEGER DEFAULT 0,
                    blocked_by_provider TEXT,
                    blocked_reason TEXT,
                    filter_list TEXT,
                    tracker_category TEXT,
                    PRIMARY KEY (domain, mac)
                )
            """)

            # Migrations for DNS security columns
            for col_def in [
                "is_blocked INTEGER DEFAULT 0",
                "blocked_by_provider TEXT",
                "blocked_reason TEXT",
                "filter_list TEXT",
                "tracker_category TEXT",
            ]:
                try:
                    await conn.execute(f"ALTER TABLE dns_queries ADD COLUMN {col_def}")
                except aiosqlite.OperationalError:
                    pass
                except Exception as e:
                    logger.warning("Unexpected migration error for dns_queries column %s: %s", col_def, e)
                try:
                    await conn.execute(f"ALTER TABLE dns_device_queries ADD COLUMN {col_def}")
                except aiosqlite.OperationalError:
                    pass
                except Exception as e:
                    logger.warning("Unexpected migration error for dns_device_queries column %s: %s", col_def, e)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_provider_sync_meta (
                    provider TEXT PRIMARY KEY,
                    last_sync_time TEXT,
                    last_record_timestamp TEXT,
                    total_blocked_synced INTEGER DEFAULT 0,
                    last_status TEXT,
                    last_error TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS custom_domain_rules (
                    domain TEXT PRIMARY KEY,
                    category TEXT,
                    description TEXT,
                    risk_level TEXT,
                    updated_at TEXT
                )
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS domain_signatures (
                    pattern TEXT PRIMARY KEY,
                    category TEXT,
                    risk_level TEXT,
                    description TEXT,
                    source TEXT,
                    updated_at TEXT
                )
            """)

            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_events_target ON events(target_mac)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_mac ON audit_reports(mac)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_reports(created_at)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_mac_ts ON traffic_history(mac, timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic_history(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_count ON dns_queries(count DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_dev_domain ON dns_device_queries(domain)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_dev_mac ON dns_device_queries(mac)")

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS iot_payload_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    mac TEXT,
                    device_name TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    direction TEXT,
                    summary TEXT,
                    payload_text TEXT,
                    payload_hex TEXT,
                    byte_size INTEGER DEFAULT 0,
                    raw_json TEXT
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_iot_mac ON iot_payload_logs(mac)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_iot_ts ON iot_payload_logs(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_iot_proto ON iot_payload_logs(protocol)")

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS lan_communications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    comm_type TEXT,
                    src_mac TEXT,
                    src_ip TEXT,
                    src_name TEXT,
                    dst_mac TEXT,
                    dst_ip TEXT,
                    dst_name TEXT,
                    protocol TEXT,
                    port INTEGER,
                    summary TEXT,
                    status TEXT,
                    rtt_ms REAL,
                    payload_preview TEXT
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_ts ON lan_communications(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_comm_type ON lan_communications(comm_type)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_src_ip ON lan_communications(src_ip)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_lan_dst_ip ON lan_communications(dst_ip)")

            # Backfill dns_device_queries from existing dns_queries if empty
            await conn.execute("""
                INSERT OR IGNORE INTO dns_device_queries (domain, mac, ip, count, first_seen, last_seen)
                SELECT domain, mac, ip, count, first_seen, last_seen
                FROM dns_queries
                WHERE mac IS NOT NULL
            """)

            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ip_blackholes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    mask TEXT DEFAULT '255.255.255.255',
                    created_at TEXT,
                    reason TEXT DEFAULT '',
                    provider TEXT DEFAULT '',
                    country TEXT DEFAULT 'WAN',
                    flag TEXT DEFAULT '🌐',
                    is_cdn INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_blackholes_ip ON ip_blackholes(ip)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_ip_blackholes_status ON ip_blackholes(status)")

            await conn.commit()
            logger.info("Database initialized at %s", self.db_path)

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

    async def record_event(self, event: SecurityEvent) -> int:
        details_str = json.dumps(event.details or {})
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                INSERT INTO events (
                    timestamp, event_type, severity, target_mac, target_ip,
                    source_mac, source_ip, source_name, description, details_json, pcap_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp, event.event_type, event.severity,
                event.target_mac.upper() if event.target_mac else None,
                event.target_ip,
                event.source_mac.upper() if event.source_mac else None,
                event.source_ip,
                event.source_name, event.description, details_str, event.pcap_file
            ))
            await conn.commit()
            return cursor.lastrowid

    async def get_recent_events(self, limit: int = 100, event_type: Optional[str] = None,
                                severity: Optional[str] = None, target_mac: Optional[str] = None) -> List[SecurityEvent]:
        query = "SELECT * FROM events"
        clauses = []
        params = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if target_mac:
            clauses.append("target_mac = ?")
            params.append(target_mac.upper())

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            return [self._row_to_event(r) for r in rows]

    async def save_setting(self, key: str, value: str):
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
            await conn.commit()

    async def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = await cursor.fetchone()
            if row:
                return row[0]
            return default

    async def get_all_settings(self) -> Dict[str, str]:
        """Returns all key-value pairs from app_settings in a single query."""
        async with aiosqlite.connect(self.db_path) as conn:
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
        async with aiosqlite.connect(self.db_path) as conn:
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
            except Exception:
                policies = dict(settings.new_device_category_policies)
        else:
            policies = dict(settings.new_device_category_policies)
        return {"mode": mode, "policies": policies, "categories": policies}

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

    async def get_presets(self) -> List[LanPolicyPreset]:
        async with aiosqlite.connect(self.db_path) as conn:
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
        async with aiosqlite.connect(self.db_path) as conn:
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
        async with aiosqlite.connect(self.db_path) as conn:
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
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM lan_policy_presets WHERE id = ? AND is_builtin = 0", (preset_id,))
            await conn.commit()
            return cursor.rowcount > 0


    def _row_to_event(self, r: aiosqlite.Row) -> SecurityEvent:
        details = {}
        if r["details_json"]:
            try:
                details = json.loads(r["details_json"])
            except (json.JSONDecodeError, TypeError) as e:
                logger.debug("Failed to decode event details_json for event %s: %s", r["id"], e)
        return SecurityEvent(
            id=r["id"],
            timestamp=r["timestamp"],
            event_type=r["event_type"],
            severity=r["severity"],
            target_mac=r["target_mac"],
            target_ip=r["target_ip"],
            source_mac=r["source_mac"],
            source_ip=r["source_ip"],
            source_name=r["source_name"],
            description=r["description"],
            details=details,
            pcap_file=r["pcap_file"]
        )

    async def save_audit_report(self, report: AuditReportRecord) -> None:
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT OR REPLACE INTO audit_reports (
                    id, mac, ip, hostname, created_at, duration_seconds,
                    total_bytes, total_packets, risk_level, summary, report_json, pcap_file
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.id, report.mac.upper(), report.ip, report.hostname,
                report.created_at, report.duration_seconds, report.total_bytes,
                report.total_packets, report.risk_level, report.summary,
                report.report_json, report.pcap_file
            ))
            await conn.commit()

    async def get_audit_reports(self, mac: Optional[str] = None, limit: int = 20) -> List[AuditReportRecord]:
        query = "SELECT * FROM audit_reports"
        params = []
        if mac:
            query += " WHERE mac = ?"
            params.append(mac.upper())
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            return [self._row_to_audit_report(r) for r in rows]

    async def get_audit_report_by_id(self, report_id: str) -> Optional[AuditReportRecord]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT * FROM audit_reports WHERE id = ?", (report_id,))
            row = await cursor.fetchone()
            if row:
                return self._row_to_audit_report(row)
            return None

    def _row_to_audit_report(self, r: aiosqlite.Row) -> AuditReportRecord:
        return AuditReportRecord(
            id=r["id"],
            mac=r["mac"],
            ip=r["ip"],
            hostname=r["hostname"],
            created_at=r["created_at"],
            duration_seconds=r["duration_seconds"],
            total_bytes=r["total_bytes"],
            total_packets=r["total_packets"],
            risk_level=r["risk_level"],
            summary=r["summary"],
            report_json=r["report_json"],
            pcap_file=r["pcap_file"]
        )

    async def delete_audit_report(self, report_id: str) -> Optional[str]:
        """Deletes an audit report by ID, returning its pcap_file filename if it had one."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT pcap_file FROM audit_reports WHERE id = ?", (report_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            pcap_file = row["pcap_file"]
            await conn.execute("DELETE FROM audit_reports WHERE id = ?", (report_id,))
            await conn.commit()
            return pcap_file or ""

    async def clear_audit_reports(self, older_than_days: Optional[int] = None) -> List[str]:
        """Clears audit reports, optionally filtered by age, returning list of pcap_file filenames."""
        clauses = []
        params = []
        if older_than_days is not None and older_than_days > 0:
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
            clauses.append("created_at < ?")
            params.append(cutoff)

        query_select = "SELECT pcap_file FROM audit_reports"
        query_delete = "DELETE FROM audit_reports"
        if clauses:
            query_select += " WHERE " + " AND ".join(clauses)
            query_delete += " WHERE " + " AND ".join(clauses)

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query_select, params)
            rows = await cursor.fetchall()
            pcap_files = [r["pcap_file"] for r in rows if r["pcap_file"]]
            await conn.execute(query_delete, params)
            await conn.commit()
            return pcap_files

    async def record_traffic_snapshot(self, mac: str, rx_bytes: int, tx_bytes: int,
                                       rx_rate_kbps: float, tx_rate_kbps: float) -> None:
        now_ts = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO traffic_history (timestamp, mac, rx_bytes, tx_bytes, rx_rate_kbps, tx_rate_kbps)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now_ts, mac.upper(), rx_bytes, tx_bytes, round(rx_rate_kbps, 2), round(tx_rate_kbps, 2)))
            await conn.commit()

    async def get_device_traffic_history(self, mac: str, limit: int = 60) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT timestamp, rx_bytes, tx_bytes, rx_rate_kbps, tx_rate_kbps
                FROM traffic_history
                WHERE mac = ?
                ORDER BY id DESC LIMIT ?
            """, (mac.upper(), limit))
            rows = await cursor.fetchall()
            return [dict(r) for r in reversed(rows)]

    async def get_network_traffic_summary(self, limit: int = 60) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT timestamp,
                       SUM(rx_rate_kbps) as total_rx_kbps,
                       SUM(tx_rate_kbps) as total_tx_kbps,
                       MAX(id) as max_id
                FROM traffic_history
                GROUP BY timestamp
                ORDER BY max_id DESC LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(r) for r in reversed(rows)]

    async def cleanup_old_traffic(self, days: int = 7) -> int:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM traffic_history WHERE timestamp < ?", (cutoff,))
            await conn.commit()
            return cursor.rowcount

    async def record_dns_query(self, domain: str, mac: Optional[str] = None, ip: Optional[str] = None) -> None:
        if not domain or len(domain) < 2 or any(c in domain for c in (" ", "/", "\\", ":", "\t", "\n")):
            return
        now_ts = datetime.now(timezone.utc).isoformat()
        clean_domain = domain.lower().strip(".")
        if not clean_domain:
            return
        mac_clean = mac.upper() if mac else None
        async with aiosqlite.connect(self.db_path) as conn:
            # 1. Update global domain query counter
            await conn.execute("""
                INSERT INTO dns_queries (domain, mac, ip, count, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    count = count + 1,
                    last_seen = excluded.last_seen,
                    mac = COALESCE(excluded.mac, dns_queries.mac),
                    ip = COALESCE(excluded.ip, dns_queries.ip)
            """, (clean_domain, mac_clean, ip, now_ts, now_ts))

            # 2. Update device-specific tracking if mac is present
            if mac_clean:
                await conn.execute("""
                    INSERT INTO dns_device_queries (domain, mac, ip, count, first_seen, last_seen)
                    VALUES (?, ?, ?, 1, ?, ?)
                    ON CONFLICT(domain, mac) DO UPDATE SET
                        count = count + 1,
                        last_seen = excluded.last_seen,
                        ip = COALESCE(excluded.ip, dns_device_queries.ip)
                """, (clean_domain, mac_clean, ip, now_ts, now_ts))

            await conn.commit()

    async def record_blocked_dns_query(
        self,
        domain: str,
        client_ip: Optional[str] = None,
        mac: Optional[str] = None,
        timestamp: Optional[str] = None,
        provider: str = "",
        block_reason: str = "",
        filter_list: Optional[str] = None,
        tracker_category: Optional[str] = None,
    ):
        """Records or updates a blocked DNS query from an external security provider."""
        if not domain:
            return
        clean_domain = domain.lower().strip(".")
        now_ts = timestamp or datetime.now(timezone.utc).isoformat()
        mac_clean = mac.upper().strip() if mac else None

        async with aiosqlite.connect(self.db_path) as conn:
            # 1. Update or insert global domain entry
            await conn.execute("""
                INSERT INTO dns_queries (
                    domain, mac, ip, count, first_seen, last_seen,
                    is_blocked, blocked_by_provider, blocked_reason, filter_list, tracker_category
                )
                VALUES (?, ?, ?, 1, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    count = count + 1,
                    last_seen = excluded.last_seen,
                    mac = COALESCE(excluded.mac, dns_queries.mac),
                    ip = COALESCE(excluded.ip, dns_queries.ip),
                    is_blocked = 1,
                    blocked_by_provider = COALESCE(excluded.blocked_by_provider, dns_queries.blocked_by_provider),
                    blocked_reason = COALESCE(excluded.blocked_reason, dns_queries.blocked_reason),
                    filter_list = COALESCE(excluded.filter_list, dns_queries.filter_list),
                    tracker_category = COALESCE(excluded.tracker_category, dns_queries.tracker_category)
            """, (clean_domain, mac_clean, client_ip, now_ts, now_ts, provider, block_reason, filter_list, tracker_category))

            # 2. Update or insert device-specific tracking if mac is known
            if mac_clean:
                await conn.execute("""
                    INSERT INTO dns_device_queries (
                        domain, mac, ip, count, first_seen, last_seen,
                        is_blocked, blocked_by_provider, blocked_reason, filter_list, tracker_category
                    )
                    VALUES (?, ?, ?, 1, ?, ?, 1, ?, ?, ?, ?)
                    ON CONFLICT(domain, mac) DO UPDATE SET
                        count = count + 1,
                        last_seen = excluded.last_seen,
                        ip = COALESCE(excluded.ip, dns_device_queries.ip),
                        is_blocked = 1,
                        blocked_by_provider = COALESCE(excluded.blocked_by_provider, dns_device_queries.blocked_by_provider),
                        blocked_reason = COALESCE(excluded.blocked_reason, dns_device_queries.blocked_reason),
                        filter_list = COALESCE(excluded.filter_list, dns_device_queries.filter_list),
                        tracker_category = COALESCE(excluded.tracker_category, dns_device_queries.tracker_category)
                """, (clean_domain, mac_clean, client_ip, now_ts, now_ts, provider, block_reason, filter_list, tracker_category))

            await conn.commit()

    async def get_dns_provider_sync_meta(self, provider: str) -> Optional[Dict[str, Any]]:
        """Retrieves synchronization metadata for a DNS security provider."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT provider, last_sync_time, last_record_timestamp, total_blocked_synced, last_status, last_error
                FROM dns_provider_sync_meta
                WHERE provider = ?
            """, (provider,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def update_dns_provider_sync_meta(
        self,
        provider: str,
        last_sync_time: str,
        last_record_timestamp: str,
        total_synced: int,
        last_status: str,
        last_error: Optional[str] = None,
    ):
        """Updates or inserts synchronization metadata for a DNS security provider."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO dns_provider_sync_meta (
                    provider, last_sync_time, last_record_timestamp, total_blocked_synced, last_status, last_error
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider) DO UPDATE SET
                    last_sync_time = excluded.last_sync_time,
                    last_record_timestamp = excluded.last_record_timestamp,
                    total_blocked_synced = excluded.total_blocked_synced,
                    last_status = excluded.last_status,
                    last_error = excluded.last_error
            """, (provider, last_sync_time, last_record_timestamp, total_synced, last_status, last_error))
            await conn.commit()

    async def get_top_dns_queries(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT domain, mac, ip, count, first_seen, last_seen,
                       is_blocked, blocked_by_provider, blocked_reason, filter_list, tracker_category
                FROM dns_queries
                ORDER BY count DESC, last_seen DESC LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_domain_devices(self, domain: str) -> List[Dict[str, Any]]:
        """Returns all devices that have communicated with a specific domain."""
        clean_domain = domain.lower().strip(".")
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT dq.mac, dq.ip, dq.count, dq.first_seen, dq.last_seen,
                       dq.is_blocked, dq.blocked_by_provider, dq.blocked_reason, dq.filter_list,
                       d.hostname, d.custom_name, d.profile, d.vendor
                FROM dns_device_queries dq
                LEFT JOIN devices d ON dq.mac = d.mac
                WHERE dq.domain = ?
                ORDER BY dq.count DESC, dq.last_seen DESC
            """, (clean_domain,))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_dns_device_counts_for_domains(self, domains: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Returns mapping of domain -> list of devices accessing it, targeted for requested domains."""
        if not domains:
            return {}
        placeholders = ",".join("?" for _ in domains)
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(f"""
                SELECT dq.domain, dq.mac, dq.ip, dq.count, dq.last_seen,
                       dq.is_blocked, dq.blocked_by_provider, dq.blocked_reason, dq.filter_list,
                       d.hostname, d.custom_name, d.profile, d.vendor
                FROM dns_device_queries dq
                LEFT JOIN devices d ON dq.mac = d.mac
                WHERE dq.domain IN ({placeholders})
                ORDER BY dq.count DESC
            """, tuple(domains))
            rows = await cursor.fetchall()
            result: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                d = dict(r)
                dom = d["domain"]
                if dom not in result:
                    result[dom] = []
                result[dom].append(d)
            return result

    async def get_all_dns_device_counts(self) -> Dict[str, List[Dict[str, Any]]]:
        """Returns a mapping of domain -> list of devices accessing it."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT dq.domain, dq.mac, dq.ip, dq.count, dq.last_seen,
                       d.hostname, d.custom_name, d.profile, d.vendor
                FROM dns_device_queries dq
                LEFT JOIN devices d ON dq.mac = d.mac
                ORDER BY dq.count DESC
            """)
            rows = await cursor.fetchall()
            result: Dict[str, List[Dict[str, Any]]] = {}
            for r in rows:
                d = dict(r)
                dom = d["domain"]
                if dom not in result:
                    result[dom] = []
                result[dom].append(d)
            return result

    async def get_device_domains_map(self) -> Dict[str, List[str]]:
        """Returns a mapping of device MAC -> list of unique domains contacted."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("""
                SELECT mac, domain
                FROM dns_device_queries
                ORDER BY count DESC
            """)
            rows = await cursor.fetchall()
            result: Dict[str, List[str]] = {}
            for r in rows:
                m = r["mac"]
                d = r["domain"]
                if m and d:
                    if m not in result:
                        result[m] = []
                    if d not in result[m]:
                        result[m].append(d)
            return result

    async def set_custom_domain_rule(self, domain: str, category: str, description: str, risk_level: str) -> None:
        """Sets or overrides a user-defined category and description for a domain."""
        clean_domain = domain.lower().strip(".")
        now_ts = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("""
                INSERT INTO custom_domain_rules (domain, category, description, risk_level, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    category = excluded.category,
                    description = excluded.description,
                    risk_level = excluded.risk_level,
                    updated_at = excluded.updated_at
            """, (clean_domain, category, description, risk_level, now_ts))
            await conn.commit()

    async def get_custom_domain_rules(self) -> Dict[str, Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT domain, category, description, risk_level, updated_at FROM custom_domain_rules")
            rows = await cursor.fetchall()
            return {r["domain"]: dict(r) for r in rows}

    async def get_domain_signatures(self) -> Dict[str, Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT pattern, category, risk_level, description, source, updated_at FROM domain_signatures")
            rows = await cursor.fetchall()
            return {r["pattern"]: dict(r) for r in rows}

    async def save_domain_signatures(self, signatures: List[Dict[str, Any]]) -> int:
        now_ts = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as conn:
            for sig in signatures:
                await conn.execute("""
                    INSERT INTO domain_signatures (pattern, category, risk_level, description, source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pattern) DO UPDATE SET
                        category = excluded.category,
                        risk_level = excluded.risk_level,
                        description = excluded.description,
                        source = excluded.source,
                        updated_at = excluded.updated_at
                """, (sig["pattern"], sig.get("category", "unknown"), sig.get("risk_level", "safe"),
                      sig.get("description", ""), sig.get("source", "online"), now_ts))
            await conn.commit()
            return len(signatures)

    async def get_digest_stats(self, hours: int = 24) -> Dict[str, Any]:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row

            # Events in timeframe
            cursor = await conn.execute("""
                SELECT severity, event_type, COUNT(*) as cnt
                FROM events
                WHERE timestamp >= ?
                GROUP BY severity, event_type
            """, (cutoff,))
            event_counts = await cursor.fetchall()

            # Device stats
            cursor = await conn.execute("SELECT COUNT(*) as total, COALESCE(SUM(is_online), 0) as online FROM devices")
            dev_row = await cursor.fetchone()

            # Audits in timeframe
            cursor = await conn.execute("""
                SELECT COUNT(*) as audit_count,
                       COALESCE(SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END), 0) as high_risk_audits
                FROM audit_reports
                WHERE created_at >= ?
            """, (cutoff,))
            audit_row = await cursor.fetchone()

            # Top 5 recent incidents
            cursor = await conn.execute("""
                SELECT timestamp, severity, event_type, description
                FROM events
                WHERE timestamp >= ? AND severity IN ('critical', 'warning')
                ORDER BY id DESC LIMIT 5
            """, (cutoff,))
            top_incidents = [dict(r) for r in await cursor.fetchall()]

            # Check for smart home hubs or IoT devices
            cursor = await conn.execute("""
                SELECT COUNT(*) as cnt FROM devices
                WHERE profile IN ('smart_home_hub', 'iot')
            """)
            hub_iot_row = await cursor.fetchone()
            has_hubs_or_vacuums = bool(hub_iot_row and hub_iot_row["cnt"] > 0)

            return {
                "hours": hours,
                "cutoff": cutoff,
                "total_devices": int(dev_row["total"] or 0) if dev_row else 0,
                "online_devices": int(dev_row["online"] or 0) if dev_row else 0,
                "event_counts": [dict(r) for r in event_counts],
                "audit_count": int(audit_row["audit_count"] or 0) if audit_row else 0,
                "high_risk_audits": int(audit_row["high_risk_audits"] or 0) if audit_row else 0,
                "top_incidents": top_incidents,
                "has_hubs_or_vacuums": has_hubs_or_vacuums
            }

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

    async def delete_event(self, event_id: int) -> bool:
        """Deletes a single security event by ID."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM events WHERE id = ?", (event_id,))
            await conn.commit()
            return cursor.rowcount > 0

    async def clear_events(self, severity: Optional[str] = None, older_than_days: Optional[int] = None) -> int:
        """Clears events matching criteria, or all events if no criteria provided."""
        clauses = []
        params = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity.lower())
        if older_than_days is not None and older_than_days > 0:
            from datetime import timedelta
            cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
            clauses.append("timestamp < ?")
            params.append(cutoff)

        query = "DELETE FROM events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute(query, params)
            await conn.commit()
            return cursor.rowcount

    async def cleanup_router_false_events(self) -> int:
        """Cleans up false-positive lan_scan events generated for router interfaces/gateways."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                DELETE FROM events
                WHERE event_type = 'lan_scan'
                  AND (source_ip LIKE '%.1' OR source_ip LIKE '%.254' OR source_ip = '192.168.1.1' OR source_ip = '192.168.2.1')
            """)
            await conn.commit()
            return cursor.rowcount

    async def delete_dns_query(self, domain: str) -> bool:
        """Deletes a domain from both dns_queries and dns_device_queries."""
        clean_domain = domain.lower().strip(".")
        if not clean_domain:
            return False
        async with aiosqlite.connect(self.db_path) as conn:
            c1 = await conn.execute("DELETE FROM dns_queries WHERE domain = ?", (clean_domain,))
            c2 = await conn.execute("DELETE FROM dns_device_queries WHERE domain = ?", (clean_domain,))
            await conn.commit()
            return (c1.rowcount + c2.rowcount) > 0

    async def clear_dns_queries(self, domains: Optional[List[str]] = None) -> int:
        """Clears all DNS queries or a specified subset of domains."""
        async with aiosqlite.connect(self.db_path) as conn:
            if domains is not None:
                if not domains:
                    return 0
                clean_domains = [d.lower().strip(".") for d in domains if d]
                if not clean_domains:
                    return 0
                placeholders = ",".join("?" for _ in clean_domains)
                cursor = await conn.execute(f"DELETE FROM dns_queries WHERE domain IN ({placeholders})", tuple(clean_domains))
                await conn.execute(f"DELETE FROM dns_device_queries WHERE domain IN ({placeholders})", tuple(clean_domains))
                await conn.commit()
                return cursor.rowcount
            else:
                cursor = await conn.execute("DELETE FROM dns_queries")
                await conn.execute("DELETE FROM dns_device_queries")
                await conn.commit()
                return cursor.rowcount

    async def get_all_dns_domains(self) -> List[Dict[str, Any]]:
        """Returns all domains with their ip and count from dns_queries."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT domain, ip, count FROM dns_queries")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ==========================================
    # IoT Payload Logs & Storage Pruning
    # ==========================================

    async def add_iot_payload(self, record: IotPayloadRecord) -> int:
        """Inserts an IoT payload record. Deduplicates rapid identical heartbeats (<3 sec)."""
        async with aiosqlite.connect(self.db_path) as conn:
            # Check for identical duplicate within last 3 seconds
            cursor = await conn.execute("""
                SELECT id, timestamp FROM iot_payload_logs
                WHERE mac = ? AND protocol = ? AND summary = ?
                ORDER BY id DESC LIMIT 1
            """, (record.mac.upper(), record.protocol, record.summary))
            row = await cursor.fetchone()
            if row:
                try:
                    last_dt = datetime.fromisoformat(row[1])
                    cur_dt = datetime.fromisoformat(record.timestamp)
                    if (cur_dt - last_dt).total_seconds() < 3.0:
                        # Update timestamp of the recent identical packet
                        await conn.execute("UPDATE iot_payload_logs SET timestamp = ? WHERE id = ?", (record.timestamp, row[0]))
                        await conn.commit()
                        return row[0]
                except (ValueError, TypeError) as e:
                    logger.debug("Failed to parse timestamp for IoT payload deduplication: %s", e)

            cursor = await conn.execute("""
                INSERT INTO iot_payload_logs (
                    timestamp, mac, device_name, src_ip, dst_ip, dst_port,
                    protocol, direction, summary, payload_text, payload_hex,
                    byte_size, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.timestamp, record.mac.upper(), record.device_name,
                record.src_ip, record.dst_ip, record.dst_port,
                record.protocol, record.direction, record.summary,
                record.payload_text, record.payload_hex, record.byte_size,
                record.raw_json
            ))
            await conn.commit()
            return cursor.lastrowid or 0

    async def get_iot_payloads(self, mac: Optional[str] = None, protocol: Optional[str] = None,
                               search: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieves IoT payload records with filtering and search."""
        query = """
            SELECT 
                l.*,
                COALESCE(d.custom_name, d.hostname, l.device_name) AS resolved_name,
                d.custom_name,
                d.hostname AS device_hostname,
                d.profile AS device_profile
            FROM iot_payload_logs l
            LEFT JOIN devices d ON UPPER(l.mac) = UPPER(d.mac)
            WHERE 1=1
        """
        params: List[Any] = []

        if mac:
            query += " AND l.mac = ?"
            params.append(mac.upper())
        if protocol and protocol.lower() != "all":
            query += " AND UPPER(l.protocol) = ?"
            params.append(protocol.upper())
        if search:
            query += " AND (l.summary LIKE ? OR l.payload_text LIKE ? OR l.src_ip LIKE ? OR l.dst_ip LIKE ? OR l.device_name LIKE ? OR d.hostname LIKE ? OR d.custom_name LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param, s_param, s_param, s_param])

        query += " ORDER BY l.id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        from keenguard.core.keenetic import keenetic_client

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
            res = []
            for r in rows:
                item = dict(r)
                resolved = item.get("resolved_name")
                if not resolved:
                    resolved = item.get("device_name") or item.get("device_hostname")
                if not resolved and item.get("mac") and keenetic_client.is_router_entity(mac=item.get("mac")):
                    resolved = "Роутер Keenetic"

                if resolved:
                    item["device_name"] = resolved
                    item["hostname"] = resolved
                elif "device_name" in item and "hostname" not in item:
                    item["hostname"] = item["device_name"]

                if "src_ip" in item and "ip" not in item:
                    item["ip"] = item["src_ip"]
                if "summary" in item and "decoded_summary" not in item:
                    item["decoded_summary"] = item["summary"]
                res.append(item)
            return res

    async def clear_iot_payloads(self, mac: Optional[str] = None) -> int:
        """Clears IoT payload records for a given MAC or all."""
        async with aiosqlite.connect(self.db_path) as conn:
            if mac:
                cursor = await conn.execute("DELETE FROM iot_payload_logs WHERE mac = ?", (mac.upper(),))
            else:
                cursor = await conn.execute("DELETE FROM iot_payload_logs")
            await conn.commit()
            return cursor.rowcount

    async def get_iot_storage_stats(self) -> Dict[str, Any]:
        """Returns storage metrics for stored IoT payloads and database size."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                SELECT COUNT(*), COALESCE(SUM(byte_size), 0), MIN(timestamp), MAX(timestamp)
                FROM iot_payload_logs
            """)
            row = await cursor.fetchone()
            count = row[0] if row else 0
            payload_bytes = row[1] if row else 0
            oldest_ts = row[2] if row else None
            newest_ts = row[3] if row else None

        # Calculate actual DB file size on disk
        db_file_bytes = 0
        try:
            if self.db_path.exists():
                db_file_bytes = self.db_path.stat().st_size
        except OSError as e:
            logger.debug("Failed to read database file size from %s: %s", self.db_path, e)

        return {
            "count": count,
            "total_records": count,
            "total_bytes": payload_bytes,
            "payload_bytes": payload_bytes,
            "total_mb": round(payload_bytes / (1024 * 1024), 2),
            "payload_mb": round(payload_bytes / (1024 * 1024), 2),
            "db_file_bytes": db_file_bytes,
            "db_file_mb": round(db_file_bytes / (1024 * 1024), 2),
            "max_storage_gb": settings.iot_payload_max_storage_gb,
            "retention_days": settings.iot_payload_retention_days,
            "capture_enabled": settings.iot_payload_capture_enabled,
            "oldest_timestamp": oldest_ts,
            "newest_timestamp": newest_ts
        }

    async def prune_iot_payloads(self, max_gb: Optional[float] = None, retention_days: Optional[int] = None, max_storage_gb: Optional[float] = None) -> Dict[str, Any]:
        """
        Enforces user storage policies:
        1. Deletes records older than retention_days.
        2. Deletes oldest records if payload size exceeds max_gb.
        """
        limit_days = retention_days if retention_days is not None else settings.iot_payload_retention_days
        limit_gb = max_storage_gb if max_storage_gb is not None else (max_gb if max_gb is not None else settings.iot_payload_max_storage_gb)
        limit_bytes = int(limit_gb * 1024 * 1024 * 1024)

        deleted_by_age = 0
        deleted_by_size = 0

        async with aiosqlite.connect(self.db_path) as conn:
            # 1. Prune by retention days
            if limit_days > 0:
                cutoff_dt = datetime.now(timezone.utc).timestamp() - (limit_days * 86400)
                cutoff_iso = datetime.fromtimestamp(cutoff_dt, tz=timezone.utc).isoformat()
                c1 = await conn.execute("DELETE FROM iot_payload_logs WHERE timestamp < ?", (cutoff_iso,))
                deleted_by_age = c1.rowcount

            # 2. Check total size and prune oldest if exceeding max_gb
            c_sum = await conn.execute("SELECT COALESCE(SUM(byte_size), 0) FROM iot_payload_logs")
            total_bytes = (await c_sum.fetchone())[0] or 0

            while total_bytes > limit_bytes:
                # Delete oldest batch of 500
                c2 = await conn.execute("""
                    DELETE FROM iot_payload_logs
                    WHERE id IN (SELECT id FROM iot_payload_logs ORDER BY id ASC LIMIT 500)
                """)
                deleted_batch = c2.rowcount
                if deleted_batch == 0:
                    break
                deleted_by_size += deleted_batch
                c_sum2 = await conn.execute("SELECT COALESCE(SUM(byte_size), 0) FROM iot_payload_logs")
                total_bytes = (await c_sum2.fetchone())[0] or 0

            await conn.commit()

            # Optional VACUUM if lots of rows were deleted
            if deleted_by_age + deleted_by_size > 1000:
                try:
                    await conn.execute("VACUUM")
                except aiosqlite.Error as e:
                    logger.warning("VACUUM failed after pruning: %s", e)

        total_del = deleted_by_age + deleted_by_size
        logger.info("IoT payload pruning complete: deleted %d by age (>%d d), %d by size (limit %s GB)",
                    deleted_by_age, limit_days, deleted_by_size, limit_gb)
        return PruneResult({
            "deleted_by_age": deleted_by_age,
            "deleted_by_size": deleted_by_size,
            "total_deleted": total_del,
            "pruned_count": total_del
        })

    # ==========================================
    # LAN Communications Records
    # ==========================================

    async def add_lan_communication(self, record: LanCommunicationRecord) -> int:
        """Inserts a LAN communication record."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("""
                INSERT INTO lan_communications (
                    timestamp, comm_type, src_mac, src_ip, src_name,
                    dst_mac, dst_ip, dst_name, protocol, port,
                    summary, status, rtt_ms, payload_preview
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.timestamp, record.comm_type, record.src_mac, record.src_ip, record.src_name,
                record.dst_mac, record.dst_ip, record.dst_name, record.protocol, record.port,
                record.summary, record.status, record.rtt_ms, record.payload_preview
            ))
            await conn.commit()
            return cursor.lastrowid or 0

    async def get_lan_communications(self, comm_type: Optional[str] = None, ip: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves LAN communications from database."""
        query = "SELECT * FROM lan_communications WHERE 1=1"
        params: List[Any] = []

        if comm_type and comm_type != "all":
            if comm_type == "ping":
                query += " AND comm_type IN ('icmp_ping', 'icmp_reply')"
            elif comm_type == "arp":
                query += " AND comm_type IN ('arp_query', 'arp_reply')"
            elif comm_type == "flows":
                query += " AND comm_type = 'local_flow'"
            else:
                query += " AND comm_type = ?"
                params.append(comm_type)

        if ip:
            query += " AND (src_ip = ? OR dst_ip = ?)"
            params.extend([ip, ip])

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def clear_lan_communications(self) -> int:
        """Clears all stored LAN communications."""
        async with aiosqlite.connect(self.db_path) as conn:
            cursor = await conn.execute("DELETE FROM lan_communications")
            await conn.commit()
            return cursor.rowcount

    async def add_ip_blackhole_record(
        self,
        ip: str,
        reason: str = "",
        provider: str = "",
        country: str = "WAN",
        flag: str = "🌐",
        is_cdn: bool = False
    ) -> None:
        """Saves or updates an IP blackhole rule in SQLite."""
        async with aiosqlite.connect(self.db_path) as conn:
            now_iso = datetime.now(timezone.utc).isoformat()
            await conn.execute("""
                INSERT INTO ip_blackholes (ip, mask, created_at, reason, provider, country, flag, is_cdn, status)
                VALUES (?, '255.255.255.255', ?, ?, ?, ?, ?, ?, 'active')
                ON CONFLICT(ip) DO UPDATE SET
                    status = 'active',
                    reason = CASE WHEN excluded.reason != '' THEN excluded.reason ELSE ip_blackholes.reason END,
                    provider = CASE WHEN excluded.provider != '' THEN excluded.provider ELSE ip_blackholes.provider END,
                    country = excluded.country,
                    flag = excluded.flag,
                    is_cdn = excluded.is_cdn,
                    created_at = excluded.created_at
            """, (ip, now_iso, reason, provider, country, flag, 1 if is_cdn else 0))
            await conn.commit()

    async def get_ip_blackholes(self, active_only: bool = True) -> List[Dict[str, Any]]:
        """Retrieves list of IP blackhole records."""
        async with aiosqlite.connect(self.db_path) as conn:
            conn.row_factory = aiosqlite.Row
            if active_only:
                cursor = await conn.execute("SELECT * FROM ip_blackholes WHERE status = 'active' ORDER BY id DESC")
            else:
                cursor = await conn.execute("SELECT * FROM ip_blackholes ORDER BY id DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def delete_ip_blackhole_record(self, ip: str) -> None:
        """Deletes an IP blackhole record from SQLite."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("DELETE FROM ip_blackholes WHERE ip = ?", (ip,))
            await conn.commit()

db = Database()


