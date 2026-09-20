"""Asynchronous SQLite database operations for KeenGuard."""
import json
import logging
from pathlib import Path
from typing import Optional, Any
import aiosqlite

from keenguard.config import settings
from keenguard.db.repositories import (
    BaseRepository,
    PruneResult,
    _UNSET,
    DeviceRepository,
    EventRepository,
    SettingsRepository,
    BUILTIN_LAN_PRESETS,
    AuditRepository,
    TrafficRepository,
    DnsRepository,
    IotRepository,
    LanRepository,
    BlackholeRepository,
    StatsRepository,
)

logger = logging.getLogger("keenguard.db")


class Database(
    DeviceRepository,
    EventRepository,
    SettingsRepository,
    AuditRepository,
    TrafficRepository,
    DnsRepository,
    IotRepository,
    LanRepository,
    BlackholeRepository,
    StatsRepository,
    BaseRepository,
):
    """Composite asynchronous SQLite database for KeenGuard."""

    def __init__(self, db_path: Optional[Any] = None):
        super().__init__(db_path=db_path)

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


db = Database()

__all__ = [
    "Database",
    "db",
    "BUILTIN_LAN_PRESETS",
    "PruneResult",
    "_UNSET",
]
