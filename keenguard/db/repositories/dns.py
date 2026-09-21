"""DNS repository for query tracking, blocking, and domain intelligence."""
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import aiosqlite

from keenguard.db.repositories.base import BaseRepository


class DnsRepository(BaseRepository):
    """Repository handling DNS queries, blocked domains, and domain signatures."""

    async def record_dns_query(self, domain: str, mac: Optional[str] = None, ip: Optional[str] = None) -> None:
        if not domain or len(domain) < 2 or any(c in domain for c in (" ", "/", "\\", ":", "\t", "\n")):
            return
        now_ts = datetime.now(timezone.utc).isoformat()
        clean_domain = domain.lower().strip(".")
        if not clean_domain:
            return
        mac_clean = mac.upper() if mac else None
        async with self.get_connection() as conn:
            valid_fk_mac = None
            if mac_clean and mac_clean != "NETWORK":
                cursor = await conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac_clean,))
                if not await cursor.fetchone():
                    await conn.execute(
                        "INSERT OR IGNORE INTO devices (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                        (mac_clean, ip, now_ts, now_ts)
                    )
                valid_fk_mac = mac_clean

            # 1. Update global domain query counter
            await conn.execute("""
                INSERT INTO dns_queries (domain, mac, ip, count, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    count = count + 1,
                    last_seen = excluded.last_seen
            """, (clean_domain, valid_fk_mac, ip, now_ts, now_ts))

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

        async with self.get_connection() as conn:
            valid_fk_mac = None
            if mac_clean and mac_clean != "NETWORK":
                cursor = await conn.execute("SELECT 1 FROM devices WHERE mac = ?", (mac_clean,))
                if not await cursor.fetchone():
                    await conn.execute(
                        "INSERT OR IGNORE INTO devices (mac, ip, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                        (mac_clean, client_ip, now_ts, now_ts)
                    )
                valid_fk_mac = mac_clean

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
                    is_blocked = 1,
                    blocked_by_provider = COALESCE(excluded.blocked_by_provider, dns_queries.blocked_by_provider),
                    blocked_reason = COALESCE(excluded.blocked_reason, dns_queries.blocked_reason),
                    filter_list = COALESCE(excluded.filter_list, dns_queries.filter_list),
                    tracker_category = COALESCE(excluded.tracker_category, dns_queries.tracker_category)
            """, (clean_domain, valid_fk_mac, client_ip, now_ts, now_ts, provider, block_reason, filter_list, tracker_category))

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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT domain, category, description, risk_level, updated_at FROM custom_domain_rules")
            rows = await cursor.fetchall()
            return {r["domain"]: dict(r) for r in rows}

    async def get_domain_signatures(self) -> Dict[str, Dict[str, Any]]:
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT pattern, category, risk_level, description, source, updated_at FROM domain_signatures")
            rows = await cursor.fetchall()
            return {r["pattern"]: dict(r) for r in rows}

    async def save_domain_signatures(self, signatures: List[Dict[str, Any]]) -> int:
        now_ts = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
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

    async def delete_dns_query(self, domain: str) -> bool:
        """Deletes a domain from both dns_queries and dns_device_queries."""
        clean_domain = domain.lower().strip(".")
        if not clean_domain:
            return False
        async with self.get_connection() as conn:
            c1 = await conn.execute("DELETE FROM dns_queries WHERE domain = ?", (clean_domain,))
            c2 = await conn.execute("DELETE FROM dns_device_queries WHERE domain = ?", (clean_domain,))
            await conn.commit()
            return (c1.rowcount + c2.rowcount) > 0

    async def clear_dns_queries(self, domains: Optional[List[str]] = None) -> int:
        """Clears all DNS queries or a specified subset of domains."""
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute("SELECT domain, ip, count FROM dns_queries")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]
