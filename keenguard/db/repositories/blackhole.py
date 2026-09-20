"""Blackhole repository for storing blocked IP addresses and route rules."""
from datetime import datetime, timezone
from typing import List, Dict, Any
import aiosqlite

from keenguard.db.repositories.base import BaseRepository


class BlackholeRepository(BaseRepository):
    """Repository handling IP blackhole records in SQLite."""

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
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            if active_only:
                cursor = await conn.execute("SELECT * FROM ip_blackholes WHERE status = 'active' ORDER BY id DESC")
            else:
                cursor = await conn.execute("SELECT * FROM ip_blackholes ORDER BY id DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def delete_ip_blackhole_record(self, ip: str) -> None:
        """Deletes an IP blackhole record from SQLite."""
        async with self.get_connection() as conn:
            await conn.execute("DELETE FROM ip_blackholes WHERE ip = ?", (ip,))
            await conn.commit()
