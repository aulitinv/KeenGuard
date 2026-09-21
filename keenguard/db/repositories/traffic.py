"""Traffic repository for bandwidth snapshots and history."""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import aiosqlite

from keenguard.db.repositories.base import BaseRepository


class TrafficRepository(BaseRepository):
    """Repository handling traffic history and bandwidth metrics."""

    async def record_traffic_snapshot(
        self,
        mac: str,
        rx_bytes: int,
        tx_bytes: int,
        rx_rate_kbps: float,
        tx_rate_kbps: float,
        timestamp: Optional[str] = None
    ) -> None:
        now_ts = timestamp or datetime.now(timezone.utc).isoformat()
        clean_mac = mac.upper()
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT 1 FROM devices WHERE mac = ?", (clean_mac,))
            if not await cursor.fetchone():
                await conn.execute(
                    "INSERT OR IGNORE INTO devices (mac, first_seen, last_seen) VALUES (?, ?, ?)",
                    (clean_mac, now_ts, now_ts)
                )
            await conn.execute("""
                INSERT INTO traffic_history (timestamp, mac, rx_bytes, tx_bytes, rx_rate_kbps, tx_rate_kbps)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now_ts, clean_mac, rx_bytes, tx_bytes, round(rx_rate_kbps, 2), round(tx_rate_kbps, 2)))
            await conn.commit()

    async def get_device_traffic_history(self, mac: str, limit: int = 60) -> List[Dict[str, Any]]:
        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            # 1. First priority: Router WAN interface hardware snapshots (stored under '02:00:00:00:00:01')
            cursor = await conn.execute("""
                SELECT timestamp, rx_rate_kbps as total_rx_kbps, tx_rate_kbps as total_tx_kbps
                FROM traffic_history
                WHERE mac = '02:00:00:00:00:01'
                ORDER BY id DESC LIMIT ?
            """, (limit,))
            wan_rows = await cursor.fetchall()
            if len(wan_rows) >= 2:
                return [dict(r) for r in reversed(wan_rows)]

            # 2. Fallback: Aggregate per-device rates grouped by timestamp
            cursor = await conn.execute("""
                SELECT timestamp,
                       SUM(rx_rate_kbps) as total_rx_kbps,
                       SUM(tx_rate_kbps) as total_tx_kbps,
                       MAX(id) as max_id
                FROM traffic_history
                WHERE mac != '02:00:00:00:00:01'
                GROUP BY timestamp
                ORDER BY max_id DESC LIMIT ?
            """, (limit,))
            rows = await cursor.fetchall()
            return [dict(r) for r in reversed(rows)]

    async def cleanup_old_traffic(self, days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with self.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM traffic_history WHERE timestamp < ?", (cutoff,))
            await conn.commit()
            return cursor.rowcount
