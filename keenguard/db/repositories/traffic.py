"""Traffic repository for bandwidth snapshots and history."""
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
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
        tx_rate_kbps: float
    ) -> None:
        now_ts = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            await conn.execute("""
                INSERT INTO traffic_history (timestamp, mac, rx_bytes, tx_bytes, rx_rate_kbps, tx_rate_kbps)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (now_ts, mac.upper(), rx_bytes, tx_bytes, round(rx_rate_kbps, 2), round(tx_rate_kbps, 2)))
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
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        async with self.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM traffic_history WHERE timestamp < ?", (cutoff,))
            await conn.commit()
            return cursor.rowcount
