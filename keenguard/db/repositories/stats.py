"""Stats repository for aggregations and digest summaries."""
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
import aiosqlite

from keenguard.db.repositories.base import BaseRepository


class StatsRepository(BaseRepository):
    """Repository handling system-wide aggregation statistics and digest metrics."""

    async def get_digest_stats(self, hours: int = 24) -> Dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        async with self.get_connection() as conn:
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
