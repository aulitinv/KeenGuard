"""Security event repository."""
import json
import logging
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import aiosqlite

from keenguard.db.models import SecurityEvent
from keenguard.db.repositories.base import BaseRepository

logger = logging.getLogger("keenguard.db.events")


class EventRepository(BaseRepository):
    """Event logging and cleanup operations."""

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
