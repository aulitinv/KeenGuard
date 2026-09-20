"""IoT payload repository for payload logs and storage pruning."""
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import aiosqlite

from keenguard.config import settings
from keenguard.db.models import IotPayloadRecord
from keenguard.db.repositories.base import BaseRepository, PruneResult

logger = logging.getLogger("keenguard.db.iot")


class IotRepository(BaseRepository):
    """Repository handling IoT payload logs and retention pruning."""

    async def add_iot_payload(self, record: IotPayloadRecord) -> int:
        """Inserts an IoT payload record. Deduplicates rapid identical heartbeats (<3 sec)."""
        async with self.get_connection() as conn:
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

    async def get_iot_payloads(
        self,
        mac: Optional[str] = None,
        protocol: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
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

        async with self.get_connection() as conn:
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
        async with self.get_connection() as conn:
            if mac:
                cursor = await conn.execute("DELETE FROM iot_payload_logs WHERE mac = ?", (mac.upper(),))
            else:
                cursor = await conn.execute("DELETE FROM iot_payload_logs")
            await conn.commit()
            return cursor.rowcount

    async def get_iot_storage_stats(self) -> Dict[str, Any]:
        """Returns storage metrics for stored IoT payloads and database size."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("""
                SELECT COUNT(*), COALESCE(SUM(byte_size), 0), MIN(timestamp), MAX(timestamp)
                FROM iot_payload_logs
            """)
            row = await cursor.fetchone()
            count = row[0] if row else 0
            payload_bytes = row[1] if row else 0
            oldest_ts = row[2] if row else None
            newest_ts = row[3] if row else None

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

    async def prune_iot_payloads(
        self,
        max_gb: Optional[float] = None,
        retention_days: Optional[int] = None,
        max_storage_gb: Optional[float] = None
    ) -> Dict[str, Any]:
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

        async with self.get_connection() as conn:
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
