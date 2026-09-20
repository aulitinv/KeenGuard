"""LAN communication repository for local traffic events."""
from typing import List, Optional, Dict, Any
import aiosqlite

from keenguard.db.models import LanCommunicationRecord
from keenguard.db.repositories.base import BaseRepository


class LanRepository(BaseRepository):
    """Repository handling LAN-to-LAN communication records."""

    async def add_lan_communication(self, record: LanCommunicationRecord) -> int:
        """Inserts a LAN communication record."""
        async with self.get_connection() as conn:
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

    async def get_lan_communications(
        self,
        comm_type: Optional[str] = None,
        ip: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
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

        async with self.get_connection() as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def clear_lan_communications(self) -> int:
        """Clears all stored LAN communications."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM lan_communications")
            await conn.commit()
            return cursor.rowcount
