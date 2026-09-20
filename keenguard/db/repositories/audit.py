"""Audit report repository."""
import logging
from typing import Optional, List
from datetime import datetime, timezone, timedelta
import aiosqlite

from keenguard.db.models import AuditReportRecord
from keenguard.db.repositories.base import BaseRepository

logger = logging.getLogger("keenguard.db.audit")


class AuditRepository(BaseRepository):
    """Audit report storage and lifecycle operations."""

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
