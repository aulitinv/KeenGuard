"""Data export endpoints (CSV and JSON)."""
import csv
import io
import logging

from fastapi import APIRouter, Response

from keenguard.web.state import get_db

logger = logging.getLogger("keenguard.web.routes.export")

router = APIRouter(tags=["export"])


@router.get("/api/export/devices")
async def export_devices(format: str = "csv"):
    db = get_db()
    devices = await db.get_all_devices()
    if format == "json":
        return [d.model_dump() for d in devices]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["MAC", "IP", "Hostname", "Vendor", "Profile", "Online", "Blocked WAN", "Isolated LAN", "AirPlay", "DLNA", "First Seen", "Last Seen"])
    for d in devices:
        writer.writerow([d.mac, d.ip, d.custom_name or d.hostname, d.vendor, d.profile, d.is_online, d.is_blocked_wan, d.is_isolated_lan, d.airplay_allowed, d.dlna_allowed, d.first_seen, d.last_seen])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=devices.csv"})


@router.get("/api/export/events")
async def export_events(format: str = "csv", limit: int = 500):
    db = get_db()
    events = await db.get_recent_events(limit=limit)
    if format == "json":
        return [e.model_dump() for e in events]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Type", "Severity", "Target MAC", "Target IP", "Source", "Description"])
    for e in events:
        writer.writerow([e.id, e.timestamp, e.event_type, e.severity, e.target_mac, e.target_ip, e.source_name or e.source_ip, e.description])

    csv_bytes = output.getvalue().encode("utf-8-sig")
    return Response(content=csv_bytes, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=security_events.csv"})


@router.get("/api/export/audits")
async def export_audits():
    db = get_db()
    reports = await db.get_audit_reports(limit=50)
    return [r.model_dump() for r in reports]
