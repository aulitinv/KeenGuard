"""Device & network traffic audit sessions, reports, and live traffic routes."""
from datetime import datetime, timezone
import json
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from keenguard.config import settings
from keenguard.core.classifier import DeviceClassifier
from keenguard.web.state import (
    get_db,
    get_audit_manager,
)
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.audit")

router = APIRouter(tags=["audit"])

NETWORK_AUDIT_TARGETS = {"NETWORK", "__ALL_NETWORK__", "__IOT_ONLY__", "__UNTRUSTED__"}


def _validate_audit_target(target: str) -> str:
    """Validates audit target string (either special keyword or valid IEEE 802 MAC)."""
    cleaned = target.upper()
    if cleaned in NETWORK_AUDIT_TARGETS:
        return cleaned
    if not DeviceClassifier.is_valid_mac(cleaned):
        raise HTTPException(status_code=400, detail=f"Invalid MAC address format: {target}")
    return cleaned


class AuditStartRequest(BaseModel):
    duration_seconds: Optional[int] = 300
    scope: Optional[str] = "all"  # "all", "iot_only", "untrusted"


class NetworkAuditStartRequest(BaseModel):
    duration_seconds: Optional[int] = 300
    scope: Optional[str] = "all"  # "all", "iot_only", "untrusted"


@router.post("/api/audit/{mac}/start")
async def start_device_audit(mac: str, req: AuditStartRequest):
    db = get_db()
    audit_manager = get_audit_manager()
    mac_upper = _validate_audit_target(mac)
    dur_sec = req.duration_seconds if req.duration_seconds is not None else 300
    if mac_upper in ("NETWORK", "__ALL_NETWORK__", "__IOT_ONLY__", "__UNTRUSTED__"):
        target_scope = "iot_only" if mac_upper == "__IOT_ONLY__" else ("untrusted" if mac_upper == "__UNTRUSTED__" else (req.scope or "all"))
        res = await audit_manager.start_network_audit(
            duration_seconds=dur_sec,
            scope=target_scope
        )
        await ws_manager.broadcast({"type": "network_audit_started", "session": res})
        return res

    dev = await db.get_device(mac_upper)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    res = await audit_manager.start_audit(
        mac=mac_upper,
        ip=dev.ip,
        hostname=dev.custom_name or dev.hostname,
        vendor=dev.vendor,
        duration_seconds=dur_sec,
        profile=dev.profile
    )
    await ws_manager.broadcast({"type": "audit_started", "mac": mac_upper, "session": res})
    return res


@router.post("/api/audit/{mac}/stop")
async def stop_device_audit(mac: str):
    audit_manager = get_audit_manager()
    mac_upper = _validate_audit_target(mac)
    if mac_upper == "NETWORK":
        report = await audit_manager.stop_network_audit()
        if not report:
            raise HTTPException(status_code=404, detail="No active network audit session")
        await ws_manager.broadcast({"type": "network_audit_stopped", "report": report})
        return report

    report = await audit_manager.stop_audit(mac_upper)
    if not report:
        raise HTTPException(status_code=404, detail="No active audit session for this device")
    await ws_manager.broadcast({"type": "audit_stopped", "mac": mac_upper, "report": report})
    return report


@router.post("/api/audit/network/start")
async def start_network_audit_endpoint(req: NetworkAuditStartRequest):
    audit_manager = get_audit_manager()
    dur_sec = req.duration_seconds if req.duration_seconds is not None else 300
    res = await audit_manager.start_network_audit(
        duration_seconds=dur_sec,
        scope=req.scope or "all"
    )
    await ws_manager.broadcast({"type": "network_audit_started", "session": res})
    return res


@router.post("/api/audit/network/stop")
async def stop_network_audit_endpoint():
    audit_manager = get_audit_manager()
    report = await audit_manager.stop_network_audit()
    if not report:
        raise HTTPException(status_code=400, detail="Нет активной сессии аудита сети")
    await ws_manager.broadcast({"type": "network_audit_stopped", "report": report})
    return report


@router.get("/api/audit/network/status")
async def get_network_audit_status_endpoint():
    audit_manager = get_audit_manager()
    status = audit_manager.get_network_audit_status()
    if not status:
        return {"is_active": False}
    return status


@router.get("/api/audit/network/latest_report")
async def get_latest_network_audit_report_endpoint():
    db = get_db()
    reports = await db.get_audit_reports(limit=50)
    net_reports = [r for r in reports if r.mac == "NETWORK" or r.id.startswith("net_audit_")]
    if not net_reports:
        raise HTTPException(status_code=404, detail="Отчет аудита сети не найден")
    r = net_reports[0]
    try:
        return json.loads(r.report_json)
    except Exception:
        return r.model_dump()


@router.get("/api/audit/{mac}/status")
async def get_audit_status(mac: str):
    audit_manager = get_audit_manager()
    target = _validate_audit_target(mac)
    if target == "NETWORK":
        status = audit_manager.get_network_audit_status()
        if not status:
            return {"is_active": False}
        return status

    session = audit_manager.get_session(target)
    if not session or not session.is_active:
        return {"is_active": False}
    elapsed = int((datetime.now(timezone.utc) - session.start_time).total_seconds())
    return {
        "is_active": True,
        "session_id": session.session_id,
        "mac": session.mac,
        "ip": session.ip,
        "hostname": session.hostname,
        "elapsed_seconds": elapsed,
        "duration_limit": session.duration_seconds,
        "flows_count": len(session.flows),
        "total_bytes": session.total_bytes_up + session.total_bytes_down,
        "total_packets": session.total_packets_up + session.total_packets_down,
        "top_flows": sorted(list(session.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)[:5],
        "top_domains": list(session.dns_queries.values())[:5]
    }


@router.get("/api/audit/{mac}/latest_report")
async def get_latest_audit_report(mac: str):
    db = get_db()
    target = _validate_audit_target(mac)
    if target == "NETWORK":
        reports = await db.get_audit_reports(limit=50)
        net_reports = [r for r in reports if r.mac == "NETWORK" or r.id.startswith("net_audit_")]
        if not net_reports:
            raise HTTPException(status_code=404, detail="No network audit reports found")
        r = net_reports[0]
        try:
            return json.loads(r.report_json)
        except Exception:
            return r.model_dump()

    reports = await db.get_audit_reports(mac=target, limit=1)
    if not reports:
        raise HTTPException(status_code=404, detail="No audit reports found for this device")
    r = reports[0]
    try:
        data = json.loads(r.report_json)
        return data
    except Exception:
        return r.model_dump()


@router.get("/api/audit/active")
async def get_active_audits():
    audit_manager = get_audit_manager()
    active = []
    now = datetime.now(timezone.utc)

    # Check network session
    net_s = audit_manager.active_network_session
    if net_s and net_s.is_active:
        elapsed = int((now - net_s.start_time).total_seconds())
        active.append({
            "session_id": net_s.session_id,
            "mac": "NETWORK",
            "ip": "0.0.0.0",
            "hostname": f"Вся сеть ({net_s.scope})",
            "vendor": "Keenetic Network",
            "profile": "network",
            "is_network": True,
            "scope": net_s.scope,
            "devices_count": len(net_s.device_stats),
            "elapsed_seconds": elapsed,
            "duration_seconds": net_s.duration_seconds,
            "flows_count": len(net_s.flows),
            "total_bytes": net_s.total_bytes_up + net_s.total_bytes_down,
            "total_packets": len(net_s.packets),
            "quarantined_count": len(net_s.quarantined_devices),
            "lateral_movements_count": len(net_s.lateral_movements),
            "top_flows": sorted(list(net_s.flows.values()), key=lambda x: x.get("bytes_up", 0) + x.get("bytes_down", 0), reverse=True)[:5],
            "top_domains": list(net_s.dns_queries.values())[:5]
        })

    for mac, session in audit_manager.active_sessions.items():
        if session.is_active:
            elapsed = int((now - session.start_time).total_seconds())
            active.append({
                "session_id": session.session_id,
                "mac": session.mac,
                "ip": session.ip,
                "hostname": session.hostname,
                "vendor": session.vendor,
                "profile": session.profile,
                "is_network": False,
                "elapsed_seconds": elapsed,
                "duration_seconds": session.duration_seconds,
                "flows_count": len(session.flows),
                "total_bytes": session.total_bytes_up + session.total_bytes_down,
                "total_packets": session.total_packets_up + session.total_packets_down,
                "top_flows": sorted(list(session.flows.values()), key=lambda x: x.get("bytes_up", 0) + x.get("bytes_down", 0), reverse=True)[:5],
                "top_domains": list(session.dns_queries.values())[:5]
            })
    return active


@router.get("/api/audit/reports")
async def list_audit_reports(limit: int = 50):
    db = get_db()
    reports = await db.get_audit_reports(limit=limit)
    return [r.model_dump() for r in reports]


@router.delete("/api/audit/reports/{report_id}")
async def delete_single_audit_report(report_id: str):
    db = get_db()
    pcap_file = await db.delete_audit_report(report_id)
    if pcap_file is None:
        raise HTTPException(status_code=404, detail="Audit report not found")
    if pcap_file:
        try:
            dump_path = settings.pcap_dir / pcap_file
            if dump_path.exists():
                dump_path.unlink()
        except Exception as e:
            logger.warning("Could not delete PCAP file %s: %s", pcap_file, e)

    await ws_manager.broadcast({"type": "audit_report_deleted", "id": report_id})
    return {"status": "ok", "id": report_id, "deleted": True}


@router.delete("/api/audit/reports")
async def clear_audit_reports_api(older_than_days: Optional[int] = None):
    db = get_db()
    pcap_files = await db.clear_audit_reports(older_than_days=older_than_days)
    for pf in pcap_files:
        try:
            dump_path = settings.pcap_dir / pf
            if dump_path.exists():
                dump_path.unlink()
        except OSError as e:
            logger.debug("Failed to unlink old audit pcap file %s: %s", pf, e)

    await ws_manager.broadcast({"type": "audit_reports_cleared", "older_than_days": older_than_days, "count": len(pcap_files)})
    return {"status": "ok", "deleted": len(pcap_files)}


@router.get("/api/audit/report/{report_id}")
async def get_audit_report_detail(report_id: str):
    db = get_db()
    r = await db.get_audit_report_by_id(report_id)
    if not r:
        raise HTTPException(status_code=404, detail="Audit report not found")
    try:
        data = json.loads(r.report_json)
        return data
    except Exception:
        return r.model_dump()


@router.get("/api/audit/pcap/{filename}")
async def download_audit_pcap(filename: str):
    file_path = settings.pcap_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="PCAP file not found")
    return FileResponse(path=str(file_path), filename=filename, media_type="application/vnd.tcpdump.pcap")


@router.get("/api/traffic/live")
async def get_live_traffic():
    db = get_db()
    summary = await db.get_network_traffic_summary(limit=30)
    return summary
