"""Manager coordinating on-demand and network-wide traffic audit sessions."""
import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from scapy.all import Packet, Ether, IP, IPv6, rdpcap

from keenguard.config import settings as default_settings
from keenguard.db.database import db as default_db
from keenguard.db.models import SecurityEvent, AuditReportRecord
from keenguard.core.routers import router_manager
from keenguard.core.audit.session import AuditSession, NetworkAuditSession

logger = logging.getLogger("keenguard.audit.manager")


def _get_db():
    import sys
    audit_mod = sys.modules.get("keenguard.core.audit")
    if audit_mod and hasattr(audit_mod, "db"):
        return audit_mod.db
    return default_db


def _get_settings():
    import sys
    audit_mod = sys.modules.get("keenguard.core.audit")
    if audit_mod and hasattr(audit_mod, "settings"):
        return audit_mod.settings
    return default_settings


class TrafficAuditManager:
    def __init__(self, pcap_dir: Optional[Path] = None):
        self._custom_pcap_dir = pcap_dir
        self.active_sessions: Dict[str, AuditSession] = {}
        self.active_network_session: Optional[NetworkAuditSession] = None
        self._lock = asyncio.Lock()
        self.suspicious_callback = None

    @property
    def pcap_dir(self) -> Path:
        return self._custom_pcap_dir or _get_settings().pcap_dir

    @property
    def network_session(self) -> Optional[NetworkAuditSession]:
        return self.active_network_session

    def set_suspicious_callback(self, callback):
        self.suspicious_callback = callback

    def get_session(self, mac: str) -> Optional[AuditSession]:
        return self.active_sessions.get(mac.upper())

    def get_network_session(self) -> Optional[NetworkAuditSession]:
        return self.active_network_session

    def get_network_audit_status(self) -> Optional[Dict[str, Any]]:
        s = self.active_network_session
        if not s or not s.is_active:
            return None
        elapsed = int((datetime.now(timezone.utc) - s.start_time).total_seconds())
        return {
            "session_id": s.session_id,
            "scope": s.scope,
            "duration_seconds": s.duration_seconds,
            "elapsed_seconds": elapsed,
            "devices_count": len(s.device_stats),
            "flows_count": len(s.flows),
            "total_packets": len(s.packets),
            "total_bytes": s.total_bytes_up + s.total_bytes_down,
            "quarantined_count": len(s.quarantined_devices),
            "lateral_movements_count": len(s.lateral_movements),
            "is_active": True
        }

    async def start_network_audit(self, duration_seconds: int = 300, scope: str = "all") -> Dict[str, Any]:
        async with self._lock:
            if self.active_network_session and self.active_network_session.is_active:
                await self.stop_network_audit()

            session = NetworkAuditSession(duration_seconds=duration_seconds, scope=scope)
            self.active_network_session = session
            session._poller_task = asyncio.create_task(self._network_session_loop(session))

            logger.info("Started network-wide traffic audit (scope: %s, duration: %ds)", scope, duration_seconds)
            return {
                "status": "started",
                "session_id": session.session_id,
                "scope": scope,
                "duration_seconds": duration_seconds
            }

    async def _network_session_loop(self, session: NetworkAuditSession):
        elapsed = 0
        db = _get_db()
        try:
            while session.is_active:
                try:
                    devices = await db.get_all_devices()
                    devices_by_ip = {d.ip: d for d in devices if d.ip}
                    presets_list = await db.get_presets()
                    presets_dict = {p.id: p for p in presets_list}
                    nat_entries = await router_manager.get_nat_table()
                    session.update_nat_table(nat_entries, devices_by_ip, on_suspicious_callback=self.suspicious_callback, presets_dict=presets_dict)
                except Exception as e:
                    logger.error("Error updating network audit NAT table: %s", e)

                await asyncio.sleep(2.0)
                elapsed += 2
                if session.duration_seconds > 0 and elapsed >= session.duration_seconds:
                    logger.info("Network audit session duration reached. Auto-stopping.")
                    await self.stop_network_audit()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error in network audit loop: %s", e)

    async def stop_network_audit(self) -> Optional[Dict[str, Any]]:
        async with self._lock:
            session = self.active_network_session
            if not session or not session.is_active:
                return None

            session.is_active = False
            db = _get_db()
            cur_task = asyncio.current_task()
            if session._poller_task and session._poller_task != cur_task and not session._poller_task.done():
                session._poller_task.cancel()

            try:
                devices = await db.get_all_devices()
                devices_by_ip = {d.ip: d for d in devices if d.ip}
                presets_list = await db.get_presets()
                presets_dict = {p.id: p for p in presets_list}
                nat_entries = await router_manager.get_nat_table()
                session.update_nat_table(nat_entries, devices_by_ip, on_suspicious_callback=self.suspicious_callback, presets_dict=presets_dict)
            except Exception as e:
                logger.warning("Failed to update final NAT table for network audit: %s", e)

            report = session.generate_network_report()

            db_record = AuditReportRecord(
                id=report["id"],
                mac="NETWORK",
                ip="0.0.0.0",
                hostname=f"Аудит всей сети ({report['scope']})",
                created_at=report["start_time"],
                duration_seconds=report["duration_seconds"],
                total_bytes=report["total_bytes"],
                total_packets=report["total_packets"],
                risk_level=report["risk_level"],
                summary=report["findings"][0] if report["findings"] else "Сетевой аудит завершен",
                report_json=json.dumps(report, ensure_ascii=False),
                pcap_file=report["pcap_file"]
            )
            await db.save_audit_report(db_record)

            await db.record_event(SecurityEvent(
                event_type="network_audit_completed",
                severity="warning" if report["risk_level"] in ["medium", "high", "critical"] else "info",
                target_mac="NETWORK",
                target_ip="0.0.0.0",
                description=f"Завершен аудит всей сети: {report['devices_count']} устройств, {report['flows_count']} потоков, риск: {report['risk_level']}",
                details={"devices_count": report["devices_count"], "flows_count": report["flows_count"], "total_bytes": report["total_bytes"], "findings": report["findings"]},
                pcap_file=report["pcap_file"]
            ))

            for dq in session.dns_queries.values():
                try:
                    await db.record_dns_query(dq["domain"], mac="NETWORK", ip="0.0.0.0")
                except Exception as e:
                    logger.debug("Failed recording DNS query %s during network audit: %s", dq.get("domain"), e)

            logger.info("Network traffic audit completed. Report %s saved.", report["id"])
            return report

    async def start_audit(self, mac: str, ip: Optional[str] = None, hostname: Optional[str] = None,
                          vendor: Optional[str] = None, duration_seconds: int = 300,
                          profile: Optional[str] = None) -> Dict[str, Any]:
        mac = mac.upper()
        async with self._lock:
            if mac in self.active_sessions:
                await self.stop_audit(mac)

            db = _get_db()
            dev_profile = profile
            dev = None
            dev_preset = None
            try:
                dev = await db.get_device(mac)
                if dev:
                    if not dev_profile or dev_profile == "unassigned":
                        dev_profile = dev.profile
                    if not hostname and dev.hostname:
                        hostname = dev.hostname
                    if not ip and dev.ip:
                        ip = dev.ip
                    if not vendor and dev.vendor:
                        vendor = dev.vendor
                    if dev.preset_id:
                        dev_preset = await db.get_preset(dev.preset_id)
            except Exception as e:
                logger.debug("Failed retrieving device metadata for %s: %s", mac, e)

            if not dev_preset and dev_profile:
                try:
                    dev_preset = await db.get_preset(f"preset_{dev_profile}")
                except Exception as e:
                    logger.debug("Failed retrieving default preset for %s: %s", dev_profile, e)

            session = AuditSession(
                mac=mac,
                ip=ip,
                hostname=hostname,
                vendor=vendor,
                duration_seconds=duration_seconds,
                profile=dev_profile,
                device=dev,
                preset=dev_preset
            )

            # Start hardware packet capture if IP is known and capture is supported
            backend = router_manager.get_backend()
            if session.ip and session.ip != "0.0.0.0":
                try:
                    if await backend.is_packet_capture_supported():
                        start_res = await backend.start_packet_capture(
                            interface="Bridge0",
                            target_ip=session.ip,
                            duration_seconds=session.duration_seconds
                        )
                        if start_res and start_res.get("status") == "ok":
                            session.capture_source = "router_hardware"
                            session._hw_capture_active = True
                            logger.info("%s hardware capture started for audit %s (%s, IP: %s)", backend.platform_name, session.session_id, mac, session.ip)
                except Exception as e:
                    logger.debug("Failed to start router hardware capture for audit %s: %s", session.session_id, e)

            self.active_sessions[mac] = session
            session._poller_task = asyncio.create_task(self._session_loop(session))

            logger.info("Started traffic audit for %s (%s, IP: %s, Profile: %s, Source: %s) for %d sec",
                        hostname, mac, ip, dev_profile, session.capture_source, duration_seconds)
            return {
                "status": "started",
                "session_id": session.session_id,
                "mac": mac,
                "ip": session.ip,
                "capture_source": session.capture_source,
                "duration_seconds": duration_seconds
            }

    async def _session_loop(self, session: AuditSession):
        elapsed = 0
        try:
            while session.is_active:
                if session.ip:
                    entries = await router_manager.get_device_nat_connections(session.ip)
                    session.update_nat_entries(entries, on_suspicious_callback=self.suspicious_callback)

                await asyncio.sleep(2.0)
                elapsed += 2
                if session.duration_seconds > 0 and elapsed >= session.duration_seconds:
                    logger.info("Audit session duration reached for %s. Auto-stopping.", session.mac)
                    await self.stop_audit(session.mac)
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error in audit session loop for %s: %s", session.mac, e)

    async def stop_audit(self, mac: str) -> Optional[Dict[str, Any]]:
        mac = mac.upper()
        async with self._lock:
            session = self.active_sessions.pop(mac, None)
            if not session:
                return None

            session.is_active = False
            db = _get_db()
            settings = _get_settings()
            cur_task = asyncio.current_task()
            if session._poller_task and session._poller_task != cur_task and not session._poller_task.done():
                session._poller_task.cancel()

            if session.ip:
                try:
                    entries = await router_manager.get_device_nat_connections(session.ip)
                    session.update_nat_entries(entries, on_suspicious_callback=self.suspicious_callback)
                except Exception as e:
                    logger.warning("Failed updating NAT entries for %s on audit stop: %s", session.ip, e)

            # If hardware capture was active on router, finalize it, download pcap and parse packets
            backend = router_manager.get_backend()
            if session._hw_capture_active:
                try:
                    cap_file = await backend.stop_packet_capture(interface="Bridge0")
                    if cap_file:
                        pcap_dest = settings.pcap_dir / session.pcap_filename
                        downloaded = await backend.download_capture_file(cap_file, pcap_dest)
                        if downloaded and pcap_dest.exists():
                            try:
                                rci_pkts = list(rdpcap(str(pcap_dest)))
                                if rci_pkts:
                                    for p in rci_pkts:
                                        session.add_packet(p)
                                    logger.info("Loaded %d hardware packets from %s for audit %s", len(rci_pkts), backend.platform_name, session.session_id)
                            except Exception as pe:
                                logger.debug("Error parsing downloaded audit PCAP: %s", pe)
                    await backend.reset_packet_capture(interface="Bridge0")
                except Exception as e:
                    logger.error("Error finalizing router capture for audit session %s: %s", session.session_id, e)

            report = session.generate_report()

            db_record = AuditReportRecord(
                id=report["id"],
                mac=report["mac"],
                ip=report["ip"],
                hostname=report["hostname"],
                created_at=report["start_time"],
                duration_seconds=report["duration_seconds"],
                total_bytes=report["total_bytes"],
                total_packets=report["total_packets"],
                risk_level=report["risk_level"],
                summary=report["findings"][0] if report["findings"] else "Аудит завершен",
                report_json=json.dumps(report, ensure_ascii=False),
                pcap_file=report["pcap_file"]
            )
            await db.save_audit_report(db_record)

            await db.record_event(SecurityEvent(
                event_type="audit_completed",
                severity="warning" if report["risk_level"] in ["medium", "high"] else "info",
                target_mac=report["mac"],
                target_ip=report["ip"],
                description=f"Завершен аудит трафика устройства '{report['hostname']}': {report['flows_count']} потоков, риск: {report['risk_level']}",
                details={"flows_count": report["flows_count"], "total_bytes": report["total_bytes"], "findings": report["findings"]},
                pcap_file=report["pcap_file"]
            ))

            for dq in session.dns_queries.values():
                try:
                    await db.record_dns_query(dq["domain"], mac=report["mac"], ip=report["ip"])
                except Exception as e:
                    logger.debug("Failed recording DNS query %s for %s: %s", dq.get("domain"), report.get("mac"), e)

            logger.info("Traffic audit completed for %s. Report %s saved.", mac, report["id"])
            return report

    def process_packet(self, pkt: Packet):
        if self.active_network_session and self.active_network_session.is_active:
            self.active_network_session.add_packet(pkt)

        if not self.active_sessions:
            return

        src_mac = pkt[Ether].src.upper() if Ether in pkt else None
        dst_mac = pkt[Ether].dst.upper() if Ether in pkt else None
        src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else None)
        dst_ip = pkt[IP].dst if IP in pkt else (pkt[IPv6].dst if IPv6 in pkt else None)

        for mac, session in self.active_sessions.items():
            if not session.is_active:
                continue
            if mac in (src_mac, dst_mac) or (session.ip and session.ip in (src_ip, dst_ip)):
                session.add_packet(pkt)


audit_manager = TrafficAuditManager()
