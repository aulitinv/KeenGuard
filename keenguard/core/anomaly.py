"""Anomaly detection engine: Camera leaks, UPnP holes, LAN scans, IoT botnet floods."""
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Any

from keenguard.config import settings
from keenguard.db.models import SecurityEvent, DeviceRecord
from keenguard.db.database import db as global_db, Database
from keenguard.core.keenetic import UPnPMapping
from keenguard.core.routers import router_manager

from keenguard.core.audit import is_lan_ip

logger = logging.getLogger("keenguard.anomaly")

class AnomalyDetector:
    def __init__(self, database: Optional[Database] = None, db: Optional[Database] = None):
        self.db = database or db or global_db
        # ARP sweep tracker: src_ip -> list of (timestamp, dst_ip)
        self.arp_probes: Dict[str, List[tuple]] = defaultdict(list)
        # Previous traffic counters for upload rate calculation: mac -> (timestamp, tx_bytes)
        self.last_tx_counters: Dict[str, tuple] = {}
        # IoT packet rate tracker: mac -> list of timestamps
        self.iot_packets: Dict[str, List[float]] = defaultdict(list)
        # MAC-IP binding trackers: mac -> (ip, timestamp), ip -> (mac, timestamp)
        self.mac_ip_tracker: Dict[str, tuple] = {}
        self.ip_mac_tracker: Dict[str, tuple] = {}
        # Deduplication cache: key -> timestamp
        self.dedup_cache: Dict[str, float] = {}

    def _is_deduped(self, key: str, window_seconds: Optional[int] = None) -> bool:
        """Returns True if the notification key is within its deduplication window."""
        now = time.time()
        win = window_seconds if window_seconds is not None else getattr(settings, "notification_dedup_window_seconds", 60)
        
        # Purge stale keys occasionally
        if len(self.dedup_cache) > 200:
            self.dedup_cache = {k: v for k, v in self.dedup_cache.items() if now - v < win * 2}

        last_time = self.dedup_cache.get(key)
        if last_time is not None and (now - last_time) < win:
            return True

        self.dedup_cache[key] = now
        return False

    async def check_mac_ip_binding(self, mac: Optional[str], ip: Optional[str]):
        """
        Detects MAC conflict / ARP spoofing:
        - When an IP is claimed by two different MACs within 30s (ARP spoofing / IP collision)
        - When a single MAC is active concurrently on two different IPs within 30s
        """
        if not getattr(settings, "mac_conflict_detection_enabled", True):
            return

        if not mac or not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return
        if ip.startswith("169.254.") or ip.startswith("127.") or ip.startswith("224."):
            return

        clean_mac = mac.upper()
        if router_manager.is_router_entity(ip=ip, mac=clean_mac):
            return

        now = time.time()

        # 1. Check IP claimed by multiple MACs (ARP Spoofing / IP collision)
        if ip in self.ip_mac_tracker:
            prev_mac, last_seen = self.ip_mac_tracker[ip]
            if prev_mac != clean_mac and (now - last_seen <= 30.0):
                dedup_key = f"ip_conflict:{ip}:{min(clean_mac, prev_mac)}"
                if not self._is_deduped(dedup_key):
                    desc = (
                        f"Конфликт IP-адреса / возможное ARP-спуфинг: IP {ip} одновременно заявляют "
                        f"MAC {prev_mac} и {clean_mac} (интервал: {now - last_seen:.1f}с)!"
                    )
                    logger.warning(desc)
                    event = SecurityEvent(
                        event_type="arp_spoofing",
                        severity="critical",
                        target_mac=clean_mac,
                        target_ip=ip,
                        description=desc,
                        details={
                            "conflicting_mac": prev_mac,
                            "interval_sec": round(now - last_seen, 2)
                        }
                    )
                    await self.db.record_event(event)

        # 2. Check single MAC active concurrently on multiple IPs
        if clean_mac in self.mac_ip_tracker:
            prev_ip, last_seen = self.mac_ip_tracker[clean_mac]
            if prev_ip != ip and (now - last_seen <= 30.0):
                dedup_key = f"mac_conflict:{clean_mac}:{min(prev_ip, ip)}"
                if not self._is_deduped(dedup_key):
                    desc = (
                        f"Конфликт MAC-адреса: устройство {clean_mac} одновременно активно "
                        f"на двух разных IP-адресах ({prev_ip} и {ip}) за последние {now - last_seen:.1f}с!"
                    )
                    logger.warning(desc)
                    event = SecurityEvent(
                        event_type="mac_conflict",
                        severity="warning",
                        target_mac=clean_mac,
                        target_ip=ip,
                        description=desc,
                        details={
                            "conflicting_ip": prev_ip,
                            "interval_sec": round(now - last_seen, 2)
                        }
                    )
                    await self.db.record_event(event)

        # Update bindings
        self.ip_mac_tracker[ip] = (clean_mac, now)
        self.mac_ip_tracker[clean_mac] = (ip, now)

        # Purge stale bindings
        if len(self.ip_mac_tracker) > 300:
            self.ip_mac_tracker = {k: v for k, v in self.ip_mac_tracker.items() if now - v[1] < 300.0}
        if len(self.mac_ip_tracker) > 300:
            self.mac_ip_tracker = {k: v for k, v in self.mac_ip_tracker.items() if now - v[1] < 300.0}

    async def check_upnp_anomalies(self, upnp_rules: List[UPnPMapping], devices: Dict[str, DeviceRecord]):
        """Detects if security cameras or untrusted IoT have open ports to the WAN."""
        for rule in upnp_rules:
            # Find device by internal IP
            matching_dev = next((d for d in devices.values() if d.ip == rule.int_ip), None)
            if matching_dev and matching_dev.profile in ["camera", "iot", "smart_home_hub"]:
                desc = f"CRITICAL: {matching_dev.profile.upper()} '{matching_dev.hostname or matching_dev.ip}' has an open UPnP WAN port {rule.ext_port}->{rule.int_port}/{rule.protocol}!"
                logger.warning(desc)

                # Record critical security event
                event = SecurityEvent(
                    event_type="upnp_detected",
                    severity="critical",
                    target_mac=matching_dev.mac,
                    target_ip=matching_dev.ip,
                    description=desc,
                    details={
                        "ext_port": rule.ext_port,
                        "int_port": rule.int_port,
                        "protocol": rule.protocol,
                        "description": rule.description
                    }
                )
                await self.db.record_event(event)

                # Auto-delete dangerous UPnP rule on router (REQ-3: UPnP auto-audit and ban)
                await router_manager.delete_upnp_mapping(rule.protocol, rule.ext_port)

    async def check_camera_upload_leak(
        self,
        device: DeviceRecord,
        current_tx_bytes: int,
        active_nat_flows: Optional[List[Dict[str, Any]]] = None
    ):
        """
        Separates external WAN upload leak from authorized LAN/NVR streaming.
        Respects designated_nvr_ip and user notification preferences for WAN/LAN streams.
        """
        if device.profile != "camera":
            return

        now = time.time()
        prev = self.last_tx_counters.get(device.mac)
        self.last_tx_counters[device.mac] = (now, current_tx_bytes)

        if not prev:
            return

        prev_time, prev_bytes = prev
        delta_time = now - prev_time
        if delta_time < 5.0 or current_tx_bytes < prev_bytes:
            return

        delta_bytes = current_tx_bytes - prev_bytes
        # Calculate rate in kbps
        tx_rate_kbps = (delta_bytes * 8) / (delta_time * 1024)

        if tx_rate_kbps <= settings.camera_upload_threshold_kbps:
            return

        target_nvr = getattr(device, "designated_nvr_ip", None)
        wan_stream_detected = False
        lan_stream_detected = False

        if active_nat_flows:
            for flow in active_nat_flows:
                src = flow.get("src_ip")
                dst = flow.get("dst_ip")
                if src == device.ip:
                    if dst and is_lan_ip(dst):
                        if target_nvr and dst == target_nvr:
                            # Streaming to designated NVR is authorized
                            continue
                        lan_stream_detected = True
                    else:
                        wan_stream_detected = True
        else:
            # Default assumption if flow breakdown not supplied:
            wan_stream_detected = True

        # WAN upload notification
        if wan_stream_detected and getattr(settings, "camera_notify_wan_stream", True):
            dedup_key = f"camera_wan_leak:{device.mac}"
            if not self._is_deduped(dedup_key):
                desc = (
                    f"Камера '{device.hostname or device.ip}' передает интенсивный видеопоток во внешнюю сеть (WAN): "
                    f"{tx_rate_kbps:.1f} Кбит/с (порог: {settings.camera_upload_threshold_kbps} Кбит/с)!"
                )
                logger.warning(desc)
                event = SecurityEvent(
                    event_type="camera_leak",
                    severity="warning",
                    target_mac=device.mac,
                    target_ip=device.ip,
                    description=desc,
                    details={
                        "upload_rate_kbps": round(tx_rate_kbps, 1),
                        "stream_type": "wan",
                        "designated_nvr": target_nvr
                    }
                )
                await self.db.record_event(event)

        # LAN streaming notification
        if lan_stream_detected and getattr(settings, "camera_notify_lan_stream", False):
            dedup_key = f"camera_lan_stream:{device.mac}"
            if not self._is_deduped(dedup_key):
                desc = (
                    f"Камера '{device.hostname or device.ip}' передает локальный видеопоток (LAN): "
                    f"{tx_rate_kbps:.1f} Кбит/с на узел сети."
                )
                logger.info(desc)
                event = SecurityEvent(
                    event_type="camera_lan_stream",
                    severity="info",
                    target_mac=device.mac,
                    target_ip=device.ip,
                    description=desc,
                    details={
                        "stream_rate_kbps": round(tx_rate_kbps, 1),
                        "stream_type": "lan",
                        "designated_nvr": target_nvr
                    }
                )
                await self.db.record_event(event)

    async def record_arp_probe(self, src_mac: Optional[str], src_ip: Optional[str], dst_ip: Optional[str]):
        # Ignore invalid, self-queries, or unassigned RFC 5227 DAD probes (0.0.0.0)
        if not src_ip or not dst_ip or src_ip == dst_ip or src_ip == "0.0.0.0":
            return

        # Ignore ARP requests originated by the router or network gateways (RFC 5227 / neighbor discovery)
        clean_mac = src_mac.upper() if src_mac else None
        if router_manager.is_router_entity(ip=src_ip, mac=clean_mac):
            return

        now = time.time()
        probes = self.arp_probes[src_ip]
        probes.append((now, dst_ip))
        # Keep probes within last 10 seconds
        self.arp_probes[src_ip] = [p for p in probes if now - p[0] <= 10.0]

        # Count unique probed destination IPs
        unique_targets = {p[1] for p in self.arp_probes[src_ip]}
        if len(unique_targets) >= settings.lan_scan_threshold:
            self.arp_probes[src_ip].clear()  # Reset counter to avoid alert spam
            desc = f"Device at {src_ip} ({src_mac or 'Unknown MAC'}) is scanning the local network! Probed {len(unique_targets)} IPs within 10s."
            logger.warning(desc)
            event = SecurityEvent(
                event_type="lan_scan",
                severity="warning",
                source_mac=src_mac,
                source_ip=src_ip,
                description=desc,
                details={"probed_ips_count": len(unique_targets)}
            )
            await self.db.record_event(event)

    async def record_iot_packet(self, mac: str, ip: str, hostname: Optional[str] = None):
        """Detects DDoS or flood activity from IoT devices."""
        now = time.time()
        pkts = self.iot_packets[mac]
        pkts.append(now)
        self.iot_packets[mac] = [t for t in pkts if now - t <= 1.0]

        if len(self.iot_packets[mac]) > settings.iot_packet_rate_threshold:
            self.iot_packets[mac].clear()
            desc = f"IoT device '{hostname or ip}' flood detected: >{settings.iot_packet_rate_threshold} pkts/sec!"
            logger.error(desc)
            event = SecurityEvent(
                event_type="iot_flood",
                severity="critical",
                target_mac=mac,
                target_ip=ip,
                description=desc,
                details={"rate_pps": settings.iot_packet_rate_threshold}
            )
            await self.db.record_event(event)

anomaly_detector = AnomalyDetector()


def _on_anomaly_config_change(key: str, value: Any) -> None:
    if key == "camera_upload_threshold_kbps" and value is not None:
        try:
            anomaly_detector.camera_upload_threshold_kbps = float(value)
        except (ValueError, TypeError):
            pass
    elif key == "notification_dedup_window_seconds" and value is not None:
        try:
            anomaly_detector.notification_dedup_window_seconds = int(value)
        except (ValueError, TypeError):
            pass
    elif key == "mac_conflict_detection_enabled" and value is not None:
        anomaly_detector.mac_conflict_detection_enabled = bool(value)
    elif key == "iot_packet_rate_threshold" and value is not None:
        try:
            anomaly_detector.iot_packet_rate_threshold = int(value)
        except (ValueError, TypeError):
            pass
    elif key == "lan_scan_threshold" and value is not None:
        try:
            anomaly_detector.lan_scan_threshold = int(value)
        except (ValueError, TypeError):
            pass


try:
    from keenguard.core.config_service import config_service
    for _k in (
        "camera_upload_threshold_kbps",
        "notification_dedup_window_seconds",
        "mac_conflict_detection_enabled",
        "iot_packet_rate_threshold",
        "lan_scan_threshold",
    ):
        config_service.subscribe(_k, _on_anomaly_config_change)
except ImportError:
    pass

