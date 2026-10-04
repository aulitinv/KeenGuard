"""Audit sessions tracking NAT entries, packet buffers, and LAN access policies."""
import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import struct
from typing import Dict, Any, List, Optional
from scapy.all import Packet, IP, IPv6, TCP, UDP, Raw

from keenguard.config import settings
from keenguard.db.models import DeviceRecord
from keenguard.core.audit.geoip import KNOWN_SERVICES, is_lan_ip, identify_geoip, is_streaming_service
from keenguard.core.audit.report import build_device_audit_report, build_network_audit_report, save_pcap_packets

logger = logging.getLogger("keenguard.audit.session")


def evaluate_lan_access_policy(
    src_profile: str,
    dst_ip: str,
    dport: int,
    designated_nvr_ip: Optional[str] = None,
    custom_allowed_ports: Optional[str] = None,
    preset_rules: Optional[Dict[str, Any]] = None,
    proto: str = "TCP",
    bytes_transferred: int = 0,
    packets_transferred: int = 0
) -> tuple[str, bool]:
    """
    Evaluates LAN communication risk and returns (risk_level, is_blocked).
    risk_level: 'safe', 'warning', 'critical'
    is_blocked: True if this violates policy and is a candidate for quarantine
    """
    # Router local gateway
    if dst_ip == "192.168.1.1":
        if dport in (53, 67, 68, 123):
            return "safe", False
        if dport in (80, 443, 22, 23, 8080):
            if src_profile in ("camera", "iot"):
                return "critical", True
            return "safe", False

    # Designated NVR access for cameras
    if designated_nvr_ip and dst_ip == designated_nvr_ip:
        return "safe", False

    # Check custom allowed ports
    if custom_allowed_ports:
        try:
            allowed_set = set(str(p).strip() for p in custom_allowed_ports.replace(",", " ").split())
            if str(dport) in allowed_set:
                return "safe", False
        except (AttributeError, ValueError) as err:
            logger.debug("Failed parsing custom_allowed_ports: %s", err)

    # Check legitimate media streaming protocols (Virtual Desktop, Steam Link, Moonlight, AirPlay, Cast, DLNA)
    is_stream, _ = is_streaming_service(dport, proto)
    if is_stream and src_profile in ("trusted", "smart_tv", "unassigned"):
        return "safe", False

    # Trusted devices (PCs, laptops, phones) have full LAN access by default
    if src_profile == "trusted" and not preset_rules:
        return "safe", False

    # High-throughput data session behavioral heuristic:
    # If bytes > 10 KB or packets > 10 on non-exploit ports, this is an established application session, NOT a scan probe!
    EXPLOIT_PORTS = {445, 139, 22, 23, 3389, 5555}
    is_data_stream = (dport >= 1024 and dport not in EXPLOIT_PORTS) and (bytes_transferred > 10240 or packets_transferred > 10)

    # If preset rules are provided
    if preset_rules:
        allowed = preset_rules.get("allowed_services", [])
        if "*" in allowed or str(dport) in allowed or any(f":{dport}" in a for a in allowed):
            return "safe", False

        # Streaming exceptions for presets
        if is_stream:
            return "safe", False

        alerts = preset_rules.get("alert_services", [])
        if str(dport) in alerts or any(f":{dport}" in a for a in alerts):
            return "warning", False

        blocked = preset_rules.get("blocked_services", [])
        if "*" in blocked or str(dport) in blocked or any(f":{dport}" in a for a in blocked):
            return "critical", True

        lan_policy = preset_rules.get("lan_to_lan_policy", "restricted")
        if lan_policy == "allow_all":
            return "safe", False
        elif lan_policy == "isolated":
            return "critical", True
        else:
            # "restricted" policy:
            # If high-throughput data stream or UDP ephemeral streaming on TV, allow as safe
            if is_data_stream:
                return "safe", False
            if src_profile == "smart_tv" and proto.upper() == "UDP" and dport >= 1024:
                return "safe", False
            return "warning", False

    # Default fallback behavior based on profile
    if src_profile == "trusted":
        return "safe", False
    elif src_profile == "smart_tv":
        if dport in (8200, 80, 443, 8080, 5353, 1900, 8008, 8009, 7000, 7100, 2869) or is_stream:
            return "safe", False
        if dport >= 1024 and (proto.upper() == "UDP" or is_data_stream):
            return "safe", False
        if dport in (22, 23, 445, 139, 3389):
            return "warning", False
        return "safe", False
    elif src_profile == "camera":
        if dport in (554, 80, 8080, 8000):
            return "safe", False
        if dport in (445, 139, 22, 23, 3389, 5555):
            return "critical", True
        return "warning", False
    elif src_profile == "iot":
        if dport in (1883, 8883, 5683, 53, 123):
            return "safe", False
        if dport in (445, 139, 22, 23, 3389, 5555):
            return "critical", True
        return "warning", False
    elif src_profile == "unassigned":
        if is_stream or is_data_stream:
            return "safe", False
        if dport in (1883, 8883, 5683, 53, 123, 80, 443):
            return "safe", False
        if dport in (445, 139, 22, 23, 3389, 5555):
            return "critical", True
        return "warning", False

    return "safe", False


def should_device_quarantine(
    profile: str,
    override: Optional[str] = None,
    scope: Optional[str] = None
) -> bool:
    override = override or "profile_default"
    scope = scope or getattr(settings, "auto_quarantine_scope", "iot_camera")

    if override == "always_quarantine":
        return True
    if override == "never_quarantine":
        return False

    if scope == "disabled":
        return False
    if scope == "custom_devices":
        return False
    if scope == "all_except_trusted":
        return profile != "trusted"
    return profile in ("camera", "iot", "unassigned")


def extract_dns_query(pkt: Packet) -> Optional[str]:
    try:
        from scapy.layers.dns import DNS, DNSQR
        if pkt.haslayer(DNS):
            dns_pkt = pkt[DNS]
            if dns_pkt.qd and isinstance(dns_pkt.qd, DNSQR):
                qname = dns_pkt.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                clean_d = qname.rstrip(".").lower()
                if clean_d and len(clean_d) > 2 and not clean_d.startswith("in-addr.arpa"):
                    return clean_d
        elif UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
            raw_payload = bytes(pkt[UDP].payload)
            if raw_payload:
                dns_parsed = DNS(raw_payload)
                if dns_parsed.qd and isinstance(dns_parsed.qd, DNSQR):
                    qname = dns_parsed.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    clean_d = qname.rstrip(".").lower()
                    if clean_d and len(clean_d) > 2 and not clean_d.startswith("in-addr.arpa"):
                        return clean_d
    except (struct.error, IndexError, AttributeError, ValueError, UnicodeDecodeError) as e:
        logger.debug("DNS packet parse exception: %s", e)
    return None


def extract_http_inspection(pkt: Packet) -> Optional[Dict[str, Any]]:
    """
    Extracts unencrypted HTTP request details from raw TCP packets (ports 80, 8080, etc.).
    Extracts HTTP method, Host, Path, User-Agent, and risk/category classification.
    """
    try:
        if TCP in pkt and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if not payload:
                return None

            dport = int(pkt[TCP].dport)
            sport = int(pkt[TCP].sport)

            first_line = payload.split(b"\r\n", 1)[0]
            verbs = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
            if any(first_line.startswith(v) for v in verbs):
                parts = first_line.decode("latin1", errors="replace").split()
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]

                    headers_raw = payload.decode("latin1", errors="replace").split("\r\n")
                    host = ""
                    user_agent = ""
                    content_type = ""
                    for h in headers_raw[1:]:
                        if not h or h == "\r\n":
                            break
                        if ":" in h:
                            k, v = h.split(":", 1)
                            k = k.strip().lower()
                            v = v.strip()
                            if k == "host":
                                host = v
                            elif k == "user-agent":
                                user_agent = v
                            elif k == "content-type":
                                content_type = v

                    category = "Веб-запрос"
                    path_lower = path.lower()
                    host_lower = host.lower()
                    if "ocsp" in host_lower or "ocsp" in path_lower:
                        category = "OCSP (Проверка отзывов сертификатов)"
                    elif "crl" in path_lower or ".crl" in path_lower:
                        category = "CRL (Список отозванных сертификатов)"
                    elif any(k in path_lower for k in ["update", "firmware", "upgrade", "ota"]):
                        category = "Обновление ПО / Прошивка"
                    elif any(k in path_lower for k in ["telemetry", "metrics", "analytic", "log", "beacon", "stat"]):
                        category = "Телеметрия / Аналитика"
                    elif any(k in path_lower for k in ["api", "json", "v1", "v2"]):
                        category = "API / Облачный сервис"
                    elif any(k in path_lower for k in [".jpg", ".png", ".webp", ".mp4", ".ts", ".m3u8"]):
                        category = "Медиа-контент"

                    dst_ip = pkt[IP].dst if IP in pkt else ""
                    return {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "method": method,
                        "host": host or dst_ip,
                        "path": path,
                        "user_agent": user_agent[:120] if user_agent else "—",
                        "content_type": content_type or "—",
                        "category": category,
                        "dst_ip": dst_ip,
                        "dst_port": dport
                    }
    except (struct.error, IndexError, AttributeError, ValueError, UnicodeDecodeError) as e:
        logger.debug("HTTP inspection parse exception: %s", e)
    return None


class AuditSession:
    def __init__(self, mac: str, ip: Optional[str] = None, hostname: Optional[str] = None,
                 vendor: Optional[str] = None, duration_seconds: int = 300, profile: Optional[str] = None,
                 device: Optional[DeviceRecord] = None, preset: Optional[Any] = None):
        self.session_id = f"audit_{mac.replace(':', '').lower()}_{int(datetime.now(timezone.utc).timestamp())}"
        self.mac = mac.upper()
        self.ip = ip or ""
        self.hostname = hostname or "Unknown Host"
        self.vendor = vendor or "Unknown Vendor"
        self.duration_seconds = duration_seconds
        self.profile = profile or (device.profile if device else "unassigned")
        self.device = device
        self.preset = preset
        self.start_time = datetime.now(timezone.utc)
        self.end_time: Optional[datetime] = None
        self.is_active = True
        self.packets: List[Packet] = []
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.dns_queries: Dict[str, Dict[str, Any]] = {}
        self.lan_probes: List[Dict[str, Any]] = []
        self.anomalies: List[Dict[str, Any]] = []
        self.total_bytes_up = 0
        self.total_bytes_down = 0
        self.total_packets_up = 0
        self.total_packets_down = 0
        self.auto_quarantined = False
        self.suspicious_reasons: List[str] = []
        self.pcap_filename = f"{self.session_id}.pcap"
        self.capture_source: str = "local_broadcast"
        self.http_inspections: List[Dict[str, Any]] = []
        self._hw_capture_active: bool = False
        self._poller_task: Optional[asyncio.Task] = None

    def add_packet(self, pkt: Packet):
        if len(self.packets) < 5000:
            self.packets.append(pkt)

        # Inspect DNS in packet via Scapy
        domain = extract_dns_query(pkt)
        if domain:
            self.dns_queries[domain] = {
                "domain": domain,
                "count": self.dns_queries.get(domain, {}).get("count", 0) + 1,
                "last_seen": datetime.now(timezone.utc).isoformat()
            }

        # Inspect unencrypted HTTP in packet via Scapy
        http_info = extract_http_inspection(pkt)
        if http_info:
            dedup_key = f"{http_info['method']}_{http_info['host']}_{http_info['path']}"
            if not any(f"{h['method']}_{h['host']}_{h['path']}" == dedup_key for h in self.http_inspections):
                if len(self.http_inspections) < 100:
                    self.http_inspections.append(http_info)

    def update_nat_entries(self, entries: List[Dict[str, Any]], on_suspicious_callback=None):
        for e in entries:
            dst_ip = e.get("dst", "")
            dport = int(e.get("dport", 0))
            proto = e.get("protocol", "TCP")
            b_up = int(e.get("bytes", 0))
            b_down = int(e.get("bytes-out", 0))
            p_up = int(e.get("packets", 0))
            p_down = int(e.get("packets-out", 0))
            total_bytes = b_up + b_down
            total_packets = p_up + p_down

            key = f"{proto}_{dst_ip}_{dport}"
            service_info = KNOWN_SERVICES.get(dport)
            if not service_info:
                is_stream_svc, stream_name = is_streaming_service(dport, proto)
                if is_stream_svc:
                    service_info = {"name": stream_name, "encrypted": True, "risk": "safe"}
                else:
                    service_info = {"name": f"Порт {dport}", "encrypted": False, "risk": "safe"}

            is_lan = is_lan_ip(dst_ip)

            # Assess risk using role-based policy
            risk = service_info.get("risk", "safe")
            is_hub = self.profile == "smart_home_hub" or (self.profile == "unassigned" and any(k in (self.hostname or "").lower() for k in ["spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt"]))
            is_discovery = dst_ip.endswith(".255") or dst_ip == "255.255.255.255" or dst_ip.startswith("224.") or dst_ip.startswith("239.") or dport in (54321, 5353, 1900, 5683)

            if is_lan and dst_ip != "192.168.1.1":
                if is_hub and is_discovery:
                    risk = "safe"  # Normal smart home peripheral discovery
                else:
                    preset_rules = self.preset.rules if (self.preset and hasattr(self.preset, "rules")) else (self.preset if isinstance(self.preset, dict) else None)
                    designated_nvr = self.device.designated_nvr_ip if self.device else None
                    custom_ports = self.device.custom_allowed_ports if self.device else None
                    risk, is_blocked = evaluate_lan_access_policy(
                        src_profile=self.profile,
                        dst_ip=dst_ip,
                        dport=dport,
                        designated_nvr_ip=designated_nvr,
                        custom_allowed_ports=custom_ports,
                        preset_rules=preset_rules,
                        proto=proto,
                        bytes_transferred=total_bytes,
                        packets_transferred=total_packets
                    )

                    is_stream_svc, _ = is_streaming_service(dport, proto)
                    is_media_data = is_stream_svc or (dport >= 1024 and total_bytes > 10240 and dport not in (445, 139, 22, 23, 3389, 5555))

                    if risk in ("warning", "critical") and not is_media_data:
                        probe_key = f"{dst_ip}:{dport}"
                        if not any(p["target"] == probe_key for p in self.lan_probes):
                            self.lan_probes.append({
                                "target": probe_key,
                                "ip": dst_ip,
                                "port": dport,
                                "service": service_info.get("name"),
                                "risk": risk,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            })
                            if is_blocked:
                                override = self.device.auto_quarantine_override if self.device else "profile_default"
                                can_quarantine = should_device_quarantine(self.profile, override=override, scope=getattr(settings, "auto_quarantine_scope", "iot_camera"))
                                if can_quarantine and getattr(settings, "audit_auto_quarantine_suspicious", True) and on_suspicious_callback:
                                    if not self.auto_quarantined:
                                        self.auto_quarantined = True
                                        reason = f"Подозрительная активность в LAN: обращение к {dst_ip}:{dport} ({service_info.get('name')})"
                                        self.suspicious_reasons.append(reason)
                                        if asyncio.iscoroutinefunction(on_suspicious_callback):
                                            asyncio.create_task(on_suspicious_callback(self.mac, self.ip, self.hostname or self.mac, reason))
                                        else:
                                            on_suspicious_callback(self.mac, self.ip, self.hostname or self.mac, reason)

            geo = identify_geoip(dst_ip)
            provider = f"{geo['flag']} {geo['provider']}"

            if key not in self.flows:
                self.flows[key] = {
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "protocol": proto,
                    "service": service_info.get("name"),
                    "is_encrypted": service_info.get("encrypted", False),
                    "provider": provider,
                    "country": geo.get("country", "WAN"),
                    "flag": geo.get("flag", "🌐"),
                    "is_lan": is_lan,
                    "risk": risk,
                    "bytes_up": b_up,
                    "bytes_down": b_down,
                    "packets_up": p_up,
                    "packets_down": p_down,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                }
            else:
                self.flows[key]["bytes_up"] = max(self.flows[key]["bytes_up"], b_up)
                self.flows[key]["bytes_down"] = max(self.flows[key]["bytes_down"], b_down)
                self.flows[key]["packets_up"] = max(self.flows[key]["packets_up"], p_up)
                self.flows[key]["packets_down"] = max(self.flows[key]["packets_down"], p_down)
                self.flows[key]["last_seen"] = datetime.now(timezone.utc).isoformat()

        self.total_bytes_up = sum(f["bytes_up"] for f in self.flows.values())
        self.total_bytes_down = sum(f["bytes_down"] for f in self.flows.values())
        self.total_packets_up = sum(f["packets_up"] for f in self.flows.values())
        self.total_packets_down = sum(f["packets_down"] for f in self.flows.values())

    def generate_report(self) -> Dict[str, Any]:
        return build_device_audit_report(self)


class NetworkAuditSession:
    """Network-wide traffic audit session capturing NAT flows and packets across all LAN hosts."""
    def __init__(self, duration_seconds: int = 300, scope: str = "all"):
        self.session_id = f"net_audit_{int(datetime.now(timezone.utc).timestamp())}"
        self.duration_seconds = duration_seconds
        self.scope = scope  # "all", "iot_only", "untrusted"
        self.start_time = datetime.now(timezone.utc)
        self.end_time: Optional[datetime] = None
        self.is_active = True
        self.packets: List[Packet] = []
        self.flows: Dict[str, Dict[str, Any]] = {}
        self.device_stats: Dict[str, Dict[str, Any]] = {}  # ip -> stats
        self.lateral_movements: List[Dict[str, Any]] = []
        self.dns_queries: Dict[str, Dict[str, Any]] = {}
        self.anomalies: List[Dict[str, Any]] = []
        self.quarantined_devices: List[Dict[str, Any]] = []
        self.total_bytes_up = 0
        self.total_bytes_down = 0
        self.total_packets_up = 0
        self.total_packets_down = 0
        self.pcap_filename = f"{self.session_id}.pcap"
        self._poller_task: Optional[asyncio.Task] = None

    @property
    def total_flows(self) -> int:
        return len(self.flows)

    @property
    def total_bytes(self) -> int:
        return self.total_bytes_up + self.total_bytes_down

    @property
    def total_packets(self) -> int:
        return self.total_packets_up + self.total_packets_down

    def add_packet(self, pkt: Packet):
        if len(self.packets) < 15000:
            self.packets.append(pkt)

        domain = extract_dns_query(pkt)
        if domain:
            self.dns_queries[domain] = {
                "domain": domain,
                "count": self.dns_queries.get(domain, {}).get("count", 0) + 1,
                "last_seen": datetime.now(timezone.utc).isoformat()
            }

    def update_nat_table(self, nat_entries: List[Dict[str, Any]], devices_by_ip: Dict[str, Any], on_suspicious_callback=None, presets_dict: Optional[Dict[str, Any]] = None):
        for e in nat_entries:
            src_ip = e.get("src", "")
            dst_ip = e.get("dst", "")
            dport = int(e.get("dport", 0))
            proto = e.get("protocol", "TCP")
            b_up = int(e.get("bytes", 0))
            b_down = int(e.get("bytes-out", 0))
            p_up = int(e.get("packets", 0))
            p_down = int(e.get("packets-out", 0))

            dev = devices_by_ip.get(src_ip)
            dev_mac = dev.mac if dev else "UNKNOWN"
            dev_name = (dev.custom_name or dev.hostname or src_ip) if dev else src_ip
            dev_prof = dev.profile if dev else "unassigned"

            # Filter by scope if needed
            if self.scope == "iot_only" and dev_prof not in ("iot", "camera", "smart_home_hub"):
                continue
            elif self.scope == "untrusted" and dev_prof not in ("iot", "camera", "smart_home_hub", "unassigned"):
                continue

            # Update device stats
            if src_ip not in self.device_stats:
                self.device_stats[src_ip] = {
                    "ip": src_ip,
                    "mac": dev_mac,
                    "hostname": dev_name,
                    "vendor": dev.vendor if dev else "",
                    "profile": dev_prof,
                    "flows_count": 0,
                    "bytes_up": 0,
                    "bytes_down": 0,
                    "packets_up": 0,
                    "packets_down": 0,
                    "risk": "safe"
                }

            d_stat = self.device_stats[src_ip]
            d_stat["bytes_up"] = max(d_stat["bytes_up"], b_up)
            d_stat["bytes_down"] = max(d_stat["bytes_down"], b_down)
            d_stat["packets_up"] = max(d_stat["packets_up"], p_up)
            d_stat["packets_down"] = max(d_stat["packets_down"], p_down)

            total_b = b_up + b_down
            total_p = p_up + p_down

            flow_key = f"{src_ip}_{proto}_{dst_ip}_{dport}"
            service_info = KNOWN_SERVICES.get(dport)
            if not service_info:
                is_stream_svc, stream_name = is_streaming_service(dport, proto)
                if is_stream_svc:
                    service_info = {"name": stream_name, "encrypted": True, "risk": "safe"}
                else:
                    service_info = {"name": f"Порт {dport}", "encrypted": False, "risk": "safe"}

            is_lan = is_lan_ip(dst_ip)
            risk = service_info.get("risk", "safe")

            # Check Lateral Movement & internal probes using role-based policy
            if is_lan and dst_ip != "192.168.1.1":
                is_discovery = dst_ip.endswith(".255") or dst_ip == "255.255.255.255" or dst_ip.startswith("224.") or dst_ip.startswith("239.") or dport in (54321, 5353, 1900, 5683)
                if not is_discovery:
                    dst_dev = devices_by_ip.get(dst_ip)
                    dst_name = (dst_dev.custom_name or dst_dev.hostname or dst_ip) if dst_dev else dst_ip
                    lat_key = f"{src_ip}->{dst_ip}:{dport}"

                    preset_rules = None
                    if dev and dev.preset_id and presets_dict and dev.preset_id in presets_dict:
                        p_obj = presets_dict[dev.preset_id]
                        preset_rules = p_obj.rules if hasattr(p_obj, "rules") else p_obj
                    elif presets_dict and f"preset_{dev_prof}" in presets_dict:
                        p_obj = presets_dict[f"preset_{dev_prof}"]
                        preset_rules = p_obj.rules if hasattr(p_obj, "rules") else p_obj

                    designated_nvr = dev.designated_nvr_ip if dev else None
                    custom_ports = dev.custom_allowed_ports if dev else None

                    risk, is_blocked = evaluate_lan_access_policy(
                        src_profile=dev_prof,
                        dst_ip=dst_ip,
                        dport=dport,
                        designated_nvr_ip=designated_nvr,
                        custom_allowed_ports=custom_ports,
                        preset_rules=preset_rules,
                        proto=proto,
                        bytes_transferred=total_b,
                        packets_transferred=total_p
                    )

                    is_stream_svc, _ = is_streaming_service(dport, proto)
                    is_media_data = is_stream_svc or (dport >= 1024 and total_b > 10240 and dport not in (445, 139, 22, 23, 3389, 5555))

                    if risk in ("warning", "critical") and not is_media_data:
                        if not any(lm["key"] == lat_key for lm in self.lateral_movements):
                            lm_entry = {
                                "key": lat_key,
                                "src_ip": src_ip,
                                "src_name": dev_name,
                                "src_mac": dev_mac,
                                "dst_ip": dst_ip,
                                "dst_name": dst_name,
                                "dst_port": dport,
                                "service": service_info.get("name"),
                                "risk": risk,
                                "timestamp": datetime.now(timezone.utc).isoformat()
                            }
                            self.lateral_movements.append(lm_entry)

                            if is_blocked:
                                d_stat["risk"] = "critical"
                                override = dev.auto_quarantine_override if dev else "profile_default"
                                can_quarantine = should_device_quarantine(dev_prof, override=override, scope=getattr(settings, "auto_quarantine_scope", "iot_camera"))
                                if can_quarantine and getattr(settings, "audit_auto_quarantine_suspicious", True) and on_suspicious_callback:
                                    if not any(q["mac"] == dev_mac for q in self.quarantined_devices) and dev_mac != "UNKNOWN":
                                        reason = f"Подозрительная активность в LAN: обращение к {dst_name} ({dst_ip}:{dport} - {service_info.get('name')})"
                                        self.quarantined_devices.append({
                                             "mac": dev_mac,
                                            "ip": src_ip,
                                            "hostname": dev_name,
                                            "reason": reason,
                                            "timestamp": datetime.now(timezone.utc).isoformat()
                                        })
                                        if asyncio.iscoroutinefunction(on_suspicious_callback):
                                            asyncio.create_task(on_suspicious_callback(dev_mac, src_ip, dev_name, reason))
                                        else:
                                            on_suspicious_callback(dev_mac, src_ip, dev_name, reason)

            geo = identify_geoip(dst_ip)
            provider = f"{geo['flag']} {geo['provider']}"

            if flow_key not in self.flows:
                d_stat["flows_count"] += 1
                self.flows[flow_key] = {
                    "src_ip": src_ip,
                    "src_name": dev_name,
                    "src_mac": dev_mac,
                    "dst_ip": dst_ip,
                    "dst_port": dport,
                    "protocol": proto,
                    "service": service_info.get("name"),
                    "is_encrypted": service_info.get("encrypted", False),
                    "provider": provider,
                    "country": geo.get("country", "WAN"),
                    "flag": geo.get("flag", "🌐"),
                    "is_lan": is_lan,
                    "risk": risk,
                    "bytes_up": b_up,
                    "bytes_down": b_down,
                    "packets_up": p_up,
                    "packets_down": p_down,
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "last_seen": datetime.now(timezone.utc).isoformat()
                }
            else:
                self.flows[flow_key]["bytes_up"] = max(self.flows[flow_key]["bytes_up"], b_up)
                self.flows[flow_key]["bytes_down"] = max(self.flows[flow_key]["bytes_down"], b_down)
                self.flows[flow_key]["packets_up"] = max(self.flows[flow_key]["packets_up"], p_up)
                self.flows[flow_key]["packets_down"] = max(self.flows[flow_key]["packets_down"], p_down)
                self.flows[flow_key]["last_seen"] = datetime.now(timezone.utc).isoformat()

        self.total_bytes_up = sum(d["bytes_up"] for d in self.device_stats.values())
        self.total_bytes_down = sum(d["bytes_down"] for d in self.device_stats.values())
        self.total_packets_up = sum(d["packets_up"] for d in self.device_stats.values())
        self.total_packets_down = sum(d["packets_down"] for d in self.device_stats.values())

    def generate_network_report(self) -> Dict[str, Any]:
        return build_network_audit_report(self)

    def update_nat_entries(self, nat_entries: List[Dict[str, Any]], devices_by_ip: Optional[Dict[str, Any]] = None, on_suspicious_callback=None):
        return self.update_nat_table(nat_entries, devices_by_ip or {}, on_suspicious_callback)

    def generate_report(self) -> Dict[str, Any]:
        return self.generate_network_report()

    def save_pcap(self, pcap_dir: Optional[Path] = None) -> Optional[str]:
        saved = save_pcap_packets(self.packets, self.pcap_filename, pcap_dir)
        return self.pcap_filename if saved else None
