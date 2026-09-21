"""Device Traffic Audit & Forensic Inspection Manager for KeenGuard."""
import asyncio
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from scapy.all import Packet, IP, IPv6, TCP, UDP, ARP, Ether, Raw, wrpcap, rdpcap

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import SecurityEvent, AuditReportRecord, DeviceRecord
from keenguard.core.routers import router_manager

logger = logging.getLogger("keenguard.audit")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_known_services() -> Dict[int, Dict[str, Any]]:
    """Loads well-known network service port descriptions from static JSON catalog."""
    json_path = _DATA_DIR / "known_services.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {int(port): info for port, info in raw.items()}
        except Exception as e:
            logger.warning("Failed to load known services catalog from %s: %s", json_path, e)
    return {}


KNOWN_SERVICES: Dict[int, Dict[str, Any]] = load_known_services()

import ipaddress


def load_cidr_providers() -> List[Any]:
    """Loads cloud provider and CDN CIDR ranges from static JSON catalog."""
    json_path = _DATA_DIR / "cidr_providers.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return [
                (ipaddress.ip_network(item["cidr"]), item["name"], item["country"], item["flag"])
                for item in raw
            ]
        except Exception as e:
            logger.warning("Failed to load CIDR providers catalog from %s: %s", json_path, e)
    return []


CIDR_PROVIDERS = load_cidr_providers()

# For backwards compatibility with any component iterating KNOWN_PROVIDERS
KNOWN_PROVIDERS = [
    (str(net), name, country, flag) for net, name, country, flag in CIDR_PROVIDERS
]

_GEOIP_CACHE: Dict[str, Dict[str, str]] = {}

def is_lan_ip(ip_str: str) -> bool:
    """Checks if an IP address belongs to private RFC 1918, loopback, or link-local ranges."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return ip_str.startswith(("192.168.", "10.", "172.16.", "127."))

def identify_geoip(dst_ip: str) -> Dict[str, str]:
    if not dst_ip:
        return {"provider": "Неизвестный узел", "country": "WAN", "flag": "🌐"}

    if dst_ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[dst_ip]

    try:
        ip_obj = ipaddress.ip_address(dst_ip)
    except ValueError:
        return {"provider": "Неизвестный узел", "country": "WAN", "flag": "🌐"}

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        if dst_ip == "192.168.1.1":
            res = {"provider": "Шлюз Keenetic (DNS/Router)", "country": "LAN", "flag": "🏠"}
        else:
            res = {"provider": "Локальная сеть (LAN Хост)", "country": "LAN", "flag": "🏠"}
        _GEOIP_CACHE[dst_ip] = res
        return res

    if ip_obj.is_multicast:
        res = {"provider": "Multicast / Локальное вещание", "country": "LAN", "flag": "📡"}
        _GEOIP_CACHE[dst_ip] = res
        return res

    for net, name, country, flag in sorted(CIDR_PROVIDERS, key=lambda x: x[0].prefixlen, reverse=True):
        if ip_obj in net:
            res = {"provider": name, "country": country, "flag": flag}
            _GEOIP_CACHE[dst_ip] = res
            return res

    res = {"provider": "Внешний интернет-хост", "country": "WAN", "flag": "🌐"}
    _GEOIP_CACHE[dst_ip] = res
    return res

def evaluate_lan_access_policy(
    src_profile: str,
    dst_ip: str,
    dport: int,
    designated_nvr_ip: Optional[str] = None,
    custom_allowed_ports: Optional[str] = None,
    preset_rules: Optional[Dict[str, Any]] = None
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

    # Trusted devices (PCs, laptops, phones) have full LAN access by default
    if src_profile == "trusted" and not preset_rules:
        return "safe", False

    # If preset rules are provided
    if preset_rules:
        allowed = preset_rules.get("allowed_services", [])
        if "*" in allowed or str(dport) in allowed or any(f":{dport}" in a for a in allowed):
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
            return "warning", False

    # Default fallback behavior based on profile
    if src_profile == "trusted":
        return "safe", False
    elif src_profile == "smart_tv":
        if dport in (8200, 80, 443, 8080, 5353, 1900):
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
    elif src_profile in ("iot", "unassigned"):
        if dport in (1883, 8883, 5683, 53, 123):
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
    except Exception as e:
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
    except Exception as e:
        logger.debug("HTTP inspection parse exception: %s", e)
    return None

async def lookup_geoip_online(ip: str) -> Dict[str, str]:
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    cc = data.get("countryCode", "WAN")
                    flag = "".join(chr(ord(c) + 127397) for c in cc.upper()) if len(cc) == 2 else "🌐"
                    org = data.get("org") or data.get("as") or "Внешний провайдер"
                    res = {"provider": org, "country": cc, "flag": flag}
                    _GEOIP_CACHE[ip] = res
                    return res
    except Exception as e:
        logger.debug("Online GeoIP lookup error for %s: %s", ip, e)

    return identify_geoip(ip)

def identify_provider(dst_ip: str) -> str:
    geo = identify_geoip(dst_ip)
    return f"{geo['flag']} {geo['provider']}"


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

            key = f"{proto}_{dst_ip}_{dport}"
            service_info = KNOWN_SERVICES.get(dport, {"name": f"Порт {dport}", "encrypted": False, "risk": "safe"})
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
                        preset_rules=preset_rules
                    )

                    if risk in ("warning", "critical"):
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
        self.end_time = datetime.now(timezone.utc)
        elapsed = int((self.end_time - self.start_time).total_seconds())

        findings = []
        overall_risk = "low"

        unencrypted_flows = [f for f in self.flows.values() if f["dst_port"] in [80, 1883] and not f["is_lan"]]
        if unencrypted_flows:
            overall_risk = "medium"
            findings.append(f"Обнаружена передача данных без шифрования (HTTP/MQTT, порты 80/1883) на {len(unencrypted_flows)} хостов.")

        if self.lan_probes:
            overall_risk = "high"
            targets_str = ", ".join(p["target"] for p in self.lan_probes[:3])
            findings.append(f"Внимание: попытка обращения к локальным устройствам сети ({targets_str}).")

        crit_flows = [f for f in self.flows.values() if f["risk"] == "critical"]
        if crit_flows:
            overall_risk = "high"
            ports_str = ", ".join(str(f["dst_port"]) for f in crit_flows)
            findings.append(f"Обнаружены попытки обращения к чувствительным портам администрирования ({ports_str}).")

        is_hub = self.profile == "smart_home_hub" or (self.profile == "unassigned" and any(k in (self.hostname or "").lower() for k in ["spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt"]))

        if is_hub:
            findings.append("Устройство идентифицировано как Хаб умного дома. Периферийный опрос локальных устройств (CoAP, mDNS, SSDP, UDP 54321) учтен как штатная работа контроллера.")

        if self.http_inspections:
            findings.append(f"Инспекция пакетов выявила {len(self.http_inspections)} незашифрованных HTTP-запросов (методы, хосты, пути URI).")

        if not findings:
            findings.append("Подозрительной активности не выявлено. Все внешние соединения защищены TLS/SSL или стандартным DNS.")

        pcap_path = settings.pcap_dir / self.pcap_filename
        pcap_saved = False
        if self.packets:
            try:
                settings.pcap_dir.mkdir(parents=True, exist_ok=True)
                wrpcap(str(pcap_path), self.packets)
                pcap_saved = True
            except Exception as e:
                logger.error("Failed to dump audit PCAP: %s", e)
        elif pcap_path.exists():
            pcap_saved = True

        recommendations = []
        if is_hub:
            recommendations.append(
                "Совет по асимметричной сегментации Keenetic: для хабов умного дома настройте односторонний доступ в межсетевом экране Keenetic. "
                "Разрешите направление «Домашняя сеть -> IoT», но заблокируйте «IoT -> Домашняя сеть». "
                "Благодаря Stateful Firewall вы сможете подключаться к интерфейсу хаба из дома, а сам хаб не сможет опрашивать домашние компьютеры и NAS."
            )

        if overall_risk == "high" or self.lan_probes:
            if not is_hub:
                recommendations.append("Для надежной изоляции от ПК и сетевых дисков (NAS) переключите устройство на Гостевую Wi-Fi сеть Keenetic (Bridge1) или выделите отдельный сегмент IoT.")
            else:
                recommendations.append("Внимание: зафиксированы попытки обращения к локальным службам домашней сети. Проверьте установленные интеграции и дополнения хаба.")

        if unencrypted_flows:
            recommendations.append("Не передавайте учетные данные через незащищенные каналы данного устройства.")
        if not self.lan_probes and overall_risk == "low":
            recommendations.append("Устройство ведет себя штатно, коммуникация ограничена заявленными облачными сервисами.")

        report = {
            "id": self.session_id,
            "mac": self.mac,
            "ip": self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "capture_source": self.capture_source,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": elapsed,
            "total_bytes": self.total_bytes_up + self.total_bytes_down,
            "total_bytes_up": self.total_bytes_up,
            "total_bytes_down": self.total_bytes_down,
            "total_packets": self.total_packets_up + self.total_packets_down,
            "flows_count": len(self.flows),
            "flows": sorted(list(self.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True),
            "dns_queries": list(self.dns_queries.values()),
            "http_inspections": self.http_inspections,
            "lan_probes": self.lan_probes,
            "risk_level": "critical" if getattr(self, "auto_quarantined", False) else overall_risk,
            "overall_risk": "critical" if getattr(self, "auto_quarantined", False) else overall_risk,
            "findings": findings,
            "recommendations": recommendations,
            "pcap_file": self.pcap_filename if pcap_saved else None,
            "auto_quarantined": getattr(self, "auto_quarantined", False),
            "suspicious_reasons": getattr(self, "suspicious_reasons", []),
            "quarantined_devices": [{"mac": self.mac, "ip": self.ip, "hostname": self.hostname, "reason": r} for r in getattr(self, "suspicious_reasons", [])] if getattr(self, "auto_quarantined", False) else []
        }
        return report

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

            flow_key = f"{src_ip}_{proto}_{dst_ip}_{dport}"
            service_info = KNOWN_SERVICES.get(dport, {"name": f"Порт {dport}", "encrypted": False, "risk": "safe"})
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
                        preset_rules=preset_rules
                    )

                    if risk in ("warning", "critical"):
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
        self.end_time = datetime.now(timezone.utc)
        elapsed = int((self.end_time - self.start_time).total_seconds())

        self.total_bytes_up = sum(d["bytes_up"] for d in self.device_stats.values())
        self.total_bytes_down = sum(d["bytes_down"] for d in self.device_stats.values())
        self.total_packets_up = sum(d["packets_up"] for d in self.device_stats.values())
        self.total_packets_down = sum(d["packets_down"] for d in self.device_stats.values())

        top_devices = sorted(
            list(self.device_stats.values()),
            key=lambda x: x["bytes_up"] + x["bytes_down"],
            reverse=True
        )

        provider_counts: Dict[str, Dict[str, Any]] = {}
        for f in self.flows.values():
            if not f.get("is_lan"):
                prov = f.get("provider", "WAN")
                if prov not in provider_counts:
                    provider_counts[prov] = {
                        "provider": prov,
                        "name": prov,
                        "country": f.get("country", "WAN"),
                        "flag": f.get("flag", "🌐"),
                        "flows": 0,
                        "bytes": 0
                    }
                provider_counts[prov]["flows"] += 1
                provider_counts[prov]["bytes"] += (f["bytes_up"] + f["bytes_down"])
        top_providers = sorted(list(provider_counts.values()), key=lambda x: x["flows"], reverse=True)[:10]

        crit_lat = [lm for lm in self.lateral_movements if lm.get("risk") == "critical"]
        unencrypted = [f for f in self.flows.values() if not f.get("is_encrypted") and not f.get("is_lan") and f.get("dst_port") not in (80, 53, 123)]

        findings = []
        if self.quarantined_devices:
            findings.append(f"🚨 Автоматически изолировано {len(self.quarantined_devices)} устройств за подозрительную активность в LAN.")
        if crit_lat:
            findings.append(f"Обнаружено {len(crit_lat)} подозрительных попыток межузлового взаимодействия (Lateral Movement) на критические порты.")
        if unencrypted:
            findings.append(f"Зафиксировано {len(unencrypted)} незашифрованных потоков данных к внешним серверам.")
        if not findings:
            findings.append("Сетевой трафик в пределах нормы, критических аномалий не зафиксировано.")

        overall_risk = "critical" if (self.quarantined_devices or crit_lat) else ("high" if unencrypted else ("medium" if len(self.flows) > 50 else "low"))

        pcap_saved = False
        if self.packets:
            try:
                settings.pcap_dir.mkdir(parents=True, exist_ok=True)
                pcap_path = settings.pcap_dir / self.pcap_filename
                wrpcap(str(pcap_path), self.packets)
                pcap_saved = True
            except Exception as e:
                logger.error("Failed to dump network audit PCAP: %s", e)

        recommendations = []
        if self.quarantined_devices:
            recommendations.append("Проверьте изолированные устройства во вкладке «Устройства». Ограничьте их доступ к домашнему сегменту.")
        if crit_lat:
            recommendations.append("Рекомендуется изолировать сегмент умного дома (IoT) в отдельный VLAN или гостевую Wi-Fi сеть Keenetic.")
        if not self.quarantined_devices and overall_risk == "low":
            recommendations.append("Сеть защищена, подозрительных перемещений между устройствами не обнаружено.")

        return {
            "id": self.session_id,
            "mac": "NETWORK",
            "is_network": True,
            "hostname": f"Сводный аудит сети ({self.scope})",
            "scope": self.scope,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": elapsed,
            "total_bytes": self.total_bytes_up + self.total_bytes_down,
            "total_bytes_up": self.total_bytes_up,
            "total_bytes_down": self.total_bytes_down,
            "total_packets": self.total_packets_up + self.total_packets_down,
            "total_flows": len(self.flows),
            "devices_count": len(self.device_stats),
            "devices_analyzed": len(self.device_stats),
            "top_devices": top_devices,
            "flows_count": len(self.flows),
            "flows": sorted(list(self.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)[:100],
            "top_providers": top_providers,
            "cloud_providers": top_providers,
            "lateral_movements": self.lateral_movements,
            "quarantined_devices": self.quarantined_devices,
            "dns_queries": list(self.dns_queries.values()),
            "risk_level": overall_risk,
            "overall_risk": overall_risk,
            "findings": findings,
            "recommendations": recommendations,
            "pcap_file": self.pcap_filename if pcap_saved else None
        }

    def update_nat_entries(self, nat_entries: List[Dict[str, Any]], devices_by_ip: Optional[Dict[str, Any]] = None, on_suspicious_callback=None):
        return self.update_nat_table(nat_entries, devices_by_ip or {}, on_suspicious_callback)

    def generate_report(self) -> Dict[str, Any]:
        return self.generate_network_report()

    def save_pcap(self, pcap_dir: Optional[Path] = None) -> Optional[str]:
        target_dir = pcap_dir or settings.pcap_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = target_dir / self.pcap_filename
        try:
            if self.packets:
                wrpcap(str(pcap_path), self.packets)
            else:
                header = bytes([
                    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
                ])
                with open(pcap_path, "wb") as f:
                    f.write(header)
            return self.pcap_filename
        except Exception as e:
            logger.error("Failed to save network audit pcap: %s", e)
            return None

class TrafficAuditManager:
    def __init__(self, pcap_dir: Optional[Path] = None):
        self.pcap_dir = pcap_dir or settings.pcap_dir
        self.active_sessions: Dict[str, AuditSession] = {}
        self.active_network_session: Optional[NetworkAuditSession] = None
        self._lock = asyncio.Lock()
        self.suspicious_callback = None

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
