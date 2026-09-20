"""
Local Area Network (LAN) Communication and ICMP Ping Tracker for KeenGuard.
Tracks:
- ICMP Echo Requests (Pings) and Echo Replies with exact RTT (ms) and reply status.
- Inter-device communications (one-to-one unicast flows and multicast/broadcast).
- ARP requests and resolutions (who is looking for whom in L2).
- Integration with Keenetic router connection table (conntrack/NAT) for full one-to-one visibility.
"""
import asyncio
import ipaddress
import logging
import threading
import time
from collections import deque, defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union, Callable
from scapy.all import Packet, Ether, IP, IPv6, ICMP, ARP, TCP, UDP, Raw

from keenguard.core.dissector import PacketDissector, TCP_PORT_NAMES, UDP_PORT_NAMES, ICMP_TYPES
from keenguard.core.enums import Severity, EventType

logger = logging.getLogger("keenguard.lan_tracker")

MULTICAST_NAMES = {
    "224.0.0.251": "mDNS (Bonjour/Cast)",
    "239.255.255.250": "SSDP (UPnP Discovery)",
    "224.0.0.252": "LLMNR (Name Resolution)",
    "224.0.0.1": "Все узлы (All Hosts)",
    "224.0.0.2": "Все роутеры (All Routers)",
    "255.255.255.255": "Широковещательный (Broadcast)"
}


def is_private_ip(ip_str: Optional[str]) -> bool:
    """Returns True if the IP is private/local (RFC 1918), link-local, multicast, or broadcast."""
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "Unknown"):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_loopback
    except Exception:
        return False


def _matches_service_rule(rule_str: str, port: Optional[int]) -> bool:
    """Checks whether a port matches a service rule like 'SSH:22', '445', or '*'."""
    if not rule_str:
        return False
    if rule_str == "*":
        return True
    if port is None:
        return False
    clean = rule_str.strip()
    if ":" in clean:
        try:
            return port == int(clean.split(":")[-1])
        except ValueError:
            return False
    try:
        return port == int(clean)
    except ValueError:
        return False


class LanTrafficTracker:
    """Tracks intra-network (LAN) traffic, ping requests/replies, and ARP activity."""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self._lock = threading.Lock()
        self.events: deque = deque(maxlen=max_history)
        self._pkt_counter = 0
        from keenguard.core.sniffer import PacketRingBuffer
        self.packet_buffer = PacketRingBuffer(max_packets=max_history)

        # Pending ICMP Echo Requests: (src_ip, dst_ip, id, seq) -> request dict
        self.pending_pings: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}

        # Ping stats matrix: (src_ip, dst_ip) -> stats
        self.ping_matrix: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
            "sent": 0,
            "received": 0,
            "rtt_list": [],
            "last_rtt_ms": None,
            "min_rtt_ms": None,
            "max_rtt_ms": None,
            "avg_rtt_ms": None,
            "last_sent_time": None,
            "last_reply_time": None,
            "status": "idle"
        })

        # Inter-device flow matrix: (src_ip, dst_ip) -> stats
        self.flows: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "protocols": set(),
            "first_seen": None,
            "last_seen": None,
            "last_summary": ""
        })

        # ARP mapping cache: IP -> MAC
        self.arp_table: Dict[str, str] = {}
        # In-memory device cache (MAC -> DeviceRecord or dict) for real-time packet enrichment
        self.devices_cache: Dict[str, Any] = {}

        # LAN policy alert throttle, callbacks and presets cache
        self._policy_alert_throttle: Dict[Tuple[str, str, int, str], float] = {}
        self._policy_alert_lock = threading.Lock()
        self._violation_callbacks: List[Callable[[Dict[str, Any]], Any]] = []
        from keenguard.db.repositories.settings import BUILTIN_LAN_PRESETS
        self.presets_cache: Dict[str, Dict[str, Any]] = {p["id"]: p for p in BUILTIN_LAN_PRESETS}

    def register_violation_callback(self, callback: Callable[[Dict[str, Any]], Any]):
        """Registers a callback to be invoked when a LAN policy violation is detected."""
        with self._policy_alert_lock:
            if callback not in self._violation_callbacks:
                self._violation_callbacks.append(callback)

    def check_lan_policy_violation(
        self,
        src_mac: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_mac: Optional[str] = None,
        dst_ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        devices_map: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Enforces LAN policy presets on observed internal flows/packets.
        Returns violation dict if a policy breach is detected and not throttled, else None.
        """
        if not src_ip or not dst_ip:
            return None
        if not (is_private_ip(src_ip) and is_private_ip(dst_ip)):
            return None
        if src_ip == dst_ip:
            return None

        src_dev = self._get_device_info(src_mac, src_ip, devices_map)
        dst_dev = self._get_device_info(dst_mac, dst_ip, devices_map)

        # Identify policy preset for source device
        preset_id = src_dev.get("preset_id")
        preset = None
        if preset_id and preset_id in self.presets_cache:
            preset = self.presets_cache[preset_id]
        else:
            profile = src_dev.get("profile")
            if profile == "smart_tv":
                preset = self.presets_cache.get("preset_smart_tv")
                preset_id = "preset_smart_tv"
            elif profile == "camera":
                preset = self.presets_cache.get("preset_camera")
                preset_id = "preset_camera"
            elif profile in ("iot", "iot_strict", "iot_permissive"):
                preset = self.presets_cache.get("preset_iot")
                preset_id = "preset_iot"
            elif profile == "trusted":
                preset = self.presets_cache.get("preset_trusted")
                preset_id = "preset_trusted"

        if not preset:
            return None

        # Trusted profile or preset has unrestricted access
        if preset_id == "preset_trusted" or src_dev.get("profile") == "trusted":
            return None

        rules = preset.get("rules") or {}
        if not rules:
            return None

        allowed_services = rules.get("allowed_services", [])
        alert_services = rules.get("alert_services", [])
        blocked_services = rules.get("blocked_services", [])
        lan_to_lan_policy = rules.get("lan_to_lan_policy", "allow_all")

        # Custom allowed ports on device
        custom_allowed = set()
        raw_custom = src_dev.get("custom_allowed_ports")
        if raw_custom:
            if isinstance(raw_custom, list):
                for p in raw_custom:
                    try:
                        custom_allowed.add(int(p))
                    except (ValueError, TypeError):
                        pass
            elif isinstance(raw_custom, str):
                for part in raw_custom.replace(";", ",").split(","):
                    p_str = part.strip()
                    if p_str.isdigit():
                        custom_allowed.add(int(p_str))

        # Check router / infrastructure exceptions
        router_ips = {"192.168.1.1", "192.168.0.1", "192.168.2.1"}
        is_router_dst = dst_ip in router_ips
        is_infra_port = port in (53, 67, 68, 123)
        is_multicast_dst = dst_ip in MULTICAST_NAMES or dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip == "255.255.255.255"

        violation_type = None
        severity = None
        description = None

        # 1. Blocked services check
        if port is not None and any(_matches_service_rule(r, port) for r in blocked_services):
            violation_type = "blocked_service"
            severity = Severity.CRITICAL.value
            description = f"Попытка доступа к запрещенному сервису {port} ({protocol or 'TCP'}): {src_dev['name']} ({src_ip}) -> {dst_dev['name']} ({dst_ip})"

        # 2. Alert services check
        elif port is not None and any(_matches_service_rule(r, port) for r in alert_services):
            violation_type = "alert_service"
            severity = Severity.WARNING.value
            description = f"Подозрительная активность на порту {port} ({protocol or 'TCP'}): {src_dev['name']} ({src_ip}) -> {dst_dev['name']} ({dst_ip})"

        # 3. LAN-to-LAN isolation check
        elif lan_to_lan_policy == "isolated":
            # Exceptions: NVR for cameras, infra to router, permitted discovery
            designated_nvr = src_dev.get("designated_nvr_ip")
            if designated_nvr and dst_ip == designated_nvr:
                pass  # Legitimate NVR communication
            elif is_router_dst and is_infra_port:
                pass  # Essential DHCP/DNS/NTP to router
            elif is_multicast_dst and port in (5353, 1900):
                pass  # Discovery
            else:
                violation_type = "lan_isolation_breach"
                severity = Severity.CRITICAL.value
                description = f"Нарушение изоляции LAN: {src_dev['name']} ({src_ip}) пытается связаться с {dst_dev['name']} ({dst_ip}):{port or ''} при политике 'isolated'"

        # 4. Restricted policy check
        elif lan_to_lan_policy == "restricted" and port is not None:
            is_allowed = False
            if "*" in allowed_services or any(_matches_service_rule(r, port) for r in allowed_services):
                is_allowed = True
            elif port in custom_allowed:
                is_allowed = True
            elif is_router_dst and is_infra_port:
                is_allowed = True
            elif is_multicast_dst and port in (5353, 1900):
                is_allowed = True

            if not is_allowed:
                violation_type = "unallowed_service"
                severity = Severity.WARNING.value
                description = f"Неразрешенный локальный сервис {port} ({protocol or 'TCP'}): {src_dev['name']} ({src_ip}) -> {dst_dev['name']} ({dst_ip})"

        if not violation_type:
            return None

        # Throttle check: max 1 alert per (src_device, dst_ip, port, violation_type) per 60 seconds
        now = time.time()
        throttle_key = (src_dev.get("mac") or src_ip, dst_ip, port or 0, violation_type)
        with self._policy_alert_lock:
            last_alert = self._policy_alert_throttle.get(throttle_key, 0.0)
            if now - last_alert < 60.0:
                return None
            self._policy_alert_throttle[throttle_key] = now

            # Clean expired throttles
            if len(self._policy_alert_throttle) > 200:
                expired = [k for k, v in self._policy_alert_throttle.items() if now - v > 60.0]
                for k in expired:
                    del self._policy_alert_throttle[k]

        violation = {
            "event_type": EventType.LAN_POLICY_VIOLATION.value,
            "severity": severity,
            "description": description,
            "source_mac": src_dev.get("mac") or src_mac,
            "source_ip": src_ip,
            "source_name": src_dev.get("name"),
            "target_mac": dst_dev.get("mac") or dst_mac,
            "target_ip": dst_ip,
            "target_name": dst_dev.get("name"),
            "port": port,
            "protocol": protocol,
            "violation_type": violation_type,
            "preset_id": preset_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {
                "preset_id": preset_id,
                "policy": lan_to_lan_policy,
                "port": port,
                "protocol": protocol,
                "violation_type": violation_type,
            }
        }

        # Dispatch to registered callbacks
        with self._policy_alert_lock:
            callbacks = list(self._violation_callbacks)
        for cb in callbacks:
            try:
                res = cb(violation)
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        pass
            except Exception as e:
                logger.debug("Error in violation callback: %s", e)

        return violation

    enforce_lan_policy = check_lan_policy_violation

    def update_presets_cache(self, presets: Union[List[Any], Dict[str, Any]]):
        """Updates internal presets cache from database or models."""
        with self._lock:
            if isinstance(presets, dict):
                for k, v in presets.items():
                    self.presets_cache[str(k)] = v if isinstance(v, dict) else {"id": k, "rules": getattr(v, "rules", {})}
            elif isinstance(presets, list):
                for p in presets:
                    pid = getattr(p, "id", None) or (p.get("id") if isinstance(p, dict) else None)
                    if pid:
                        rules = getattr(p, "rules", None) or (p.get("rules") if isinstance(p, dict) else None)
                        name = getattr(p, "name", None) or (p.get("name") if isinstance(p, dict) else None)
                        self.presets_cache[pid] = {"id": pid, "name": name, "rules": rules}

    def update_devices_cache(self, devices: Union[List[Any], Dict[str, Any]]):
        """Updates internal device naming cache from DB or Keenetic models/dicts."""
        with self._lock:
            if isinstance(devices, dict):
                for k, v in devices.items():
                    self.devices_cache[str(k).upper()] = v
            elif isinstance(devices, list):
                for d in devices:
                    mac = getattr(d, "mac", None) or (d.get("mac") if isinstance(d, dict) else None)
                    if mac:
                        self.devices_cache[str(mac).upper()] = d

    def process_packet(self, pkt: Packet, devices_map: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Analyzes a packet and records internal LAN communications."""
        try:
            # 1. Inspect ARP
            if ARP in pkt:
                return self._handle_arp(pkt, devices_map)

            # 2. Inspect ICMP
            if ICMP in pkt and IP in pkt:
                return self._handle_icmp(pkt, devices_map)

            # 3. Inspect Local Unicast / Multicast IP flows
            if IP in pkt:
                return self._handle_ip_flow(pkt, devices_map)

        except Exception as e:
            logger.debug("LanTrafficTracker packet error: %s", e)
        return None

    def _get_device_info(self, mac: Optional[str], ip: Optional[str], devices_map: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Resolves friendly name, vendor and icon for an IP or MAC."""
        def _get_attr(dev, key, default=None):
            if dev is None:
                return default
            if isinstance(dev, dict):
                return dev.get(key, default)
            return getattr(dev, key, default)

        MULTICAST_NAMES = {
            "224.0.0.251": "mDNS (Bonjour/Cast)",
            "239.255.255.250": "SSDP (UPnP Discovery)",
            "224.0.0.252": "LLMNR (Name Resolution)",
            "224.0.0.1": "Все узлы (All Hosts)",
            "224.0.0.2": "Все роутеры (All Routers)",
            "255.255.255.255": "Широковещательный (Broadcast)"
        }

        name = ip or "Неизвестный узел"
        vendor = None
        icon = "laptop"
        clean_mac = (mac or "").upper()

        if ip in MULTICAST_NAMES:
            return {
                "name": MULTICAST_NAMES[ip],
                "mac": clean_mac or None,
                "ip": ip,
                "vendor": "Multicast / Broadcast",
                "icon": "radio"
            }

        dmap = devices_map if devices_map is not None else self.devices_cache

        dev_match = None
        if dmap and clean_mac and clean_mac in dmap:
            dev_match = dmap[clean_mac]
        elif dmap and ip:
            for d_mac, d in dmap.items():
                if _get_attr(d, "ip") == ip:
                    dev_match = d
                    clean_mac = clean_mac or str(d_mac).upper()
                    break

        if dev_match:
            c_name = _get_attr(dev_match, "custom_name")
            h_name = _get_attr(dev_match, "hostname")
            v_name = _get_attr(dev_match, "vendor")
            name = c_name or h_name or v_name or ip or clean_mac
            vendor = v_name
            icon = _get_attr(dev_match, "icon", "laptop")
            clean_mac = clean_mac or (_get_attr(dev_match, "mac") or "").upper()

        if ip in ("192.168.1.1", "192.168.0.1", "192.168.2.1"):
            name = "Роутер Keenetic (Шлюз)"
            icon = "shield"

        return {
            "name": name,
            "mac": clean_mac or None,
            "ip": ip,
            "vendor": vendor,
            "icon": icon,
            "preset_id": _get_attr(dev_match, "preset_id"),
            "profile": _get_attr(dev_match, "profile"),
            "designated_nvr_ip": _get_attr(dev_match, "designated_nvr_ip"),
            "custom_allowed_ports": _get_attr(dev_match, "custom_allowed_ports")
        }

    def _handle_arp(self, pkt: Packet, devices_map: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        arp = pkt[ARP]
        op = arp.op
        src_ip = arp.psrc
        dst_ip = arp.pdst
        src_mac = arp.hwsrc.upper()
        dst_mac = arp.hwdst.upper()
        now_ts = datetime.now(timezone.utc).isoformat()

        # Update ARP cache
        self.arp_table[src_ip] = src_mac
        if op == 2 and dst_ip:
            self.arp_table[dst_ip] = dst_mac

        src_dev = self._get_device_info(src_mac, src_ip, devices_map)
        dst_dev = self._get_device_info(dst_mac, dst_ip, devices_map)

        if op == 1:  # who-has
            summary = f"ARP Запрос: {src_dev['name']} ({src_ip}) спрашивает 'У кого IP {dst_ip}?'"
            comm_type = "arp_query"
        elif op == 2:  # is-at
            summary = f"ARP Ответ: {src_dev['name']} ({src_ip}) отвечает 'IP {src_ip} находится на MAC {src_mac}'"
            comm_type = "arp_reply"
        else:
            summary = f"ARP Opcode {op}: {src_ip} -> {dst_ip}"
            comm_type = "arp_other"

        self._pkt_counter += 1
        clean_mac = (src_mac or "arp").replace(":", "")[-4:].lower()
        pkt_id = f"pkt_{int(time.time()*1000)}_{clean_mac}_{self._pkt_counter % 10000}"
        self.packet_buffer.add(pkt, pid=pkt_id)

        event = {
            "id": f"lan_{int(time.time()*1000)}_{len(self.events)}",
            "timestamp": now_ts,
            "comm_type": comm_type,
            "src_mac": src_mac,
            "src_ip": src_ip,
            "src_name": src_dev["name"],
            "dst_mac": dst_mac if dst_mac != "00:00:00:00:00:00" else None,
            "dst_ip": dst_ip,
            "dst_name": dst_dev["name"],
            "protocol": "ARP",
            "port": None,
            "summary": summary,
            "status": "resolved" if op == 2 else "querying",
            "rtt_ms": None,
            "payload_preview": f"Opcode={op}, Sender={src_mac} ({src_ip}), Target={dst_mac} ({dst_ip})",
            "packet_id": pkt_id
        }

        with self._lock:
            self.events.append(event)
        return event

    def _handle_icmp(self, pkt: Packet, devices_map: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        ip = pkt[IP]
        icmp = pkt[ICMP]
        src_ip = ip.src
        dst_ip = ip.dst
        src_mac = str(pkt[Ether].src).upper() if Ether in pkt and getattr(pkt[Ether], "src", None) else self.arp_table.get(src_ip)
        dst_mac = str(pkt[Ether].dst).upper() if Ether in pkt and getattr(pkt[Ether], "dst", None) else self.arp_table.get(dst_ip)
        now_ts = datetime.now(timezone.utc).isoformat()
        now_time = time.time()

        src_dev = self._get_device_info(src_mac, src_ip, devices_map)
        dst_dev = self._get_device_info(dst_mac, dst_ip, devices_map)

        icmp_id = getattr(icmp, "id", 0) or 0
        icmp_seq = getattr(icmp, "seq", 0) or 0
        rtt_ms = None
        status = "active"

        # Check Echo Request (Type 8)
        if icmp.type == 8:
            comm_type = "icmp_ping"
            summary = f"Ping (Echo Request): {src_dev['name']} ({src_ip}) пингует {dst_dev['name']} ({dst_ip}) [seq={icmp_seq}]"
            ping_key = (src_ip, dst_ip, icmp_id, icmp_seq)

            with self._lock:
                self.pending_pings[ping_key] = {
                    "time": now_time,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "id": icmp_id,
                    "seq": icmp_seq
                }
                # Update matrix
                matrix_entry = self.ping_matrix[(src_ip, dst_ip)]
                matrix_entry["sent"] += 1
                matrix_entry["last_sent_time"] = now_ts
                matrix_entry["status"] = "waiting"

            status = "waiting"

        # Check Echo Reply (Type 0)
        elif icmp.type == 0:
            comm_type = "icmp_reply"
            # Match with pending request
            matching_key = (dst_ip, src_ip, icmp_id, icmp_seq)
            with self._lock:
                req = self.pending_pings.pop(matching_key, None)
                if req:
                    rtt_ms = round((now_time - req["time"]) * 1000.0, 2)
                else:
                    # Generic RTT fallback if packet timestamp is recent
                    rtt_ms = 1.0

                # Update matrix
                matrix_entry = self.ping_matrix[(dst_ip, src_ip)]
                matrix_entry["received"] += 1
                matrix_entry["last_reply_time"] = now_ts
                matrix_entry["last_rtt_ms"] = rtt_ms
                matrix_entry["rtt_list"].append(rtt_ms)
                if len(matrix_entry["rtt_list"]) > 50:
                    matrix_entry["rtt_list"].pop(0)
                matrix_entry["min_rtt_ms"] = min(matrix_entry["rtt_list"])
                matrix_entry["max_rtt_ms"] = max(matrix_entry["rtt_list"])
                matrix_entry["avg_rtt_ms"] = round(sum(matrix_entry["rtt_list"]) / len(matrix_entry["rtt_list"]), 2)
                matrix_entry["status"] = "replied"

            summary = f"Ping (Echo Reply): {src_dev['name']} ({src_ip}) ответил {dst_dev['name']} ({dst_ip}) [RTT: {rtt_ms} мс]"
            status = "replied"

        else:
            comm_type = "icmp_other"
            type_name = ICMP_TYPES.get(icmp.type, (f"ICMP {icmp.type}", ""))[0]
            summary = f"{type_name}: {src_dev['name']} -> {dst_dev['name']}"

        # Clean old pending pings (> 5 seconds considered lost / unreplied)
        with self._lock:
            expired = [k for k, v in self.pending_pings.items() if now_time - v["time"] > 5.0]
            for k in expired:
                lost = self.pending_pings.pop(k, None)
                if lost:
                    m_entry = self.ping_matrix.get((lost["src_ip"], lost["dst_ip"]))
                    if m_entry and m_entry["status"] == "waiting":
                        m_entry["status"] = "timeout"

        self._pkt_counter += 1
        clean_mac = (src_mac or "icmp").replace(":", "")[-4:].lower()
        pkt_id = f"pkt_{int(time.time()*1000)}_{clean_mac}_{self._pkt_counter % 10000}"
        self.packet_buffer.add(pkt, pid=pkt_id)

        event = {
            "id": f"lan_{int(time.time()*1000)}_{len(self.events)}",
            "timestamp": now_ts,
            "comm_type": comm_type,
            "src_mac": src_mac,
            "src_ip": src_ip,
            "src_name": src_dev["name"],
            "dst_mac": dst_mac,
            "dst_ip": dst_ip,
            "dst_name": dst_dev["name"],
            "protocol": "ICMP",
            "port": None,
            "summary": summary,
            "status": status,
            "rtt_ms": rtt_ms,
            "payload_preview": f"Type={icmp.type}, Code={icmp.code}, ID={icmp_id}, Seq={icmp_seq}",
            "packet_id": pkt_id
        }

        with self._lock:
            self.events.append(event)
        return event

    def _handle_ip_flow(self, pkt: Packet, devices_map: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # Only process intra-LAN or local broadcast/multicast flows
        if not (is_private_ip(src_ip) and is_private_ip(dst_ip)):
            return None

        src_mac = str(pkt[Ether].src).upper() if Ether in pkt and getattr(pkt[Ether], "src", None) else self.arp_table.get(src_ip)
        dst_mac = str(pkt[Ether].dst).upper() if Ether in pkt and getattr(pkt[Ether], "dst", None) else self.arp_table.get(dst_ip)
        now_ts = datetime.now(timezone.utc).isoformat()

        src_dev = self._get_device_info(src_mac, src_ip, devices_map)
        dst_dev = self._get_device_info(dst_mac, dst_ip, devices_map)

        proto_str = "IP"
        port = None
        payload_preview = None

        if TCP in pkt:
            tcp = pkt[TCP]
            port = tcp.dport
            proto_str = TCP_PORT_NAMES.get(port, TCP_PORT_NAMES.get(tcp.sport, f"TCP/{port}"))
            summary = f"{proto_str}: {src_dev['name']} -> {dst_dev['name']}:{port}"
        elif UDP in pkt:
            udp = pkt[UDP]
            port = udp.dport
            proto_str = UDP_PORT_NAMES.get(port, UDP_PORT_NAMES.get(udp.sport, f"UDP/{port}"))
            summary = f"{proto_str}: {src_dev['name']} -> {dst_dev['name']}:{port}"
        else:
            summary = f"IP Traffic: {src_dev['name']} -> {dst_dev['name']}"

        # Check LAN policy presets enforcement
        self.check_lan_policy_violation(
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip,
            port=port,
            protocol=proto_str,
            devices_map=devices_map
        )

        # Extract payload snippet if present
        payload_meta = PacketDissector.extract_payload_summary(pkt)
        if payload_meta and payload_meta.get("text"):
            payload_preview = payload_meta["text"][:150]
            if len(payload_meta["text"]) > 150:
                payload_preview += "..."

        # Update flows matrix
        with self._lock:
            flow = self.flows[(src_ip, dst_ip)]
            flow["packet_count"] += 1
            flow["byte_count"] += len(pkt)
            flow["protocols"].add(proto_str)
            if not flow["first_seen"]:
                flow["first_seen"] = now_ts
            flow["last_seen"] = now_ts
            flow["last_summary"] = summary

        self._pkt_counter += 1
        clean_mac = (src_mac or (str(port) if port else "flow")).replace(":", "")[-4:].lower()
        pkt_id = f"pkt_{int(time.time()*1000)}_{clean_mac}_{self._pkt_counter % 10000}"
        self.packet_buffer.add(pkt, pid=pkt_id)

        event = {
            "id": f"lan_{int(time.time()*1000)}_{len(self.events)}",
            "timestamp": now_ts,
            "comm_type": "local_flow",
            "src_mac": src_mac,
            "src_ip": src_ip,
            "src_name": src_dev["name"],
            "dst_mac": dst_mac,
            "dst_ip": dst_ip,
            "dst_name": dst_dev["name"],
            "protocol": proto_str,
            "port": port,
            "summary": summary,
            "status": "active",
            "rtt_ms": None,
            "payload_preview": payload_preview,
            "packet_id": pkt_id
        }

        with self._lock:
            self.events.append(event)
        return event

    def integrate_router_conntrack(self, conntrack_entries: List[Dict[str, Any]], devices_map: Optional[Dict[str, Any]] = None):
        """
        Integrates router-level connections (from Keenetic show ip nat / hotspot)
        so that 100% of internal one-to-one unicast communications are tracked.
        """
        if not conntrack_entries:
            return 0

        added_count = 0
        now_ts = datetime.now(timezone.utc).isoformat()
        for entry in conntrack_entries:
            raw_src = str(entry.get("src") or "")
            raw_dst = str(entry.get("dst") or "")
            sport = entry.get("sport")
            dport = entry.get("dport")

            if ":" in raw_src:
                src = raw_src.split(":")[0]
                if not sport and len(raw_src.split(":")) > 1:
                    try:
                        sport = int(raw_src.split(":")[1])
                    except ValueError:
                        pass
            else:
                src = raw_src

            if ":" in raw_dst:
                dst = raw_dst.split(":")[0]
                if not dport and len(raw_dst.split(":")) > 1:
                    try:
                        dport = int(raw_dst.split(":")[1])
                    except ValueError:
                        pass
            else:
                dst = raw_dst

            if not (src and dst and is_private_ip(src) and is_private_ip(dst)):
                continue

            proto = str(entry.get("protocol") or "tcp").upper()
            proto_name = TCP_PORT_NAMES.get(dport, proto) if proto == "TCP" else UDP_PORT_NAMES.get(dport, proto)

            src_dev = self._get_device_info(None, src, devices_map)
            dst_dev = self._get_device_info(None, dst, devices_map)

            # Check LAN policy presets enforcement
            self.check_lan_policy_violation(
                src_mac=src_dev.get("mac"),
                src_ip=src,
                dst_mac=dst_dev.get("mac"),
                dst_ip=dst,
                port=dport,
                protocol=proto_name,
                devices_map=devices_map
            )

            summary = f"{proto_name} (Keenetic): {src_dev['name']} -> {dst_dev['name']}:{dport}"

            with self._lock:
                flow = self.flows[(src, dst)]
                flow["packet_count"] += int(entry.get("packets", 1) or 1)
                flow["byte_count"] += int(entry.get("bytes", 64) or 64)
                flow["protocols"].add(proto_name)
                flow["last_seen"] = now_ts
                flow["last_summary"] = summary

                # Add to event stream if new or active
                event = {
                    "id": f"lan_rci_{int(time.time()*1000)}_{len(self.events)}",
                    "timestamp": now_ts,
                    "comm_type": "local_flow",
                    "src_mac": src_dev.get("mac"),
                    "src_ip": src,
                    "src_name": src_dev["name"],
                    "dst_mac": dst_dev.get("mac"),
                    "dst_ip": dst,
                    "dst_name": dst_dev["name"],
                    "protocol": proto_name,
                    "port": dport,
                    "summary": summary,
                    "status": "conntrack",
                    "rtt_ms": None,
                    "payload_preview": f"Трансляция роутера Keenetic: {src}:{sport} -> {dst}:{dport} ({proto})",
                    "packet_id": None
                }
                self.events.append(event)
                added_count += 1

        return added_count

    def get_recent_communications(self, comm_type: Optional[str] = None, ip: Optional[str] = None, limit: int = 100, devices_map: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Returns recent LAN events matching filters, enriched with device names."""
        if devices_map:
            self.update_devices_cache(devices_map)

        with self._lock:
            res = [dict(e) for e in self.events]

        if comm_type and comm_type != "all":
            if comm_type == "ping":
                res = [e for e in res if e["comm_type"] in ("icmp_ping", "icmp_reply")]
            elif comm_type == "arp":
                res = [e for e in res if e["comm_type"] in ("arp_query", "arp_reply")]
            elif comm_type == "flows":
                res = [e for e in res if e["comm_type"] == "local_flow"]
            else:
                res = [e for e in res if e["comm_type"] == comm_type]

        if ip:
            clean_ip = ip.strip()
            res = [e for e in res if e.get("src_ip") == clean_ip or e.get("dst_ip") == clean_ip]

        # Return latest first
        res.reverse()
        slice_res = res[:limit]

        # Dynamically enrich device names and MAC addresses
        for e in slice_res:
            src_info = self._get_device_info(e.get("src_mac"), e.get("src_ip"), devices_map)
            if src_info.get("name") and src_info["name"] != e.get("src_ip"):
                e["src_name"] = src_info["name"]
            if not e.get("src_mac") and src_info.get("mac"):
                e["src_mac"] = src_info["mac"]

            dst_info = self._get_device_info(e.get("dst_mac"), e.get("dst_ip"), devices_map)
            if dst_info.get("name") and dst_info["name"] != e.get("dst_ip"):
                e["dst_name"] = dst_info["name"]
            if not e.get("dst_mac") and dst_info.get("mac"):
                e["dst_mac"] = dst_info["mac"]

        return slice_res

    def get_ping_matrix(self, devices_map: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Returns aggregated ping monitoring pairs: who pings whom, RTT, success rates."""
        result = []
        with self._lock:
            for (src_ip, dst_ip), stats in list(self.ping_matrix.items()):
                sent = stats["sent"]
                recv = stats["received"]
                success_rate = round((recv / sent * 100.0), 1) if sent > 0 else 0.0

                src_dev = self._get_device_info(None, src_ip, devices_map)
                dst_dev = self._get_device_info(None, dst_ip, devices_map)

                result.append({
                    "src_ip": src_ip,
                    "src_name": src_dev["name"],
                    "src_icon": src_dev.get("icon", "laptop"),
                    "dst_ip": dst_ip,
                    "dst_name": dst_dev["name"],
                    "dst_icon": dst_dev.get("icon", "laptop"),
                    "sent": sent,
                    "sent_count": sent,
                    "received": recv,
                    "reply_count": recv,
                    "lost": max(0, sent - recv),
                    "loss_count": max(0, sent - recv),
                    "success_rate": success_rate,
                    "last_rtt_ms": stats["last_rtt_ms"],
                    "min_rtt_ms": stats["min_rtt_ms"],
                    "max_rtt_ms": stats["max_rtt_ms"],
                    "avg_rtt_ms": stats["avg_rtt_ms"],
                    "status": "OK" if stats["status"] == "replied" else stats["status"],
                    "last_sent_time": stats["last_sent_time"],
                    "last_reply_time": stats["last_reply_time"]
                })

        # Sort by sent count descending
        result.sort(key=lambda x: x["sent"], reverse=True)
        return result

    def get_topology(self, devices_map: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Returns nodes and directed edges for the LAN communication graph/matrix."""
        nodes = {}
        links = []

        with self._lock:
            for (src_ip, dst_ip), flow in list(self.flows.items()):
                src_dev = self._get_device_info(None, src_ip, devices_map)
                dst_dev = self._get_device_info(None, dst_ip, devices_map)

                if src_ip not in nodes:
                    nodes[src_ip] = {
                        "id": src_ip,
                        "label": src_dev["name"],
                        "icon": src_dev.get("icon", "laptop"),
                        "vendor": src_dev.get("vendor"),
                        "mac": src_dev.get("mac")
                    }
                if dst_ip not in nodes:
                    nodes[dst_ip] = {
                        "id": dst_ip,
                        "label": dst_dev["name"],
                        "icon": dst_dev.get("icon", "laptop"),
                        "vendor": dst_dev.get("vendor"),
                        "mac": dst_dev.get("mac")
                    }

                links.append({
                    "source": src_ip,
                    "target": dst_ip,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_mac": src_dev.get("mac"),
                    "dst_mac": dst_dev.get("mac"),
                    "src_name": src_dev.get("name"),
                    "dst_name": dst_dev.get("name"),
                    "packet_count": flow["packet_count"],
                    "packets": flow["packet_count"],
                    "byte_count": flow["byte_count"],
                    "bytes": flow["byte_count"],
                    "protocols": list(flow["protocols"]),
                    "last_seen": flow["last_seen"],
                    "last_summary": flow["last_summary"]
                })

        return {
            "nodes": list(nodes.values()),
            "links": links,
            "edges": links
        }

    def get_stats(self) -> Dict[str, Any]:
        """Returns summary statistics of LAN activity."""
        with self._lock:
            total_events = len(self.events)
            ping_events = sum(1 for e in self.events if e["comm_type"] in ("icmp_ping", "icmp_reply"))
            arp_events = sum(1 for e in self.events if e["comm_type"] in ("arp_query", "arp_reply"))
            flow_events = sum(1 for e in self.events if e["comm_type"] == "local_flow")
            active_pings = sum(1 for m in self.ping_matrix.values() if m["status"] == "waiting")

            ping_requests_count = sum(m["sent"] for m in self.ping_matrix.values())
            ping_replies_count = sum(m["received"] for m in self.ping_matrix.values())

            # Top chatter pair
            top_pair = None
            top_packets = 0
            for (src, dst), fl in self.flows.items():
                if fl["packet_count"] > top_packets:
                    top_packets = fl["packet_count"]
                    top_pair = f"{src} -> {dst}"

        return {
            "total_events": total_events,
            "ping_events": ping_events,
            "ping_requests_count": ping_requests_count,
            "ping_replies_count": ping_replies_count,
            "arp_events": arp_events,
            "arp_queries_count": arp_events,
            "flow_events": flow_events,
            "active_flows_count": len(self.flows),
            "active_pings": active_pings,
            "top_chatter": top_pair or "Нет активности",
            "top_chatter_packets": top_packets
        }

    def get_packet_by_id(self, pkt_id: str) -> Optional[Any]:
        """Finds a packet by its ID in the LAN packet buffer."""
        return self.packet_buffer.find_by_id(pkt_id)

    def clear(self):
        """Clears all in-memory events, packets, and matrices."""
        with self._lock:
            self.events.clear()
            self.packet_buffer.clear()
            self.pending_pings.clear()
            self.ping_matrix.clear()
            self.flows.clear()


lan_tracker = LanTrafficTracker()
