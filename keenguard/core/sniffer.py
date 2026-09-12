import asyncio
import logging
import queue
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Callable, List, Tuple, Any, Iterable, Set
from scapy.all import Packet, IP, IPv6, UDP, TCP, ARP, Ether, ICMP, wrpcap

class PacketRingBuffer:
    """Stores the latest N packets for forensic analysis and PCAP dumping."""
    def __init__(self, max_packets: int = 500, max_age_seconds: Optional[float] = None):
        self.max_packets = max_packets
        self.max_age_seconds = max_age_seconds
        self.buffer: deque = deque(maxlen=max_packets)
        self._lock = threading.Lock()
        self._counter = 0
        self.last_pkt_id: Optional[str] = None

    def add(self, pkt: Packet, pid: Optional[str] = None, timestamp: Optional[float] = None):
        with self._lock:
            ts = timestamp if timestamp is not None else float(getattr(pkt, "time", time.time()))
            self._counter += 1
            if pid is None:
                src_mac = pkt[Ether].src.replace(":", "")[-4:].upper() if Ether in pkt else "0000"
                pkt_id = f"pkt_{int(ts*1000)}_{src_mac}_{self._counter % 10000}"
            else:
                pkt_id = pid
            self.last_pkt_id = pkt_id
            self.buffer.append((ts, pkt, pkt_id))

            # Prune packets older than max_age_seconds if configured
            if self.max_age_seconds and self.max_age_seconds > 0:
                cutoff = ts - self.max_age_seconds
                while self.buffer and self.buffer[0][0] < cutoff:
                    self.buffer.popleft()

    def clear(self):
        with self._lock:
            self.buffer.clear()
            self._counter = 0
            self.last_pkt_id = None

    def __len__(self) -> int:
        with self._lock:
            return len(self.buffer)

    def get_packets(self, filter_func: Optional[Callable[[Any], bool]] = None) -> List[Any]:
        with self._lock:
            if filter_func:
                return [p[1] for p in self.buffer if filter_func(p[1])]
            return [p[1] for p in self.buffer]

    def get_packets_since(self, cutoff_timestamp: float, filter_func: Optional[Callable[[Any], bool]] = None) -> List[Any]:
        """Returns packets captured at or after cutoff_timestamp."""
        with self._lock:
            if filter_func:
                return [p[1] for p in self.buffer if p[0] >= cutoff_timestamp and filter_func(p[1])]
            return [p[1] for p in self.buffer if p[0] >= cutoff_timestamp]

    def get_packets_with_meta(self, filter_func: Optional[Callable[[Any], bool]] = None) -> List[Tuple[float, Any, str]]:
        with self._lock:
            if filter_func:
                return [p for p in self.buffer if filter_func(p[1])]
            return list(self.buffer)

    def find_by_id(self, target_id: str) -> Optional[Any]:
        with self._lock:
            for ts, pkt, pid in self.buffer:
                if pid == target_id:
                    return pkt
            return None

    def dump_pcap(self, filepath: Path, filter_func: Optional[Callable[[Any], bool]] = None) -> int:
        pkts = self.get_packets(filter_func=filter_func)
        if pkts:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            wrpcap(str(filepath), pkts)
            return len(pkts)
        return 0

from keenguard.config import settings
from keenguard.core.dissector import PacketDissector
from keenguard.db.models import IotPayloadRecord

logger = logging.getLogger("keenguard.sniffer")

PORT_NAMES = {
    21: "FTP (Передача файлов)",
    22: "SSH (Удаленный терминал)",
    23: "Telnet (Незащищенный терминал)",
    80: "HTTP (Веб-интерфейс)",
    139: "NetBIOS (Сетевое окружение)",
    445: "SMB (Сетевые папки Windows/NAS)",
    1433: "MSSQL Database",
    3306: "MySQL Database",
    3389: "RDP (Удаленный рабочий стол)",
    5555: "ADB (Отладка Android)",
    8080: "HTTP-Alt (Веб-портал)"
}

class NetworkSniffer:
    def __init__(self):
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._db_thread: Optional[threading.Thread] = None
        self._db_queue: queue.Queue = queue.Queue(maxsize=1500)
        self.ring_buffers: Dict[str, PacketRingBuffer] = {}  # keyed by MAC
        self.tracked_tv_macs: Set[str] = set()
        self.global_buffer = PacketRingBuffer(max_packets=1000)
        self.pcap_buffer = PacketRingBuffer(max_packets=3000)
        self.active_pcap_name: Optional[str] = None
        self.event_callbacks: List[Callable[[Dict], None]] = []

    def set_tracked_tvs(self, macs: Iterable[str], pre_record_seconds: Optional[int] = None):
        """Only allocate and maintain dedicated pre-wake ring buffers for tracked TVs."""
        clean_macs = {m.upper() for m in macs if m}
        pre_sec = pre_record_seconds if pre_record_seconds is not None else getattr(settings, "tv_wake_pre_record_seconds", 30)
        max_age = float(pre_sec + 15)
        max_pkts = max(500, int(pre_sec * 40))

        self.tracked_tv_macs = clean_macs
        # Discard buffers for devices no longer tracked as Smart TV
        to_remove = [m for m in list(self.ring_buffers.keys()) if m not in clean_macs]
        for m in to_remove:
            self.ring_buffers.pop(m, None)

        for m in clean_macs:
            if m not in self.ring_buffers:
                self.ring_buffers[m] = PacketRingBuffer(max_packets=max_pkts, max_age_seconds=max_age)
            else:
                self.ring_buffers[m].max_age_seconds = max_age
                self.ring_buffers[m].max_packets = max_pkts

    @property
    def ring_buffer(self) -> PacketRingBuffer:
        """Compatibility property returning the global ring buffer."""
        return self.global_buffer

    @property
    def is_running(self) -> bool:
        return self.running

    def load_pcap_packets(self, pkts: List[Any], source_name: str = ""):
        """Loads packets from a PCAP dump into the inspector's pcap_buffer."""
        self.pcap_buffer.clear()
        self.active_pcap_name = source_name
        for idx, pkt in enumerate(pkts):
            pkt_time = float(getattr(pkt, "time", time.time()))
            self.pcap_buffer.add(pkt, pid=f"pcap_{idx}", timestamp=pkt_time)

    def clear_pcap(self):
        """Clears the PCAP buffer and returns to live mode."""
        self.pcap_buffer.clear()
        self.active_pcap_name = None

    def get_packet_by_id(self, pkt_id: str) -> Optional[Any]:
        """Finds a packet by its unique ID in the PCAP buffer, global buffer, per-device buffers, or LAN tracker."""
        if self.pcap_buffer:
            pkt = self.pcap_buffer.find_by_id(pkt_id)
            if pkt is not None:
                return pkt
        pkt = self.global_buffer.find_by_id(pkt_id)
        if pkt is not None:
            return pkt
        for buf in self.ring_buffers.values():
            pkt = buf.find_by_id(pkt_id)
            if pkt is not None:
                return pkt
        try:
            from keenguard.core.lan_tracker import lan_tracker
            pkt = lan_tracker.get_packet_by_id(pkt_id)
            if pkt is not None:
                return pkt
        except Exception as e:
            logger.debug("Error retrieving packet from lan_tracker: %s", e)
        return None

    def register_callback(self, cb: Callable[[Dict], None]):
        self.event_callbacks.append(cb)

    def _emit_event(self, event_dict: Dict):
        for cb in self.event_callbacks:
            try:
                cb(event_dict)
            except RuntimeError as e:
                if "no running event loop" in str(e).lower():
                    logger.debug("Event loop not active during sniffer callback: %s", e)
                else:
                    logger.error("Runtime error in sniffer event callback: %s", e)
            except Exception as e:
                logger.error("Error in sniffer event callback: %s", e)

    @staticmethod
    def parse_wol(raw_payload: bytes) -> Optional[str]:
        """
        Parses a Wake-on-LAN Magic Packet.
        Format: 6 bytes of 0xFF followed by 16 repetitions of the target MAC (6 bytes).
        Returns the target MAC address in 'AA:BB:CC:DD:EE:FF' format or None.
        """
        if len(raw_payload) < 102:
            return None

        # Look for 6 consecutive 0xFF bytes
        idx = raw_payload.find(b"\xff" * 6)
        if idx == -1 or len(raw_payload) < idx + 102:
            return None

        mac_bytes = raw_payload[idx + 6: idx + 12]
        # Verify 16 repetitions
        if raw_payload[idx + 6: idx + 102] == mac_bytes * 16:
            target_mac = ":".join(f"{b:02X}" for b in mac_bytes)
            return target_mac

        return None

    def _process_packet(self, pkt: Packet):
        try:
            self.global_buffer.add(pkt)
            from keenguard.core.audit import audit_manager
            audit_manager.process_packet(pkt)

            src_mac = pkt[Ether].src.upper() if Ether in pkt else None
            dst_mac = pkt[Ether].dst.upper() if Ether in pkt else None

            # Add to per-device ring buffers ONLY for tracked Smart TVs (saves RAM, respects settings)
            if self.tracked_tv_macs:
                if src_mac and src_mac in self.tracked_tv_macs:
                    if src_mac not in self.ring_buffers:
                        self.ring_buffers[src_mac] = PacketRingBuffer(max_packets=1000, max_age_seconds=60)
                    self.ring_buffers[src_mac].add(pkt)
                if dst_mac and dst_mac in self.tracked_tv_macs:
                    if dst_mac not in self.ring_buffers:
                        self.ring_buffers[dst_mac] = PacketRingBuffer(max_packets=1000, max_age_seconds=60)
                    self.ring_buffers[dst_mac].add(pkt)

            # Route to active post-wake forensics collectors if TV wake session is recording
            from keenguard.core.forensics import forensics
            forensics.on_packet(pkt, src_mac, dst_mac)

            # 0. LAN communication tracking (Pings, Replies, ARP, local flows)
            from keenguard.core.lan_tracker import lan_tracker
            lan_tracker.process_packet(pkt)

            # MAC-IP binding tracking for conflict / ARP spoofing detection
            if ARP in pkt:
                arp_layer = pkt[ARP]
                arp_mac = getattr(arp_layer, "hwsrc", None) or src_mac
                arp_ip = getattr(arp_layer, "psrc", None)
                if arp_mac and arp_ip:
                    self._emit_event({
                        "event_type": "mac_ip_binding",
                        "mac": arp_mac,
                        "ip": arp_ip
                    })
            elif IP in pkt and src_mac:
                ip_src = pkt[IP].src
                if ip_src and ip_src.startswith(("192.168.", "10.", "172.")):
                    self._emit_event({
                        "event_type": "mac_ip_binding",
                        "mac": src_mac,
                        "ip": ip_src
                    })

            # 0.1 IoT payload capture
            if getattr(settings, "iot_payload_capture_enabled", True) and (src_mac or dst_mac):
                self._check_and_queue_iot_payload(pkt, src_mac, dst_mac)

            # 1. Inspect Wake-on-LAN (UDP port 7 or 9 or broadcast payload)
            if UDP in pkt and (pkt[UDP].dport in [7, 9] or pkt[UDP].sport in [7, 9]):
                payload = bytes(pkt[UDP].payload)
                target_mac = self.parse_wol(payload)
                if target_mac:
                    src_ip = pkt[IP].src if IP in pkt else "Unknown IP"
                    logger.warning("WOL Magic Packet detected! Target: %s from %s (%s)", target_mac, src_ip, src_mac)
                    self._emit_event({
                        "event_type": "wol_wake",
                        "severity": "warning",
                        "target_mac": target_mac,
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "description": f"Wake-on-LAN magic packet sent to {target_mac} by {src_ip} ({src_mac})",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"dst_port": pkt[UDP].dport, "protocol": "UDP/WOL"}
                    })

            # 2. Inspect mDNS / Bonjour (UDP 5353) - AirPlay & Cast
            elif UDP in pkt and pkt[UDP].dport == 5353:
                payload = bytes(pkt[UDP].payload)
                src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else (src_mac or "Unknown"))
                # Check for AirPlay / RAOP signatures
                if b"_airplay._tcp" in payload or b"_raop._tcp" in payload:
                    self._emit_event({
                        "event_type": "airplay_activity",
                        "severity": "info",
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "description": f"AirPlay discovery query/announcement from {src_ip}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"protocol": "mDNS", "service": "AirPlay"}
                    })
                elif b"_googlecast._tcp" in payload:
                    self._emit_event({
                        "event_type": "cast_activity",
                        "severity": "info",
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "description": f"Google Cast discovery query from {src_ip}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"protocol": "mDNS", "service": "GoogleCast"}
                    })

            # 3. Inspect SSDP (UDP 1900) - DIAL / UPnP
            elif UDP in pkt and pkt[UDP].dport == 1900:
                payload = bytes(pkt[UDP].payload)
                src_ip = pkt[IP].src if IP in pkt else (pkt[IPv6].src if IPv6 in pkt else (src_mac or "Unknown"))
                if b"urn:dial-multiscreen-org" in payload:
                    self._emit_event({
                        "event_type": "dial_activity",
                        "severity": "info",
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "description": f"DIAL (Second Screen / Cast) probe from {src_ip}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"protocol": "SSDP/DIAL"}
                    })

            # 4. Inspect ARP probes / sweeps (App Reconnaissance / LAN scanning)
            elif ARP in pkt and pkt[ARP].op == 1:  # who-has request
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                from keenguard.core.keenetic import keenetic_client
                if not keenetic_client.is_router_entity(ip=src_ip, mac=src_mac):
                    self._emit_event({
                        "event_type": "arp_probe",
                        "severity": "info",
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "description": f"ARP probe from {src_ip} looking for {dst_ip}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"opcode": "who-has"}
                    })

            # 5. Inspect TCP SYN probes to sensitive internal ports (Telnet 23, SSH 22, SMB 445, RDP 3389, ADB 5555, etc.)
            elif TCP in pkt and (pkt[TCP].flags & 0x02):  # SYN flag is set
                src_ip = pkt[IP].src if IP in pkt else None
                dst_ip = pkt[IP].dst if IP in pkt else None
                dport = pkt[TCP].dport
                service_name = PORT_NAMES.get(dport, f"порт {dport}")

                # Flag probes to sensitive services
                if dport in [21, 22, 23, 139, 445, 1433, 3306, 3389, 5555]:
                    logger.warning("Connection attempt: %s -> %s:%d (%s)", src_ip, dst_ip, dport, service_name)
                    self._emit_event({
                        "event_type": "port_probe",
                        "severity": "warning",
                        "source_mac": src_mac,
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "description": f"Попытка подключения к {service_name}: {src_ip} -> {dst_ip}:{dport}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "details": {"port": dport, "protocol": "TCP", "service": service_name, "action": "observed"}
                    })

        except Exception as e:
            logger.debug("Packet processing error: %s", e)

    def _check_and_queue_iot_payload(self, pkt: Packet, src_mac: Optional[str], dst_mac: Optional[str]):
        """Inspects and queues payload data from IoT devices."""
        try:
            payload_meta = PacketDissector.extract_payload_summary(pkt)
            if not payload_meta:
                return

            size = payload_meta.get("size", 0)
            proto = payload_meta.get("protocol", "RAW")
            dst_port = payload_meta.get("dst_port")

            # Ignore generic non-IoT bulk traffic (e.g. PC HTTPS/ephemeral port streams)
            if proto in ("TCP", "UDP", "RAW"):
                sport = getattr(pkt[TCP], "sport", None) if TCP in pkt else (getattr(pkt[UDP], "sport", None) if UDP in pkt else None)
                known_iot_ports = {80, 8080, 8000, 8200, 554, 1883, 8883, 5683, 1900, 5353, 123}
                if dst_port not in known_iot_ports and sport not in known_iot_ports:
                    return

            # Only record if there is actual payload or meaningful protocol
            if size == 0 and proto not in ("MQTT", "HTTP", "NTP", "DNS", "mDNS", "SSDP", "CoAP"):
                return

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            elif ARP in pkt:
                src_ip = getattr(pkt[ARP], "psrc", "0.0.0.0")
                dst_ip = getattr(pkt[ARP], "pdst", "0.0.0.0")
            else:
                src_ip = "0.0.0.0"
                dst_ip = "0.0.0.0"

            # Determine target device MAC and direction
            from keenguard.core.keenetic import keenetic_client

            is_src_router = keenetic_client.is_router_entity(mac=src_mac)
            is_dst_router = keenetic_client.is_router_entity(mac=dst_mac)

            if is_src_router and dst_mac:
                target_mac = dst_mac
                direction = "inbound"
            elif is_dst_router and src_mac:
                target_mac = src_mac
                direction = "outbound"
            elif src_mac:
                target_mac = src_mac
                direction = "outbound"
            else:
                target_mac = dst_mac or "00:00:00:00:00:00"
                direction = "inbound"

            summary = f"{proto}: {src_ip} -> {dst_ip}"
            if dst_port:
                summary += f":{dst_port}"
            if payload_meta.get("text"):
                summary += f" ({payload_meta['text'][:40]}...)"

            rec = IotPayloadRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                mac=target_mac,
                device_name=None,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                direction=direction,
                summary=summary,
                payload_text=payload_meta.get("text"),
                payload_hex=payload_meta.get("hex"),
                byte_size=size,
                raw_json=None
            )
            try:
                self._db_queue.put_nowait(rec)
            except queue.Full:
                pass
        except Exception as e:
            logger.debug("Error queuing IoT payload: %s", e)

    def _db_worker(self):
        """Worker thread that persists queued IoT payloads to SQLite asynchronously."""
        from keenguard.db.database import db
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        while self.running:
            try:
                rec = self._db_queue.get(timeout=1.0)
                try:
                    loop.run_until_complete(db.add_iot_payload(rec))
                except Exception as ex:
                    logger.debug("Error saving IoT payload to DB: %s", ex)
                finally:
                    self._db_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.debug("Error in db_worker: %s", e)
        loop.close()

    def start(self, interface: Optional[str] = None):
        if self.running:
            return
        self.running = True

        # Start background DB writer thread for IoT payloads
        self._db_thread = threading.Thread(target=self._db_worker, daemon=True)
        self._db_thread.start()

        def _sniff_worker():
            from scapy.all import sniff
            logger.info("Starting network sniffer thread (interface=%s)...", interface or "default")
            try:
                # BPF filter targeting ICMP, ARP, broadcast/multicast UDP, DNS, NTP, SSDP, mDNS, CoAP,
                # and TCP on web/IoT/camera/sensitive ports (HTTPS 443, HTTP 80/8080/8000, RTSP 554, MQTT 1883/8883, DLNA 8200, etc.)
                bpf = (
                    "icmp or arp or "
                    "(udp and (port 7 or port 9 or port 53 or port 123 or port 1900 or port 5353 or port 5683)) or "
                    "(tcp and (port 21 or port 22 or port 23 or port 80 or port 443 or port 554 or "
                    "port 1883 or port 8883 or port 139 or port 445 or port 1433 or port 3306 or "
                    "port 3389 or port 5000 or port 5555 or port 8000 or port 8080 or port 8200))"
                )
                sniff_kwargs = {
                    "filter": bpf,
                    "prn": self._process_packet,
                    "store": 0,
                    "stop_filter": lambda _: not self.running
                }
                if interface:
                    sniff_kwargs["iface"] = interface
                sniff(**sniff_kwargs)
            except Exception as e:
                logger.warning("Scapy live sniffing encountered an issue (WinPcap/Npcap may be required for raw promiscuous capture): %s. Passive fallback active.", e)

        self._thread = threading.Thread(target=_sniff_worker, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._db_thread and self._db_thread.is_alive():
            try:
                self._db_thread.join(timeout=1.0)
            except Exception:
                pass

sniffer = NetworkSniffer()
