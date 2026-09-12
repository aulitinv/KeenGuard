"""
Deep Packet Inspector and Protocol Dissector for KeenGuard.
Decodes packet layers, protocol fields, byte offsets, and hex dumps.
Supports NTP, DNS, HTTP, MQTT, TLS ClientHello, SSDP, ICMP, ARP, CoAP, and raw payloads.
"""
import json
import logging
import struct
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Union
from scapy.all import Packet, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR, DNSRR

logger = logging.getLogger("keenguard.dissector")

ICMP_TYPES = {
    0: ("Echo Reply", "Ответ на эхо-запрос (Ping Reply)"),
    3: ("Destination Unreachable", "Узел назначения недоступен"),
    4: ("Source Quench", "Подавление источника"),
    5: ("Redirect", "Перенаправление маршрута"),
    8: ("Echo Request", "Эхо-запрос (Ping Request)"),
    9: ("Router Advertisement", "Объявление маршрутизатора"),
    10: ("Router Solicitation", "Запрос маршрутизатора"),
    11: ("Time Exceeded", "Превышен TTL пакета (Time to Live Exceeded)"),
    12: ("Parameter Problem", "Ошибка в параметрах заголовка IP"),
    13: ("Timestamp", "Запрос временного штампа"),
    14: ("Timestamp Reply", "Ответ временного штампа"),
}

MQTT_CONTROL_PACKET_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH"
}

TCP_PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    139: "NetBIOS",
    443: "HTTPS / TLS",
    445: "SMB",
    554: "RTSP (Video)",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP / Media",
    5555: "ADB (Android)",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8200: "DLNA (Keenetic)",
    8443: "HTTPS-Alt",
    8883: "MQTT-TLS"
}

UDP_PORT_NAMES = {
    7: "Echo / WOL",
    9: "Discard / WOL",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    123: "NTP (Сетевое время)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    161: "SNMP",
    1900: "SSDP / UPnP",
    5353: "mDNS (Bonjour/Cast)",
    5683: "CoAP"
}


class PacketDissector:
    """Dissects Scapy packets into layers, protocol fields, byte ranges, and hex dumps."""

    @classmethod
    def generate_hex_dump(cls, raw_bytes: bytes) -> List[Dict[str, str]]:
        """
        Formats raw bytes into 16-byte aligned Hex + ASCII rows.
        Example row: {'offset': '00000000', 'hex': '58 2d 34 ...', 'ascii': 'X-4q...'}
        """
        rows = []
        if not raw_bytes:
            return rows

        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i + 16]
            offset_str = f"{i:08x}"
            hex_parts = [f"{b:02x}" for b in chunk]
            hex_str = " ".join(hex_parts)
            # Pad hex string if chunk < 16 bytes
            if len(chunk) < 16:
                hex_str = hex_str.ljust(16 * 3 - 1)

            ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in chunk]
            ascii_str = "".join(ascii_chars)

            rows.append({
                "offset": offset_str,
                "hex": hex_str,
                "ascii": ascii_str,
                "byte_start": i,
                "byte_end": i + len(chunk) - 1
            })
        return rows

    @classmethod
    def decode_ntp(cls, payload: bytes, base_offset: int) -> Optional[Dict[str, Any]]:
        """Decodes RFC 5905 Network Time Protocol (48 bytes minimum)."""
        if len(payload) < 48:
            return None

        first_byte = payload[0]
        li = (first_byte >> 6) & 0x03
        version = (first_byte >> 3) & 0x07
        mode = first_byte & 0x07
        stratum = payload[1]
        poll = payload[2]
        precision = struct.unpack("!b", payload[3:4])[0]

        root_delay = struct.unpack("!I", payload[4:8])[0] / 65536.0
        root_disp = struct.unpack("!I", payload[8:12])[0] / 65536.0
        ref_id_bytes = payload[12:16]

        if stratum <= 1:
            ref_id_str = ref_id_bytes.decode("ascii", errors="replace").strip()
        else:
            ref_id_str = ".".join(str(b) for b in ref_id_bytes)

        # Transmit timestamp (bytes 40..48)
        sec, frac = struct.unpack("!II", payload[40:48])
        # NTP epoch is 1900-01-01, Unix epoch is 1970-01-01 (offset 2208988800s)
        unix_ts = sec - 2208988800 if sec >= 2208988800 else sec
        human_time = datetime.fromtimestamp(max(0, unix_ts), tz=timezone.utc).isoformat() if unix_ts > 0 else "0"

        mode_names = {1: "Symmetric Active", 2: "Symmetric Passive", 3: "Client (Запрос)", 4: "Server (Ответ)", 5: "Broadcast"}
        mode_str = mode_names.get(mode, f"Mode {mode}")

        return {
            "name": "Network Time Protocol (NTP)",
            "offset": base_offset,
            "length": 48,
            "fields": {
                "Mode": f"{mode_str} ({mode})",
                "Version": version,
                "Version Name": f"NTPv{version}",
                "Leap Indicator": f"{li} (Предупреждение секунды координации)",
                "Stratum": f"{stratum} ({'Primary reference' if stratum == 1 else 'Secondary reference' if 2 <= stratum <= 15 else 'Unspecified'})",
                "Poll Interval": f"2^{poll} ({2**poll if 0 <= poll <= 20 else poll} сек)",
                "Precision": f"{2**precision:.6f} сек",
                "Root Delay": f"{root_delay:.4f} мс",
                "Root Dispersion": f"{root_disp:.4f} мс",
                "Reference ID": ref_id_str,
                "Transmit Timestamp": human_time,
                "Пояснение": "Служебный запрос/ответ точного времени. Полезная нагрузка пользователя отсутствует."
            }
        }

    @classmethod
    def decode_http(cls, payload: bytes, base_offset: int) -> Optional[Dict[str, Any]]:
        """Decodes HTTP 1.0/1.1 request or response."""
        try:
            text = payload.decode("iso-8859-1")
        except Exception:
            return None

        if "\r\n\r\n" in text:
            header_part, body_part = text.split("\r\n\r\n", 1)
        elif "\n\n" in text:
            header_part, body_part = text.split("\n\n", 1)
        else:
            header_part, body_part = text, ""

        lines = header_part.splitlines()
        if not lines:
            return None

        first_line = lines[0].strip()
        is_request = any(first_line.startswith(m) for m in ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "])
        is_response = first_line.startswith("HTTP/")

        if not (is_request or is_response):
            return None

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip()
                v_clean = v.strip()
                # Mask sensitive headers
                if k_clean.lower() in ("authorization", "cookie", "set-cookie", "x-auth-token"):
                    v_clean = "******** [PROTECTED]"
                headers[k_clean] = v_clean

        # Check body format
        body_preview = body_part[:1000]
        if "application/json" in headers.get("Content-Type", ""):
            try:
                parsed_json = json.loads(body_part)
                body_preview = json.dumps(parsed_json, ensure_ascii=False, indent=2)
            except Exception:
                pass

        fields = {
            "First Line": first_line,
            "Type": "HTTP Request" if is_request else "HTTP Response",
            "Headers Count": len(headers),
        }
        if is_request:
            parts = first_line.split(" ", 2)
            if len(parts) >= 1:
                fields["Method"] = parts[0]
            if len(parts) >= 2:
                fields["URI"] = parts[1]
            if len(parts) >= 3:
                fields["HTTP Version"] = parts[2]
        elif is_response:
            parts = first_line.split(" ", 2)
            if len(parts) >= 2:
                fields["Status Code"] = parts[1]
            if len(parts) >= 3:
                fields["Status Text"] = parts[2]

        for hk, hv in list(headers.items())[:12]:
            fields[f"Header: {hk}"] = hv

        if body_part:
            fields["Body Size"] = f"{len(body_part)} байт"
            fields["Body Preview"] = body_preview[:500]

        return {
            "name": "Hypertext Transfer Protocol (HTTP)",
            "offset": base_offset,
            "length": len(payload),
            "fields": fields
        }

    @classmethod
    def decode_mqtt(cls, payload: bytes, base_offset: int) -> Optional[Dict[str, Any]]:
        """Decodes MQTT 3.1.1 / 5.0 Control Packets (PUBLISH, CONNECT, PINGREQ, etc.)."""
        if len(payload) < 2:
            return None

        first_byte = payload[0]
        packet_type = (first_byte >> 4) & 0x0F
        flags = first_byte & 0x0F

        if packet_type not in MQTT_CONTROL_PACKET_TYPES:
            return None

        type_name = MQTT_CONTROL_PACKET_TYPES[packet_type]

        # Remaining length decoder
        multiplier = 1
        rem_len = 0
        idx = 1
        while idx < len(payload) and idx <= 4:
            encoded_byte = payload[idx]
            rem_len += (encoded_byte & 127) * multiplier
            multiplier *= 128
            idx += 1
            if (encoded_byte & 128) == 0:
                break

        fields: Dict[str, Any] = {
            "Packet Type": type_name,
            "Packet Type Code": packet_type,
            "Flags": f"0x{flags:x}",
            "Remaining Length": f"{rem_len} байт"
        }

        # Specific decoders
        if type_name == "PUBLISH" and idx + 2 <= len(payload):
            topic_len = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2
            if idx + topic_len <= len(payload):
                topic = payload[idx:idx + topic_len].decode("utf-8", errors="replace")
                idx += topic_len
                fields["Topic"] = topic

                # Check QoS
                qos = (flags >> 1) & 0x03
                fields["QoS"] = qos
                if qos > 0 and idx + 2 <= len(payload):
                    pkt_id = struct.unpack("!H", payload[idx:idx + 2])[0]
                    fields["Packet ID"] = pkt_id
                    idx += 2

                # Message payload
                msg_payload = payload[idx:]
                try:
                    payload_str = msg_payload.decode("utf-8")
                    try:
                        parsed_json = json.loads(payload_str)
                        fields["Payload (JSON)"] = json.dumps(parsed_json, ensure_ascii=False, indent=2)
                    except Exception:
                        fields["Payload (Text)"] = payload_str
                except Exception:
                    fields["Payload (Hex)"] = msg_payload.hex()

        elif type_name == "CONNECT" and idx + 2 <= len(payload):
            proto_len = struct.unpack("!H", payload[idx:idx + 2])[0]
            idx += 2
            if idx + proto_len <= len(payload):
                proto_name = payload[idx:idx + proto_len].decode("ascii", errors="replace")
                fields["Protocol Name"] = proto_name
                idx += proto_len
                if idx < len(payload):
                    proto_level = payload[idx]
                    fields["Protocol Level"] = f"v{proto_level}"
                    idx += 1
                if idx < len(payload):
                    connect_flags = payload[idx]
                    idx += 1
                if idx + 2 <= len(payload):
                    keep_alive = struct.unpack("!H", payload[idx:idx + 2])[0]
                    fields["Keep Alive"] = f"{keep_alive}s"
                    idx += 2
                if idx + 2 <= len(payload):
                    cid_len = struct.unpack("!H", payload[idx:idx + 2])[0]
                    idx += 2
                    if idx + cid_len <= len(payload):
                        fields["Client ID"] = payload[idx:idx + cid_len].decode("utf-8", errors="replace")

        elif type_name in ("PINGREQ", "PINGRESP"):
            fields["Note"] = "Служебный heartbeat-сигнал (проверка связи брокера умного дома)"

        return {
            "name": f"MQTT Protocol [{type_name}]",
            "offset": base_offset,
            "length": len(payload),
            "fields": fields
        }

    @classmethod
    def decode_tls_client_hello(cls, payload: bytes, base_offset: int) -> Optional[Dict[str, Any]]:
        """Extracts TLS ClientHello Server Name Indication (SNI)."""
        if len(payload) < 43:
            return None

        # TLS Record Header: Content Type 22 (Handshake), Version 0x0301/0x0303
        if payload[0] != 22:
            return None

        # Handshake Type 1 = Client Hello
        if len(payload) < 6 or payload[5] != 1:
            return None

        idx = 5 + 4  # skip handshake type (1) + length (3)
        if idx + 2 > len(payload):
            return None

        tls_ver = struct.unpack("!H", payload[idx:idx + 2])[0]
        ver_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2 / TLS 1.3", 0x0304: "TLS 1.3"}
        ver_str = ver_map.get(tls_ver, f"0x{tls_ver:04x}")
        idx += 2 + 32  # skip version + 32 bytes random

        if idx >= len(payload):
            return None

        # Session ID length
        sess_id_len = payload[idx]
        idx += 1 + sess_id_len
        if idx + 2 > len(payload):
            return None

        # Cipher suites
        cipher_len = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2 + cipher_len
        if idx >= len(payload):
            return None

        # Compression methods
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return None

        # Extensions
        ext_total_len = struct.unpack("!H", payload[idx:idx + 2])[0]
        idx += 2
        sni_host = None

        ext_end = min(idx + ext_total_len, len(payload))
        while idx + 4 <= ext_end:
            ext_type = struct.unpack("!H", payload[idx:idx + 2])[0]
            ext_len = struct.unpack("!H", payload[idx + 2:idx + 4])[0]
            idx += 4
            if ext_type == 0 and idx + ext_len <= len(payload):  # Server Name
                # SNI list
                sni_idx = idx + 2  # skip list length
                if sni_idx + 3 <= len(payload):
                    name_type = payload[sni_idx]
                    name_len = struct.unpack("!H", payload[sni_idx + 1:sni_idx + 3])[0]
                    if name_type == 0 and sni_idx + 3 + name_len <= len(payload):
                        sni_host = payload[sni_idx + 3:sni_idx + 3 + name_len].decode("utf-8", errors="replace")
                        break
            idx += ext_len

        return {
            "name": "Transport Layer Security (TLS ClientHello)",
            "offset": base_offset,
            "length": len(payload),
            "fields": {
                "Handshake Type": "Client Hello (1)",
                "Version": ver_str,
                "Server Name (SNI)": sni_host or "Не указан (или зашифрован)",
                "Ciphers Count": cipher_len // 2,
                "Пояснение": f"Установление зашифрованного HTTPS/TLS соединения с хостом '{sni_host}'" if sni_host else "Зашифрованное TLS рукопожатие"
            }
        }

    @classmethod
    def decode_ssdp(cls, payload: bytes, base_offset: int) -> Optional[Dict[str, Any]]:
        """Decodes SSDP / UPnP discovery (M-SEARCH, NOTIFY)."""
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return None

        lines = text.splitlines()
        if not lines:
            return None

        first = lines[0].strip()
        if not any(first.startswith(prefix) for prefix in ["M-SEARCH ", "NOTIFY ", "HTTP/1.1 200 OK"]):
            return None

        fields: Dict[str, Any] = {"First Line": first}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().upper()
                if k_clean in ("HOST", "ST", "NT", "USN", "LOCATION", "SERVER"):
                    fields[k_clean] = v.strip()

        return {
            "name": "Simple Service Discovery Protocol (SSDP / UPnP)",
            "offset": base_offset,
            "length": len(payload),
            "fields": fields
        }

    @classmethod
    def dissect(cls, pkt: Any, pkt_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Deeply inspects a Scapy packet or raw packet bytes.
        Returns a structured JSON-ready dictionary with summary, layers, byte offsets,
        parsed application protocols, and interactive hex dump.
        """
        if not isinstance(pkt, Packet):
            # Try parsing from raw bytes
            try:
                pkt = Ether(pkt)
            except Exception:
                return {"status": "error", "message": "Невозможно разобрать пакет"}

        raw_bytes = bytes(pkt)
        total_len = len(raw_bytes)
        cur_offset = 0
        layers: List[Dict[str, Any]] = []

        # Default summary fields
        src_mac = None
        dst_mac = None
        src_ip = None
        dst_ip = None
        sport = None
        dport = None
        proto_name = "RAW"
        summary_str = pkt.summary() if hasattr(pkt, "summary") else "Сетевой пакет"
        badge = {"text": "NET", "color": "slate"}

        # 1. Ethernet Layer
        if Ether in pkt:
            eth = pkt[Ether]
            src_mac = str(eth.src).upper() if getattr(eth, "src", None) else "00:00:00:00:00:00"
            dst_mac = str(eth.dst).upper() if getattr(eth, "dst", None) else "FF:FF:FF:FF:FF:FF"
            eth_type = hex(eth.type) if hasattr(eth, "type") and eth.type is not None else "0x0800"
            type_name = "IPv4 (0x0800)" if getattr(eth, "type", 0) == 0x0800 else "ARP (0x0806)" if getattr(eth, "type", 0) == 0x0806 else "IPv6 (0x86dd)" if getattr(eth, "type", 0) == 0x86dd else str(eth_type)

            layers.append({
                "name": "Ethernet II",
                "offset": cur_offset,
                "length": 14,
                "fields": {
                    "Source MAC": src_mac,
                    "Destination MAC": dst_mac,
                    "Type": type_name
                }
            })
            cur_offset += 14

        # 2. ARP Layer
        if ARP in pkt:
            arp = pkt[ARP]
            op_name = "Who-has (Запрос адреса)" if arp.op == 1 else "Is-at (Ответ на запрос)" if arp.op == 2 else f"Opcode {arp.op}"
            proto_name = "ARP"
            badge = {"text": "ARP", "color": "amber"}
            src_ip = arp.psrc
            dst_ip = arp.pdst
            summary_str = f"ARP: {arp.psrc} спрашивает 'Кто имеет {arp.pdst}?'" if arp.op == 1 else f"ARP: {arp.psrc} сообщает 'Мой MAC {arp.hwsrc}'"

            layers.append({
                "name": "Address Resolution Protocol (ARP)",
                "offset": cur_offset,
                "length": 28,
                "fields": {
                    "Hardware Type": hex(arp.hwtype) if hasattr(arp, "hwtype") else "0x1",
                    "Protocol Type": hex(arp.ptype) if hasattr(arp, "ptype") else "0x800",
                    "Opcode": f"{arp.op} ({op_name})",
                    "Sender MAC": str(arp.hwsrc).upper() if getattr(arp, "hwsrc", None) else "",
                    "Sender IP": arp.psrc,
                    "Target MAC": str(arp.hwdst).upper() if getattr(arp, "hwdst", None) else "",
                    "Target IP": arp.pdst
                }
            })
            cur_offset += 28

        # 3. IP Layer
        ip_layer_len = 0
        if IP in pkt:
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto_name = "IP"
            ihl_val = getattr(ip, "ihl", None)
            ip_layer_len = (ihl_val * 4) if ihl_val is not None else 20
            ip_proto = getattr(ip, "proto", 0) or 0
            ip_ttl = getattr(ip, "ttl", 64) or 64
            ip_len = getattr(ip, "len", None) or len(ip)
            ip_id = getattr(ip, "id", 0) or 0
            ip_chk = getattr(ip, "chksum", None)

            layers.append({
                "name": "Internet Protocol Version 4 (IPv4)",
                "offset": cur_offset,
                "length": ip_layer_len,
                "fields": {
                    "Source IP": ip.src,
                    "Destination IP": ip.dst,
                    "Protocol": f"{ip_proto} ({'TCP' if ip_proto == 6 else 'UDP' if ip_proto == 17 else 'ICMP' if ip_proto == 1 else 'Unknown'})",
                    "TTL (Time to Live)": ip_ttl,
                    "Total Length": f"{ip_len} байт",
                    "Identification": f"0x{ip_id:04x} ({ip_id})",
                    "Checksum": hex(ip_chk) if ip_chk is not None else "0x0000"
                }
            })
            cur_offset += ip_layer_len

        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            src_ip = ip6.src
            dst_ip = ip6.dst
            proto_name = "IPv6"
            ip_layer_len = 40
            layers.append({
                "name": "Internet Protocol Version 6 (IPv6)",
                "offset": cur_offset,
                "length": 40,
                "fields": {
                    "Source IP": ip6.src,
                    "Destination IP": ip6.dst,
                    "Next Header": ip6.nh,
                    "Hop Limit": ip6.hlim
                }
            })
            cur_offset += 40

        # 4. Transport Layer (TCP, UDP, ICMP)
        payload_bytes = b""

        if ICMP in pkt:
            icmp = pkt[ICMP]
            proto_name = "ICMP"
            type_info = ICMP_TYPES.get(icmp.type, ("ICMP Type", "Служебный ICMP"))
            badge = {"text": "ICMP", "color": "cyan"}
            icmp_len = 8

            icmp_chk = getattr(icmp, "chksum", None)
            fields = {
                "Type": f"{icmp.type} ({type_info[0]} / {type_info[1]})",
                "Code": getattr(icmp, "code", 0),
                "Checksum": hex(icmp_chk) if icmp_chk is not None else "0x0000"
            }
            if getattr(icmp, "id", None) is not None:
                fields["Identifier"] = f"0x{icmp.id:04x} ({icmp.id})"
            if getattr(icmp, "seq", None) is not None:
                fields["Sequence Number"] = icmp.seq
                fields["Sequence"] = icmp.seq

            if icmp.type == 8:
                summary_str = f"Ping Echo Request (Эхо-запрос): {src_ip} -> {dst_ip} (seq={getattr(icmp, 'seq', 0)})"
            elif icmp.type == 0:
                summary_str = f"Ping Echo Reply (Эхо-ответ): {src_ip} -> {dst_ip} (seq={getattr(icmp, 'seq', 0)})"
            else:
                summary_str = f"ICMP {type_info[0]}: {src_ip} -> {dst_ip}"

            layers.append({
                "name": "Internet Control Message Protocol (ICMP)",
                "offset": cur_offset,
                "length": icmp_len,
                "fields": fields
            })
            cur_offset += icmp_len
            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)

        elif UDP in pkt:
            udp = pkt[UDP]
            sport = getattr(udp, "sport", 0) or 0
            dport = getattr(udp, "dport", 0) or 0
            proto_name = UDP_PORT_NAMES.get(dport, UDP_PORT_NAMES.get(sport, "UDP"))
            badge = {"text": proto_name.split()[0], "color": "blue"}
            udp_len = 8
            udp_chk = getattr(udp, "chksum", None)
            udp_len_val = getattr(udp, "len", None) or 8

            layers.append({
                "name": "User Datagram Protocol (UDP)",
                "offset": cur_offset,
                "length": udp_len,
                "fields": {
                    "Source Port": f"{sport} ({UDP_PORT_NAMES.get(sport, 'Custom')})",
                    "Destination Port": f"{dport} ({UDP_PORT_NAMES.get(dport, 'Custom')})",
                    "Length": f"{udp_len_val} байт",
                    "Checksum": hex(udp_chk) if udp_chk is not None else "0x0000"
                }
            })
            cur_offset += udp_len

            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
            elif hasattr(udp, "payload") and udp.payload:
                payload_bytes = bytes(udp.payload)

            # Application protocol checks for UDP
            if dport == 123 or sport == 123:
                proto_name = "NTP"
                badge = {"text": "NTP", "color": "blue"}
                ntp_layer = cls.decode_ntp(payload_bytes, cur_offset)
                if ntp_layer:
                    layers.append(ntp_layer)
                    summary_str = f"NTP: Синхронизация времени ({src_ip} -> {dst_ip})"

            elif dport in (53, 5353) or sport in (53, 5353):
                proto_name = "mDNS" if dport == 5353 or sport == 5353 else "DNS"
                badge = {"text": proto_name, "color": "emerald"}
                if DNS in pkt:
                    dns = pkt[DNS]
                    qnames = [q.qname.decode("utf-8", errors="replace").rstrip(".") for q in getattr(dns, "qd", []) if hasattr(q, "qname")] if dns.qd else []
                    summary_str = f"{proto_name} Query: {', '.join(qnames)}" if dns.qr == 0 else f"{proto_name} Response ({len(getattr(dns, 'an', []) or [])} ответов)"
                    layers.append({
                        "name": f"{proto_name} Layer",
                        "offset": cur_offset,
                        "length": len(payload_bytes) or 32,
                        "fields": {
                            "Transaction ID": hex(dns.id),
                            "Type": "Query (Запрос)" if dns.qr == 0 else "Response (Ответ)",
                            "Opcode": dns.opcode,
                            "Questions": qnames,
                            "Answer Count": dns.ancount
                        }
                    })

            elif dport == 1900 or sport == 1900:
                proto_name = "SSDP"
                badge = {"text": "SSDP", "color": "amber"}
                ssdp_layer = cls.decode_ssdp(payload_bytes, cur_offset)
                if ssdp_layer:
                    layers.append(ssdp_layer)
                    summary_str = f"SSDP: Обнаружение устройств ({ssdp_layer['fields'].get('First Line', '')[:40]})"

        elif TCP in pkt:
            tcp = pkt[TCP]
            sport = getattr(tcp, "sport", 0) or 0
            dport = getattr(tcp, "dport", 0) or 0
            proto_name = TCP_PORT_NAMES.get(dport, TCP_PORT_NAMES.get(sport, "TCP"))
            badge = {"text": proto_name.split()[0], "color": "indigo"}

            flags_list = []
            if hasattr(tcp, "flags"):
                if getattr(tcp.flags, "S", False): flags_list.append("SYN")
                if getattr(tcp.flags, "A", False): flags_list.append("ACK")
                if getattr(tcp.flags, "F", False): flags_list.append("FIN")
                if getattr(tcp.flags, "R", False): flags_list.append("RST")
                if getattr(tcp.flags, "P", False): flags_list.append("PSH")
                if getattr(tcp.flags, "U", False): flags_list.append("URG")

            tcp_dataofs = getattr(tcp, "dataofs", None)
            tcp_header_len = (tcp_dataofs * 4) if tcp_dataofs is not None else 20
            flags_int = int(tcp.flags) if hasattr(tcp, "flags") else 0
            layers.append({
                "name": "Transmission Control Protocol (TCP)",
                "offset": cur_offset,
                "length": tcp_header_len,
                "fields": {
                    "Source Port": f"{sport} ({TCP_PORT_NAMES.get(sport, 'Client')})",
                    "Destination Port": f"{dport} ({TCP_PORT_NAMES.get(dport, 'Server')})",
                    "Flags": f"{', '.join(flags_list)} (0x{flags_int:02x})",
                    "Sequence Number": getattr(tcp, "seq", 0),
                    "Acknowledgment Number": getattr(tcp, "ack", 0),
                    "Window Size": getattr(tcp, "window", 0),
                    "Header Length": f"{tcp_header_len} байт"
                }
            })
            cur_offset += tcp_header_len

            if Raw in pkt:
                payload_bytes = bytes(pkt[Raw].load)
            elif hasattr(tcp, "payload") and tcp.payload:
                payload_bytes = bytes(tcp.payload)

            summary_str = f"TCP [{', '.join(flags_list)}]: {src_ip}:{sport} -> {dst_ip}:{dport}"

            # Application protocol checks for TCP
            if payload_bytes:
                # HTTP
                http_layer = cls.decode_http(payload_bytes, cur_offset)
                if http_layer:
                    proto_name = "HTTP"
                    badge = {"text": "HTTP", "color": "amber"}
                    layers.append(http_layer)
                    summary_str = f"HTTP: {http_layer['fields'].get('First Line', '')[:60]}"
                # MQTT
                elif dport in (1883, 8883) or sport in (1883, 8883):
                    mqtt_layer = cls.decode_mqtt(payload_bytes, cur_offset)
                    if mqtt_layer:
                        proto_name = "MQTT"
                        badge = {"text": "MQTT", "color": "purple"}
                        layers.append(mqtt_layer)
                        pkt_type = mqtt_layer["fields"].get("Packet Type", "")
                        topic = mqtt_layer["fields"].get("Topic", "")
                        summary_str = f"MQTT {pkt_type}: {topic}" if topic else f"MQTT {pkt_type}"
                # TLS ClientHello
                elif dport in (443, 8443) or sport in (443, 8443):
                    tls_layer = cls.decode_tls_client_hello(payload_bytes, cur_offset)
                    if tls_layer:
                        proto_name = "TLS"
                        badge = {"text": "TLS", "color": "emerald"}
                        layers.append(tls_layer)
                        sni = tls_layer["fields"].get("Server Name (SNI)")
                        summary_str = f"TLS ClientHello: {sni}" if sni else "TLS Handshake"

        # Raw Payload Layer
        if payload_bytes:
            # Decode preview string
            decoded_text = None
            is_json = False
            try:
                txt = payload_bytes.decode("utf-8")
                try:
                    json_val = json.loads(txt)
                    decoded_text = json.dumps(json_val, ensure_ascii=False, indent=2)
                    is_json = True
                except Exception:
                    decoded_text = txt
            except Exception:
                decoded_text = payload_bytes[:200].decode("ascii", errors="replace")

            layers.append({
                "name": "Полезная нагрузка (Payload Data)",
                "offset": cur_offset,
                "length": len(payload_bytes),
                "fields": {
                    "Размер данных": f"{len(payload_bytes)} байт",
                    "Формат": "JSON" if is_json else "Текст (UTF-8)" if decoded_text else "Двоичные данные (Binary)",
                    "Предпросмотр данных": decoded_text[:1000] if decoded_text else payload_bytes[:100].hex()
                }
            })

        # Generate 16-byte aligned Hex/ASCII dump
        hex_dump = cls.generate_hex_dump(raw_bytes)

        generated_id = pkt_id or f"pkt_{int(time.time()*1000)}_{src_mac[-4:] if src_mac else '0000'}"

        hexdump_str = "\n".join([f"{l['offset']}  {l['hex']:<48}  |{l['ascii']}|" for l in hex_dump])
        payload_text_full = payload_bytes.decode("utf-8", errors="replace") if payload_bytes else ""

        return {
            "status": "ok",
            "id": generated_id,
            "pkt_id": generated_id,
            "packet_id": generated_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "length": total_len,
            "length_bytes": total_len,
            "src": src_ip or src_mac,
            "dst": dst_ip or dst_mac,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto_name,
            "summary": summary_str,
            "badge": badge,
            "has_payload": len(payload_bytes) > 0,
            "payload_size": len(payload_bytes),
            "payload_preview": (payload_bytes.decode("utf-8", errors="replace")[:200]) if payload_bytes else None,
            "payload_str": payload_text_full,
            "layers": layers,
            "hex_dump": hex_dump,
            "hex_dump_lines": hex_dump,
            "hexdump": hexdump_str
        }

    @classmethod
    def extract_payload_summary(cls, pkt: Any) -> Optional[Dict[str, Any]]:
        """Quickly extracts payload metadata without generating full hex dump."""
        payload_bytes = b""
        if Raw in pkt:
            payload_bytes = bytes(pkt[Raw].load)
        elif UDP in pkt and hasattr(pkt[UDP], "payload") and pkt[UDP].payload:
            payload_bytes = bytes(pkt[UDP].payload)
        elif TCP in pkt and hasattr(pkt[TCP], "payload") and pkt[TCP].payload:
            payload_bytes = bytes(pkt[TCP].payload)

        if not payload_bytes and ICMP not in pkt and ARP not in pkt:
            return None

        # Determine protocol
        proto = "RAW"
        dport = None
        if TCP in pkt:
            dport = pkt[TCP].dport
            proto = TCP_PORT_NAMES.get(dport, "TCP")
        elif UDP in pkt:
            dport = pkt[UDP].dport
            proto = UDP_PORT_NAMES.get(dport, "UDP")
        elif ICMP in pkt:
            proto = "ICMP"
        elif ARP in pkt:
            proto = "ARP"

        text_preview = ""
        is_json = False
        if payload_bytes:
            try:
                decoded = payload_bytes.decode("utf-8")
                try:
                    json.loads(decoded)
                    is_json = True
                except Exception:
                    pass
                text_preview = decoded[:500]
            except Exception:
                text_preview = payload_bytes[:100].decode("ascii", errors="replace")

        return {
            "size": len(payload_bytes),
            "protocol": proto,
            "dst_port": dport,
            "text": text_preview,
            "hex": payload_bytes[:128].hex() if payload_bytes else "",
            "is_json": is_json
        }
