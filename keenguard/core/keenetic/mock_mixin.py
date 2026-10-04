"""Mock mode mixin for Keenetic client, consolidating in-memory testing logic."""
import logging
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Set
from keenguard.core.keenetic.models import HotspotHost, UPnPMapping

logger = logging.getLogger("keenguard.keenetic.mock")


class KeeneticMockMixin:
    """Consolidated in-memory simulation methods for testing without a physical Keenetic router."""

    mock_mode: bool = False
    _mock_hosts: List[Dict[str, Any]]
    _mock_upnp: List[Dict[str, Any]]
    _mock_captures: Dict[str, Dict[str, Any]]
    _mock_sinkholes: Set[str]
    _mock_ip_blackholes: Set[str]
    _mock_guest_wifi: bool = True
    _mock_rebooted: bool = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mock_mode = getattr(self, "mock_mode", False)
        if not hasattr(self, "_mock_hosts"):
            self._mock_hosts = []
        if not hasattr(self, "_mock_upnp"):
            self._mock_upnp = []
        if not hasattr(self, "_mock_captures"):
            self._mock_captures = {}
        if not hasattr(self, "_mock_sinkholes"):
            self._mock_sinkholes = set()
        if not hasattr(self, "_mock_ip_blackholes"):
            self._mock_ip_blackholes = set()
        if not hasattr(self, "_mock_guest_wifi"):
            self._mock_guest_wifi = True
        if not hasattr(self, "_mock_rebooted"):
            self._mock_rebooted = False
        if not hasattr(self, "_mock_speed_limits"):
            self._mock_speed_limits = {}

    # --- Base Auth & Connectivity Mocks ---

    def _mock_authenticate(self) -> Dict[str, Any]:
        return {"status": "ok", "version": "KeeneticOS 4.1 (Mock)", "model": "Keenetic Hero 4G"}

    def _mock_test_connection(self) -> Dict[str, Any]:
        return {"status": "ok", "version": "KeeneticOS 4.1 (Mock)", "model": "Keenetic Hero 4G"}

    # --- Telemetry Mocks ---

    def _mock_get_hotspot_hosts(self) -> List[HotspotHost]:
        hosts = []
        for h in getattr(self, "_mock_hosts", []):
            d = dict(h)
            if "segment" not in d:
                iface = str(d.get("interface", "")).lower()
                ip_str = str(d.get("ip", ""))
                if "guest" in iface or "bridge1" in iface or (ip_str and not ip_str.startswith("192.168.1.") and ip_str != "0.0.0.0"):
                    d["segment"] = "Guest"
                else:
                    d["segment"] = "Home"
            hosts.append(HotspotHost(**d))
        return hosts

    def _mock_get_nat_table(self) -> List[Dict[str, Any]]:
        return getattr(self, "_mock_nat_table", [])

    def _mock_get_dns_cache(self) -> List[Dict[str, Any]]:
        return [
            {"domain": "gateway.fe.apple-dns.net", "ip": "17.248.190.245", "ttl": 300},
            {"domain": "api.dreame.tech", "ip": "47.91.78.162", "ttl": 60},
            {"domain": "pool.ntp.org", "ip": "194.226.177.202", "ttl": 120}
        ]

    def _mock_get_wifi_security(self) -> Dict[str, Any]:
        return {
            "grade": "A+",
            "score": 100,
            "access_points": [
                {
                    "interface": "WifiMaster0/AccessPoint0",
                    "ssid": "Keenetic-Home",
                    "band": "2.4 ГГц",
                    "security": "WPA3 / WPA2 mixed",
                    "security_type": "wpa3_mixed",
                    "wps": False,
                    "pmf": "optional"
                }
            ],
            "networks": [
                {
                    "interface": "WifiMaster0/AccessPoint0",
                    "ssid": "Keenetic-Home",
                    "band": "2.4 ГГц",
                    "security": "WPA3 / WPA2 mixed",
                    "security_type": "wpa3_mixed",
                    "wps": False,
                    "pmf": "optional"
                }
            ],
            "wps_enabled": False,
            "pmf_enabled": True,
            "guest_network": {"configured": True, "isolated": True},
            "guest_network_enabled": True,
            "guest_isolation_enabled": True,
            "recommendations": ["Рекомендуется установить PMF в режим 'Обязательно' для защиты от Deauth-атак."]
        }

    def _mock_check_firmware_updates(self, current_v: str) -> Dict[str, Any]:
        return {
            "status": "ok",
            "current_version": current_v,
            "latest_version": current_v,
            "available_version": current_v,
            "has_update": False,
            "update_available": False,
            "channel": "release",
            "message": "Установлена актуальная версия KeeneticOS."
        }

    def _mock_get_dns_proxy_status(self) -> Dict[str, Any]:
        return {
            "active": True,
            "filter_engine": "adguard",
            "rebind_protect": True,
            "has_doh": True,
            "has_dot": False,
            "servers": ["94.140.14.14", "94.140.15.15"]
        }

    def _mock_get_network_segments(self) -> List[Dict[str, Any]]:
        return [
            {"id": "Home", "name": "Домашняя сеть", "interface": "Bridge0", "subnet": "192.168.1.0/24", "dhcp": True, "security_level": "trusted"},
            {"id": "Guest", "name": "Гостевая сеть", "interface": "Bridge1", "subnet": "192.168.2.0/24", "dhcp": True, "security_level": "isolated"}
        ]

    # --- Filtering Mocks ---

    def _mock_get_upnp_mappings(self) -> List[UPnPMapping]:
        return [UPnPMapping(**m) for m in getattr(self, "_mock_upnp", [])]

    def _mock_delete_upnp_mapping(self, protocol: str, ext_port: int) -> bool:
        self._mock_upnp = [
            m for m in getattr(self, "_mock_upnp", [])
            if not (m.get("protocol") == protocol and m.get("ext_port") == ext_port)
        ]
        return True

    def _mock_add_dns_sinkholes(self, valid_domains: List[str]) -> Tuple[List[str], List[str]]:
        if not hasattr(self, "_mock_sinkholes"):
            self._mock_sinkholes = set()
        for d in valid_domains:
            self._mock_sinkholes.add(d)
        return valid_domains, []

    def _mock_remove_dns_sinkholes(self, clean_domains: List[str]) -> Tuple[List[str], List[str]]:
        if hasattr(self, "_mock_sinkholes"):
            for d in clean_domains:
                self._mock_sinkholes.discard(d)
        return clean_domains, []

    def _mock_get_active_sinkholes(self) -> List[str]:
        return sorted(list(getattr(self, "_mock_sinkholes", set())))

    def _mock_add_ip_blackholes(self, valid_ips: List[str], rejected_ips: List[str]) -> Tuple[List[str], List[str]]:
        if not hasattr(self, "_mock_ip_blackholes"):
            self._mock_ip_blackholes = set()
        for ip in valid_ips:
            self._mock_ip_blackholes.add(ip)
        return valid_ips, rejected_ips

    def _mock_remove_ip_blackholes(self, clean_ips: List[str]) -> Tuple[List[str], List[str]]:
        if hasattr(self, "_mock_ip_blackholes"):
            for ip in clean_ips:
                self._mock_ip_blackholes.discard(ip)
        return clean_ips, []

    def _mock_get_active_ip_blackholes(self) -> List[str]:
        return sorted(list(getattr(self, "_mock_ip_blackholes", set())))

    def _mock_reboot_router(self) -> bool:
        self._mock_rebooted = True
        return True

    def _mock_toggle_guest_wifi(self, enable: bool) -> bool:
        self._mock_guest_wifi = enable
        return True

    def _mock_get_guest_wifi_status(self) -> Dict[str, Any]:
        return {"enabled": getattr(self, "_mock_guest_wifi", True), "interface": "GuestWiFi"}

    # --- Policies Mocks ---

    def _mock_set_device_policy(self, mac: str, access: str) -> bool:
        clean_mac = mac.upper()
        for h in getattr(self, "_mock_hosts", []):
            if str(h.get("mac", "")).upper() == clean_mac:
                h["access"] = access
        return True

    def _mock_isolate_device_to_segment(self, mac: str, segment_id: str = "Guest") -> bool:
        clean_mac = mac.upper()
        for h in getattr(self, "_mock_hosts", []):
            if str(h.get("mac", "")).upper() == clean_mac:
                if h.get("interface") == "Bridge0" or (h.get("ip") and h.get("ip").startswith("192.168.1.")):
                    return False
                return True
        return False

    def _mock_enable_mdns_relay(self) -> Dict[str, Any]:
        return {"status": "ok", "method": "mock"}

    def _mock_set_dlna_access(self, mac: str, ip: str, allow: bool) -> bool:
        return True

    # --- Capture Mocks ---

    def _mock_is_packet_capture_supported(self) -> bool:
        return True

    def _mock_start_packet_capture(
        self,
        interface: str,
        target_ip: Optional[str],
        payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        if not hasattr(self, "_mock_captures"):
            self._mock_captures = {}
        self._mock_captures[interface] = {
            "payload": payload,
            "file_path": f"capture_{interface}.pcap",
            "target_ip": target_ip,
            "is_running": True
        }
        return {"status": "ok", "interface": interface, "filter": payload.get("filter")}

    def _mock_stop_packet_capture(self, interface: str) -> str:
        if not hasattr(self, "_mock_captures"):
            self._mock_captures = {}
        info = self._mock_captures.get(interface, {})
        info["is_running"] = False
        return info.get("file_path", f"capture_{interface}.pcap")

    def _mock_download_capture_file(self, local_dest_path: Path) -> bool:
        try:
            from scapy.all import wrpcap, Ether, IP, TCP, UDP, Raw
            pkts = [
                Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") /
                IP(src="192.168.1.105", dst="198.51.100.10") /
                TCP(sport=54321, dport=80, flags="PA") /
                Raw(load=b"GET /api/v1/telemetry HTTP/1.1\r\nHost: smart-tv-cloud.example.com\r\nUser-Agent: SmartTV/5.0\r\n\r\n"),
                Ether(src="00:11:22:33:44:55", dst="AA:BB:CC:DD:EE:FF") /
                IP(src="192.168.1.105", dst="192.168.1.1") /
                UDP(sport=53535, dport=53) /
                Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
            ]
            wrpcap(str(local_dest_path), pkts)
            return True
        except (OSError, ValueError, AttributeError) as e:
            logger.error("Mock pcap generation failed: %s", e)
            header = bytes([
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
            ])
            local_dest_path.write_bytes(header)
            return True

    def _mock_reset_packet_capture(self, interface: str) -> bool:
        if hasattr(self, "_mock_captures"):
            self._mock_captures.pop(interface, None)
        return True

    def _mock_block_dot(self, enable: bool = True) -> bool:
        self._mock_dot_blocked = enable
        return True

    def _mock_is_dot_blocked(self) -> bool:
        return getattr(self, "_mock_dot_blocked", False)

    def _mock_set_device_speed_limit(self, mac: str, speed_kbps: int) -> bool:
        if not hasattr(self, "_mock_speed_limits"):
            self._mock_speed_limits = {}
        if speed_kbps <= 0:
            self._mock_speed_limits.pop(mac.upper(), None)
        else:
            self._mock_speed_limits[mac.upper()] = int(speed_kbps)
        return True

    def _mock_get_device_speed_limits(self) -> Dict[str, int]:
        return dict(getattr(self, "_mock_speed_limits", {}))
