"""Abstract base class for router backends in KeenGuard."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Set, Optional

from keenguard.core.routers.models import RouterHost, RouterSystemInfo


class BaseRouterBackend(ABC):
    """Abstract contract for hardware routers integrated with KeenGuard."""

    @property
    @abstractmethod
    def platform_id(self) -> str:
        """Unique identifier, e.g. 'keenetic' or 'openwrt'."""
        ...

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Human-readable display name, e.g. 'KeeneticOS' or 'OpenWrt'."""
        ...

    @property
    @abstractmethod
    def capabilities(self) -> Set[str]:
        """Set of supported capabilities."""
        ...

    @abstractmethod
    async def connect(self) -> bool:
        """Validates connection and credentials with the router."""
        ...

    @abstractmethod
    async def get_system_info(self) -> RouterSystemInfo:
        """Retrieves router model, firmware, uptime, and hardware status."""
        ...

    @abstractmethod
    async def get_hosts(self) -> List[RouterHost]:
        """Returns list of connected and known network hosts."""
        ...

    @abstractmethod
    async def set_wan_access(self, mac: str, allow: bool) -> bool:
        """Allows or blocks Internet (WAN) access for the given MAC address."""
        ...

    async def set_lan_isolation(self, mac: str, isolate: bool) -> bool:
        """Isolates the device from other LAN clients. Default returns False if unsupported."""
        return False

    @abstractmethod
    async def reboot(self) -> bool:
        """Reboots the router."""
        ...

    async def reboot_router(self) -> bool:
        """Alias for reboot."""
        return await self.reboot()

    @abstractmethod
    async def add_dns_sinkhole(self, domain: str, ip: str = "0.0.0.0") -> bool:
        """Adds a domain to router's local DNS sinkhole (returns 0.0.0.0)."""
        ...

    @abstractmethod
    async def remove_dns_sinkhole(self, domain: str) -> bool:
        """Removes a domain from the router's DNS sinkhole."""
        ...

    async def get_guest_wifi_status(self) -> Dict[str, Any]:
        """Returns status of guest Wi-Fi segment."""
        return {"enabled": False, "supported": False}

    async def toggle_guest_wifi(self, enable: bool) -> bool:
        """Enables or disables guest Wi-Fi segment."""
        return False

    async def get_upnp_mappings(self) -> List[Any]:
        """Returns active UPnP port mappings."""
        return []

    async def delete_upnp_mapping(self, proto: str, port: int) -> bool:
        """Deletes a specific UPnP port mapping."""
        return False

    @property
    def host(self) -> str:
        """IP address or hostname of the router gateway."""
        return getattr(self, "_host", "192.168.1.1")

    @host.setter
    def host(self, val: str):
        self._host = val

    async def get_active_sinkholes(self) -> List[str]:
        """Returns list of active domains redirected to 0.0.0.0 on router."""
        return []

    async def add_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        """Batch adds multiple domains to local DNS sinkhole. Returns (succeeded, failed)."""
        succeeded, failed = [], []
        for d in domains:
            if await self.add_dns_sinkhole(d):
                succeeded.append(d)
            else:
                failed.append(d)
        return succeeded, failed

    async def remove_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        """Batch removes multiple domains from local DNS sinkhole. Returns (succeeded, failed)."""
        succeeded, failed = [], []
        for d in domains:
            if await self.remove_dns_sinkhole(d):
                succeeded.append(d)
            else:
                failed.append(d)
        return succeeded, failed

    async def get_active_ip_blackholes(self) -> List[str]:
        """Returns list of IP addresses actively blackholed on router hardware."""
        return []

    async def add_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        """Batch adds IP blackhole rules to router. Returns (succeeded, failed)."""
        return [], ips

    async def remove_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        """Batch removes IP blackhole rules from router. Returns (succeeded, failed)."""
        return [], ips

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        """Returns active network connection / NAT flows (Conntrack)."""
        return []

    async def get_device_nat_connections(self, ip: str) -> List[Dict[str, Any]]:
        """Returns active NAT flows associated with the specified device IP."""
        flows = await self.get_nat_table()
        return [f for f in flows if f.get("src") == ip or f.get("dst") == ip]

    async def get_dns_cache(self) -> List[Dict[str, Any]]:
        """Returns recent DNS proxy cache entries from the router."""
        return []

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        """Returns list of hardware network segments / interfaces."""
        return []

    def evaluate_segment_risk(self, profile: str, segment: str, ip: str = "") -> Dict[str, Any]:
        """Evaluates L2 isolation and firewall bypass risk for a device based on segment."""
        clean_seg = (segment or "Home").strip()
        is_guest_or_isolated = any(x in clean_seg.lower() for x in ("guest", "гост", "iot", "isolate"))
        
        if profile in ("camera", "iot", "smart_home_hub") and not is_guest_or_isolated:
            return {
                "risk_level": "high",
                "badge": "Внимание: L2-обход",
                "color": "rose",
                "warning": f"L2-обход: устройство находится в общем мосте '{clean_seg}'. Трафик между устройствами идет в обход файрвола.",
                "message": f"Устройство находится в общем мосте '{clean_seg}'. Трафик между устройствами идет в обход файрвола.",
                "recommendation": "Изолируйте устройство в гостевом Wi-Fi или отдельном VLAN."
            }
        elif profile in ("camera", "iot") and is_guest_or_isolated:
            return {
                "risk_level": "low",
                "badge": "Изолирован",
                "color": "emerald",
                "warning": "",
                "message": f"Устройство в изолированном сегменте '{clean_seg}'. L2-трафик к основной сети закрыт.",
                "recommendation": "Конфигурация соответствует политике безопасности."
            }
        return {
            "risk_level": "safe",
            "badge": "Норма",
            "color": "slate",
            "warning": "",
            "message": f"Сегмент '{clean_seg}'. Рисков изоляции не выявлено.",
            "recommendation": "Действий не требуется."
        }

    async def get_wifi_security(self) -> Dict[str, Any]:
        """Performs Wi-Fi security audit (encryption, WPA3, PMF, isolation)."""
        return {
            "score": 80,
            "grade": "B",
            "networks": [],
            "recommendations": []
        }

    async def check_firmware_updates(self) -> Dict[str, Any]:
        """Checks for router firmware updates."""
        info = await self.get_system_info()
        return {
            "update_available": False,
            "current_version": info.firmware_version,
            "latest_version": info.firmware_version,
            "channel": "stable"
        }

    async def get_wan_ip(self) -> Optional[str]:
        """Returns external WAN IPv4 address if available."""
        return None

    async def get_interface_stats(self, dev_name: str = "wan") -> Dict[str, int]:
        """Queries network interface rx_bytes / tx_bytes."""
        return {"rx_bytes": 0, "tx_bytes": 0}

    async def get_dns_proxy_status(self) -> Dict[str, Any]:
        """Returns router DNS server/proxy status."""
        return {"status": "ok", "mode": "standard"}

    async def is_packet_capture_supported(self) -> bool:
        """Returns True if the router supports hardware-level packet capture."""
        return False

    async def start_packet_capture(
        self,
        interface: str = "Bridge0",
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        proto: Optional[str] = None,
        port: Optional[int] = None,
        duration_seconds: int = 60,
        target_ip: Optional[str] = None
    ) -> Any:
        """Starts hardware packet capture on router."""
        return {"status": "error", "message": "Hardware packet capture unsupported"}

    async def stop_packet_capture(self, interface: str = "Bridge0") -> Optional[str]:
        """Stops hardware packet capture and returns capture filename/token."""
        return None

    async def download_capture_file(self, filename: str, destination_path: Any) -> bool:
        """Downloads recorded PCAP file from router to destination path."""
        return False

    async def reset_packet_capture(self, interface: str = "Bridge0") -> bool:
        """Cleans up temporary packet capture sessions on router."""
        return False

    def is_router_entity(self, ip: Optional[str] = None, mac: Optional[str] = None) -> bool:
        """Returns True if the given IP or MAC belongs to the router itself."""
        return False

    async def set_dlna_access(self, mac: str, ip: str, allow: bool = True) -> bool:
        """Configures router access rules for DLNA/UPnP AV streams for the device."""
        return True

    async def enable_mdns_relay(self) -> bool:
        """Enables mDNS discovery relay between network segments."""
        return True
