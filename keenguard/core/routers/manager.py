"""RouterManager orchestrates router backend selection and provides a unified interface."""
import logging
from typing import List, Dict, Any, Set, Optional

from keenguard.config import settings
from keenguard.core.routers.base import BaseRouterBackend
from keenguard.core.routers.models import RouterHost, RouterSystemInfo
from keenguard.core.routers.keenetic import KeeneticBackend
from keenguard.core.routers.openwrt import OpenWrtBackend

logger = logging.getLogger("keenguard.routers.manager")


class RouterManager:
    """Singleton manager that delegates operations to the configured router backend."""

    def __init__(self):
        self._current_backend: Optional[BaseRouterBackend] = None
        self._cached_type: Optional[str] = None
        self._explicit_override: bool = False

    def get_active_type(self) -> str:
        """Returns the configured router platform type ('keenetic' or 'openwrt')."""
        return (settings.router_type or "keenetic").lower().strip()

    def get_backend(self) -> BaseRouterBackend:
        """Returns the active router backend, initializing or re-creating if configuration changed."""
        if self._explicit_override and self._current_backend is not None:
            return self._current_backend

        active_type = self.get_active_type()
        if self._current_backend is None or self._cached_type != active_type:
            if active_type == "openwrt":
                logger.info("Initializing OpenWrt backend (%s:%s)", settings.openwrt_host, settings.openwrt_port)
                self._current_backend = OpenWrtBackend()
            else:
                logger.info("Initializing Keenetic backend (%s:%s)", settings.router_host, settings.router_port)
                self._current_backend = KeeneticBackend()
            self._cached_type = active_type
            self._explicit_override = False
        return self._current_backend

    def set_backend(self, backend: Optional[BaseRouterBackend]):
        """Allows explicitly overriding or mocking the router backend (e.g. for testing)."""
        self._current_backend = backend
        self._explicit_override = backend is not None
        if backend is not None:
            self._cached_type = getattr(backend, "platform_id", None)
        else:
            self._cached_type = None

    @property
    def platform_id(self) -> str:
        return self.get_backend().platform_id

    @property
    def platform_name(self) -> str:
        return self.get_backend().platform_name

    @property
    def capabilities(self) -> Set[str]:
        return self.get_backend().capabilities

    async def connect(self) -> bool:
        return await self.get_backend().connect()

    async def get_system_info(self) -> RouterSystemInfo:
        return await self.get_backend().get_system_info()

    async def get_hosts(self) -> List[RouterHost]:
        return await self.get_backend().get_hosts()

    async def set_wan_access(self, mac: str, allow: bool) -> bool:
        return await self.get_backend().set_wan_access(mac=mac, allow=allow)

    async def set_lan_isolation(self, mac: str, isolate: bool) -> bool:
        return await self.get_backend().set_lan_isolation(mac=mac, isolate=isolate)

    async def reboot(self) -> bool:
        return await self.get_backend().reboot()

    async def add_dns_sinkhole(self, domain: str, ip: str = "0.0.0.0") -> bool:
        return await self.get_backend().add_dns_sinkhole(domain=domain, ip=ip)

    async def remove_dns_sinkhole(self, domain: str) -> bool:
        return await self.get_backend().remove_dns_sinkhole(domain=domain)

    async def get_guest_wifi_status(self) -> Dict[str, Any]:
        return await self.get_backend().get_guest_wifi_status()

    async def toggle_guest_wifi(self, enable: bool) -> bool:
        return await self.get_backend().toggle_guest_wifi(enable=enable)

    async def get_upnp_mappings(self) -> List[Any]:
        return await self.get_backend().get_upnp_mappings()

    async def delete_upnp_mapping(self, proto: str, port: int) -> bool:
        return await self.get_backend().delete_upnp_mapping(proto=proto, port=port)

    @property
    def host(self) -> str:
        return self.get_backend().host

    async def get_active_sinkholes(self) -> List[str]:
        return await self.get_backend().get_active_sinkholes()

    async def add_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        return await self.get_backend().add_dns_sinkholes(domains)

    async def remove_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        return await self.get_backend().remove_dns_sinkholes(domains)

    async def get_active_ip_blackholes(self) -> List[str]:
        return await self.get_backend().get_active_ip_blackholes()

    async def add_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        return await self.get_backend().add_ip_blackholes(ips)

    async def remove_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        return await self.get_backend().remove_ip_blackholes(ips)

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        return await self.get_backend().get_nat_table()

    async def get_device_nat_connections(self, ip: str) -> List[Dict[str, Any]]:
        return await self.get_backend().get_device_nat_connections(ip)

    async def get_dns_cache(self) -> List[Dict[str, Any]]:
        return await self.get_backend().get_dns_cache()

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        return await self.get_backend().get_network_segments()

    def evaluate_segment_risk(self, profile: str, segment: str, ip: str = "") -> Dict[str, Any]:
        return self.get_backend().evaluate_segment_risk(profile, segment, ip)

    async def get_wifi_security(self) -> Dict[str, Any]:
        return await self.get_backend().get_wifi_security()

    async def check_firmware_updates(self) -> Dict[str, Any]:
        return await self.get_backend().check_firmware_updates()

    async def get_wan_ip(self) -> Optional[str]:
        return await self.get_backend().get_wan_ip()

    async def get_interface_stats(self, dev_name: str = "wan") -> Dict[str, int]:
        return await self.get_backend().get_interface_stats(dev_name)

    async def get_dns_proxy_status(self) -> Dict[str, Any]:
        return await self.get_backend().get_dns_proxy_status()

    async def is_packet_capture_supported(self) -> bool:
        return await self.get_backend().is_packet_capture_supported()

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
        return await self.get_backend().start_packet_capture(
            interface=interface,
            ip=ip,
            mac=mac,
            proto=proto,
            port=port,
            duration_seconds=duration_seconds,
            target_ip=target_ip
        )

    async def stop_packet_capture(self, interface: str = "Bridge0") -> Optional[str]:
        return await self.get_backend().stop_packet_capture(interface=interface)

    async def download_capture_file(self, filename: str, destination_path: Any) -> bool:
        return await self.get_backend().download_capture_file(filename, destination_path)

    async def reset_packet_capture(self, interface: str = "Bridge0") -> bool:
        return await self.get_backend().reset_packet_capture(interface=interface)

    def is_router_entity(self, ip: Optional[str] = None, mac: Optional[str] = None) -> bool:
        return self.get_backend().is_router_entity(ip=ip, mac=mac)

    async def set_dlna_access(self, mac: str, ip: str, allow: bool = True) -> bool:
        return await self.get_backend().set_dlna_access(mac, ip, allow=allow)

    async def enable_mdns_relay(self) -> bool:
        return await self.get_backend().enable_mdns_relay()


router_manager = RouterManager()
