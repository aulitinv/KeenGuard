import asyncio
import logging
from typing import List, Dict, Any, Set, Optional

from keenguard.core.routers.base import BaseRouterBackend
from keenguard.core.routers.models import RouterHost, RouterSystemInfo
from keenguard.core.keenetic.client import keenetic_client

logger = logging.getLogger("keenguard.routers.keenetic")


class KeeneticBackend(BaseRouterBackend):
    """Adapter wrapping native Keenetic RCI client into unified BaseRouterBackend."""

    def __init__(self, client: Optional[Any] = None):
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from keenguard.web.state import get_keenetic_client
            return get_keenetic_client()
        except Exception:
            return keenetic_client

    @property
    def platform_id(self) -> str:
        return "keenetic"

    @property
    def platform_name(self) -> str:
        return "KeeneticOS"

    @property
    def capabilities(self) -> Set[str]:
        return {
            "wan_block",
            "lan_isolation",
            "dns_sinkhole",
            "guest_wifi",
            "upnp_management",
            "reboot",
            "conntrack",
            "packet_capture"
        }

    async def connect(self) -> bool:
        """Attempts connection to Keenetic RCI."""
        try:
            hosts = await self.client.get_hotspot_hosts()
            if hosts is not None:
                try:
                    await self.client.refresh_router_interfaces()
                except Exception as ex:
                    logger.debug("Interface refresh error: %s", ex)
                return True
            return False
        except Exception as e:
            logger.warning("Keenetic connection check failed: %s", e)
            return False

    async def get_system_info(self) -> RouterSystemInfo:
        """Returns Keenetic system information."""
        try:
            status_data = {}
            if hasattr(self.client, "get_system_status"):
                res = self.client.get_system_status()
                if asyncio.iscoroutine(res):
                    status_data = await res or {}
                elif isinstance(res, dict):
                    status_data = res

            dev_info = status_data.get("device", {}) if isinstance(status_data, dict) else {}
            model = dev_info.get("model") if isinstance(dev_info, dict) else None
            if not isinstance(model, str):
                last_m = getattr(self.client, "last_model", None)
                model = last_m if isinstance(last_m, str) else "Keenetic"

            version = dev_info.get("ndms", {}).get("version") if isinstance(dev_info, dict) and isinstance(dev_info.get("ndms"), dict) else None
            if not isinstance(version, str):
                last_v = getattr(self.client, "last_version", None)
                version = last_v if isinstance(last_v, str) else "KeeneticOS"

            uptime = int(dev_info.get("uptime") or 0) if isinstance(dev_info, dict) else 0
            mem_data = dev_info.get("memory", {}) if isinstance(dev_info, dict) else {}
            mem_total = int(mem_data.get("total") or 0) if isinstance(mem_data, dict) else 0
            mem_free = int(mem_data.get("free") or 0) if isinstance(mem_data, dict) else 0

            return RouterSystemInfo(
                model=model,
                firmware_version=version,
                uptime=uptime,
                memory_total=mem_total,
                memory_free=mem_free,
                platform="keenetic",
                extra=status_data if isinstance(status_data, dict) else {}
            )
        except Exception as e:
            logger.debug("Error fetching Keenetic system info: %s", e)
            last_m = getattr(self.client, "last_model", None)
            model = last_m if isinstance(last_m, str) else "Keenetic"
            last_v = getattr(self.client, "last_version", None)
            version = last_v if isinstance(last_v, str) else "KeeneticOS"
            return RouterSystemInfo(
                model=model,
                firmware_version=version,
                platform="keenetic"
            )

    async def get_hosts(self) -> List[RouterHost]:
        """Fetches active network hosts from Keenetic RCI."""
        if hasattr(self.client, "get_hotspot_hosts"):
            res = self.client.get_hotspot_hosts()
            raw_hosts = await res if asyncio.iscoroutine(res) else res
        else:
            raw_hosts = []
        result: List[RouterHost] = []
        if not raw_hosts:
            return result
        for h in raw_hosts:
            result.append(RouterHost(
                mac=h.mac.upper(),
                ip=h.ip,
                hostname=getattr(h, "hostname", None) or getattr(h, "name", None),
                name=getattr(h, "name", None),
                interface=getattr(h, "interface", None),
                link=getattr(h, "link", "up"),
                active=getattr(h, "active", True),
                rxbytes=int(getattr(h, "rxbytes", 0) or 0),
                txbytes=int(getattr(h, "txbytes", 0) or 0),
                uptime=getattr(h, "uptime", 0),
                access=getattr(h, "access", "permit"),
                registered=getattr(h, "registered", False),
                policy=getattr(h, "policy", None),
                segment=getattr(h, "segment", "Home") or "Home"
            ))
        return result

    async def set_wan_access(self, mac: str, allow: bool) -> bool:
        """Blocks or allows WAN access for device on Keenetic."""
        access_val = "permit" if allow else "deny"
        return await self.client.set_device_policy(mac, access=access_val)

    async def set_lan_isolation(self, mac: str, isolate: bool) -> bool:
        """Applies LAN isolation (delegated to profile manager / Guest WiFi)."""
        from keenguard.core.profiles import profile_manager
        return await profile_manager.toggle_lan_isolation(mac, isolate=isolate)

    async def reboot(self) -> bool:
        """Reboots Keenetic router."""
        return await self.client.reboot_router()

    async def add_dns_sinkhole(self, domain: str, ip: str = "0.0.0.0") -> bool:
        """Injects static ip host into Keenetic dnsmasq."""
        if ip == "0.0.0.0":
            return await self.client.add_dns_sinkhole(domain)
        return await self.client.add_dns_sinkhole(domain, ip)

    async def remove_dns_sinkhole(self, domain: str) -> bool:
        """Removes static ip host from Keenetic dnsmasq."""
        return await self.client.remove_dns_sinkhole(domain)

    async def get_guest_wifi_status(self) -> Dict[str, Any]:
        """Retrieves guest Wi-Fi state on Keenetic."""
        return await self.client.get_guest_wifi_status()

    async def toggle_guest_wifi(self, enable: bool) -> bool:
        """Toggles guest Wi-Fi on Keenetic."""
        return await self.client.toggle_guest_wifi(enable)

    async def get_upnp_mappings(self) -> List[Any]:
        """Retrieves active UPnP port mappings from Keenetic."""
        if hasattr(self.client, "get_upnp_mappings"):
            res = self.client.get_upnp_mappings()
            if asyncio.iscoroutine(res):
                res = await res
            if isinstance(res, list):
                return res
        return []

    async def delete_upnp_mapping(self, proto: str, port: int) -> bool:
        """Deletes a UPnP port mapping on Keenetic."""
        return await self.client.delete_upnp_mapping(proto, port)

    @property
    def host(self) -> str:
        return self.client.host

    async def get_active_sinkholes(self) -> List[str]:
        return await self.client.get_active_sinkholes()

    async def add_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        return await self.client.add_dns_sinkholes(domains)

    async def remove_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        return await self.client.remove_dns_sinkholes(domains)

    async def get_active_ip_blackholes(self) -> List[str]:
        return await self.client.get_active_ip_blackholes()

    async def add_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        return await self.client.add_ip_blackholes(ips)

    async def remove_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        return await self.client.remove_ip_blackholes(ips)

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        return await self.client.get_nat_table()

    async def get_device_nat_connections(self, ip: str) -> List[Dict[str, Any]]:
        return await self.client.get_device_nat_connections(ip)

    async def get_dns_cache(self) -> List[Dict[str, Any]]:
        return await self.client.get_dns_cache()

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        return await self.client.get_network_segments()

    def evaluate_segment_risk(self, profile: str, segment: str, ip: str = "") -> Dict[str, Any]:
        return self.client.evaluate_segment_risk(profile, segment, ip)

    async def get_wifi_security(self) -> Dict[str, Any]:
        return await self.client.get_wifi_security()

    async def check_firmware_updates(self) -> Dict[str, Any]:
        return await self.client.check_firmware_updates()

    async def get_wan_ip(self) -> Optional[str]:
        if hasattr(self.client, "get_wan_ip"):
            res = self.client.get_wan_ip()
            if asyncio.iscoroutine(res):
                return await res
            return res
        try:
            resp = await self.client._send_request("POST", "/rci/", json_data=[{"show": {"interface": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    ifaces = data[0].get("show", {}).get("interface", {})
                    for if_name, if_data in ifaces.items():
                        if isinstance(if_data, dict) and (if_data.get("defaultgw") or if_data.get("global")):
                            addr = if_data.get("address")
                            if addr and addr != "0.0.0.0":
                                return str(addr)
        except Exception:
            pass
        return None

    async def get_interface_stats(self, dev_name: str = "wan") -> Dict[str, Any]:
        """Fetches interface byte counters and speed from Keenetic."""
        try:
            target_iface = getattr(self, "_wan_interface_name", None)
            if not target_iface or dev_name != "wan":
                resp = await self.client._send_request("POST", "/rci/", json_data=[{"show": {"interface": {}}}])
                if resp and resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list) and len(data) > 0:
                        ifaces = data[0].get("show", {}).get("interface", {})
                        wan_if = next((k for k, v in ifaces.items() if (v.get("defaultgw") or v.get("global")) and v.get("link") == "up"), None)
                        if not wan_if:
                            wan_if = next((k for k, v in ifaces.items() if v.get("defaultgw") or v.get("global")), "GigabitEthernet1")
                        self._wan_interface_name = wan_if
                        target_iface = wan_if

            if not target_iface:
                target_iface = "GigabitEthernet1"

            stat_resp = await self.client._send_request("POST", "/rci/", json_data=[{"show": {"interface": {"stat": {"name": target_iface}}}}])
            if stat_resp and stat_resp.status_code == 200:
                sdata = stat_resp.json()
                if isinstance(sdata, list) and len(sdata) > 0:
                    stat = sdata[0].get("show", {}).get("interface", {}).get("stat", {})
                    rx_b = int(stat.get("rxbytes") or 0)
                    tx_b = int(stat.get("txbytes") or 0)
                    rx_speed = int(stat.get("rxspeed") or 0)
                    tx_speed = int(stat.get("txspeed") or 0)
                    return {
                        "rx_bytes": rx_b,
                        "tx_bytes": tx_b,
                        "rx_speed_bps": rx_speed,
                        "tx_speed_bps": tx_speed
                    }
        except Exception as e:
            logger.debug("Keenetic interface stats query error: %s", e)
        return {"rx_bytes": 0, "tx_bytes": 0, "rx_speed_bps": 0, "tx_speed_bps": 0}

    async def get_dns_proxy_status(self) -> Dict[str, Any]:
        return await self.client.get_dns_proxy_status()

    async def is_packet_capture_supported(self) -> bool:
        return await self.client.is_packet_capture_supported()

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
        eff_ip = target_ip or ip
        return await self.client.start_packet_capture(
            interface=interface,
            target_ip=eff_ip,
            duration_seconds=duration_seconds
        )

    async def stop_packet_capture(self, interface: str = "Bridge0") -> Optional[str]:
        return await self.client.stop_packet_capture(interface=interface)

    async def download_capture_file(self, filename: str, destination_path: Any) -> bool:
        return await self.client.download_capture_file(filename, destination_path)

    async def reset_packet_capture(self, interface: str = "Bridge0") -> bool:
        return await self.client.reset_packet_capture(interface=interface)

    def is_router_entity(self, ip: Optional[str] = None, mac: Optional[str] = None) -> bool:
        """Checks if target IP or MAC belongs to Keenetic router."""
        return self.client.is_router_entity(ip=ip, mac=mac)

    async def set_dlna_access(self, mac: str, ip: str, allow: bool = True) -> bool:
        return await self.client.set_dlna_access(mac, ip, allow=allow)

    async def enable_mdns_relay(self) -> bool:
        return await self.client.enable_mdns_relay()
