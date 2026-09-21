"""OpenWrt router backend implementation via /ubus JSON-RPC."""
import asyncio
import logging
import re
import time
from typing import List, Dict, Any, Set, Optional
import httpx

from keenguard.config import settings
from keenguard.core.routers.base import BaseRouterBackend
from keenguard.core.routers.models import RouterHost, RouterSystemInfo

logger = logging.getLogger("keenguard.routers.openwrt")


class OpenWrtBackend(BaseRouterBackend):
    """Integrates with OpenWrt routers using standard /ubus JSON-RPC API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_https: Optional[bool] = None,
        ubus_path: Optional[str] = None,
        timeout: float = 6.0
    ):
        self.host = host or settings.openwrt_host or "192.168.1.1"
        self.port = port or settings.openwrt_port or 80
        self.username = username or settings.openwrt_username or "root"
        self.password = password if password is not None else settings.openwrt_password
        self.use_https = use_https if use_https is not None else settings.openwrt_use_https
        self.ubus_path = ubus_path or settings.openwrt_ubus_path or "/ubus"
        self.timeout = timeout

        self.session_token: Optional[str] = None
        self.session_expires: float = 0.0
        self._rpc_id = 0
        self._lock = asyncio.Lock()

        # Cached info
        self.last_model = "OpenWrt Device"
        self.last_version = "OpenWrt"
        self._blocked_macs_cache: Set[str] = set()
        self._current_capture_file: Optional[str] = None

    @property
    def platform_id(self) -> str:
        return "openwrt"

    @property
    def platform_name(self) -> str:
        return "OpenWrt"

    @property
    def capabilities(self) -> Set[str]:
        return {
            "wan_block",
            "dns_sinkhole",
            "reboot",
            "dhcp_leases",
            "traffic_stats"
        }

    @property
    def base_url(self) -> str:
        proto = "https" if self.use_https else "http"
        return f"{proto}://{self.host}:{self.port}{self.ubus_path}"

    async def _call_ubus(self, subsystem: str, method: str, params: Optional[Dict[str, Any]] = None, require_auth: bool = True) -> Any:
        """Executes a JSON-RPC call against OpenWrt /ubus endpoint."""
        if require_auth:
            token = await self._ensure_authenticated()
            if not token:
                raise ConnectionError("Failed to authenticate with OpenWrt /ubus")
        else:
            token = "00000000000000000000000000000000"

        self._rpc_id += 1
        req_payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": "call",
            "params": [
                token,
                subsystem,
                method,
                params or {}
            ]
        }

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            res = await client.post(self.base_url, json=req_payload)
            if res.status_code != 200:
                raise ConnectionError(f"OpenWrt ubus HTTP error: {res.status_code}")
            data = res.json()

            # Format: {"jsonrpc": "2.0", "id": 1, "result": [status_code, return_data]}
            result = data.get("result")
            if not result or not isinstance(result, list) or len(result) < 2:
                err = data.get("error", "Invalid ubus response")
                raise RuntimeError(f"OpenWrt RPC error: {err}")

            status_code = result[0]
            if status_code != 0:
                # 4 = UBUS_STATUS_PERMISSION_DENIED
                if status_code == 4 and require_auth:
                    self.session_token = None
                raise RuntimeError(f"OpenWrt ubus call failed: code {status_code} for {subsystem}->{method}")

            return result[1]

    async def _ensure_authenticated(self) -> Optional[str]:
        """Ensures a valid ubus session token exists, renewing if necessary."""
        async with self._lock:
            now = time.time()
            if self.session_token and now < self.session_expires - 30:
                return self.session_token

            login_params = {
                "username": self.username,
                "password": self.password
            }

            try:
                res_data = await self._call_ubus("session", "login", login_params, require_auth=False)
                token = res_data.get("ubus_rpc_session")
                expires_in = res_data.get("expires", 300)
                if token:
                    self.session_token = token
                    self.session_expires = now + expires_in
                    logger.info("OpenWrt ubus session established (valid %ds)", expires_in)
                    return token
            except Exception as e:
                logger.error("OpenWrt authentication failed: %s", e)
                self.session_token = None
                return None
            return None

    async def connect(self) -> bool:
        """Validates connection to OpenWrt ubus."""
        try:
            token = await self._ensure_authenticated()
            return token is not None
        except Exception as e:
            logger.warning("OpenWrt connection failed: %s", e)
            return False

    async def get_system_info(self) -> RouterSystemInfo:
        """Queries OpenWrt system board and system info."""
        model = self.last_model
        version = self.last_version
        uptime = 0
        cpu_load = 0.0
        mem_total = 0
        mem_free = 0
        extra: Dict[str, Any] = {}

        try:
            # 1. System info
            sys_info = await self._call_ubus("system", "info", {})
            uptime = int(sys_info.get("uptime") or 0)
            load_arr = sys_info.get("load") or [0, 0, 0]
            cpu_load = float(load_arr[0]) / 65536.0 if load_arr else 0.0
            mem = sys_info.get("memory") or {}
            mem_total = int(mem.get("total") or 0)
            mem_free = int(mem.get("free") or 0)
            rel = sys_info.get("release") or {}
            if rel.get("description"):
                version = str(rel.get("description"))

            extra["system"] = sys_info
        except Exception as e:
            logger.debug("OpenWrt system info error: %s", e)

        try:
            # 2. Board info
            board_info = await self._call_ubus("system", "board", {})
            b_model = board_info.get("model") or board_info.get("board_name")
            if b_model:
                model = str(b_model)
            rel_b = board_info.get("release") or {}
            if rel_b.get("description"):
                version = str(rel_b.get("description"))
            extra["board"] = board_info
        except Exception as e:
            logger.debug("OpenWrt board info error: %s", e)

        self.last_model = model
        self.last_version = version

        return RouterSystemInfo(
            model=model,
            firmware_version=version,
            uptime=uptime,
            cpu_load=round(cpu_load, 2),
            memory_total=mem_total,
            memory_free=mem_free,
            platform="openwrt",
            extra=extra
        )

    async def get_hosts(self) -> List[RouterHost]:
        """
        Retrieves active devices from OpenWrt by querying:
        1. luci-rpc -> getHostHints (leases, ARP entries, static hosts)
        2. dhcp -> get_leases (active DHCP leases)
        """
        hosts_map: Dict[str, RouterHost] = {}

        # 1. Try luci-rpc getHostHints
        try:
            hints = await self._call_ubus("luci-rpc", "getHostHints", {})
            if isinstance(hints, dict):
                for mac, info in hints.items():
                    clean_mac = mac.upper()
                    ip = info.get("ip") or (info.get("ipv4", [None])[0] if isinstance(info.get("ipv4"), list) else None)
                    hostname = info.get("name") or info.get("hostname")
                    is_blocked = clean_mac in self._blocked_macs_cache

                    hosts_map[clean_mac] = RouterHost(
                        mac=clean_mac,
                        ip=ip,
                        hostname=hostname,
                        name=hostname,
                        link="up",
                        active=True,
                        access="deny" if is_blocked else "permit",
                        segment="Home"
                    )
        except Exception as e:
            logger.debug("OpenWrt luci-rpc getHostHints fallback: %s", e)

        # 2. Try dhcp get_leases (or luci getDHCPLeases)
        try:
            leases_data = await self._call_ubus("dhcp", "get_leases", {})
            leases = leases_data.get("leases") or []
            for item in leases:
                mac = (item.get("macaddr") or item.get("mac") or "").upper()
                if not mac:
                    continue
                ip = item.get("ipaddr") or item.get("ip")
                hostname = item.get("hostname") or item.get("name")
                is_blocked = mac in self._blocked_macs_cache

                if mac in hosts_map:
                    if not hosts_map[mac].hostname and hostname:
                        hosts_map[mac].hostname = hostname
                        hosts_map[mac].name = hostname
                    if not hosts_map[mac].ip and ip:
                        hosts_map[mac].ip = ip
                else:
                    hosts_map[mac] = RouterHost(
                        mac=mac,
                        ip=ip,
                        hostname=hostname,
                        name=hostname,
                        link="up",
                        active=True,
                        access="deny" if is_blocked else "permit",
                        segment="Home"
                    )
        except Exception as e:
            logger.debug("OpenWrt dhcp get_leases fallback: %s", e)

        # Refresh WAN block state from firewall if cache empty
        if not self._blocked_macs_cache:
            try:
                fw_data = await self._call_ubus("uci", "get", {"config": "firewall"})
                values = fw_data.get("values", {})
                for section_name, sec_data in values.items():
                    if sec_data.get(".type") == "rule" and sec_data.get("name", "").startswith("keenguard_block_"):
                        b_mac = sec_data.get("src_mac", "").upper()
                        if b_mac:
                            self._blocked_macs_cache.add(b_mac)
                            if b_mac in hosts_map:
                                hosts_map[b_mac].access = "deny"
            except Exception as e:
                logger.debug("Error checking OpenWrt firewall rules: %s", e)

        return list(hosts_map.values())

    async def set_wan_access(self, mac: str, allow: bool) -> bool:
        """
        Controls device WAN access using OpenWrt UCI firewall rules.
        Creates a rule named 'keenguard_block_<clean_mac>' with target 'DROP'.
        """
        clean_mac = mac.upper()
        rule_name = f"keenguard_block_{clean_mac.replace(':', '')}"

        try:
            if not allow:
                # Block WAN: Add firewall rule
                rule_values = {
                    "name": rule_name,
                    "src": "lan",
                    "dest": "wan",
                    "src_mac": clean_mac,
                    "target": "DROP"
                }
                await self._call_ubus("uci", "add", {
                    "config": "firewall",
                    "type": "rule",
                    "name": rule_name,
                    "values": rule_values
                })
                await self._call_ubus("uci", "commit", {"config": "firewall"})
                self._blocked_macs_cache.add(clean_mac)
            else:
                # Allow WAN: Delete firewall rule
                try:
                    await self._call_ubus("uci", "delete", {
                        "config": "firewall",
                        "section": rule_name
                    })
                    await self._call_ubus("uci", "commit", {"config": "firewall"})
                except Exception as del_err:
                    logger.debug("Delete rule %s failed (might not exist): %s", rule_name, del_err)
                self._blocked_macs_cache.discard(clean_mac)

            # Reload firewall
            try:
                await self._call_ubus("luci-rpc", "setInitStatus", {"name": "firewall", "action": "reload"})
            except Exception:
                pass

            logger.info("OpenWrt WAN access for %s set to %s", clean_mac, "allow" if allow else "block")
            return True
        except Exception as e:
            logger.error("Failed to set WAN access on OpenWrt for %s: %s", clean_mac, e)
            return False

    async def reboot(self) -> bool:
        """Sends reboot command to OpenWrt router."""
        try:
            await self._call_ubus("system", "reboot", {})
            logger.warning("OpenWrt reboot command issued successfully")
            return True
        except Exception as e:
            logger.error("Failed to trigger OpenWrt reboot: %s", e)
            return False

    async def add_dns_sinkhole(self, domain: str, ip: str = "0.0.0.0") -> bool:
        """
        Adds a DNS sinkhole mapping in OpenWrt dnsmasq via UCI:
        Adds '/domain/0.0.0.0' to dhcp.@dnsmasq[0].address list.
        """
        clean_domain = domain.strip().lower()
        entry_val = f"/{clean_domain}/{ip}"
        try:
            await self._call_ubus("uci", "add_list", {
                "config": "dhcp",
                "section": "@dnsmasq[0]",
                "option": "address",
                "value": entry_val
            })
            await self._call_ubus("uci", "commit", {"config": "dhcp"})
            try:
                await self._call_ubus("luci-rpc", "setInitStatus", {"name": "dnsmasq", "action": "reload"})
            except Exception:
                pass
            logger.info("OpenWrt DNS sinkhole added: %s -> %s", clean_domain, ip)
            return True
        except Exception as e:
            logger.error("Failed to add DNS sinkhole on OpenWrt: %s", e)
            return False

    async def remove_dns_sinkhole(self, domain: str) -> bool:
        """Removes a DNS sinkhole mapping in OpenWrt dnsmasq via UCI."""
        clean_domain = domain.strip().lower()
        entry_val = f"/{clean_domain}/0.0.0.0"
        try:
            await self._call_ubus("uci", "del_list", {
                "config": "dhcp",
                "section": "@dnsmasq[0]",
                "option": "address",
                "value": entry_val
            })
            await self._call_ubus("uci", "commit", {"config": "dhcp"})
            try:
                await self._call_ubus("luci-rpc", "setInitStatus", {"name": "dnsmasq", "action": "reload"})
            except Exception:
                pass
            logger.info("OpenWrt DNS sinkhole removed: %s", clean_domain)
            return True
        except Exception as e:
            logger.error("Failed to remove DNS sinkhole on OpenWrt: %s", e)
            return False

    async def get_guest_wifi_status(self) -> Dict[str, Any]:
        """Checks if a guest wireless network or interface exists on OpenWrt."""
        try:
            res = await self._call_ubus("network.interface", "dump", {})
            interfaces = res.get("interface", [])
            for iface in interfaces:
                if "guest" in str(iface.get("interface", "")).lower():
                    is_up = bool(iface.get("up", False))
                    return {"enabled": is_up, "interface": iface.get("interface"), "supported": True}
            return {"enabled": False, "interface": None, "supported": False}
        except Exception as e:
            logger.debug("OpenWrt guest wifi status error: %s", e)
            return {"enabled": False, "supported": False}

    async def toggle_guest_wifi(self, enable: bool) -> bool:
        """Toggles guest Wi-Fi interface if present on OpenWrt."""
        status = await self.get_guest_wifi_status()
        iface = status.get("interface")
        if not iface:
            logger.info("No guest interface found on OpenWrt to toggle")
            return False

        action = "up" if enable else "down"
        try:
            await self._call_ubus("network.interface", action, {"interface": iface})
            logger.info("OpenWrt interface %s set to %s", iface, action)
            return True
        except Exception as e:
            logger.error("Failed to toggle OpenWrt interface %s: %s", iface, e)
            return False

    def is_router_entity(self, ip: Optional[str] = None, mac: Optional[str] = None) -> bool:
        """Identifies if the IP matches the OpenWrt router address."""
        if ip and ip == self.host:
            return True
        return False

    async def get_active_sinkholes(self) -> List[str]:
        """Returns list of active DNS sinkhole domains configured in OpenWrt dnsmasq."""
        sinkholes = []
        try:
            dhcp_data = await self._call_ubus("uci", "get", {"config": "dhcp"})
            values = dhcp_data.get("values", {})
            for sec_name, sec_data in values.items():
                if sec_data.get(".type") == "dnsmasq":
                    addresses = sec_data.get("address", [])
                    if isinstance(addresses, str):
                        addresses = [addresses]
                    for addr in addresses:
                        # Entry format: /example.com/0.0.0.0
                        parts = [p for p in addr.strip().split("/") if p]
                        if len(parts) >= 2 and parts[-1] in ("0.0.0.0", "127.0.0.1", "::"):
                            sinkholes.append(parts[0].lower())
        except Exception as e:
            logger.debug("Failed to read OpenWrt active sinkholes: %s", e)
        return sorted(list(set(sinkholes)))

    async def add_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        """Batch adds multiple domains to OpenWrt dnsmasq address sinkhole list."""
        succeeded, failed = [], []
        clean_domains = [d.strip().lower() for d in domains if d and d.strip()]
        if not clean_domains:
            return [], []

        for d in clean_domains:
            entry_val = f"/{d}/0.0.0.0"
            try:
                await self._call_ubus("uci", "add_list", {
                    "config": "dhcp",
                    "section": "@dnsmasq[0]",
                    "option": "address",
                    "value": entry_val
                })
                succeeded.append(d)
            except Exception as e:
                logger.debug("Error adding OpenWrt sinkhole for %s: %s", d, e)
                failed.append(d)

        try:
            await self._call_ubus("uci", "commit", {"config": "dhcp"})
            try:
                await self._call_ubus("luci-rpc", "setInitStatus", {"name": "dnsmasq", "action": "reload"})
            except Exception:
                pass
        except Exception as commit_err:
            logger.error("Failed committing OpenWrt DNS sinkhole rules: %s", commit_err)

        return succeeded, failed

    async def remove_dns_sinkholes(self, domains: List[str]) -> tuple[List[str], List[str]]:
        """Batch removes multiple domains from OpenWrt dnsmasq sinkhole list."""
        succeeded, failed = [], []
        clean_domains = [d.strip().lower() for d in domains if d and d.strip()]
        if not clean_domains:
            return [], []

        for d in clean_domains:
            entry_val = f"/{d}/0.0.0.0"
            try:
                await self._call_ubus("uci", "del_list", {
                    "config": "dhcp",
                    "section": "@dnsmasq[0]",
                    "option": "address",
                    "value": entry_val
                })
                succeeded.append(d)
            except Exception as e:
                logger.debug("Error removing OpenWrt sinkhole for %s: %s", d, e)
                failed.append(d)

        try:
            await self._call_ubus("uci", "commit", {"config": "dhcp"})
            try:
                await self._call_ubus("luci-rpc", "setInitStatus", {"name": "dnsmasq", "action": "reload"})
            except Exception:
                pass
        except Exception as commit_err:
            logger.error("Failed committing OpenWrt DNS sinkhole removal: %s", commit_err)

        return succeeded, failed

    async def get_active_ip_blackholes(self) -> List[str]:
        """Returns list of IP addresses actively blackholed on OpenWrt firewall."""
        ips = []
        try:
            fw_data = await self._call_ubus("uci", "get", {"config": "firewall"})
            values = fw_data.get("values", {})
            for sec_name, sec_data in values.items():
                name = sec_data.get("name") or sec_data.get(".name") or sec_name
                if sec_data.get(".type") == "rule" and (name.startswith("keenguard_blackhole_") or name.startswith("keenguard_ip_blackhole_")):
                    dest_ip = sec_data.get("dest_ip")
                    if dest_ip:
                        ips.append(dest_ip)
        except Exception as e:
            logger.debug("Error checking OpenWrt firewall blackhole rules: %s", e)
        return sorted(list(set(ips)))

    async def add_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        """Batch adds REJECT firewall rules for destination IPs on OpenWrt."""
        succeeded, failed = [], []
        for ip in ips:
            clean_ip = ip.strip()
            rule_name = f"keenguard_blackhole_{clean_ip.replace('.', '_').replace(':', '_')}"
            try:
                await self._call_ubus("uci", "add", {
                    "config": "firewall",
                    "type": "rule",
                    "name": rule_name,
                    "values": {
                        "name": rule_name,
                        "src": "lan",
                        "dest": "wan",
                        "dest_ip": clean_ip,
                        "target": "REJECT"
                    }
                })
                succeeded.append(clean_ip)
            except Exception as e:
                logger.debug("Error adding OpenWrt IP blackhole for %s: %s", clean_ip, e)
                failed.append(clean_ip)

        if succeeded:
            try:
                await self._call_ubus("uci", "commit", {"config": "firewall"})
                try:
                    await self._call_ubus("luci-rpc", "setInitStatus", {"name": "firewall", "action": "reload"})
                except Exception:
                    pass
            except Exception as e:
                logger.error("Failed committing OpenWrt IP blackhole rules: %s", e)
        return succeeded, failed

    async def remove_ip_blackholes(self, ips: List[str]) -> tuple[List[str], List[str]]:
        """Batch removes IP blackhole rules from OpenWrt firewall."""
        succeeded, failed = [], []
        for ip in ips:
            clean_ip = ip.strip()
            rule_name = f"keenguard_blackhole_{clean_ip.replace('.', '_').replace(':', '_')}"
            try:
                await self._call_ubus("uci", "delete", {
                    "config": "firewall",
                    "section": rule_name
                })
                succeeded.append(clean_ip)
            except Exception as e:
                logger.debug("Error removing OpenWrt IP blackhole for %s: %s", clean_ip, e)
                failed.append(clean_ip)

        if succeeded:
            try:
                await self._call_ubus("uci", "commit", {"config": "firewall"})
                try:
                    await self._call_ubus("luci-rpc", "setInitStatus", {"name": "firewall", "action": "reload"})
                except Exception:
                    pass
            except Exception as e:
                logger.error("Failed committing OpenWrt IP blackhole removal: %s", e)
        return succeeded, failed

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        """Queries active Linux kernel Conntrack flows via OpenWrt luci-rpc."""
        try:
            res = await self._call_ubus("luci-rpc", "getConntrackList", {})
            raw_entries = res if isinstance(res, list) else (res.get("entries", []) if isinstance(res, dict) else [])
            entries = []
            for item in raw_entries:
                entries.append({
                    "protocol": (item.get("layer4") or item.get("protocol") or "TCP").upper(),
                    "src": item.get("src") or item.get("orig_src"),
                    "sport": int(item.get("sport") or item.get("orig_sport") or 0),
                    "dst": item.get("dst") or item.get("orig_dst"),
                    "dport": int(item.get("dport") or item.get("orig_dport") or 0),
                    "bytes": int(item.get("bytes") or 0),
                    "packets": int(item.get("packets") or 0)
                })
            return entries
        except Exception as e:
            logger.debug("OpenWrt getConntrackList fallback: %s", e)
            return []

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        """Retrieves OpenWrt network interfaces and segments (br-lan, guest, wan)."""
        segments = []
        try:
            res = await self._call_ubus("network.interface", "dump", {})
            interfaces = res.get("interface", [])
            for iface in interfaces:
                name = iface.get("interface", "unknown")
                dev = iface.get("device") or iface.get("l3_device") or name
                up = bool(iface.get("up", False))
                ipv4_list = iface.get("ipv4-address", [])
                subnet = ipv4_list[0].get("address") if ipv4_list else None
                mask = ipv4_list[0].get("mask") if ipv4_list else 24
                
                is_guest = "guest" in name.lower() or "изолир" in name.lower()
                is_wan = "wan" in name.lower()
                
                segments.append({
                    "id": name,
                    "name": name,
                    "description": "Гостевой сегмент" if is_guest else ("Интернет (WAN)" if is_wan else "Основная сеть (LAN)"),
                    "interface": dev,
                    "active": up,
                    "is_isolated": is_guest,
                    "isolated": is_guest,
                    "subnet": f"{subnet}/{mask}" if subnet else "",
                    "security_level": "guest" if is_guest else ("external" if is_wan else "private")
                })
        except Exception as e:
            logger.debug("OpenWrt network segments query error: %s", e)

        if not segments:
            segments = [
                {"id": "lan", "name": "lan", "description": "Основная сеть (LAN)", "interface": "br-lan", "active": True, "is_isolated": False, "isolated": False, "security_level": "private"}
            ]
        return segments

    async def get_wifi_security(self) -> Dict[str, Any]:
        """Audits OpenWrt wireless network encryption, client isolation, and PMF."""
        networks = []
        recommendations = []
        score = 85

        try:
            wl_data = await self._call_ubus("uci", "get", {"config": "wireless"})
            values = wl_data.get("values", {})
            for sec_name, sec_data in values.items():
                if sec_data.get(".type") == "wifi-iface":
                    ssid = sec_data.get("ssid", "OpenWrt Wi-Fi")
                    enc = str(sec_data.get("encryption", "")).lower()
                    isolate = str(sec_data.get("isolate", "0")) == "1"
                    pmf = str(sec_data.get("ieee80211w", "0"))
                    
                    has_wpa3 = "sae" in enc or "wpa3" in enc
                    has_wpa2 = "psk2" in enc or "wpa2" in enc
                    is_open = enc in ("none", "", "open")
                    
                    sec_type = "WPA3-SAE" if has_wpa3 else ("WPA2-PSK" if has_wpa2 else ("Открытая сеть" if is_open else enc))
                    
                    risk_val = "critical" if is_open else ("medium" if not has_wpa3 else "low")
                    net_item = {
                        "ssid": ssid,
                        "encryption": sec_type,
                        "client_isolation": isolate,
                        "pmf": pmf in ("1", "2"),
                        "wpa3_supported": has_wpa3,
                        "risk": risk_val,
                        "risk_level": risk_val
                    }
                    networks.append(net_item)
                    
                    if is_open:
                        score -= 40
                        recommendations.append(f"Сеть '{ssid}' не защищена паролем (Open). Включите WPA2/WPA3.")
                    elif not isolate and "guest" in ssid.lower():
                        score -= 15
                        recommendations.append(f"В гостевой сети '{ssid}' отключена изоляция клиентов (option isolate '1').")
        except Exception as e:
            logger.debug("OpenWrt Wi-Fi security query error: %s", e)

        score = max(0, min(100, score))
        grade = "A" if score >= 90 else ("B" if score >= 75 else ("C" if score >= 50 else "F"))
        has_critical = any(n.get("risk_level") == "critical" or n.get("risk") == "critical" for n in networks)
        has_warnings = any(n.get("risk_level") == "warning" or n.get("risk") == "warning" for n in networks)
        return {
            "score": score,
            "grade": grade,
            "networks": networks,
            "has_critical": has_critical,
            "has_warnings": has_warnings,
            "recommendations": recommendations
        }

    async def check_firmware_updates(self) -> Dict[str, Any]:
        """Checks OpenWrt system firmware status."""
        sys_info = await self.get_system_info()
        return {
            "update_available": False,
            "current_version": sys_info.firmware_version,
            "latest_version": sys_info.firmware_version,
            "channel": "openwrt-release"
        }

    async def is_packet_capture_supported(self) -> bool:
        """
        Checks if hardware-level packet capture (tcpdump) is installed and available on OpenWrt.
        """
        try:
            res = await self._call_ubus("file", "exec", {"command": "which", "params": ["tcpdump"]})
            if res and (res.get("code") == 0 or "/tcpdump" in str(res.get("stdout", ""))):
                return True
        except Exception:
            pass
        try:
            stat_res = await self._call_ubus("file", "stat", {"path": "/usr/sbin/tcpdump"})
            if stat_res and stat_res.get("type") in ("file", "regular"):
                return True
        except Exception:
            pass
        try:
            stat_res2 = await self._call_ubus("file", "stat", {"path": "/usr/bin/tcpdump"})
            if stat_res2 and stat_res2.get("type") in ("file", "regular"):
                return True
        except Exception:
            pass
        return False

    async def start_packet_capture(
        self,
        interface: str = "br-lan",
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        proto: Optional[str] = None,
        port: Optional[int] = None,
        duration_seconds: int = 60,
        target_ip: Optional[str] = None
    ) -> Any:
        """Starts tcpdump packet capture on OpenWrt router to /tmp/keenguard_capture.pcap."""
        target = target_ip or ip
        can_capture = await self.is_packet_capture_supported()
        if not can_capture:
            return {
                "status": "error",
                "message": "tcpdump не установлен на OpenWrt. Установите: 'opkg update && opkg install tcpdump-mini' (OpenWrt <=24) или 'apk -U add tcpdump-mini' (OpenWrt 25+)"
            }

        out_path = "/tmp/keenguard_capture.pcap"
        cmd_filter = f"host {target}" if target else ""
        if proto:
            cmd_filter += f" and {proto.lower()}"
        if port:
            cmd_filter += f" and port {port}"

        tcpdump_bin = "/usr/sbin/tcpdump"
        args = ["-i", "br-lan", "-w", out_path, "-s", "0", "-U"]
        if cmd_filter:
            args.extend(cmd_filter.split())

        try:
            await self._call_ubus("file", "exec", {
                "command": tcpdump_bin,
                "params": args
            })
            self._current_capture_file = out_path
            logger.info("OpenWrt tcpdump capture started for target %s -> %s", target, out_path)
            return {"status": "running", "pcap_file": out_path}
        except Exception as e:
            logger.warning("Failed to start OpenWrt packet capture: %s", e)
            return {"status": "error", "message": str(e)}

    async def stop_packet_capture(self, interface: str = "br-lan") -> Optional[str]:
        """Stops running tcpdump on OpenWrt and returns capture file path."""
        try:
            await self._call_ubus("file", "exec", {
                "command": "killall",
                "params": ["-SIGINT", "tcpdump"]
            })
        except Exception as e:
            logger.debug("Stop tcpdump error: %s", e)
        return self._current_capture_file or "/tmp/keenguard_capture.pcap"

    async def download_capture_file(self, filename: str, destination_path: Any) -> bool:
        """Downloads capture file from OpenWrt (/tmp/keenguard_capture.pcap) to local storage."""
        from pathlib import Path
        import base64
        dest = Path(destination_path)
        try:
            read_res = await self._call_ubus("file", "read", {
                "path": filename or "/tmp/keenguard_capture.pcap",
                "base64": True
            })
            b64_data = read_res.get("data")
            if b64_data:
                raw_bytes = base64.b64decode(b64_data)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw_bytes)
                logger.info("Successfully downloaded %d bytes PCAP from OpenWrt to %s", len(raw_bytes), dest)
                return True
        except Exception as e:
            logger.debug("Failed reading PCAP file from OpenWrt: %s", e)
        return False

    async def reset_packet_capture(self, interface: str = "br-lan") -> bool:
        """Removes temporary PCAP files on OpenWrt."""
        try:
            await self._call_ubus("file", "remove", {"path": "/tmp/keenguard_capture.pcap"})
            return True
        except Exception:
            return False
