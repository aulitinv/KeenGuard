"""Keenetic RCI (Remote Control Interface) async client with NDM Challenge-Response authentication."""
import asyncio
import hashlib
import ipaddress
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
import httpx
from pydantic import BaseModel

from keenguard.config import settings

logger = logging.getLogger("keenguard.keenetic")

class HotspotHost(BaseModel):
    mac: str
    ip: Optional[str] = None
    name: Optional[str] = None
    hostname: Optional[str] = None
    interface: Optional[Any] = None
    link: str = "down"  # "up" or "down"
    active: bool = False
    rxbytes: int = 0
    txbytes: int = 0
    uptime: int = 0
    access: str = "permit"  # "permit" or "deny" (WAN access)
    registered: bool = False
    policy: Optional[str] = None
    segment: Optional[str] = "Home"

def is_host_lan_isolated(interface: Optional[str], ip: Optional[str]) -> bool:
    """
    Evaluates whether a host is physically isolated from the main LAN.
    In KeeneticOS:
    - Bridge0 is the default unisolated Home network (192.168.1.0/24).
    - Bridge1 is the Guest Wi-Fi network with client isolation enabled.
    - Devices with interface != Bridge0 or outside 192.168.1.0/24 are isolated.
    """
    if not interface and not ip:
        return False
    if interface == "Bridge0":
        return False
    if ip and ip.startswith("192.168.1."):
        return False
    if interface and ("bridge1" in str(interface).lower() or "guest" in str(interface).lower()):
        return True
    if ip and not ip.startswith("192.168.1.") and ip != "0.0.0.0":
        return True
    return False

def is_unsafe_ip_for_blackhole(ip_obj: ipaddress.IPv4Address) -> bool:
    """
    Checks if an IP address is unsafe to blackhole on Keenetic router.
    Prevents blackholing RFC 1918 LAN, gateway, loopback, multicast, or link-local addresses.
    Permits RFC 5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24) for safe testing.
    """
    if getattr(ip_obj, "version", 0) != 4:
        return True
    if (ip_obj in ipaddress.ip_network("198.51.100.0/24") or
        ip_obj in ipaddress.ip_network("203.0.113.0/24") or
        ip_obj in ipaddress.ip_network("192.0.2.0/24")):
        return False
    if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
        ip_obj.is_multicast or ip_obj.is_unspecified or int(ip_obj) >= 0xF0000000):
        return True
    return False

class UPnPMapping(BaseModel):
    interface: Optional[Any] = None
    protocol: str = "tcp"
    ext_port: int
    int_ip: str
    int_port: int
    description: Optional[str] = None

class KeeneticClient:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None,
                 user: Optional[str] = None, password: Optional[str] = None,
                 use_https: Optional[bool] = None):
        self.host = host or settings.router_host
        self.port = port or settings.router_port
        self.user = user or settings.router_user
        self.password = password or settings.router_password
        self.use_https = use_https if use_https is not None else settings.router_use_https
        self.schema = "https" if self.use_https else "http"
        self.base_url = f"{self.schema}://{self.host}:{self.port}"
        self._cookies: Dict[str, str] = {}
        self._auth_lock = asyncio.Lock()
        self.mock_mode = False
        self._mock_hosts: List[Dict[str, Any]] = []
        self._mock_upnp: List[Dict[str, Any]] = []
        self.last_model = "Keenetic"
        self.last_version = "KeeneticOS"
        self.router_ips: Set[str] = {self.host, "192.168.1.1", "192.168.2.1"}
        self.router_macs: Set[str] = set()
        self._capture_supported: Optional[bool] = None
        self._mock_captures: Dict[str, Dict[str, Any]] = {}


    async def authenticate(self, host: Optional[str] = None, user: Optional[str] = None,
                           password: Optional[str] = None) -> Dict[str, Any]:
        """
        Authenticates against KeeneticOS using the NDM Challenge-Response scheme:
        1. GET /auth -> 401 with X-NDM-Challenge and X-NDM-Realm + session cookie
        2. md5_hash = md5(user:realm:password)
        3. sha_hash = sha256(challenge + md5_hash)
        4. POST /auth with {"login": user, "password": sha_hash} -> 200 OK + auth cookie
        """
        if self.mock_mode:
            return {"status": "ok", "version": "KeeneticOS 4.1 (Mock)", "model": "Keenetic Hero 4G"}

        target_host = host or self.host
        target_user = user or self.user
        target_pass = password if password is not None else self.password
        base_url = f"{self.schema}://{target_host}:{self.port}"

        if not target_pass:
            return {"status": "error", "message": "Пароль пуст. Введите пароль администратора Keenetic."}

        async with self._auth_lock:
            try:
                async with httpx.AsyncClient(base_url=base_url, timeout=6.0, verify=False) as client:
                    # Step 1: Request challenge
                    r1 = await client.get("/auth")
                    if r1.status_code == 200:
                        self._cookies = dict(r1.cookies)
                        self.host = target_host
                        self.user = target_user
                        self.password = target_pass
                        self.base_url = base_url
                        return {"status": "ok", "version": "KeeneticOS", "model": "Keenetic"}

                    if r1.status_code != 401:
                        return {"status": "error", "message": f"Неожиданный ответ роутера HTTP {r1.status_code}"}

                    challenge = r1.headers.get("X-NDM-Challenge")
                    realm = r1.headers.get("X-NDM-Realm")
                    if not challenge or not realm:
                        return {"status": "error", "message": "Роутер не вернул X-NDM-Challenge или X-NDM-Realm"}

                    # Step 2: Compute challenge hash
                    md5_str = hashlib.md5(f"{target_user}:{realm}:{target_pass}".encode("utf-8")).hexdigest()
                    sha_str = hashlib.sha256(f"{challenge}{md5_str}".encode("utf-8")).hexdigest()

                    # Step 3: POST /auth with session cookies from step 1
                    session_cookies = dict(r1.cookies)
                    r2 = await client.post(
                        "/auth",
                        json={"login": target_user, "password": sha_str},
                        cookies=session_cookies
                    )

                    if r2.status_code == 200:
                        # Combine cookies
                        merged_cookies = dict(session_cookies)
                        merged_cookies.update(dict(r2.cookies))
                        self._cookies = merged_cookies
                        self.host = target_host
                        self.user = target_user
                        self.password = target_pass
                        self.base_url = base_url

                        # Check router model/version
                        version_title = "KeeneticOS"
                        model_name = realm
                        try:
                            v_res = await client.get("/rci/show/version", cookies=self._cookies)
                            if v_res.status_code == 200:
                                v_data = v_res.json()
                                version_title = v_data.get("title", "KeeneticOS")
                                model_name = v_data.get("model", realm)
                        except Exception as e:
                            logger.debug("Failed fetching Keenetic version info: %s", e)

                        self.last_model = model_name
                        self.last_version = version_title

                        # Cache local interface IP and MAC addresses to prevent false positive scanning alerts
                        try:
                            if_res = await client.get("/rci/show/interface", cookies=self._cookies)
                            if if_res.status_code == 200:
                                for if_name, if_obj in if_res.json().items():
                                    if isinstance(if_obj, dict):
                                        if if_obj.get("address"):
                                            self.router_ips.add(if_obj["address"])
                                        if if_obj.get("mac"):
                                            self.router_macs.add(if_obj["mac"].upper())
                        except Exception as e:
                            logger.debug("Failed fetching Keenetic interface info: %s", e)

                        logger.info("Keenetic auth successful for %s (%s)", model_name, self.base_url)
                        return {"status": "ok", "version": version_title, "model": model_name}

                    elif r2.status_code == 401:
                        return {"status": "error", "message": "Неверный логин или пароль администратора Keenetic (401)"}
                    else:
                        return {"status": "error", "message": f"Ошибка авторизации HTTP {r2.status_code}"}

            except Exception as e:
                logger.error("Keenetic connection error: %s", e)
                return {"status": "unreachable", "message": f"Не удалось подключиться к {target_host}: {e}"}

    async def test_connection(self) -> Dict[str, Any]:
        """Tests connectivity and authentication."""
        if self.mock_mode:
            return {"status": "ok", "version": "KeeneticOS 4.1 (Mock)", "model": "Keenetic Hero 4G"}

        if not self._cookies:
            return await self.authenticate()

        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=5.0, verify=False) as client:
                resp = await client.get("/rci/show/version", cookies=self._cookies)
                if resp.status_code == 200:
                    data = resp.json()
                    return {"status": "ok", "version": data.get("title", "KeeneticOS"), "model": data.get("model", "Keenetic")}
                elif resp.status_code == 401:
                    # Cookie might have expired, try re-authenticating
                    return await self.authenticate()
                else:
                    return {"status": "error", "message": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            logger.warning("Keenetic connection test failed: %s", e)
            return {"status": "unreachable", "message": str(e)}

    async def refresh_router_interfaces(self):
        """Fetches all local IP and MAC addresses belonging to router interfaces to prevent false positive alerts."""
        if self.mock_mode or not self._cookies:
            return
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=5.0, verify=False) as client:
                resp = await client.get("/rci/show/interface", cookies=self._cookies)
                if resp.status_code == 200:
                    for name, iface in resp.json().items():
                        if isinstance(iface, dict):
                            ip = iface.get("address")
                            mac = iface.get("mac")
                            if ip:
                                self.router_ips.add(ip)
                            if mac:
                                self.router_macs.add(mac.upper())
        except Exception as e:
            logger.debug("Could not refresh router interfaces: %s", e)

    def is_router_entity(self, ip: Optional[str] = None, mac: Optional[str] = None) -> bool:
        """Checks if an IP or MAC belongs to the Keenetic router itself or its network gateways."""
        if mac and mac.upper() in self.router_macs:
            return True
        if ip:
            if ip in self.router_ips:
                return True
            # Subnet gateways: in standard IPv4 private networks, .1 or .254 is the router gateway
            parts = ip.split(".")
            if len(parts) == 4 and (parts[3] == "1" or parts[3] == "254"):
                if ip.startswith("192.168.") or ip.startswith("10.") or (ip.startswith("172.") and parts[1].isdigit() and 16 <= int(parts[1]) <= 31):
                    return True
        return False

    async def _send_request(self, method: str, path: str, json_data: Optional[Any] = None) -> Optional[httpx.Response]:
        if not self._cookies and not self.mock_mode:
            auth_res = await self.authenticate()
            if auth_res.get("status") != "ok":
                return None

        for attempt in range(2):
            try:
                async with httpx.AsyncClient(base_url=self.base_url, timeout=6.0, verify=False) as client:
                    if method.upper() == "GET":
                        resp = await client.get(path, cookies=self._cookies)
                    else:
                        resp = await client.post(path, json=json_data, cookies=self._cookies)

                    if resp.status_code == 401 and attempt == 0:
                        # Session expired, re-auth
                        await self.authenticate()
                        continue
                    return resp
            except Exception as e:
                logger.error("Keenetic request error (%s %s): %s", method, path, e)
                return None
        return None

    async def get_hotspot_hosts(self) -> List[HotspotHost]:
        """Pulls the current ARP & device table from Keenetic RAM."""
        if self.mock_mode:
            hosts = []
            for h in self._mock_hosts:
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

        resp = await self._send_request("GET", "/rci/show/ip/hotspot")
        if resp and resp.status_code == 200:
            raw_hosts = resp.json().get("host", [])
            result = []
            for h in raw_hosts:
                iface = h.get("interface")
                if isinstance(iface, dict):
                    iface_name = iface.get("name") or iface.get("id") or "Bridge0"
                else:
                    iface_name = str(iface) if iface else None

                name_val = h.get("name")
                if isinstance(name_val, dict):
                    name_val = name_val.get("name") or name_val.get("id")

                hname_val = h.get("hostname")
                if isinstance(hname_val, dict):
                    hname_val = hname_val.get("name") or hname_val.get("id")

                seg_name = "Home"
                if iface_name:
                    if "guest" in iface_name.lower() or "bridge1" in iface_name.lower():
                        seg_name = "Guest"
                    elif iface_name in ("Home", "Bridge0"):
                        seg_name = "Home"
                    else:
                        seg_name = iface_name
                elif h.get("ip") and not str(h.get("ip")).startswith("192.168.1.") and h.get("ip") != "0.0.0.0":
                    seg_name = "Guest"

                result.append(HotspotHost(
                    mac=str(h.get("mac", "")).upper(),
                    ip=h.get("ip"),
                    name=name_val,
                    hostname=hname_val,
                    interface=iface_name,
                    link=h.get("link", "down"),
                    active=h.get("active", False),
                    rxbytes=int(h.get("rxbytes", 0) or 0),
                    txbytes=int(h.get("txbytes", 0) or 0),
                    uptime=int(h.get("uptime", 0) or 0),
                    access=str(h.get("access", "permit")),
                    registered=bool(h.get("registered", False)),
                    policy=h.get("policy"),
                    segment=seg_name
                ))
            return result
        return []

    async def get_upnp_mappings(self) -> List[UPnPMapping]:
        """Pulls current UPnP / NAT-PMP port forwarding rules."""
        if self.mock_mode:
            return [UPnPMapping(**m) for m in self._mock_upnp]

        resp = await self._send_request("GET", "/rci/show/upnp")
        if resp and resp.status_code == 200:
            raw = resp.json().get("rule", [])
            result = []
            for r in raw:
                iface = r.get("interface")
                if isinstance(iface, dict):
                    iface_str = iface.get("name") or iface.get("id")
                else:
                    iface_str = str(iface) if iface else None

                result.append(UPnPMapping(
                    interface=iface_str,
                    protocol=r.get("protocol", "tcp"),
                    ext_port=int(r.get("port", 0)),
                    int_ip=r.get("to-address", ""),
                    int_port=int(r.get("to-port", 0)),
                    description=r.get("description")
                ))
            return result
        return []

    get_upnp_table = get_upnp_mappings

    async def delete_upnp_mapping(self, protocol: str, ext_port: int) -> bool:
        """Deletes a dangerous UPnP port forwarding rule."""
        logger.warning("Deleting dangerous UPnP rule: %s port %d", protocol, ext_port)
        if self.mock_mode:
            self._mock_upnp = [m for m in self._mock_upnp if not (m.get("protocol") == protocol and m.get("ext_port") == ext_port)]
            return True

        payload = [{"no": "upnp", "rule": {"protocol": protocol, "port": ext_port}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        return resp is not None and resp.status_code == 200

    async def set_device_policy(self, mac: str, access: str = "permit") -> bool:
        """Sets device access policy: 'permit' or 'deny'."""
        logger.warning("HARDWARE MUTATION REQUEST: set_device_policy(mac=%s, access=%s)", mac, access)
        if self.mock_mode:
            clean_mac = mac.upper()
            for h in self._mock_hosts:
                if str(h.get("mac", "")).upper() == clean_mac:
                    h["access"] = access
            return True

        payload = [{"ip": {"hotspot": {"host": {"mac": mac.lower(), "access": access}}}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        success = resp is not None and resp.status_code == 200
        if success:
            logger.warning("HARDWARE MUTATION APPLIED: Keenetic host %s access set to '%s'", mac, access)
        else:
            logger.error("HARDWARE MUTATION FAILED: Failed to set Keenetic host %s access to '%s'", mac, access)
        return success

    async def isolate_device_to_segment(self, mac: str, segment_id: str = "Guest") -> bool:
        """
        In KeeneticOS, Wi-Fi devices are bound to their physical SSID (Bridge0 for Home,
        Bridge1 for Guest). An API call cannot move a Wi-Fi client between SSIDs without reassociation.
        """
        clean_mac = mac.upper()
        if self.mock_mode:
            for h in self._mock_hosts:
                if str(h.get("mac", "")).upper() == clean_mac:
                    if h.get("interface") == "Bridge0" or (h.get("ip") and h.get("ip").startswith("192.168.1.")):
                        return False
                    return True
            return False

        logger.info(
            "LAN isolation requested for %s. Note: In KeeneticOS, Wi-Fi devices must connect to Guest SSID.",
            mac
        )
        return False

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        """Pulls the live active NAT connection table from Keenetic."""
        if self.mock_mode:
            return []
        resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"ip": {"nat": {}}}}])
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    return data[0].get("show", {}).get("ip", {}).get("nat", [])
            except Exception as e:
                logger.error("Error parsing Keenetic NAT table: %s", e)
        return []

    async def get_device_nat_connections(self, ip: str) -> List[Dict[str, Any]]:
        """Returns active NAT connections specifically for this device IP."""
        if not ip:
            return []
        nat_entries = await self.get_nat_table()
        return [e for e in nat_entries if e.get("src") == ip]

    async def enable_mdns_relay(self) -> Dict[str, Any]:
        """
        Enable mDNS (Bonjour/AirPlay/Cast) relay between Home and Guest segments.
        Uses Keenetic's built-in UDP proxy component (KeeneticOS 3.1+).
        This is required for AirPlay/Chromecast discovery when TV is isolated in Guest.
        """
        if self.mock_mode:
            return {"status": "ok", "method": "mock"}

        # Method 1: Configure UDP proxy for mDNS (port 5353) — most reliable
        try:
            payload = [{"udp-proxy": {"listen": {"port": 5353}}}]
            resp = await self._send_request("POST", "/rci/", json_data=payload)
            if resp and resp.status_code == 200:
                logger.info("mDNS relay (UDP proxy port 5353) enabled on Keenetic")
                return {"status": "ok", "method": "udp-proxy"}
        except Exception as e:
            logger.debug("UDP proxy method failed: %s", e)

        # Method 2: Enable IGMP proxy for general multicast forwarding
        try:
            payload2 = [{"ip": {"igmp": {"proxy": True}}}]
            resp2 = await self._send_request("POST", "/rci/", json_data=payload2)
            if resp2 and resp2.status_code == 200:
                logger.info("IGMP proxy enabled on Keenetic as mDNS relay fallback")
                return {"status": "ok", "method": "igmp-proxy"}
        except Exception as e:
            logger.debug("IGMP proxy method failed: %s", e)

        logger.warning(
            "Could not enable mDNS relay automatically. "
            "Install 'UDP Proxy' component in Keenetic UI: "
            "Система → Обновление компонентов → UDP Proxy"
        )
        return {
            "status": "warning",
            "method": None,
            "message": "Не удалось включить mDNS relay. "
                       "Установите компонент 'UDP Proxy' в настройках Keenetic "
                       "(Система → Обновление компонентов)."
        }

    async def set_dlna_access(self, mac: str, ip: str, allow: bool) -> bool:
        """
        Control DLNA (port 8200) access for a specific device via Keenetic ip policy.
        When allow=False, blocks the device from reaching the router's DLNA media server.
        When allow=True, removes the blocking rule.
        """
        if self.mock_mode:
            return True

        comment = f"keenguard-dlna-{mac.replace(':', '').lower()}"

        if not allow and ip:
            # Add deny rule: block this device from reaching port 8200 on the router
            payload = [{"ip": {"policy": {
                "deny": True,
                "protocol": "tcp",
                "src": ip,
                "dst": self.host,
                "dst-port": "8200",
                "comment": comment
            }}}]
        else:
            # Remove the deny rule
            payload = [{"no": {"ip": {"policy": {"comment": comment}}}}]

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            action = "разрешён" if allow else "заблокирован"
            logger.info("DLNA access %s for %s (%s)", action, mac, ip)
            return True

        # Fallback: if ip policy is not supported, try access-list approach
        if not allow and ip:
            payload2 = [{"access-list": {
                "keenguard-dlna": {
                    "deny": {"protocol": "tcp", "src": f"host {ip}",
                             "dst-port": "8200"}
                }
            }}]
            resp2 = await self._send_request("POST", "/rci/", json_data=payload2)
            if resp2 and resp2.status_code == 200:
                logger.info("DLNA access blocked via access-list for %s", mac)
                return True

        logger.warning("Could not enforce DLNA rule for %s via RCI. "
                       "Keenetic may not support per-device port filtering.", mac)
        return False

    async def get_dns_cache(self) -> List[Dict[str, Any]]:
        """Extracts the DNS proxy cache from Keenetic router."""
        if self.mock_mode:
            return [
                {"domain": "gateway.fe.apple-dns.net", "ip": "17.248.190.245", "ttl": 300},
                {"domain": "api.dreame.tech", "ip": "47.91.78.162", "ttl": 60},
                {"domain": "pool.ntp.org", "ip": "194.226.177.202", "ttl": 120}
            ]
        payload = [{"show": {"ip": {"dns": {"proxy": {"cache": {}}}}}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        entries = []
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    raw_cache = data[0].get("show", {}).get("ip", {}).get("dns", {}).get("proxy", {}).get("cache", [])
                    if isinstance(raw_cache, list):
                        for item in raw_cache:
                            name = item.get("name") or item.get("domain")
                            if name:
                                entries.append({
                                    "domain": name,
                                    "ip": item.get("address") or item.get("ip"),
                                    "ttl": item.get("ttl", 0)
                                })
            except Exception as e:
                logger.debug("Error parsing DNS cache: %s", e)

        # Fallback for KeeneticOS 4+/5+: extract configured names from show/dns-proxy
        if not entries:
            try:
                p_resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"dns-proxy": {}}}])
                if p_resp and p_resp.status_code == 200:
                    p_data = p_resp.json()
                    if isinstance(p_data, list) and p_data:
                        status_list = p_data[0].get("show", {}).get("dns-proxy", {}).get("proxy-status", [])
                        for st in status_list:
                            cfg = st.get("proxy-config", "")
                            for line in cfg.splitlines():
                                line = line.strip()
                                if line.startswith("static_a = ") or line.startswith("static_aaaa = "):
                                    parts = line.split()
                                    if len(parts) >= 4 and "." in parts[2]:
                                        domain_name = parts[2]
                                        ip_val = parts[3]
                                        # Skip sinkholes (0.0.0.0, 127.0.0.1, ::) and internal router aliases
                                        if ip_val in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                                            continue
                                        if domain_name.endswith(".keenetic.net") or domain_name.endswith(".netcraze.io") or "dnscheck.test" in domain_name:
                                            continue
                                        entries.append({"domain": domain_name, "ip": ip_val, "ttl": 3600})
                                elif "#" in line and "@" in line:
                                    # e.g. dns_server = 127.0.0.1:40500 . # 8.8.8.8@dns.google
                                    comment_part = line.split("#", 1)[1].strip()
                                    if "@" in comment_part:
                                        srv_host = comment_part.split("@", 1)[1].split()[0].strip()
                                        if "." in srv_host:
                                            entries.append({"domain": srv_host, "ip": None, "ttl": 3600})
            except Exception as e:
                logger.debug("Error in dns-proxy fallback: %s", e)

        return entries

    async def get_wifi_security(self) -> Dict[str, Any]:
        """Audits Wi-Fi configuration (WPA mode, WPS, Guest isolation) via Keenetic RCI."""
        if self.mock_mode:
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
                "guest_network": {"configured": True, "isolated": True},
                "recommendations": ["Все активные Wi-Fi сети защищены современным шифрованием WPA3/WPA2."]
            }

        resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"interface": {}}}])
        aps = []
        guest_isolated = False
        guest_configured = False
        recommendations = []
        score = 100

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    ifaces = data[0].get("show", {}).get("interface", {})
                    for if_name, if_data in ifaces.items():
                        if isinstance(if_data, dict) and ("AccessPoint" in if_name or if_data.get("type") == "AccessPoint"):
                            ssid = if_data.get("ssid")
                            # Keenetic allocates multiple virtual slots (AccessPoint0..6).
                            # Only slots with a configured SSID and active state represent real Wi-Fi networks.
                            if not ssid:
                                continue

                            is_active = (if_data.get("state") == "up" or if_data.get("link") == "up") and if_data.get("connected") != "no"
                            if not is_active:
                                continue

                            sec = str(if_data.get("security") or "").lower()
                            auth = str(if_data.get("authentication") or "").lower()
                            enc = str(if_data.get("encryption") or "").lower()
                            wps = bool(if_data.get("wps", False))
                            pmf = str(if_data.get("pmf") or "none").lower()
                            group = if_data.get("group", "")

                            band = "5 ГГц" if ("WifiMaster1" in if_name or "5ghz" in ssid.lower() or "5g" in ssid.lower()) else "2.4 ГГц"

                            if "wpa3" in enc and "wpa2" in enc:
                                mode_str = "WPA3 / WPA2 mixed"
                                sec_type = "wpa3_mixed"
                            elif "wpa3" in enc or "wpa3" in sec or "sae" in auth:
                                mode_str = "WPA3-SAE"
                                sec_type = "wpa3"
                            elif "wpa2" in enc or "wpa2" in sec:
                                mode_str = "WPA2-PSK"
                                sec_type = "wpa2"
                            elif "wpa" in enc or "wpa" in sec:
                                mode_str = "WPA (Устаревший)"
                                sec_type = "wpa"
                                score -= 30
                                recommendations.append(f"Сеть '{ssid}' ({band}) использует устаревший WPA. Переключите на WPA2/WPA3.")
                            elif enc in ("", "none", "open") and not sec:
                                mode_str = "Открытая (Без пароля)"
                                sec_type = "open"
                                score -= 50
                                recommendations.append(f"Внимание: сеть '{ssid}' ({band}) открыта без шифрования!")
                            else:
                                mode_str = enc.upper() if enc else "Защищенная"
                                sec_type = "custom"

                            if wps:
                                score -= 15
                                recommendations.append(f"WPS активен на сети '{ssid}'. Рекомендуется отключить WPS для защиты от атак перебора PIN.")

                            aps.append({
                                "interface": if_name,
                                "ssid": ssid,
                                "band": band,
                                "security": mode_str,
                                "security_type": sec_type,
                                "wps": wps,
                                "pmf": pmf,
                                "group": group
                            })

                            if ("guest" in if_name.lower() or "guest" in ssid.lower() or group == "Bridge1" or "smart" in ssid.lower()):
                                guest_configured = True
                                guest_isolated = True
            except Exception as e:
                logger.debug("Error parsing wifi security: %s", e)

        if aps and not any("WPA3" in a["security"] for a in aps):
            score -= 10
            recommendations.append("Рекомендуется включить комбинированный режим WPA2/WPA3 (SAE) для защиты от офлайн-подбора пароля.")

        if not guest_configured:
            recommendations.append("Настройте отдельный гостевой сегмент для изоляции ненадежных IoT-устройств.")

        if score >= 90:
            grade = "A+" if score == 100 else "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        else:
            grade = "F"

        return {
            "grade": grade,
            "score": max(0, score),
            "access_points": aps,
            "networks": aps,
            "guest_network": {"configured": guest_configured, "isolated": guest_isolated},
            "recommendations": recommendations or ["Все активные Wi-Fi сети защищены современным шифрованием WPA3/WPA2, уязвимый WPS отключен."]
        }

    async def check_firmware_updates(self) -> Dict[str, Any]:
        """Checks router firmware version and component update status."""
        current_v = self.last_version or "KeeneticOS 5.1.4"
        if self.mock_mode:
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

        payload = [{"show": {"version": {}}}, {"show": {"components": {"list": {}}}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        has_update = False
        avail_ver = current_v
        channel = "release"

        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    v_info = data[0].get("show", {}).get("version", {})
                    current_v = v_info.get("title", current_v)
                    channel = v_info.get("channel", "release")
                    if len(data) > 1:
                        c_info = data[1].get("show", {}).get("components", {}).get("list", {})
                        if c_info.get("update_available") or c_info.get("update"):
                            has_update = True
                            avail_ver = c_info.get("version", "Новая версия")
            except Exception as e:
                logger.debug("Error checking firmware updates: %s", e)

        msg = f"Доступно обновление до {avail_ver}." if has_update else "Установлена актуальная версия KeeneticOS."
        return {
            "status": "ok",
            "current_version": current_v,
            "latest_version": avail_ver if has_update else current_v,
            "available_version": avail_ver if has_update else current_v,
            "has_update": has_update,
            "update_available": has_update,
            "channel": channel,
            "message": msg
        }

    async def get_dns_proxy_status(self) -> Dict[str, Any]:
        """Queries Keenetic /rci/show/sc/dns-proxy for internet filter and DoH/DoT status."""
        if self.mock_mode:
            return {
                "filter_engine": "nextdns",
                "has_doh": True,
                "has_dot": True,
                "rebind_protect": True,
                "intercept": True
            }
        try:
            resp = await self._send_request("GET", "/rci/show/sc/dns-proxy")
            if resp and resp.status_code == 200:
                data = resp.json() or {}
                return {
                    "filter_engine": data.get("filter", {}).get("engine"),
                    "has_doh": bool(data.get("https", {}).get("upstream")),
                    "has_dot": bool(data.get("tls", {}).get("upstream")),
                    "rebind_protect": bool(data.get("rebind-protect", {}).get("auto")),
                    "intercept": bool(data.get("intercept", {}).get("enable")),
                    "raw": data
                }
        except Exception as e:
            logger.debug("Error fetching dns-proxy status: %s", e)
        return {"filter_engine": None, "has_doh": False, "has_dot": False, "rebind_protect": False, "intercept": False}

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        """
        Retrieves all configured L2/L3 network segments from Keenetic router,
        their IP subnets, interfaces, and station isolation status.
        """
        if self.mock_mode:
            return [
                {
                    "id": "Home",
                    "name": "Домашняя сеть",
                    "interface": "Bridge0",
                    "subnet": "192.168.1.0/24",
                    "router_ip": "192.168.1.1",
                    "is_isolated": False,
                    "description": "Основной домашний сегмент. L2-трафик между устройствами не фильтруется (общий свитч)."
                },
                {
                    "id": "Guest",
                    "name": "Гостевая сеть",
                    "interface": "Bridge1",
                    "subnet": "192.168.2.0/24",
                    "router_ip": "192.168.2.1",
                    "is_isolated": True,
                    "description": "Изолированный гостевой сегмент. Клиенты изолированы друг от друга и от домашней сети."
                }
            ]

        segments = []
        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"interface": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    ifaces = data[0].get("show", {}).get("interface", {})
                    for if_name, if_obj in ifaces.items():
                        if not isinstance(if_obj, dict):
                            continue
                        itype = if_obj.get("type")
                        if itype == "Bridge" or "Bridge" in if_name:
                            addr = if_obj.get("address", "")
                            mask = if_obj.get("mask", "255.255.255.0")
                            desc = if_obj.get("description") or if_name
                            isolate = bool(if_obj.get("isolate-stations", False))
                            seg_id = "Home" if if_name == "Bridge0" else ("Guest" if "guest" in desc.lower() or "guest" in if_name.lower() else if_name)
                            is_iso = isolate or seg_id == "Guest"
                            subnet_str = f"{addr}/24" if addr else ""
                            if addr and mask:
                                parts = addr.split(".")
                                if len(parts) == 4:
                                    subnet_str = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

                            segments.append({
                                "id": seg_id,
                                "name": desc if desc and not desc.startswith("") else ("Домашняя сеть" if seg_id == "Home" else "Гостевая сеть"),
                                "interface": if_name,
                                "subnet": subnet_str,
                                "router_ip": addr,
                                "is_isolated": is_iso,
                                "description": "Изолированный сегмент" if is_iso else "Основной домашний мост (L2 не изолирован)"
                            })
        except Exception as e:
            logger.debug("Error fetching network segments: %s", e)

        if not segments:
            segments = [
                {
                    "id": "Home",
                    "name": "Домашняя сеть",
                    "interface": "Bridge0",
                    "subnet": "192.168.1.0/24",
                    "router_ip": "192.168.1.1",
                    "is_isolated": False,
                    "description": "Основной домашний сегмент. L2-трафик между устройствами не фильтруется (общий свитч)."
                }
            ]
        return segments

    def evaluate_segment_risk(self, profile: str, segment: Optional[str], ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluates physical L2 segmentation risk for a device.
        Returns risk level, status title, and actionable advice.
        """
        clean_seg = (segment or "Home").strip()
        is_isolated = clean_seg == "Guest" or "guest" in clean_seg.lower() or (ip and not ip.startswith("192.168.1.") and ip != "0.0.0.0")

        if profile in ("camera", "iot"):
            if not is_isolated:
                return {
                    "risk_level": "high",
                    "status": "В зоне риска (L2-обход)",
                    "badge_color": "rose",
                    "is_isolated": False,
                    "recommendation": (
                        "Устройство находится в основном домашнем мосте 'Home' (192.168.1.0/24). "
                        "L2-трафик между клиентами идет в обход файрвола роутера. "
                        "Рекомендуется перенести устройство в 'Гостевой сегмент' или отдельный IoT VLAN в KeeneticOS."
                    )
                }
            else:
                return {
                    "risk_level": "low",
                    "status": "Изолировано физически",
                    "badge_color": "emerald",
                    "is_isolated": True,
                    "recommendation": "Устройство находится в изолированном сегменте. Прямой доступ к рабочему ПК заблокирован на уровне L2."
                }
        elif profile == "smart_tv":
            if not is_isolated:
                return {
                    "risk_level": "medium",
                    "status": "Домашняя сеть (L2 открыт)",
                    "badge_color": "amber",
                    "is_isolated": False,
                    "recommendation": (
                        "Телевизор находится в общем мосте с ПК. Это необходимо для AirPlay и DLNA без mDNS-релея, "
                        "но позволяет телевизору сканировать локальную сеть в режиме Standby."
                    )
                }
            else:
                return {
                    "risk_level": "low",
                    "status": "Изолировано в гостевой сети",
                    "badge_color": "emerald",
                    "is_isolated": True,
                    "recommendation": "Телевизор изолирован от домашних ПК. AirPlay/DLNA потребуют настройки проксирования."
                }
        elif profile in ("trusted", "smart_home_hub"):
            return {
                "risk_level": "low",
                "status": "Доверенный сегмент",
                "badge_color": "emerald",
                "is_isolated": is_isolated,
                "recommendation": "Устройство авторизовано в домашней сети."
            }
        else:
            return {
                "risk_level": "medium" if not is_isolated else "low",
                "status": "Не классифицировано" if not is_isolated else "Гостевая сеть",
                "badge_color": "slate",
                "is_isolated": is_isolated,
                "recommendation": "Назначьте профиль безопасности для оценки рисков."
            }

    async def add_dns_sinkholes(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch blocks domains on Keenetic by creating static DNS host entries resolving to 0.0.0.0.
        Returns a tuple of (succeeded_domains, failed_domains).
        """
        valid_domains = []
        for d in domains:
            clean_d = d.lower().strip().strip(".")
            if not clean_d or "." not in clean_d:
                continue
            # Never allow IP addresses in DNS sinkhole
            try:
                ipaddress.ip_address(clean_d)
                logger.warning("Rejecting IP address %s from DNS sinkhole (sinkhole requires domain names)", clean_d)
                continue
            except ValueError:
                pass
            # Never allow router management domains or local suffixes
            if clean_d in ("localhost", "my.keenetic.net", "keenetic.net", "router") or clean_d.endswith((".keenetic.link", ".keenetic.pro", ".local", ".lan", ".home")):
                logger.warning("Rejecting router/local domain %s from DNS sinkhole", clean_d)
                continue
            if clean_d not in valid_domains:
                valid_domains.append(clean_d)

        if not valid_domains:
            return [], []

        logger.info("Adding %d Keenetic DNS sinkhole(s) -> 0.0.0.0: %s", len(valid_domains), valid_domains[:5])
        if self.mock_mode:
            if not hasattr(self, "_mock_sinkholes"):
                self._mock_sinkholes = set()
            for d in valid_domains:
                self._mock_sinkholes.add(d)
            return valid_domains, []

        payload = [{"ip": {"host": {"domain": d, "address": "0.0.0.0"}}} for d in valid_domains]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, d in enumerate(valid_domains):
                        if idx < len(data):
                            item = data[idx]
                            host_res = item.get("ip", {}).get("host", {})
                            statuses = host_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    if s.get("status") == "error":
                                        has_error = True
                                        logger.warning("Keenetic RCI error adding sinkhole %s: %s", d, s.get("message"))
                                        break
                            if has_error:
                                failed.append(d)
                            else:
                                succeeded.append(d)
                        else:
                            succeeded.append(d)
                else:
                    succeeded = valid_domains
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI batch add response: %s", e)
                succeeded = valid_domains
        else:
            failed = valid_domains

        return succeeded, failed

    async def add_dns_sinkhole(self, domain: str) -> bool:
        """
        Blocks a single domain on Keenetic by creating a static DNS host entry resolving to 0.0.0.0.
        """
        clean_d = domain.lower().strip().strip(".")
        if not clean_d or "." not in clean_d:
            return False
        succeeded, _ = await self.add_dns_sinkholes([clean_d])
        return clean_d in succeeded

    async def remove_dns_sinkholes(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch removes static DNS sinkhole rules from Keenetic.
        Returns a tuple of (succeeded_domains, failed_domains).
        """
        valid_domains = []
        for d in domains:
            clean_d = d.lower().strip().strip(".")
            if clean_d and clean_d not in valid_domains:
                valid_domains.append(clean_d)

        if not valid_domains:
            return [], []

        logger.info("Removing %d Keenetic DNS sinkhole(s): %s", len(valid_domains), valid_domains[:5])
        if self.mock_mode:
            if hasattr(self, "_mock_sinkholes"):
                for d in valid_domains:
                    self._mock_sinkholes.discard(d)
            return valid_domains, []

        payload = [{"ip": {"host": {"domain": d, "address": "0.0.0.0", "no": True}}} for d in valid_domains]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, d in enumerate(valid_domains):
                        if idx < len(data):
                            item = data[idx]
                            host_res = item.get("ip", {}).get("host", {})
                            statuses = host_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    # code 22544392 is 'no such record', which still means the record is absent
                                    if s.get("status") == "error" and s.get("code") != "22544392":
                                        has_error = True
                                        logger.warning("Keenetic RCI error removing sinkhole %s: %s", d, s.get("message"))
                                        break
                            if has_error:
                                failed.append(d)
                            else:
                                succeeded.append(d)
                        else:
                            succeeded.append(d)
                else:
                    succeeded = valid_domains
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI batch remove response: %s", e)
                succeeded = valid_domains
        else:
            failed = valid_domains

        return succeeded, failed

    async def remove_dns_sinkhole(self, domain: str) -> bool:
        """
        Removes a previously configured static DNS sinkhole rule from Keenetic.
        """
        clean_d = domain.lower().strip().strip(".")
        if not clean_d:
            return False
        succeeded, _ = await self.remove_dns_sinkholes([clean_d])
        return clean_d in succeeded

    async def get_active_sinkholes(self) -> List[str]:
        """
        Fetches currently configured static 0.0.0.0 sinkhole domains from Keenetic.
        """
        if self.mock_mode:
            return sorted(list(getattr(self, "_mock_sinkholes", set())))

        sinkholes = set()
        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"running-config": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    lines = data[0].get("show", {}).get("running-config", {}).get("message", [])
                    for line in lines:
                        if line.startswith("ip host ") and (" 0.0.0.0" in line or " 127.0.0.1" in line):
                            parts = line.split()
                            if len(parts) >= 3:
                                sinkholes.add(parts[2].lower())
        except Exception as e:
            logger.debug("Error fetching active sinkholes from Keenetic: %s", e)
        return sorted(list(sinkholes))

    async def add_ip_blackholes(self, ips: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch blocks external IP addresses on Keenetic by creating static reject routes.
        Command equivalent in KeeneticOS: `ip route <IP> 255.255.255.255 reject`.
        Returns a tuple of (succeeded_ips, failed_ips).
        """
        valid_ips = []
        failed_ips = []
        for raw_ip in ips:
            clean_ip = raw_ip.strip()
            if not clean_ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                # Strict guardrails: allow only public IPv4 (no LAN, loopback, multicast, or reserved 240.0.0.0/4)
                if is_unsafe_ip_for_blackhole(ip_obj):
                    logger.warning("Rejecting invalid/private IP %s from IP blackhole", clean_ip)
                    failed_ips.append(clean_ip)
                    continue
                if clean_ip not in valid_ips:
                    valid_ips.append(clean_ip)
            except ValueError:
                logger.warning("Invalid IP string %s for blackhole", clean_ip)
                failed_ips.append(clean_ip)
                continue

        if not valid_ips:
            return [], failed_ips

        logger.info("Adding %d Keenetic IP blackhole(s) -> reject: %s", len(valid_ips), valid_ips[:5])
        if self.mock_mode:
            if not hasattr(self, "_mock_ip_blackholes"):
                self._mock_ip_blackholes = set()
            for ip_addr in valid_ips:
                self._mock_ip_blackholes.add(ip_addr)
            return valid_ips, failed_ips

        payload = [{"ip": {"route": {"address": ip_addr, "mask": "255.255.255.255", "reject": True}}} for ip_addr in valid_ips]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, ip_addr in enumerate(valid_ips):
                        if idx < len(data):
                            item = data[idx]
                            route_res = item.get("ip", {}).get("route", {})
                            statuses = route_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    if s.get("status") == "error":
                                        has_error = True
                                        logger.warning("Keenetic RCI error adding IP blackhole %s: %s", ip_addr, s.get("message"))
                                        break
                            if has_error:
                                failed.append(ip_addr)
                            else:
                                succeeded.append(ip_addr)
                        else:
                            succeeded.append(ip_addr)
                else:
                    succeeded = valid_ips
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI IP blackhole response: %s", e)
                succeeded = valid_ips
        else:
            failed = valid_ips

        return succeeded, failed

    async def remove_ip_blackholes(self, ips: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch removes static reject routes from Keenetic.
        Returns a tuple of (succeeded_ips, failed_ips).
        """
        valid_ips = []
        for raw_ip in ips:
            clean_ip = raw_ip.strip()
            if clean_ip and clean_ip not in valid_ips:
                valid_ips.append(clean_ip)

        if not valid_ips:
            return [], []

        logger.info("Removing %d Keenetic IP blackhole(s): %s", len(valid_ips), valid_ips[:5])
        if self.mock_mode:
            if hasattr(self, "_mock_ip_blackholes"):
                for ip_addr in valid_ips:
                    self._mock_ip_blackholes.discard(ip_addr)
            return valid_ips, []

        payload = [{"ip": {"route": {"address": ip_addr, "mask": "255.255.255.255", "reject": True, "no": True}}} for ip_addr in valid_ips]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            succeeded = valid_ips
        else:
            failed = valid_ips

        return succeeded, failed

    async def get_active_ip_blackholes(self) -> List[str]:
        """
        Fetches currently configured static reject IP routes from Keenetic running-config.
        """
        if self.mock_mode:
            return sorted(list(getattr(self, "_mock_ip_blackholes", set())))

        blackholes = set()
        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"running-config": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    lines = data[0].get("show", {}).get("running-config", {}).get("message", [])
                    for line in lines:
                        clean_line = line.strip()
                        if clean_line.startswith("ip route ") and "reject" in clean_line:
                            parts = clean_line.split()
                            if len(parts) >= 3:
                                target_ip = parts[2].split("/")[0]
                                try:
                                    ipaddress.ip_address(target_ip)
                                    blackholes.add(target_ip)
                                except ValueError:
                                    pass
        except Exception as e:
            logger.debug("Error fetching active IP blackholes from Keenetic: %s", e)
        return sorted(list(blackholes))

    async def is_packet_capture_supported(self) -> bool:
        """
        Checks whether the router firmware supports hardware packet capture via RCI.
        Caches the result to avoid redundant network round-trips.
        """
        if self.mock_mode:
            return True
        if self._capture_supported is not None:
            return self._capture_supported

        try:
            resp = await self._send_request("GET", "/rci/monitor/capture/interface")
            if resp is not None and resp.status_code in (200, 204):
                self._capture_supported = True
            elif resp is not None and resp.status_code in (400, 404, 501):
                self._capture_supported = False
            else:
                return False
        except Exception as e:
            logger.debug("Error checking packet capture support: %s", e)
            return False
        return bool(self._capture_supported)

    async def start_packet_capture(
        self,
        interface: str = "Bridge0",
        target_ip: Optional[str] = None,
        duration_seconds: int = 300,
        max_size_kb: int = 5120,
        buffer_size_kb: int = 512
    ) -> Optional[Dict[str, Any]]:
        """
        Configures and starts event-driven packet capture on Keenetic interface.
        BPF filter restricts capture strictly to target_ip if provided.
        """
        payload: Dict[str, Any] = {
            "name": interface,
            "enable": True,
            "capture-size": {"size-kb": max_size_kb},
            "buffer-size": {"size-kb": buffer_size_kb},
            "max-frame-size": {"size": 1518},
            "direction": "in-out",
            "timeout": {"timeout-ms": duration_seconds * 1000}
        }
        if target_ip:
            payload["filter"] = {"bpf-program": f"host {target_ip}"}

        logger.info(
            "Starting Keenetic hardware capture on %s (IP: %s, duration: %ds, max: %dKB)",
            interface, target_ip or "all", duration_seconds, max_size_kb
        )

        if self.mock_mode:
            self._mock_captures[interface] = {
                "payload": payload,
                "file_path": f"capture_{interface}.pcap",
                "target_ip": target_ip,
                "is_running": True
            }
            return {"status": "ok", "interface": interface, "filter": payload.get("filter")}

        resp = await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)
        if resp and resp.status_code in (200, 201, 204):
            return {"status": "ok", "interface": interface, "filter": payload.get("filter")}
        else:
            status = resp.status_code if resp else "no response"
            logger.warning("Keenetic hardware capture start failed on %s: HTTP %s", interface, status)
            return None

    async def stop_packet_capture(self, interface: str = "Bridge0") -> Optional[str]:
        """
        Stops packet capture on Keenetic interface and retrieves the relative capture file path.
        """
        logger.info("Stopping Keenetic hardware capture on %s", interface)
        if self.mock_mode:
            info = self._mock_captures.get(interface, {})
            info["is_running"] = False
            return info.get("file_path", f"capture_{interface}.pcap")

        # 1. Stop capture
        payload = {"name": interface, "enable": False}
        await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)

        # 2. Query status to discover generated pcap file path
        capture_file = None
        status_resp = await self._send_request("GET", "/rci/monitor/capture/interface")
        if status_resp and status_resp.status_code == 200:
            try:
                data = status_resp.json()
                items = data if isinstance(data, list) else [data]
                for item in items:
                    if isinstance(item, dict) and item.get("name") == interface:
                        capture_file = item.get("captureFilePath") or item.get("file") or item.get("path") or item.get("capture-file")
                        break
            except Exception as e:
                logger.debug("Error parsing capture status JSON: %s", e)

        if not capture_file:
            capture_file = f"capture_{interface}.pcap"

        return capture_file

    async def download_capture_file(self, capture_file_path: str, local_dest_path: Path) -> bool:
        """
        Downloads a captured .pcap file from Keenetic router via /ci/<path> and saves locally.
        """
        local_dest_path = Path(local_dest_path)
        local_dest_path.parent.mkdir(parents=True, exist_ok=True)

        if self.mock_mode:
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
            except Exception as e:
                logger.error("Mock pcap generation failed: %s", e)
                header = bytes([
                    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
                ])
                local_dest_path.write_bytes(header)
                return True

        if not self._cookies:
            auth = await self.authenticate()
            if auth.get("status") != "ok":
                return False

        clean_path = capture_file_path.strip().lstrip("/")
        url = f"/{clean_path}" if clean_path.startswith("ci/") else f"/ci/{clean_path}"

        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=30.0, verify=False) as client:
                resp = await client.get(url, cookies=self._cookies)
                if resp.status_code == 200 and len(resp.content) > 0:
                    local_dest_path.write_bytes(resp.content)
                    logger.info("Successfully downloaded router capture to %s (%d bytes)", local_dest_path, len(resp.content))
                    return True
                else:
                    logger.warning("Router capture download failed (HTTP %d, %d bytes)", resp.status_code, len(resp.content))
                    return False
        except Exception as e:
            logger.error("Failed to download capture file from %s: %s", url, e)
            return False

    async def reset_packet_capture(self, interface: str = "Bridge0") -> bool:
        """
        Resets packet capture state on Keenetic and frees allocated buffer memory on router.
        """
        logger.debug("Resetting Keenetic hardware capture on %s", interface)
        if self.mock_mode:
            self._mock_captures.pop(interface, None)
            return True

        payload = {"name": interface, "enable": False, "reset": True}
        resp = await self._send_request("POST", "/rci/monitor/capture/interface", json_data=payload)
        return resp is not None and resp.status_code in (200, 204)

    async def cleanup_orphan_captures(self) -> None:
        """
        Resets and cleans up any lingering capture sessions on common router interfaces.
        """
        for iface in ("Bridge0", "Bridge1", "ISP"):
            try:
                await self.reset_packet_capture(iface)
            except Exception as e:
                logger.debug("Failed resetting packet capture on %s: %s", iface, e)

keenetic_client = KeeneticClient()


def _on_router_config_change(key: str, value: Any) -> None:
    if key == "router_host" and value:
        keenetic_client.host = str(value)
        keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"
        keenetic_client.router_ips.add(str(value))
    elif key == "router_port" and value is not None:
        try:
            keenetic_client.port = int(value)
            keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"
        except (ValueError, TypeError):
            pass
    elif key == "router_user" and value:
        keenetic_client.user = str(value)
    elif key == "router_password":
        keenetic_client.password = str(value) if value else ""
    elif key == "router_use_https" and value is not None:
        keenetic_client.use_https = bool(value)
        keenetic_client.schema = "https" if bool(value) else "http"
        keenetic_client.base_url = f"{keenetic_client.schema}://{keenetic_client.host}:{keenetic_client.port}"


try:
    from keenguard.core.config_service import config_service
    for _k in ("router_host", "router_port", "router_user", "router_password", "router_use_https"):
        config_service.subscribe(_k, _on_router_config_change)
except ImportError:
    pass



