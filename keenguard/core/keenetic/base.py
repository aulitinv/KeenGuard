"""Base Keenetic RCI HTTP client with NDM Challenge-Response authentication."""
import asyncio
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set
import httpx

from keenguard.config import settings

logger = logging.getLogger("keenguard.keenetic.base")


class KeeneticBaseClient:
    """Core RCI HTTP transport, authentication and connection management."""

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

                    md5_str = hashlib.md5(f"{target_user}:{realm}:{target_pass}".encode("utf-8")).hexdigest()
                    sha_str = hashlib.sha256(f"{challenge}{md5_str}".encode("utf-8")).hexdigest()

                    session_cookies = dict(r1.cookies)
                    r2 = await client.post(
                        "/auth",
                        json={"login": target_user, "password": sha_str},
                        cookies=session_cookies
                    )

                    if r2.status_code == 200:
                        merged_cookies = dict(session_cookies)
                        merged_cookies.update(dict(r2.cookies))
                        self._cookies = merged_cookies
                        self.host = target_host
                        self.user = target_user
                        self.password = target_pass
                        self.base_url = base_url

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
                        await self.authenticate()
                        continue
                    return resp
            except Exception as e:
                logger.error("Keenetic request error (%s %s): %s", method, path, e)
                return None
        return None
