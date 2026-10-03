"""GeoIP identification, CIDR provider matching, and port service catalog."""
import ipaddress
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
import httpx

logger = logging.getLogger("keenguard.audit.geoip")

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def load_known_services() -> Dict[int, Dict[str, Any]]:
    """Loads well-known network service port descriptions from static JSON catalog."""
    json_path = _DATA_DIR / "known_services.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return {int(port): info for port, info in raw.items()}
        except Exception as e:
            logger.warning("Failed to load known services catalog from %s: %s", json_path, e)
    return {}


KNOWN_SERVICES: Dict[int, Dict[str, Any]] = load_known_services()


def load_cidr_providers() -> List[Any]:
    """Loads cloud provider and CDN CIDR ranges from static JSON catalog."""
    json_path = _DATA_DIR / "cidr_providers.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            return [
                (ipaddress.ip_network(item["cidr"]), item["name"], item["country"], item["flag"])
                for item in raw
            ]
        except Exception as e:
            logger.warning("Failed to load CIDR providers catalog from %s: %s", json_path, e)
    return []


CIDR_PROVIDERS = load_cidr_providers()

# For backwards compatibility with any component iterating KNOWN_PROVIDERS
KNOWN_PROVIDERS = [
    (str(net), name, country, flag) for net, name, country, flag in CIDR_PROVIDERS
]

_GEOIP_CACHE: Dict[str, Dict[str, str]] = {}


def is_lan_ip(ip_str: str) -> bool:
    """Checks if an IP address belongs to private RFC 1918, loopback, or link-local ranges."""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return ip_str.startswith(("192.168.", "10.", "172.16.", "127."))


def identify_geoip(dst_ip: str) -> Dict[str, str]:
    if not dst_ip:
        return {"provider": "Неизвестный узел", "country": "WAN", "flag": "🌐"}

    if dst_ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[dst_ip]

    try:
        ip_obj = ipaddress.ip_address(dst_ip)
    except ValueError:
        return {"provider": "Неизвестный узел", "country": "WAN", "flag": "🌐"}

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        if dst_ip == "192.168.1.1":
            res = {"provider": "Шлюз Keenetic (DNS/Router)", "country": "LAN", "flag": "🏠"}
        else:
            res = {"provider": "Локальная сеть (LAN Хост)", "country": "LAN", "flag": "🏠"}
        _GEOIP_CACHE[dst_ip] = res
        return res

    if ip_obj.is_multicast:
        res = {"provider": "Multicast / Локальное вещание", "country": "LAN", "flag": "📡"}
        _GEOIP_CACHE[dst_ip] = res
        return res

    for net, name, country, flag in sorted(CIDR_PROVIDERS, key=lambda x: x[0].prefixlen, reverse=True):
        if ip_obj in net:
            res = {"provider": name, "country": country, "flag": flag}
            _GEOIP_CACHE[dst_ip] = res
            return res

    res = {"provider": "Внешний интернет-хост", "country": "WAN", "flag": "🌐"}
    _GEOIP_CACHE[dst_ip] = res
    return res


async def lookup_geoip_online(ip: str) -> Dict[str, str]:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    cc = data.get("countryCode", "WAN")
                    flag = "".join(chr(ord(c) + 127397) for c in cc.upper()) if len(cc) == 2 else "🌐"
                    org = data.get("org") or data.get("as") or "Внешний провайдер"
                    res = {"provider": org, "country": cc, "flag": flag}
                    _GEOIP_CACHE[ip] = res
                    return res
    except Exception as e:
        logger.debug("Online GeoIP lookup error for %s: %s", ip, e)

    return identify_geoip(ip)


def identify_provider(dst_ip: str) -> str:
    geo = identify_geoip(dst_ip)
    return f"{geo['flag']} {geo['provider']}"
