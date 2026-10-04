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
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as e:
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
        except (OSError, json.JSONDecodeError, ValueError, KeyError) as e:
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
    except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
        logger.debug("Online GeoIP lookup error for %s: %s", ip, e)

    return identify_geoip(ip)


def identify_provider(dst_ip: str) -> str:
    geo = identify_geoip(dst_ip)
    return f"{geo['flag']} {geo['provider']}"


def is_streaming_service(dport: int, proto: str = "TCP") -> tuple[bool, Optional[str]]:
    """
    Identifies legitimate local media streaming protocols:
    - Virtual Desktop: TCP/UDP 38810..38840
    - Steam In-Home / Steam Link: UDP 27031, 27036; TCP 27036, 27037
    - Moonlight / Sunshine: TCP 47984, 47989, 48010; UDP 47998..48002
    - Oculus Air Link: UDP 5669; UDP 50000..50020
    - Google Cast / DIAL: TCP 8008, 8009
    - Apple AirPlay: TCP 7000, 7100; UDP 6000..6002, 7010, 7011
    - DLNA / UPnP Media: TCP 8200, 2869
    Returns (is_streaming, service_name).
    """
    p = proto.upper() if proto else "TCP"
    try:
        dport_num = int(dport)
    except (ValueError, TypeError):
        return False, None

    # Virtual Desktop (VR streaming)
    if 38810 <= dport_num <= 38840:
        if dport_num == 38810:
            return True, "Virtual Desktop Streamer (Control)"
        elif dport_num == 38820:
            return True, "Virtual Desktop Video Stream"
        elif dport_num == 38830:
            return True, "Virtual Desktop Audio/Mic Stream"
        return True, "Virtual Desktop Stream"

    # Steam In-Home Streaming / Steam Link
    if dport_num in (27031, 27036, 27037):
        if dport_num == 27031:
            return True, "Steam In-Home Streaming (Discovery)"
        elif dport_num == 27036:
            return True, "Steam In-Home Streaming (Control/Video)"
        elif dport_num == 27037:
            return True, "Steam In-Home Streaming (Data)"

    # Moonlight / Sunshine / NVIDIA GameStream
    if dport_num in (47984, 47989, 48010) or (47998 <= dport_num <= 48002):
        if dport_num == 47984:
            return True, "Moonlight/Sunshine (HTTPS Control)"
        elif dport_num == 47989:
            return True, "Moonlight/Sunshine (HTTP Pairing)"
        elif dport_num == 48010:
            return True, "Moonlight/Sunshine (RTSP Control)"
        elif dport_num == 47998:
            return True, "Moonlight/Sunshine (Video UDP)"
        elif dport_num == 47999:
            return True, "Moonlight/Sunshine (Control UDP)"
        elif dport_num == 48000:
            return True, "Moonlight/Sunshine (Audio UDP)"
        elif dport_num == 48002:
            return True, "Moonlight/Sunshine (Mic UDP)"
        return True, "Moonlight/Sunshine Streaming"

    # Oculus Air Link
    if dport_num == 5669 and p == "UDP":
        return True, "Oculus Air Link (Discovery)"
    if 50000 <= dport_num <= 50020 and p == "UDP":
        return True, "Oculus Air Link (Media Stream)"

    # Google Cast / DIAL
    if dport_num in (8008, 8009):
        if dport_num == 8008:
            return True, "Google Cast (HTTP/DIAL)"
        return True, "Google Cast (V2 TLS)"

    # Apple AirPlay 2
    if dport_num in (7000, 7100):
        if dport_num == 7000:
            return True, "AirPlay (Screen Mirroring)"
        return True, "AirPlay (Media Streaming)"
    if 6000 <= dport_num <= 6002 and p == "UDP":
        return True, "AirPlay (Audio RTP)"
    if dport_num in (7010, 7011) and p == "UDP":
        return True, "AirPlay (Screen RTP)"

    # DLNA / UPnP AV
    if dport_num in (8200, 2869):
        if dport_num == 8200:
            return True, "MiniDLNA / Keenetic Media Server"
        return True, "SSDP Event Notification / DLNA"

    return False, None

