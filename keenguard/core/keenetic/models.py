"""Data models and helper functions for Keenetic integration."""
import ipaddress
from typing import Optional, Any
from pydantic import BaseModel


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


def is_unsafe_ip_for_blackhole(ip_obj: Any) -> bool:
    """
    Checks if an IP address is unsafe to blackhole on Keenetic or OpenWrt router.
    Prevents blackholing RFC 1918 LAN, gateway, loopback, multicast, link-local, or reserved addresses.
    Permits RFC 5737 (IPv4) and RFC 3849 (IPv6) documentation ranges for safe testing:
    - 198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24
    - 2001:db8::/32
    """
    version = getattr(ip_obj, "version", 0)
    if version == 4:
        if (ip_obj in ipaddress.ip_network("198.51.100.0/24") or
            ip_obj in ipaddress.ip_network("203.0.113.0/24") or
            ip_obj in ipaddress.ip_network("192.0.2.0/24")):
            return False
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
            ip_obj.is_multicast or ip_obj.is_unspecified or int(ip_obj) >= 0xF0000000):
            return True
        return False
    elif version == 6:
        if ip_obj in ipaddress.ip_network("2001:db8::/32"):
            return False
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved):
            return True
        return False
    return True


def _has_rci_error(obj: Any) -> bool:
    """Recursively checks if any dictionary or list element contains error indicators."""
    if isinstance(obj, dict):
        status_val = obj.get("status")
        if status_val in ("error", "fail", "failure"):
            return True
        if "error" in obj and obj["error"]:
            return True
        for val in obj.values():
            if _has_rci_error(val):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _has_rci_error(item):
                return True
    return False


def is_rci_success(response: Any) -> bool:
    """
    Checks whether a Keenetic RCI response represents a successful execution.
    Keenetic RCI returns HTTP 200 even when commands fail, returning JSON
    arrays containing {"status": "error", "message": ...}.
    """
    if response is None:
        return False

    if hasattr(response, "status_code"):
        if response.status_code not in (200, 201, 204):
            return False
        try:
            data = response.json()
        except Exception:
            return True
    else:
        data = response

    return not _has_rci_error(data)


class UPnPMapping(BaseModel):
    interface: Optional[Any] = None
    protocol: str = "tcp"
    ext_port: int
    int_ip: str
    int_port: int
    description: Optional[str] = None
