"""Network Topology Map API route.
Aggregates Keenetic RCI interfaces, segments, hotspot hosts, and database records
into an interactive graph (nodes and links) reflecting real L2/L3 hardware architecture.
"""
from typing import Dict, Any, List, Optional
import logging

from fastapi import APIRouter

from keenguard.core.keenetic import is_host_lan_isolated
from keenguard.web.state import (
    get_db,
    get_keenetic_client,
)

logger = logging.getLogger("keenguard.web.routes.topology")

router = APIRouter(tags=["topology"])


@router.get("/api/network/topology", response_model=Dict[str, Any])
async def get_network_topology() -> Dict[str, Any]:
    """
    Returns nodes and links representing the physical and logical network topology:
    Internet WAN -> Router -> Segments (Bridge0/Bridge1) -> Interfaces (Wi-Fi 2.4/5GHz, LAN) -> Devices.
    """
    client = get_keenetic_client()
    db = get_db()

    # 1. Fetch DB devices
    db_devices_map: Dict[str, Any] = {}
    try:
        devices = await db.get_all_devices()
        for d in devices:
            db_devices_map[d.mac.upper()] = d
    except Exception as e:
        logger.warning("Error fetching devices from DB for topology: %s", e)

    # 2. Fetch live Keenetic data
    hotspot_hosts_map: Dict[str, Any] = {}
    router_info: Dict[str, Any] = {}
    wan_status: Dict[str, Any] = {}
    segments: List[Dict[str, Any]] = []

    try:
        hosts = await client.get_hotspot_hosts()
        for h in hosts:
            hotspot_hosts_map[h.mac.upper()] = h
    except Exception as e:
        logger.debug("Error fetching hotspot hosts from Keenetic: %s", e)

    try:
        router_info = await client.get_device_info()
    except Exception as e:
        logger.debug("Error fetching router info: %s", e)

    try:
        wan_status = await client.get_wan_status()
    except Exception as e:
        logger.debug("Error fetching WAN status: %s", e)

    try:
        segments = await client.get_segments()
    except Exception as e:
        logger.debug("Error fetching segments: %s", e)

    if not segments:
        segments = [
            {"id": "Home", "name": "Домашняя сеть", "interface": "Bridge0", "subnet": "192.168.1.0/24", "security_level": "trusted"},
            {"id": "Guest", "name": "Гостевой сегмент", "interface": "Bridge1", "subnet": "10.1.30.0/24", "security_level": "isolated"},
        ]

    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []

    # 3. Add Infrastructure Nodes
    # WAN / Internet Node
    is_wan_online = bool(wan_status.get("online", True))
    nodes.append({
        "id": "node_internet",
        "label": "Интернет (WAN)",
        "type": "wan",
        "icon": "globe",
        "status": "online" if is_wan_online else "offline",
        "details": {
            "uptime": wan_status.get("uptime", 0),
            "ip": wan_status.get("ip", ""),
            "gateway": wan_status.get("gateway", ""),
        }
    })

    # Secure DNS / Sinkhole Node
    nodes.append({
        "id": "node_dns",
        "label": "Безопасный DNS",
        "type": "dns",
        "icon": "shield-check",
        "status": "online",
        "details": {
            "type": "NextDNS / Keenetic DNS-proxy",
            "sinkhole_active": True
        }
    })

    # Central Router Node
    router_model = router_info.get("model") or router_info.get("device") or "Keenetic Router"
    router_ver = router_info.get("version") or router_info.get("firmware") or "KeeneticOS"
    nodes.append({
        "id": "node_router",
        "label": f"{router_model}",
        "type": "router",
        "icon": "router",
        "status": "online",
        "details": {
            "model": router_model,
            "version": router_ver,
            "wan_ip": wan_status.get("ip", ""),
            "lan_ip": "192.168.1.1",
        }
    })

    links.append({"source": "node_internet", "target": "node_router", "type": "wan", "status": "active" if is_wan_online else "inactive"})
    links.append({"source": "node_dns", "target": "node_router", "type": "dns", "status": "active"})

    # 4. Add Segments (Bridges)
    for seg in segments:
        iface = seg.get("interface", "Bridge0")
        seg_id = f"segment_{iface}"
        nodes.append({
            "id": seg_id,
            "label": seg.get("name", iface),
            "type": "segment",
            "icon": "network",
            "status": "online",
            "details": {
                "interface": iface,
                "subnet": seg.get("subnet", ""),
                "security_level": seg.get("security_level", "trusted"),
            }
        })
        links.append({"source": "node_router", "target": seg_id, "type": "trunk", "status": "active"})

    # 5. Add Physical & Wireless Interfaces
    interface_nodes = [
        {
            "id": "ap_wifi_24",
            "label": "Wi-Fi 2.4 GHz",
            "type": "access_point",
            "icon": "wifi",
            "segment_id": "segment_Bridge0",
            "details": {"band": "2.4 GHz", "standard": "802.11b/g/n/ax"}
        },
        {
            "id": "ap_wifi_5",
            "label": "Wi-Fi 5 GHz",
            "type": "access_point",
            "icon": "wifi",
            "segment_id": "segment_Bridge0",
            "details": {"band": "5 GHz", "standard": "802.11a/n/ac/ax"}
        },
        {
            "id": "ap_lan",
            "label": "Ethernet LAN",
            "type": "access_point",
            "icon": "server",
            "segment_id": "segment_Bridge0",
            "details": {"ports": "1-4 (1 Gbps)", "media": "Twisted Pair"}
        },
        {
            "id": "ap_guest",
            "label": "Гостевой Wi-Fi",
            "type": "access_point",
            "icon": "wifi",
            "segment_id": "segment_Bridge1",
            "details": {"isolation": "L2 Isolated", "band": "2.4 GHz / 5 GHz"}
        },
    ]

    for iface_node in interface_nodes:
        nodes.append(iface_node)
        links.append({
            "source": iface_node["segment_id"],
            "target": iface_node["id"],
            "type": "uplink",
            "status": "active"
        })

    # 6. Add Devices (Combining Database & Live Hotspot)
    all_macs = set(db_devices_map.keys()) | set(hotspot_hosts_map.keys())
    device_nodes: List[Dict[str, Any]] = []

    for mac in all_macs:
        db_dev = db_devices_map.get(mac)
        hs = hotspot_hosts_map.get(mac)

        name = (db_dev.custom_name if db_dev and db_dev.custom_name else None) or \
               (db_dev.hostname if db_dev and db_dev.hostname else None) or \
               (hs.hostname if hs and hs.hostname else None) or \
               (hs.name if hs and hs.name else None) or \
               mac

        ip = (hs.ip if hs and hs.ip else None) or (db_dev.ip if db_dev else "") or "0.0.0.0"
        vendor = (db_dev.vendor if db_dev and db_dev.vendor else None) or "Unknown Vendor"
        profile = (db_dev.profile if db_dev and db_dev.profile else None) or "unassigned"
        is_online = bool(hs.link == "up" and hs.active) if hs else (db_dev.is_online if db_dev else False)
        is_wan_blocked = bool(db_dev.is_blocked_wan if db_dev else False)
        is_isolated_lan = bool(db_dev.is_isolated_lan if db_dev else False)
        rssi = hs.rssi if hs and hasattr(hs, "rssi") else None
        speed = hs.speed if hs and hasattr(hs, "speed") else (db_dev.bandwidth_limit_kbps if db_dev else None)
        hs_iface = str(hs.interface if hs and hasattr(hs, "interface") else "").lower()
        db_segment = (db_dev.segment if db_dev and db_dev.segment else "Home").lower()

        # Determine segment and parent AP
        is_isolated = is_host_lan_isolated(hs_iface, ip) or "bridge1" in hs_iface or "guest" in hs_iface or "guest" in db_segment or is_isolated_lan or profile == "quarantine"
        if is_isolated:
            segment_id = "segment_Bridge1"
            parent_ap = "ap_guest"
        else:
            segment_id = "segment_Bridge0"
            if "wifimaster1" in hs_iface or "5g" in hs_iface:
                parent_ap = "ap_wifi_5"
            elif any(k in hs_iface for k in ["fastethernet", "gigabitethernet", "eth", "lan", "port"]):
                parent_ap = "ap_lan"
            else:
                # Default to 2.4 GHz Wi-Fi or LAN based on profile
                parent_ap = "ap_lan" if profile in ("camera", "smart_home_hub") and not rssi else "ap_wifi_24"

        # Determine node icon
        icon = "laptop"
        if profile == "smart_tv":
            icon = "tv"
        elif profile == "camera":
            icon = "camera"
        elif profile in ("iot", "smart_home_hub"):
            icon = "cpu"
        elif profile == "quarantine":
            icon = "shield-alert"
        elif profile == "trusted":
            icon = "shield-check"

        dev_node_id = f"dev_{mac.replace(':', '').lower()}"
        dev_node = {
            "id": dev_node_id,
            "mac": mac,
            "ip": ip,
            "label": name,
            "hostname": (db_dev.hostname if db_dev else None) or (hs.hostname if hs else None) or name,
            "vendor": vendor,
            "profile": profile,
            "type": "device",
            "icon": icon,
            "is_online": is_online,
            "is_wan_blocked": is_wan_blocked,
            "is_isolated_lan": is_isolated_lan,
            "segment_id": segment_id,
            "parent_ap": parent_ap,
            "details": {
                "rssi": rssi,
                "speed": speed,
                "bandwidth_limit_kbps": db_dev.bandwidth_limit_kbps if db_dev else None,
                "custom_allowed_ports": db_dev.custom_allowed_ports if db_dev else None,
                "designated_nvr_ip": db_dev.designated_nvr_ip if db_dev else None,
            }
        }
        nodes.append(dev_node)
        device_nodes.append(dev_node)

        links.append({
            "source": parent_ap,
            "target": dev_node_id,
            "type": "client",
            "is_online": is_online,
            "is_wan_blocked": is_wan_blocked,
            "rssi": rssi
        })

    return {
        "nodes": nodes,
        "links": links,
        "meta": {
            "total_devices": len(device_nodes),
            "online_devices": sum(1 for d in device_nodes if d["is_online"]),
            "wan_status": "online" if is_wan_online else "offline",
            "l2_realism_note": (
                "Устройства в сегменте Bridge0 находятся в общем L2-домене "
                "(трафик между ними коммутируется аппаратно без участия межсетевого экрана роутера). "
                "Сегмент Bridge1 аппаратно изолирован от Bridge0 на уровне сетевого моста Keenetic."
            )
        }
    }
