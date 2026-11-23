"""Network Topology Map API route.
Aggregates router interfaces, segments, hotspot hosts, and database records
into an interactive graph (nodes and links) reflecting real L2/L3 hardware architecture.
"""
from typing import Dict, Any, List, Optional
import logging

from fastapi import APIRouter

from keenguard.core.keenetic import is_host_lan_isolated
from keenguard.core.routers import router_manager
from keenguard.core.dns_providers import dns_security_manager
from keenguard.web.state import (
    get_db,
    get_router_health,
)

logger = logging.getLogger("keenguard.web.routes.topology")

router = APIRouter(tags=["topology"])


@router.get("/api/network/topology", response_model=Dict[str, Any])
async def get_network_topology() -> Dict[str, Any]:
    """
    Returns nodes and links representing the physical and logical network topology:
    Internet WAN -> Router -> Segments (Bridge0/Bridge1/br-lan) -> Interfaces (Wi-Fi 2.4/5GHz, LAN) -> Devices.
    """
    db = get_db()
    router_health = get_router_health()

    # 1. Fetch DB devices
    db_devices_map: Dict[str, Any] = {}
    try:
        devices = await db.get_all_devices()
        for d in devices:
            db_devices_map[d.mac.upper()] = d
    except Exception as e:
        logger.warning("Error fetching devices from DB for topology: %s", e)

    # 2. Fetch live Router data via router_manager
    hotspot_hosts_map: Dict[str, Any] = {}
    router_info: Dict[str, Any] = {}
    wan_ip = ""
    segments: List[Dict[str, Any]] = []

    try:
        hosts = await router_manager.get_hosts()
        for h in hosts:
            hotspot_hosts_map[h.mac.upper()] = h
    except Exception as e:
        logger.debug("Error fetching hosts from router_manager: %s", e)

    try:
        sys_info = await router_manager.get_system_info()
        router_info = {
            "model": sys_info.model or router_manager.platform_name,
            "version": sys_info.firmware_version or ("OpenWrt" if router_manager.platform_id == "openwrt" else "KeeneticOS"),
        }
    except Exception as e:
        logger.debug("Error fetching router info: %s", e)

    try:
        wan_ip = (await router_manager.get_wan_ip()) or getattr(router_health, "wan_ip", "") or ""
    except Exception as e:
        logger.debug("Error fetching WAN IP: %s", e)

    try:
        segments = await router_manager.get_network_segments()
    except Exception as e:
        logger.debug("Error fetching segments: %s", e)

    if not segments:
        if router_manager.platform_id == "openwrt":
            segments = [
                {"id": "Home", "name": "LAN", "interface": "br-lan", "subnet": "192.168.1.0/24", "security_level": "trusted"}
            ]
        else:
            segments = [
                {"id": "Home", "name": "Домашняя сеть", "interface": "Bridge0", "subnet": "192.168.1.0/24", "security_level": "trusted"},
                {"id": "Guest", "name": "Гостевой сегмент", "interface": "Bridge1", "subnet": "10.1.30.0/24", "security_level": "isolated"},
            ]

    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []

    # 3. Add Infrastructure Nodes
    # WAN / Internet Node (do not hardcode True: check actual connection state and WAN IP)
    is_wan_online = bool(router_health.is_connected and (wan_ip or getattr(router_health, "wan_online", False)))
    nodes.append({
        "id": "node_internet",
        "label": "Интернет (WAN)",
        "type": "wan",
        "icon": "globe",
        "status": "online" if is_wan_online else "offline",
        "details": {
            "uptime": getattr(router_health, "uptime", 0),
            "ip": wan_ip,
            "gateway": getattr(router_health, "gateway", ""),
        }
    })

    # Secure DNS / Sinkhole Node (dynamically check actual sinkhole status)
    sinkhole_active = False
    try:
        active_sinkholes = await router_manager.get_active_sinkholes()
        sinkhole_active = bool(len(active_sinkholes) > 0 or (dns_security_manager.active_provider_id and dns_security_manager.active_provider_id != "none"))
    except Exception:
        sinkhole_active = bool(dns_security_manager.active_provider_id and dns_security_manager.active_provider_id != "none")

    nodes.append({
        "id": "node_dns",
        "label": "Безопасный DNS",
        "type": "dns",
        "icon": "shield-check",
        "status": "online" if sinkhole_active else "idle",
        "details": {
            "type": f"{dns_security_manager.active_provider_id.capitalize() if dns_security_manager.active_provider_id != 'none' else router_manager.platform_name} DNS",
            "sinkhole_active": sinkhole_active
        }
    })

    # Central Router Node
    router_model = router_info.get("model") or router_manager.platform_name
    router_ver = router_info.get("version") or ("OpenWrt" if router_manager.platform_id == "openwrt" else "KeeneticOS")
    lan_ip = getattr(router_manager.get_backend(), "host", "192.168.1.1")
    nodes.append({
        "id": "node_router",
        "label": f"{router_model}",
        "type": "router",
        "icon": "router",
        "status": "online" if router_health.is_connected else "offline",
        "details": {
            "model": router_model,
            "version": router_ver,
            "wan_ip": wan_ip,
            "lan_ip": lan_ip,
        }
    })

    links.append({"source": "node_internet", "target": "node_router", "type": "wan", "status": "active" if is_wan_online else "inactive"})
    links.append({"source": "node_dns", "target": "node_router", "type": "dns", "status": "active" if sinkhole_active else "inactive"})

    # 4. Add Segments (Bridges)
    main_iface = segments[0].get("interface", "Bridge0") if segments else "Bridge0"
    main_seg_id = f"segment_{main_iface}"

    guest_seg = next((s for s in segments if "guest" in s.get("id", "").lower() or s.get("security_level") == "isolated" or "bridge1" in s.get("interface", "").lower()), None)
    guest_seg_id = f"segment_{guest_seg.get('interface', 'Bridge1')}" if guest_seg else main_seg_id

    for seg in segments:
        iface = seg.get("interface", main_iface)
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
            "segment_id": main_seg_id,
            "details": {"band": "2.4 GHz", "standard": "802.11b/g/n/ax"}
        },
        {
            "id": "ap_wifi_5",
            "label": "Wi-Fi 5 GHz",
            "type": "access_point",
            "icon": "wifi",
            "segment_id": main_seg_id,
            "details": {"band": "5 GHz", "standard": "802.11a/n/ac/ax"}
        },
        {
            "id": "ap_lan",
            "label": "Ethernet LAN",
            "type": "access_point",
            "icon": "server",
            "segment_id": main_seg_id,
            "details": {"ports": "1-4 (1 Gbps)", "media": "Twisted Pair"}
        },
        {
            "id": "ap_guest",
            "label": "Гостевой Wi-Fi",
            "type": "access_point",
            "icon": "wifi",
            "segment_id": guest_seg_id,
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
        # AGENTS.md Rule 1: We strictly do NOT move devices to Bridge1 just because profile == "quarantine".
        # Quarantine WAN block in database is NOT physical L2 isolation.
        is_isolated = is_host_lan_isolated(hs_iface, ip) or "bridge1" in hs_iface or "guest" in hs_iface or "guest" in db_segment or is_isolated_lan
        if is_isolated and guest_seg:
            segment_id = guest_seg_id
            parent_ap = "ap_guest"
        else:
            segment_id = main_seg_id
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
                "Устройства в основном сегменте (Bridge0) находятся в общем L2-домене "
                "(трафик между ними коммутируется аппаратно без участия межсетевого экрана роутера). "
                "Изолированные сегменты (Bridge1 / Guest) аппаратно отделены на уровне роутера."
            )
        }
    }
