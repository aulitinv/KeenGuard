"""Tests for LAN preset rules enforcement and sniffer transparency."""
import pytest
from keenguard.core.lan_tracker import LanTrafficTracker
from keenguard.core.sniffer import NetworkSniffer
from keenguard.core.enums import Severity, EventType


def test_sniffer_transparency_status():
    """Verify technical realism in sniffer status (L2 limitations disclosed)."""
    sniffer = NetworkSniffer()
    status = sniffer.get_status()
    assert status["cross_client_l2_visibility"] is False
    assert status["capture_mode"] == "local_promiscuous"
    assert "зеркалирование" in status["recommended_action"] or "Conntrack" in status["recommended_action"]


def test_camera_preset_enforcement_and_nvr_exception():
    """Camera with isolated policy must permit NVR but alert on unallowed LAN destinations."""
    tracker = LanTrafficTracker()

    cam_mac = "AA:BB:CC:DD:EE:01"
    cam_ip = "192.168.1.50"
    nvr_ip = "192.168.1.200"
    other_ip = "192.168.1.88"
    router_ip = "192.168.1.1"

    devices_map = {
        cam_mac: {
            "mac": cam_mac,
            "ip": cam_ip,
            "hostname": "Yard-Camera",
            "profile": "camera",
            "preset_id": "preset_camera",
            "designated_nvr_ip": nvr_ip
        },
        "AA:BB:CC:DD:EE:02": {
            "mac": "AA:BB:CC:DD:EE:02",
            "ip": nvr_ip,
            "hostname": "Home-NVR"
        },
        "AA:BB:CC:DD:EE:03": {
            "mac": "AA:BB:CC:DD:EE:03",
            "ip": other_ip,
            "hostname": "Workstation"
        }
    }

    # 1. Allowed RTSP video stream to designated NVR
    violation = tracker.check_lan_policy_violation(
        src_mac=cam_mac,
        src_ip=cam_ip,
        dst_ip=nvr_ip,
        port=554,
        protocol="RTSP",
        devices_map=devices_map
    )
    assert violation is None

    # 2. Blocked service (Telnet port 23) from camera
    violation_telnet = tracker.check_lan_policy_violation(
        src_mac=cam_mac,
        src_ip=cam_ip,
        dst_ip=router_ip,
        port=23,
        protocol="TCP",
        devices_map=devices_map
    )
    assert violation_telnet is not None
    assert violation_telnet["violation_type"] == "blocked_service"
    assert violation_telnet["severity"] == Severity.CRITICAL.value

    # 3. Alert service (SSH port 22) from camera
    violation_ssh = tracker.check_lan_policy_violation(
        src_mac=cam_mac,
        src_ip=cam_ip,
        dst_ip=router_ip,
        port=22,
        protocol="TCP",
        devices_map=devices_map
    )
    assert violation_ssh is not None
    assert violation_ssh["violation_type"] == "alert_service"
    assert violation_ssh["severity"] == Severity.WARNING.value

    # 4. LAN isolation breach: camera trying to reach another workstation in LAN
    violation_breach = tracker.check_lan_policy_violation(
        src_mac=cam_mac,
        src_ip=cam_ip,
        dst_ip=other_ip,
        port=80,
        protocol="HTTP",
        devices_map=devices_map
    )
    assert violation_breach is not None
    assert violation_breach["violation_type"] == "lan_isolation_breach"
    assert violation_breach["severity"] == Severity.CRITICAL.value


def test_smart_tv_preset_enforcement():
    """Smart TV permits DLNA and web, alerts on unallowed or sensitive services."""
    tracker = LanTrafficTracker()

    tv_mac = "11:22:33:44:55:01"
    tv_ip = "192.168.1.60"
    nas_ip = "192.168.1.10"

    devices_map = {
        tv_mac: {
            "mac": tv_mac,
            "ip": tv_ip,
            "hostname": "Living-Room-TV",
            "profile": "smart_tv",
            "preset_id": "preset_smart_tv",
            "custom_allowed_ports": [9090]
        },
        "11:22:33:44:55:02": {
            "mac": "11:22:33:44:55:02",
            "ip": nas_ip,
            "hostname": "NAS-Server"
        }
    }

    # 1. Allowed DLNA port 8200
    v_dlna = tracker.check_lan_policy_violation(
        src_mac=tv_mac,
        src_ip=tv_ip,
        dst_ip=nas_ip,
        port=8200,
        protocol="TCP",
        devices_map=devices_map
    )
    assert v_dlna is None

    # 2. Custom allowed port 9090
    v_custom = tracker.check_lan_policy_violation(
        src_mac=tv_mac,
        src_ip=tv_ip,
        dst_ip=nas_ip,
        port=9090,
        protocol="TCP",
        devices_map=devices_map
    )
    assert v_custom is None

    # 3. Blocked port 3389 (RDP)
    v_rdp = tracker.check_lan_policy_violation(
        src_mac=tv_mac,
        src_ip=tv_ip,
        dst_ip=nas_ip,
        port=3389,
        protocol="TCP",
        devices_map=devices_map
    )
    assert v_rdp is not None
    assert v_rdp["violation_type"] == "blocked_service"
    assert v_rdp["severity"] == Severity.CRITICAL.value

    # 4. Unallowed service port 7777 (restricted policy)
    v_unallowed = tracker.check_lan_policy_violation(
        src_mac=tv_mac,
        src_ip=tv_ip,
        dst_ip=nas_ip,
        port=7777,
        protocol="TCP",
        devices_map=devices_map
    )
    assert v_unallowed is not None
    assert v_unallowed["violation_type"] == "unallowed_service"
    assert v_unallowed["severity"] == Severity.WARNING.value


def test_trusted_preset_and_alert_throttling():
    """Trusted device has full access; repeated alerts are throttled."""
    tracker = LanTrafficTracker()

    pc_mac = "CC:DD:EE:FF:00:11"
    pc_ip = "192.168.1.25"
    srv_ip = "192.168.1.10"

    devices_map = {
        pc_mac: {
            "mac": pc_mac,
            "ip": pc_ip,
            "hostname": "Admin-Laptop",
            "profile": "trusted",
            "preset_id": "preset_trusted"
        }
    }

    # Trusted workstation accessing sensitive ports: should NOT trigger violation
    assert tracker.check_lan_policy_violation(
        src_mac=pc_mac, src_ip=pc_ip, dst_ip=srv_ip, port=22, protocol="SSH", devices_map=devices_map
    ) is None
    assert tracker.check_lan_policy_violation(
        src_mac=pc_mac, src_ip=pc_ip, dst_ip=srv_ip, port=23, protocol="Telnet", devices_map=devices_map
    ) is None

    # Throttling test on untrusted IoT device
    iot_mac = "EE:FF:00:11:22:33"
    iot_ip = "192.168.1.65"
    devices_map[iot_mac] = {
        "mac": iot_mac,
        "ip": iot_ip,
        "hostname": "Smart-Socket",
        "profile": "iot",
        "preset_id": "preset_iot"
    }

    # First violation should register
    v1 = tracker.check_lan_policy_violation(
        src_mac=iot_mac, src_ip=iot_ip, dst_ip=srv_ip, port=445, protocol="SMB", devices_map=devices_map
    )
    assert v1 is not None

    # Second violation immediately after should be throttled (return None)
    v2 = tracker.check_lan_policy_violation(
        src_mac=iot_mac, src_ip=iot_ip, dst_ip=srv_ip, port=445, protocol="SMB", devices_map=devices_map
    )
    assert v2 is None
