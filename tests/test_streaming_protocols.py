"""
Unit and integration tests for Plan 01: Streaming noise reduction & behavioral traffic analysis.
Verifies that legitimate media streaming protocols (Virtual Desktop, Steam Link, Moonlight,
AirPlay 2, Google Cast, DLNA) do not trigger false positive lan_probes or auto-quarantine,
while real lateral movement and exploit attempts (SMB 445, Telnet 23, SSH 22) are strictly blocked.
"""
import pytest
from keenguard.core.audit.geoip import is_streaming_service, KNOWN_SERVICES
from keenguard.core.audit.session import AuditSession, evaluate_lan_access_policy
from keenguard.core.audit.report import build_device_audit_report
from keenguard.core.lan_tracker import LanTrafficTracker
from keenguard.db.models import DeviceRecord
from keenguard.db.repositories.settings import BUILTIN_LAN_PRESETS


def test_is_streaming_service_identification():
    # Virtual Desktop
    is_vd, name_vd = is_streaming_service(38820, "TCP")
    assert is_vd is True
    assert "Virtual Desktop" in name_vd

    # Steam In-Home / Steam Link
    is_steam, name_steam = is_streaming_service(27036, "TCP")
    assert is_steam is True
    assert "Steam" in name_steam

    # Moonlight / Sunshine
    is_moon, name_moon = is_streaming_service(47984, "TCP")
    assert is_moon is True
    assert "Moonlight" in name_moon

    # Oculus Air Link
    is_airlink, name_airlink = is_streaming_service(5669, "UDP")
    assert is_airlink is True
    assert "Air Link" in name_airlink

    is_airlink_udp, _ = is_streaming_service(50010, "UDP")
    assert is_airlink_udp is True

    # Google Cast / DIAL
    is_cast, name_cast = is_streaming_service(8008, "TCP")
    assert is_cast is True
    assert "Google Cast" in name_cast

    # Apple AirPlay
    is_airplay, name_airplay = is_streaming_service(7000, "TCP")
    assert is_airplay is True
    assert "AirPlay" in name_airplay

    # DLNA
    is_dlna, name_dlna = is_streaming_service(8200, "TCP")
    assert is_dlna is True
    assert "DLNA" in name_dlna

    # Non-streaming exploit and standard ports
    assert is_streaming_service(445, "TCP")[0] is False
    assert is_streaming_service(22, "TCP")[0] is False
    assert is_streaming_service(23, "TCP")[0] is False
    assert is_streaming_service(3389, "TCP")[0] is False
    assert is_streaming_service(80, "TCP")[0] is False


def test_evaluate_lan_access_policy_streaming_profiles():
    # Virtual Desktop video stream from unassigned VR headset
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="unassigned",
        dst_ip="192.168.1.150",
        dport=38820,
        proto="TCP"
    )
    assert risk == "safe"
    assert is_blocked is False

    # Steam streaming from trusted gaming PC
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="trusted",
        dst_ip="192.168.1.60",
        dport=27036,
        proto="TCP"
    )
    assert risk == "safe"
    assert is_blocked is False

    # AirPlay media streaming to Smart TV
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="smart_tv",
        dst_ip="192.168.1.55",
        dport=7000,
        proto="TCP"
    )
    assert risk == "safe"
    assert is_blocked is False

    # Google Cast to Smart TV with preset_smart_tv rules
    tv_preset = next(p for p in BUILTIN_LAN_PRESETS if p["id"] == "preset_smart_tv")
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="smart_tv",
        dst_ip="192.168.1.55",
        dport=8008,
        preset_rules=tv_preset["rules"]
    )
    assert risk == "safe"
    assert is_blocked is False


def test_evaluate_lan_access_policy_preserves_exploit_detection():
    # SMB probe from IoT camera must be CRITICAL and BLOCKED
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="camera",
        dst_ip="192.168.1.150",
        dport=445,
        proto="TCP"
    )
    assert risk == "critical"
    assert is_blocked is True

    # Telnet probe from IoT device must be CRITICAL and BLOCKED
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="iot",
        dst_ip="192.168.1.1",
        dport=23,
        proto="TCP"
    )
    assert risk == "critical"
    assert is_blocked is True

    # SMB probe from unassigned device must be CRITICAL and BLOCKED
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="unassigned",
        dst_ip="192.168.1.150",
        dport=445,
        proto="TCP"
    )
    assert risk == "critical"
    assert is_blocked is True


def test_behavioral_high_throughput_data_session():
    # High-throughput data session (e.g. iperf3 or file transfer on custom port 5201)
    # with 50 KB transferred: must be recognized as active data session (safe)
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="unassigned",
        dst_ip="192.168.1.150",
        dport=5201,
        proto="TCP",
        bytes_transferred=51200,
        packets_transferred=45
    )
    assert risk == "safe"
    assert is_blocked is False

    # Low-volume probe (e.g. single SYN packet of 60 bytes) on custom port 5201:
    # should be flagged as warning (potential scan probe)
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="unassigned",
        dst_ip="192.168.1.150",
        dport=5201,
        proto="TCP",
        bytes_transferred=60,
        packets_transferred=1
    )
    assert risk == "warning"
    assert is_blocked is False

    # High-throughput SMB transfer on port 445 from IoT device must NEVER be safe
    risk, is_blocked = evaluate_lan_access_policy(
        src_profile="iot",
        dst_ip="192.168.1.150",
        dport=445,
        proto="TCP",
        bytes_transferred=51200,
        packets_transferred=45
    )
    assert risk == "critical"
    assert is_blocked is True


def test_audit_session_virtual_desktop_noise_reduction():
    # Model an unassigned VR headset streaming to PC via Virtual Desktop
    session = AuditSession(
        mac="C0:DD:8A:11:22:33",
        ip="192.168.1.75",
        hostname="Meta-Quest-3",
        profile="unassigned"
    )

    nat_entries = [
        {
            "src": "192.168.1.75",
            "dst": "192.168.1.100",
            "dport": 38820,
            "protocol": "TCP",
            "bytes": 5000000,
            "bytes-out": 250000,
            "packets": 4000,
            "packets-out": 2000
        },
        {
            "src": "192.168.1.75",
            "dst": "192.168.1.100",
            "dport": 38830,
            "protocol": "TCP",
            "bytes": 150000,
            "bytes-out": 15000,
            "packets": 300,
            "packets-out": 150
        }
    ]

    quarantined = []
    def on_suspicious(mac, ip, name, reason):
        quarantined.append((mac, reason))

    session.update_nat_entries(nat_entries, on_suspicious_callback=on_suspicious)

    # Must NOT generate lan_probes or auto-quarantine
    assert len(session.lan_probes) == 0
    assert session.auto_quarantined is False
    assert len(quarantined) == 0

    # Report risk must be low and indicate media streaming
    report = build_device_audit_report(session)
    assert report["risk_level"] == "low"
    assert any("медиастриминг" in f or "Virtual Desktop" in f for f in report["findings"])


def test_audit_session_real_lateral_movement_quarantines():
    # Model a compromised camera scanning LAN
    dev = DeviceRecord(
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.80",
        hostname="outdoor-cam",
        profile="camera"
    )
    session = AuditSession(
        mac=dev.mac,
        ip=dev.ip,
        hostname=dev.hostname,
        profile=dev.profile,
        device=dev
    )

    nat_entries = [
        {
            "src": "192.168.1.80",
            "dst": "192.168.1.100",
            "dport": 445,
            "protocol": "TCP",
            "bytes": 120,
            "bytes-out": 0,
            "packets": 2,
            "packets-out": 0
        }
    ]

    quarantined = []
    def on_suspicious(mac, ip, name, reason):
        quarantined.append((mac, reason))

    session.update_nat_entries(nat_entries, on_suspicious_callback=on_suspicious)

    # Must be detected as critical lan_probe and quarantined
    assert len(session.lan_probes) == 1
    assert session.lan_probes[0]["risk"] == "critical"
    assert session.lan_probes[0]["port"] == 445
    assert session.auto_quarantined is True
    assert len(quarantined) == 1


def test_lan_tracker_streaming_exemption():
    tracker = LanTrafficTracker()
    devices_map = {
        "11:22:33:44:55:66": {
            "mac": "11:22:33:44:55:66",
            "ip": "192.168.1.55",
            "hostname": "LG-webOS-TV",
            "profile": "smart_tv",
            "preset_id": "preset_smart_tv"
        },
        "AA:BB:CC:DD:EE:FF": {
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.150",
            "hostname": "Home-PC",
            "profile": "trusted"
        }
    }

    # AirPlay (7000) from Smart TV must NOT be a violation
    violation = tracker.check_lan_policy_violation(
        src_mac="11:22:33:44:55:66",
        src_ip="192.168.1.55",
        dst_mac="AA:BB:CC:DD:EE:FF",
        dst_ip="192.168.1.150",
        port=7000,
        protocol="TCP",
        devices_map=devices_map
    )
    assert violation is None

    # Google Cast (8008) from Smart TV must NOT be a violation
    violation = tracker.check_lan_policy_violation(
        src_mac="11:22:33:44:55:66",
        src_ip="192.168.1.55",
        dst_mac="AA:BB:CC:DD:EE:FF",
        dst_ip="192.168.1.150",
        port=8008,
        protocol="TCP",
        devices_map=devices_map
    )
    assert violation is None

    # RDP (3389) from Smart TV MUST be a blocked violation
    violation = tracker.check_lan_policy_violation(
        src_mac="11:22:33:44:55:66",
        src_ip="192.168.1.55",
        dst_mac="AA:BB:CC:DD:EE:FF",
        dst_ip="192.168.1.150",
        port=3389,
        protocol="TCP",
        devices_map=devices_map
    )
    assert violation is not None
    assert violation["violation_type"] == "blocked_service"
