"""Strongly-typed StrEnum classes for KeenGuard domains, profiles, and events."""
from enum import StrEnum


class DeviceProfile(StrEnum):
    """Network security policy profiles assigned to devices."""
    UNASSIGNED = "unassigned"
    TRUSTED = "trusted"
    SMART_TV = "smart_tv"
    CAMERA = "camera"
    IOT = "iot"
    SMART_HOME_HUB = "smart_home_hub"
    GUEST = "guest"
    NAS = "nas"
    PRINTER = "printer"


class Severity(StrEnum):
    """Severity levels for security events, incidents, and alerts."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RiskLevel(StrEnum):
    """Aggregate risk score classification for audit reports and devices."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EventType(StrEnum):
    """Identifies the detection engine or telemetry source for a SecurityEvent."""
    NEW_DEVICE = "new_device"
    MAC_CONFLICT = "mac_conflict"
    MAC_ROTATION = "mac_rotation"
    PORT_PROBE = "port_probe"
    ARP_PROBE = "arp_probe"
    WOL_WAKE = "wol_wake"
    AIRPLAY_ACTIVITY = "airplay_activity"
    CAST_ACTIVITY = "cast_activity"
    DIAL_ACTIVITY = "dial_activity"
    ROUTER_ONLINE = "router_online"
    ROUTER_OFFLINE = "router_offline"
    IP_BLACKHOLE_BLOCKED = "ip_blackhole_blocked"
    UPNP_DETECTED = "upnp_detected"
    CAMERA_LEAK = "camera_leak"
    IOT_FLOOD = "iot_flood"
    NIGHT_WAKE = "night_wake"
    ROGUE_DNS = "rogue_dns"
    ANOMALY = "anomaly"
    POLICY_VIOLATION = "policy_violation"
    LAN_POLICY_VIOLATION = "lan_policy_violation"
    TV_STANDBY_WAKE = "tv_standby_wake"


class AutoQuarantineOverride(StrEnum):
    """Device-specific overrides for new-device quarantine policies."""
    PROFILE_DEFAULT = "profile_default"
    ALWAYS_QUARANTINE = "always_quarantine"
    NEVER_QUARANTINE = "never_quarantine"
