"""Database models and schema definitions for KeenGuard."""
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union, List
from pydantic import BaseModel, Field

from keenguard.core.enums import (
    DeviceProfile,
    Severity,
    RiskLevel,
    EventType,
    AutoQuarantineOverride,
)


class DeviceRecord(BaseModel):
    mac: str
    ip: Optional[str] = None
    interface: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    profile: Union[DeviceProfile, str] = DeviceProfile.UNASSIGNED
    is_blocked_wan: bool = False
    is_isolated_lan: bool = False
    airplay_allowed: bool = True
    dlna_allowed: bool = True
    night_mode_enabled: bool = False
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_online: bool = False
    rx_bytes: int = 0
    tx_bytes: int = 0
    custom_name: Optional[str] = None
    notes: Optional[str] = None
    preset_id: Optional[str] = None
    designated_nvr_ip: Optional[str] = None
    auto_quarantine_override: Union[AutoQuarantineOverride, str] = AutoQuarantineOverride.PROFILE_DEFAULT
    custom_allowed_ports: Optional[Union[List[int], str]] = None
    tv_pre_record_seconds: Optional[int] = None
    tv_post_record_seconds: Optional[int] = None
    tv_day_mode: Optional[str] = None
    wizard_completed: bool = False
    segment: Optional[str] = "Home"  # Home (Bridge0), Guest (Bridge1), IoT, etc.
    bandwidth_limit_kbps: int = 0

class LanPolicyPreset(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    is_builtin: bool = False
    rules: Dict[str, Any] = Field(default_factory=dict)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class SecurityEvent(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: Union[EventType, str]
    severity: Union[Severity, str] = Severity.INFO
    target_mac: Optional[str] = None
    target_ip: Optional[str] = None
    source_mac: Optional[str] = None
    source_ip: Optional[str] = None
    source_name: Optional[str] = None
    description: str
    details: Optional[Dict[str, Any]] = None
    pcap_file: Optional[str] = None
    matched_rule_id: Optional[str] = None
    matched_rule_name: Optional[str] = None

class RuleSource(BaseModel):
    invert: bool = False
    device_macs: List[str] = Field(default_factory=list)
    profiles: List[str] = Field(default_factory=list)
    segments: List[str] = Field(default_factory=list)
    vendors: List[str] = Field(default_factory=list)
    properties: List[str] = Field(default_factory=list)

class RuleDestination(BaseModel):
    direction: str = "lan_to_lan"  # lan_to_lan, lan_to_wan, lan_to_router, wan_to_lan, any
    invert_targets: bool = False
    targets: List[str] = Field(default_factory=list)  # IPs, subnets
    domains: List[str] = Field(default_factory=list)
    invert_ports: bool = False
    ports: List[Union[int, str]] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=lambda: ["TCP", "UDP"])

class RuleContext(BaseModel):
    volume_operator: Optional[str] = None  # ">", "<", None
    volume_bytes: int = 0
    bandwidth_operator: Optional[str] = None  # ">", "<", None
    bandwidth_kbps: float = 0.0
    time_window: str = "always"  # always, night_only, day_only
    rate_limit_burst: Optional[int] = None

class RuleReaction(BaseModel):
    severity: Union[Severity, str] = Severity.INFO
    action_mode: str = "pass"  # "pass" (whitelist) or "alert" (flag incident)
    notify_telegram: bool = False
    telegram_mode: str = "digest"  # "immediate" or "digest"
    record_pcap_seconds: int = 0
    hardware_wan_block: bool = False
    apply_preset_id: Optional[str] = None

class RuleTelemetry(BaseModel):
    hits_total: int = 0
    hits_24h: int = 0
    last_hit_at: Optional[str] = None
    last_hit_summary: Optional[str] = None

class SecurityRule(BaseModel):
    id: str
    order_index: int
    name: str
    description: Optional[str] = ""
    enabled: bool = True
    is_builtin: bool = False
    category: str = "general"  # core, media, perimeter, iot, custom
    temporary_until: Optional[str] = None
    source: RuleSource = Field(default_factory=RuleSource)
    destination: RuleDestination = Field(default_factory=RuleDestination)
    context: RuleContext = Field(default_factory=RuleContext)
    reaction: RuleReaction = Field(default_factory=RuleReaction)
    telemetry: RuleTelemetry = Field(default_factory=RuleTelemetry)
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class RuleHitRecord(BaseModel):
    id: Optional[int] = None
    rule_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    src_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "TCP"
    bytes_count: int = 0
    action_taken: str = "pass"
    summary: Optional[str] = None

class AuditReportRecord(BaseModel):
    id: str
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_seconds: int = 0
    total_bytes: int = 0
    total_packets: int = 0
    risk_level: Union[RiskLevel, str] = RiskLevel.LOW
    summary: str = ""
    report_json: str = "{}"
    pcap_file: Optional[str] = None

class TrafficSnapshot(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mac: str
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_rate_kbps: float = 0.0
    tx_rate_kbps: float = 0.0

class DnsQueryRecord(BaseModel):
    domain: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    count: int = 1
    first_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class IotPayloadRecord(BaseModel):
    model_config = {"extra": "allow"}

    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    mac: str
    device_name: Optional[str] = None
    hostname: Optional[str] = None
    src_ip: Optional[str] = None
    ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: str = "RAW"
    direction: str = "outbound"
    summary: str = ""
    decoded_summary: Optional[str] = None
    payload_text: Optional[str] = None
    payload_hex: Optional[str] = None
    byte_size: int = 0
    payload_len: Optional[int] = None
    raw_json: Optional[str] = None
    is_cloud: Optional[bool] = False

    def model_post_init(self, __context: Any) -> None:
        if not self.byte_size:
            if self.payload_len is not None and self.payload_len > 0:
                self.byte_size = self.payload_len
            elif self.payload_hex:
                self.byte_size = len(self.payload_hex) // 2
            elif self.payload_text:
                self.byte_size = len(self.payload_text.encode("utf-8", errors="replace"))
        if not self.device_name and self.hostname:
            self.device_name = self.hostname
        if not self.src_ip and self.ip:
            self.src_ip = self.ip
        if not self.summary and self.decoded_summary:
            self.summary = self.decoded_summary

class LanCommunicationRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    comm_type: str  # icmp_ping, icmp_reply, arp_query, arp_reply, local_flow
    src_mac: Optional[str] = None
    src_ip: Optional[str] = None
    src_name: Optional[str] = None
    dst_mac: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_name: Optional[str] = None
    protocol: str = "IP"
    port: Optional[int] = None
    summary: str = ""
    status: str = "active"  # replied, waiting, timeout, active, querying, resolved
    rtt_ms: Optional[float] = None
    payload_preview: Optional[str] = None


