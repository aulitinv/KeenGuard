"""Unit tests for Phase 2: StrEnums, typed models, and robust parser error handling."""
import json
import pytest
from scapy.all import Ether, IP, TCP, UDP, Raw
from keenguard.core.enums import (
    DeviceProfile,
    Severity,
    RiskLevel,
    EventType,
    AutoQuarantineOverride,
)
from keenguard.db.models import (
    DeviceRecord,
    SecurityEvent,
    AuditReportRecord,
)
from keenguard.core.dissector import PacketDissector


def test_str_enums_are_strings():
    """Verify that StrEnum instances inherit from str and match literal strings."""
    assert isinstance(DeviceProfile.TRUSTED, str)
    assert DeviceProfile.TRUSTED == "trusted"
    assert DeviceProfile.SMART_TV == "smart_tv"
    assert Severity.WARNING == "warning"
    assert RiskLevel.HIGH == "high"
    assert EventType.PORT_PROBE == "port_probe"
    assert AutoQuarantineOverride.ALWAYS_QUARANTINE == "always_quarantine"


def test_device_record_enum_serialization():
    """Verify DeviceRecord serialization and deserialization with StrEnums."""
    dev = DeviceRecord(
        mac="AA:BB:CC:DD:EE:FF",
        profile=DeviceProfile.CAMERA,
        auto_quarantine_override=AutoQuarantineOverride.NEVER_QUARANTINE,
    )
    assert dev.profile == "camera"
    assert dev.auto_quarantine_override == "never_quarantine"

    dumped = json.loads(dev.model_dump_json())
    assert dumped["profile"] == "camera"
    assert dumped["auto_quarantine_override"] == "never_quarantine"

    dev2 = DeviceRecord(
        mac="11:22:33:44:55:66",
        profile="smart_home_hub",
        auto_quarantine_override="always_quarantine"
    )
    assert dev2.profile == DeviceProfile.SMART_HOME_HUB
    assert dev2.auto_quarantine_override == AutoQuarantineOverride.ALWAYS_QUARANTINE


def test_security_event_enums():
    """Verify SecurityEvent model properly accepts EventType and Severity."""
    event = SecurityEvent(
        event_type=EventType.NIGHT_WAKE,
        severity=Severity.CRITICAL,
        target_mac="AA:BB:CC:DD:EE:01",
        description="Night wake detected"
    )
    assert event.event_type == "night_wake"
    assert event.severity == "critical"

    event_json = json.loads(event.model_dump_json())
    assert event_json["event_type"] == "night_wake"
    assert event_json["severity"] == "critical"


def test_audit_report_risk_level_enum():
    """Verify AuditReportRecord accepts RiskLevel enum."""
    report = AuditReportRecord(
        id="test_report_1",
        mac="AA:BB:CC:DD:EE:02",
        risk_level=RiskLevel.MEDIUM,
        summary="Medium risk detected"
    )
    assert report.risk_level == "medium"
    assert report.risk_level == RiskLevel.MEDIUM


def test_dissector_robustness_malformed_packets():
    """Verify PacketDissector handles malformed or truncated payloads gracefully."""
    malformed_http = b"GET /somepath HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{malformed_json"
    res_http = PacketDissector.decode_http(malformed_http, base_offset=0)
    assert res_http is not None
    assert res_http["fields"]["Type"] == "HTTP Request"

    truncated_mqtt = b"\x30\x10\x00\x05topic"
    res_mqtt = PacketDissector.decode_mqtt(truncated_mqtt, base_offset=0)
    assert res_mqtt is not None
    assert "MQTT" in res_mqtt["name"]
    assert "PUBLISH" in res_mqtt["name"]

    bad_bytes = b"\x00\x01\x02"
    result = PacketDissector.dissect(bad_bytes)
    assert isinstance(result, dict)
