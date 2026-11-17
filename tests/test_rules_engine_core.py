"""Unit tests for RuleMatcher and RuleLinter."""
from datetime import datetime
import pytest

from keenguard.db.models import (
    SecurityRule,
    RuleSource,
    RuleDestination,
    RuleContext,
    RuleReaction,
)
from keenguard.core.rules.matcher import RuleMatcher
from keenguard.core.rules.linter import RuleLinter, LinterSeverity


def test_rule_matcher_basic_pass():
    """Verify basic rule matching for Smart TV media stream."""
    rule_tv = SecurityRule(
        id="rule_tv",
        order_index=20,
        name="Smart TV Media",
        source=RuleSource(profiles=["smart_tv"]),
        destination=RuleDestination(direction="lan_to_lan", ports=[8096, 32400]),
        reaction=RuleReaction(severity="INFO", action_mode="pass")
    )

    matcher = RuleMatcher([rule_tv])

    devices_map = {
        "AA:BB:CC:DD:EE:01": {
            "mac": "AA:BB:CC:DD:EE:01",
            "ip": "192.168.1.60",
            "profile": "smart_tv"
        }
    }

    # Matches Jellyfin stream
    res = matcher.evaluate_flow(
        src_mac="AA:BB:CC:DD:EE:01",
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=8096,
        protocol="TCP",
        devices_map=devices_map
    )
    assert res.matched is True
    assert res.action_mode == "pass"
    assert res.rule_id == "rule_tv"

    # Does not match unallowed port 445
    res_smb = matcher.evaluate_flow(
        src_mac="AA:BB:CC:DD:EE:01",
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=445,
        protocol="TCP",
        devices_map=devices_map
    )
    assert res_smb.matched is False


def test_rule_matcher_source_inversion():
    """Verify source inversion ('All devices EXCEPT Workstation')."""
    pc_mac = "AA:BB:CC:DD:EE:99"
    other_mac = "11:22:33:44:55:66"

    rule_smb_shield = SecurityRule(
        id="rule_smb_shield",
        order_index=15,
        name="SMB Alert for all except Workstation",
        source=RuleSource(invert=True, device_macs=[pc_mac]),
        destination=RuleDestination(direction="lan_to_lan", ports=[445]),
        reaction=RuleReaction(severity="CRITICAL", action_mode="alert", notify_telegram=True)
    )

    matcher = RuleMatcher([rule_smb_shield])

    # 1. Workstation is excluded -> should NOT match this rule
    res_pc = matcher.evaluate_flow(
        src_mac=pc_mac,
        src_ip="192.168.1.25",
        dst_ip="192.168.1.10",
        port=445,
        protocol="TCP"
    )
    assert res_pc.matched is False

    # 2. Other device tries port 445 -> MATCHES and ALERTS
    res_other = matcher.evaluate_flow(
        src_mac=other_mac,
        src_ip="192.168.1.80",
        dst_ip="192.168.1.10",
        port=445,
        protocol="TCP"
    )
    assert res_other.matched is True
    assert res_other.action_mode == "alert"
    assert res_other.severity == "critical"
    assert res_other.notify_telegram is True


def test_rule_matcher_port_inversion():
    """Verify port inversion ('All ports EXCEPT RTSP 554')."""
    cam_mac = "00:AA:BB:CC:DD:01"

    rule_cam_strict = SecurityRule(
        id="rule_cam_strict",
        order_index=25,
        name="Camera Alert on any port except RTSP",
        source=RuleSource(device_macs=[cam_mac]),
        destination=RuleDestination(direction="any", invert_ports=True, ports=[554]),
        reaction=RuleReaction(severity="WARNING", action_mode="alert")
    )

    matcher = RuleMatcher([rule_cam_strict])

    # 1. RTSP 554 is excluded -> does NOT match rule
    res_rtsp = matcher.evaluate_flow(
        src_mac=cam_mac,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.200",
        port=554,
        protocol="TCP"
    )
    assert res_rtsp.matched is False

    # 2. Port 80 matches inverted rule -> alerts!
    res_http = matcher.evaluate_flow(
        src_mac=cam_mac,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.200",
        port=80,
        protocol="TCP"
    )
    assert res_http.matched is True
    assert res_http.action_mode == "alert"


def test_rule_matcher_volume_and_time_context():
    """Verify volume thresholds and time window filtering."""
    # Rule 1: High throughput video session (> 10 KB)
    rule_stream = SecurityRule(
        id="rule_stream",
        order_index=30,
        name="High Throughput Media Stream",
        destination=RuleDestination(ports=[8096]),
        context=RuleContext(volume_operator=">", volume_bytes=10240),
        reaction=RuleReaction(severity="INFO", action_mode="pass")
    )

    # Rule 2: Night wake anomaly (only between 00:00 - 07:00)
    rule_night = SecurityRule(
        id="rule_night",
        order_index=40,
        name="Night Anomaly Alert",
        destination=RuleDestination(ports=[8080]),
        context=RuleContext(time_window="night_only"),
        reaction=RuleReaction(severity="WARNING", action_mode="alert")
    )

    matcher = RuleMatcher([rule_stream, rule_night])

    # Volume < 10KB -> does NOT match rule_stream
    res_small = matcher.evaluate_flow(
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=8096,
        bytes_count=2048
    )
    assert res_small.matched is False

    # Volume > 10KB -> MATCHES rule_stream
    res_large = matcher.evaluate_flow(
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=8096,
        bytes_count=50000
    )
    assert res_large.matched is True
    assert res_large.action_mode == "pass"

    # Time window: Night (03:00) vs Day (15:00)
    dt_night = datetime(2026, 10, 5, 3, 30)
    dt_day = datetime(2026, 10, 5, 15, 30)

    res_night = matcher.evaluate_flow(
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=8080,
        current_dt=dt_night
    )
    assert res_night.matched is True

    res_day = matcher.evaluate_flow(
        src_ip="192.168.1.60",
        dst_ip="192.168.1.10",
        port=8080,
        current_dt=dt_day
    )
    assert res_day.matched is False


def test_rule_linter_shadowed_rule():
    """Verify that RuleLinter detects shadowed/dead allowing rules."""
    rule_block = SecurityRule(
        id="rule_block_smb",
        order_index=20,
        name="Block All SMB",
        destination=RuleDestination(direction="any", ports=[445]),
        reaction=RuleReaction(severity="CRITICAL", action_mode="alert")
    )

    rule_allow = SecurityRule(
        id="rule_allow_smb_pc",
        order_index=30,  # Below blocking rule!
        name="Allow SMB for PC",
        source=RuleSource(device_macs=["AA:BB:CC:DD:EE:01"]),
        destination=RuleDestination(direction="lan_to_lan", ports=[445]),
        reaction=RuleReaction(severity="INFO", action_mode="pass")
    )

    issues = RuleLinter.validate_rules([rule_block, rule_allow])
    assert len(issues) >= 1
    shadow_issue = next(i for i in issues if i.issue_type == "shadowed_rule")
    assert shadow_issue.rule_id == "rule_allow_smb_pc"
    assert shadow_issue.conflicting_rule_id == "rule_block_smb"
    assert shadow_issue.severity == LinterSeverity.WARNING


def test_rule_linter_core_breach():
    """Verify that RuleLinter detects custom rules placed above core failsafe rules."""
    rule_core = SecurityRule(
        id="rule_core_dns",
        order_index=10,
        category="core",
        name="Core DNS",
        reaction=RuleReaction(action_mode="pass")
    )

    rule_custom = SecurityRule(
        id="rule_custom_test",
        order_index=5,  # Placed above core rule!
        category="custom",
        name="Custom Override DNS",
        reaction=RuleReaction(action_mode="alert")
    )

    issues = RuleLinter.validate_rules([rule_custom, rule_core])
    assert len(issues) >= 1
    core_issue = next(i for i in issues if i.issue_type == "core_breach")
    assert core_issue.rule_id == "rule_custom_test"
    assert core_issue.severity == LinterSeverity.ERROR
