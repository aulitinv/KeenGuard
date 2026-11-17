"""Tests for Security Rules repository and database persistence."""
import pytest
from pathlib import Path
from keenguard.db.database import Database
from keenguard.db.models import (
    SecurityRule,
    RuleSource,
    RuleDestination,
    RuleContext,
    RuleReaction,
    RuleHitRecord,
    SecurityEvent,
)


@pytest.mark.asyncio
async def test_rules_repository_seeding(tmp_path):
    """Verifies that built-in security rules are seeded properly."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    rules = await test_db.get_rules()
    assert len(rules) >= 6

    # Verify Core Failsafe rules exist at top
    core_rules = [r for r in rules if r.category == "core"]
    assert len(core_rules) == 3
    assert core_rules[0].id == "rule_core_dhcp"
    assert core_rules[0].order_index == 1
    assert core_rules[1].id == "rule_core_dns"
    assert core_rules[2].id == "rule_core_web"

    # Verify Built-in Media rule includes Jellyfin & Plex
    media_rule = next(r for r in rules if r.id == "rule_smart_tv_media")
    assert 8096 in media_rule.destination.ports
    assert 32400 in media_rule.destination.ports
    assert "smart_tv" in media_rule.source.profiles


@pytest.mark.asyncio
async def test_rules_crud_operations(tmp_path):
    """Verifies CRUD operations on custom security rules."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    new_rule = SecurityRule(
        id="rule_custom_test_1",
        order_index=15,
        name="Custom Camera Whitelist",
        description="Allow specific camera to cloud",
        enabled=True,
        is_builtin=False,
        category="custom",
        source=RuleSource(device_macs=["00:11:22:33:44:55"]),
        destination=RuleDestination(direction="lan_to_wan", ports=[443]),
        reaction=RuleReaction(severity="INFO", action_mode="pass")
    )

    # 1. Create
    created = await test_db.create_rule(new_rule)
    assert created.id == "rule_custom_test_1"

    # 2. Get
    fetched = await test_db.get_rule("rule_custom_test_1")
    assert fetched is not None
    assert fetched.name == "Custom Camera Whitelist"
    assert fetched.source.device_macs == ["00:11:22:33:44:55"]

    # 3. Update
    fetched.name = "Updated Camera Rule"
    fetched.enabled = False
    updated = await test_db.update_rule(fetched)
    assert updated is not None
    assert updated.name == "Updated Camera Rule"
    assert updated.enabled is False

    # 4. Toggle
    toggled = await test_db.toggle_rule("rule_custom_test_1", enabled=True)
    assert toggled is True
    refetched = await test_db.get_rule("rule_custom_test_1")
    assert refetched.enabled is True

    # 5. Delete
    deleted = await test_db.delete_rule("rule_custom_test_1")
    assert deleted is True
    assert await test_db.get_rule("rule_custom_test_1") is None


@pytest.mark.asyncio
async def test_core_rule_deletion_protection(tmp_path):
    """Core failsafe rules must be protected from deletion."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    deleted = await test_db.delete_rule("rule_core_dns")
    assert deleted is False
    assert await test_db.get_rule("rule_core_dns") is not None


@pytest.mark.asyncio
async def test_rules_reordering(tmp_path):
    """Reordering updates order_index while protecting core rules priority."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    rules = await test_db.get_rules()
    rule_ids = [r.id for r in rules]

    # Swap two rules in the main pool
    idx_tv = rule_ids.index("rule_smart_tv_media")
    idx_mirai = rule_ids.index("rule_block_mirai_botnet")
    rule_ids[idx_tv], rule_ids[idx_mirai] = rule_ids[idx_mirai], rule_ids[idx_tv]

    success = await test_db.reorder_rules(rule_ids)
    assert success is True

    reordered = await test_db.get_rules()
    reordered_map = {r.id: r.order_index for r in reordered}

    # Core rules remain 1..10
    assert reordered_map["rule_core_dhcp"] == 1
    assert reordered_map["rule_core_dns"] == 2
    assert reordered_map["rule_core_web"] == 3

    # Mirai rule is now before Smart TV media rule
    assert reordered_map["rule_block_mirai_botnet"] < reordered_map["rule_smart_tv_media"]


@pytest.mark.asyncio
async def test_rule_hits_recording_and_telemetry(tmp_path):
    """Verifies hit telemetry incrementing and drilldown history logging."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    rule_id = "rule_smart_tv_media"

    hit = RuleHitRecord(
        rule_id=rule_id,
        src_ip="192.168.1.60",
        src_mac="AA:BB:CC:DD:EE:01",
        dst_ip="192.168.1.10",
        port=8096,
        protocol="TCP",
        bytes_count=1048576,
        action_taken="pass",
        summary="192.168.1.60 -> 192.168.1.10:8096 (Jellyfin, 1 MB)"
    )

    success = await test_db.record_rule_hit(rule_id, hit)
    assert success is True

    # Rule telemetry updated
    rule = await test_db.get_rule(rule_id)
    assert rule.telemetry.hits_total == 1
    assert rule.telemetry.hits_24h == 1
    assert rule.telemetry.last_hit_summary == "192.168.1.60 -> 192.168.1.10:8096 (Jellyfin, 1 MB)"

    # Hits history drilldown
    hits = await test_db.get_rule_hits(rule_id, limit=5)
    assert len(hits) == 1
    assert hits[0].src_ip == "192.168.1.60"
    assert hits[0].port == 8096
    assert hits[0].bytes_count == 1048576


@pytest.mark.asyncio
async def test_event_rule_attribution(tmp_path):
    """Verifies that SecurityEvent properly stores matched_rule_id and matched_rule_name."""
    test_db = Database(db_path=tmp_path / "rules.db")
    await test_db.init_db()

    event = SecurityEvent(
        event_type="lan_policy_violation",
        severity="critical",
        target_ip="192.168.1.50",
        source_ip="192.168.1.60",
        description="Blocked Telnet connection",
        matched_rule_id="rule_block_mirai_botnet",
        matched_rule_name="Block Mirai Botnet Ports"
    )

    event_id = await test_db.record_event(event)
    assert event_id > 0

    events = await test_db.get_recent_events(limit=10)
    matched = next(e for e in events if e.id == event_id)
    assert matched.matched_rule_id == "rule_block_mirai_botnet"
    assert matched.matched_rule_name == "Block Mirai Botnet Ports"
