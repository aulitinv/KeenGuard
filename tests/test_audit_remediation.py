"""Unit tests verifying fixes from comprehensive project audit (November 2026)."""
import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from httpx import AsyncClient, ASGITransport

from keenguard.web.app import app
import keenguard.web.app as web_app
from keenguard.db.database import Database
from keenguard.db.models import SecurityRule, RuleReaction, SecurityEvent, DeviceRecord
from keenguard.core.rules.matcher import RuleMatcher
from keenguard.core.scheduler import BackgroundScheduler
from keenguard.web.workers import _process_lan_violation


@pytest.mark.asyncio
async def test_path_traversal_audit_pcap_rejected():
    """Verify that path traversal attempts in /api/audit/pcap/ are blocked with 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        # Traversal with .. and backslashes (Windows traversal)
        res = await client.get("/api/audit/pcap/..%5C.env")
        assert res.status_code == 400
        assert "Invalid PCAP filename" in res.json().get("detail", "")

        res2 = await client.get("/api/audit/pcap/..%5C..%5Cdata%5Ckeenguard.db")
        assert res2.status_code == 400

        # Filename with embedded ..
        res3 = await client.get("/api/audit/pcap/invalid..dump.pcap")
        assert res3.status_code == 400

        # Non-existent file
        res4 = await client.get("/api/audit/pcap/non_existent_file.pcap")
        assert res4.status_code == 404


@pytest.mark.asyncio
async def test_path_traversal_events_pcap_rejected():
    """Verify that path traversal attempts in /api/events/pcap/ are blocked with 400."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        res = await client.get("/api/events/pcap/..%5C..%5Ckeenguard.db")
        assert res.status_code == 400
        assert "Invalid PCAP filename" in res.json().get("detail", "")

        res2 = await client.get("/api/events/pcap/traversal..name.pcap")
        assert res2.status_code == 400

        res3 = await client.get("/api/events/pcap/some_missing_dump.pcap")
        assert res3.status_code == 404


@pytest.mark.asyncio
async def test_rules_engine_automatic_hit_recording_and_wan_block(tmp_path, monkeypatch):
    """Verify that _process_lan_violation automatically records rule hits and executes reactions."""
    db_file = tmp_path / "test_reactions.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()
    monkeypatch.setattr(web_app, "db", test_db)

    # 1. Create target rule
    rule_id = "rule_test_reaction_01"
    rule = SecurityRule(
        id=rule_id,
        order_index=50,
        name="Test Reaction Rule",
        enabled=True,
        reaction=RuleReaction(
            action_mode="alert",
            severity="CRITICAL",
            hardware_wan_block=True,
            record_pcap_seconds=10
        )
    )
    await test_db.save_rule(rule)

    wan_blocked_macs = []

    async def fake_toggle_wan(mac, block=True):
        wan_blocked_macs.append((mac, block))
        return True

    from keenguard.core.profiles import profile_manager
    monkeypatch.setattr(profile_manager, "toggle_wan", fake_toggle_wan)

    # 2. Simulate LanTracker dispatching violation with rule attribution
    violation_dict = {
        "event_type": "lan_policy_violation",
        "severity": "CRITICAL",
        "description": "Suspicious flow to port 9999",
        "source_mac": "11:22:33:44:55:77",
        "source_ip": "192.168.1.155",
        "target_ip": "192.168.1.1",
        "port": 9999,
        "protocol": "TCP",
        "bytes_count": 2048,
        "matched_rule_id": rule_id,
        "matched_rule_name": "Test Reaction Rule",
        "hardware_wan_block": True,
        "record_pcap_seconds": 10,
    }

    await _process_lan_violation(violation_dict)
    # Allow background tracked tasks to complete
    await asyncio.sleep(0.1)

    # 3. Verify hit was recorded in database
    hits = await test_db.get_rule_hits(rule_id)
    assert len(hits) == 1
    assert hits[0].port == 9999
    assert hits[0].src_ip == "192.168.1.155"

    updated_rule = await test_db.get_rule(rule_id)
    assert updated_rule is not None
    assert updated_rule.telemetry.hits_total == 1
    assert updated_rule.telemetry.last_hit_at is not None

    # 4. Verify hardware WAN block reaction was triggered
    assert len(wan_blocked_macs) == 1
    assert wan_blocked_macs[0] == ("11:22:33:44:55:77", True)

    await test_db.close()


def test_rule_matcher_temporary_until_expiration():
    """Verify that RuleMatcher respects temporary_until expiration."""
    past_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    future_time = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()

    expired_rule = SecurityRule(
        id="rule_expired",
        order_index=15,
        name="Expired Temporary Rule",
        enabled=True,
        temporary_until=past_time
    )

    active_temp_rule = SecurityRule(
        id="rule_active_temp",
        order_index=20,
        name="Active Temporary Rule",
        enabled=True,
        temporary_until=future_time
    )

    matcher = RuleMatcher(rules=[expired_rule, active_temp_rule])

    # Flow should NOT match expired rule, but SHOULD match active temporary rule
    now = datetime.now(timezone.utc)
    res = matcher.evaluate_flow(
        src_mac="AA:BB:CC:DD:EE:01",
        src_ip="192.168.1.50",
        dst_ip="192.168.1.10",
        port=80,
        protocol="TCP",
        current_dt=now
    )
    assert res.matched is True
    assert res.rule_id == "rule_active_temp"


@pytest.mark.asyncio
async def test_scheduler_expires_temporary_rules(tmp_path, monkeypatch):
    """Verify that BackgroundScheduler auto-disables expired temporary rules in DB."""
    db_file = tmp_path / "test_sched_rules.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    past_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    rule = SecurityRule(
        id="rule_sched_temp_01",
        order_index=30,
        name="Temporary Pass Rule",
        enabled=True,
        temporary_until=past_time
    )
    await test_db.save_rule(rule)

    import keenguard.core.scheduler
    monkeypatch.setattr(keenguard.core.scheduler, "db", test_db)

    sched = BackgroundScheduler()
    await sched._check_temporary_rules_expiration()

    # Rule must now be disabled
    db_rule = await test_db.get_rule("rule_sched_temp_01")
    assert db_rule is not None
    assert db_rule.enabled is False

    await test_db.close()


@pytest.mark.asyncio
async def test_export_events_json_attachment_header():
    """Verify that GET /api/export/events?format=json returns Content-Disposition attachment header."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        res = await client.get("/api/export/events?format=json")
        assert res.status_code == 200
        assert "Content-Disposition" in res.headers
        assert "attachment; filename=security_events.json" in res.headers["Content-Disposition"]
