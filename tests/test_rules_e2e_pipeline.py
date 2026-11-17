"""End-to-End pipeline verification for KeenGuard Rules Engine."""
import asyncio
from contextlib import asynccontextmanager
import pytest
from httpx import AsyncClient, ASGITransport

from keenguard.web.app import app
import keenguard.web.app as web_app
from keenguard.db.database import Database
from keenguard.db.models import SecurityEvent, RuleHitRecord
from keenguard.core.rules.matcher import rule_matcher
from keenguard.core.lan_tracker import lan_tracker


@asynccontextmanager
async def create_e2e_env(tmp_path, monkeypatch):
    """Sets up an isolated database and test client for E2E rules tests."""
    db_file = tmp_path / "test_rules_e2e.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    monkeypatch.setattr(web_app, "db", test_db)

    rules = await test_db.get_rules()
    rule_matcher.load_rules(rules)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        yield client, test_db


@pytest.mark.asyncio
async def test_rules_e2e_alert_pipeline(tmp_path, monkeypatch):
    """Verifies E2E flow: API Create Rule -> LanTracker Detection -> DB Event Attribution -> Hit Telemetry."""
    async with create_e2e_env(tmp_path, monkeypatch) as (client, test_db):
        # 1. Create a custom rule targeting Telnet probe (port 23)
        res_create = await client.post("/api/rules", json={
            "name": "Block Rogue Port 4444",
            "description": "Alert on any internal 4444 attempts",
            "enabled": True,
            "category": "perimeter",
            "destination": {
                "direction": "lan_to_lan",
                "ports": [4444],
                "protocols": ["TCP"]
            },
            "reaction": {
                "action_mode": "alert",
                "severity": "CRITICAL",
                "notify_telegram": True,
                "record_pcap_seconds": 30
            }
        })
        assert res_create.status_code == 201
        created_rule = res_create.json()
        rule_id = created_rule["id"]

        devices_map = {
            "AA:BB:CC:11:22:33": {
                "mac": "AA:BB:CC:11:22:33",
                "ip": "192.168.1.75",
                "name": "Suspicious IoT Plug",
                "profile": "iot"
            },
            "192.168.1.10": {
                "mac": "00:11:22:33:44:55",
                "ip": "192.168.1.10",
                "name": "Home NAS",
                "profile": "trusted"
            }
        }

        # 2. Simulate LanTracker observing intra-LAN traffic on port 4444
        violation = lan_tracker.check_lan_policy_violation(
            src_mac="AA:BB:CC:11:22:33",
            src_ip="192.168.1.75",
            dst_ip="192.168.1.10",
            port=4444,
            protocol="TCP",
            bytes_count=1024,
            devices_map=devices_map
        )

        assert violation is not None
        assert violation["violation_type"] == "rule_alert"
        assert violation["matched_rule_id"] == rule_id
        assert violation["matched_rule_name"] == "Block Rogue Port 4444"
        assert violation["severity"] == "CRITICAL"

        # 3. Automatic background pipeline records the event and hit telemetry
        await asyncio.sleep(0.05)

        # 4. Query events from DB and verify rule attribution
        events = await test_db.get_recent_events(limit=10)
        matched_event = next((e for e in events if e.matched_rule_id == rule_id), None)
        assert matched_event is not None
        assert matched_event.matched_rule_name == "Block Rogue Port 4444"

        # 5. Query rule hit history via REST API
        res_hits = await client.get(f"/api/rules/{rule_id}/hits")
        assert res_hits.status_code == 200
        hits_data = res_hits.json()
        assert len(hits_data) == 1
        assert hits_data[0]["port"] == 4444
        assert hits_data[0]["action_taken"] == "alert"


@pytest.mark.asyncio
async def test_rules_whitelist_overrides_isolated_preset(tmp_path, monkeypatch):
    """Verifies that a custom Pass rule overrides default preset isolation."""
    async with create_e2e_env(tmp_path, monkeypatch) as (client, test_db):
        devices_map = {
            "AA:BB:CC:99:88:77": {
                "mac": "AA:BB:CC:99:88:77",
                "ip": "192.168.1.80",
                "name": "Garden Cam",
                "profile": "camera",
                "preset_id": "preset_camera"  # Policy: isolated
            },
            "192.168.1.100": {
                "mac": "00:AA:BB:CC:DD:EE",
                "ip": "192.168.1.100",
                "name": "Home Assistant Server",
                "profile": "trusted"
            }
        }

        # Without custom rule: port 8123 triggers lan_isolation_breach
        v_before = lan_tracker.check_lan_policy_violation(
            src_mac="AA:BB:CC:99:88:77",
            src_ip="192.168.1.80",
            dst_ip="192.168.1.100",
            port=8123,
            protocol="TCP",
            devices_map=devices_map
        )
        assert v_before is not None
        assert v_before["violation_type"] == "lan_isolation_breach"

        # Create custom pass rule for port 8123
        res_create = await client.post("/api/rules", json={
            "name": "Allow Camera HA Integration",
            "enabled": True,
            "category": "custom",
            "source": {
                "profiles": ["camera"]
            },
            "destination": {
                "direction": "lan_to_lan",
                "ports": [8123],
                "protocols": ["TCP"]
            },
            "reaction": {
                "action_mode": "pass",
                "severity": "INFO"
            }
        })
        assert res_create.status_code == 201

        # Clear throttle cache in lan_tracker for immediate evaluation
        lan_tracker._policy_alert_throttle.clear()

        # With custom pass rule: returns None (whitelisted)
        v_after = lan_tracker.check_lan_policy_violation(
            src_mac="AA:BB:CC:99:88:77",
            src_ip="192.168.1.80",
            dst_ip="192.168.1.100",
            port=8123,
            protocol="TCP",
            devices_map=devices_map
        )
        assert v_after is None


@pytest.mark.asyncio
async def test_first_match_win_reordering_pipeline(tmp_path, monkeypatch):
    """Verifies that changing rule order changes matching behavior per First-Match Win."""
    async with create_e2e_env(tmp_path, monkeypatch) as (client, test_db):
        # Create Rule Pass on port 9000
        r_pass = await client.post("/api/rules", json={
            "name": "Pass Port 9000",
            "enabled": True,
            "destination": {"ports": [9000]},
            "reaction": {"action_mode": "pass"}
        })
        pass_id = r_pass.json()["id"]

        # Create Rule Alert on port 9000
        r_alert = await client.post("/api/rules", json={
            "name": "Alert Port 9000",
            "enabled": True,
            "destination": {"ports": [9000]},
            "reaction": {"action_mode": "alert", "severity": "WARNING"}
        })
        alert_id = r_alert.json()["id"]

        # 1. Order: Core Rules -> Pass -> Alert
        rules = await test_db.get_rules()
        core_ids = [r.id for r in rules if r.category == "core"]
        other_ids = [r.id for r in rules if r.category != "core" and r.id not in (pass_id, alert_id)]
        order1 = core_ids + [pass_id, alert_id] + other_ids

        await client.put("/api/rules/reorder", json={"ordered_ids": order1, "force": True})

        eval1 = rule_matcher.evaluate_flow(
            src_ip="192.168.1.50",
            dst_ip="192.168.1.60",
            port=9000,
            protocol="TCP"
        )
        assert eval1.matched is True
        assert eval1.rule_id == pass_id
        assert eval1.action_mode == "pass"

        # 2. Reorder: Core Rules -> Alert -> Pass
        order2 = core_ids + [alert_id, pass_id] + other_ids
        await client.put("/api/rules/reorder", json={"ordered_ids": order2, "force": True})

        eval2 = rule_matcher.evaluate_flow(
            src_ip="192.168.1.50",
            dst_ip="192.168.1.60",
            port=9000,
            protocol="TCP"
        )
        assert eval2.matched is True
        assert eval2.rule_id == alert_id
        assert eval2.action_mode == "alert"
