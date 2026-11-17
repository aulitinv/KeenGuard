"""Comprehensive REST API tests for KeenGuard Rules Engine endpoints."""
from contextlib import asynccontextmanager
import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path

from keenguard.web.app import app
import keenguard.web.app as web_app
from keenguard.db.database import Database
from keenguard.db.models import RuleHitRecord
from keenguard.core.rules.matcher import rule_matcher


@asynccontextmanager
async def create_test_client(tmp_path, monkeypatch):
    """Sets up an isolated database and test client for rules API."""
    db_file = tmp_path / "test_rules_api.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    # Monkeypatch web_app.db so state.get_db() uses our isolated database
    monkeypatch.setattr(web_app, "db", test_db)

    # Initialize rule_matcher with our test db rules
    rules = await test_db.get_rules()
    rule_matcher.load_rules(rules)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        yield client, test_db


@pytest.mark.asyncio
async def test_get_rules_list(tmp_path, monkeypatch):
    """Verifies listing all rules ordered by order_index ASC."""
    async with create_test_client(tmp_path, monkeypatch) as (client, test_db):
        res = await client.get("/api/rules")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        assert len(data) >= 6

        # Verify order_index is monotonically non-decreasing
        indices = [r["order_index"] for r in data]
        assert indices == sorted(indices)

        # Verify core rules are present at the beginning
        assert data[0]["category"] == "core"
        assert data[0]["id"] == "rule_core_dhcp"


@pytest.mark.asyncio
async def test_create_update_delete_custom_rule(tmp_path, monkeypatch):
    """Verifies creating, updating, and deleting a custom security rule."""
    async with create_test_client(tmp_path, monkeypatch) as (client, test_db):
        # 1. Create custom rule
        payload = {
            "name": "Custom Home Assistant Rule",
            "description": "Allow Smart TV to access Home Assistant dashboard",
            "enabled": True,
            "category": "custom",
            "source": {
                "invert": False,
                "profiles": ["smart_tv"],
            },
            "destination": {
                "direction": "lan_to_lan",
                "ports": [8123],
                "protocols": ["TCP"],
            },
            "reaction": {
                "severity": "INFO",
                "action_mode": "pass",
            }
        }
        create_res = await client.post("/api/rules", json=payload)
        assert create_res.status_code == 201
        created = create_res.json()
        rule_id = created["id"]
        assert rule_id.startswith("rule_custom_")
        assert created["name"] == "Custom Home Assistant Rule"
        assert created["destination"]["ports"] == [8123]

        # Verify rule is now active in matcher
        match_eval = rule_matcher.evaluate_flow(
            src_ip="192.168.1.55",
            dst_ip="192.168.1.10",
            port=8123,
            protocol="TCP",
            devices_map={"192.168.1.55": {"ip": "192.168.1.55", "profile": "smart_tv"}}
        )
        assert match_eval.matched is True
        assert match_eval.rule_id == rule_id

        # 2. Get rule details
        get_res = await client.get(f"/api/rules/{rule_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == rule_id

        # 3. Update rule
        update_res = await client.put(f"/api/rules/{rule_id}", json={
            "name": "Updated HA Rule",
            "reaction": {
                "severity": "WARNING",
                "action_mode": "alert",
            }
        })
        assert update_res.status_code == 200
        updated = update_res.json()
        assert updated["name"] == "Updated HA Rule"
        assert updated["reaction"]["action_mode"] == "alert"

        # 4. Toggle rule
        toggle_res = await client.post(f"/api/rules/{rule_id}/toggle", json={"enabled": False})
        assert toggle_res.status_code == 200
        assert toggle_res.json()["enabled"] is False

        # Verify disabled rule is skipped by matcher
        match_eval2 = rule_matcher.evaluate_flow(
            src_ip="192.168.1.55",
            dst_ip="192.168.1.10",
            port=8123,
            protocol="TCP",
            devices_map={"192.168.1.55": {"ip": "192.168.1.55", "profile": "smart_tv"}}
        )
        assert match_eval2.rule_id != rule_id

        # 5. Delete rule
        del_res = await client.delete(f"/api/rules/{rule_id}")
        assert del_res.status_code == 200
        assert del_res.json()["success"] is True

        # Confirm deletion
        get_del = await client.get(f"/api/rules/{rule_id}")
        assert get_del.status_code == 404


@pytest.mark.asyncio
async def test_protected_core_rules(tmp_path, monkeypatch):
    """Verifies that Zone 1 Core rules cannot be deleted, disabled, or demoted."""
    async with create_test_client(tmp_path, monkeypatch) as (client, test_db):
        # 1. Attempt to delete core rule
        del_res = await client.delete("/api/rules/rule_core_dns")
        assert del_res.status_code == 400
        assert "нельзя удалять" in del_res.json()["detail"]

        # 2. Attempt to disable core rule
        toggle_res = await client.post("/api/rules/rule_core_dns/toggle", json={"enabled": False})
        assert toggle_res.status_code == 400
        assert "нельзя отключать" in toggle_res.json()["detail"]

        # 3. Attempt to change category
        put_res = await client.put("/api/rules/rule_core_dns", json={"category": "custom"})
        assert put_res.status_code == 400


@pytest.mark.asyncio
async def test_reorder_and_linter_validation(tmp_path, monkeypatch):
    """Verifies rules reordering with conflict detection (shadowing & core breach)."""
    async with create_test_client(tmp_path, monkeypatch) as (client, test_db):
        rules = await test_db.get_rules()
        rule_ids = [r.id for r in rules]

        # Test 1: Core breach attempt (placing a custom rule before core DHCP)
        # Put rule_smart_tv_media first before rule_core_dhcp
        breached_order = ["rule_smart_tv_media"] + [rid for rid in rule_ids if rid != "rule_smart_tv_media"]
        res_breach = await client.put("/api/rules/reorder", json={"ordered_ids": breached_order})
        assert res_breach.status_code == 400
        data_breach = res_breach.json()
        assert any(i["issue_type"] == "core_breach" for i in data_breach["issues"])

        # Test 2: Shadowing conflict (create broad alert on 8080 above pass on 8080)
        # First create a custom pass rule on 8080
        r_pass = await client.post("/api/rules", json={
            "name": "Pass 8080 Rule",
            "enabled": True,
            "destination": {"ports": [8080]},
            "reaction": {"action_mode": "pass"}
        })
        pass_id = r_pass.json()["id"]

        # Create alert rule on 8080
        r_alert = await client.post("/api/rules", json={
            "name": "Block 8080 Rule",
            "enabled": True,
            "destination": {"ports": [8080]},
            "reaction": {"action_mode": "alert", "severity": "CRITICAL"}
        })
        alert_id = r_alert.json()["id"]

        # Reorder so alert_id comes BEFORE pass_id -> shadows pass_id
        updated_rules = await test_db.get_rules()
        core_ids = [r.id for r in updated_rules if r.category == "core"]
        other_ids = [r.id for r in updated_rules if r.category != "core" and r.id not in (alert_id, pass_id)]
        shadow_order = core_ids + [alert_id, pass_id] + other_ids

        # Without force: should return 409 Conflict
        res_shadow = await client.put("/api/rules/reorder", json={"ordered_ids": shadow_order, "force": False})
        assert res_shadow.status_code == 409
        data_shadow = res_shadow.json()
        assert any(i["issue_type"] in ("shadowed_rule", "direct_conflict") for i in data_shadow["issues"])

        # With force: should succeed
        res_force = await client.put("/api/rules/reorder", json={"ordered_ids": shadow_order, "force": True})
        assert res_force.status_code == 200
        assert res_force.json()["success"] is True


@pytest.mark.asyncio
async def test_rule_simulation_and_hits(tmp_path, monkeypatch):
    """Verifies dry-run simulator and hit telemetry history endpoint."""
    async with create_test_client(tmp_path, monkeypatch) as (client, test_db):
        # 1. Test simulator with TV streaming flow to Jellyfin port 8096
        sim_res = await client.post("/api/rules/test", json={
            "src_mac": "AA:BB:CC:DD:EE:FF",
            "src_ip": "192.168.1.150",
            "dst_ip": "192.168.1.200",
            "port": 8096,
            "protocol": "TCP",
            "bytes_count": 50000,
        })
        assert sim_res.status_code == 200
        sim_data = sim_res.json()
        assert "matched" in sim_data

        # 2. Record hit in test DB and query via hits endpoint
        hit = RuleHitRecord(
            rule_id="rule_smart_tv_media",
            src_ip="192.168.1.150",
            dst_ip="192.168.1.200",
            port=8096,
            protocol="TCP",
            bytes_count=12000,
            action_taken="pass",
            summary="192.168.1.150 -> 192.168.1.200:8096 (TCP)",
        )
        await test_db.record_rule_hit("rule_smart_tv_media", hit)

        hits_res = await client.get("/api/rules/rule_smart_tv_media/hits?limit=10")
        assert hits_res.status_code == 200
        hits_data = hits_res.json()
        assert len(hits_data) >= 1
        assert hits_data[0]["port"] == 8096
        assert hits_data[0]["action_taken"] == "pass"
