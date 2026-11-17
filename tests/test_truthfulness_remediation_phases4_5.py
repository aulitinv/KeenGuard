"""Unit and integration tests for Technical Truthfulness Remediation (Phases 4 & 5).

Covers:
- Phase 4: Smartphone MAC rotation policy synchronization and multi-MAC WAN toggle.
- Phase 5: Sniffer engine mode switching (conntrack_passive vs promiscuous_active) API & runtime behavior.
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from keenguard.core.classifier import DeviceClassifier
from keenguard.core.sniffer import NetworkSniffer
from keenguard.config import settings
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_toggle_wan_apply_to_linked(tmp_path):
    """Verifies that toggle_wan with apply_to_linked=True toggles all linked MAC aliases in a rotation group."""
    test_db = Database(db_path=tmp_path / "test_wan_group.db")
    await test_db.init_db()

    mac_hw = "00:11:22:33:44:01"
    mac_rand = "02:11:22:33:44:02"

    d_hw = DeviceRecord(
        mac=mac_hw,
        ip="192.168.1.10",
        hostname="My-Smartphone-User",
        profile="trusted",
        is_blocked_wan=False,
        is_online=True
    )
    d_rand = DeviceRecord(
        mac=mac_rand,
        ip="192.168.1.11",
        hostname="My-Smartphone-User",
        profile="trusted",
        is_blocked_wan=False,
        is_online=True
    )
    await test_db.upsert_device(d_hw)
    await test_db.upsert_device(d_rand)

    with patch("keenguard.web.routes.devices.get_db", return_value=test_db), \
         patch("keenguard.core.profiles.db", test_db), \
         patch("keenguard.web.app.db", test_db):
        client = TestClient(app)
        
        # Toggle WAN block with apply_to_linked=True
        resp = client.post(f"/api/devices/{mac_hw}/toggle_wan", json={"enabled": True, "apply_to_linked": True})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["blocked_wan"] is True
        assert data["applied_to_linked"] is True
        assert mac_hw in data["affected_macs"]
        assert mac_rand in data["affected_macs"]

        # Check DB states
        dev1 = await test_db.get_device(mac_hw)
        dev2 = await test_db.get_device(mac_rand)
        assert dev1.is_blocked_wan is True
        assert dev2.is_blocked_wan is True


@pytest.mark.asyncio
async def test_apply_policy_to_group(tmp_path):
    """Verifies that apply_policy_to_group copies security profile and policy to all linked aliases."""
    test_db = Database(db_path=tmp_path / "test_apply_policy_group.db")
    await test_db.init_db()

    mac_hw = "00:11:22:33:44:01"
    mac_rand = "02:11:22:33:44:02"

    d_hw = DeviceRecord(
        mac=mac_hw,
        ip="192.168.1.10",
        hostname="Personal-Phone-Max",
        profile="smart_home_hub",
        is_blocked_wan=True,
        auto_quarantine_override="always_quarantine",
        is_online=True
    )
    d_rand = DeviceRecord(
        mac=mac_rand,
        ip="192.168.1.11",
        hostname="Personal-Phone-Max",
        profile="unassigned",
        is_blocked_wan=False,
        auto_quarantine_override="profile_default",
        is_online=True
    )
    await test_db.upsert_device(d_hw)
    await test_db.upsert_device(d_rand)

    with patch("keenguard.web.routes.devices.get_db", return_value=test_db), \
         patch("keenguard.core.profiles.db", test_db), \
         patch("keenguard.web.app.db", test_db):
        client = TestClient(app)

        resp = client.post(f"/api/devices/{mac_hw}/apply_policy_to_group")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert mac_rand in data["affected_macs"]
        assert data["count"] == 1

        dev2 = await test_db.get_device(mac_rand)
        assert dev2.profile == "smart_home_hub"
        assert dev2.is_blocked_wan is True
        assert dev2.auto_quarantine_override == "always_quarantine"


@pytest.mark.asyncio
async def test_sniffer_mode_api_and_runtime(tmp_path):
    """Verifies sniffer mode reading, setting, validation, and runtime effect."""
    test_db = Database(db_path=tmp_path / "test_sniffer_mode.db")
    await test_db.init_db()

    sniffer = NetworkSniffer()

    with patch("keenguard.web.routes.settings.get_db", return_value=test_db), \
         patch("keenguard.web.routes.settings.get_sniffer", return_value=sniffer):
        client = TestClient(app)

        # 1. GET sniffer mode
        resp = client.get("/api/settings/sniffer_mode")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["sniffer_mode"] in ("conntrack_passive", "promiscuous_active")

        # 2. Switch to promiscuous_active
        resp2 = client.post("/api/settings/sniffer_mode", json={"sniffer_mode": "promiscuous_active"})
        assert resp2.status_code == 200
        assert resp2.json()["sniffer_mode"] == "promiscuous_active"
        assert settings.sniffer_mode == "promiscuous_active"

        # 3. Switch back to conntrack_passive
        resp3 = client.post("/api/settings/sniffer_mode", json={"sniffer_mode": "conntrack_passive"})
        assert resp3.status_code == 200
        assert resp3.json()["sniffer_mode"] == "conntrack_passive"
        assert settings.sniffer_mode == "conntrack_passive"

        # 4. Invalid mode returns 400
        resp_bad = client.post("/api/settings/sniffer_mode", json={"sniffer_mode": "magic_mode"})
        assert resp_bad.status_code == 400
