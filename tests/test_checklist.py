# -*- coding: utf-8 -*-
"""Unit tests for the consolidated Security Checklist & Audit Hub."""
import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.core.checklist import SecurityChecklistEvaluator
from keenguard.db.models import DeviceRecord
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_checklist_evaluator_structure():
    result = await SecurityChecklistEvaluator.evaluate_checklist()
    assert result["status"] == "ok"
    assert "score" in result
    assert 0 <= result["score"] <= 100
    assert "score_label" in result
    assert "stats" in result
    assert result["stats"]["total_checks"] == 11

    items = result["items"]
    assert len(items) == 11

    item_ids = [item["id"] for item in items]
    expected_ids = [
        "hub_isolation",
        "zero_internet_sensors",
        "appliance_lan_isolation",
        "camera_security_upnp",
        "smart_tv_security",
        "wifi_security_pmf",
        "firmware_updates",
        "dns_protection",
        "new_device_quarantine",
        "arp_scan_spoofing",
        "hardware_segmentation"
    ]
    for eid in expected_ids:
        assert eid in item_ids

    # Each item must have valid structure
    for item in items:
        assert item["status"] in ("ok", "warning", "critical")
        assert len(item["title"]) > 0
        assert len(item["why_it_matters"]) > 0
        assert len(item["manual_guide"]) > 0
        assert len(item["live_status"]) > 0


@pytest.mark.asyncio
async def test_checklist_api_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. GET /api/security/checklist
        res = await ac.get("/api/security/checklist")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert len(data["items"]) == 11

        # 2. POST /api/security/checklist/apply-sensors-zero-internet
        res_sensors = await ac.post("/api/security/checklist/apply-sensors-zero-internet", json={"block": True})
        assert res_sensors.status_code == 200
        data_sensors = res_sensors.json()
        assert data_sensors["status"] == "ok"
        assert data_sensors["blocked"] is True

        # Revert sensors
        res_revert = await ac.post("/api/security/checklist/apply-sensors-zero-internet", json={"block": False})
        assert res_revert.status_code == 200
        assert res_revert.json()["blocked"] is False

        # 3. POST /api/security/checklist/apply-appliances-lan-isolation
        res_app = await ac.post("/api/security/checklist/apply-appliances-lan-isolation", json={"isolate": True})
        assert res_app.status_code == 200
        data_app = res_app.json()
        assert data_app["status"] == "ok"
        assert data_app["requested_isolate"] is True
        # Wi-Fi devices in Bridge0 cannot be isolated via software call; must report actually_isolated == 0
        assert data_app["actually_isolated"] == 0
        assert "Bridge1" in data_app["message"]

        # 4. POST /api/security/checklist/toggle-quarantine
        res_quar = await ac.post("/api/security/checklist/toggle-quarantine", json={"enable": True})
        assert res_quar.status_code == 200
        assert res_quar.json()["quarantine_active"] is True

        # 5. POST /api/security/checklist/device-toggle (Direct 1-click WAN toggle)
        res_dev_toggle = await ac.post("/api/security/checklist/device-toggle", json={
            "mac": "AA:BB:CC:DD:EE:FF",
            "target": "wan",
            "enabled": True
        })
        assert res_dev_toggle.status_code == 200
        assert res_dev_toggle.json()["target"] == "wan"
        assert res_dev_toggle.json()["enabled"] is True

        # LAN toggle on Bridge0 device must NOT falsely report enabled=True
        res_dev_toggle_lan = await ac.post("/api/security/checklist/device-toggle", json={
            "mac": "6C:1F:F7:5F:60:4A",
            "target": "lan",
            "enabled": True
        })
        assert res_dev_toggle_lan.status_code == 200
        assert res_dev_toggle_lan.json()["target"] == "lan"
        assert res_dev_toggle_lan.json()["enabled"] is False
        assert res_dev_toggle_lan.json()["success"] is False

        # 6. POST /api/security/checklist/toggle-quarantine-rule (Modular quarantine rules)
        res_rule = await ac.post("/api/security/checklist/toggle-quarantine-rule", json={
            "rule": "continuous_audit",
            "enabled": True
        })
        assert res_rule.status_code == 200
        assert res_rule.json()["status"] == "ok"
        assert res_rule.json()["settings"]["continuous_audit"] is True

        # 7. POST /api/security/checklist/apply-sensors-zero-internet with mode="autonomous_only"
        res_auto = await ac.post("/api/security/checklist/apply-sensors-zero-internet", json={
            "block": True,
            "mode": "autonomous_only"
        })
        assert res_auto.status_code == 200
        assert res_auto.json()["mode"] == "autonomous_only"


def test_classify_iot_trust_tier():
    from keenguard.core.classifier import DeviceClassifier
    from keenguard.db.models import DeviceRecord

    # 1. Environmental Air Monitor (Needs weather forecast and NTP, must not be blindly blocked)
    qp_dev = DeviceRecord(mac="50:02:91:AA:BB:CC", hostname="air-monitor-station", ip="192.168.1.101", profile="iot")
    tier_qp = DeviceClassifier.classify_iot_trust_tier(qp_dev, observed_domains=["api.weather-service.com", "pool.ntp.org"])
    assert tier_qp["tier"] == "hybrid_weather"
    assert tier_qp["weather_dependent"] is True
    assert tier_qp["wan_needed"] is True
    assert "погод" in tier_qp["impact_wan_block"].lower()

    # 2. Dumb / local IoT (Relay, soil moisture, valve, Zigbee hub)
    relay_dev = DeviceRecord(mac="84:F3:EB:11:22:33", hostname="esp-soil-moisture", ip="192.168.1.150", profile="iot")
    tier_relay = DeviceClassifier.classify_iot_trust_tier(relay_dev)
    assert tier_relay["tier"] == "pure_local"
    assert tier_relay["wan_needed"] is False
    assert "локальный" in tier_relay["tier_title"].lower()

    # 3. Cloud Appliance (Robot vacuum cleaner)
    vacuum_dev = DeviceRecord(mac="68:AB:1E:44:55:66", hostname="smart-vacuum-cleaner", ip="192.168.1.180", profile="iot")
    tier_vac = DeviceClassifier.classify_iot_trust_tier(vacuum_dev)
    assert tier_vac["tier"] == "cloud_appliance"
    assert tier_vac["wan_needed"] is True

    # 4. Central Hub / Controller (Smart Hub)
    hub_dev = DeviceRecord(mac="B8:27:EB:77:88:99", hostname="Smart-Hub-Controller", ip="192.168.1.104", profile="smart_home_hub")
    tier_hub = DeviceClassifier.classify_iot_trust_tier(hub_dev)
    assert tier_hub["tier"] == "controller"

    # 5. Smart TV Media
    tv_dev = DeviceRecord(mac="00:1C:62:01:02:03", hostname="Smart-Media-TV", ip="192.168.1.55", profile="smart_tv")
    tier_tv = DeviceClassifier.classify_iot_trust_tier(tv_dev)
    assert tier_tv["tier"] == "media_tv"

    # 6. Surveillance Camera
    cam_dev = DeviceRecord(mac="70:B3:D5:11:22:33", hostname="ipcam-outdoor-01", ip="192.168.1.70", profile="camera")
    tier_cam = DeviceClassifier.classify_iot_trust_tier(cam_dev)
    assert tier_cam["tier"] == "camera"


@pytest.mark.asyncio
async def test_security_wizard_apply_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post("/api/security/wizard/apply", json={
            "tv_night_mode": True,
            "zero_internet_sensors": True,
            "quarantine_enabled": True,
            "quarantine_continuous": True
        })
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["quarantine_active"] is True
        assert data["continuous_audit_active"] is True
        assert "tv_updated_count" in data
        assert "sensors_blocked_count" in data
        assert "Политики безопасности" in data["message"]

