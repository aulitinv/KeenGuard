"""Tests verifying fixes for Wi-Fi encryption detection and IoT storage settings."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from keenguard.core.keenetic import KeeneticClient
from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.checklist import SecurityChecklistEvaluator
from keenguard.core.checklist.context import ChecklistContext
from keenguard.core.checklist.network_checks import evaluate_wifi_security
from keenguard.config import settings
from keenguard.db.database import Database


@pytest.mark.asyncio
async def test_keenetic_wifi_wpa3_mixed_detection():
    """Verify that Keenetic encryption='wpa2,wpa3' is correctly identified as WPA3/WPA2 mixed."""
    client = KeeneticClient(host="192.168.1.1", user="admin", password="password")
    client.mock_mode = False

    raw_response = [
        {
            "show": {
                "interface": {
                    "Bridge0": {
                        "type": "Bridge",
                        "state": "up",
                        "link": "up",
                        "security-level": "private"
                    },
                    "Bridge1": {
                        "type": "Bridge",
                        "state": "up",
                        "link": "up",
                        "security-level": "protected"
                    },
                    "WifiMaster0/AccessPoint0": {
                        "type": "AccessPoint",
                        "state": "up",
                        "link": "up",
                        "ssid": "Test-Home-2.4",
                        "encryption": "wpa2,wpa3",
                        "auth-type": "none",
                        "pmf": "optional"
                    },
                    "WifiMaster1/AccessPoint0": {
                        "type": "AccessPoint",
                        "state": "up",
                        "link": "up",
                        "ssid": "Test-Home-5G",
                        "encryption": "wpa2,wpa3",
                        "auth-type": "none"
                    }
                }
            }
        }
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = raw_response

    with patch.object(client, "_send_request", new=AsyncMock(return_value=mock_resp)):
        wifi = await client.get_wifi_security()

    assert wifi["grade"] in ("A+", "A")
    assert wifi["score"] >= 80
    assert len(wifi["access_points"]) == 2

    ap0 = wifi["access_points"][0]
    assert ap0["ssid"] == "Test-Home-2.4"
    assert ap0["security"] == "WPA3 / WPA2 mixed"
    assert ap0["security_type"] == "wpa3_mixed"
    assert ap0["pmf"] == "optional"

    ap1 = wifi["access_points"][1]
    assert ap1["ssid"] == "Test-Home-5G"
    assert ap1["security"] == "WPA3 / WPA2 mixed"
    assert ap1["security_type"] == "wpa3_mixed"

    # Guest network with security-level: protected must be marked as isolated
    assert wifi["guest_network"]["configured"] is True
    assert wifi["guest_network"]["isolated"] is True
    assert wifi["guest_isolation_enabled"] is True


@pytest.mark.asyncio
async def test_keenetic_wifi_explicit_open_detection():
    """Verify that a network with encryption='none' or 'open' is correctly flagged as open."""
    client = KeeneticClient(host="192.168.1.1", user="admin", password="password")
    client.mock_mode = False

    raw_response = [
        {
            "show": {
                "interface": {
                    "WifiMaster0/AccessPoint0": {
                        "type": "AccessPoint",
                        "state": "up",
                        "link": "up",
                        "ssid": "Public-Coffee",
                        "encryption": "none",
                        "auth-type": "none"
                    }
                }
            }
        }
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = raw_response

    with patch.object(client, "_send_request", new=AsyncMock(return_value=mock_resp)):
        wifi = await client.get_wifi_security()

    assert wifi["score"] <= 60
    assert any("открытая" in r.lower() for r in wifi["recommendations"])
    assert wifi["access_points"][0]["security_type"] == "open"
    assert "Открытая" in wifi["access_points"][0]["security"]


@pytest.mark.asyncio
async def test_openwrt_wifi_dual_key_compatibility():
    """Verify that OpenWrt get_wifi_security returns both access_points and networks."""
    backend = OpenWrtBackend(host="10.0.0.1")

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "uci" and method == "get":
            return {
                "values": {
                    "wifinet0": {
                        ".type": "wifi-iface",
                        "ssid": "OpenWrt_Main",
                        "encryption": "sae-mixed",
                        "key": "SecretPassword123",
                        "isolate": "0"
                    }
                }
            }
        return {}

    backend._call_ubus = mock_call
    audit = await backend.get_wifi_security()

    assert "access_points" in audit
    assert "networks" in audit
    assert audit["access_points"] == audit["networks"]
    assert len(audit["access_points"]) == 1

    net = audit["access_points"][0]
    assert net["ssid"] == "OpenWrt_Main"
    assert net["security"] == "WPA3 / WPA2 mixed"
    assert net["encryption"] == "WPA3 / WPA2 mixed"
    assert net["security_type"] == "wpa3"


@pytest.mark.asyncio
async def test_checklist_wifi_security_evaluation():
    """Verify that checklist evaluator handles WPA3 mixed and open network risks."""
    ctx = ChecklistContext()
    ctx.wifi_security = {
        "access_points": [
            {
                "ssid": "Home-WiFi",
                "security": "WPA3 / WPA2 mixed",
                "security_type": "wpa3_mixed",
                "pmf": "required"
            }
        ]
    }
    res = evaluate_wifi_security(ctx)
    assert res["status"] == "ok"
    assert "WPA3" in res["live_status"]

    # Now test open network
    ctx.wifi_security = {
        "access_points": [
            {
                "ssid": "Insecure-Free-WiFi",
                "security": "Открытая (Без пароля)",
                "security_type": "open",
                "pmf": "disabled"
            }
        ]
    }
    res_open = evaluate_wifi_security(ctx)
    assert res_open["status"] == "critical"
    assert "Insecure-Free-WiFi" in res_open["live_status"]


@pytest.mark.asyncio
async def test_iot_storage_settings_db_persistence(tmp_path):
    """Verify that IoT storage settings can be saved and restored from app_settings."""
    db_file = tmp_path / "test_keenguard.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    # Save custom storage parameters
    await test_db.save_setting("iot_payload_max_storage_gb", "5.0")
    await test_db.save_setting("iot_payload_retention_days", "30")
    await test_db.save_setting("iot_payload_capture_enabled", "true")

    # Read back
    saved_gb = await test_db.get_setting("iot_payload_max_storage_gb")
    saved_days = await test_db.get_setting("iot_payload_retention_days")
    saved_cap = await test_db.get_setting("iot_payload_capture_enabled")

    assert float(saved_gb) == 5.0
    assert int(saved_days) == 30
    assert saved_cap == "true"
    await test_db.close()
