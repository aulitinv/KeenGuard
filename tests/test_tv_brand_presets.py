"""Tests for Smart TV Brand DNS Sinkhole Presets (Plan 01)."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from keenguard.core.domain_analyzer import (
    TV_BRAND_PRESETS,
    detect_tv_brand,
    get_tv_brand_presets
)
from keenguard.web.app import app
from keenguard.core.keenetic import keenetic_client
from keenguard.db.database import db


def test_tv_brand_presets_catalog_integrity():
    """Verify that all 5 Smart TV brand presets are complete, well-formed, and exclude critical services."""
    required_presets = ["tv_lg", "tv_samsung", "tv_android_google", "tv_xiaomi", "tv_apple"]
    for pid in required_presets:
        assert pid in TV_BRAND_PRESETS, f"Preset {pid} missing from TV_BRAND_PRESETS"
        preset = TV_BRAND_PRESETS[pid]
        assert preset["name"]
        assert preset["icon"]
        assert isinstance(preset["keywords"], list) and len(preset["keywords"]) > 0
        assert preset["manual_hint"]
        assert isinstance(preset["domains"], list) and len(preset["domains"]) > 0

        for item in preset["domains"]:
            dom = item["domain"]
            assert dom == dom.lower().strip()
            assert "." in dom
            assert item["name"]
            assert item["category"] in ("advertising", "telemetry")
            assert item["risk"] in ("ad", "telemetry")
            assert item["description"]

    # Strict check: Critical ecosystem domains MUST NEVER be blocked
    forbidden_domains = {
        "play.google.com",
        "android.clients.google.com",
        "connectivitycheck.gstatic.com",
        "apple.com",
        "icloud.com",
        "appleid.apple.com",
        "push.apple.com",
        "appletv.apple.com"
    }
    all_domains = set()
    for p in TV_BRAND_PRESETS.values():
        for item in p["domains"]:
            all_domains.add(item["domain"])

    intersect = all_domains.intersection(forbidden_domains)
    assert not intersect, f"Forbidden critical domains found in TV presets: {intersect}"


def test_detect_tv_brand_heuristics():
    """Test device brand detection based on hostname, vendor, custom_name, model."""
    # 1. LG Smart TV
    assert detect_tv_brand({"hostname": "LGwebOSTV-4K", "vendor": "LG Electronics"}) == "tv_lg"
    assert detect_tv_brand({"custom_name": "Телевизор в спальне (LG OLED)"}) == "tv_lg"

    # 2. Samsung Tizen
    assert detect_tv_brand({"hostname": "Samsung-QLED-Living", "vendor": "Samsung Electronics Co.,Ltd"}) == "tv_samsung"
    assert detect_tv_brand({"model": "Tizen Smart Hub TV"}) == "tv_samsung"

    # 3. Android / Google TV
    assert detect_tv_brand({"hostname": "BRAVIA-4K-Android", "vendor": "Sony Corporation"}) == "tv_android_google"
    assert detect_tv_brand({"custom_name": "Приставка Google Chromecast"}) == "tv_android_google"
    assert detect_tv_brand({"hostname": "TCL-GoogleTV"}) == "tv_android_google"

    # 4. Xiaomi PatchWall / Mi TV
    assert detect_tv_brand({"hostname": "MiTV-PatchWall-Living", "vendor": "Xiaomi Communications"}) == "tv_xiaomi"
    assert detect_tv_brand({"custom_name": "Xiaomi Mi Box S"}) == "tv_xiaomi"

    # 5. Apple TV
    assert detect_tv_brand({"custom_name": "Apple TV 4K", "vendor": "Apple, Inc."}) == "tv_apple"
    assert detect_tv_brand({"hostname": "appletv-livingroom"}) == "tv_apple"

    # 6. Non-TV Apple device should NOT match tv_apple
    assert detect_tv_brand({"custom_name": "iPhone Alex", "hostname": "iPhone-15", "vendor": "Apple, Inc."}) is None

    # 7. Generic or empty device
    assert detect_tv_brand({}) is None
    assert detect_tv_brand({"hostname": "DESKTOP-ALEX", "vendor": "ASUSTek"}) is None


def test_get_tv_brand_presets_enrichment():
    """Test get_tv_brand_presets with empty and active router sinkhole sets."""
    # Empty sinkholes
    presets = get_tv_brand_presets(active_sinkholes=set())
    assert len(presets) == 5
    for p in presets:
        assert p["active_count"] == 0
        assert p["is_fully_blocked"] is False
        for d in p["domains"]:
            assert d["is_active"] is False

    # Partial active sinkholes
    active = {"emp.lgsmartad.com", "samsungacr.com", "ad.xiaomi.com"}
    enriched = get_tv_brand_presets(active_sinkholes=active)
    lg = next(p for p in enriched if p["id"] == "tv_lg")
    samsung = next(p for p in enriched if p["id"] == "tv_samsung")
    xiaomi = next(p for p in enriched if p["id"] == "tv_xiaomi")
    apple = next(p for p in enriched if p["id"] == "tv_apple")

    assert lg["active_count"] == 1
    assert any(d["domain"] == "emp.lgsmartad.com" and d["is_active"] is True for d in lg["domains"])
    assert samsung["active_count"] == 1
    assert any(d["domain"] == "samsungacr.com" and d["is_active"] is True for d in samsung["domains"])
    assert xiaomi["active_count"] == 1
    assert apple["active_count"] == 0


@pytest.mark.asyncio
async def test_api_get_tv_brand_presets():
    """Test GET /api/tv/brand_presets endpoint with simulated devices and router sinkholes."""
    mock_devices = [
        {
            "mac": "AA:BB:CC:11:22:33",
            "ip": "192.168.1.105",
            "hostname": "LGwebOSTV",
            "custom_name": "LG OLED C2",
            "vendor": "LG Electronics",
            "profile": "smart_tv",
            "is_online": True
        },
        {
            "mac": "11:22:33:44:55:66",
            "ip": "192.168.1.50",
            "hostname": "Desktop-PC",
            "custom_name": "Alex PC",
            "vendor": "Intel",
            "profile": "workstation",
            "is_online": True
        }
    ]

    with patch.object(keenetic_client, "get_active_sinkholes", new_callable=AsyncMock) as mock_get_sinkholes, \
         patch.object(db, "get_all_devices", new_callable=AsyncMock) as mock_get_devices:
        mock_get_sinkholes.return_value = ["emp.lgsmartad.com", "lgtvcommon.com"]
        mock_get_devices.return_value = mock_devices

        client = TestClient(app)
        resp = client.get("/api/tv/brand_presets")
        assert resp.status_code == 200
        data = resp.json()

        assert data["status"] == "ok"
        assert data["suggested_brand"] == "tv_lg"
        assert data["active_sinkholes_count"] == 2
        assert "streaming_ads_note" in data

        lg_preset = next(p for p in data["presets"] if p["id"] == "tv_lg")
        assert lg_preset["active_count"] == 2
        assert len(lg_preset["detected_devices"]) == 1
        assert lg_preset["detected_devices"][0]["ip"] == "192.168.1.105"


@pytest.mark.asyncio
async def test_api_block_and_unblock_tv_preset():
    """Test POST /api/tv/sinkhole/block_preset and unblock_preset."""
    with patch.object(keenetic_client, "add_dns_sinkholes", new_callable=AsyncMock) as mock_add, \
         patch.object(keenetic_client, "remove_dns_sinkholes", new_callable=AsyncMock) as mock_remove:

        mock_add.return_value = (["emp.lgsmartad.com", "lgtvcommon.com"], [])
        mock_remove.return_value = (["emp.lgsmartad.com", "lgtvcommon.com"], [])

        client = TestClient(app)

        # 1. Block LG preset (all)
        resp_block = client.post("/api/tv/sinkhole/block_preset", json={"preset": "tv_lg", "save_config": True})
        assert resp_block.status_code == 200
        data_block = resp_block.json()
        assert data_block["status"] == "ok"
        assert data_block["preset"] == "tv_lg"
        assert len(data_block["blocked"]) == 2
        mock_add.assert_called_once()

        # 1b. Block LG preset (only_safe=True)
        mock_add.reset_mock()
        resp_safe = client.post("/api/tv/sinkhole/block_preset", json={"preset": "tv_lg", "only_safe": True})
        assert resp_safe.status_code == 200
        mock_add.assert_called_once()
        passed_domains = mock_add.call_args[0][0]
        # Verify cautious domains like aic.lgtvcommon.com are excluded
        assert "aic.lgtvcommon.com" not in passed_domains
        assert "emp.lgsmartad.com" in passed_domains

        # 2. Unblock LG preset
        resp_unblock = client.post("/api/tv/sinkhole/unblock_preset", json={"preset": "tv_lg", "save_config": True})
        assert resp_unblock.status_code == 200
        data_unblock = resp_unblock.json()
        assert data_unblock["status"] == "ok"
        assert data_unblock["preset"] == "tv_lg"
        mock_remove.assert_called_once()

        # 3. Invalid preset
        resp_invalid = client.post("/api/tv/sinkhole/block_preset", json={"preset": "nonexistent_tv"})
        assert resp_invalid.status_code == 400


@pytest.mark.asyncio
async def test_api_toggle_sinkhole_domain():
    """Test POST /api/tv/sinkhole/toggle for individual domain rules."""
    with patch.object(keenetic_client, "add_dns_sinkhole", new_callable=AsyncMock) as mock_add, \
         patch.object(keenetic_client, "remove_dns_sinkhole", new_callable=AsyncMock) as mock_remove:

        mock_add.return_value = True
        mock_remove.return_value = True

        client = TestClient(app)

        # 1. Toggle ON (block)
        res_on = client.post("/api/tv/sinkhole/toggle", json={"domain": "samsungacr.com", "block": True})
        assert res_on.status_code == 200
        assert res_on.json()["action"] == "blocked"
        assert res_on.json()["is_active"] is True
        mock_add.assert_called_once_with("samsungacr.com")

        # 2. Toggle OFF (unblock)
        res_off = client.post("/api/tv/sinkhole/toggle", json={"domain": "samsungacr.com", "block": False})
        assert res_off.status_code == 200
        assert res_off.json()["action"] == "unblocked"
        assert res_off.json()["is_active"] is False
        mock_remove.assert_called_once_with("samsungacr.com")

        # 3. Invalid domain format
        res_bad = client.post("/api/tv/sinkhole/toggle", json={"domain": "invalid_domain_no_dot", "block": True})
        assert res_bad.status_code == 400
