"""Unit tests for router status card, Wi-Fi band detection, WAN traffic, and favicon."""
import pytest
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient

from keenguard.web.app import app
from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.routers import router_manager


@pytest.mark.asyncio
async def test_openwrt_wifi_band_detection():
    """Verify that OpenWrt get_wifi_security correctly resolves 2.4 GHz vs 5 GHz bands."""
    backend = OpenWrtBackend()

    mock_wireless_uci = {
        "values": {
            "radio0": {
                ".type": "wifi-device",
                "band": "5g",
                "channel": "36",
                "htmode": "HE160"
            },
            "radio1": {
                ".type": "wifi-device",
                "band": "2g",
                "channel": "6",
                "htmode": "HE40"
            },
            "default_radio0": {
                ".type": "wifi-iface",
                "device": "radio0",
                "ssid": "Redmi AX6000 5G",
                "encryption": "sae-mixed"
            },
            "default_radio1": {
                ".type": "wifi-iface",
                "device": "radio1",
                "ssid": "Redmi AX6000",
                "encryption": "psk2"
            }
        }
    }

    with patch.object(backend, "_call_ubus", new_callable=AsyncMock) as mock_ubus:
        mock_ubus.return_value = mock_wireless_uci
        res = await backend.get_wifi_security()

        assert res["platform"] == "openwrt"
        assert len(res["access_points"]) == 2

        ap_5g = next(ap for ap in res["access_points"] if ap["ssid"] == "Redmi AX6000 5G")
        assert ap_5g["band"] == "5 ГГц"
        assert "WPA3" in ap_5g["security"]

        ap_2g = next(ap for ap in res["access_points"] if ap["ssid"] == "Redmi AX6000")
        assert ap_2g["band"] == "2.4 ГГц"
        assert ap_2g["security"] == "WPA2-PSK"

        assert len(res["recommendations"]) > 0
        assert "RCI" not in res["recommendations"][0]


@pytest.mark.asyncio
async def test_openwrt_wan_ip_and_interface_stats():
    """Verify OpenWrt WAN IP discovery and interface statistics query."""
    backend = OpenWrtBackend()

    wan_status_mock = {
        "ipv4-address": [{"address": "198.51.100.42", "mask": 24}]
    }
    dev_status_mock = {
        "statistics": {
            "rx_bytes": 10485760,
            "tx_bytes": 5242880
        }
    }

    async def fake_ubus(subsystem, method, params=None):
        if subsystem == "network.interface.wan" and method == "status":
            return wan_status_mock
        if subsystem == "network.device" and method == "status":
            return dev_status_mock
        return {}

    with patch.object(backend, "_call_ubus", side_effect=fake_ubus):
        wan_ip = await backend.get_wan_ip()
        assert wan_ip == "198.51.100.42"

        stats = await backend.get_interface_stats("wan")
        assert stats["rx_bytes"] == 10485760
        assert stats["tx_bytes"] == 5242880


@pytest.mark.asyncio
async def test_system_status_router_fields():
    """Verify that /api/status returns model, wan_ip, memory, active_hosts."""
    client = TestClient(app)
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()

    assert "router" in data
    router_data = data["router"]
    assert "model" in router_data
    assert "platform" in router_data
    assert "version" in router_data
    assert "wan_ip" in router_data
    assert "memory" in router_data
    assert "active_hosts" in router_data


def test_favicon_endpoint_returns_svg():
    """Verify that /favicon.ico returns 200 and valid SVG content with no 404."""
    client = TestClient(app)
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert "svg" in response.headers.get("content-type", "")
    assert "<svg" in response.text
