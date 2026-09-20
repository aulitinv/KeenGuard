"""Tests for Phase 1 hardening: data extraction, concurrency lock, ws debounce, MAC validation."""
import asyncio
import time
import pytest
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from keenguard.web.app import app
from keenguard.core.classifier import OUI_DATABASE, DeviceClassifier, is_valid_mac
from keenguard.core.audit import CIDR_PROVIDERS, KNOWN_SERVICES, KNOWN_PROVIDERS
from keenguard.core.investigator import KNOWN_SYSTEM_SERVICES
from keenguard.web.workers import get_poll_lock, do_keenetic_poll
from keenguard.web.ws import REFRESH_DEBOUNCE_SECONDS, MAX_WS_MESSAGES_PER_SECOND


def test_static_data_catalogs_loaded():
    """Verify all static data catalogs are loaded properly from keenguard/data/*.json."""
    # 1. OUI Database
    assert len(OUI_DATABASE) >= 30
    assert "Keenetic Limited" in OUI_DATABASE
    prefixes, profile = OUI_DATABASE["Keenetic Limited"]
    assert "50:FF:20" in prefixes
    assert profile == "trusted"

    # 2. CIDR Providers
    assert len(CIDR_PROVIDERS) >= 70
    assert len(KNOWN_PROVIDERS) == len(CIDR_PROVIDERS)
    first_net, name, country, flag = CIDR_PROVIDERS[0]
    assert hasattr(first_net, "num_addresses")

    # 3. Known Services
    assert len(KNOWN_SERVICES) >= 15
    assert 53 in KNOWN_SERVICES
    assert KNOWN_SERVICES[53]["name"].startswith("DNS")
    assert 443 in KNOWN_SERVICES
    assert KNOWN_SERVICES[443]["encrypted"] is True

    # 4. Known System Services
    assert len(KNOWN_SYSTEM_SERVICES) >= 3
    assert any(s["category"] == "system_crl_ocsp" for s in KNOWN_SYSTEM_SERVICES)


def test_is_valid_mac():
    """Verify MAC address format validation."""
    valid_macs = [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
        "aa:bb:cc:dd:ee:ff",
        "AA-BB-CC-DD-EE-FF",
        "12:34:56:78:9A:BC",
    ]
    for m in valid_macs:
        assert is_valid_mac(m) is True
        assert DeviceClassifier.is_valid_mac(m) is True

    invalid_macs = [
        "",
        None,
        "not-a-mac",
        "192.168.1.1",
        "00:11:22:33:44",
        "00:11:22:33:44:55:66",
        "GG:11:22:33:44:55",
        "00:11:22:33:44:5Z",
        "../../etc/passwd",
    ]
    for m in invalid_macs:
        assert is_valid_mac(m) is False
        assert DeviceClassifier.is_valid_mac(m) is False


@pytest.mark.asyncio
async def test_api_rejects_invalid_mac():
    """Verify REST API returns 400 Bad Request when passed a malformed MAC address."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # GET /api/devices/{mac}
        r_get = await client.get("/api/devices/invalid-mac")
        assert r_get.status_code == 400
        assert "Invalid MAC address" in r_get.json()["detail"]

        # DELETE /api/devices/{mac}
        r_del = await client.delete("/api/devices/not-valid-mac")
        assert r_del.status_code == 400

        # POST /api/devices/{mac}/toggle_wan
        r_wan = await client.post("/api/devices/malicious'injection/toggle_wan", json={"enabled": True})
        assert r_wan.status_code == 400

        # POST /api/devices/{mac}/lan-policy
        r_lan = await client.post("/api/devices/12345/lan-policy", json={"preset_id": "preset_iot"})
        assert r_lan.status_code == 400

        # POST /api/audit/{mac}/start
        r_aud = await client.post("/api/audit/bad_mac/start", json={"duration_seconds": 60})
        assert r_aud.status_code == 400


@pytest.mark.asyncio
async def test_poll_lock_concurrency():
    """Verify that get_poll_lock returns a functional lock and do_keenetic_poll acquires it."""
    lock = get_poll_lock()
    assert isinstance(lock, asyncio.Lock)
    assert not lock.locked()

    # Verify do_keenetic_poll runs cleanly without lock contention
    await do_keenetic_poll()
    assert not lock.locked()


def test_ws_debounce_and_rate_limit():
    """Verify WebSocket client debounce for refresh command."""
    client = TestClient(app)
    with client.websocket_connect("/ws/live") as ws:
        # First refresh -> should start polling
        ws.send_json({"command": "refresh"})
        resp1 = ws.receive_json()
        assert resp1["type"] == "refresh_ack"
        assert resp1["status"] == "polling_started"

        # Immediate second refresh -> should be debounced
        ws.send_json({"command": "refresh"})
        resp2 = ws.receive_json()
        assert resp2["type"] == "refresh_ack"
        assert resp2["status"] == "debounced"

        # Ping heartbeat should work regardless
        ws.send_json({"command": "ping"})
        resp3 = ws.receive_json()
        assert resp3["type"] == "pong"

        # Start audit with invalid MAC should fail validation
        ws.send_json({"command": "start_audit", "mac": "invalid_mac"})
        resp4 = ws.receive_json()
        assert resp4["type"] == "error"
        assert "Valid MAC" in resp4["message"]
