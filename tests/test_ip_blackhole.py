import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from keenguard.core.keenetic import KeeneticClient
from keenguard.db.database import Database
from keenguard.web.app import app, check_ip_cdn_status

@pytest.mark.asyncio
async def test_keenetic_client_ip_blackhole_mock():
    """Verify add_ip_blackholes, remove_ip_blackholes, and get_active_ip_blackholes in mock mode."""
    client = KeeneticClient()
    client.mock_mode = True

    # 1. Reject private/LAN or invalid IP
    succeeded, failed = await client.add_ip_blackholes(["192.168.1.1", "not-an-ip", "10.0.0.5"])
    assert len(succeeded) == 0
    assert len(failed) == 3

    # 2. Add valid public IPv4
    test_ip = "198.51.100.50"
    succeeded, failed = await client.add_ip_blackholes([test_ip])
    assert test_ip in succeeded
    assert len(failed) == 0

    # 3. Verify active blackholes contains test_ip
    active = await client.get_active_ip_blackholes()
    assert test_ip in active

    # 4. Remove blackhole
    succeeded, failed = await client.remove_ip_blackholes([test_ip])
    assert test_ip in succeeded
    assert len(failed) == 0

    active_after = await client.get_active_ip_blackholes()
    assert test_ip not in active_after

@pytest.mark.asyncio
async def test_database_ip_blackhole_records(tmp_path):
    """Verify SQLite persistence for IP blackhole rules."""
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()

    # 1. Add record
    await test_db.add_ip_blackhole_record(
        ip="198.51.100.99",
        reason="Port Scanner C2",
        provider="Dedicated Server",
        country="US",
        flag="🇺🇸",
        is_cdn=False
    )

    # 2. Retrieve records
    rules = await test_db.get_ip_blackholes()
    assert len(rules) == 1
    assert rules[0]["ip"] == "198.51.100.99"
    assert rules[0]["reason"] == "Port Scanner C2"
    assert rules[0]["is_cdn"] == 0

    # 3. Delete record
    await test_db.delete_ip_blackhole_record("198.51.100.99")
    rules_after = await test_db.get_ip_blackholes()
    assert len(rules_after) == 0

def test_check_ip_cdn_status():
    """Verify CDN classification against known cloud provider IP ranges."""
    # Cloudflare IP
    is_cdn, provider, _ = check_ip_cdn_status("104.16.1.1")
    assert is_cdn is True
    assert "Cloudflare" in provider

    # Non-CDN IP
    is_cdn, provider, _ = check_ip_cdn_status("198.51.100.1")
    assert is_cdn is False

def test_api_check_ip_blackhole_preflight():
    """Verify POST /api/firewall/ip_blackhole/check endpoint validation."""
    client = TestClient(app)

    # Reject private/LAN
    resp = client.post("/api/firewall/ip_blackhole/check", json={"ip": "192.168.1.1"})
    assert resp.status_code == 400
    assert "Запрещено" in resp.json()["detail"]

    # Reject loopback
    resp = client.post("/api/firewall/ip_blackhole/check", json={"ip": "127.0.0.1"})
    assert resp.status_code == 400

    # Reject invalid format
    resp = client.post("/api/firewall/ip_blackhole/check", json={"ip": "bad_ip_address"})
    assert resp.status_code == 400

    # CDN IP detection
    resp = client.post("/api/firewall/ip_blackhole/check", json={"ip": "104.16.1.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_cdn"] is True
    assert data["warning"] is not None

    # Dedicated non-CDN IP
    resp = client.post("/api/firewall/ip_blackhole/check", json={"ip": "198.51.100.77"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_cdn"] is False
    assert data["warning"] is None

def test_api_block_and_unblock_ip_blackhole():
    """Verify block, list, and unblock endpoints with CDN 409 conflict handling."""
    client = TestClient(app)

    # 1. CDN blocking without force_cdn must return 409 Conflict
    resp = client.post("/api/firewall/ip_blackhole/block", json={"ip": "104.16.2.2", "force_cdn": False})
    assert resp.status_code == 409
    assert "CDN" in resp.json()["detail"]

    # 2. CDN blocking with force_cdn must succeed
    resp = client.post("/api/firewall/ip_blackhole/block", json={"ip": "104.16.2.2", "force_cdn": True, "reason": "Test force CDN"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    # 3. Verify rule appears in GET /api/firewall/ip_blackholes
    resp = client.get("/api/firewall/ip_blackholes")
    assert resp.status_code == 200
    rules = resp.json()["rules"]
    assert any(r["ip"] == "104.16.2.2" for r in rules)

    # 4. Unblock
    resp = client.post("/api/firewall/ip_blackhole/unblock", json={"ip": "104.16.2.2"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

def test_api_investigator_block_ip():
    """Verify Incident Investigator IP block endpoint."""
    client = TestClient(app)

    # Reject private IP
    resp = client.post("/api/investigator/block_ip", json={"ip": "192.168.1.1"})
    assert resp.status_code == 400

    # CDN IP returns cdn_warning when force_cdn is False
    resp = client.post("/api/investigator/block_ip", json={"ip": "104.16.3.3", "force_cdn": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "cdn_warning"

    # CDN IP with force_cdn succeeds
    resp = client.post("/api/investigator/block_ip", json={"ip": "104.16.3.3", "force_cdn": True})
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    # Cleanup
    client.post("/api/firewall/ip_blackhole/unblock", json={"ip": "104.16.3.3"})
