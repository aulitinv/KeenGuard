# -*- coding: utf-8 -*-
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from keenguard.core.keenetic import KeeneticClient
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_keenetic_speed_limiting_methods():
    """Verify KeeneticClient bandwidth shaping methods in mock mode."""
    client = KeeneticClient(host="192.168.1.1")
    client.mock_mode = True

    mac = "AA:BB:CC:DD:EE:11"

    # Initially empty
    limits = await client.get_device_speed_limits()
    assert mac not in limits

    # Set 5 Mbps limit (5120 kbps)
    ok = await client.set_device_speed_limit(mac, 5120)
    assert ok is True

    limits = await client.get_device_speed_limits()
    assert limits.get(mac) == 5120

    # Unset limit (0 kbps)
    ok = await client.set_device_speed_limit(mac, 0)
    assert ok is True

    limits = await client.get_device_speed_limits()
    assert mac not in limits

    # Component check
    assert await client.has_traffic_shaper_component() is True


@pytest.mark.asyncio
async def test_db_speed_limit_persistence(tmp_path):
    """Verify speed limit is stored and retrieved in DeviceRecord."""
    test_db = Database(db_path=tmp_path / "test_shaping.db")
    await test_db.init_db()

    mac = "AA:BB:CC:DD:EE:22"
    dev = DeviceRecord(
        mac=mac,
        ip="192.168.1.222",
        hostname="Client-PC",
        profile="trusted",
        is_online=True,
        bandwidth_limit_kbps=0
    )
    await test_db.upsert_device(dev)

    loaded = await test_db.get_device(mac)
    assert loaded is not None
    assert loaded.bandwidth_limit_kbps == 0

    # Update limit to 15 Mbps (15360 kbps)
    ok = await test_db.update_device_speed_limit(mac, 15360)
    assert ok is True

    updated = await test_db.get_device(mac)
    assert updated is not None
    assert updated.bandwidth_limit_kbps == 15360


@pytest.mark.asyncio
async def test_api_speed_limit_endpoint(tmp_path):
    """Verify /api/devices/{mac}/speed-limit endpoint with TestClient."""
    test_db = Database(db_path=tmp_path / "test_api_shaping.db")
    await test_db.init_db()

    mac = "AA:BB:CC:DD:EE:33"
    dev = DeviceRecord(
        mac=mac,
        ip="192.168.1.130",
        hostname="Smart-TV-Box",
        profile="smart_tv",
        is_online=True
    )
    await test_db.upsert_device(dev)

    mock_client = KeeneticClient(host="192.168.1.1")
    mock_client.mock_mode = True

    with patch("keenguard.web.routes.devices.get_db", return_value=test_db), \
         patch("keenguard.web.state.get_keenetic_client", return_value=mock_client):

        client = TestClient(app)

        # 1. Set 512 kbps limit (IoT preset)
        resp = client.post(f"/api/devices/{mac}/speed-limit", json={"speed_kbps": 512})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["speed_limit_kbps"] == 512

        # Verify DB updated
        d = await test_db.get_device(mac)
        assert d.bandwidth_limit_kbps == 512

        # Verify mock client updated
        client_limits = await mock_client.get_device_speed_limits()
        assert client_limits.get(mac) == 512

        # 2. Test failure when shaper component is missing
        with patch.object(mock_client, "has_traffic_shaper_component", AsyncMock(return_value=False)):
            resp_err = client.post(f"/api/devices/{mac}/speed-limit", json={"speed_kbps": 1024})
            assert resp_err.status_code == 400
            assert "Шейпер трафика" in resp_err.json()["detail"]
