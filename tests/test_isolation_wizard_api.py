import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord


@pytest.mark.asyncio
async def test_isolation_guide_endpoint():
    """Verifies isolation guide returns real physical steps for Bridge0 vs isolated devices."""
    test_mac = "AA:BB:CC:DD:EE:11"
    # Seed a device
    await db.upsert_device(DeviceRecord(
        mac=test_mac,
        ip="192.168.1.150",
        hostname="Test-Wired-Camera",
        custom_name="Camera 1",
        interface="Bridge0",
        is_isolated_lan=False
    ))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Fetch isolation guide
        res = await client.get(f"/api/devices/{test_mac}/isolation_guide")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["mac"] == test_mac
        assert data["is_physically_isolated"] is False
        assert len(data["steps"]) >= 2

        # 2. Try toggle LAN on Bridge0 device
        toggle_res = await client.post(f"/api/devices/{test_mac}/toggle_lan", json={"enabled": True})
        assert toggle_res.status_code == 200
        toggle_data = toggle_res.json()
        assert toggle_data["needs_physical_segmentation"] is True
        assert toggle_data["isolated_lan"] is False
        assert "Bridge0" in toggle_data["message"]
