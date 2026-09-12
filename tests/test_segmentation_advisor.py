import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, MagicMock

from keenguard.core.keenetic import keenetic_client
from keenguard.db.models import DeviceRecord
from keenguard.db.database import db
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_evaluate_segment_risk_logic():
    """Test L2 physical segmentation risk evaluation across device profiles."""
    # 1. IoT / Camera on Home (Bridge0) -> High risk of L2 bypass
    risk_iot_home = keenetic_client.evaluate_segment_risk("iot", "Home", "192.168.1.50")
    assert risk_iot_home["risk_level"] == "high"
    assert risk_iot_home["is_isolated"] is False
    assert "Bridge0" in risk_iot_home["recommendation"] or "обход файрвола" in risk_iot_home["recommendation"]

    risk_cam_home = keenetic_client.evaluate_segment_risk("camera", "Home", "192.168.1.60")
    assert risk_cam_home["risk_level"] == "high"
    assert risk_cam_home["is_isolated"] is False

    # 2. IoT / Camera on Guest -> Low risk (Physically isolated)
    risk_iot_guest = keenetic_client.evaluate_segment_risk("iot", "Guest", "192.168.2.50")
    assert risk_iot_guest["risk_level"] == "low"
    assert risk_iot_guest["is_isolated"] is True

    # 3. Smart TV on Home -> Medium risk (Open L2 for Cast/DLNA)
    risk_tv_home = keenetic_client.evaluate_segment_risk("smart_tv", "Home", "192.168.1.70")
    assert risk_tv_home["risk_level"] == "medium"
    assert risk_tv_home["is_isolated"] is False
    assert "AirPlay" in risk_tv_home["recommendation"] or "DLNA" in risk_tv_home["recommendation"]

    # 4. Smart TV on Guest -> Low risk
    risk_tv_guest = keenetic_client.evaluate_segment_risk("smart_tv", "Guest", "192.168.2.70")
    assert risk_tv_guest["risk_level"] == "low"
    assert risk_tv_guest["is_isolated"] is True

    # 5. Trusted PC on Home -> Low risk
    risk_pc_home = keenetic_client.evaluate_segment_risk("trusted", "Home", "192.168.1.100")
    assert risk_pc_home["risk_level"] == "low"


@pytest.mark.asyncio
async def test_get_network_segments_mock():
    """Test get_network_segments returns valid router bridges in mock mode."""
    with patch.object(keenetic_client, "mock_mode", True):
        segments = await keenetic_client.get_network_segments()
        assert len(segments) >= 2
        seg_ids = [s["id"] for s in segments]
        seg_ifaces = [s["interface"] for s in segments]
        assert "Home" in seg_ids
        assert "Bridge0" in seg_ifaces
        assert "Bridge1" in seg_ifaces


@pytest.mark.asyncio
async def test_security_segments_api():
    """Test GET /api/security/segments endpoint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/security/segments")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "segments" in data
        assert "devices" in data
        assert "devices_at_risk_count" in data
        assert isinstance(data["devices_at_risk"], list)
