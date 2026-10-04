"""Tests for Plan 09: Interactive Network Topology Map."""
import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord
from keenguard.core.keenetic import keenetic_client


@pytest.mark.asyncio
async def test_network_topology_endpoint(monkeypatch):
    keenetic_client.mock_mode = True
    await db.init_db()

    # Insert test devices in DB
    await db.upsert_device(DeviceRecord(
        mac="00:11:22:33:44:55",
        ip="192.168.1.110",
        hostname="Home-PC",
        custom_name="Рабочий ПК",
        profile="trusted",
        vendor="Intel",
        is_online=True,
        is_blocked_wan=False,
    ))
    await db.upsert_device(DeviceRecord(
        mac="AA:BB:CC:DD:EE:01",
        ip="192.168.1.222",
        hostname="Malicious-Camera",
        profile="quarantine",
        vendor="Dahua",
        is_online=True,
        is_blocked_wan=True,
        is_isolated_lan=True,
    ))

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/network/topology")
        assert resp.status_code == 200
        data = resp.json()

        assert "nodes" in data
        assert "links" in data
        assert "meta" in data

        node_ids = {n["id"] for n in data["nodes"]}
        # Core infrastructure nodes
        assert "node_internet" in node_ids
        assert "node_dns" in node_ids
        assert "node_router" in node_ids

        # Segments
        assert "segment_Bridge0" in node_ids
        assert "segment_Bridge1" in node_ids

        # Access points / interfaces
        assert "ap_wifi_24" in node_ids
        assert "ap_wifi_5" in node_ids
        assert "ap_lan" in node_ids
        assert "ap_guest" in node_ids

        # Check devices
        dev_home = next((n for n in data["nodes"] if n.get("mac") == "00:11:22:33:44:55"), None)
        assert dev_home is not None
        assert dev_home["segment_id"] == "segment_Bridge0"
        assert dev_home["label"] == "Рабочий ПК"
        assert dev_home["is_online"] is True

        dev_quar = next((n for n in data["nodes"] if n.get("mac") == "AA:BB:CC:DD:EE:01"), None)
        assert dev_quar is not None
        assert dev_quar["segment_id"] == "segment_Bridge1"
        assert dev_quar["is_wan_blocked"] is True

        # Check Links
        link_targets = {l["target"] for l in data["links"]}
        assert "node_router" in link_targets
        assert "segment_Bridge0" in link_targets
        assert dev_home["id"] in link_targets
        assert dev_quar["id"] in link_targets

        # Check Technical Realism disclosure
        assert "l2_realism_note" in data["meta"]
        assert "Bridge0" in data["meta"]["l2_realism_note"]
        assert "Bridge1" in data["meta"]["l2_realism_note"]
