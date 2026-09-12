"""Tests for Device Traffic Audit Manager and Forensics."""
import pytest
from keenguard.core.audit import identify_provider, AuditSession, TrafficAuditManager
from keenguard.db.database import Database
from pathlib import Path
import tempfile
import asyncio

def test_identify_provider():
    assert "Alibaba" in identify_provider("47.91.78.162")
    assert "Tuya" in identify_provider("152.32.227.164")
    assert "Telegram" in identify_provider("149.154.166.110")
    assert "Шлюз Keenetic" in identify_provider("192.168.1.1")
    assert "Локальная сеть" in identify_provider("192.168.1.50")
    assert "Внешний" in identify_provider("93.184.216.34")

def test_audit_session_nat_processing():
    session = AuditSession(
        mac="AA:BB:CC:DD:EE:FF",
        ip="192.168.1.55",
        hostname="test-iot-device",
        vendor="Test Vendor",
        duration_seconds=60
    )

    sample_nat = [
        {
            "protocol": "TCP",
            "src": "192.168.1.55",
            "dst": "47.91.78.162",
            "sport": 40120,
            "dport": 443,
            "bytes": 2048,
            "packets": 15,
            "bytes-out": 5120,
            "packets-out": 20
        },
        {
            "protocol": "TCP",
            "src": "192.168.1.55",
            "dst": "192.168.1.100",  # Lateral movement / LAN probe!
            "sport": 40122,
            "dport": 445,
            "bytes": 100,
            "packets": 2,
            "bytes-out": 0,
            "packets-out": 0
        }
    ]

    session.update_nat_entries(sample_nat)

    assert len(session.flows) == 2
    assert session.total_bytes_up == 2148
    assert session.total_bytes_down == 5120
    assert len(session.lan_probes) == 1
    assert session.lan_probes[0]["target"] == "192.168.1.100:445"

    report = session.generate_report()
    assert report["risk_level"] == "high"  # because of port 445 on LAN host!
    assert any("192.168.1.100:445" in f for f in report["findings"])
    assert report["mac"] == "AA:BB:CC:DD:EE:FF"

@pytest.mark.asyncio
async def test_traffic_audit_manager_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db_path = Path(tmpdir) / "test_audit.db"
        test_db = Database(test_db_path)
        await test_db.init_db()

        # Mock database inside audit manager
        from keenguard.core import audit
        audit.db = test_db

        mgr = TrafficAuditManager()

        # Start audit
        start_res = await mgr.start_audit(
            mac="11:22:33:44:55:66",
            ip="192.168.1.99",
            hostname="test-vacuum",
            duration_seconds=10
        )
        assert start_res["status"] == "started"
        assert mgr.get_session("11:22:33:44:55:66") is not None

        # Stop audit
        report = await mgr.stop_audit("11:22:33:44:55:66")
        assert report is not None
        assert report["hostname"] == "test-vacuum"
        assert mgr.get_session("11:22:33:44:55:66") is None

        # Check saved report in DB
        saved_reports = await test_db.get_audit_reports("11:22:33:44:55:66")
        assert len(saved_reports) == 1
        assert saved_reports[0].hostname == "test-vacuum"

def test_hub_audit_nat_discovery_and_recommendation():
    # Smart Home Hub audit session
    session = AuditSession(
        mac="00:11:22:33:44:01",
        ip="192.168.1.101",
        hostname="smart-home-hub-01",
        vendor="SmartHub",
        profile="smart_home_hub",
        duration_seconds=60
    )

    # Smart Hub normal peripheral discovery: broadcast 192.168.1.255:54321, mDNS 5353, SSDP 1900
    hub_nat = [
        {
            "protocol": "UDP",
            "src": "192.168.1.101",
            "dst": "192.168.1.255",
            "sport": 54321,
            "dport": 54321,
            "bytes": 500,
            "packets": 5,
            "bytes-out": 0,
            "packets-out": 0
        },
        {
            "protocol": "UDP",
            "src": "192.168.1.101",
            "dst": "224.0.0.251",
            "sport": 5353,
            "dport": 5353,
            "bytes": 300,
            "packets": 3,
            "bytes-out": 0,
            "packets-out": 0
        }
    ]

    session.update_nat_entries(hub_nat)

    # Broadcast discovery shouldn't be treated as unauthorized lan_probes
    assert len(session.lan_probes) == 0

    report = session.generate_report()
    # Risk should not be 'high'
    assert report["risk_level"] in ("low", "safe")
    # Finding should acknowledge hub peripheral operation
    assert any("Хаб умного дома" in f for f in report["findings"])
    # Recommendations should contain asymmetric segmentation advice
    assert any("асимметричн" in r for r in report["recommendations"])

@pytest.mark.asyncio
async def test_audit_api_endpoints(tmp_path, monkeypatch):
    """Tests /api/audit/active, start, stop, and report endpoints."""
    from keenguard.web.app import app
    from keenguard.db.database import Database
    from keenguard.db.models import DeviceRecord
    from httpx import ASGITransport, AsyncClient

    test_db = Database(db_path=tmp_path / "test_audit_api.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.core.audit.db", test_db)

    # Insert a dummy device
    await test_db.upsert_device(DeviceRecord(
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.55",
        hostname="iot-plug-test",
        vendor="IoT-Device",
        profile="iot",
        is_online=True
    ))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Active audits initially empty
        res_active = await client.get("/api/audit/active")
        assert res_active.status_code == 200
        assert res_active.json() == []

        # 2. Start audit
        res_start = await client.post("/api/audit/AA:BB:CC:11:22:33/start", json={"duration_seconds": 60})
        assert res_start.status_code == 200
        assert res_start.json()["status"] == "started"

        # 3. Active audits now contains 1 session
        res_active2 = await client.get("/api/audit/active")
        assert res_active2.status_code == 200
        active_list = res_active2.json()
        assert len(active_list) == 1
        assert active_list[0]["mac"] == "AA:BB:CC:11:22:33"

        # 4. Stop audit
        res_stop = await client.post("/api/audit/AA:BB:CC:11:22:33/stop")
        assert res_stop.status_code == 200
        report = res_stop.json()
        assert report["mac"] == "AA:BB:CC:11:22:33"

        # 5. Check reports list
        res_reports = await client.get("/api/audit/reports")
        assert res_reports.status_code == 200
        reports_list = res_reports.json()
        assert len(reports_list) >= 1
        rep_id = reports_list[0]["id"]

        # 6. Check report detail endpoint
        res_rep_detail = await client.get(f"/api/audit/report/{rep_id}")
        assert res_rep_detail.status_code == 200
        detail = res_rep_detail.json()
        assert detail["mac"] == "AA:BB:CC:11:22:33"

