"""Tests for Incidents and DNS queries cleanup features."""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from keenguard.db.database import Database
from keenguard.db.models import SecurityEvent, AuditReportRecord, DeviceRecord
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_database_event_deletion(tmp_path):
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()

    now = datetime.now(timezone.utc).isoformat()
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

    # Insert events
    e1_id = await test_db.record_event(SecurityEvent(
        timestamp=now, event_type="port_probe", severity="warning", description="Port 23 scan"
    ))
    e2_id = await test_db.record_event(SecurityEvent(
        timestamp=now, event_type="info_event", severity="info", description="Routine check"
    ))
    e3_id = await test_db.record_event(SecurityEvent(
        timestamp=old_ts, event_type="old_event", severity="info", description="Old log"
    ))

    # Test single event deletion
    deleted = await test_db.delete_event(e1_id)
    assert deleted is True
    remaining = await test_db.get_recent_events(limit=10)
    assert len(remaining) == 2
    assert all(e.id != e1_id for e in remaining)

    # Test clear_events by older_than_days
    cleared_old = await test_db.clear_events(older_than_days=7)
    assert cleared_old == 1
    remaining2 = await test_db.get_recent_events(limit=10)
    assert len(remaining2) == 1
    assert remaining2[0].id == e2_id

    # Test clear_events all
    cleared_all = await test_db.clear_events()
    assert cleared_all == 1
    remaining_final = await test_db.get_recent_events(limit=10)
    assert len(remaining_final) == 0


@pytest.mark.asyncio
async def test_database_dns_deletion(tmp_path):
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()

    # Insert test DNS queries
    await test_db.record_dns_query("tracker.example.com", mac="AA:BB:CC:DD:EE:01", ip="192.168.1.50")
    await test_db.record_dns_query("ads.doubleclick.net", mac="AA:BB:CC:DD:EE:02", ip="192.168.1.101")
    await test_db.record_dns_query("safe.cloud-service.com", mac="AA:BB:CC:DD:EE:03", ip="192.168.1.52")

    top_before = await test_db.get_top_dns_queries(limit=10)
    assert len(top_before) == 3

    # Delete single domain
    deleted = await test_db.delete_dns_query("tracker.example.com")
    assert deleted is True

    # Check that it is deleted from both dns_queries and dns_device_queries
    devs = await test_db.get_domain_devices("tracker.example.com")
    assert len(devs) == 0
    top_after = await test_db.get_top_dns_queries(limit=10)
    assert len(top_after) == 2
    assert all(q["domain"] != "tracker.example.com" for q in top_after)

    # Partial delete by domains list
    cleared = await test_db.clear_dns_queries(domains=["ads.doubleclick.net"])
    assert cleared == 1
    top_after2 = await test_db.get_top_dns_queries(limit=10)
    assert len(top_after2) == 1
    assert top_after2[0]["domain"] == "safe.cloud-service.com"

    # Full clear
    cleared_all = await test_db.clear_dns_queries()
    assert cleared_all == 1
    top_final = await test_db.get_top_dns_queries(limit=10)
    assert len(top_final) == 0


@pytest.mark.asyncio
async def test_api_events_and_dns_cleanup_endpoints(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_cleanup_api.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)

    client = TestClient(app)

    # 1. Test DELETE /api/events/{id} for non-existing event
    resp = client.delete("/api/events/99999999")
    assert resp.status_code == 404

    # 2. Test DELETE /api/events with severity filter
    resp_clear = client.delete("/api/events?severity=info")
    assert resp_clear.status_code == 200
    data = resp_clear.json()
    assert data["status"] == "ok"
    assert "deleted" in data

    # 3. Test DELETE /api/dns/queries with category filter
    resp_dns_cat = client.delete("/api/dns/queries?category=advertising")
    assert resp_dns_cat.status_code == 200
    cat_data = resp_dns_cat.json()
    assert cat_data["status"] == "ok"
    assert cat_data["category"] == "advertising"
    assert "deleted" in cat_data

    # 4. Test DELETE /api/dns/queries with empty body (clears all or none)
    resp_dns_all = client.delete("/api/dns/queries")
    assert resp_dns_all.status_code == 200
    all_data = resp_dns_all.json()
    assert all_data["status"] == "ok"
    assert "deleted" in all_data

    # 5. Test DELETE /api/dns/queries/{domain}
    resp_single = client.delete("/api/dns/queries/test.delete.me.com")
    assert resp_single.status_code == 200
    single_data = resp_single.json()
    assert single_data["status"] == "ok"
    assert single_data["domain"] == "test.delete.me.com"


@pytest.mark.asyncio
async def test_database_audit_report_deletion(tmp_path):
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()

    now = datetime.now(timezone.utc).isoformat()
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()

    r1 = AuditReportRecord(
        id="audit-001",
        mac="00:11:22:33:44:55",
        ip="192.168.1.50",
        hostname="TestDevice1",
        created_at=now,
        duration_seconds=300,
        total_bytes=1024,
        total_packets=10,
        risk_level="low",
        summary="Safe audit",
        pcap_file="dump_001.pcap"
    )
    r2 = AuditReportRecord(
        id="audit-002",
        mac="00:11:22:33:44:56",
        ip="192.168.1.101",
        hostname="TestDevice2",
        created_at=old_ts,
        duration_seconds=300,
        total_bytes=2048,
        total_packets=20,
        risk_level="high",
        summary="Risky audit",
        pcap_file="dump_002.pcap"
    )
    r3 = AuditReportRecord(
        id="audit-003",
        mac="00:11:22:33:44:57",
        ip="192.168.1.102",
        hostname="TestDevice3",
        created_at=now,
        duration_seconds=120,
        total_bytes=512,
        total_packets=5,
        risk_level="low",
        summary="Another safe audit",
        pcap_file=None
    )

    await test_db.save_audit_report(r1)
    await test_db.save_audit_report(r2)
    await test_db.save_audit_report(r3)

    reports = await test_db.get_audit_reports()
    assert len(reports) == 3

    # 1. Delete single report by ID
    pcap = await test_db.delete_audit_report("audit-001")
    assert pcap == "dump_001.pcap"
    reports = await test_db.get_audit_reports()
    assert len(reports) == 2
    assert all(r.id != "audit-001" for r in reports)

    # 2. Clear reports older than 7 days
    cleared_pcaps = await test_db.clear_audit_reports(older_than_days=7)
    assert "dump_002.pcap" in cleared_pcaps
    reports = await test_db.get_audit_reports()
    assert len(reports) == 1
    assert reports[0].id == "audit-003"

    # 3. Clear all remaining reports
    all_cleared = await test_db.clear_audit_reports()
    assert len(all_cleared) == 0  # r3 had no pcap_file
    reports = await test_db.get_audit_reports()
    assert len(reports) == 0


@pytest.mark.asyncio
async def test_api_audit_reports_cleanup(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_cleanup_reports_api.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)

    client = TestClient(app)

    # 1. DELETE non-existing single report
    resp = client.delete("/api/audit/reports/non-existent-id-999")
    assert resp.status_code == 404

    # 2. DELETE /api/audit/reports with older_than_days
    resp_7d = client.delete("/api/audit/reports?older_than_days=7")
    assert resp_7d.status_code == 200
    data_7d = resp_7d.json()
    assert data_7d["status"] == "ok"
    assert "deleted" in data_7d

    # 3. DELETE /api/audit/reports (all)
    resp_all = client.delete("/api/audit/reports")
    assert resp_all.status_code == 200
    data_all = resp_all.json()
    assert data_all["status"] == "ok"
    assert "deleted" in data_all


@pytest.mark.asyncio
async def test_device_deletion_and_api(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_keenguard.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)

    # Create dummy device
    d = DeviceRecord(
        mac="FF:EE:DD:CC:BB:AA",
        ip="192.168.1.250",
        hostname="Old-Ghost-Device",
        profile="iot",
        is_online=False
    )
    await test_db.upsert_device(d)
    assert await test_db.get_device("FF:EE:DD:CC:BB:AA") is not None

    # Delete device
    deleted = await test_db.delete_device("FF:EE:DD:CC:BB:AA")
    assert deleted is True
    assert await test_db.get_device("FF:EE:DD:CC:BB:AA") is None

    # Test DELETE /api/devices/{mac} with TestClient
    client = TestClient(app)
    resp_404 = client.delete("/api/devices/00:00:00:00:00:00")
    assert resp_404.status_code == 404


@pytest.mark.asyncio
async def test_delete_offline_devices_db_and_api(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_offline_cleanup.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.web.app.db", test_db)

    # 1. Seed devices: 2 Online, 3 Offline
    d1 = DeviceRecord(mac="11:22:33:44:55:01", ip="192.168.1.10", hostname="Active-Phone", profile="trusted", is_online=True)
    d2 = DeviceRecord(mac="11:22:33:44:55:02", ip="192.168.1.11", hostname="Active-TV", profile="smart_tv", is_online=True)
    d3 = DeviceRecord(mac="11:22:33:44:55:03", ip="192.168.1.12", hostname="Old-Random-MAC-1", profile="trusted", is_online=False)
    d4 = DeviceRecord(mac="11:22:33:44:55:04", ip="192.168.1.13", hostname="Sleeping-Sensor", profile="iot", is_online=False)
    d5 = DeviceRecord(mac="11:22:33:44:55:05", ip="192.168.1.14", hostname="Old-Random-MAC-2", profile="trusted", is_online=False)

    for d in [d1, d2, d3, d4, d5]:
        await test_db.upsert_device(d)

    # 2. Test DB layer directly
    deleted_count = await test_db.delete_offline_devices()
    assert deleted_count == 3

    remaining = await test_db.get_all_devices()
    assert len(remaining) == 2
    assert all(dev.is_online for dev in remaining)
    assert {dev.mac for dev in remaining} == {"11:22:33:44:55:01", "11:22:33:44:55:02"}

    # 3. Add 2 new offline devices and test REST API endpoint
    d6 = DeviceRecord(mac="AA:BB:CC:00:00:01", ip="192.168.1.20", hostname="Stale-1", profile="unassigned", is_online=False)
    d7 = DeviceRecord(mac="AA:BB:CC:00:00:02", ip="192.168.1.21", hostname="Stale-2", profile="unassigned", is_online=False)
    await test_db.upsert_device(d6)
    await test_db.upsert_device(d7)

    client = TestClient(app)
    resp = client.delete("/api/devices-offline")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["deleted_count"] == 2

    # Verify only original online devices remain
    final_devices = await test_db.get_all_devices()
    assert len(final_devices) == 2
    assert all(dev.is_online for dev in final_devices)



