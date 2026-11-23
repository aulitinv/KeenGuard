"""Unit tests for SQLite migration, FK integrity, upload streaming limits, and settings persistence."""
import asyncio
import io
import pytest
from datetime import datetime, timezone
import aiosqlite
from fastapi.testclient import TestClient

from keenguard.db.database import Database
from keenguard.db.models import SecurityEvent, AuditReportRecord, DeviceRecord
from keenguard.core.config_service import ConfigService
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_events_fk_migration_preserves_rule_columns(tmp_path):
    """Legacy events table migration to FK schema must preserve matched_rule_id and matched_rule_name."""
    db_path = tmp_path / "legacy_events.db"
    
    # 1. Create a legacy database where events has NO foreign keys
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute("""
            CREATE TABLE devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT
            )
        """)
        await conn.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('00:11:22:33:44:55', '192.168.1.50', 'TestDev')")

        # Legacy events table without 'REFERENCES devices(mac)'
        await conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                severity TEXT,
                target_mac TEXT,
                target_ip TEXT,
                source_mac TEXT,
                source_ip TEXT,
                source_name TEXT,
                description TEXT,
                details_json TEXT,
                pcap_file TEXT,
                matched_rule_id TEXT,
                matched_rule_name TEXT
            )
        """)
        await conn.execute("""
            INSERT INTO events (
                timestamp, event_type, severity, target_mac, target_ip,
                description, matched_rule_id, matched_rule_name
            ) VALUES (
                '2026-11-23T00:00:00Z', 'rule_alert', 'warning', '00:11:22:33:44:55', '192.168.1.50',
                'Blocked camera stream', 'rule_cam_isolate', 'Block Camera Internet'
            )
        """)
        await conn.commit()

    # 2. Run Database.init_db() which executes _migrate_fk_constraints
    test_db = Database(db_path=db_path)
    await test_db.init_db()

    # 3. Verify events table schema and preserved data
    async with aiosqlite.connect(str(db_path)) as conn:
        cursor = await conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='events'")
        row = await cursor.fetchone()
        assert row is not None
        sql = row[0]
        assert "REFERENCES devices(mac)" in sql or "REFERENCES devices (mac)" in sql
        assert "matched_rule_id TEXT" in sql
        assert "matched_rule_name TEXT" in sql

        # Check that the data survived
        conn.row_factory = aiosqlite.Row
        cur = await conn.execute("SELECT * FROM events WHERE id = 1")
        ev_row = await cur.fetchone()
        assert ev_row is not None
        assert ev_row["target_mac"] == "00:11:22:33:44:55"
        assert ev_row["matched_rule_id"] == "rule_cam_isolate"
        assert ev_row["matched_rule_name"] == "Block Camera Internet"


@pytest.mark.asyncio
async def test_wan_metrics_and_network_events_fk_integrity(tmp_path):
    """Verifies that WAN traffic metrics and whole-network events succeed with PRAGMA foreign_keys = ON."""
    db_path = tmp_path / "test_fk_integrity.db"
    test_db = Database(db_path=db_path)
    await test_db.init_db()

    # 1. Direct verification with SQLite foreign_keys = ON
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute("PRAGMA foreign_keys = ON;")

        # WAN metrics snapshot record under '02:00:00:00:00:01'
        await test_db.record_traffic_snapshot(
            mac="02:00:00:00:00:01",
            rx_bytes=1000000,
            tx_bytes=500000,
            rx_rate_kbps=1024.5,
            tx_rate_kbps=512.0
        )

        # Whole-network security event with target_mac = None (NULL)
        ev_id = await test_db.record_event(SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type="network_audit_completed",
            severity="info",
            target_mac=None,
            description="Network-wide scan complete"
        ))
        assert ev_id > 0

        # Whole-network audit report with mac = None (NULL)
        report_record = AuditReportRecord(
            id="net_audit_1001",
            mac=None,
            ip="0.0.0.0",
            hostname="Network Audit",
            summary="All clear",
            report_json="{}"
        )
        await test_db.save_audit_report(report_record)

    # 2. Ensure WAN snapshots are queryable in traffic summary
    summary = await test_db.get_network_traffic_summary(limit=10)
    # When fewer than 2 snapshots exist, fallback or empty is returned
    history = await test_db.get_device_traffic_history("02:00:00:00:00:01", limit=10)
    assert len(history) == 1
    assert history[0]["rx_rate_kbps"] == 1024.5

    # 3. Ensure get_all_devices does not return WAN pseudo-device to regular device listings
    devices = await test_db.get_all_devices()
    assert all(d.mac != "02:00:00:00:00:01" for d in devices)


def test_upload_pcap_streaming_rejects_oversized_file(tmp_path, monkeypatch):
    """Uploading a PCAP file larger than 25MB must be aborted with HTTP 413 immediately during streaming."""
    test_db = Database(db_path=tmp_path / "test_upload.db")
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir(parents=True, exist_ok=True)

    from keenguard.config import settings
    monkeypatch.setattr(settings, "pcap_dir", pcap_dir)
    monkeypatch.setattr("keenguard.web.routes.security.get_db", lambda: test_db)

    client = TestClient(app)

    # Generate a dummy stream slightly above 25MB (25MB + 64KB)
    oversized_bytes = b"0" * (25 * 1024 * 1024 + 65536)
    file_obj = io.BytesIO(oversized_bytes)

    resp = client.post(
        "/api/packets/pcap/upload",
        files={"file": ("huge_capture.pcap", file_obj, "application/vnd.tcpdump.pcap")}
    )

    assert resp.status_code == 413
    assert "25 МБ" in resp.json()["detail"]

    # Verify no leaked partial upload files remain in pcap_dir
    files_in_pcap = list(pcap_dir.glob("upload_*huge_capture.pcap"))
    assert len(files_in_pcap) == 0


@pytest.mark.asyncio
async def test_quarantine_settings_persistence(tmp_path, monkeypatch):
    """Settings updated via quarantine toggle endpoints must persist to SQLite and survive restarts."""
    test_db = Database(db_path=tmp_path / "test_settings_persist.db")
    await test_db.init_db()

    from keenguard.config import settings
    custom_cfg = ConfigService(settings_instance=settings)
    await custom_cfg.initialize(database=test_db)

    monkeypatch.setattr("keenguard.web.routes.security.get_db", lambda: test_db)
    monkeypatch.setattr("keenguard.core.config_service.config_service", custom_cfg)

    client = TestClient(app)

    # 1. Toggle WAN quarantine rule on
    resp1 = client.post("/api/security/checklist/toggle-quarantine-rule", json={"rule": "wan", "enabled": True})
    assert resp1.status_code == 200
    assert resp1.json()["settings"]["quarantine_wan"] is True

    # 2. Toggle auto_audit on
    resp2 = client.post("/api/security/checklist/toggle-quarantine-rule", json={"rule": "auto_audit", "enabled": True})
    assert resp2.status_code == 200
    assert resp2.json()["settings"]["auto_audit"] is True

    # 3. Verify values stored directly in SQLite app_settings
    val_wan = await test_db.get_setting("new_device_quarantine_wan")
    assert val_wan == "true"
    val_audit = await test_db.get_setting("new_device_auto_audit")
    assert val_audit == "true"

    # 4. Simulate application restart: create a new fresh ConfigService and initialize from SQLite
    fresh_cfg = ConfigService(settings_instance=settings)
    await fresh_cfg.initialize(database=test_db)

    assert fresh_cfg.get("new_device_quarantine_wan") is True
    assert fresh_cfg.get("new_device_auto_audit") is True
