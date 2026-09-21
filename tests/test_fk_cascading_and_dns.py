"""Tests for Foreign Key constraints, Cascading Deletes, DNS PK fix, and legacy DB migrations."""
import pytest
import sqlite3
import aiosqlite
from datetime import datetime, timezone
from pathlib import Path

from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord, SecurityEvent, AuditReportRecord


@pytest.mark.asyncio
async def test_fk_cascading_deletes(tmp_path):
    """Verify that deleting a device cascades to traffic/dns_device_queries and sets NULL on events/audit/dns_queries."""
    test_db_path = tmp_path / "test_fk_cascade.db"
    db = Database(db_path=test_db_path)
    await db.init_db()

    target_mac = "11:22:33:44:55:AA"
    dev = DeviceRecord(
        mac=target_mac,
        ip="192.168.1.100",
        hostname="Test-Device",
        profile="smart_tv",
        is_online=True
    )
    await db.upsert_device(dev)

    # 1. Add event targeting device
    ev = SecurityEvent(
        event_type="test_probe",
        severity="warning",
        target_mac=target_mac,
        description="Probe test"
    )
    ev_id = await db.record_event(ev)

    # 2. Add traffic snapshot
    await db.record_traffic_snapshot(mac=target_mac, rx_bytes=1000, tx_bytes=2000, rx_rate_kbps=10.5, tx_rate_kbps=20.5)

    # 3. Add audit report
    audit_record = AuditReportRecord(
        id="audit-test-1",
        mac=target_mac,
        ip="192.168.1.100",
        hostname="Test-Device",
        created_at=datetime.now(timezone.utc).isoformat(),
        duration_seconds=60,
        total_bytes=3000,
        total_packets=30,
        risk_level="low",
        summary="Test audit",
        report_json="{}",
        pcap_file=""
    )
    await db.save_audit_report(audit_record)

    # 4. Add DNS query
    await db.record_dns_query(domain="stream.netflix.com", mac=target_mac, ip="192.168.1.100")

    # 5. Add IoT payload log and LAN comm
    async with db.get_connection() as conn:
        await conn.execute("""
            INSERT INTO iot_payload_logs (mac, device_name, summary)
            VALUES (?, ?, ?)
        """, (target_mac, "Test-Device", "MQTT message"))
        await conn.execute("""
            INSERT INTO lan_communications (src_mac, dst_mac, summary)
            VALUES (?, ?, ?)
        """, (target_mac, "AA:BB:CC:DD:EE:FF", "LAN packet"))
        await conn.commit()

    # Verify all tables have records
    async with db.get_connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM traffic_history WHERE mac = ?", (target_mac,))
        assert (await cursor.fetchone())[0] == 1

        cursor = await conn.execute("SELECT COUNT(*) FROM dns_device_queries WHERE mac = ?", (target_mac,))
        assert (await cursor.fetchone())[0] == 1

        cursor = await conn.execute("SELECT COUNT(*) FROM iot_payload_logs WHERE mac = ?", (target_mac,))
        assert (await cursor.fetchone())[0] == 1

        cursor = await conn.execute("SELECT COUNT(*) FROM lan_communications WHERE src_mac = ?", (target_mac,))
        assert (await cursor.fetchone())[0] == 1

    # PRAGMA foreign_key_check before delete
    async with db.get_connection() as conn:
        cur = await conn.execute("PRAGMA foreign_key_check;")
        assert await cur.fetchall() == []

    # 6. Delete device
    deleted = await db.delete_device(target_mac)
    assert deleted is True

    # 7. Check database state after deletion
    async with db.get_connection() as conn:
        # Device is deleted
        cur = await conn.execute("SELECT * FROM devices WHERE mac = ?", (target_mac,))
        assert await cur.fetchone() is None

        # traffic_history is cleaned (CASCADE)
        cur = await conn.execute("SELECT COUNT(*) FROM traffic_history WHERE mac = ?", (target_mac,))
        assert (await cur.fetchone())[0] == 0

        # dns_device_queries is cleaned
        cur = await conn.execute("SELECT COUNT(*) FROM dns_device_queries WHERE mac = ?", (target_mac,))
        assert (await cur.fetchone())[0] == 0

        # iot_payload_logs is cleaned
        cur = await conn.execute("SELECT COUNT(*) FROM iot_payload_logs WHERE mac = ?", (target_mac,))
        assert (await cur.fetchone())[0] == 0

        # lan_communications is cleaned
        cur = await conn.execute("SELECT COUNT(*) FROM lan_communications WHERE src_mac = ?", (target_mac,))
        assert (await cur.fetchone())[0] == 0

        # events: target_mac set to NULL (ON DELETE SET NULL)
        cur = await conn.execute("SELECT target_mac FROM events WHERE id = ?", (ev_id,))
        ev_row = await cur.fetchone()
        assert ev_row is not None
        assert ev_row[0] is None

        # audit_reports: mac set to NULL (ON DELETE SET NULL)
        cur = await conn.execute("SELECT mac FROM audit_reports WHERE id = ?", ("audit-test-1",))
        audit_row = await cur.fetchone()
        assert audit_row is not None
        assert audit_row[0] is None

        # dns_queries: mac set to NULL, but aggregate domain entry remains
        cur = await conn.execute("SELECT domain, mac, count FROM dns_queries WHERE domain = ?", ("stream.netflix.com",))
        dns_row = await cur.fetchone()
        assert dns_row is not None
        assert dns_row[0] == "stream.netflix.com"
        assert dns_row[1] is None
        assert dns_row[2] == 1

        # PRAGMA foreign_key_check after delete must be completely clean
        cur = await conn.execute("PRAGMA foreign_key_check;")
        assert await cur.fetchall() == []

    await db.close()


@pytest.mark.asyncio
async def test_dns_multi_device_tracking(tmp_path):
    """Verify that multiple devices querying the same domain don't overwrite each other in dns_device_queries."""
    test_db_path = tmp_path / "test_dns_multi.db"
    db = Database(db_path=test_db_path)
    await db.init_db()

    mac1 = "AA:BB:CC:11:11:11"
    mac2 = "AA:BB:CC:22:22:22"
    domain = "api.example.com"

    # Seed devices
    await db.upsert_device(DeviceRecord(mac=mac1, ip="192.168.1.10", hostname="Phone-1"))
    await db.upsert_device(DeviceRecord(mac=mac2, ip="192.168.1.20", hostname="TV-1"))

    # Device 1 queries domain
    await db.record_dns_query(domain=domain, mac=mac1, ip="192.168.1.10")

    # Device 2 queries same domain
    await db.record_dns_query(domain=domain, mac=mac2, ip="192.168.1.20")

    # Device 1 queries domain again
    await db.record_dns_query(domain=domain, mac=mac1, ip="192.168.1.10")

    async with db.get_connection() as conn:
        conn.row_factory = aiosqlite.Row

        # 1. Global dns_queries table aggregates total count (1 + 1 + 1 = 3)
        cur = await conn.execute("SELECT * FROM dns_queries WHERE domain = ?", (domain,))
        dq_row = await cur.fetchone()
        assert dq_row is not None
        assert dq_row["domain"] == domain
        assert dq_row["count"] == 3
        # mac was set on initial insert and NOT overwritten by Device 2
        assert dq_row["mac"] == mac1

        # 2. Per-device table preserves separate counts for both devices
        cur = await conn.execute("SELECT * FROM dns_device_queries WHERE domain = ? ORDER BY mac", (domain,))
        dev_rows = await cur.fetchall()
        assert len(dev_rows) == 2

        assert dev_rows[0]["mac"] == mac1
        assert dev_rows[0]["count"] == 2
        assert dev_rows[0]["ip"] == "192.168.1.10"

        assert dev_rows[1]["mac"] == mac2
        assert dev_rows[1]["count"] == 1
        assert dev_rows[1]["ip"] == "192.168.1.20"

        # FK check is clean
        cur = await conn.execute("PRAGMA foreign_key_check;")
        assert await cur.fetchall() == []

    await db.close()


@pytest.mark.asyncio
async def test_legacy_schema_migration(tmp_path):
    """Verify automatic migration of legacy databases without FK constraints to new schema with FK constraints."""
    test_db_path = tmp_path / "test_legacy.db"

    # Step 1: Create a database with the old schema (no REFERENCES devices(mac), old dns_queries PK)
    conn = sqlite3.connect(test_db_path)
    conn.execute("PRAGMA foreign_keys = OFF;")
    conn.execute("""
        CREATE TABLE devices (
            mac TEXT PRIMARY KEY,
            ip TEXT,
            hostname TEXT
        );
    """)
    conn.execute("INSERT INTO devices (mac, ip, hostname) VALUES ('11:22:33:44:55:01', '192.168.1.50', 'KnownDevice');")

    conn.execute("""
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
            pcap_file TEXT
        );
    """)
    # 1 valid event, 1 orphaned event (device doesn't exist)
    conn.execute("INSERT INTO events (timestamp, event_type, target_mac, description) VALUES ('2026-01-01', 'info', '11:22:33:44:55:01', 'Valid event');")
    conn.execute("INSERT INTO events (timestamp, event_type, target_mac, description) VALUES ('2026-01-01', 'info', 'ORPHAN:MAC:00:00:01', 'Orphaned event');")

    conn.execute("""
        CREATE TABLE traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            mac TEXT,
            rx_bytes INTEGER,
            tx_bytes INTEGER,
            rx_rate_kbps REAL,
            tx_rate_kbps REAL
        );
    """)
    conn.execute("INSERT INTO traffic_history (timestamp, mac, rx_bytes, tx_bytes) VALUES ('2026-01-01', '11:22:33:44:55:01', 100, 200);")
    conn.execute("INSERT INTO traffic_history (timestamp, mac, rx_bytes, tx_bytes) VALUES ('2026-01-01', 'ORPHAN:MAC:00:00:02', 300, 400);")

    conn.execute("""
        CREATE TABLE audit_reports (
            id TEXT PRIMARY KEY,
            mac TEXT,
            ip TEXT,
            hostname TEXT,
            created_at TEXT,
            duration_seconds INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            total_packets INTEGER DEFAULT 0,
            risk_level TEXT DEFAULT 'low',
            summary TEXT,
            report_json TEXT,
            pcap_file TEXT
        );
    """)
    conn.execute("INSERT INTO audit_reports (id, mac, summary) VALUES ('rep-1', '11:22:33:44:55:01', 'Valid audit');")
    conn.execute("INSERT INTO audit_reports (id, mac, summary) VALUES ('rep-2', 'ORPHAN:MAC:00:00:03', 'Orphaned audit');")

    conn.execute("""
        CREATE TABLE dns_queries (
            domain TEXT PRIMARY KEY,
            mac TEXT,
            ip TEXT,
            count INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen TEXT,
            is_blocked INTEGER DEFAULT 0,
            blocked_by_provider TEXT,
            blocked_reason TEXT,
            filter_list TEXT,
            tracker_category TEXT
        );
    """)
    conn.execute("INSERT INTO dns_queries (domain, mac, count) VALUES ('google.com', '11:22:33:44:55:01', 5);")
    conn.execute("INSERT INTO dns_queries (domain, mac, count) VALUES ('orphan.org', 'ORPHAN:MAC:00:00:04', 2);")

    conn.commit()
    conn.close()

    # Step 2: Open and initialize with KeenGuard Database class
    db = Database(db_path=test_db_path)
    await db.init_db()

    # Step 3: Verify schema migration results
    async with db.get_connection() as aio_conn:
        aio_conn.row_factory = aiosqlite.Row

        # Check sqlite_master schema definitions
        for tbl in ["events", "traffic_history", "audit_reports", "dns_queries"]:
            cur = await aio_conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (tbl,))
            row = await cur.fetchone()
            assert row is not None
            assert "REFERENCES devices(mac)" in row["sql"] or "REFERENCES devices (mac)" in row["sql"]

        # Check dns_queries has id INTEGER PRIMARY KEY AUTOINCREMENT
        cur = await aio_conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='dns_queries'")
        row = await cur.fetchone()
        assert "AUTOINCREMENT" in row["sql"]

        # Check data preservation and orphan cleanup
        # events: 1 valid target_mac preserved, 1 orphaned set to NULL
        cur = await aio_conn.execute("SELECT target_mac, description FROM events ORDER BY id")
        ev_rows = await cur.fetchall()
        assert len(ev_rows) == 2
        assert ev_rows[0]["target_mac"] == "11:22:33:44:55:01"
        assert ev_rows[1]["target_mac"] is None

        # traffic_history: 1 valid preserved, orphaned deleted
        cur = await aio_conn.execute("SELECT mac, rx_bytes FROM traffic_history")
        th_rows = await cur.fetchall()
        assert len(th_rows) == 1
        assert th_rows[0]["mac"] == "11:22:33:44:55:01"

        # audit_reports: 1 valid preserved, 1 orphaned set to NULL
        cur = await aio_conn.execute("SELECT id, mac FROM audit_reports ORDER BY id")
        rep_rows = await cur.fetchall()
        assert len(rep_rows) == 2
        assert rep_rows[0]["mac"] == "11:22:33:44:55:01"
        assert rep_rows[1]["mac"] is None

        # dns_queries: 1 valid preserved, 1 orphaned set to NULL, counts preserved
        cur = await aio_conn.execute("SELECT domain, mac, count FROM dns_queries ORDER BY domain")
        dns_rows = await cur.fetchall()
        assert len(dns_rows) == 2
        assert dns_rows[0]["domain"] == "google.com"
        assert dns_rows[0]["mac"] == "11:22:33:44:55:01"
        assert dns_rows[0]["count"] == 5
        assert dns_rows[1]["domain"] == "orphan.org"
        assert dns_rows[1]["mac"] is None
        assert dns_rows[1]["count"] == 2

        # PRAGMA foreign_key_check is completely clean!
        cur = await aio_conn.execute("PRAGMA foreign_key_check;")
        assert await cur.fetchall() == []

    await db.close()


@pytest.mark.asyncio
async def test_delete_offline_devices_cascading(tmp_path):
    """Verify that deleting offline devices properly cleans dependent tables."""
    test_db_path = tmp_path / "test_offline_cascade.db"
    db = Database(db_path=test_db_path)
    await db.init_db()

    online_mac = "00:11:22:33:44:01"
    offline_mac = "00:11:22:33:44:02"

    await db.upsert_device(DeviceRecord(mac=online_mac, ip="192.168.1.10", is_online=True))
    await db.upsert_device(DeviceRecord(mac=offline_mac, ip="192.168.1.20", is_online=False))

    # Add traffic
    await db.record_traffic_snapshot(mac=online_mac, rx_bytes=500, tx_bytes=500, rx_rate_kbps=5.0, tx_rate_kbps=5.0)
    await db.record_traffic_snapshot(mac=offline_mac, rx_bytes=100, tx_bytes=100, rx_rate_kbps=1.0, tx_rate_kbps=1.0)

    # Add DNS queries
    await db.record_dns_query(domain="online.com", mac=online_mac)
    await db.record_dns_query(domain="offline.com", mac=offline_mac)

    # Delete offline devices
    deleted_count = await db.delete_offline_devices()
    assert deleted_count == 1

    # Verify online device remains, offline is removed
    all_devs = await db.get_all_devices()
    assert len(all_devs) == 1
    assert all_devs[0].mac == online_mac

    # Verify traffic history
    online_traffic = await db.get_device_traffic_history(online_mac)
    assert len(online_traffic) == 1
    offline_traffic = await db.get_device_traffic_history(offline_mac)
    assert len(offline_traffic) == 0

    # Verify per-device DNS queries
    async with db.get_connection() as conn:
        cur = await conn.execute("SELECT * FROM dns_device_queries WHERE mac = ?", (offline_mac,))
        assert await cur.fetchall() == []

        cur = await conn.execute("SELECT * FROM dns_device_queries WHERE mac = ?", (online_mac,))
        assert len(await cur.fetchall()) == 1

        cur = await conn.execute("PRAGMA foreign_key_check;")
        assert await cur.fetchall() == []

    await db.close()
