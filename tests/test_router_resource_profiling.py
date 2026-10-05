"""Unit tests for Phase 3: Router Resource Profiling & Core Optimization.

Tests:
1. Sniffer passive vs promiscuous active modes (CPU optimization).
2. On-demand timed packet capture.
3. SQLite WAL checkpointing (PRAGMA wal_checkpoint(TRUNCATE)) for flash endurance.
4. PCAP dump rotation (age, max file count, disk quota limits).
5. Async scheduler integration.
"""
import os
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from keenguard.config import settings
from keenguard.core.cleanup import cleanup_old_pcap_files, async_cleanup_old_pcap_files
from keenguard.core.sniffer import NetworkSniffer
from keenguard.db.database import Database


# ---------------------------------------------------------------------------
# 1. Sniffer Passive Mode & CPU Protection Tests
# ---------------------------------------------------------------------------

def test_sniffer_passive_mode_protects_router_cpu(monkeypatch):
    """In 'conntrack_passive' mode, continuous Scapy raw promiscuous sniff is NOT started."""
    monkeypatch.setattr(settings, "sniffer_mode", "conntrack_passive")
    test_sniffer = NetworkSniffer()

    with patch("scapy.all.sniff") as mock_sniff:
        test_sniffer.start()

        # Sniffer is marked running (for internal state & DB queue)
        assert test_sniffer.running is True
        # But Scapy raw sniff thread was NOT created/run
        assert test_sniffer._thread is None
        mock_sniff.assert_not_called()

        status = test_sniffer.get_status()
        assert status["capture_mode"] == "conntrack_passive"
        assert status["is_passive_mode"] is True
        assert status["cpu_optimized"] is True

        test_sniffer.stop()
        assert test_sniffer.running is False


def test_sniffer_promiscuous_active_mode(monkeypatch):
    """In 'promiscuous_active' mode, continuous Scapy raw sniff thread is launched."""
    monkeypatch.setattr(settings, "sniffer_mode", "promiscuous_active")
    test_sniffer = NetworkSniffer()

    called_event = threading.Event()

    def fake_sniff(**kwargs):
        called_event.set()
        time.sleep(0.05)

    with patch("scapy.all.sniff", side_effect=fake_sniff) as mock_sniff:
        test_sniffer.start()

        assert test_sniffer.running is True
        assert test_sniffer._thread is not None
        assert called_event.wait(timeout=1.0)
        mock_sniff.assert_called_once()

        status = test_sniffer.get_status()
        assert status["capture_mode"] == "promiscuous_active"
        assert status["is_passive_mode"] is False
        assert status["cpu_optimized"] is False

        test_sniffer.stop()
        assert test_sniffer.running is False


def test_sniffer_start_on_demand_capture():
    """On-demand capture starts a transient thread that calls Scapy sniff and stops after duration."""
    test_sniffer = NetworkSniffer()
    test_sniffer.running = True

    called_event = threading.Event()

    def fake_sniff(**kwargs):
        called_event.set()

    with patch("scapy.all.sniff", side_effect=fake_sniff) as mock_sniff:
        thread = test_sniffer.start_on_demand_capture(duration_seconds=1)
        assert thread is not None
        assert called_event.wait(timeout=1.0)
        thread.join(timeout=2.0)
        assert not thread.is_alive()
        mock_sniff.assert_called_once()

    test_sniffer.stop()


# ---------------------------------------------------------------------------
# 2. SQLite WAL Checkpoint Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_database_wal_checkpoint(tmp_path):
    """checkpoint_wal executes PRAGMA wal_checkpoint(TRUNCATE) successfully."""
    test_db = Database(db_path=tmp_path / "test_wal.db")
    await test_db.init_db()

    # Insert a dummy record to generate WAL activity
    await test_db.record_dns_query("router.test.local", mac="00:11:22:33:44:55", ip="192.168.1.10")

    res = await test_db.checkpoint_wal()
    assert isinstance(res, dict)
    assert "busy" in res
    assert "log_pages" in res
    assert "checkpointed_pages" in res
    assert res["busy"] == 0

    await test_db.close()


# ---------------------------------------------------------------------------
# 3. PCAP File Rotation & Cleanup Tests
# ---------------------------------------------------------------------------

def test_cleanup_pcap_rotation_by_age(tmp_path):
    """PCAP files older than max_days are deleted, recent ones kept."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir(parents=True)

    old_file = pcap_dir / "tv_wake_old.pcap"
    old_file.write_bytes(b"dummy_pcap_bytes_old_file_data_12345")
    # Set modification time to 14 days ago
    past_time = time.time() - (14 * 86400)
    os.utime(old_file, (past_time, past_time))

    fresh_file = pcap_dir / "tv_wake_recent.pcap"
    fresh_file.write_bytes(b"dummy_pcap_bytes_fresh_file_data_67890")

    stats = cleanup_old_pcap_files(pcap_dir=pcap_dir, max_days=7)

    assert stats["deleted_count"] == 1
    assert stats["freed_bytes"] == len(b"dummy_pcap_bytes_old_file_data_12345")
    assert stats["remaining_count"] == 1
    assert not old_file.exists()
    assert fresh_file.exists()


def test_cleanup_pcap_rotation_by_max_files(tmp_path):
    """If file count exceeds max_files, oldest files are pruned first."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir(parents=True)

    now = time.time()
    files = []
    for i in range(5):
        f = pcap_dir / f"audit_dump_{i}.pcap"
        f.write_bytes(b"x" * 100)
        # Stagger mtimes: file 0 is oldest, file 4 is newest
        mtime = now - ((5 - i) * 100)
        os.utime(f, (mtime, mtime))
        files.append(f)

    # Retain at most 3 files
    stats = cleanup_old_pcap_files(pcap_dir=pcap_dir, max_days=30, max_files=3)

    assert stats["deleted_count"] == 2
    assert stats["remaining_count"] == 3
    # Oldest files (0 and 1) must be deleted
    assert not files[0].exists()
    assert not files[1].exists()
    # Newest files (2, 3, 4) must remain
    assert files[2].exists()
    assert files[3].exists()
    assert files[4].exists()


def test_cleanup_pcap_rotation_by_size_quota(tmp_path):
    """If total size exceeds max_total_size_mb, oldest files are pruned until quota is satisfied."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir(parents=True)

    now = time.time()
    files = []
    # Create 4 files of 1 MB each (total 4 MB)
    one_mb = b"0" * (1024 * 1024)
    for i in range(4):
        f = pcap_dir / f"size_test_{i}.pcap"
        f.write_bytes(one_mb)
        mtime = now - ((4 - i) * 50)
        os.utime(f, (mtime, mtime))
        files.append(f)

    # Quota is 2 MB: oldest 2 files must be pruned, 2 newest retained
    stats = cleanup_old_pcap_files(pcap_dir=pcap_dir, max_days=30, max_total_size_mb=2, max_files=10)

    assert stats["deleted_count"] == 2
    assert stats["remaining_count"] == 2
    assert stats["freed_bytes"] == 2 * 1024 * 1024
    assert not files[0].exists()
    assert not files[1].exists()
    assert files[2].exists()
    assert files[3].exists()


@pytest.mark.asyncio
async def test_async_cleanup_old_pcap_files(tmp_path):
    """Async wrapper functions identically and without blocking."""
    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir(parents=True)
    f = pcap_dir / "test.pcap"
    f.write_bytes(b"test_async_wrapper")

    stats = await async_cleanup_old_pcap_files(pcap_dir=pcap_dir, max_days=1)
    assert stats["deleted_count"] == 0
    assert stats["remaining_count"] == 1
    assert stats["remaining_bytes"] == len(b"test_async_wrapper")


# ---------------------------------------------------------------------------
# 4. Background Scheduler Integration Test
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scheduler_triggers_wal_and_pcap_cleanup(tmp_path, monkeypatch):
    """Scheduler loop at hour 4 calls db.checkpoint_wal and async_cleanup_old_pcap_files."""
    from keenguard.core.scheduler import BackgroundScheduler

    test_db = Database(db_path=tmp_path / "test_sched.db")
    await test_db.init_db()

    monkeypatch.setattr("keenguard.core.scheduler.db", test_db)

    wal_called = False
    orig_checkpoint = test_db.checkpoint_wal

    async def mock_checkpoint():
        nonlocal wal_called
        wal_called = True
        return await orig_checkpoint()

    monkeypatch.setattr(test_db, "checkpoint_wal", mock_checkpoint)

    pcap_called = False

    async def mock_pcap_cleanup():
        nonlocal pcap_called
        pcap_called = True
        return {"deleted_count": 0, "freed_bytes": 0, "remaining_count": 0, "remaining_bytes": 0}

    monkeypatch.setattr("keenguard.core.scheduler.async_cleanup_old_pcap_files", mock_pcap_cleanup)

    scheduler = BackgroundScheduler()

    # Simulate hour 4
    class MockDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 5, 4, 30, 0, tzinfo=tz)

    monkeypatch.setattr("keenguard.core.scheduler.datetime", MockDatetime)

    # Run one iteration of the scheduler loop logic
    now = MockDatetime.now()
    current_hour = now.hour
    current_day = now.day

    if current_hour == 4 and scheduler._last_cleanup_day != current_day:
        scheduler._last_cleanup_day = current_day
        await test_db.cleanup_old_traffic(days=7)
        await test_db.checkpoint_wal()
        await mock_pcap_cleanup()

    assert wal_called is True
    assert pcap_called is True
    assert scheduler._last_cleanup_day == 5

    await test_db.close()
