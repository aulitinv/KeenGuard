"""Tests for SQLite persistent connection pooling in BaseRepository and Database."""
import asyncio
from pathlib import Path
import threading
import pytest
import aiosqlite

from keenguard.db import Database
from keenguard.db.repositories.base import BaseRepository
from keenguard.db.models import DeviceRecord, SecurityEvent


@pytest.mark.asyncio
async def test_persistent_connection_reuse(tmp_path: Path):
    """Verify that multiple get_connection() calls return the exact same connection object."""
    db_file = tmp_path / "test_pool_reuse.db"
    repo = BaseRepository(db_path=db_file)

    async with repo.get_connection() as conn1:
        assert conn1 is not None
        assert isinstance(conn1, aiosqlite.Connection)
        await conn1.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);")
        await conn1.commit()

    async with repo.get_connection() as conn2:
        # Must be the exact same connection instance
        assert conn1 is conn2

    # Also test Database composite instance
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    async with test_db.get_connection() as db_conn1:
        pass
    async with test_db.get_connection() as db_conn2:
        assert db_conn1 is db_conn2

    await repo.close()
    await test_db.close()


@pytest.mark.asyncio
async def test_close_and_reopen(tmp_path: Path):
    """Verify that after close(), the connection is terminated and next call creates a new one."""
    db_file = tmp_path / "test_pool_close.db"
    repo = BaseRepository(db_path=db_file)

    async with repo.get_connection() as conn1:
        await conn1.execute("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT);")
        await conn1.commit()
        assert getattr(conn1, "_running", False) is True

    # Close the connection
    await repo.close()
    assert repo._connection is None
    assert getattr(conn1, "_running", True) is False

    # Next call should transparently open a new connection
    async with repo.get_connection() as conn2:
        assert conn2 is not None
        assert conn2 is not conn1
        assert getattr(conn2, "_running", False) is True
        # Verify new connection is completely operational
        await conn2.execute("INSERT INTO kv VALUES ('key1', 'val1');")
        await conn2.commit()
        cursor = await conn2.execute("SELECT v FROM kv WHERE k = 'key1';")
        row = await cursor.fetchone()
        assert row[0] == "val1"

    await repo.close()


@pytest.mark.asyncio
async def test_nested_get_connection_no_deadlock(tmp_path: Path):
    """Verify that nested get_connection() calls do not deadlock due to lock-free yield."""
    db_file = tmp_path / "test_nested.db"
    repo = BaseRepository(db_path=db_file)

    async with repo.get_connection() as conn1:
        await conn1.execute("CREATE TABLE counter (val INTEGER);")
        await conn1.execute("INSERT INTO counter VALUES (1);")
        await conn1.commit()

        # Nested call within the same task
        async with repo.get_connection() as conn2:
            assert conn1 is conn2
            cursor = await conn2.execute("SELECT val FROM counter;")
            row = await cursor.fetchone()
            assert row[0] == 1

            # Double nested
            async with repo.get_connection() as conn3:
                assert conn3 is conn1

    await repo.close()


@pytest.mark.asyncio
async def test_concurrent_tasks_using_pool(tmp_path: Path):
    """Verify that multiple concurrent asyncio tasks can safely perform queries via the pooled connection."""
    db_file = tmp_path / "test_concurrent.db"
    repo = BaseRepository(db_path=db_file)

    async with repo.get_connection() as conn:
        await conn.execute("CREATE TABLE ledger (task_id INTEGER, step INTEGER);")
        await conn.commit()

    async def worker(task_id: int):
        for step in range(5):
            async with repo.get_connection() as conn:
                await conn.execute("INSERT INTO ledger VALUES (?, ?);", (task_id, step))
                await conn.commit()
                cursor = await conn.execute("SELECT COUNT(*) FROM ledger WHERE task_id = ?;", (task_id,))
                row = await cursor.fetchone()
                assert row[0] >= step + 1
            await asyncio.sleep(0.005)

    # Run 10 concurrent worker tasks
    tasks = [asyncio.create_task(worker(i)) for i in range(10)]
    await asyncio.gather(*tasks)

    async with repo.get_connection() as conn:
        cursor = await conn.execute("SELECT COUNT(*) FROM ledger;")
        row = await cursor.fetchone()
        assert row[0] == 50

    await repo.close()


@pytest.mark.asyncio
async def test_database_repository_methods_share_connection(tmp_path: Path):
    """Verify that domain repository operations in Database share the persistent connection."""
    db_file = tmp_path / "test_db_share.db"
    test_db = Database(db_path=db_file)
    await test_db.init_db()

    conn_init = test_db._connection
    assert conn_init is not None

    # Test settings repo
    await test_db.save_setting("test_key", "test_val")
    assert test_db._connection is conn_init
    val = await test_db.get_setting("test_key")
    assert val == "test_val"
    assert test_db._connection is conn_init

    # Test device repo
    dev = DeviceRecord(mac="AA:BB:CC:DD:EE:01", ip="192.168.1.150", hostname="TestDev")
    await test_db.upsert_device(dev)
    assert test_db._connection is conn_init
    fetched = await test_db.get_device("AA:BB:CC:DD:EE:01")
    assert fetched is not None
    assert fetched.hostname == "TestDev"
    assert test_db._connection is conn_init

    # Test event repo
    ev = SecurityEvent(event_type="test_event", severity="info", description="Test event")
    ev_id = await test_db.record_event(ev)
    assert ev_id > 0
    assert test_db._connection is conn_init

    # Close and verify clean shutdown
    await test_db.close()
    assert test_db._connection is None


def test_concurrent_threads_and_loops_no_different_loop_error(tmp_path: Path):
    """Verify that concurrent threads with separate event loops accessing the same Database instance do not raise RuntimeError bound to a different event loop."""
    db_file = tmp_path / "test_cross_thread_loop.db"
    shared_db = Database(db_path=db_file)

    # Initialize tables first
    init_loop = asyncio.new_event_loop()
    init_loop.run_until_complete(shared_db.init_db())
    init_loop.run_until_complete(shared_db.close())
    init_loop.close()

    errors = []

    def thread_worker(thread_idx: int):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def worker_coro():
            for i in range(10):
                try:
                    await shared_db.save_setting(f"thread_{thread_idx}_key_{i}", f"val_{i}")
                    val = await shared_db.get_setting(f"thread_{thread_idx}_key_{i}")
                    assert val == f"val_{i}"
                except Exception as ex:
                    errors.append(ex)
                await asyncio.sleep(0.002)

        try:
            loop.run_until_complete(worker_coro())
            loop.run_until_complete(shared_db.close())
        finally:
            loop.close()

    # Launch 4 concurrent threads each with its own event loop, accessing the exact same Database instance
    threads = [threading.Thread(target=thread_worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Cross-thread / cross-loop errors occurred: {errors}"

