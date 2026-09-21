"""Base repository providing SQLite connection context and common utilities."""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Any
import threading
import aiosqlite
import aiosqlite.core

from keenguard.config import settings

class _AioSqliteDaemonThread(threading.Thread):
    """Ensure aiosqlite connection worker threads are always daemon threads.

    Prevents background thread hangs and ensures clean process exit across dynamic event loops.
    """
    def __init__(self, *args, **kwargs):
        kwargs["daemon"] = True
        super().__init__(*args, **kwargs)

aiosqlite.core.Thread = _AioSqliteDaemonThread


def _safe_connection_worker_thread(tx):
    """Worker thread that safely handles callbacks to event loops that may have closed."""
    while True:
        future, function = tx.get()
        try:
            result = function()
            if future:
                loop = future.get_loop()
                if not loop.is_closed():
                    try:
                        loop.call_soon_threadsafe(aiosqlite.core.set_result, future, result)
                    except RuntimeError:
                        pass
            if result is aiosqlite.core._STOP_RUNNING_SENTINEL:
                break
        except BaseException as e:
            if future:
                loop = future.get_loop()
                if not loop.is_closed():
                    try:
                        loop.call_soon_threadsafe(aiosqlite.core.set_exception, future, e)
                    except RuntimeError:
                        pass

aiosqlite.core._connection_worker_thread = _safe_connection_worker_thread

import weakref

_UNSET = object()


class PruneResult(dict):
    """Dictionary holding prune metrics that also behaves as an integer for backwards compatibility."""
    def __int__(self):
        return int(self.get("total_deleted", 0))

    def __ge__(self, other):
        return self.get("total_deleted", 0) >= (int(other) if isinstance(other, (int, float)) else other)

    def __gt__(self, other):
        return self.get("total_deleted", 0) > (int(other) if isinstance(other, (int, float)) else other)

    def __le__(self, other):
        return self.get("total_deleted", 0) <= (int(other) if isinstance(other, (int, float)) else other)

    def __lt__(self, other):
        return self.get("total_deleted", 0) < (int(other) if isinstance(other, (int, float)) else other)

    def __eq__(self, other):
        if isinstance(other, (int, float)):
            return self.get("total_deleted", 0) == other
        return super().__eq__(other)


class _AsyncRLock:
    """Task-reentrant asynchronous lock for serializing queries on a shared connection."""
    def __init__(self):
        self._lock = asyncio.Lock()
        self._owner: Optional[asyncio.Task] = None
        self._depth: int = 0

    async def acquire(self):
        cur = asyncio.current_task()
        if self._owner is cur:
            self._depth += 1
            return True
        await self._lock.acquire()
        self._owner = cur
        self._depth = 1
        return True

    def release(self):
        cur = asyncio.current_task()
        if self._owner is not cur:
            raise RuntimeError("Cannot release unowned lock")
        self._depth -= 1
        if self._depth == 0:
            self._owner = None
            self._lock.release()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.release()


class BaseRepository:
    """Provides database connection helper for domain repositories with loop-safe persistent pooling."""

    _thread_lock = threading.Lock()

    def __init__(self, db_path: Optional[Any] = None):
        self.db_path = Path(db_path) if db_path else settings.db_path
        self._loop_connections: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._loop_locks: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
        self._loop_paths: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

    @property
    def _connection(self) -> Optional[aiosqlite.Connection]:
        """Backwards compatibility property returning the persistent connection for current loop."""
        try:
            loop = asyncio.get_running_loop()
            return self._loop_connections.get(loop)
        except RuntimeError:
            with self._thread_lock:
                if hasattr(self, "_loop_connections") and self._loop_connections:
                    return next(iter(self._loop_connections.values()), None)
            return None

    @_connection.setter
    def _connection(self, val: Optional[aiosqlite.Connection]):
        try:
            loop = asyncio.get_running_loop()
            with self._thread_lock:
                if val is None:
                    self._loop_connections.pop(loop, None)
                else:
                    self._loop_connections[loop] = val
        except RuntimeError:
            with self._thread_lock:
                if val is None and hasattr(self, "_loop_connections"):
                    self._loop_connections.clear()

    @property
    def _conn_lock(self) -> Optional[Any]:
        """Backwards compatibility property returning the lock for current loop."""
        try:
            loop = asyncio.get_running_loop()
            return self._loop_locks.get(loop)
        except RuntimeError:
            return None

    @_conn_lock.setter
    def _conn_lock(self, val: Optional[Any]):
        try:
            loop = asyncio.get_running_loop()
            with self._thread_lock:
                if val is None:
                    self._loop_locks.pop(loop, None)
                else:
                    self._loop_locks[loop] = val
        except RuntimeError:
            with self._thread_lock:
                if val is None and hasattr(self, "_loop_locks"):
                    self._loop_locks.clear()

    @property
    def _conn_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            return None

    @property
    def _conn_db_path(self) -> Optional[Path]:
        try:
            loop = asyncio.get_running_loop()
            return self._loop_paths.get(loop)
        except RuntimeError:
            return None

    @asynccontextmanager
    async def get_connection(self):
        """Returns persistent connection, lazily creating it per event loop."""
        current_loop = asyncio.get_running_loop()

        with self._thread_lock:
            if current_loop not in self._loop_locks:
                self._loop_locks[current_loop] = _AsyncRLock()
            conn_lock = self._loop_locks[current_loop]

        async with conn_lock:
            conn = self._loop_connections.get(current_loop)
            conn_path = self._loop_paths.get(current_loop)
            conn_running = getattr(conn, "_running", False) if conn is not None else False

            if conn is not None and (not conn_running or conn_path != self.db_path):
                try:
                    if conn_running:
                        await conn.close()
                except Exception:
                    pass
                conn = None
                with self._thread_lock:
                    self._loop_connections.pop(current_loop, None)
                    self._loop_paths.pop(current_loop, None)

            if conn is None:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                conn = await aiosqlite.connect(self.db_path, timeout=30.0)
                conn.row_factory = aiosqlite.Row
                try:
                    await conn.execute("PRAGMA journal_mode=WAL;")
                    await conn.execute("PRAGMA synchronous=NORMAL;")
                    await conn.execute("PRAGMA foreign_keys = ON;")
                    await conn.execute("PRAGMA busy_timeout = 30000;")
                    await conn.commit()
                except Exception:
                    pass
                with self._thread_lock:
                    self._loop_connections[current_loop] = conn
                    self._loop_paths[current_loop] = self.db_path

            try:
                yield conn
            except BaseException:
                try:
                    await conn.rollback()
                except Exception:
                    pass
                raise

    async def close(self, all_loops: bool = True):
        """Close persistent connection(s) safely across all event loops."""
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        with self._thread_lock:
            if not all_loops and current_loop is not None:
                loops_to_close = [current_loop]
            else:
                loops_to_close = list(self._loop_connections.keys())

        for l in loops_to_close:
            with self._thread_lock:
                conn = self._loop_connections.pop(l, None)
                self._loop_paths.pop(l, None)
                self._loop_locks.pop(l, None)
            if conn is not None and getattr(conn, "_running", False):
                try:
                    if l is current_loop and not l.is_closed():
                        await conn.close()
                    else:
                        if hasattr(conn, "_connection") and conn._connection:
                            conn._connection.close()
                        conn._running = False
                except Exception:
                    pass
