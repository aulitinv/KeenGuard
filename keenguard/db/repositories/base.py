"""Base repository providing SQLite connection context and common utilities."""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional, Any
import aiosqlite

from keenguard.config import settings

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


class BaseRepository:
    """Provides database connection helper for domain repositories."""

    def __init__(self, db_path: Optional[Any] = None):
        self.db_path = Path(db_path) if db_path else settings.db_path

    @asynccontextmanager
    async def get_connection(self):
        """Returns an async connection context manager for SQLite with foreign keys enabled."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
