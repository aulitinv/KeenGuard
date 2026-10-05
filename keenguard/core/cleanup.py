"""Storage and PCAP cleanup utilities for KeenGuard embedded environments."""
import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger("keenguard.cleanup")


def cleanup_old_pcap_files(
    pcap_dir: Optional[Path] = None,
    max_days: Optional[int] = None,
    max_total_size_mb: Optional[int] = None,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """Rotates and prunes PCAP dumps to protect flash memory and disk storage on routers.

    Enforces 3 retention bounds:
    1. Age: removes files older than max_days (default from settings.pcap_max_age_days)
    2. Count: retains at most max_files newest dumps (default from settings.max_pcap_files)
    3. Storage: limits total size of PCAPs to max_total_size_mb (default from settings.pcap_max_total_size_mb)
    """
    from keenguard.config import settings

    target_dir = Path(pcap_dir) if pcap_dir else settings.pcap_dir
    days = max_days if max_days is not None else getattr(settings, "pcap_max_age_days", 7)
    max_mb = max_total_size_mb if max_total_size_mb is not None else getattr(settings, "pcap_max_total_size_mb", 50)
    max_size_bytes = max_mb * 1024 * 1024
    file_limit = max_files if max_files is not None else getattr(settings, "max_pcap_files", 50)

    if not target_dir.exists():
        return {
            "deleted_count": 0,
            "freed_bytes": 0,
            "remaining_count": 0,
            "remaining_bytes": 0,
        }

    now = time.time()
    cutoff_time = now - (days * 86400)

    # Gather all pcap files in target directory
    pcap_files = [f for f in target_dir.glob("*.pcap*") if f.is_file()]

    deleted_count = 0
    freed_bytes = 0
    remaining_files = []

    # 1. Prune files older than max_days
    for f in pcap_files:
        try:
            stat = f.stat()
            if stat.st_mtime < cutoff_time:
                file_size = stat.st_size
                f.unlink(missing_ok=True)
                deleted_count += 1
                freed_bytes += file_size
                logger.info(
                    "Deleted expired PCAP dump %s (age: %.1f days, size: %d bytes)",
                    f.name, (now - stat.st_mtime) / 86400, file_size
                )
            else:
                remaining_files.append((stat.st_mtime, stat.st_size, f))
        except Exception as e:
            logger.warning("Error inspecting or deleting PCAP file %s: %s", f.name, e)

    # Sort remaining files by modification time ascending (oldest first)
    remaining_files.sort(key=lambda x: x[0])

    # 2. Prune by max_files count (drop oldest first)
    while len(remaining_files) > file_limit:
        mtime, size, f = remaining_files.pop(0)
        try:
            f.unlink(missing_ok=True)
            deleted_count += 1
            freed_bytes += size
            logger.info("Deleted oldest PCAP dump %s to enforce file count limit (%d)", f.name, file_limit)
        except Exception as e:
            logger.warning("Error deleting PCAP file %s: %s", f.name, e)

    # 3. Prune by max_total_size_mb (drop oldest first until within size quota)
    total_bytes = sum(item[1] for item in remaining_files)
    while remaining_files and total_bytes > max_size_bytes:
        mtime, size, f = remaining_files.pop(0)
        try:
            f.unlink(missing_ok=True)
            deleted_count += 1
            freed_bytes += size
            total_bytes -= size
            logger.info("Deleted oldest PCAP dump %s to enforce size quota (%d MB)", f.name, max_mb)
        except Exception as e:
            logger.warning("Error deleting PCAP file %s: %s", f.name, e)

    return {
        "deleted_count": deleted_count,
        "freed_bytes": freed_bytes,
        "remaining_count": len(remaining_files),
        "remaining_bytes": total_bytes,
    }


async def async_cleanup_old_pcap_files(
    pcap_dir: Optional[Path] = None,
    max_days: Optional[int] = None,
    max_total_size_mb: Optional[int] = None,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """Non-blocking async wrapper around cleanup_old_pcap_files."""
    return await asyncio.to_thread(
        cleanup_old_pcap_files,
        pcap_dir=pcap_dir,
        max_days=max_days,
        max_total_size_mb=max_total_size_mb,
        max_files=max_files,
    )
