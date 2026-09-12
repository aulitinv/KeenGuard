"""Background scheduler for KeenGuard: automated digests, scheduled audits, and maintenance."""
import asyncio
from datetime import datetime, timezone
import logging

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.core.digest import digest_generator
from keenguard.core.audit import audit_manager

logger = logging.getLogger("keenguard.scheduler")

class BackgroundScheduler:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_digest_day: int | None = None
        self._last_audit_day: int | None = None
        self._last_cleanup_day: int | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("BackgroundScheduler started.")

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("BackgroundScheduler stopped.")

    async def _loop(self):
        while self._running:
            try:
                now = datetime.now()
                current_hour = now.hour
                current_day = now.day

                # 1. Daily Security Digest
                if settings.digest_enabled and current_hour == settings.digest_schedule_hour:
                    if self._last_digest_day != current_day:
                        self._last_digest_day = current_day
                        logger.info("Triggering scheduled Security Digest...")
                        try:
                            await digest_generator.send_digest_to_telegram(hours=24, force=False)
                        except Exception as e:
                            logger.error("Error sending scheduled digest: %s", e)

                # 2. Daily Scheduled Device Audit
                if settings.scheduled_audit_enabled and current_hour == settings.scheduled_audit_hour:
                    if self._last_audit_day != current_day:
                        self._last_audit_day = current_day
                        logger.info("Triggering scheduled IoT/Device audit...")
                        try:
                            await self._run_scheduled_audit()
                        except Exception as e:
                            logger.error("Error running scheduled audit: %s", e)

                # 3. Daily DB Cleanup
                if current_hour == 4 and self._last_cleanup_day != current_day:
                    self._last_cleanup_day = current_day
                    deleted = await db.cleanup_old_traffic(days=7)
                    if deleted > 0:
                        logger.info("Cleaned up %d old traffic history records", deleted)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Unexpected error in scheduler loop: %s", e)

            # Sleep for 60 seconds
            await asyncio.sleep(60)

    async def _run_scheduled_audit(self):
        """Audits online devices according to user-selected scope (all, iot_only, untrusted)."""
        devices = await db.get_all_devices()
        scope = getattr(settings, "scheduled_audit_scope", "all")

        if scope == "all":
            candidates = [d for d in devices if d.is_online and d.ip]
        elif scope == "iot_only":
            candidates = [d for d in devices if d.is_online and d.ip and d.profile in ("iot", "camera", "smart_home_hub")]
        else: # untrusted
            candidates = [d for d in devices if d.is_online and d.ip and d.profile in ("iot", "camera", "smart_home_hub", "unassigned")]

        if not candidates:
            logger.info("Scheduled audit: no online devices found for scope '%s'", scope)
            return

        dur = getattr(settings, "scheduled_audit_duration", 60)
        logger.info("Starting scheduled security audit for %d devices (scope: %s, duration: %ds each)",
                    len(candidates), scope, dur)

        # Audit devices sequentially (up to 15 active devices per run)
        for target in candidates[:15]:
            if not self._running:
                break
            try:
                logger.info("Scheduled audit running on %s (%s, IP: %s)", target.hostname, target.mac, target.ip)
                await audit_manager.start_audit(
                    mac=target.mac,
                    ip=target.ip,
                    hostname=target.hostname,
                    vendor=target.vendor,
                    duration_seconds=dur,
                    profile=target.profile
                )
                await asyncio.sleep(dur + 2)
            except Exception as e:
                logger.warning("Error auditing device %s during scheduled run: %s", target.hostname, e)

scheduler = BackgroundScheduler()
