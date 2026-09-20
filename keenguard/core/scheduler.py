import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Optional, Dict, Any

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import SecurityEvent
from keenguard.core.enums import EventType, Severity
from keenguard.core.digest import digest_generator
from keenguard.core.audit import audit_manager
from keenguard.core.forensics import forensics

logger = logging.getLogger("keenguard.scheduler")

class BackgroundScheduler:
    def __init__(self):
        self._running = False
        self._task: asyncio.Task | None = None
        self._last_digest_day: int | None = None
        self._last_audit_day: int | None = None
        self._last_cleanup_day: int | None = None
        self._tv_night_status: Dict[str, Dict[str, Any]] = {}

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

                # 4. Smart Night Mode Check & Transitions
                try:
                    await self._check_night_mode_transitions(now)
                except Exception as e:
                    logger.error("Error checking night mode transitions: %s", e)

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

    async def _is_device_active(self, d: Any, threshold_minutes: int) -> bool:
        """Checks whether a device has active network traffic within the threshold."""
        try:
            # 1. Check traffic history bandwidth rates
            history = await db.get_device_traffic_history(d.mac, limit=threshold_minutes + 2)
            if history:
                # If any of the recent snapshots shows active traffic (> 5 KB/s = 40 kbps)
                recent_active = any(
                    (h.get("rx_rate_kbps", 0) > 40.0 or h.get("tx_rate_kbps", 0) > 40.0)
                    for h in history[-max(1, threshold_minutes):]
                )
                if recent_active:
                    return True

            # 2. Check sniffer buffer for very recent packets
            from keenguard.core.sniffer import get_sniffer
            sn = get_sniffer()
            buf = sn.ring_buffers.get(d.mac.upper())
            if buf and len(buf) > 0:
                latest = buf.get_all()[-1]
                pkt_time = getattr(latest, "time", 0)
                if pkt_time and (time.time() - pkt_time) < (threshold_minutes * 60):
                    return True

            # 3. Check online status and last_seen
            if d.is_online and d.last_seen:
                try:
                    dt = datetime.fromisoformat(d.last_seen)
                    if (datetime.now(timezone.utc) - dt).total_seconds() < 60:
                        return True
                except Exception:
                    pass
        except Exception as e:
            logger.debug("Error checking device activity for %s: %s", getattr(d, "mac", ""), e)
        return False

    async def _check_night_mode_transitions(self, now: Optional[datetime] = None):
        """Monitors and manages Smart Night Mode transitions and inactivity deferrals."""
        now = now or datetime.now()
        is_night = forensics.is_night_time(now)
        devices = await db.get_all_devices()
        night_devices = [d for d in devices if d.night_mode_enabled]

        if not night_devices:
            return

        inactivity_minutes = getattr(settings, "night_mode_tv_inactivity_minutes", 5)

        for d in night_devices:
            mac = d.mac.upper()
            if mac not in self._tv_night_status:
                self._tv_night_status[mac] = {
                    "entered_night_mode_tonight": False,
                    "in_night_mode": False,
                    "wan_blocked_by_night_mode": False,
                    "morning_notified": not is_night,  # True if started during day/evening: prevents false morning alert
                    "was_in_night_window": is_night,   # Only alert if night was actually monitored
                    "last_active_time": time.time()
                }
            state = self._tv_night_status[mac]

            if is_night:
                if not state.get("was_in_night_window"):
                    # Entering a new night window: reset flags
                    state["was_in_night_window"] = True
                    state["entered_night_mode_tonight"] = False
                    state["in_night_mode"] = False
                state["morning_notified"] = False
                is_active = await self._is_device_active(d, inactivity_minutes)
                if is_active:
                    state["last_active_time"] = time.time()
                    logger.debug("Smart Night Mode deferred for %s (%s): device is active", d.hostname or mac, d.ip)
                else:
                    # Inactive for at least inactivity_minutes
                    silence_sec = time.time() - state["last_active_time"]
                    if silence_sec >= (inactivity_minutes * 60) and not state["in_night_mode"]:
                        state["in_night_mode"] = True
                        state["entered_night_mode_tonight"] = True
                        logger.info("Smart Night Mode activated for %s (%s) after %d min inactivity",
                                    d.hostname or mac, d.ip, inactivity_minutes)
                        if getattr(settings, "night_mode_auto_block_wan", False) and not d.is_blocked_wan:
                            try:
                                from keenguard.core.profiles import profile_manager
                                await profile_manager.toggle_wan(d.mac, block=True)
                                state["wan_blocked_by_night_mode"] = True
                                logger.info("Smart Night Mode: WAN blocked for %s", d.hostname or mac)
                            except Exception as ex:
                                logger.error("Failed to block WAN in night mode for %s: %s", mac, ex)

            else:
                # Daytime / Morning
                if not state.get("morning_notified"):
                    state["morning_notified"] = True
                    # Check if TV was active all night and never entered night mode
                    notify_enabled = getattr(settings, "night_mode_notify_tv_never_slept", True)
                    was_monitored = state.get("was_in_night_window", True)
                    state["was_in_night_window"] = False
                    if was_monitored and not state.get("entered_night_mode_tonight") and notify_enabled:
                        dev_name = d.custom_name or d.hostname or d.ip or mac
                        desc = (f"Smart TV ({dev_name}) за всю ночь так и не перешёл в ночной режим: "
                                f"непрерывная сетевая активность без перехода в режим ожидания")
                        ev = SecurityEvent(
                            event_type=EventType.TV_STANDBY_WAKE.value,
                            severity=Severity.WARNING.value,
                            target_mac=d.mac,
                            target_ip=d.ip,
                            source_mac=d.mac,
                            source_name=dev_name,
                            description=desc,
                            details={
                                "reason": "tv_active_all_night",
                                "night_start_hour": settings.night_mode_start_hour,
                                "night_end_hour": settings.night_mode_end_hour,
                                "inactivity_threshold_min": inactivity_minutes
                            }
                        )
                        await db.record_event(ev)
                        try:
                            from keenguard.core.notifier import notifier
                            await notifier.send_alert(ev)
                        except Exception as ne:
                            logger.debug("Failed to send morning TV alert to Telegram: %s", ne)

                # Restore WAN if blocked by night mode
                if state.get("wan_blocked_by_night_mode"):
                    try:
                        from keenguard.core.profiles import profile_manager
                        await profile_manager.toggle_wan(d.mac, block=False)
                        state["wan_blocked_by_night_mode"] = False
                        logger.info("Smart Night Mode: WAN unblocked in morning for %s", d.hostname or mac)
                    except Exception as ex:
                        logger.error("Failed to unblock WAN in morning for %s: %s", mac, ex)

                # Reset night state for following night
                state["in_night_mode"] = False
                state["entered_night_mode_tonight"] = False

scheduler = BackgroundScheduler()
