"""Forensics module for investigating nighttime TV wake-ups and generating PCAP dumps."""
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

from keenguard.config import settings
from keenguard.db.models import SecurityEvent
from keenguard.db.database import db
from keenguard.core.sniffer import sniffer
from keenguard.core.keenetic import keenetic_client
from scapy.all import wrpcap, rdpcap, Ether, IP, ARP

logger = logging.getLogger("keenguard.forensics")

class ForensicsEngine:
    def __init__(self):
        self.tv_last_known_state: Dict[str, bool] = {}  # mac -> is_active
        self.recent_triggers: List[Dict[str, Any]] = []
        self.active_wake_collectors: Dict[str, List[Any]] = {}  # mac -> post-wake packet list

    def on_packet(self, pkt: Any, src_mac: Optional[str], dst_mac: Optional[str]):
        """Collects live packets for TVs currently in their post-wake recording window."""
        if not self.active_wake_collectors:
            return
        for target_mac, col in self.active_wake_collectors.items():
            if target_mac in (src_mac, dst_mac):
                col.append(pkt)

    def is_night_time(self, dt: Optional[datetime] = None) -> bool:
        """Returns True if current local time is within the night mode window (e.g. 00:00 - 07:00)."""
        now = dt or datetime.now()
        hour = now.hour
        start = settings.night_mode_start_hour
        end = settings.night_mode_end_hour
        if start < end:
            return start <= hour < end
        else:  # e.g., 23:00 to 07:00
            return hour >= start or hour < end

    def register_trigger(self, trigger_event: Dict[str, Any]):
        """Caches recent potential wake triggers (WOL, AirPlay, Cast, SSDP)."""
        import time
        trigger_event.setdefault("timestamp_float", time.time())
        self.recent_triggers.append(trigger_event)
        # Keep only the last 50 triggers
        if len(self.recent_triggers) > 50:
            self.recent_triggers.pop(0)

    async def check_tv_state_transition(self, mac: str, ip: str, is_active: bool, hostname: Optional[str] = None):
        """Called during periodic Keenetic RCI polling when TV changes link/active status."""
        prev_state = self.tv_last_known_state.get(mac, None)
        self.tv_last_known_state[mac] = is_active

        # TV transitioned from SLEEP (False) to AWAKE (True) - ignore startup baseline (None)
        if prev_state is False and is_active:
            import asyncio
            # Launch in background so the post-wake capture window doesn't block the main polling loop
            asyncio.create_task(self._handle_tv_wake(mac, ip, hostname))

    async def _handle_tv_wake(self, mac: str, ip: str, hostname: Optional[str] = None):
        import time
        import asyncio

        clean_mac = mac.upper()
        tv_name = hostname or f"TV ({clean_mac})"
        is_night = self.is_night_time()
        wake_time = time.time()
        logger.info("TV '%s' (%s) woke up! Night mode: %s", tv_name, clean_mac, is_night)

        # 0. Load device-specific configuration if present
        dev = await db.get_device(clean_mac)
        pre_seconds = dev.tv_pre_record_seconds if (dev and dev.tv_pre_record_seconds is not None) else getattr(settings, "tv_wake_pre_record_seconds", 30)
        post_seconds = dev.tv_post_record_seconds if (dev and dev.tv_post_record_seconds is not None) else getattr(settings, "tv_wake_post_record_seconds", 30)
        day_mode = dev.tv_day_mode if (dev and dev.tv_day_mode) else getattr(settings, "tv_day_tracking_mode", "autonomous_only")
        trigger_ttl = getattr(settings, "tv_wake_trigger_ttl_seconds", 60)

        # 1. Filter triggers by TTL (default <= 60s) to prevent daytime triggers falsely accusing devices at 3 AM
        valid_triggers = [
            trig for trig in self.recent_triggers
            if (wake_time - trig.get("timestamp_float", wake_time)) <= trigger_ttl
        ]

        cause_description = "Автономное пробуждение без внешних команд (внутренний таймер, облачный push или фоновая активность)"
        culprit_mac = None
        culprit_ip = None
        culprit_name = None
        is_autonomous = True

        # Look for matching triggers within TTL window
        matching_trigger = None
        for trig in reversed(valid_triggers):
            if trig.get("target_mac") == clean_mac:
                trig_src_mac = (trig.get("source_mac") or "").upper()
                trig_src_ip = trig.get("source_ip") or ""
                if (clean_mac and trig_src_mac == clean_mac) or (ip and trig_src_ip == ip):
                    continue
                matching_trigger = trig
                break

        if matching_trigger:
            is_autonomous = False
            culprit_mac = matching_trigger.get("source_mac")
            culprit_ip = matching_trigger.get("source_ip")
            culprit_name = matching_trigger.get("source_name", culprit_ip)
            cause_description = f"Пробуждение по локальной команде: {matching_trigger.get('description', 'local trigger')}"
            event_severity = "critical" if is_night else "info"
        elif valid_triggers:
            last_trig = valid_triggers[-1]
            if last_trig.get("event_type") in ["airplay_activity", "cast_activity", "dial_activity"]:
                trig_src_mac = (last_trig.get("source_mac") or "").upper()
                trig_src_ip = last_trig.get("source_ip") or ""
                if (clean_mac and trig_src_mac == clean_mac) or (ip and trig_src_ip == ip):
                    is_autonomous = True
                    cause_description = f"Автономное пробуждение (телевизор сам начал анонс/поиск {last_trig.get('event_type')})"
                    event_severity = "critical" if is_night else "info"
                else:
                    is_autonomous = False
                    culprit_ip = trig_src_ip
                    culprit_mac = trig_src_mac
                    cause_description = f"Возможное пробуждение через трансляцию {last_trig.get('event_type')} от {culprit_ip}"
                    event_severity = "critical" if is_night else "info"
            else:
                event_severity = "critical" if is_night else "warning"
        else:
            event_severity = "critical" if is_night else "warning"

        # Check daytime tracking filter
        if not is_night:
            if day_mode == "disabled":
                logger.info("Daytime tracking disabled for %s, skipping wake analysis.", tv_name)
                return
            if day_mode == "autonomous_only" and not is_autonomous:
                logger.info(
                    "Daytime wake for %s is user-initiated (%s), skipping alert/pcap per autonomous_only setting.",
                    tv_name, cause_description
                )
                return

        # 2. Extract Pre-Wake packets from dedicated device ring buffer or global buffer
        cutoff_time = wake_time - pre_seconds

        dev_buffer = sniffer.ring_buffers.get(clean_mac)
        pre_packets = []
        if dev_buffer and len(dev_buffer.buffer) > 0:
            pre_packets = dev_buffer.get_packets_since(cutoff_time)
        else:
            # Fallback to filtered global buffer
            pre_packets = [
                p for ts, p, _ in sniffer.global_buffer.get_packets_with_meta()
                if ts >= cutoff_time and (
                    (Ether in p and (p[Ether].src.upper() == clean_mac or p[Ether].dst.upper() == clean_mac)) or
                    (IP in p and (p[IP].src == ip or p[IP].dst == ip)) or
                    (ARP in p and (p[ARP].psrc == ip or p[ARP].pdst == ip))
                )
            ]

        # 3. Handle Post-Wake collection window (Hardware Keenetic Capture with fallback to Local Sniffer)
        post_packets = []
        capture_source = "local_broadcast"
        hw_capture_active = False

        if post_seconds > 0:
            logger.info("Recording post-wake packets for %s (%s) for %d seconds...", tv_name, clean_mac, post_seconds)
            self.active_wake_collectors[clean_mac] = []

            # Try Keenetic hardware packet capture directly on router kernel
            if ip and ip != "0.0.0.0":
                try:
                    if await keenetic_client.is_packet_capture_supported():
                        start_res = await keenetic_client.start_packet_capture(
                            interface="Bridge0",
                            target_ip=ip,
                            duration_seconds=post_seconds
                        )
                        if start_res and start_res.get("status") == "ok":
                            hw_capture_active = True
                            logger.info("Keenetic hardware packet capture started for TV %s (%s)", tv_name, ip)
                except Exception as e:
                    logger.debug("Could not start Keenetic hardware capture for TV %s: %s", tv_name, e)

            try:
                await asyncio.sleep(post_seconds)
            finally:
                local_packets = self.active_wake_collectors.pop(clean_mac, [])

            if hw_capture_active:
                try:
                    cap_file = await keenetic_client.stop_packet_capture(interface="Bridge0")
                    if cap_file:
                        temp_dest = settings.pcap_dir / f"temp_rci_{clean_mac.replace(':', '')}_{int(wake_time)}.pcap"
                        downloaded = await keenetic_client.download_capture_file(cap_file, temp_dest)
                        if downloaded and temp_dest.exists():
                            try:
                                rci_pkts = list(rdpcap(str(temp_dest)))
                                if rci_pkts:
                                    post_packets = rci_pkts
                                    capture_source = "router_hardware"
                                    logger.info(
                                        "Retrieved %d hardware packets from Keenetic for TV %s",
                                        len(rci_pkts), tv_name
                                    )
                            except Exception as pe:
                                logger.debug("Error parsing downloaded router PCAP: %s", pe)
                            finally:
                                try:
                                    temp_dest.unlink(missing_ok=True)
                                except Exception:
                                    pass
                        await keenetic_client.reset_packet_capture(interface="Bridge0")
                except Exception as e:
                    logger.error("Error finalizing Keenetic hardware capture for TV %s: %s", tv_name, e)

            if not post_packets:
                post_packets = local_packets

        # 4. Save combined Pre-wake + Post-wake PCAP file
        combined_packets = pre_packets + post_packets
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_filename = f"tv_wake_{clean_mac.replace(':', '')}_{timestamp_str}.pcap"
        pcap_path = settings.pcap_dir / pcap_filename
        packet_count = 0

        if combined_packets:
            try:
                settings.pcap_dir.mkdir(parents=True, exist_ok=True)
                wrpcap(str(pcap_path), combined_packets)
                packet_count = len(combined_packets)
            except Exception as e:
                logger.error("Failed to write tv_wake PCAP %s: %s", pcap_path, e)
                packet_count = 0

        logger.info(
            "Saved %d packets (pre: %d, post: %d, source: %s) to %s for target %s",
            packet_count, len(pre_packets), len(post_packets), capture_source, pcap_filename, clean_mac
        )

        prefix = "🚨 [НОЧНАЯ ТРЕВОГА]" if is_night else ("⚠️ [ПОДОЗРИТЕЛЬНО]" if is_autonomous else "📺 [АКТИВНОСТЬ]")
        full_desc = f"{prefix} {tv_name} включился: {cause_description}."
        if is_autonomous:
            source_lbl = "аппаратный дамп роутера" if capture_source == "router_hardware" else "локальный срез"
            full_desc += f" Сохранен {source_lbl} (-{pre_seconds}с .. +{post_seconds}с, {packet_count} пак.). Запущен аудит."

        # 5. Record SecurityEvent in Database
        event = SecurityEvent(
            event_type="night_wake" if is_night else "tv_wake",
            severity=event_severity,
            target_mac=clean_mac,
            target_ip=ip,
            source_mac=culprit_mac,
            source_ip=culprit_ip,
            source_name=culprit_name,
            description=full_desc,
            details={
                "is_night": is_night,
                "is_autonomous": is_autonomous,
                "capture_source": capture_source,
                "packet_dump_count": packet_count,
                "pre_packets_count": len(pre_packets),
                "post_packets_count": len(post_packets),
                "pre_seconds": pre_seconds,
                "post_seconds": post_seconds,
                "culprit_mac": culprit_mac,
                "culprit_ip": culprit_ip,
                "pcap_file": pcap_filename if packet_count > 0 else None,
                "auto_audit_started": is_autonomous and bool(ip and ip != "0.0.0.0")
            },
            pcap_file=pcap_filename if packet_count > 0 else None
        )
        await db.record_event(event)

        # 6. If autonomous, auto-start deep forensic audit to inspect every packet & connection
        if is_autonomous and ip and ip != "0.0.0.0":
            try:
                from keenguard.core.audit import audit_manager
                await audit_manager.start_audit(
                    mac=clean_mac,
                    ip=ip,
                    hostname=tv_name,
                    vendor="Smart TV",
                    duration_seconds=180 # 3 minutes deep packet & flow inspection
                )
                logger.info("Auto-started 3-min forensic audit for autonomously woken TV %s (%s)", tv_name, ip)
            except Exception as e:
                logger.error("Failed to auto-start traffic audit for TV %s: %s", tv_name, e)

        # 7. Send Telegram alert if warning or critical
        if event_severity in ("warning", "critical"):
            try:
                from keenguard.core.notifier import notifier
                asyncio.create_task(notifier.send_alert(event))
            except Exception as e:
                logger.debug("Failed to dispatch TV wake alert to Telegram: %s", e)

forensics = ForensicsEngine()


def _on_forensics_config_change(key: str, value: Any) -> None:
    if key == "night_mode_start_hour" and value is not None:
        try:
            forensics.night_mode_start_hour = int(value)
        except (ValueError, TypeError):
            pass
    elif key == "night_mode_end_hour" and value is not None:
        try:
            forensics.night_mode_end_hour = int(value)
        except (ValueError, TypeError):
            pass


try:
    from keenguard.core.config_service import config_service
    config_service.subscribe("night_mode_start_hour", _on_forensics_config_change)
    config_service.subscribe("night_mode_end_hour", _on_forensics_config_change)
except ImportError:
    pass

