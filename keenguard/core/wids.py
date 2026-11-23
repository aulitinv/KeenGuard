"""Wireless Intrusion Detection System (WIDS) for KeenGuard.

Provides defense against wireless attacks (inspired by the Airgorah threat model):
1. Deauth Flood Attack Detection from system logs.
2. PMF (802.11w) Management Frame Protection Auditing.
3. Rogue AP / Evil Twin Wireless Clone Detection.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import logging
import re
from typing import List, Dict, Any, Optional, Set

from keenguard.db.models import SecurityEvent

logger = logging.getLogger("keenguard.core.wids")

MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})")
TIMESTAMP_REGEX = re.compile(r"([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")

DEAUTH_SIGNATURES = [
    re.compile(r"deauthenticated due to local deauth request", re.IGNORECASE),
    re.compile(r"deauthenticated \(reason=(\d+)\)", re.IGNORECASE),
    re.compile(r"Station\s+([0-9a-fA-F:]{17})\s+deauthenticated", re.IGNORECASE),
    re.compile(r"AP-STA-DISCONNECTED\s+([0-9a-fA-F:]{17})", re.IGNORECASE),
    re.compile(r"deauth request from\s+([0-9a-fA-F:]{17})", re.IGNORECASE),
    re.compile(r"unicast deauth", re.IGNORECASE),
    re.compile(r"Station\s+([0-9a-fA-F:]{17})\s+disassociated", re.IGNORECASE),
]


@dataclass
class DeauthEvent:
    timestamp: datetime
    mac: str
    interface: str = "wlan0"
    reason: str = "deauth"
    raw_message: str = ""


class DeauthFloodDetector:
    """Detects bursts of deauthentication frames indicative of Wi-Fi jamming or handshake capture."""

    def __init__(self, burst_threshold: int = 5, window_seconds: int = 15):
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds

    def parse_log_line(self, line: str, reference_year: Optional[int] = None) -> Optional[DeauthEvent]:
        if "disassociated due to inactivity" in line.lower():
            return None
        is_deauth = any(sig.search(line) for sig in DEAUTH_SIGNATURES)
        if not is_deauth:
            return None

        # Extract MAC
        mac_match = MAC_REGEX.search(line)
        mac = mac_match.group(1).upper() if mac_match else "UNKNOWN_MAC"

        # Extract Interface if present
        if_match = re.search(r"\b(wlan\d+|WifiMaster\d+(?:/AccessPoint\d+)?|ra\d+|rai\d+)\b", line, re.IGNORECASE)
        interface = if_match.group(1) if if_match else "Wi-Fi"

        # Extract Timestamp
        now = datetime.now(timezone.utc)
        ts_match = TIMESTAMP_REGEX.search(line)
        event_time = now
        if ts_match:
            raw_ts = ts_match.group(1)
            try:
                if "T" in raw_ts or "-" in raw_ts:
                    event_time = datetime.fromisoformat(raw_ts).replace(tzinfo=timezone.utc)
                else:
                    # e.g. "Nov 22 17:30:15"
                    year = reference_year or now.year
                    parsed = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
                    event_time = parsed.replace(tzinfo=timezone.utc)
            except Exception:
                event_time = now

        reason = "deauth_request"
        if "reason=" in line:
            r_match = re.search(r"reason=(\d+)", line)
            if r_match:
                reason = f"code_{r_match.group(1)}"

        return DeauthEvent(
            timestamp=event_time,
            mac=mac,
            interface=interface,
            reason=reason,
            raw_message=line.strip()
        )

    def analyze_logs(self, log_lines: List[str]) -> List[Dict[str, Any]]:
        """Parses lines and returns detected deauth flood bursts."""
        events: List[DeauthEvent] = []
        for line in log_lines:
            ev = self.parse_log_line(line)
            if ev:
                events.append(ev)

        if not events:
            return []

        # Sort chronologically
        events.sort(key=lambda x: x.timestamp)

        floods = []
        n = len(events)
        i = 0
        while i < n:
            window_start = events[i].timestamp
            window_end = window_start + timedelta(seconds=self.window_seconds)

            window_events = [events[i]]
            j = i + 1
            while j < n and events[j].timestamp <= window_end:
                window_events.append(events[j])
                j += 1

            unique_macs = {e.mac for e in window_events if e.mac != "UNKNOWN_MAC"}
            count = len(window_events)

            # Burst criteria: >= burst_threshold total events OR >= 3 unique stations in window
            if count >= self.burst_threshold or len(unique_macs) >= 3:
                first_ts = window_events[0].timestamp.isoformat()
                last_ts = window_events[-1].timestamp.isoformat()
                interfaces = list({e.interface for e in window_events})

                floods.append({
                    "type": "wifi_deauth_flood",
                    "severity": "critical",
                    "title": "Обнаружен Deauth-флуд: атака на беспроводной эфир",
                    "description": (
                        f"Зафиксирован всплеск из {count} событий принудительного отключения клиентов (Deauth) "
                        f"в диапазоне {', '.join(interfaces)} за {self.window_seconds} сек. "
                        f"Вероятна атака глушения Wi-Fi (Airgorah/Aireplay-ng/mdk4) или перехват WPA-рукопожатий."
                    ),
                    "event_count": count,
                    "affected_macs": list(unique_macs),
                    "interfaces": interfaces,
                    "start_time": first_ts,
                    "end_time": last_ts,
                    "recommendations": [
                        "Включите обязательный PMF (802.11w) в настройках роутера для защиты кадров управления.",
                        "Для камер наблюдения и критичных узлов используйте проводное подключение Ethernet или WPA3-SAE.",
                        "Проверьте радиоэфир на наличие активных источников помех или портативных глушилок (Flipper Zero / Deauther)."
                    ]
                })
                # Move pointer past this window to avoid overlapping duplicates
                i = j
            else:
                i += 1

        return floods


class PmfSecurityAuditor:
    """Audits 802.11w Protected Management Frames (PMF) configuration."""

    @staticmethod
    def audit(networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not networks:
            return {
                "status": "warning",
                "grade": "C",
                "score": 60,
                "badge": "Wi-Fi не настроен",
                "summary": "Нет информации об активных точках доступа.",
                "networks": [],
                "recommendations": ["Настройте и защитите беспроводные сети роутера."]
            }

        audited_nets = []
        all_required = True
        any_disabled = False
        has_wpa3 = False

        for net in networks:
            ssid = net.get("ssid", "Unknown")
            sec = str(net.get("security", "") or net.get("security_type", "")).lower()
            pmf = str(net.get("pmf", "") or "").lower()
            band = net.get("band", "2.4/5 ГГц")

            is_wpa3 = "wpa3" in sec or "sae" in sec
            if is_wpa3:
                has_wpa3 = True

            # Determine effective PMF level
            if pmf in ("required", "mandatory", "1", "true") or (is_wpa3 and "mixed" not in sec):
                level = "required"
                label = "Обязательно (Mandatory)"
                level_desc = "Кадры управления зашифрованы аппаратно. Сеть неуязвима к Deauth-глушению."
            elif pmf in ("optional", "supported") or (is_wpa3 and "mixed" in sec):
                level = "optional"
                label = "По возможности (Optional)"
                level_desc = "PMF доступен только клиентам с поддержкой 802.11w. Старые WPA2 клиенты уязвимы."
                all_required = False
            else:
                level = "disabled"
                label = "Отключен (Disabled)"
                level_desc = "Защита кадров управления выключена. Любой клиент может быть отключен атакующим."
                all_required = False
                any_disabled = True

            audited_nets.append({
                "ssid": ssid,
                "band": band,
                "security": net.get("security", "WPA2"),
                "pmf_level": level,
                "pmf_label": label,
                "description": level_desc
            })

        if all_required:
            status = "ok"
            grade = "A+"
            score = 100
            badge = "802.11w Mandatory (Защищено)"
            summary = "Все Wi-Fi сети защищены обязательным шифрованием кадров управления (PMF). Деаутентификация блокируется на уровне радиочипа."
            recommendations = []
        elif any_disabled:
            status = "critical"
            grade = "D"
            score = 45
            badge = "PMF Отключен (Уязвимо)"
            summary = "Внимание: на части сетей отключена защита 802.11w! Сеть уязвима к принудительному отключению умных устройств и камер."
            recommendations = [
                "Включите PMF (802.11w) в режим 'По возможности' (optional) или 'Обязательно' (required).",
                "Переведите совместимые клиенты на протокол WPA3-Personal."
            ]
        else:
            status = "warning"
            grade = "B"
            score = 80
            badge = "PMF Optional (Совместимость)"
            summary = "Защита PMF включена в адаптивном режиме. Клиенты без поддержки 802.11w могут быть атакованы Deauth-пакетами."
            recommendations = [
                "По возможности переведите режим PMF в 'Обязательно' (required), если в сети нет устаревших 2.4 ГГц устройств."
            ]

        return {
            "status": status,
            "grade": grade,
            "score": score,
            "badge": badge,
            "summary": summary,
            "has_wpa3": has_wpa3,
            "networks": audited_nets,
            "recommendations": recommendations
        }


class RogueApDetector:
    """Detects Evil Twin and Rogue Access Points mimicking home network SSIDs."""

    @staticmethod
    def detect(
        scanned_aps: List[Dict[str, Any]],
        local_networks: List[Dict[str, Any]],
        authorized_bssids: Optional[Set[str]] = None
    ) -> List[Dict[str, Any]]:
        if not scanned_aps or not local_networks:
            return []

        authorized: Set[str] = set()
        if authorized_bssids:
            authorized.update(b.upper() for b in authorized_bssids)

        local_ssids: Dict[str, List[Dict[str, Any]]] = {}
        for net in local_networks:
            ssid = net.get("ssid")
            if ssid:
                s_lower = ssid.strip().lower()
                local_ssids.setdefault(s_lower, []).append(net)
                bssid = net.get("bssid") or net.get("mac")
                if bssid:
                    authorized.add(bssid.upper())

        rogue_incidents = []
        for ap in scanned_aps:
            ap_ssid = (ap.get("ssid") or "").strip()
            ap_bssid = (ap.get("bssid") or ap.get("mac") or "").upper()
            if not ap_ssid or not ap_bssid:
                continue

            # Skip our own authorized BSSIDs
            if ap_bssid in authorized:
                continue

            # Check for SSID clone (case-insensitive)
            if ap_ssid.lower() in local_ssids:
                matching_local = local_ssids[ap_ssid.lower()][0]
                channel = ap.get("channel", "Auto")
                rssi = ap.get("rssi", -70)
                sec = ap.get("security", "Unknown")

                rogue_incidents.append({
                    "type": "wifi_evil_twin",
                    "severity": "critical",
                    "title": f"Обнаружен клон сети (Evil Twin / Rogue AP): «{ap_ssid}»",
                    "description": (
                        f"Обнаружена сторонняя точка доступа с именем вашей сети «{ap_ssid}» "
                        f"и чужим BSSID {ap_bssid} на канале {channel} (уровень сигнала: {rssi} dBm). "
                        f"Возможна атака перехвата учетных данных и трафика клиентов (Man-in-the-Middle)."
                    ),
                    "ssid": ap_ssid,
                    "bssid": ap_bssid,
                    "channel": channel,
                    "rssi": rssi,
                    "security": sec,
                    "recommendations": [
                        "Не подключайтесь к открытым или дублирующим сетям с этим именем.",
                        "Включите в роутере режим WPA3-Personal (SAE), устойчивый к поддельным точкам доступа благодаря протоколу Dragonfly.",
                        "Проверьте помещение на наличие посторонних репитеров, Wi-Fi модулей или шпионских устройств."
                    ]
                })

        return rogue_incidents


class WIDSService:
    """Coordinating service for Wireless Intrusion Detection in KeenGuard."""

    def __init__(self):
        self.deauth_detector = DeauthFloodDetector()
        self.pmf_auditor = PmfSecurityAuditor()
        self.rogue_detector = RogueApDetector()
        self.deauth_silenced_until: Optional[datetime] = None
        self._last_notified: Dict[str, datetime] = {}
        self._last_recorded: Dict[str, datetime] = {}
        self._seen_deauth_fingerprints: Set[str] = set()

    def silence_deauth(self, seconds: int = 3600):
        """Silences deauth flood alerts for specified duration in seconds."""
        self.deauth_silenced_until = datetime.now(timezone.utc) + timedelta(seconds=seconds)
        logger.info("Deauth flood alerts silenced until %s", self.deauth_silenced_until.isoformat())

    def is_deauth_silenced(self) -> bool:
        """Returns True if deauth flood alert silence window is active."""
        if self.deauth_silenced_until is None:
            return False
        return datetime.now(timezone.utc) < self.deauth_silenced_until

    async def run_wids_audit(
        self,
        router_backend: Any,
        db: Optional[Any] = None,
        custom_logs: Optional[List[str]] = None,
        custom_scan: Optional[List[Dict[str, Any]]] = None,
        notify: bool = True
    ) -> Dict[str, Any]:
        """Runs full WIDS evaluation: Deauth detection, PMF posture, and Rogue AP scan."""
        # 1. Wi-Fi Security & PMF Audit
        wifi_data = await router_backend.get_wifi_security()
        networks = wifi_data.get("networks") or wifi_data.get("access_points", [])
        pmf_report = self.pmf_auditor.audit(networks)

        # 2. Deauth Flood Analysis
        log_lines: List[str] = []
        if self.is_deauth_silenced():
            deauth_incidents = []
        else:
            if custom_logs is not None:
                log_lines = custom_logs
            elif hasattr(router_backend, "get_system_log"):
                log_lines = await router_backend.get_system_log(limit=200)

            deauth_incidents = self.deauth_detector.analyze_logs(log_lines)

        # 3. Rogue AP / Evil Twin Detection
        scanned_aps: List[Dict[str, Any]] = []
        if custom_scan is not None:
            scanned_aps = custom_scan
        elif hasattr(router_backend, "get_wlan_scan"):
            scanned_aps = await router_backend.get_wlan_scan()

        evil_twin_incidents = self.rogue_detector.detect(scanned_aps, networks)

        # 4. Record detected incidents in DB and send notifications (deduplicated)
        recorded_ids = []
        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()

        # Prune memory caches if needed
        if len(self._last_recorded) > 200:
            self._last_recorded = {k: v for k, v in self._last_recorded.items() if (now_dt - v).total_seconds() < 3600}
        if len(self._last_notified) > 200:
            self._last_notified = {k: v for k, v in self._last_notified.items() if (now_dt - v).total_seconds() < 3600}

        events_to_notify = []
        for incident in deauth_incidents + evil_twin_incidents:
            if incident.get("type") == "wifi_deauth_flood":
                ifaces = tuple(sorted(incident.get("interfaces", [])))
                fp = f"deauth:{incident.get('start_time')}:{incident.get('end_time')}:{incident.get('event_count')}:{ifaces}"
                if fp in self._seen_deauth_fingerprints:
                    continue
                self._seen_deauth_fingerprints.add(fp)
                if len(self._seen_deauth_fingerprints) > 1000:
                    self._seen_deauth_fingerprints = set(list(self._seen_deauth_fingerprints)[-500:])

            incident_key = f"{incident['type']}:{incident.get('bssid') or incident.get('mac') or 'ALL'}:{incident.get('title') or ''}"
            last_recorded_time = self._last_recorded.get(incident_key)
            if last_recorded_time and (now_dt - last_recorded_time).total_seconds() < 900:
                continue
            self._last_recorded[incident_key] = now_dt

            ev = SecurityEvent(
                timestamp=now_iso,
                event_type=incident["type"],
                severity=incident["severity"],
                target_mac=None,
                source_mac=incident.get("bssid") or incident.get("mac"),
                source_name="WIDS Monitor",
                description=incident["title"],
                details=incident
            )
            if db:
                try:
                    ev_id = await db.record_event(ev)
                    recorded_ids.append(ev_id)
                except Exception as e:
                    logger.warning("Failed to record WIDS event into DB: %s", e)
            events_to_notify.append(ev)

        if notify and events_to_notify:
            try:
                from keenguard.core.notifier import notifier
                for ev in events_to_notify:
                    incident_key = f"{ev.event_type}:{ev.source_mac or 'ALL'}"
                    last_time = self._last_notified.get(incident_key)
                    if last_time and (now_dt - last_time).total_seconds() < 900:
                        continue
                    self._last_notified[incident_key] = now_dt
                    await notifier.send_alert(ev)
            except Exception as ex:
                logger.debug("Failed to send WIDS Telegram alert: %s", ex)

        # 5. Composite WIDS Score
        wids_score = pmf_report["score"]
        if deauth_incidents:
            wids_score = max(10, wids_score - 40)
        if evil_twin_incidents:
            wids_score = max(10, wids_score - 45)

        if wids_score >= 90:
            wids_grade = "A+"
        elif wids_score >= 75:
            wids_grade = "B"
        elif wids_score >= 50:
            wids_grade = "C"
        else:
            wids_grade = "F"

        all_incidents = deauth_incidents + evil_twin_incidents

        return {
            "score": wids_score,
            "grade": wids_grade,
            "pmf_audit": pmf_report,
            "deauth_incidents": deauth_incidents,
            "evil_twin_incidents": evil_twin_incidents,
            "all_incidents": all_incidents,
            "threats_count": len(all_incidents),
            "scanned_aps_count": len(scanned_aps),
            "timestamp": now_iso
        }


wids_service = WIDSService()
