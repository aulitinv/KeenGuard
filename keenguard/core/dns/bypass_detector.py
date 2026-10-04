"""Real-time detector of DNS-over-TLS (DoT), DNS-over-HTTPS (DoH), and external DNS bypasses."""
from datetime import datetime, timezone
import logging
import time
from typing import Optional, Dict, Any

from keenguard.core.dns.doh_catalog import (
    is_doh_domain,
    get_provider_for_domain,
    is_public_resolver_ip,
    get_provider_for_ip,
)
from keenguard.db.models import SecurityEvent

logger = logging.getLogger("keenguard.core.dns.bypass_detector")


class DnsBypassDetector:
    """Detects when network clients bypass Keenetic local DNS proxy via DoH, DoT, or direct external DNS."""

    def __init__(self, alert_cooldown_seconds: int = 300):
        self._alert_cooldown = alert_cooldown_seconds
        # Key: (src_mac_or_ip, bypass_type, target) -> last_alert_time
        self._last_alert: Dict[str, float] = {}

    def inspect_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str = "tcp",
        sni: Optional[str] = None,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Inspects flow parameters for DoH, DoT, or unencrypted external DNS.
        Returns a dictionary with bypass details if detected, else None.
        """
        if not src_ip or not dst_ip or not dst_port:
            return None

        proto_lower = proto.lower()
        bypass_type: Optional[str] = None
        provider: Optional[str] = None
        detail_target: str = ""

        # 1. DNS-over-TLS (DoT) on port 853 TCP or UDP
        if dst_port == 853:
            bypass_type = "dot_bypass"
            provider = get_provider_for_ip(dst_ip) or "Public DoT Resolver"
            detail_target = f"{dst_ip}:853"

        # 2. DNS-over-HTTPS (DoH) on port 443 TCP or UDP (QUIC)
        elif dst_port == 443:
            if sni and is_doh_domain(sni):
                bypass_type = "doh_bypass"
                provider = get_provider_for_domain(sni) or sni
                detail_target = sni
            elif is_public_resolver_ip(dst_ip):
                bypass_type = "doh_bypass"
                provider = get_provider_for_ip(dst_ip) or dst_ip
                detail_target = f"{dst_ip}:443"

        # 3. Direct unencrypted external DNS on port 53 (bypassing local Keenetic resolver)
        elif dst_port == 53:
            # Check if destination is not a private RFC1918 / localhost IP
            if not self._is_private_ip(dst_ip):
                bypass_type = "external_dns_bypass"
                provider = get_provider_for_ip(dst_ip) or dst_ip
                detail_target = f"{dst_ip}:53"

        if not bypass_type:
            return None

        # Format detection record
        device_label = hostname or mac or src_ip
        if bypass_type == "dot_bypass":
            desc = (
                f"Обнаружен обход локального DNS через DoT (DNS-over-TLS, порт 853) "
                f"устройством '{device_label}' ({src_ip} -> {detail_target}, {provider}). "
                f"Локальные фильтры Keenetic не действуют на этот трафик."
            )
            severity = "warning"
        elif bypass_type == "doh_bypass":
            desc = (
                f"Обнаружен обход локального DNS через DoH (DNS-over-HTTPS, порт 443) "
                f"устройством '{device_label}' ({src_ip} -> {detail_target}, {provider}). "
                f"Запросы направляются в обход локального DNS-прокси роутера."
            )
            severity = "warning"
        else:
            desc = (
                f"Обнаружен прямой DNS-запрос на внешний сервер "
                f"устройством '{device_label}' ({src_ip} -> {detail_target}, {provider}) "
                f"в обход локального резолвера Keenetic."
            )
            severity = "info"

        dedup_key = f"{mac or src_ip}:{bypass_type}:{detail_target}"
        now = time.time()
        should_alert = False
        if now - self._last_alert.get(dedup_key, 0.0) >= self._alert_cooldown:
            self._last_alert[dedup_key] = now
            should_alert = True

        return {
            "event_type": bypass_type,
            "severity": severity,
            "src_ip": src_ip,
            "src_mac": mac,
            "hostname": hostname,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": proto_lower,
            "sni": sni,
            "provider": provider,
            "target": detail_target,
            "description": desc,
            "should_alert": should_alert,
        }

    async def handle_detected_flow(self, flow_info: Dict[str, Any], db=None, notifier=None):
        """Creates a SecurityEvent in DB and optionally dispatches a Telegram notification."""
        if not flow_info or not flow_info.get("should_alert"):
            return

        ev = SecurityEvent(
            event_type=flow_info["event_type"],
            severity=flow_info["severity"],
            target_mac=flow_info.get("src_mac"),
            target_ip=flow_info.get("src_ip"),
            description=flow_info["description"],
            details={
                "provider": flow_info.get("provider"),
                "target": flow_info.get("target"),
                "dst_ip": flow_info.get("dst_ip"),
                "dst_port": flow_info.get("dst_port"),
                "proto": flow_info.get("proto"),
                "sni": flow_info.get("sni"),
            }
        )

        if db:
            await db.record_event(ev)
        if notifier:
            await notifier.send_alert(ev)

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Checks if IP is private/local."""
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            try:
                parts = ip.split(".")
                second = int(parts[1])
                return 16 <= second <= 31
            except Exception:
                pass
        if ip in ("::1", "fe80:", "fc00:", "fd00:"):
            return True
        return False


dns_bypass_detector = DnsBypassDetector()
