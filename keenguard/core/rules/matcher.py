"""High-performance Rule Matching Engine for KeenGuard Rules Engine."""
import ipaddress
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union, Set
from pydantic import BaseModel, Field

from keenguard.db.models import SecurityRule
from keenguard.core.classifier import DeviceClassifier

logger = logging.getLogger("keenguard.rules.matcher")

ROUTER_DEFAULT_IPS = {"192.168.1.1", "192.168.0.1", "192.168.2.1"}


class MatchResult(BaseModel):
    """Result of flow evaluation against the rules chain."""
    matched: bool = False
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    action_mode: str = "pass"  # "pass" or "alert"
    severity: str = "info"
    notify_telegram: bool = False
    telegram_mode: str = "digest"
    record_pcap_seconds: int = 0
    hardware_wan_block: bool = False
    apply_preset_id: Optional[str] = None
    description: Optional[str] = None


def is_private_ip_address(ip_str: Optional[str]) -> bool:
    """Checks if an IP is private RFC 1918, link-local, loopback, or multicast."""
    if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "Unknown"):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_loopback
    except Exception:
        return False


def parse_port_rule(port_spec: Union[int, str]) -> Set[int]:
    """Parses port specifier (e.g. 8096, 'Jellyfin:8096', or '50000-50005') into a set of ports."""
    if isinstance(port_spec, int):
        return {port_spec}
    spec = str(port_spec).strip()
    if ":" in spec:
        spec = spec.split(":")[-1].strip()
    if "-" in spec:
        try:
            start_s, end_s = spec.split("-", 1)
            start_p, end_p = int(start_s), int(end_s)
            if 0 < start_p <= end_p <= 65535 and (end_p - start_p) <= 2000:
                return set(range(start_p, end_p + 1))
        except ValueError:
            pass
    try:
        return {int(spec)}
    except ValueError:
        return set()


class RuleMatcher:
    """In-memory, thread-safe rule matching engine."""

    def __init__(self, rules: Optional[List[SecurityRule]] = None):
        self._lock = threading.RLock()
        self.rules: List[SecurityRule] = []
        if rules:
            self.load_rules(rules)

    def load_rules(self, rules: List[SecurityRule]):
        """Loads and pre-sorts rules by order_index ASC."""
        with self._lock:
            # Only keep enabled rules for evaluation
            self.rules = sorted([r for r in rules if r.enabled], key=lambda r: r.order_index)
            logger.debug("RuleMatcher loaded %d active rules", len(self.rules))

    def evaluate_flow(
        self,
        src_mac: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = "TCP",
        bytes_count: int = 0,
        devices_map: Optional[Dict[str, Any]] = None,
        current_dt: Optional[datetime] = None
    ) -> MatchResult:
        """
        Evaluates a network flow against the active rule chain (First-Match Win).
        Returns MatchResult indicating whether a rule matched and the specified actions.
        """
        if not src_ip or not dst_ip:
            return MatchResult(matched=False)

        clean_src_mac = src_mac.upper() if src_mac else None
        proto_clean = (protocol or "TCP").upper()
        now = current_dt or datetime.now()

        # 1. Resolve source device properties
        src_dev = self._resolve_device(clean_src_mac, src_ip, devices_map)

        # 2. Determine flow direction
        is_dst_router = dst_ip in ROUTER_DEFAULT_IPS
        is_dst_private = is_private_ip_address(dst_ip)
        if is_dst_router:
            flow_direction = "lan_to_router"
        elif is_dst_private:
            flow_direction = "lan_to_lan"
        else:
            flow_direction = "lan_to_wan"

        with self._lock:
            for rule in self.rules:
                if self._matches_rule(rule, clean_src_mac, src_ip, src_dev, dst_ip, port, proto_clean, flow_direction, bytes_count, now):
                    return MatchResult(
                        matched=True,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        action_mode=rule.reaction.action_mode,
                        severity=str(rule.reaction.severity).lower(),
                        notify_telegram=rule.reaction.notify_telegram,
                        telegram_mode=rule.reaction.telegram_mode,
                        record_pcap_seconds=rule.reaction.record_pcap_seconds,
                        hardware_wan_block=rule.reaction.hardware_wan_block,
                        apply_preset_id=rule.reaction.apply_preset_id,
                        description=rule.description or rule.name
                    )

        return MatchResult(matched=False)

    def _resolve_device(self, clean_mac: Optional[str], ip: Optional[str], devices_map: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Resolves device info from devices_map cache or defaults."""
        dev = {}
        if devices_map:
            if clean_mac and clean_mac in devices_map:
                dev = devices_map[clean_mac]
            elif ip:
                for d in devices_map.values():
                    if isinstance(d, dict) and d.get("ip") == ip:
                        dev = d
                        break
                    elif hasattr(d, "ip") and getattr(d, "ip") == ip:
                        dev = {
                            "mac": getattr(d, "mac", clean_mac),
                            "ip": getattr(d, "ip", ip),
                            "profile": getattr(d, "profile", "unassigned"),
                            "segment": getattr(d, "segment", "Home"),
                            "vendor": getattr(d, "vendor", None),
                            "hostname": getattr(d, "hostname", None)
                        }
                        break

        # Normalize attributes
        return {
            "mac": dev.get("mac") or clean_mac,
            "ip": dev.get("ip") or ip,
            "profile": dev.get("profile") or "unassigned",
            "segment": dev.get("segment") or "Home",
            "vendor": dev.get("vendor") or "",
            "is_random_mac": DeviceClassifier.is_randomized_mac(clean_mac) if clean_mac else False
        }

    def _matches_rule(
        self,
        rule: SecurityRule,
        clean_src_mac: Optional[str],
        src_ip: str,
        src_dev: Dict[str, Any],
        dst_ip: str,
        port: Optional[int],
        protocol: str,
        flow_direction: str,
        bytes_count: int,
        now: datetime
    ) -> bool:
        """Evaluates whether all conditions of a specific rule match."""
        # 0. Check Temporary Rule expiration
        if rule.temporary_until:
            try:
                clean_ts = rule.temporary_until.replace("Z", "+00:00")
                exp_dt = datetime.fromisoformat(clean_ts)
                now_cmp = now
                if exp_dt.tzinfo is not None and now_cmp.tzinfo is None:
                    now_cmp = now_cmp.replace(tzinfo=timezone.utc)
                elif exp_dt.tzinfo is None and now_cmp.tzinfo is not None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                if now_cmp > exp_dt:
                    return False
            except Exception:
                pass

        # 1. Source matching
        src_cond = rule.source
        has_src_filter = bool(
            src_cond.device_macs or src_cond.profiles or
            src_cond.segments or src_cond.vendors or src_cond.properties
        )

        if has_src_filter:
            cand_match = False
            if clean_src_mac and any(m.upper() == clean_src_mac for m in src_cond.device_macs):
                cand_match = True
            elif src_ip and any(m == src_ip for m in src_cond.device_macs):
                cand_match = True
            elif src_dev["profile"] in src_cond.profiles:
                cand_match = True
            elif src_dev["segment"] in src_cond.segments:
                cand_match = True
            elif src_dev["vendor"] and any(v.lower() in src_dev["vendor"].lower() for v in src_cond.vendors):
                cand_match = True
            elif "random_mac" in src_cond.properties and src_dev["is_random_mac"]:
                cand_match = True

            matches_src = (not cand_match) if src_cond.invert else cand_match
            if not matches_src:
                return False

        # 2. Destination Direction matching
        dst_cond = rule.destination
        if dst_cond.direction != "any":
            if dst_cond.direction != flow_direction:
                return False

        # 3. Protocol matching
        if dst_cond.protocols and "ANY" not in [p.upper() for p in dst_cond.protocols]:
            if protocol not in [p.upper() for p in dst_cond.protocols]:
                return False

        # 4. Target IP matching
        if dst_cond.targets:
            target_matched = False
            for t in dst_cond.targets:
                clean_t = t.strip()
                if clean_t == dst_ip:
                    target_matched = True
                    break
                try:
                    if "/" in clean_t and ipaddress.ip_address(dst_ip) in ipaddress.ip_network(clean_t, strict=False):
                        target_matched = True
                        break
                except ValueError:
                    pass

            matches_target = (not target_matched) if dst_cond.invert_targets else target_matched
            if not matches_target:
                return False

        # 5. Port matching
        if dst_cond.ports:
            if port is None:
                return False
            allowed_ports = set()
            for p_spec in dst_cond.ports:
                allowed_ports.update(parse_port_rule(p_spec))

            port_matched = port in allowed_ports
            matches_port = (not port_matched) if dst_cond.invert_ports else port_matched
            if not matches_port:
                return False

        # 6. Context Volume matching
        ctx = rule.context
        if ctx.volume_operator:
            if ctx.volume_operator == ">" and bytes_count <= ctx.volume_bytes:
                return False
            elif ctx.volume_operator == "<" and (bytes_count >= ctx.volume_bytes or bytes_count == 0):
                return False

        # 7. Context Time Window matching
        if ctx.time_window == "night_only" or ctx.time_window == "day_only":
            try:
                from keenguard.config import settings
                start_h = getattr(settings, "night_mode_start_hour", 0)
                end_h = getattr(settings, "night_mode_end_hour", 7)
            except Exception:
                start_h, end_h = 0, 7

            if start_h <= end_h:
                is_night = (start_h <= now.hour < end_h)
            else:
                is_night = (now.hour >= start_h or now.hour < end_h)

            if ctx.time_window == "night_only" and not is_night:
                return False
            elif ctx.time_window == "day_only" and is_night:
                return False

        return True


# Global shared instance
rule_matcher = RuleMatcher()
