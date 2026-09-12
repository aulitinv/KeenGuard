"""DNS and Domain Activity Tracker for KeenGuard.

Tracks domain resolutions and connections made by network devices via
reverse DNS (PTR) lookups and cloud provider identification from active
NAT connection flows.
"""
import asyncio
import logging
import socket
import time
from typing import Dict, Any, List, Optional, Tuple

from keenguard.db.database import db

logger = logging.getLogger("keenguard.dns_tracker")

# Canonical domain fallbacks for IPs without PTR records
PROVIDER_DOMAINS: List[Tuple[str, str]] = [
    ("47.91.", "dreame.iot.alibabacloud.com"),
    ("47.", "iot.alibabacloud.com"),
    ("46.8.", "p2p.dreame.tech"),
    ("152.32.", "tuya.iot.cloud"),
    ("149.154.", "telegram.org"),
    ("91.108.", "telegram.org"),
    ("212.41.", "tantos.cloud"),
    ("161.117.", "qingping.iot.cloud"),
    ("46.46.", "qingping.iot.cloud"),
    ("89.232.", "smartac.gree.com"),
    ("46.32.186.", "keenetic.cloud"),
    ("17.", "apple.com"),
    ("142.250.", "google.com"),
    ("172.217.", "google.com"),
    ("216.58.", "google.com"),
    ("8.8.8.8", "dns.google"),
    ("8.8.4.4", "dns.google"),
    ("1.1.1.1", "one.one.one.one"),
    ("1.0.0.1", "cloudflare-dns.com"),
    ("104.", "cloudflare.com"),
    ("172.67.", "cloudflare.com"),
    ("77.88.", "yandex.net"),
    ("87.250.", "yandex.net"),
    ("93.158.", "yandex.net"),
    ("5.255.", "yandex.net"),
    ("95.163.", "mail.ru"),
    ("128.140.", "mail.ru"),
    ("88.198.", "hetzner.com"),
    ("136.243.", "hetzner.com"),
    ("3.", "amazonaws.com"),
    ("18.", "amazonaws.com"),
    ("52.", "amazonaws.com"),
    ("54.", "amazonaws.com"),
    ("20.", "azure.com"),
    ("40.", "azure.com"),
]

# Private / local IP ranges that shouldn't be resolved via external PTR
LOCAL_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "224.", "239.", "255.", "169.254."
)


class DnsTracker:
    """Continuously resolves and records domain activity of local devices."""

    def __init__(self, cache_ttl: float = 86400.0):
        # In-memory IP -> (domain_or_none, timestamp)
        self._cache: Dict[str, Tuple[Optional[str], float]] = {}
        self.cache_ttl = cache_ttl
        self._resolving: set = set()

    async def resolve_ip(self, ip: str) -> Optional[str]:
        """Resolves an external IP to a domain name using async PTR or provider fallback."""
        if not ip or ip.startswith(LOCAL_PREFIXES):
            return None

        now = time.time()
        if ip in self._cache:
            cached_domain, ts = self._cache[ip]
            if now - ts < self.cache_ttl:
                return cached_domain

        if ip in self._resolving:
            return None
        self._resolving.add(ip)

        domain: Optional[str] = None
        try:
            loop = asyncio.get_running_loop()
            res = await asyncio.wait_for(
                loop.getnameinfo((ip, 0), socket.NI_NAMEREQD),
                timeout=0.6
            )
            if res and res[0] and "." in res[0]:
                domain = res[0].lower().strip(".")
        except Exception:
            pass
        finally:
            self._resolving.discard(ip)

        # Fallback to known cloud provider domains if PTR returned nothing
        if not domain:
            for prefix, canon_domain in PROVIDER_DOMAINS:
                if ip.startswith(prefix):
                    domain = canon_domain
                    break

        self._cache[ip] = (domain, now)
        return domain

    async def track_nat_connections(self, nat_entries: List[Dict[str, Any]], current_devices_map: Dict[str, Any]) -> int:
        """Processes active NAT entries and records domain activity to SQLite."""
        if not nat_entries:
            return 0

        # Build IP -> MAC lookup
        ip_to_mac: Dict[str, str] = {}
        for mac, dev in current_devices_map.items():
            dev_ip = getattr(dev, "ip", None) or (dev.get("ip") if isinstance(dev, dict) else None)
            if dev_ip:
                ip_to_mac[dev_ip] = mac.upper()

        unique_connections = set()
        for entry in nat_entries:
            src = entry.get("src")
            dst = entry.get("dst")
            if not src or not dst:
                continue
            if dst.startswith(LOCAL_PREFIXES):
                continue
            unique_connections.add((src, dst))

        # Limit per poll to avoid overwhelming DNS resolver (up to 20 unique pairs per cycle)
        recorded = 0
        tasks = []
        for src, dst in list(unique_connections)[:20]:
            mac = ip_to_mac.get(src)
            tasks.append(self._process_single_connection(src, dst, mac))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            recorded = sum(1 for r in results if r is True)

        return recorded

    async def _process_single_connection(self, src: str, dst: str, mac: Optional[str]) -> bool:
        domain = await self.resolve_ip(dst)
        if domain and "." in domain:
            try:
                await db.record_dns_query(domain=domain, mac=mac, ip=dst)
                return True
            except Exception as e:
                logger.debug("Failed to record DNS query %s: %s", domain, e)
        return False

    async def record_domain(self, domain: str, mac: Optional[str] = None, ip: Optional[str] = None):
        """Directly records a queried domain (e.g. from sniffer or audit sessions)."""
        if domain and "." in domain:
            await db.record_dns_query(domain=domain, mac=mac, ip=ip)


dns_tracker = DnsTracker()
