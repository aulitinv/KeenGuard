"""DNS security, DoH/DoT leak prevention, and bypass detection module."""
from keenguard.core.dns.doh_catalog import (
    DOH_DOMAINS,
    PUBLIC_RESOLVER_IPS,
    is_doh_domain,
    get_provider_for_domain,
    is_public_resolver_ip,
    get_provider_for_ip,
)
from keenguard.core.dns.bypass_detector import DnsBypassDetector, dns_bypass_detector

__all__ = [
    "DOH_DOMAINS",
    "PUBLIC_RESOLVER_IPS",
    "is_doh_domain",
    "get_provider_for_domain",
    "is_public_resolver_ip",
    "get_provider_for_ip",
    "DnsBypassDetector",
    "dns_bypass_detector",
]
