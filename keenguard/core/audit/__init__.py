"""Device & network traffic audit package for KeenGuard.

Re-exports core forensic inspection, GeoIP categorization, and session management facilities.
"""
from keenguard.config import settings
from keenguard.db.database import db

from keenguard.core.audit.geoip import (
    KNOWN_SERVICES,
    CIDR_PROVIDERS,
    KNOWN_PROVIDERS,
    is_lan_ip,
    identify_geoip,
    lookup_geoip_online,
    identify_provider,
    load_known_services,
    load_cidr_providers,
)
from keenguard.core.audit.report import (
    build_device_audit_report,
    build_network_audit_report,
    save_pcap_packets,
)
from keenguard.core.audit.session import (
    evaluate_lan_access_policy,
    should_device_quarantine,
    extract_dns_query,
    extract_http_inspection,
    AuditSession,
    NetworkAuditSession,
)
from keenguard.core.audit.manager import (
    TrafficAuditManager,
    audit_manager,
)

__all__ = [
    "settings",
    "db",
    "KNOWN_SERVICES",
    "CIDR_PROVIDERS",
    "KNOWN_PROVIDERS",
    "is_lan_ip",
    "identify_geoip",
    "lookup_geoip_online",
    "identify_provider",
    "load_known_services",
    "load_cidr_providers",
    "build_device_audit_report",
    "build_network_audit_report",
    "save_pcap_packets",
    "evaluate_lan_access_policy",
    "should_device_quarantine",
    "extract_dns_query",
    "extract_http_inspection",
    "AuditSession",
    "NetworkAuditSession",
    "TrafficAuditManager",
    "audit_manager",
]
