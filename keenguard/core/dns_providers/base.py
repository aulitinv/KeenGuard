"""Base abstractions and data models for KeenGuard DNS security providers."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class UnifiedBlockedDnsQuery:
    """Represents a normalized blocked DNS query event from any DNS security provider."""
    domain: str
    timestamp: str            # ISO 8601 UTC
    client_ip: Optional[str] = None
    client_device_name: Optional[str] = None
    provider: str = ""        # "nextdns", "controld", "adguard_home", "pihole"
    block_reason: str = ""    # "ads_trackers", "malware", "parental", "custom_rule", etc.
    filter_list: Optional[str] = None     # e.g., "OISD", "AdGuard Base", "Pi-hole Gravity"
    tracker_category: Optional[str] = None # e.g., "Telemetry", "Analytics", "Advertising"


@dataclass
class DnsProviderStatus:
    """Connection status and diagnostics result for a DNS security provider."""
    is_connected: bool
    provider_name: str
    profile_or_version: str
    active_filters_count: int = 0
    error_message: Optional[str] = None


class BaseDnsSecurityProvider(ABC):
    """Abstract base class that every DNS security provider plugin must implement."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique provider identifier: 'nextdns', 'controld', 'adguard_home', 'pihole'."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable provider name, e.g. 'NextDNS', 'Control D', 'AdGuard Home', 'Pi-hole'."""
        pass

    @property
    @abstractmethod
    def is_cloud(self) -> bool:
        """True if cloud-hosted service (DoH/DoT), False if on-premise/LAN server."""
        pass

    @abstractmethod
    async def test_connection(self) -> DnsProviderStatus:
        """Tests API reachability, credentials and returns provider diagnostics."""
        pass

    @abstractmethod
    async def fetch_blocked_logs(
        self, since_iso: Optional[str] = None, limit: int = 100
    ) -> List[UnifiedBlockedDnsQuery]:
        """Fetches recent blocked queries from provider logs since since_iso timestamp."""
        pass
