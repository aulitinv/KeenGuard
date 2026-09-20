"""Keenetic integration package."""
from keenguard.core.keenetic.models import (
    HotspotHost,
    UPnPMapping,
    is_host_lan_isolated,
    is_unsafe_ip_for_blackhole,
)
from keenguard.core.keenetic.base import KeeneticBaseClient
from keenguard.core.keenetic.client import KeeneticClient, keenetic_client, _on_router_config_change

__all__ = [
    "HotspotHost",
    "UPnPMapping",
    "is_host_lan_isolated",
    "is_unsafe_ip_for_blackhole",
    "KeeneticBaseClient",
    "KeeneticClient",
    "keenetic_client",
    "_on_router_config_change",
]
