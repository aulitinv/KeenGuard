"""Multi-router support package for KeenGuard."""
from keenguard.core.routers.base import BaseRouterBackend
from keenguard.core.routers.models import RouterHost, RouterSystemInfo
from keenguard.core.routers.keenetic import KeeneticBackend
from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.routers.manager import RouterManager, router_manager

__all__ = [
    "BaseRouterBackend",
    "RouterHost",
    "RouterSystemInfo",
    "KeeneticBackend",
    "OpenWrtBackend",
    "RouterManager",
    "router_manager",
]
