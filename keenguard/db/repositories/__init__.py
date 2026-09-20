"""Database repositories for KeenGuard domain entities."""
from keenguard.db.repositories.base import BaseRepository, PruneResult, _UNSET
from keenguard.db.repositories.devices import DeviceRepository
from keenguard.db.repositories.events import EventRepository
from keenguard.db.repositories.settings import SettingsRepository, BUILTIN_LAN_PRESETS
from keenguard.db.repositories.audit import AuditRepository
from keenguard.db.repositories.traffic import TrafficRepository
from keenguard.db.repositories.dns import DnsRepository
from keenguard.db.repositories.iot import IotRepository
from keenguard.db.repositories.lan import LanRepository
from keenguard.db.repositories.blackhole import BlackholeRepository
from keenguard.db.repositories.stats import StatsRepository

__all__ = [
    "BaseRepository",
    "PruneResult",
    "_UNSET",
    "DeviceRepository",
    "EventRepository",
    "SettingsRepository",
    "BUILTIN_LAN_PRESETS",
    "AuditRepository",
    "TrafficRepository",
    "DnsRepository",
    "IotRepository",
    "LanRepository",
    "BlackholeRepository",
    "StatsRepository",
]
