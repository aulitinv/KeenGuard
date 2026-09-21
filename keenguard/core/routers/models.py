"""Unified data models for multi-router integration."""
from typing import Optional, Any, Set
from pydantic import BaseModel, Field


class RouterHost(BaseModel):
    """Unified network host representation across all router backends."""
    mac: str
    ip: Optional[str] = None
    hostname: Optional[str] = None
    name: Optional[str] = None
    interface: Optional[Any] = None
    link: str = "up"
    active: bool = True
    rxbytes: int = 0
    txbytes: int = 0
    uptime: int = 0
    access: str = "permit"  # "permit" (WAN allowed) or "deny" (WAN blocked)
    registered: bool = False
    policy: Optional[str] = None
    segment: Optional[str] = "Home"


class RouterSystemInfo(BaseModel):
    """System information returned by the router backend."""
    model: str = "Router"
    firmware_version: str = "Unknown"
    uptime: int = 0
    cpu_load: float = 0.0
    memory_total: int = 0
    memory_free: int = 0
    platform: str = "generic"  # "keenetic" | "openwrt"
    extra: dict = Field(default_factory=dict)
