"""Modular APIRouter package for KeenGuard web services."""
from typing import List
from fastapi import APIRouter

from keenguard.web.routes.devices import router as devices_router
from keenguard.web.routes.tv import router as tv_router
from keenguard.web.routes.dns import router as dns_router
from keenguard.web.routes.audit import router as audit_router
from keenguard.web.routes.security import router as security_router
from keenguard.web.routes.settings import router as settings_router
from keenguard.web.routes.export import router as export_router

all_routers: List[APIRouter] = [
    devices_router,
    tv_router,
    dns_router,
    audit_router,
    security_router,
    settings_router,
    export_router,
]

__all__ = [
    "all_routers",
    "devices_router",
    "tv_router",
    "dns_router",
    "audit_router",
    "security_router",
    "settings_router",
    "export_router",
]
