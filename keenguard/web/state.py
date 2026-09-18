"""Dynamic state resolver for KeenGuard web services.
Provides accessors that dynamically check `keenguard.web.app` attributes
to support monkeypatching and dependency isolation in automated tests.
"""
import sys
from typing import Any

from keenguard.db.database import db as default_db
from keenguard.core.keenetic import keenetic_client as default_keenetic_client
from keenguard.core.audit import audit_manager as default_audit_manager
from keenguard.core.sniffer import sniffer as default_sniffer


def get_db() -> Any:
    """Returns the active database instance, honoring test monkeypatching of keenguard.web.app.db."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "db"):
        return app_mod.db
    return default_db


def get_keenetic_client() -> Any:
    """Returns the active Keenetic RCI client, honoring test monkeypatching of keenguard.web.app.keenetic_client."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "keenetic_client"):
        return app_mod.keenetic_client
    return default_keenetic_client


def get_audit_manager() -> Any:
    """Returns the active audit manager, honoring test monkeypatching of keenguard.web.app.audit_manager."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "audit_manager"):
        return app_mod.audit_manager
    return default_audit_manager


def get_sniffer() -> Any:
    """Returns the active sniffer instance, honoring test monkeypatching of keenguard.web.app.sniffer."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "sniffer"):
        return app_mod.sniffer
    return default_sniffer


def get_router_health() -> Any:
    """Returns the active router health monitor."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "router_health"):
        return app_mod.router_health
    from keenguard.web.workers import router_health
    return router_health


def get_ws_manager() -> Any:
    """Returns the active WebSocket connection manager."""
    app_mod = sys.modules.get("keenguard.web.app")
    if app_mod and hasattr(app_mod, "ws_manager"):
        return app_mod.ws_manager
    from keenguard.web.ws import ws_manager
    return ws_manager
