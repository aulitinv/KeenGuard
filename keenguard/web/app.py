"""FastAPI application providing REST endpoints and WebSockets for KeenGuard."""
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Core singletons and database
from keenguard.db.database import db
from keenguard.core.keenetic import keenetic_client
from keenguard.core.sniffer import sniffer
from keenguard.core.audit import audit_manager

# WebSocket and task tracking
from keenguard.web.ws import (
    ConnectionManager,
    ws_manager,
    set_main_loop,
    _main_loop,
    create_tracked_task,
    _background_tasks,
    broadcast_event,
    router as ws_router,
)

# Background workers, health monitoring, and lifespan
from keenguard.web.workers import (
    RouterHealthMonitor,
    router_health,
    do_keenetic_poll,
    _poll_counter,
    _handle_sniffer_event,
    lifespan,
)

# Modular REST routers
from keenguard.web.routes import all_routers
from keenguard.web.routes.security import check_ip_cdn_status

logger = logging.getLogger("keenguard.web")

# Initialize FastAPI application
app = FastAPI(
    title="KeenGuard",
    description="Network Security & Monitoring for Keenetic",
    version="1.0.0",
    lifespan=lifespan,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "KeenGuard backend is active. Web UI index.html not found."}


# Mount all modular routers
app.include_router(ws_router)
for router in all_routers:
    app.include_router(router)

__all__ = [
    "app",
    "lifespan",
    "db",
    "keenetic_client",
    "audit_manager",
    "sniffer",
    "router_health",
    "ws_manager",
    "ConnectionManager",
    "RouterHealthMonitor",
    "do_keenetic_poll",
    "_poll_counter",
    "create_tracked_task",
    "_background_tasks",
    "_main_loop",
    "set_main_loop",
    "_handle_sniffer_event",
    "check_ip_cdn_status",
    "broadcast_event",
]
