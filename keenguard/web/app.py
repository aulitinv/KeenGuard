"""FastAPI application providing REST endpoints and WebSockets for KeenGuard."""
import logging
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Authentication & LAN access guard
from keenguard.web.routes.auth import is_request_authorized

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


FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
    'stroke="#6366f1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)


@app.get("/favicon.ico")
async def serve_favicon():
    from fastapi.responses import Response
    return Response(content=FAVICON_SVG, media_type="image/svg+xml")


PUBLIC_EXACT_PATHS = {
    "/",
    "/favicon.ico",
    "/api/auth/login",
    "/api/auth/status",
    "/api/auth/logout",
}

PUBLIC_PATH_PREFIXES = (
    "/static/",
    "/docs",
    "/redoc",
    "/openapi.json",
)


@app.middleware("http")
async def web_auth_middleware(request: Request, call_next):
    """Guards protected REST endpoints from unauthorized LAN access.
    Requests from localhost are exempt by default.
    Static assets, index page, and auth endpoints are always accessible.
    """
    path = request.url.path

    # Public exemptions
    if path in PUBLIC_EXACT_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
        return await call_next(request)

    # CORS pre-flight
    if request.method == "OPTIONS":
        return await call_next(request)

    # Enforce authentication on all protected API routes
    if path.startswith("/api/"):
        if not is_request_authorized(request):
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Требуется авторизация", "auth_required": True},
                headers={"WWW-Authenticate": "Bearer"},
            )

    return await call_next(request)


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
