"""WebSocket management, real-time client broadcasting, and background task tracking."""
import asyncio
import json
import logging
import time
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from keenguard.core.scheduler import scheduler
from keenguard.db.models import SecurityEvent
from keenguard.web.state import (
    get_audit_manager,
    get_sniffer,
    get_router_health,
)

logger = logging.getLogger("keenguard.web.ws")

router = APIRouter(tags=["ws"])

# Retain strong references to background tasks so Python's GC does not terminate them
_background_tasks: set[Any] = set()
_main_loop: Optional[asyncio.AbstractEventLoop] = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop


def create_tracked_task(coro) -> Any:
    """Create an asyncio Task and retain a strong reference until completion to prevent GC collection.
    Thread-safe: if called from a background worker thread (like Scapy's sniffer thread),
    it safely schedules the coroutine onto the main event loop using run_coroutine_threadsafe.
    """
    global _main_loop
    try:
        loop = asyncio.get_running_loop()
        _main_loop = loop
        task = loop.create_task(coro)
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
        return task
    except RuntimeError:
        # No running event loop in current thread (e.g. Scapy sniffer worker thread)
        loop = _main_loop
        if loop is not None and loop.is_running():
            async def _tracked():
                t = asyncio.current_task()
                if t:
                    _background_tasks.add(t)
                    t.add_done_callback(_background_tasks.discard)
                return await coro

            return asyncio.run_coroutine_threadsafe(_tracked(), loop)
        else:
            logger.debug("Cannot schedule background task '%s': main event loop is not active", coro)
            try:
                coro.close()
            except Exception:
                pass
            return None


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for conn in list(self.active_connections):
            try:
                await conn.send_json(message)
            except Exception:
                self.disconnect(conn)


ws_manager = ConnectionManager()


async def broadcast_event(event: SecurityEvent):
    """Helper to broadcast a security event to all active WebSocket clients."""
    ev_dict = event.to_dict() if hasattr(event, "to_dict") else dict(event)
    await ws_manager.broadcast({
        "type": "security_event",
        "event": ev_dict
    })


@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    router_health = get_router_health()
    sniffer = get_sniffer()
    audit_manager = get_audit_manager()

    # Import do_keenetic_poll dynamically to avoid circular import issues
    from keenguard.web.workers import do_keenetic_poll

    try:
        while True:
            raw_data = await websocket.receive_text()
            try:
                msg = json.loads(raw_data)
                cmd = msg.get("command") or msg.get("type")
                if cmd in ("ping", "heartbeat"):
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
                elif cmd == "get_status":
                    await websocket.send_json({
                        "type": "status_response",
                        "connected": router_health.is_connected,
                        "model": router_health.model,
                        "version": router_health.version,
                        "sniffer_active": sniffer.is_running,
                        "scheduler_active": scheduler.is_running,
                        "timestamp": time.time()
                    })
                elif cmd == "refresh":
                    create_tracked_task(do_keenetic_poll())
                    await websocket.send_json({"type": "refresh_ack", "status": "polling_started"})
                elif cmd == "start_audit":
                    mac = msg.get("mac")
                    duration = int(msg.get("duration", 60))
                    if mac:
                        create_tracked_task(audit_manager.start_audit(mac=mac, duration_seconds=duration))
                        await websocket.send_json({"type": "audit_started", "mac": mac, "duration": duration})
                    else:
                        await websocket.send_json({"type": "error", "message": "MAC address is required for start_audit"})
                elif cmd == "stop_audit":
                    mac = msg.get("mac")
                    if mac:
                        audit_manager.stop_audit(mac)
                        await websocket.send_json({"type": "audit_stopped", "mac": mac})
                    else:
                        await websocket.send_json({"type": "error", "message": "MAC address is required for stop_audit"})
                else:
                    await websocket.send_json({"type": "ack", "received": cmd})
            except json.JSONDecodeError:
                if raw_data.strip().lower() in ("ping", "health"):
                    await websocket.send_json({"type": "pong", "timestamp": time.time()})
                else:
                    await websocket.send_json({"type": "ack", "received": raw_data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
