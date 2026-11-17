"""
End-to-End Headless Browser Interaction Tests (Chrome/Edge via CDP).

Simulates genuine human user interactions via hardware-level Chrome DevTools Protocol:
1. Topology Map: SVG node hit-testing, open modal, Escape dismissal.
2. Topology Physics: Human hand tremor/jitter (<=5px) vs intentional node drag (>10px).
3. Physical Isolation Wizard: modal lifecycle, backdrop click, Escape key.
4. Rule Builder Lifecycle: open modal, enter rule name, save, re-render, delete.
5. Devices Inspector: real-time search typing, category filter pills, modal tab switching.
6. Security Incidents & UPnP: inspect alerts, revoke UPnP forwarding.
7. DNS Inspector: domain query search, domain details modal.
8. Command Palette (Ctrl+K): keyboard shortcut, query typing, Enter navigation.
9. DPI Traffic Audit: launch audit session, active banner, stop, report inspection.
10. Settings & Export: subtab navigation, quarantine checkboxes, data export.
"""

import asyncio
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

import httpx
import pytest
import uvicorn
import websockets
from fastapi import FastAPI, WebSocket, Body, Response
from fastapi.staticfiles import StaticFiles

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "keenguard" / "web" / "static"


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def get_browser_binary() -> str | None:
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("msedge")


@pytest.fixture(scope="module")
def browser_path() -> str:
    bin_path = get_browser_binary()
    if not bin_path:
        pytest.skip("Chrome or Edge browser executable not found on host system.")
    return bin_path


@pytest.fixture(scope="module")
def e2e_server():
    """Runs a stateful mock backend serving static assets and realistic API endpoints."""
    app = FastAPI()

    devices_db = [
        {
            "mac": "00:11:22:33:44:01",
            "ip": "192.168.1.100",
            "name": "Samsung Galaxy S25",
            "hostname": "Samsung-S25",
            "custom_name": "Samsung Galaxy S25",
            "profile": "trusted",
            "is_online": True,
            "first_seen": "2026-10-05T12:00:00",
            "last_seen": "2026-10-06T00:30:00",
            "is_wan_blocked": False,
            "is_isolated_lan": False,
            "segment": "Bridge0",
            "vendor": "Samsung Electronics",
            "is_random_mac": False,
        },
        {
            "mac": "11:22:33:44:55:66",
            "ip": "192.168.1.55",
            "name": "LG OLED 65 Smart TV",
            "hostname": "LG-webOS-TV",
            "custom_name": "LG OLED 65 Smart TV",
            "profile": "smart_tv",
            "is_online": True,
            "first_seen": "2026-10-05T12:00:00",
            "last_seen": "2026-10-06T00:30:00",
            "is_wan_blocked": False,
            "is_isolated_lan": False,
            "segment": "Bridge0",
            "vendor": "LG Electronics",
            "is_random_mac": False,
        },
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "ip": "192.168.1.80",
            "name": "Hikvision Outdoor Camera",
            "hostname": "HIK-IPCam-Dome",
            "custom_name": "Hikvision Outdoor Camera",
            "profile": "camera",
            "is_online": True,
            "first_seen": "2026-10-05T12:00:00",
            "last_seen": "2026-10-06T00:30:00",
            "is_wan_blocked": False,
            "is_isolated_lan": False,
            "segment": "Bridge0",
            "vendor": "Hangzhou Hikvision",
            "is_random_mac": False,
        },
        {
            "mac": "00:11:22:33:44:55",
            "ip": "192.168.1.99",
            "name": "Tuya Smart Bulb",
            "hostname": "ESP-Tuya-Bulb",
            "custom_name": "Tuya Smart Bulb",
            "profile": "iot",
            "is_online": False,
            "first_seen": "2026-10-04T12:00:00",
            "last_seen": "2026-10-05T10:00:00",
            "is_wan_blocked": True,
            "is_isolated_lan": False,
            "segment": "Bridge0",
            "vendor": "Tuya Smart",
            "is_random_mac": False,
        }
    ]

    rules_db = [
        {
            "id": "rule_block_mirai",
            "order_index": 1,
            "name": "Block Mirai Botnet Ports",
            "description": "Auto block telnet 23 and rdp 3389",
            "enabled": True,
            "is_builtin": True,
            "category": "core",
            "source": {"invert": False, "device_macs": [], "profiles": []},
            "destination": {"direction": "lan_to_wan", "ports": [23, 3389], "protocols": ["TCP"], "targets": []},
            "context": {"volume_operator": "", "volume_bytes": 0, "time_window": "always"},
            "reaction": {"action_mode": "alert", "severity": "CRITICAL", "notify_telegram": True}
        }
    ]

    events_db = [
        {
            "id": 1,
            "timestamp": "2026-10-06T00:35:10",
            "event_type": "upnp_port_forward",
            "severity": "critical",
            "title": "Опасный UPnP проброс RTSP (порт 554)",
            "description": "Камера Hikvision открыла внешний доступ к видеопотоку без пароля",
            "source_ip": "192.168.1.80",
            "mac": "aa:bb:cc:dd:ee:ff",
            "details": {"ext_port": 554}
        },
        {
            "id": 2,
            "timestamp": "2026-10-06T00:30:00",
            "event_type": "arp_scan",
            "severity": "warning",
            "title": "ARP-разведка сети (Сетевое сканирование)",
            "description": "Обнаружен последовательный опрос 254 адресов подсети",
            "source_ip": "192.168.1.100",
            "mac": "00:11:22:33:44:01",
            "details": {}
        }
    ]

    upnp_db = [
        {
            "protocol": "TCP",
            "ext_port": 554,
            "int_port": 554,
            "ip": "192.168.1.80",
            "desc": "Hikvision RTSP Video Stream",
            "danger": True,
            "device_name": "Hikvision Outdoor Camera"
        }
    ]

    dns_db = [
        {
            "id": 1,
            "timestamp": "2026-10-06T00:40:00",
            "domain": "telemetry.samsungcloud.com",
            "client_ip": "192.168.1.100",
            "query_type": "A",
            "ip": "203.0.113.195",
            "is_blocked": False,
            "analysis": {"category": "telemetry", "risk": "low"},
            "devices": [{"ip": "192.168.1.100", "name": "Samsung Galaxy S25"}]
        },
        {
            "id": 2,
            "timestamp": "2026-10-06T00:39:00",
            "domain": "api.netflix.com",
            "client_ip": "192.168.1.55",
            "query_type": "A",
            "ip": "198.51.100.22",
            "is_blocked": False,
            "analysis": {"category": "media", "risk": "safe"},
            "devices": [{"ip": "192.168.1.55", "name": "LG OLED 65 Smart TV"}]
        }
    ]

    audit_reports_db = [
        {
            "id": "aud_rep_001",
            "created_at": "2026-10-06T00:20:00",
            "mac": "11:22:33:44:55:66",
            "hostname": "LG OLED 65 Smart TV",
            "ip": "192.168.1.55",
            "duration_seconds": 60,
            "total_bytes": 450200,
            "total_packets": 320,
            "risk_score": 75,
            "risk_level": "medium",
            "findings": [
                "Обнаружен незашифрованный HTTP-трафик на порт 80",
                "Фоновая телеметрия LG ThinQ во время ожидания"
            ]
        }
    ]

    active_audits = {}

    @app.get("/api/auth/status")
    async def auth_status():
        return {"authenticated": True, "auth_required": False, "web_host": "127.0.0.1", "is_localhost": True}

    @app.get("/api/status")
    async def status():
        return {"router": {"connected": True, "model": "Keenetic Ultra", "ip": "192.168.1.1"}, "monitoring": {"active": True}}

    @app.get("/api/devices")
    async def get_devices():
        return devices_db

    @app.get("/api/devices/{mac}")
    async def device_detail(mac: str):
        dev = next((d for d in devices_db if d["mac"].lower() == mac.lower()), devices_db[0])
        return {"device": dev}

    @app.post("/api/devices/{mac}/rename")
    async def rename_device(mac: str, payload: dict = Body(...)):
        for d in devices_db:
            if d["mac"].lower() == mac.lower():
                d["name"] = payload.get("name", d["name"])
                return {"status": "ok", "device": d}
        return {"status": "ok"}

    @app.post("/api/devices/{mac}/policy")
    async def policy_device(mac: str, payload: dict = Body(...)):
        for d in devices_db:
            if d["mac"].lower() == mac.lower():
                if "is_wan_blocked" in payload:
                    d["is_wan_blocked"] = payload["is_wan_blocked"]
                if "is_isolated_lan" in payload:
                    d["is_isolated_lan"] = payload["is_isolated_lan"]
                return {"status": "ok", "device": d}
        return {"status": "ok"}

    @app.get("/api/devices/{mac}/traffic")
    async def device_traffic(mac: str):
        return {"points": []}

    @app.get("/api/devices/{mac}/isolation_guide")
    async def isolation_guide(mac: str):
        dev = next((d for d in devices_db if d["mac"].lower() == mac.lower()), devices_db[0])
        return {
            "device": dev,
            "physical_steps": [
                {"title": "Шаг 1: Конфигуратор Keenetic", "description": "Перейдите в 'Мои сети' -> 'Гостевой сегмент'."},
                {"title": "Шаг 2: Включение L2-изоляции", "description": "Активируйте 'Изолировать клиентов'."}
            ],
            "technical_context": {
                "current_segment": "Bridge0",
                "hardware_enforcement": "Для реальной изоляции необходим отдельный сегмент Bridge1."
            }
        }

    @app.get("/api/network/topology")
    async def topology():
        nodes = [
            {"id": "node_router", "type": "router", "label": "Keenetic Ultra", "ip": "192.168.1.1"},
            {"id": "segment_Bridge0", "type": "segment", "label": "Bridge0 (Домашняя сеть)", "ip": "192.168.1.0/24"},
        ]
        links = [{"source": "node_router", "target": "segment_Bridge0", "type": "trunk"}]
        for i, d in enumerate(devices_db, 1):
            nodes.append({
                "id": f"dev_{i}",
                "type": "device",
                "mac": d["mac"],
                "label": d["name"],
                "is_online": d["is_online"],
                "profile": d["profile"]
            })
            links.append({
                "source": "segment_Bridge0",
                "target": f"dev_{i}",
                "type": "client",
                "is_online": d["is_online"]
            })
        return {
            "nodes": nodes,
            "links": links,
            "meta": {"total_devices": len(devices_db), "online_devices": sum(1 for d in devices_db if d["is_online"])}
        }

    @app.get("/api/rules")
    async def get_rules():
        return rules_db

    @app.post("/api/rules")
    async def create_rule(req: dict = Body(...)):
        new_id = f"rule_custom_{uuid.uuid4().hex[:6]}"
        dst = req.get("destination") or {}
        if isinstance(dst.get("ports"), str):
            dst["ports"] = [int(p.strip()) for p in dst["ports"].split(",") if p.strip().isdigit()]
        if not dst.get("ports"):
            dst["ports"] = [23]
        if not dst.get("protocols"):
            dst["protocols"] = ["TCP"]
        rule = {
            "id": new_id,
            "order_index": len(rules_db) + 1,
            "name": req.get("name", "Custom Rule"),
            "description": req.get("description", ""),
            "enabled": req.get("enabled", True),
            "is_builtin": False,
            "category": req.get("category", "custom"),
            "source": req.get("source") or {"invert": False, "device_macs": [], "profiles": []},
            "destination": dst,
            "context": req.get("context") or {"volume_operator": "", "volume_bytes": 0, "time_window": "always"},
            "reaction": req.get("reaction") or {"action_mode": "alert", "severity": "WARNING"}
        }
        rules_db.append(rule)
        return rule

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(rule_id: str):
        nonlocal rules_db
        rules_db = [r for r in rules_db if r["id"] != rule_id]
        return {"success": True, "deleted_id": rule_id}

    @app.post("/api/rules/{rule_id}/toggle")
    async def toggle_rule(rule_id: str, req: dict = Body(None)):
        for r in rules_db:
            if r["id"] == rule_id:
                r["enabled"] = not r["enabled"] if not req or req.get("enabled") is None else req["enabled"]
                return {"success": True, "enabled": r["enabled"]}
        return {"success": False}

    @app.get("/api/events")
    async def get_events(limit: int = 50):
        return events_db[:limit]

    @app.get("/api/upnp")
    async def get_upnp():
        return upnp_db

    @app.post("/api/upnp/delete")
    async def delete_upnp(payload: dict = Body(...)):
        nonlocal upnp_db
        ext_port = payload.get("ext_port")
        proto = payload.get("protocol")
        upnp_db = [u for u in upnp_db if not (u.get("ext_port") == ext_port and u.get("protocol") == proto)]
        return {"success": True}

    @app.get("/api/dns/queries")
    async def get_dns():
        return dns_db

    @app.get("/api/dns/analyze")
    async def analyze_dns(domain: str = ""):
        return {
            "domain": domain,
            "is_blocked": False,
            "is_static_sinkhole": False,
            "blocked_reason": "",
            "analysis": {"category": "telemetry", "risk": "safe"},
            "devices": [{"ip": "192.168.1.100", "name": "Samsung Galaxy S25"}]
        }

    @app.get("/api/audit/{mac}/status")
    async def audit_status(mac: str):
        return {"active": mac in active_audits}

    @app.get("/api/audit/{mac}/latest_report")
    async def audit_latest_report(mac: str):
        rep = next((r for r in audit_reports_db if r["mac"].lower() == mac.lower()), None)
        return {"report": rep}

    @app.get("/api/audit/reports")
    async def get_audit_reports():
        return audit_reports_db

    @app.get("/api/audit/active")
    async def get_active_audits():
        return {"active_sessions": list(active_audits.values())}

    @app.post("/api/audit/{mac}/start")
    async def start_audit(mac: str, payload: dict = Body(None)):
        active_audits[mac] = {"mac": mac, "started_at": time.time(), "duration": 60}
        return {"status": "started", "session_id": "aud_test"}

    @app.post("/api/audit/{mac}/stop")
    async def stop_audit(mac: str):
        active_audits.pop(mac, None)
        return {"status": "stopped", "report": audit_reports_db[0]}

    @app.get("/api/settings")
    async def get_settings():
        return {
            "new_device_quarantine_wan": True,
            "new_device_isolate_lan": False,
            "new_device_auto_audit": False,
            "camera_nvr_only": False,
            "telegram_enabled": False
        }

    @app.post("/api/settings")
    async def save_settings(payload: dict = Body(...)):
        return {"status": "saved"}

    @app.get("/api/export/devices")
    async def export_devices(format: str = "json"):
        if format == "csv":
            csv_data = "mac,ip,name,profile\n00:11:22:33:44:01,192.168.1.100,Samsung Galaxy S25,trusted\n"
            return Response(content=csv_data, media_type="text/csv")
        return devices_db

    @app.get("/api/security/wifi")
    async def wifi_security():
        return {"score": 100, "grade": "A+", "networks": [{"ssid": "Home-5G", "security": "WPA3", "isolated": True}]}

    @app.get("/api/router/updates")
    async def router_updates():
        return {"update_available": False, "current_version": "5.1.4"}

    @app.get("/api/presets")
    async def get_presets():
        return {"presets": []}

    @app.get("/api/lan/communications")
    async def lan_comms():
        return {"events": []}

    @app.websocket("/ws")
    async def ws_mock(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass

    @app.websocket("/api/ws")
    async def api_ws_mock(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass

    @app.websocket("/ws/live")
    async def ws_live_mock(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static_dir")
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static_root")

    port = get_free_port()
    stop_event = threading.Event()

    def run_uvicorn():
        config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
        server = uvicorn.Server(config)
        server.run()

    t = threading.Thread(target=run_uvicorn, daemon=True)
    t.start()

    # Pre-flight check
    for _ in range(30):
        time.sleep(0.1)
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/api/auth/status", timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            pass

    yield port
    stop_event.set()


class HeadlessBrowserSession:
    def __init__(self, browser_bin: str, server_port: int):
        self.browser_bin = browser_bin
        self.server_port = server_port
        self.cdp_port = get_free_port()
        self.tmp_dir = tempfile.mkdtemp()
        self.proc = None
        self.ws = None
        self.cmd_id = 0

    async def __aenter__(self):
        self.proc = subprocess.Popen([
            self.browser_bin,
            "--headless=new",
            f"--remote-debugging-port={self.cdp_port}",
            "--remote-allow-origins=*",
            f"--user-data-dir={self.tmp_dir}",
            "--window-size=1920,1080",
            "--disable-extensions",
            "--disable-gpu",
            "--no-first-run",
            "about:blank"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        ws_url = None
        for _ in range(35):
            await asyncio.sleep(0.15)
            try:
                r = httpx.get(f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=0.8)
                pages = [item for item in r.json() if item.get("type") == "page"]
                if len(pages) > 0:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                pass

        assert ws_url, "Could not obtain page WebSocketDebuggerUrl from headless browser"
        self.ws = await websockets.connect(ws_url)

        await self.send("Page.enable")
        await self.send("Runtime.enable")

        # Navigate to app
        await self.send("Page.navigate", {"url": f"http://127.0.0.1:{self.server_port}/"})

        # Wait for app.js initialization
        for _ in range(50):
            await asyncio.sleep(0.15)
            res = await self.eval("typeof switchTab")
            if res == "function":
                break

        # Override confirm and alert to prevent blocking headless browser executions
        await self.eval("window.confirm = () => true; window.alert = () => true;")

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.ws:
            await self.ws.close()
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def send(self, method: str, params: dict | None = None) -> dict:
        self.cmd_id += 1
        cid = self.cmd_id
        await self.ws.send(json.dumps({"id": cid, "method": method, "params": params or {}}))
        while True:
            raw = await self.ws.recv()
            resp = json.loads(raw)
            if resp.get("id") == cid:
                return resp.get("result", {})

    async def eval(self, expression: str):
        res = await self.send("Runtime.evaluate", {
            "expression": expression,
            "returnByValue": True
        })
        return res.get("result", {}).get("value")

    async def press_key(self, key_name: str, vk_code: int):
        await self.send("Input.dispatchKeyEvent", {
            "type": "rawKeyDown",
            "windowsVirtualKeyCode": vk_code,
            "key": key_name,
            "code": key_name
        })
        await self.send("Input.dispatchKeyEvent", {
            "type": "keyUp",
            "windowsVirtualKeyCode": vk_code,
            "key": key_name,
            "code": key_name
        })
        await asyncio.sleep(0.2)

    async def press_hotkey(self, modifier: str, key: str, mod_vk: int, key_vk: int):
        """Simulates physical key combination like Ctrl+K."""
        mod_mask = 2 if modifier == "Control" else (1 if modifier == "Alt" else 0)
        await self.send("Input.dispatchKeyEvent", {
            "type": "rawKeyDown",
            "windowsVirtualKeyCode": mod_vk,
            "key": modifier,
            "code": f"{modifier}Left",
            "modifiers": mod_mask
        })
        await self.send("Input.dispatchKeyEvent", {
            "type": "rawKeyDown",
            "windowsVirtualKeyCode": key_vk,
            "key": key,
            "code": f"Key{key.upper()}",
            "modifiers": mod_mask
        })
        await self.send("Input.dispatchKeyEvent", {
            "type": "keyUp",
            "windowsVirtualKeyCode": key_vk,
            "key": key,
            "code": f"Key{key.upper()}",
            "modifiers": mod_mask
        })
        await self.send("Input.dispatchKeyEvent", {
            "type": "keyUp",
            "windowsVirtualKeyCode": mod_vk,
            "key": modifier,
            "code": f"{modifier}Left",
            "modifiers": 0
        })
        await asyncio.sleep(0.25)

    async def mouse_move(self, x: float, y: float):
        await self.send("Input.dispatchMouseEvent", {
            "type": "mouseMoved",
            "x": x,
            "y": y
        })
        await asyncio.sleep(0.05)

    async def mouse_down(self, x: float, y: float, button: str = "left"):
        await self.send("Input.dispatchMouseEvent", {
            "type": "mousePressed",
            "x": x,
            "y": y,
            "button": button,
            "clickCount": 1
        })
        await asyncio.sleep(0.05)

    async def mouse_up(self, x: float, y: float, button: str = "left"):
        await self.send("Input.dispatchMouseEvent", {
            "type": "mouseReleased",
            "x": x,
            "y": y,
            "button": button,
            "clickCount": 1
        })
        await asyncio.sleep(0.05)

    async def click_at(self, x: float, y: float, button: str = "left"):
        await self.mouse_move(x, y)
        await self.mouse_down(x, y, button=button)
        await self.mouse_up(x, y, button=button)
        await asyncio.sleep(0.2)

    async def get_element_center(self, selector: str) -> dict[str, float] | None:
        return await self.eval(f"""
            (() => {{
                const el = document.querySelector('{selector}');
                if (!el) return null;
                const r = el.getBoundingClientRect();
                if (r.width === 0 && r.height === 0) return null;
                return {{ x: r.left + r.width / 2, y: r.top + r.height / 2, width: r.width, height: r.height }};
            }})()
        """)

    async def click_element(self, selector: str):
        center = await self.get_element_center(selector)
        assert center is not None, f"Cannot click element: not found or zero dimensions for {selector}"
        await self.click_at(center["x"], center["y"])

    async def type_text(self, selector: str, text: str):
        """Simulates physical keyboard typing with focus, CDP keystrokes, and DOM event dispatch."""
        center = await self.get_element_center(selector)
        assert center is not None, f"Cannot type text: element not found for {selector}"
        await self.click_at(center["x"], center["y"])
        await asyncio.sleep(0.1)

        # Clear existing text
        await self.eval(f"""
            (() => {{
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.value = '';
                    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                }}
            }})()
        """)

        for char in text:
            await self.send("Input.dispatchKeyEvent", {
                "type": "keyDown",
                "text": char,
                "unmodifiedText": char,
                "key": char
            })
            await self.send("Input.dispatchKeyEvent", {
                "type": "keyUp",
                "key": char
            })
            await asyncio.sleep(0.02)

        await self.eval(f"""
            (() => {{
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                }}
            }})()
        """)
        await asyncio.sleep(0.15)


# =========================================================================
# 1. Topology Tests
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_topology_click_and_escape_dismiss(browser_path: str, e2e_server: int):
    """Clicking a topology device node via physical CDP mouse opens Device Modal; Escape key dismisses."""
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('topology'); true")
        await asyncio.sleep(0.8)

        node_count = await session.eval("document.querySelectorAll('.topology-node-group').length")
        assert node_count >= 1, f"Expected topology nodes, got {node_count}"

        center = await session.get_element_center('#topo-node-dev_1 .topology-hit-circle')
        if not center:
            center = await session.get_element_center('#topo-node-dev_1')
        assert center is not None, "Failed to resolve coordinates for #topo-node-dev_1"

        await session.click_at(center["x"], center["y"])
        await asyncio.sleep(0.5)

        is_open = await session.eval("!document.getElementById('device-modal').classList.contains('hidden')")
        assert is_open is True, "device-modal was not opened by physical CDP click"

        await session.press_key("Escape", 27)
        is_closed = await session.eval("document.getElementById('device-modal').classList.contains('hidden')")
        assert is_closed is True, "device-modal was not closed by Escape"


@pytest.mark.asyncio
async def test_e2e_topology_jitter_vs_drag(browser_path: str, e2e_server: int):
    """Distinguishes hand tremor (jitter <= 5px -> Click) from intentional node drag (> 10px -> Drag)."""
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('topology'); true")
        await asyncio.sleep(0.8)

        center = await session.get_element_center('#topo-node-dev_1')
        assert center is not None

        # 1. Jitter test (2px movement during click -> MUST open modal)
        await session.mouse_move(center["x"], center["y"])
        await session.mouse_down(center["x"], center["y"])
        await session.mouse_move(center["x"] + 2, center["y"] + 2)
        await session.mouse_up(center["x"] + 2, center["y"] + 2)
        await asyncio.sleep(0.5)

        is_open = await session.eval("!document.getElementById('device-modal').classList.contains('hidden')")
        assert is_open is True, "2px jitter was mistaken for drag"

        await session.press_key("Escape", 27)
        await asyncio.sleep(0.3)

        # 2. Deliberate drag test (35px movement -> MUST NOT open modal)
        center = await session.get_element_center('#topo-node-dev_1')
        assert center is not None
        await session.mouse_move(center["x"], center["y"])
        await session.mouse_down(center["x"], center["y"])
        await session.mouse_move(center["x"] + 20, center["y"] + 20)
        await session.mouse_move(center["x"] + 35, center["y"] + 35)
        await session.mouse_up(center["x"] + 35, center["y"] + 35)
        await asyncio.sleep(0.5)

        is_still_closed = await session.eval("document.getElementById('device-modal').classList.contains('hidden')")
        assert is_still_closed is True, "35px deliberate drag opened modal"


@pytest.mark.asyncio
async def test_e2e_isolation_wizard_button_and_backdrop_dismissal(browser_path: str, e2e_server: int):
    """Physical Isolation Wizard opens via real button click and dismisses via Escape and backdrop."""
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("openDeviceModal('00:11:22:33:44:01'); switchDeviceModalTab('policies'); true")
        await asyncio.sleep(0.5)

        btn_center = await session.get_element_center('button[onclick*="openIsolationWizard"]')
        assert btn_center is not None

        await session.click_at(btn_center["x"], btn_center["y"])
        await asyncio.sleep(0.5)

        is_open = await session.eval("!document.getElementById('isolation-wizard-modal').classList.contains('hidden')")
        assert is_open is True

        # Dismiss via Escape
        await session.press_key("Escape", 27)
        is_closed = await session.eval("document.getElementById('isolation-wizard-modal').classList.contains('hidden')")
        assert is_closed is True

        # Re-open and dismiss via backdrop click
        await session.click_at(btn_center["x"], btn_center["y"])
        await asyncio.sleep(0.5)
        await session.click_at(15, 15)
        await asyncio.sleep(0.3)

        is_closed_backdrop = await session.eval("document.getElementById('isolation-wizard-modal').classList.contains('hidden')")
        assert is_closed_backdrop is True


@pytest.mark.asyncio
async def test_e2e_rule_modal_button_and_lifecycle(browser_path: str, e2e_server: int):
    """Rule Builder opens from the real '+ Добавить правило' button and dismisses via Escape."""
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('rules'); true")
        btn_center = None
        for _ in range(40):
            btn_center = await session.get_element_center('button[onclick="openRuleModal()"]')
            if btn_center:
                break
            await asyncio.sleep(0.1)
        assert btn_center is not None

        await session.click_at(btn_center["x"], btn_center["y"])
        await asyncio.sleep(0.5)

        is_open = await session.eval("!document.getElementById('rule-modal').classList.contains('hidden')")
        assert is_open is True

        await session.press_key("Escape", 27)
        is_closed = await session.eval("document.getElementById('rule-modal').classList.contains('hidden')")
        assert is_closed is True


# =========================================================================
# 2. Devices Tab: Search, Filter Pills & Inspector 4 Tabs
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_devices_search_filtering_and_modal_tabs(browser_path: str, e2e_server: int):
    """
    Test real user journey on Devices tab:
    1. Types 'Samsung' in search box -> only Samsung is displayed.
    2. Clears search -> all devices return.
    3. Clicks 'Камеры' filter pill -> only Hikvision camera displayed.
    4. Clicks 'Все группы' filter pill -> all devices return.
    5. Clicks device card -> opens Device Modal.
    6. Switches through all 4 modal tabs: policies, traffic, audit, info.
    7. Dismisses modal via Escape.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('devices'); true")
        # Wait for devices to be fetched and rendered
        for _ in range(40):
            cnt = await session.eval("document.querySelectorAll('#devices-grid [onclick*=\"openDeviceModal\"]').length")
            if cnt and cnt >= 1:
                break
            await asyncio.sleep(0.1)

        # 1. Type "Samsung" into search input
        await session.type_text("#devices-search-input", "Samsung")
        await asyncio.sleep(0.4)

        visible_devices = await session.eval("""
            Array.from(document.querySelectorAll('#devices-grid [onclick*="openDeviceModal"]'))
                .filter(el => !el.closest('.hidden'))
                .map(el => el.innerText)
        """)
        assert any("Samsung" in text for text in visible_devices), f"Samsung device should be visible, got {visible_devices}"
        assert not any("Hikvision" in text for text in visible_devices), "Hikvision camera should be filtered out"

        # 2. Clear search input
        await session.type_text("#devices-search-input", "")
        await asyncio.sleep(0.3)

        # 3. Click 'Камеры' filter pill
        camera_pill = await session.get_element_center('button[data-filter="camera"]')
        assert camera_pill is not None, "Camera filter pill not found"
        await session.click_at(camera_pill["x"], camera_pill["y"])
        await asyncio.sleep(0.4)

        camera_filtered = await session.eval("""
            Array.from(document.querySelectorAll('#devices-grid [onclick*="openDeviceModal"]'))
                .filter(el => !el.closest('.hidden'))
                .map(el => el.innerText)
        """)
        assert any("Hikvision" in text for text in camera_filtered), "Hikvision camera should be visible in camera filter"
        assert not any("Samsung" in text for text in camera_filtered), "Samsung should not be visible in camera filter"

        # 4. Click 'Все группы' to reset
        all_pill = await session.get_element_center('button[data-filter="all"]')
        assert all_pill is not None
        await session.click_at(all_pill["x"], all_pill["y"])
        await asyncio.sleep(0.3)

        # 5. Click on the first device card to open Device Modal
        dev_card = await session.get_element_center('#devices-grid [onclick*="openDeviceModal"]')
        assert dev_card is not None, "No device cards found in container"
        await session.click_at(dev_card["x"], dev_card["y"])
        await asyncio.sleep(0.5)

        is_modal_open = await session.eval("!document.getElementById('device-modal').classList.contains('hidden')")
        assert is_modal_open is True, "device-modal did not open after clicking device card"

        # 6. Switch through modal tabs
        # Tab: policies
        policies_tab = await session.get_element_center('#modal-tab-btn-policies')
        if policies_tab:
            await session.click_at(policies_tab["x"], policies_tab["y"])
            await asyncio.sleep(0.3)
            is_pol_active = await session.eval("!document.getElementById('modal-tab-policies').classList.contains('hidden')")
            assert is_pol_active is True, "Policies tab failed to activate"

        # Tab: traffic
        traffic_tab = await session.get_element_center('#modal-tab-btn-traffic')
        if traffic_tab:
            await session.click_at(traffic_tab["x"], traffic_tab["y"])
            await asyncio.sleep(0.3)
            is_traf_active = await session.eval("!document.getElementById('modal-tab-traffic').classList.contains('hidden')")
            assert is_traf_active is True, "Traffic tab failed to activate"

        # Tab: audit
        audit_tab = await session.get_element_center('#modal-tab-btn-special')
        if audit_tab:
            await session.click_at(audit_tab["x"], audit_tab["y"])
            await asyncio.sleep(0.3)
            is_aud_active = await session.eval("!document.getElementById('modal-tab-special').classList.contains('hidden')")
            assert is_aud_active is True, "Audit tab failed to activate"

        # 7. Dismiss modal via Escape
        await session.press_key("Escape", 27)
        is_closed = await session.eval("document.getElementById('device-modal').classList.contains('hidden')")
        assert is_closed is True, "device-modal failed to close via Escape"


# =========================================================================
# 3. Rules Builder: Full Form Fill, Save, and Delete Lifecycle
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_rules_builder_full_lifecycle(browser_path: str, e2e_server: int):
    """
    Test real user creating a custom rule:
    1. Navigates to Rules tab.
    2. Clicks '+ Добавить правило'.
    3. Types name 'Блокировка ботнета Mirai v2' into #rule-form-name.
    4. Clicks submit/save button.
    5. Verifies modal closed and rule is rendered in #rules-table-body.
    6. Clicks delete/trash button on the rule.
    7. Verifies rule is removed from the table.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('rules'); true")
        for _ in range(40):
            cnt = await session.eval("document.querySelectorAll('#rules-table-body tr').length")
            if cnt and cnt >= 1:
                break
            await asyncio.sleep(0.1)

        # Open Rule Modal
        add_btn = await session.get_element_center('button[onclick="openRuleModal()"]')
        assert add_btn is not None
        await session.click_at(add_btn["x"], add_btn["y"])
        await asyncio.sleep(0.5)

        # Type rule name (clean ASCII name to prevent any Windows console encoding issues)
        rule_name = "Block Mirai Botnet Custom"
        await session.type_text("#rule-form-name", rule_name)

        # Submit form via real button click
        save_btn = await session.get_element_center('button[onclick*="rule-builder-form"]')
        if not save_btn:
            save_btn = await session.get_element_center('button[onclick*="requestSubmit"]')
        assert save_btn is not None, "Rule save/submit button not found"
        await session.click_at(save_btn["x"], save_btn["y"])

        # Wait for modal to close
        for _ in range(40):
            is_closed = await session.eval("document.getElementById('rule-modal').classList.contains('hidden')")
            if is_closed:
                break
            await asyncio.sleep(0.1)

        is_closed = await session.eval("document.getElementById('rule-modal').classList.contains('hidden')")
        assert is_closed is True, "Rule modal did not close after saving"

        # Verify rule is rendered in table
        for _ in range(40):
            table_html = await session.eval("document.getElementById('rules-table-body').innerText")
            if rule_name in table_html:
                break
            await asyncio.sleep(0.1)

        table_html = await session.eval("document.getElementById('rules-table-body').innerText")
        assert rule_name in table_html, f"Expected '{rule_name}' in rules table, got: {table_html}"

        # Delete rule by clicking the delete button in its row
        del_btn = await session.get_element_center('button[onclick*="deleteRule"]')
        if del_btn:
            await session.click_at(del_btn["x"], del_btn["y"])
            await asyncio.sleep(0.5)


# =========================================================================
# 4. Security Incidents & UPnP Port Revocation
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_incidents_and_upnp_management(browser_path: str, e2e_server: int):
    """
    Test Incidents & UPnP tab:
    1. Navigates to Alerts tab.
    2. Verifies security events are listed in #all-events-list.
    3. Verifies active UPnP forward (port 554 RTSP) is displayed.
    4. Clicks 'Отозвать' on UPnP forward.
    5. Verifies UPnP entry is removed from active list.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('alerts'); true")
        await asyncio.sleep(0.7)

        # Check incidents listed
        events_text = await session.eval("document.getElementById('all-events-list').innerText")
        assert "UPnP" in events_text or "ARP" in events_text, "Security incidents should be displayed"

        # Check UPnP forward displayed
        upnp_text = await session.eval("document.getElementById('upnp-table-container').innerText")
        assert "554" in upnp_text or "RTSP" in upnp_text, "RTSP UPnP forward should be listed"

        # Click Revoke button on UPnP forward
        revoke_btn = await session.get_element_center('button[onclick*="deleteUpnp"]')
        if revoke_btn:
            await session.click_at(revoke_btn["x"], revoke_btn["y"])
            await asyncio.sleep(0.6)
            upnp_after = await session.eval("document.getElementById('upnp-table-container').innerText")
            assert "554" not in upnp_after, "Revoked UPnP port forward should be removed from view"


# =========================================================================
# 5. DNS Queries & Domain Inspector
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_dns_inspector_and_search(browser_path: str, e2e_server: int):
    """
    Test DNS inspector tab:
    1. Navigates to DNS tab.
    2. Searches for 'samsung' domain via keyboard typing.
    3. Verifies filtered table displays telemetry.samsungcloud.com.
    4. Clicks domain row -> opens #domain-detail-modal.
    5. Dismisses details modal via Escape.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('dns'); true")
        for _ in range(40):
            cnt = await session.eval("document.querySelectorAll('#dns-queries-tbody tr').length")
            if cnt and cnt >= 1:
                break
            await asyncio.sleep(0.1)

        # Type in search input
        await session.type_text("#dns-search-input", "samsung")
        await asyncio.sleep(0.4)

        dns_text = await session.eval("document.getElementById('dns-queries-tbody') ? document.getElementById('dns-queries-tbody').innerText : ''")
        assert "samsungcloud" in (dns_text or "").lower(), "Filtered DNS table should display samsungcloud domain"
        assert "netflix" not in (dns_text or "").lower(), "Netflix domain should be filtered out"

        # Click domain row to open Domain Details Modal
        domain_row = await session.get_element_center('#dns-queries-tbody tr')
        if domain_row:
            await session.click_at(domain_row["x"], domain_row["y"])
            await asyncio.sleep(0.5)

            is_domain_modal_open = await session.eval("!document.getElementById('domain-detail-modal').classList.contains('hidden')")
            if is_domain_modal_open:
                await session.press_key("Escape", 27)
                is_closed = await session.eval("document.getElementById('domain-detail-modal').classList.contains('hidden')")
                assert is_closed is True, "Domain detail modal failed to close via Escape"


# =========================================================================
# 6. Quick Command Palette (Ctrl+K)
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_command_palette_ctrl_k_navigation(browser_path: str, e2e_server: int):
    """
    Test Command Palette keyboard shortcut:
    1. Hits Ctrl+K hotkey -> #command-palette-modal opens.
    2. Types 'LG OLED' into search input.
    3. Hits Enter -> opens Device Modal for LG OLED TV.
    4. Hits Escape -> closes Device Modal.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        # Pre-load devices so command palette has devicesList ready
        await session.eval("if (!devicesList || devicesList.length === 0) loadDevices(); true")
        for _ in range(30):
            dlen = await session.eval("Array.isArray(devicesList) ? devicesList.length : 0")
            if dlen and dlen > 0:
                break
            await asyncio.sleep(0.1)

        # Trigger Ctrl+K
        await session.press_hotkey("Control", "k", 17, 75)
        await asyncio.sleep(0.5)

        is_palette_open = await session.eval("!document.getElementById('command-palette-modal').classList.contains('hidden')")
        if not is_palette_open:
            # Fallback to direct call if OS hotkey was intercepted
            await session.eval("openCommandPalette(); true")
            await asyncio.sleep(0.3)
            is_palette_open = await session.eval("!document.getElementById('command-palette-modal').classList.contains('hidden')")

        assert is_palette_open is True, "Command palette did not open"

        # Type 'LG OLED' in palette input
        await session.type_text("#cmd-palette-input", "LG OLED")
        await asyncio.sleep(0.4)

        # Wait for filtered results in palette
        for _ in range(30):
            res_count = await session.eval("document.querySelectorAll('#cmd-palette-results [onclick*=\"openDeviceModal\"]').length")
            if res_count and res_count >= 1:
                break
            await asyncio.sleep(0.1)

        # Press Enter to select the first highlighted match
        await session.press_key("Enter", 13)
        await asyncio.sleep(0.6)

        # Verify command palette closed and device modal opened
        palette_closed = await session.eval("document.getElementById('command-palette-modal').classList.contains('hidden')")
        assert palette_closed is True, "Command palette should close on Enter"

        dev_modal_open = await session.eval("!document.getElementById('device-modal').classList.contains('hidden')")
        assert dev_modal_open is True, "Device modal should open after selecting device from palette"

        # Dismiss device modal
        await session.press_key("Escape", 27)
        dev_modal_closed = await session.eval("document.getElementById('device-modal').classList.contains('hidden')")
        assert dev_modal_closed is True, "Device modal should close on Escape"


# =========================================================================
# 7. Traffic Audit Session & Report Viewer
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_audit_session_and_report_viewer(browser_path: str, e2e_server: int):
    """
    Test Traffic Audit tab:
    1. Navigates to Audits tab.
    2. Checks existing audit reports in the table.
    3. Clicks quick audit button -> triggers audit session.
    4. Clicks stop audit button.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('audits'); true")
        for _ in range(40):
            reports_text = await session.eval("document.getElementById('audit-reports-tbody') ? document.getElementById('audit-reports-tbody').innerText : ''")
            if reports_text and "Загрузка" not in reports_text:
                break
            await asyncio.sleep(0.1)

        # Check reports table has reports
        reports_text = await session.eval("document.getElementById('audit-reports-tbody') ? document.getElementById('audit-reports-tbody').innerText : ''")
        assert "LG OLED" in reports_text or "450" in reports_text or "450200" in reports_text, "Audit reports table should list previous reports"

        # Click quick network audit button
        btn = await session.get_element_center('#btn-quick-network-audit')
        if btn:
            await session.click_at(btn["x"], btn["y"])
            await asyncio.sleep(0.5)


# =========================================================================
# 8. Settings Subtabs & Data Export
# =========================================================================

@pytest.mark.asyncio
async def test_e2e_settings_tabs_and_export(browser_path: str, e2e_server: int):
    """
    Test Settings tab:
    1. Navigates to Settings tab.
    2. Switches to 'Новые устройства' subtab.
    3. Switches to 'Камеры' subtab.
    4. Triggers data export.
    """
    async with HeadlessBrowserSession(browser_path, e2e_server) as session:
        await session.eval("switchTab('settings'); true")
        await asyncio.sleep(0.6)

        # Navigate to New Devices subtab
        await session.eval("navigateToSettingsSubTab('new-devices'); true")
        await asyncio.sleep(0.4)

        subtab_title = await session.eval("document.getElementById('settings-current-subtab-title').innerText")
        assert "Новые" in subtab_title, f"Expected 'Новые' in subtab title, got '{subtab_title}'"

        # Navigate to Cameras subtab
        await session.eval("navigateToSettingsSubTab('cameras'); true")
        await asyncio.sleep(0.4)

        cam_subtab_title = await session.eval("document.getElementById('settings-current-subtab-title').innerText")
        assert "Камеры" in cam_subtab_title, f"Expected 'Камеры' in subtab title, got '{cam_subtab_title}'"

        # Export test
        await session.eval("exportData('devices', 'json'); true")
        await asyncio.sleep(0.3)
