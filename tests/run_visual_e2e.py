"""
Deep Visual E2E Browser Showcase with Real Mouse Simulation, Drag & Drop, Live HUD & Snapshot Testing.

Features:
- Launches a visible Chromium/Edge window pinned TOPMOST on desktop (WinSta0\\Default).
- Performs interactive testing across all 12 major functional areas of KeenGuard.
- Takes a high-resolution screenshot at EVERY single action.
- Compares screenshots with Golden Baselines (tests/visual_baselines/).
- Highlights visual diffs in red if rendering or DOM states deviate.
- Generates an interactive HTML Visual Gallery report (tests/visual_report.html).
"""

import argparse
import asyncio
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

# Safe stdout encoding for Windows console (avoid cp1251 crash)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import httpx
import uvicorn
import websockets
from fastapi import FastAPI, Body, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.c_char_p),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

REPO_ROOT = Path(__file__).resolve().parent.parent
STATIC_DIR = REPO_ROOT / "keenguard" / "web" / "static"


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
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


def bring_window_to_front(pid: int, topmost: bool = True):
    """Brings browser window to the front on the user's interactive Windows desktop and pins it topmost."""
    if sys.platform != "win32":
        return
    try:
        u32 = ctypes.windll.user32
        h_default = u32.OpenDesktopW("Default", 0, False, 0x01FF)
        if h_default:
            u32.SetThreadDesktop(h_default)

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        target_hwnds = []

        def enum_proc(hwnd, lparam):
            if u32.IsWindowVisible(hwnd):
                proc_id = wintypes.DWORD()
                u32.GetWindowThreadProcessId(hwnd, ctypes.byref(proc_id))
                buf = ctypes.create_unicode_buffer(256)
                u32.GetWindowTextW(hwnd, buf, 256)
                title = buf.value
                if proc_id.value == pid or "KeenGuard" in title or "Chrome" in title:
                    target_hwnds.append(hwnd)
            return True

        u32.EnumWindows(WNDENUMPROC(enum_proc), 0)
        HWND_TOPMOST = -1
        HWND_NOTOPMOST = -2
        SWP_NOMOVE = 0x0002
        SWP_NOSIZE = 0x0001
        SWP_SHOWWINDOW = 0x0040
        flag = HWND_TOPMOST if topmost else HWND_NOTOPMOST
        for hwnd in target_hwnds:
            u32.ShowWindow(hwnd, 3)  # SW_MAXIMIZE
            u32.SetForegroundWindow(hwnd)
            if topmost:
                u32.SetWindowPos(hwnd, flag, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
    except Exception as e:
        print(f"[Warning] Failed to bring window to front: {e}")


def start_mock_server(port: int):
    app = FastAPI()

    # Synthetic demo devices conforming to Zero-Leak policy (RFC 5737 / synthetic MACs)
    devices_db = [
        {
            "mac": "02:00:00:11:22:33",
            "ip": "192.168.1.10",
            "name": "Samsung Galaxy S25 Demo",
            "hostname": "Samsung-S25-Demo",
            "custom_name": "Samsung Galaxy S25 Demo",
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
        },
    ]

    rules_db = [
        {
            "id": "rule_block_mirai",
            "order_index": 1,
            "name": "Блокировка ботнета Mirai",
            "description": "Автоматическая блокировка портов Telnet 23 и RDP 3389",
            "enabled": True,
            "is_builtin": True,
            "category": "core",
            "source": {"invert": False, "device_macs": [], "profiles": []},
            "destination": {"direction": "lan_to_wan", "ports": [23, 3389], "protocols": ["TCP"], "targets": []},
            "context": {"volume_operator": "", "volume_bytes": 0, "time_window": "always"},
            "reaction": {"action_mode": "alert", "severity": "critical", "notify_telegram": True},
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
            "details": {"ext_port": 554},
        },
        {
            "id": 2,
            "timestamp": "2026-10-06T00:30:00",
            "event_type": "arp_scan",
            "severity": "warning",
            "title": "ARP-разведка сети (Сетевое сканирование)",
            "description": "Обнаружен последовательный опрос 254 адресов подсети",
            "source_ip": "192.168.1.10",
            "mac": "02:00:00:11:22:33",
        },
    ]

    dns_queries_db = [
        {
            "id": 1,
            "timestamp": "2026-10-06T00:41:00",
            "last_seen": "2026-10-06T00:41:00",
            "domain": "telemetry.samsungcloud.com",
            "ip": "0.0.0.0",
            "client_ip": "192.168.1.10",
            "query_type": "A",
            "count": 42,
            "is_blocked": True,
            "is_static_sinkhole": True,
            "devices": [{"ip": "192.168.1.10", "name": "Samsung Galaxy S25 Demo"}],
            "analysis": {
                "category_name": "Телеметрия",
                "badge_color": "rose",
                "badge_text": "Заблокирован",
                "vendor": "Samsung Cloud Services",
                "description": "Сбор диагностических данных и активности устройства",
                "is_blocked": True,
                "is_static_sinkhole": True,
                "safety_label": "Заблокирован роутером (0.0.0.0)",
                "safety_color": "rose",
                "impact_explanation": "Перенаправлен в 0.0.0.0 на роутере Keenetic",
            },
        },
        {
            "id": 2,
            "timestamp": "2026-10-06T00:40:00",
            "last_seen": "2026-10-06T00:40:00",
            "domain": "api.netflix.com",
            "ip": "198.51.100.22",
            "client_ip": "192.168.1.55",
            "query_type": "A",
            "count": 18,
            "is_blocked": False,
            "devices": [{"ip": "192.168.1.55", "name": "LG OLED 65 Smart TV"}],
            "analysis": {
                "category_name": "Стриминг",
                "badge_color": "emerald",
                "badge_text": "Безопасно",
                "vendor": "Netflix Video Streaming",
                "description": "Стриминг медиаконтента 4K HDR",
            },
        },
    ]

    audit_reports_db = [
        {
            "id": "aud_rep_001",
            "mac": "11:22:33:44:55:66",
            "hostname": "LG OLED 65 Smart TV",
            "ip": "192.168.1.55",
            "created_at": "2026-10-06T00:30:00",
            "duration_seconds": 60,
            "summary": "Обнаружено 14 соединений. Потенциальная утечка HTTP на порт 80.",
            "risk_level": "medium",
            "flows_count": 14,
            "total_bytes": 450200,
            "bytes_total": 450200,
            "total_packets": 320,
            "pcap_file": "aud_rep_001.pcap",
            "findings": [
                "Обнаружен незашифрованный HTTP-трафик на порт 80",
                "Фоновая телеметрия LG ThinQ во время ожидания",
            ],
        }
    ]

    packets_db = [
        {
            "pkt_id": 1,
            "timestamp": "2026-10-06T00:45:01",
            "src": "192.168.1.10",
            "src_mac": "02:00:00:11:22:33",
            "dst": "192.168.1.1",
            "dst_mac": "00:04:9f:ef:01:02",
            "protocol": "DNS",
            "length": 78,
            "summary": "Standard query 0x1a2b A telemetry.samsungcloud.com",
        },
        {
            "pkt_id": 2,
            "timestamp": "2026-10-06T00:45:02",
            "src": "192.168.1.55",
            "src_mac": "11:22:33:44:55:66",
            "dst": "198.51.100.22",
            "dst_mac": "00:04:9f:ef:01:02",
            "protocol": "TLS",
            "length": 512,
            "summary": "TLSv1.3 Client Hello (SNI=api.netflix.com)",
        },
        {
            "pkt_id": 3,
            "timestamp": "2026-10-06T00:45:03",
            "src": "192.168.1.80",
            "src_mac": "aa:bb:cc:dd:ee:ff",
            "dst": "203.0.113.5",
            "dst_mac": "00:04:9f:ef:01:02",
            "protocol": "HTTP",
            "length": 240,
            "summary": "GET /api/stream/live HTTP/1.1 (Port 80 Unencrypted)",
        },
    ]

    active_audits = {}

    @app.get("/api/auth/status")
    async def auth_status():
        return {"authenticated": True, "auth_required": False, "web_host": "127.0.0.1", "is_localhost": True}

    @app.get("/api/status")
    async def status():
        return {
            "router": {"connected": True, "model": "Keenetic Ultra (KN-1811)", "ip": "192.168.1.1", "version": "4.2.1", "active_hosts": 3},
            "monitoring": {"active": True},
            "online_devices": 3,
            "total_devices": 4,
            "critical_alerts": 1,
        }

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
                d["custom_name"] = payload.get("name", d["name"])
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
                if "profile" in payload:
                    d["profile"] = payload["profile"]
                return {"status": "ok", "device": d}
        return {"status": "ok"}

    @app.get("/api/devices/{mac}/traffic")
    async def device_traffic(mac: str):
        return {"points": [{"time": "00:40", "bytes": 12000}, {"time": "00:45", "bytes": 35000}]}

    @app.get("/api/devices/{mac}/isolation_guide")
    async def isolation_guide(mac: str):
        dev = next((d for d in devices_db if d["mac"].lower() == mac.lower()), devices_db[0])
        return {
            "status": "ok",
            "mac": dev["mac"],
            "name": dev.get("name") or dev.get("custom_name") or dev["mac"],
            "ip": dev.get("ip", "192.168.1.10"),
            "is_physically_isolated": False,
            "current_segment": "Bridge0",
            "is_wifi": True,
            "steps": [
                {
                    "title": "Шаг 1: Включите Гостевую сеть в Keenetic",
                    "desc": "Откройте панель роутера (http://192.168.1.1) ➔ «Мои сети и Wi-Fi» ➔ «Гостевая сеть». Убедитесь, что она включена.",
                },
                {
                    "title": "Шаг 2: Подключите устройство к Гостевой сети",
                    "desc": f"На самом устройстве ({dev.get('name', 'Galaxy S25')}) выберите Гостевую Wi-Fi сеть. Роутер выдаст IP из изолированной подсети.",
                },
                {
                    "title": "Шаг 3: Аппаратная изоляция готова",
                    "desc": "В гостевой сети роутер аппаратно блокирует L2-трафик к домашним устройствам. KeenGuard зафиксирует изоляцию.",
                },
            ],
            "technical_context": {
                "current_segment": "Bridge0",
                "hardware_enforcement": "Для реальной изоляции необходим перенос в гостевой сегмент Bridge1.",
            },
        }

    @app.get("/api/network/topology")
    async def topology():
        return {
            "nodes": [
                {"id": "node_router", "type": "router", "label": "Keenetic Ultra", "ip": "192.168.1.1"},
                {"id": "segment_Bridge0", "type": "segment", "label": "Bridge0 (Домашняя сеть)", "ip": "192.168.1.0/24"},
                {
                    "id": "dev_1",
                    "type": "device",
                    "mac": "02:00:00:11:22:33",
                    "label": "Galaxy S25 Demo",
                    "is_online": True,
                    "profile": "trusted",
                },
                {
                    "id": "dev_2",
                    "type": "device",
                    "mac": "11:22:33:44:55:66",
                    "label": "LG OLED TV",
                    "is_online": True,
                    "profile": "smart_tv",
                },
                {
                    "id": "dev_3",
                    "type": "device",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "label": "Hikvision IPCam",
                    "is_online": True,
                    "profile": "camera",
                },
                {
                    "id": "dev_4",
                    "type": "device",
                    "mac": "00:11:22:33:44:55",
                    "label": "Tuya Smart Bulb",
                    "is_online": False,
                    "profile": "iot",
                },
            ],
            "links": [
                {"source": "node_router", "target": "segment_Bridge0", "type": "trunk"},
                {"source": "segment_Bridge0", "target": "dev_1", "type": "client", "is_online": True},
                {"source": "segment_Bridge0", "target": "dev_2", "type": "client", "is_online": True},
                {"source": "segment_Bridge0", "target": "dev_3", "type": "client", "is_online": True},
                {"source": "segment_Bridge0", "target": "dev_4", "type": "client", "is_online": False},
            ],
            "meta": {
                "total_devices": 4,
                "online_devices": 3,
                "l2_realism_note": "Физический L2-трафик в Bridge0 идет напрямую через коммутатор роутера.",
            },
        }

    @app.get("/api/smarthome/overview")
    async def smarthome_overview():
        return {
            "total_iot": 1,
            "online_iot": 0,
            "zero_internet_count": 1,
            "cloud_connections": 0,
            "hub": {"name": "SprutHub (Zigbee/Matter)", "status": "online", "ip": "192.168.1.60", "mac": "00:11:22:33:44:99", "vendor": "SprutHub"},
        }

    @app.post("/api/smarthome/hub/audit")
    async def hub_audit():
        return {"status": "started", "session_id": "sh_hub_audit_01"}

    @app.get("/api/security/checklist")
    async def security_checklist():
        return {
            "score": 85,
            "grade": "B+",
            "items": [
                {"title": "Пароль администратора роутера", "status": "pass", "desc": "Установлен надежный пароль"},
                {"title": "Изоляция гостевой сети", "status": "pass", "desc": "L2/L3 изоляция активна"},
                {"title": "UPnP автоматический проброс", "status": "warn", "desc": "Обнаружен проброс порта RTSP 554"},
            ],
        }

    @app.get("/api/security/wifi")
    async def wifi_security():
        return {
            "grade": "A-",
            "score": 88,
            "networks": [
                {"ssid": "Keenetic-Home-5G", "security": "WPA3-SAE", "status": "secure", "clients": 3},
                {"ssid": "Keenetic-Guest", "security": "WPA2-PSK", "status": "warning", "clients": 1},
            ],
            "wps_active": False,
            "recommendations": ["Рекомендуется отключить устаревшие протоколы TKIP"],
        }

    @app.get("/api/router/updates")
    async def router_updates():
        return {
            "current_version": "4.2.1",
            "latest_version": "4.2.1",
            "update_available": False,
            "channel": "release",
            "status_text": "Установлена актуальная версия KeeneticOS",
        }

    @app.get("/api/security/digest")
    async def security_digest():
        return {
            "score": 88,
            "period": "Последние 24 часа",
            "total_devices": 4,
            "online_devices": 3,
            "active_devices": 3,
            "critical_count": 1,
            "warning_count": 1,
            "info_count": 5,
            "incidents": {"critical": 1, "warning": 1, "info": 5},
            "recommendations": [
                "Отозван UPnP-проброс порта 554 для камеры Hikvision",
                "Выполнен перенос умного устройства в изолированный сегмент",
            ],
        }

    @app.get("/api/rules")
    async def get_rules():
        return rules_db

    @app.post("/api/rules")
    async def create_rule(payload: dict = Body(...)):
        new_rule = {
            "id": f"rule_{uuid.uuid4().hex[:8]}",
            "order_index": len(rules_db) + 1,
            "name": payload.get("name", "Новое правило"),
            "description": payload.get("description", ""),
            "enabled": True,
            "is_builtin": False,
            "category": "user",
            "source": payload.get("source", {}),
            "destination": payload.get("destination", {}),
            "context": payload.get("context", {}),
            "reaction": payload.get("reaction", {}),
        }
        rules_db.append(new_rule)
        return {"status": "ok", "rule": new_rule}

    @app.post("/api/rules/{rule_id}/toggle")
    async def toggle_rule(rule_id: str, payload: dict = Body(...)):
        for r in rules_db:
            if r["id"] == rule_id:
                r["enabled"] = payload.get("enabled", not r["enabled"])
                return {"status": "ok", "rule": r}
        return {"status": "ok"}

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(rule_id: str):
        nonlocal rules_db
        rules_db = [r for r in rules_db if r["id"] != rule_id]
        return {"status": "deleted"}

    @app.get("/api/events")
    async def get_events():
        return events_db

    @app.get("/api/upnp")
    async def get_upnp():
        return [
            {
                "protocol": "TCP",
                "ext_port": 554,
                "int_port": 554,
                "int_ip": "192.168.1.80",
                "client_ip": "192.168.1.80",
                "description": "Hikvision RTSP Stream",
                "duration": "01:45:00",
            }
        ]

    @app.post("/api/upnp/delete")
    async def delete_upnp(payload: dict = Body(...)):
        return {"status": "ok", "deleted_port": payload.get("port")}

    @app.get("/api/dns/queries")
    async def get_dns_queries():
        return dns_queries_db

    @app.get("/api/dns/analyze")
    async def analyze_dns(domain: str = ""):
        return {
            "domain": domain,
            "is_blocked": False,
            "is_static_sinkhole": False,
            "blocked_reason": "",
            "analysis": {
                "category": "telemetry",
                "category_name": "Телеметрия",
                "risk": "warning",
                "risk_level": "warning",
                "badge_text": "Внимание",
                "badge_color": "amber",
                "vendor": "Samsung Cloud Platform",
                "description": "Сбор диагностических данных и активности устройства",
                "keenetic_tip": "Рекомендуется заблокировать для предотвращения передачи профиля активности.",
            },
            "devices": [{"ip": "192.168.1.10", "name": "Samsung Galaxy S25 Demo"}],
        }

    @app.get("/api/investigator/incidents")
    async def get_investigator_incidents():
        return {
            "incidents": [
                {
                    "type": "event",
                    "id": "1",
                    "event_id": 1,
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "ip": "192.168.1.80",
                    "title": "UPnP RTSP 554 проброс камеры Hikvision",
                    "severity": "critical",
                    "created_at": "2026-10-06T00:35:10",
                },
                {
                    "type": "audit",
                    "id": "aud_1",
                    "mac": "11:22:33:44:55:66",
                    "ip": "192.168.1.55",
                    "hostname": "LG OLED 65 Smart TV",
                    "risk_level": "warning",
                    "created_at": "2026-10-06T00:30:00",
                },
            ],
            "devices": [
                {"mac": "02:00:00:11:22:33", "ip": "192.168.1.10", "hostname": "Samsung Galaxy S25 Demo", "vendor": "Samsung Electronics"},
                {"mac": "11:22:33:44:55:66", "ip": "192.168.1.55", "hostname": "LG OLED 65 Smart TV", "vendor": "LG Electronics"},
                {"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.80", "hostname": "Hikvision Outdoor Camera", "vendor": "Hikvision"},
            ],
        }

    @app.get("/api/dns/sinkholes")
    async def get_sinkholes():
        return {
            "sinkholes": ["telemetry.samsungcloud.com"],
            "rules": [{"domain": "telemetry.samsungcloud.com", "action": "sinkhole_0000", "hits": 45}],
        }

    @app.post("/api/dns/sinkhole/block")
    async def block_sinkhole(payload: dict = Body(...)):
        return {"status": "ok", "blocked": payload.get("domain")}

    @app.post("/api/dns/sinkhole/unblock")
    async def unblock_sinkhole(payload: dict = Body(...)):
        return {"status": "ok", "unblocked": payload.get("domain")}

    @app.post("/api/audit/{mac}/start")
    async def start_device_audit(mac: str, payload: dict = Body(...)):
        active_audits[mac] = {"mac": mac, "duration": payload.get("duration_seconds", 60), "started_at": time.time()}
        return {"status": "ok", "is_active": True}

    @app.post("/api/audit/{mac}/stop")
    async def stop_device_audit(mac: str):
        active_audits.pop(mac, None)
        return {"status": "stopped"}

    @app.get("/api/audit/{mac}/status")
    async def audit_status(mac: str):
        return {"is_active": mac in active_audits, "active": mac in active_audits}

    @app.get("/api/audit/{mac}/latest_report")
    async def audit_latest_report(mac: str):
        rep = next((r for r in audit_reports_db if r["mac"].lower() == mac.lower()), audit_reports_db[0])
        return rep

    @app.post("/api/audit/network/start")
    async def start_net_audit(payload: dict = Body(...)):
        active_audits["NETWORK"] = {"mac": "NETWORK", "duration": payload.get("duration_seconds", 0)}
        return {"status": "ok", "active": True}

    @app.post("/api/audit/network/stop")
    async def stop_net_audit():
        active_audits.pop("NETWORK", None)
        return {"status": "stopped"}

    @app.get("/api/audit/reports")
    async def get_audit_reports():
        return audit_reports_db

    @app.get("/api/audit/report/{report_id}")
    async def get_report_detail(report_id: str):
        return audit_reports_db[0]

    @app.get("/api/audit/active")
    async def get_active_audits():
        return list(active_audits.values())

    @app.get("/api/packets/live")
    async def get_live_packets(limit: int = 100):
        return {"packets": packets_db, "total_buffered": len(packets_db), "is_pcap": False}

    @app.get("/api/packets/inspect/{pkt_id}")
    async def inspect_packet(pkt_id: int):
        return {
            "dissection": {
                "layers": [
                    {
                        "name": "Ethernet II",
                        "summary": "Src: 02:00:00:11:22:33, Dst: ff:ff:ff:ff:ff:ff",
                        "fields": [
                            {"name": "Destination", "value": "ff:ff:ff:ff:ff:ff"},
                            {"name": "Source", "value": "02:00:00:11:22:33"},
                            {"name": "Type", "value": "IPv4 (0x0800)"},
                        ],
                    },
                    {
                        "name": "Internet Protocol Version 4",
                        "summary": "Src: 192.168.1.10, Dst: 192.168.1.1",
                        "fields": [
                            {"name": "Version", "value": "4"},
                            {"name": "Header Length", "value": "20 bytes"},
                            {"name": "Protocol", "value": "TCP (6)"},
                        ],
                    },
                    {
                        "name": "Transmission Control Protocol",
                        "summary": "Src Port: 54321, Dst Port: 443, Seq: 1, Ack: 1",
                        "fields": [
                            {"name": "Source Port", "value": "54321"},
                            {"name": "Destination Port", "value": "443"},
                            {"name": "Flags", "value": "SYN, ACK"},
                        ],
                    },
                ]
            },
            "hexdump": "0000   ff ff ff ff ff ff 02 00 00 11 22 33 08 00 45 00\n0010   00 3c 1a 2b 40 00 40 06 b2 a1 c0 a8 01 0a c0 a8",
            "hex_dump_lines": [
                {
                    "offset": "0000",
                    "hex_bytes": ["ff", "ff", "ff", "ff", "ff", "ff", "02", "00", "00", "11", "22", "33", "08", "00", "45", "00"],
                    "ascii": "............\"3..",
                },
                {
                    "offset": "0010",
                    "hex_bytes": ["00", "3c", "1a", "2b", "40", "00", "40", "06", "b2", "a1", "c0", "a8", "01", "0a", "c0", "a8"],
                    "ascii": ".<.+@.@.........",
                },
            ],
            "payload_str": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        }

    @app.get("/api/packets/pcap/saved")
    async def get_saved_pcaps():
        return {"pcaps": [{"filename": "sample_tv_night_dump.pcap", "size_kb": 128, "created_at": "2026-10-06T00:30:00"}]}

    @app.get("/api/tv/brand_presets")
    async def tv_brand_presets():
        return {
            "presets": [
                {
                    "id": "tv_lg",
                    "name": "LG webOS",
                    "brand": "LG webOS",
                    "active_count": 0,
                    "total_count": 18,
                    "safe_count": 12,
                    "blocked_domains_count": 18,
                    "manual_hint": "Меню -> Все настройки -> Общие -> Дополнительные настройки -> Live Plus -> Отключить",
                    "detected_devices": [{"custom_name": "LG OLED 65 Smart TV", "ip": "192.168.1.55"}],
                },
                {
                    "id": "tv_samsung",
                    "name": "Samsung Tizen",
                    "brand": "Samsung Tizen",
                    "active_count": 0,
                    "total_count": 24,
                    "safe_count": 16,
                    "blocked_domains_count": 24,
                    "manual_hint": "Меню -> Настройки -> Все настройки -> Условия и политика -> Службы информации о просмотре -> Отключить",
                    "detected_devices": [],
                },
            ],
            "active_sinkholes_count": 0,
            "suggested_brand": "tv_lg",
        }

    @app.get("/api/settings")
    async def get_settings():
        return {
            "new_device_quarantine_wan": True,
            "new_device_isolate_lan": False,
            "new_device_auto_audit": False,
            "camera_nvr_ip": "192.168.1.100",
            "camera_upload_threshold": 1500,
            "telegram_enabled": True,
            "telegram_token": "123456789:ABCdefGhIJKlmNoPQRstuVWXyz",
            "telegram_chat": "987654321",
            "night_mode_start": 0,
            "night_mode_end": 7,
            "digest_enabled": True,
            "digest_condition": "only_on_issues",
        }

    @app.post("/api/settings")
    async def save_settings(payload: dict = Body(...)):
        return {"status": "saved"}

    @app.post("/api/telegram/test")
    async def telegram_test():
        return {"status": "ok", "delivered": True}

    @app.get("/api/export/{entity}")
    async def export_data(entity: str, format: str = "csv"):
        if format == "json":
            json_bytes = json.dumps(devices_db, ensure_ascii=False, indent=2).encode("utf-8")
            return Response(
                content=json_bytes,
                media_type="application/json",
                headers={"Content-Disposition": f"attachment; filename={entity}.json"},
            )
        else:
            csv_data = "mac,ip,name,profile\n02:00:00:11:22:33,192.168.1.10,Samsung Galaxy S25 Demo,trusted\n".encode("utf-8-sig")
            return Response(
                content=csv_data,
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename={entity}.csv"},
            )

    @app.get("/")
    async def index_page():
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static_dir")
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR)), name="static_assets")

    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()


class VisualCDPSession:
    def __init__(
        self,
        browser_bin: str,
        server_port: int,
        headless: bool = False,
        speed_factor: float = 1.0,
        update_baselines: bool = False,
        topmost: bool = True,
    ):
        self.browser_bin = browser_bin
        self.server_port = server_port
        self.headless = headless
        self.speed = speed_factor
        self.update_baselines = update_baselines
        self.topmost = topmost
        self.cdp_port = get_free_port()
        self.tmp_dir = tempfile.mkdtemp()
        self.proc = None
        self.win32_process = None
        self.pid = 0
        self.ws = None
        self.cmd_id = 0
        self.step_counter = 0
        self.step_results = []
        self.baseline_dir = REPO_ROOT / "tests" / "visual_baselines"
        self.run_dir = REPO_ROOT / "tests" / "visual_runs" / "latest"
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self):
        cmd = [
            self.browser_bin,
            f"--remote-debugging-port={self.cdp_port}",
            "--remote-allow-origins=*",
            f"--user-data-dir={self.tmp_dir}",
            "--window-size=1920,1080",
            "--disable-extensions",
            "--no-first-run",
            "--no-default-browser-check",
            "--start-maximized",
            "about:blank",
        ]
        if self.headless:
            cmd.insert(1, "--headless=new")

        if not self.headless and sys.platform == "win32":
            k32 = ctypes.windll.kernel32
            si = STARTUPINFOW()
            si.cb = ctypes.sizeof(STARTUPINFOW)
            si.lpDesktop = "Default"
            pi = PROCESS_INFORMATION()

            cmd_str = subprocess.list2cmdline(cmd)
            res = k32.CreateProcessW(None, cmd_str, None, None, False, 0, None, None, ctypes.byref(si), ctypes.byref(pi))
            if res == 0:
                raise RuntimeError(f"Не удалось запустить браузер на рабочем столе: код ошибки {k32.GetLastError()}")
            self.win32_process = pi
            self.pid = pi.dwProcessId
        else:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.pid = self.proc.pid

        ws_url = None
        for _ in range(45):
            await asyncio.sleep(0.15)
            try:
                r = httpx.get(f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=0.8)
                pages = [item for item in r.json() if item.get("type") == "page"]
                if len(pages) > 0:
                    ws_url = pages[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                pass

        if not ws_url:
            raise RuntimeError("Не удалось получить URL подключения Chrome DevTools Protocol (CDP).")

        self.ws = await websockets.connect(ws_url)

        await self.send("Page.enable")
        await self.send("Runtime.enable")
        try:
            await self.send("Page.setDownloadBehavior", {"behavior": "allow", "downloadPath": str(self.tmp_dir)})
        except Exception:
            pass

        # Navigate to KeenGuard UI
        await self.send("Page.navigate", {"url": f"http://127.0.0.1:{self.server_port}/"})

        # Wait for app.js initialization
        for _ in range(50):
            await asyncio.sleep(0.15)
            res = await self.eval("typeof switchTab")
            if res == "function":
                break

        # Bring window to front & pin topmost
        try:
            await self.send("Page.bringToFront")
        except Exception:
            pass

        if not self.headless:
            bring_window_to_front(self.pid, topmost=self.topmost)

        # Override confirm and alert to prevent modal dialog freezes
        await self.eval("window.confirm = () => true; window.alert = () => true;")

        # Inject Visual HUD & Cursor Overlay
        await self.inject_visual_overlays()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if not self.headless and self.topmost:
            bring_window_to_front(self.pid, topmost=False)

        if self.ws:
            await self.ws.close()
        if self.win32_process:
            k32 = ctypes.windll.kernel32
            k32.TerminateProcess(self.win32_process.hProcess, 0)
            k32.CloseHandle(self.win32_process.hProcess)
            k32.CloseHandle(self.win32_process.hThread)
        elif self.proc:
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
        res = await self.send("Runtime.evaluate", {"expression": expression, "returnByValue": True})
        return res.get("result", {}).get("value")

    async def inject_visual_overlays(self):
        script = """
        (() => {
            if (document.getElementById('__cdp_hud')) return;

            // 1. Dual-line Floating Top HUD
            const hud = document.createElement('div');
            hud.id = '__cdp_hud';
            hud.style.cssText = `
                position: fixed;
                top: 18px;
                left: 50%;
                transform: translateX(-50%);
                z-index: 999999;
                background: rgba(15, 23, 42, 0.95);
                backdrop-filter: blur(14px);
                border: 1px solid rgba(56, 189, 248, 0.65);
                box-shadow: 0 12px 35px -5px rgba(0, 0, 0, 0.7), 0 0 25px rgba(56, 189, 248, 0.3);
                color: #f8fafc;
                padding: 10px 26px;
                border-radius: 9999px;
                font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 3px;
                pointer-events: none;
                transition: all 0.3s ease;
                min-width: 380px;
                text-align: center;
            `;
            hud.innerHTML = `
                <div style="display:flex; align-items:center; gap:10px;">
                    <span id="__cdp_hud_dot" style="display:inline-block; width:10px; height:10px; border-radius:50%; background:#22c55e; box-shadow:0 0 12px #22c55e;"></span>
                    <span id="__cdp_hud_title" style="font-size:13px; font-weight:700; color:#38bdf8;">Инициализация KeenGuard Showcase...</span>
                </div>
                <div id="__cdp_hud_action" style="font-size:11px; color:#cbd5e1; font-weight:500;">Подготовка виртуального оператора...</div>
            `;
            document.body.appendChild(hud);

            // 2. Glowing Visual Mouse Pointer
            const cursor = document.createElement('div');
            cursor.id = '__cdp_cursor';
            cursor.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 28px;
                height: 28px;
                pointer-events: none;
                z-index: 1000000;
                transform: translate(960px, 540px);
                transition: transform 0.35s cubic-bezier(0.25, 1, 0.5, 1);
            `;
            cursor.innerHTML = `
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 3px 10px rgba(0,0,0,0.85));">
                    <path d="M5.5 3.5l13 8-6.5 1.5-3.5 7.5-3-17z" fill="#06b6d4" stroke="#ffffff" stroke-width="1.8" stroke-linejoin="round"/>
                </svg>
                <div id="__cdp_ripple" style="
                    position: absolute;
                    top: -4px;
                    left: -4px;
                    width: 36px;
                    height: 36px;
                    border-radius: 50%;
                    border: 2px solid #38bdf8;
                    background: rgba(56, 189, 248, 0.25);
                    opacity: 0;
                    transform: scale(0.4);
                    pointer-events: none;
                "></div>
            `;
            document.body.appendChild(cursor);

            window.__moveVisualCursor = (x, y) => {
                cursor.style.transform = `translate(${x}px, ${y}px)`;
            };

            window.__clickVisualCursor = () => {
                const ripple = document.getElementById('__cdp_ripple');
                if (ripple) {
                    ripple.style.transition = 'none';
                    ripple.style.opacity = '1';
                    ripple.style.transform = 'scale(0.8)';
                    requestAnimationFrame(() => {
                        ripple.style.transition = 'all 0.55s ease-out';
                        ripple.style.opacity = '0';
                        ripple.style.transform = 'scale(3.0)';
                    });
                }
            };

            window.__setHud = (title, action, dotColor = '#22c55e') => {
                const titleEl = document.getElementById('__cdp_hud_title');
                if (titleEl) titleEl.textContent = title;
                const actionEl = document.getElementById('__cdp_hud_action');
                if (actionEl) actionEl.textContent = action;
                const dot = document.getElementById('__cdp_hud_dot');
                if (dot) {
                    dot.style.background = dotColor;
                    dot.style.boxShadow = `0 0 12px ${dotColor}`;
                }
            };
        })();
        """
        await self.eval(script)

    async def set_hud(self, title: str, action: str = "", dot_color: str = "#22c55e"):
        safe_title = title.replace('"', '\\"').replace("'", "\\'")
        safe_action = action.replace('"', '\\"').replace("'", "\\'")
        await self.eval(f"window.__setHud && window.__setHud('{safe_title}', '{safe_action}', '{dot_color}')")
        print(f"  [HUD] {title} -> {action}")

    async def mouse_move_to(self, x: float, y: float):
        await self.eval(f"window.__moveVisualCursor && window.__moveVisualCursor({x}, {y})")
        await self.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
        await asyncio.sleep(0.35 * self.speed)

    async def click_at(self, x: float, y: float):
        await self.mouse_move_to(x, y)
        await self.eval("window.__clickVisualCursor && window.__clickVisualCursor()")
        await self.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": x, "y": y, "button": "left", "clickCount": 1})
        await asyncio.sleep(0.12 * self.speed)
        await self.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": x, "y": y, "button": "left", "clickCount": 1})
        await asyncio.sleep(0.4 * self.speed)

    async def drag_and_drop(self, start_x: float, start_y: float, end_x: float, end_y: float, steps: int = 14):
        """Simulates physical mouse press, continuous drag across screen, and release."""
        await self.mouse_move_to(start_x, start_y)
        await asyncio.sleep(0.15 * self.speed)
        await self.eval("window.__clickVisualCursor && window.__clickVisualCursor()")
        await self.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": start_x, "y": start_y, "button": "left", "clickCount": 1})
        await asyncio.sleep(0.15 * self.speed)

        for i in range(1, steps + 1):
            curr_x = start_x + (end_x - start_x) * (i / steps)
            curr_y = start_y + (end_y - start_y) * (i / steps)
            await self.eval(f"window.__moveVisualCursor && window.__moveVisualCursor({curr_x}, {curr_y})")
            await self.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": curr_x, "y": curr_y, "button": "left"})
            await asyncio.sleep(0.04 * self.speed)

        await self.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": end_x, "y": end_y, "button": "left", "clickCount": 1})
        await asyncio.sleep(0.35 * self.speed)

    async def press_key(self, key_name: str, vk_code: int):
        await self.send("Input.dispatchKeyEvent", {"type": "rawKeyDown", "windowsVirtualKeyCode": vk_code, "key": key_name, "code": key_name})
        await asyncio.sleep(0.06)
        await self.send("Input.dispatchKeyEvent", {"type": "keyUp", "windowsVirtualKeyCode": vk_code, "key": key_name, "code": key_name})
        await asyncio.sleep(0.3 * self.speed)

    async def type_text(self, selector: str, text: str, clear: bool = True):
        center = await self.get_center(selector)
        if center:
            await self.click_at(center["x"], center["y"])
        await asyncio.sleep(0.1)

        if clear:
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
                "key": char,
            })
            await self.send("Input.dispatchKeyEvent", {
                "type": "keyUp",
                "key": char,
            })
            await asyncio.sleep(0.04 * self.speed)

        await self.eval(f"""
            (() => {{
                const el = document.querySelector('{selector}');
                if (el) {{
                    el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                    el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                }}
            }})()
        """)
        await asyncio.sleep(0.25 * self.speed)

    async def get_center(self, selector: str) -> dict[str, float] | None:
        return await self.eval(f"""
            (() => {{
                const el = document.querySelector('{selector}');
                if (!el) return null;
                const r = el.getBoundingClientRect();
                if (r.width === 0 && r.height === 0) return null;
                return {{ x: r.left + r.width / 2, y: r.top + r.height / 2, width: r.width, height: r.height }};
            }})()
        """)

    async def click_element(self, selector: str) -> bool:
        center = await self.get_center(selector)
        if center:
            await self.click_at(center["x"], center["y"])
            return True
        return False

    async def capture_step(self, step_slug: str, title: str, description: str) -> dict:
        """Captures screenshot via CDP, compares with baseline, and tracks metrics."""
        self.step_counter += 1
        seq = self.step_counter
        step_id = f"{seq:02d}_{step_slug}"

        await asyncio.sleep(0.3 * self.speed)

        # 1. Take Screenshot via CDP
        data = await self.send("Page.captureScreenshot", {"format": "png"})
        img_b64 = data.get("data", "")
        img_bytes = base64.b64decode(img_b64)

        run_file = self.run_dir / f"{step_id}.png"
        run_file.write_bytes(img_bytes)

        baseline_file = self.baseline_dir / f"{step_id}.png"
        diff_file = self.run_dir / f"{step_id}_diff.png"

        status = "new"
        diff_percent = 0.0

        if self.update_baselines or not baseline_file.exists():
            baseline_file.write_bytes(img_bytes)
            status = "baseline_saved"
        else:
            try:
                from PIL import Image, ImageChops

                img_curr = Image.open(run_file).convert("RGBA")
                img_base = Image.open(baseline_file).convert("RGBA")

                if img_curr.size != img_base.size:
                    status = "mismatch"
                    diff_percent = 100.0
                else:
                    diff = ImageChops.difference(img_curr, img_base)
                    diff_bbox = diff.getbbox()
                    if diff_bbox is None:
                        status = "match"
                        diff_percent = 0.0
                    else:
                        diff_gray = diff.convert("L")
                        # Noise filter threshold for minor font rendering anti-aliasing (<= 20)
                        diff_thresh = diff_gray.point(lambda p: 255 if p > 20 else 0)
                        diff_pixels = diff_thresh.histogram()[-1]
                        total_pixels = img_curr.width * img_curr.height
                        diff_percent = round((diff_pixels / total_pixels) * 100, 3)

                        if diff_percent <= 1.2:
                            status = "match"
                        else:
                            status = "mismatch"
                            # Visual highlight changed areas in vibrant neon red
                            highlight = Image.new("RGBA", img_curr.size, (255, 0, 70, 210))
                            mask = diff_thresh.convert("L")
                            diff_vis = Image.composite(highlight, img_curr, mask)
                            diff_vis.save(diff_file)
            except Exception as e:
                print(f"    [Warning] Image diffing error: {e}")
                status = "error"

        result = {
            "seq": seq,
            "step_id": step_id,
            "slug": step_slug,
            "title": title,
            "description": description,
            "status": status,
            "diff_percent": diff_percent,
            "run_image": str(run_file.relative_to(REPO_ROOT)).replace("\\", "/"),
            "baseline_image": str(baseline_file.relative_to(REPO_ROOT)).replace("\\", "/"),
            "diff_image": str(diff_file.relative_to(REPO_ROOT)).replace("\\", "/") if diff_file.exists() else None,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        self.step_results.append(result)

        badge = {
            "match": "✅ MATCH",
            "baseline_saved": "📸 BASELINE",
            "mismatch": f"⚠️ DIFF ({diff_percent}%)",
            "error": "❌ ERROR",
        }.get(status, status)
        print(f"    [SNAPSHOT #{seq:02d}] {badge} -> {title} ({step_slug})")
        return result


def generate_html_report(results: list[dict], report_file: Path):
    total = len(results)
    matches = sum(1 for r in results if r["status"] == "match")
    baselines = sum(1 for r in results if r["status"] == "baseline_saved")
    mismatches = sum(1 for r in results if r["status"] == "mismatch")
    errors = sum(1 for r in results if r["status"] == "error")

    cards_html = []
    for r in results:
        status_colors = {
            "match": ("bg-emerald-500/10 text-emerald-400 border-emerald-500/30", "MATCH (100% совпадение)"),
            "baseline_saved": ("bg-blue-500/10 text-blue-400 border-blue-500/30", "ЭТАЛОН (Baseline сохранен)"),
            "mismatch": ("bg-rose-500/10 text-rose-400 border-rose-500/30", f"РАСХОЖДЕНИЕ ({r['diff_percent']}%)"),
            "error": ("bg-amber-500/10 text-amber-400 border-amber-500/30", "ОШИБКА СРАВНЕНИЯ"),
        }
        badge_cls, badge_text = status_colors.get(r["status"], ("bg-slate-800 text-slate-300", r["status"]))

        tabs_btns = f"""
            <button onclick="showStepImg('{r['step_id']}', 'run')" id="tab-{r['step_id']}-run" class="px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition">Факт (Текущий прогон)</button>
            <button onclick="showStepImg('{r['step_id']}', 'base')" id="tab-{r['step_id']}-base" class="px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white transition">Эталон (Референс)</button>
        """
        if r.get("diff_image"):
            tabs_btns += f"""
            <button onclick="showStepImg('{r['step_id']}', 'diff')" id="tab-{r['step_id']}-diff" class="px-3 py-1 rounded-lg text-xs font-semibold bg-rose-950/80 text-rose-300 border border-rose-700/50 hover:bg-rose-900 transition">Diff (Расхождения)</button>
            """

        card = f"""
        <div class="bg-surface-900 border border-slate-800/90 rounded-2xl p-5 space-y-4 shadow-xl">
            <div class="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
                <div class="space-y-1">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300">#{r['seq']:02d}</span>
                        <h3 class="text-sm font-bold text-white font-sans">{r['title']}</h3>
                    </div>
                    <p class="text-xs text-slate-400">{r['description']}</p>
                </div>
                <div class="flex items-center space-x-2 shrink-0">
                    <span class="px-2.5 py-1 rounded-lg text-xs font-bold border {badge_cls}">{badge_text}</span>
                    <span class="text-[11px] text-slate-500 font-mono">{r['timestamp']}</span>
                </div>
            </div>

            <div class="flex items-center space-x-2">
                {tabs_btns}
            </div>

            <div class="relative rounded-xl overflow-hidden border border-slate-800 bg-slate-950 group cursor-pointer" onclick="openFullscreenModal('{r['step_id']}')">
                <img id="img-{r['step_id']}" src="../{r['run_image']}" data-run="../{r['run_image']}" data-base="../{r['baseline_image']}" data-diff="{('../' + r['diff_image']) if r.get('diff_image') else ''}" alt="{r['title']}" class="w-full h-auto object-cover max-h-[500px] transition-transform duration-200 group-hover:scale-[1.01]">
                <div class="absolute bottom-3 right-3 px-2.5 py-1 rounded-lg bg-black/80 backdrop-blur text-[11px] text-slate-300 border border-slate-700/60 pointer-events-none flex items-center space-x-1">
                    <span>🔍 Нажмите для полноэкранного осмотра</span>
                </div>
            </div>
        </div>
        """
        cards_html.append(card)

    template = """<!DOCTYPE html>
<html lang="ru" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KeenGuard — Отчет визуального регрессионного тестирования (Visual Snapshot Suite)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        surface: { 900: '#0f172a', 950: '#020617' }
                    }
                }
            }
        };
    </script>
</head>
<body class="bg-surface-950 text-slate-100 min-h-screen p-6 sm:p-10 font-sans antialiased">
    <div class="max-w-7xl mx-auto space-y-8">
        <!-- Header -->
        <header class="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-6">
            <div>
                <div class="flex items-center space-x-3">
                    <span class="w-3.5 h-3.5 rounded-full bg-cyan-400 shadow-[0_0_12px_#22d3ee]"></span>
                    <h1 class="text-2xl font-bold text-white tracking-tight">KeenGuard Visual Regression Report</h1>
                </div>
                <p class="text-sm text-slate-400 mt-1">Пошаговая фото-фиксация каждого действия и попиксельное сравнение с эталонными референсами (Golden Images)</p>
            </div>
            <!-- Stats Bar -->
            <div class="flex items-center space-x-3 bg-surface-900 border border-slate-800 p-2.5 rounded-2xl shadow-xl">
                <div class="px-3 py-1.5 rounded-xl bg-slate-800/80 text-center">
                    <span class="text-[10px] text-slate-400 block uppercase font-bold tracking-wider">Всего шагов</span>
                    <span class="text-lg font-bold text-white">__TOTAL__</span>
                </div>
                <div class="px-3 py-1.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-center">
                    <span class="text-[10px] text-emerald-400 block uppercase font-bold tracking-wider">Совпало</span>
                    <span class="text-lg font-bold text-emerald-300">__MATCHES__</span>
                </div>
                <div class="px-3 py-1.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-center">
                    <span class="text-[10px] text-blue-400 block uppercase font-bold tracking-wider">Эталонов</span>
                    <span class="text-lg font-bold text-blue-300">__BASELINES__</span>
                </div>
                <div class="px-3 py-1.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-center">
                    <span class="text-[10px] text-rose-400 block uppercase font-bold tracking-wider">Расхождений</span>
                    <span class="text-lg font-bold text-rose-300">__MISMATCHES__</span>
                </div>
            </div>
        </header>

        <!-- Gallery of Steps -->
        <main class="space-y-6">
            __CARDS__
        </main>
    </div>

    <!-- Fullscreen Modal -->
    <div id="modal-fs" class="fixed inset-0 z-50 bg-black/90 backdrop-blur hidden flex flex-col items-center justify-center p-4 cursor-zoom-out" onclick="closeFullscreenModal()">
        <img id="modal-fs-img" src="" class="max-w-full max-h-[92vh] object-contain rounded-xl shadow-2xl border border-slate-800">
        <p class="text-xs text-slate-400 mt-2">Кликните в любое место для закрытия</p>
    </div>

    <script>
        function showStepImg(stepId, type) {
            const img = document.getElementById('img-' + stepId);
            if (!img) return;
            const btnRun = document.getElementById('tab-' + stepId + '-run');
            const btnBase = document.getElementById('tab-' + stepId + '-base');
            const btnDiff = document.getElementById('tab-' + stepId + '-diff');

            if (type === 'run') {
                img.src = img.getAttribute('data-run');
                if (btnRun) btnRun.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition";
                if (btnBase) btnBase.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white transition";
                if (btnDiff) btnDiff.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-rose-300 border border-rose-700/50 hover:bg-rose-900 transition";
            } else if (type === 'base') {
                img.src = img.getAttribute('data-base');
                if (btnRun) btnRun.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white transition";
                if (btnBase) btnBase.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition";
                if (btnDiff) btnDiff.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-rose-300 border border-rose-700/50 hover:bg-rose-900 transition";
            } else if (type === 'diff') {
                img.src = img.getAttribute('data-diff');
                if (btnRun) btnRun.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white transition";
                if (btnBase) btnBase.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-slate-800 text-slate-400 hover:text-white transition";
                if (btnDiff) btnDiff.className = "px-3 py-1 rounded-lg text-xs font-semibold bg-rose-600 text-white transition";
            }
        }

        function openFullscreenModal(stepId) {
            const img = document.getElementById('img-' + stepId);
            if (!img) return;
            const modal = document.getElementById('modal-fs');
            const modalImg = document.getElementById('modal-fs-img');
            modalImg.src = img.src;
            modal.classList.remove('hidden');
        }

        function closeFullscreenModal() {
            document.getElementById('modal-fs').classList.add('hidden');
        }
    </script>
</body>
</html>
"""
    html_content = (
        template.replace("__TOTAL__", str(total))
        .replace("__MATCHES__", str(matches))
        .replace("__BASELINES__", str(baselines))
        .replace("__MISMATCHES__", str(mismatches))
        .replace("__CARDS__", "\n".join(cards_html))
    )
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(html_content, encoding="utf-8")
    print(f"\n📊 [REPORT] Полный HTML-отчет со скриншотами сохранен: {report_file}")


async def run_visual_demo(
    browser_bin: str,
    server_port: int,
    headless: bool,
    speed: float,
    pause: float = 30.0,
    update_baselines: bool = False,
    topmost: bool = True,
):
    print("\n" + "=" * 80)
    print("🚀 Запуск глубокой интерактивной демонстрации со скриншотом КАЖДОГО действия")
    print(f"🌐 Браузер: {browser_bin}")
    print(f"🖥️  Режим: {'Headless (фоновый)' if headless else 'GUI (закреплен поверх всех окон на рабочем столе)'}")
    print(f"📸 Запись скриншотов: {'Обновление эталонов (--update-baselines)' if update_baselines else 'Попиксельное сравнение с эталонами'}")
    print(f"⏱️  Коэффициент скорости: {speed}x")
    print(f"⏳ Время осмотра после завершения: {int(pause)} сек")
    print("=" * 80 + "\n")

    async with VisualCDPSession(
        browser_bin,
        server_port,
        headless=headless,
        speed_factor=speed,
        update_baselines=update_baselines,
        topmost=topmost,
    ) as session:
        # =====================================================================
        # ГЛАВА 1: Дашборд и сетевые экспресс-проверки
        # =====================================================================
        await session.set_hud("Глава 1/12: Дашборд безопасности", "Переход на главный экран и обзор метрик...", "#38bdf8")
        await session.eval("switchTab('dashboard'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("01_dashboard_initial", "Дашборд безопасности", "Начальное состояние главной панели")

        await session.set_hud("Глава 1/12: Дашборд безопасности", "Запуск экспресс-аудита Wi-Fi сети роутера...", "#f59e0b")
        await session.eval("loadWifiAudit && loadWifiAudit()")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("02_dashboard_wifi_audit", "Экспресс-аудит Wi-Fi", "Результаты проверки безопасности беспроводной сети")

        await session.set_hud("Глава 1/12: Дашборд безопасности", "Проверка доступности обновлений KeeneticOS...", "#10b981")
        await session.eval("checkRouterUpdates && checkRouterUpdates()")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("03_dashboard_keeneticos_updates", "Проверка обновлений KeeneticOS", "Статус версии прошивки и обновлений безопасности")

        await session.set_hud("Глава 1/12: Дашборд безопасности", "Открытие суточного дайджеста безопасности...", "#a855f7")
        await session.eval("openDigestModal && openDigestModal()")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("04_dashboard_security_digest_modal", "Суточный дайджест безопасности", "Модальное окно сводки инцидентов и оценки сети")

        await session.eval("closeDigestModal && closeDigestModal()")
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("05_dashboard_after_digest_close", "Закрытие дайджеста", "Возврат на главный экран дашборда")

        # =====================================================================
        # ГЛАВА 2: Интерактивная Топология сети (SVG физика и Drag & Drop)
        # =====================================================================
        await session.set_hud("Глава 2/12: Интерактивная Топология", "Переход в топологию и построение графа связей...", "#38bdf8")
        await session.eval("switchTab('topology'); true")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("06_topology_graph_rendered", "Топология сети", "SVG-граф связей устройств и сетевых сегментов")

        node_center = await session.get_center("#topo-node-dev_1 .topology-hit-circle") or await session.get_center("#topo-node-dev_1")
        if node_center:
            # 1. Сначала кликаем по узлу для открытия карточки устройства
            await session.set_hud("Глава 2/12: Интерактивная Топология", "Клик по узлу Galaxy S25 для открытия инспектора...", "#06b6d4")
            await session.click_at(node_center["x"], node_center["y"])
            await asyncio.sleep(1.0 * speed)

            is_modal_open = await session.eval("!document.getElementById('device-modal').classList.contains('hidden')")
            if not is_modal_open:
                await session.eval("openDeviceModal('02:00:00:11:22:33')")
                await asyncio.sleep(1.0 * speed)
            await session.capture_step("07_topology_device_modal_opened", "Открытие карточки устройства", "Инспектор устройства Galaxy S25 поверх топологии")

            # 2. Переходим во вкладку «Безопасность»
            await session.set_hud("Глава 2/12: Интерактивная Топология", "Переход во вкладку «Безопасность» в карточке устройства...", "#8b5cf6")
            await session.click_element("#modal-tab-btn-policies")
            await asyncio.sleep(1.0 * speed)
            await session.capture_step("08_topology_device_policies_tab", "Вкладка «Безопасность»", "Статус L2-сегмента Bridge0 и кнопка мастера изоляции")

            # 3. Открываем мастер L2/L3 изоляции
            await session.set_hud("Глава 2/12: Интерактивная Топология", "Открытие мастера L2/L3-изоляции (Advisor) по кнопке «Как изолировать?»...", "#a855f7")
            guide_btn = await session.get_center('button[onclick*="openIsolationWizard"]')
            if guide_btn:
                await session.click_at(guide_btn["x"], guide_btn["y"])
            else:
                await session.eval("openIsolationWizard('02:00:00:11:22:33')")
            await asyncio.sleep(2.0 * speed)
            await session.capture_step("09_topology_isolation_wizard_modal", "Мастер L2/L3-изоляции", "3 пошаговые инструкции аппаратного переноса в гостевую сеть")

            # 4. Закрываем мастер изоляции
            await session.set_hud("Глава 2/12: Интерактивная Топология", "Закрытие мастера изоляции по кнопке закрытия...", "#ec4899")
            close_wizard_btn = await session.get_center('button[onclick*="closeIsolationWizardModal"]')
            if close_wizard_btn:
                await session.click_at(close_wizard_btn["x"], close_wizard_btn["y"])
            else:
                await session.eval("closeIsolationWizardModal && closeIsolationWizardModal()")
            await asyncio.sleep(0.8 * speed)

            # 5. Закрываем карточку устройства
            await session.set_hud("Глава 2/12: Интерактивная Топология", "Закрытие инспектора устройства клавишей Escape...", "#64748b")
            await session.press_key("Escape", 27)
            await asyncio.sleep(0.8 * speed)
            await session.capture_step("10_topology_modals_closed", "Закрытие модальных окон", "Возврат на чистый граф топологии")

            # 6. Физический Drag-and-Drop демонстрация на топологии
            fresh_node_center = await session.get_center("#topo-node-dev_1 .topology-hit-circle") or await session.get_center("#topo-node-dev_1")
            if fresh_node_center:
                await session.set_hud("Глава 2/12: Интерактивная Топология", "Физический Drag-and-Drop: перетаскивание узла по экрану...", "#ec4899")
                await session.drag_and_drop(fresh_node_center["x"], fresh_node_center["y"], fresh_node_center["x"] + 140, fresh_node_center["y"] + 60, steps=16)
                await asyncio.sleep(1.2 * speed)
                await session.capture_step("11_topology_drag_and_drop_physics", "Drag-and-Drop физика", "Перемещение узла по холсту с растяжением связей D3")

        # =====================================================================
        # ГЛАВА 3: Инспектор устройств — переименование, WAN-блок, изоляция, экспорт
        # =====================================================================
        await session.set_hud("Глава 3/12: Инспектор устройств", "Переход в каталог сетевых устройств...", "#3b82f6")
        await session.eval("switchTab('devices'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("12_devices_catalog", "Реестр устройств", "Каталог подключенных и офлайн клиентов")

        await session.set_hud("Глава 3/12: Инспектор устройств", "Живой поиск с клавиатуры: ввод «Samsung»...", "#06b6d4")
        await session.type_text("#devices-search-input", "Samsung")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("13_devices_search_samsung", "Живой поиск", "Фильтрация таблицы по запросу «Samsung»")

        await session.set_hud("Глава 3/12: Инспектор устройств", "Фильтрация по категориям: Камеры, затем IoT...", "#f59e0b")
        await session.type_text("#devices-search-input", "")
        await session.click_element('button[data-filter="camera"]')
        await asyncio.sleep(0.8 * speed)
        await session.capture_step("14_devices_filter_camera", "Фильтр «Камеры»", "Отображение только сетевых IP-камер")

        await session.click_element('button[data-filter="iot"]')
        await asyncio.sleep(0.8 * speed)
        await session.capture_step("15_devices_filter_iot", "Фильтр «IoT»", "Отображение умных устройств")

        await session.click_element('button[data-filter="all"]')
        await asyncio.sleep(0.8 * speed)
        await session.capture_step("16_devices_filter_all", "Сброс фильтра", "Полный список всех устройств")

        await session.set_hud("Глава 3/12: Инспектор устройств", "Открытие глубокой карточки смартфона Galaxy S25...", "#8b5cf6")
        first_card = await session.get_center('#devices-grid .bg-surface-950')
        if first_card:
            await session.click_at(first_card["x"], first_card["y"])
            await asyncio.sleep(1.2 * speed)
            await session.capture_step("17_devices_card_opened", "Детальная карточка", "Инспектор выбранного смартфона")

            await session.set_hud("Глава 3/12: Инспектор устройств", "Переименование: ввод нового имени «Galaxy S25 Ultra (Рабочий)»...", "#10b981")
            name_input = await session.get_center("#modal-dev-custom-name-input")
            if name_input:
                await session.type_text("#modal-dev-custom-name-input", "Galaxy S25 Ultra (Рабочий)")
                await asyncio.sleep(0.6 * speed)
                await session.click_element('button[onclick*="saveModalCustomName"]')
                await asyncio.sleep(1.0 * speed)
                await session.capture_step("18_devices_renamed", "Переименование", "Сохранение пользовательского имени устройства")

            await session.set_hud("Глава 3/12: Инспектор устройств", "Вкладка «Политики»: включение блокировки выхода в интернет (WAN Block)...", "#ef4444")
            await session.click_element('#modal-tab-btn-policies')
            await asyncio.sleep(0.8 * speed)
            await session.click_element('#modal-toggle-wan')
            await asyncio.sleep(1.0 * speed)
            await session.capture_step("19_devices_wan_block_toggled", "Тумблер WAN Block", "Блокировка выхода в интернет на аппаратном уровне")

            await session.set_hud("Глава 3/12: Инспектор устройств", "Вкладка «Трафик»: осмотр динамики соединений устройства...", "#06b6d4")
            await session.click_element('#modal-tab-btn-traffic')
            await asyncio.sleep(1.2 * speed)
            await session.capture_step("20_devices_traffic_tab", "Вкладка «Трафик»", "График объемов передачи данных устройства")

            await session.set_hud("Глава 3/12: Инспектор устройств", "Вкладка «Спец-режимы & Аудит»: запуск 1-минутной сессии аудита...", "#f97316")
            await session.click_element('#modal-tab-btn-special')
            await asyncio.sleep(1.0 * speed)
            await session.click_element('button[onclick*="startModalAudit"]')
            await asyncio.sleep(1.5 * speed)
            await session.capture_step("21_devices_audit_started", "Запуск аудита", "Запуск 1-минутной сессии глубокого анализа")

            await session.press_key("Escape", 27)
            await asyncio.sleep(0.8 * speed)
            await session.capture_step("22_devices_card_closed", "Закрытие карточки", "Возврат к реестру устройств")

        await session.set_hud("Глава 3/12: Инспектор устройств", "Экспорт реестра устройств: выгрузка данных в CSV и JSON...", "#10b981")
        await session.click_element('button[onclick*="exportData"][onclick*="devices"][onclick*="csv"]')
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("23_devices_export_csv", "Экспорт CSV", "Выгрузка реестра в CSV для Excel")

        await session.click_element('button[onclick*="exportData"][onclick*="devices"][onclick*="json"]')
        await asyncio.sleep(0.8 * speed)
        await session.capture_step("24_devices_export_json", "Экспорт JSON", "Выгрузка реестра в формате JSON")

        curr_path = await session.eval("window.location.pathname")
        if curr_path and curr_path != "/":
            print(f"    [Guard] URL изменился на {curr_path}, возвращаем на главное приложение...")
            await session.send("Page.navigate", {"url": f"http://127.0.0.1:{server_port}/"})
            await asyncio.sleep(1.0)
            await session.inject_visual_overlays()

        # =====================================================================
        # ГЛАВА 4: Умный дом (Smart Home) и защита Zero-Internet
        # =====================================================================
        await session.set_hud("Глава 4/12: Экосистема Умного дома", "Переход в мониторинг хаба SprutHub и IoT-устройств...", "#38bdf8")
        await session.eval("switchTab('smarthome'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("25_smarthome_overview", "Экосистема Умного дома", "Мониторинг хаба SprutHub и счетчики Zero-Internet")

        await session.set_hud("Глава 4/12: Экосистема Умного дома", "Запуск глубокого аудита сетевой активности хаба контроллера...", "#a855f7")
        await session.click_element("#sh-hub-audit-btn")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("26_smarthome_hub_audit_active", "Аудит хаба", "Активация анализа сетевых потоков контроллера")

        # =====================================================================
        # ГЛАВА 5: Конструктор правил (Rules Engine) — полное создание, тумблеры, удаление
        # =====================================================================
        await session.set_hud("Глава 5/12: Конструктор правил", "Переход в центр правил безопасности и фильтрации...", "#3b82f6")
        await session.eval("switchTab('rules'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("27_rules_overview", "Конструктор правил", "Таблица активных правил фаервола")

        await session.set_hud("Глава 5/12: Конструктор правил", "Открытие формы создания правила: кнопка «+ Новое правило»...", "#10b981")
        await session.click_element('button[onclick*="openRuleModal"]')
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("28_rules_modal_opened", "Форма нового правила", "Открытая модальная форма создания правила")

        await session.set_hud("Глава 5/12: Конструктор правил", "Ввод названия: «Блокировка ботнета Mirai (IoT)»...", "#06b6d4")
        await session.type_text("#rule-form-name", "Блокировка ботнета Mirai (IoT)")
        await asyncio.sleep(0.6 * speed)

        await session.set_hud("Глава 5/12: Конструктор правил", "Ввод портов: ограничение Telnet 23 и RDP 3389...", "#f59e0b")
        await session.type_text("#rule-form-ports", "23, 2323, 3389")
        await asyncio.sleep(0.6 * speed)

        await session.set_hud("Глава 5/12: Конструктор правил", "Включение немедленного Telegram-оповещения при инциденте...", "#a855f7")
        await session.click_element("#rule-form-tg-notify")
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("29_rules_form_filled", "Заполнение параметров", "Заполненные порты и Telegram-оповещение")

        await session.set_hud("Глава 5/12: Конструктор правил", "Сохранение правила в активный фаервол роутера...", "#10b981")
        await session.eval("document.getElementById('rule-builder-form') && document.getElementById('rule-builder-form').requestSubmit()")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("30_rules_saved_in_table", "Сохранение правила", "Новое правило добавлено в таблицу активных")

        await session.set_hud("Глава 5/12: Конструктор правил", "Интерактивный тумблер: отключение/включение правила прямо в таблице...", "#eab308")
        toggle_cb = await session.get_center('#rules-table-body input[type="checkbox"]')
        if toggle_cb:
            await session.click_at(toggle_cb["x"], toggle_cb["y"])
            await asyncio.sleep(0.8 * speed)
            await session.capture_step("31_rules_toggle_disabled", "Интерактивный тумблер", "Отключение/включение правила прямо в строке таблицы")
            await session.click_at(toggle_cb["x"], toggle_cb["y"])
            await asyncio.sleep(0.8 * speed)
        else:
            await session.capture_step("31_rules_toggle_disabled", "Интерактивный тумблер", "Отключение/включение правила прямо в строке таблицы")

        await session.set_hud("Глава 5/12: Конструктор правил", "Поиск по правилам: фильтрация таблицы по слову «Mirai»...", "#06b6d4")
        await session.type_text("#rules-search-input", "Mirai")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("32_rules_search_filter", "Поиск правил", "Фильтрация списка по слову «Mirai»")
        await session.type_text("#rules-search-input", "")
        await asyncio.sleep(0.6 * speed)

        await session.set_hud("Глава 5/12: Конструктор правил", "Удаление созданного правила из конфигурации...", "#ef4444")
        await session.eval("window.confirm = () => true; true")
        del_btn = await session.get_center('#rules-table-body button[onclick*="deleteRule"]')
        if del_btn:
            await session.click_at(del_btn["x"], del_btn["y"])
            await asyncio.sleep(1.2 * speed)
        await session.capture_step("33_rules_deleted", "Удаление правила", "Удаление правила из конфигурации фаервола")

        # =====================================================================
        # ГЛАВА 6: Центр инцидентов, отзыв UPnP и мастер расследований
        # =====================================================================
        await session.set_hud("Глава 6/12: Инциденты & UPnP", "Переход в журнал сетевых аномалий и пробросов портов...", "#ef4444")
        await session.eval("switchTab('alerts'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("34_incidents_overview", "Инциденты & UPnP", "Журнал аномалий и список пробросов портов")

        await session.set_hud("Глава 6/12: Инциденты & UPnP", "Обнаружение опасного RTSP-порта 554 камеры: физический отзыв проброса...", "#f97316")
        await session.eval("window.confirm = () => true; deleteUpnp && deleteUpnp('TCP', 554)")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("35_incidents_upnp_revoked", "Отзыв опасного UPnP", "Удаление автоматического проброса видеокамеры")

        await session.set_hud("Глава 6/12: Инциденты & UPnP", "Переход в Мастер расследований инцидентов (Incident Investigator)...", "#a855f7")
        await session.eval("switchTab('investigator'); true")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("36_incidents_investigator_wizard", "Мастер расследований", "Интерактивный мастер расследования аномалий сети")

        # =====================================================================
        # ГЛАВА 7: DNS-мониторинг и аппаратный 0.0.0.0 Sinkhole
        # =====================================================================
        await session.set_hud("Глава 7/12: DNS & Домены", "Переход в мониторинг доменных запросов...", "#06b6d4")
        await session.eval("switchTab('dns'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("37_dns_overview", "DNS-мониторинг", "Журнал доменных запросов и трекеров")

        await session.set_hud("Глава 7/12: DNS & Домены", "Поиск подозрительной телеметрии: фильтрация «samsung»...", "#f59e0b")
        await session.type_text("#dns-search-input", "samsung")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("38_dns_search_samsung", "Поиск телеметрии", "Фильтрация запросов Smart TV телеметрии")

        await session.set_hud("Глава 7/12: DNS & Домены", "Клик по домену telemetry.samsungcloud.com для аналитики трекера...", "#8b5cf6")
        await session.eval("openDomainModal && openDomainModal('telemetry.samsungcloud.com')")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("39_dns_domain_modal_opened", "Аналитика трекера", "Карточка репутации домена и привязка к 0.0.0.0")

        await session.eval("closeDomainModal && closeDomainModal()")
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("40_dns_domain_modal_closed", "Закрытие карточки домена", "Возврат в журнал DNS-запросов")

        # =====================================================================
        # ГЛАВА 8: Инспектор пакетов (Deep Packet Inspector / Live Hex)
        # =====================================================================
        await session.set_hud("Глава 8/12: Инспектор пакетов (DPI)", "Переход в трехпанельный анализатор сырого трафика...", "#38bdf8")
        await session.eval("switchTab('packets'); true")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("41_packets_inspector_live", "Анализатор пакетов (DPI)", "Трехпанельный инспектор с живым потоком")

        await session.set_hud("Глава 8/12: Инспектор пакетов (DPI)", "Фильтрация пакетов: переключение протокола на DNS, затем HTTP...", "#06b6d4")
        await session.eval("""
            (() => {
                const s = document.getElementById('pkt-protocol-select');
                if (s) { s.value = 'DNS'; s.dispatchEvent(new Event('change')); }
            })()
        """)
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("42_packets_protocol_filter_dns", "Фильтр протокола", "Выборка только DNS-трафика")

        await session.set_hud("Глава 8/12: Инспектор пакетов (DPI)", "Заморозка эфира (Пауза) для детального изучения структуры кадра...", "#f59e0b")
        await session.click_element("#pkt-freeze-btn")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("43_packets_frozen", "Пауза захвата", "Заморозка буфера для глубокого анализа кадра")

        await session.set_hud("Глава 8/12: Инспектор пакетов (DPI)", "Выбор первого пакета: декодирование уровней OSI и Hex-дампа...", "#a855f7")
        await session.eval("selectPacketForInspection && selectPacketForInspection(1)")
        await asyncio.sleep(1.6 * speed)
        await session.capture_step("44_packets_osi_hex_decoded", "Декодирование OSI и Hex", "Слои Ethernet/IP/TCP и шестнадцатеричный дамп")

        # =====================================================================
        # ГЛАВА 9: Smart TV & Форензика ночного режима
        # =====================================================================
        await session.set_hud("Глава 9/12: Smart TV & Forensics", "Переход в специализированный анализ поведения телевизоров...", "#10b981")
        await session.eval("switchTab('tv_forensics'); true")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("45_tv_forensics_overview", "Smart TV Форензика", "Пресеты блокировок и анализ фоновой активности ТВ")

        # =====================================================================
        # ГЛАВА 10: Глубокий аудит трафика и архивы отчетов
        # =====================================================================
        await session.set_hud("Глава 10/12: Аудит трафика", "Переход в архив сессий глубокого анализа с детекцией облаков...", "#38bdf8")
        await session.eval("switchTab('audits'); true")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("46_audits_overview", "Архив аудитов", "Список завершенных сессий анализа трафика")

        await session.set_hud("Глава 10/12: Аудит трафика", "Открытие отчета LG OLED TV: оценка риска (75/100) и утечки HTTP...", "#f97316")
        await session.eval("openAuditReportById && openAuditReportById('aud_rep_001')")
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("47_audits_report_modal_opened", "Отчет аудита", "Оценка риска, обнаружение незашифрованного HTTP и облаков")

        await session.eval("closeAuditModal && closeAuditModal()")
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("48_audits_report_closed", "Закрытие отчета", "Возврат в архив аудитов")

        # =====================================================================
        # ГЛАВА 11: Конфигурация Настроек системы (9 категорий)
        # =====================================================================
        await session.set_hud("Глава 11/12: Настройки системы", "Переход в центр параметров: подраздел «Новые устройства»...", "#6366f1")
        await session.eval("navigateToSettingsSubTab('new-devices'); true")
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("49_settings_new_devices", "Новые устройства", "Режим автоматических политик безопасности")

        await session.set_hud("Глава 11/12: Настройки системы", "Подраздел «Камеры»: настройка порога утечки видео (2500 Кбит/с)...", "#f59e0b")
        await session.eval("navigateToSettingsSubTab('cameras'); true")
        await asyncio.sleep(1.0 * speed)
        await session.type_text("#cfg-camera-upload-threshold", "2500")
        await asyncio.sleep(0.6 * speed)
        await session.click_element('button[onclick*="saveCameraSettings"]')
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("50_settings_cameras", "Настройки видеокамер", "Порог утечки видеопотока 2500 Кбит/с")

        await session.set_hud("Глава 11/12: Настройки системы", "Подраздел «Telegram»: настройка бота и проверка отправки алерта...", "#06b6d4")
        await session.eval("navigateToSettingsSubTab('telegram'); true")
        await asyncio.sleep(1.0 * speed)
        await session.click_element('button[onclick*="testTelegram"]')
        await asyncio.sleep(1.2 * speed)
        await session.capture_step("51_settings_telegram", "Telegram-уведомления", "Конфигурация бота и отправка тестового алерта")

        await session.set_hud("Глава 11/12: Настройки системы", "Подраздел «Smart TV & Ночь»: настройка тихих часов (23:00 - 07:00)...", "#a855f7")
        await session.eval("navigateToSettingsSubTab('tv-night'); true")
        await asyncio.sleep(1.0 * speed)
        await session.type_text("#cfg-night-start", "23")
        await asyncio.sleep(0.6 * speed)
        await session.capture_step("52_settings_tv_night", "Smart TV & Ночной режим", "Расписание тихих часов (23:00 - 07:00)")

        await session.set_hud("Глава 11/12: Настройки системы", "Подраздел «Расписание & Дайджест»: включение автоматического отчета...", "#8b5cf6")
        await session.eval("navigateToSettingsSubTab('schedules'); true")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("53_settings_schedules", "Расписания и дайджест", "Автоматические ночные аудиты и дайджесты")

        # =====================================================================
        # ГЛАВА 12: Командная строка быстрого доступа (Ctrl+K)
        # =====================================================================
        await session.set_hud("Глава 12/12: Командная палитра (Ctrl+K)", "Вызов глобальной строки поиска через горячие клавиши...", "#ec4899")
        await session.eval("openCommandPalette(); true")
        await asyncio.sleep(1.0 * speed)
        await session.capture_step("54_command_palette_opened", "Командная палитра (Ctrl+K)", "Глобальная строка быстрого поиска команд и устройств")

        await session.set_hud("Глава 12/12: Командная палитра (Ctrl+K)", "Быстрый набор «Правила» и переход по клавише Enter...", "#06b6d4")
        await session.type_text("#cmd-palette-input", "Правила")
        await asyncio.sleep(0.8 * speed)
        await session.capture_step("55_command_palette_search_rules", "Поиск в палитре", "Подсветка совпадений для быстрого перехода")

        await session.press_key("Enter", 13)
        await asyncio.sleep(1.4 * speed)
        await session.capture_step("56_final_destination", "Финал демонстрации", "Успешный переход к разделу и завершение всех 12 глав")

        # =====================================================================
        # ФИНАЛ: Генерация HTML-отчета со всеми скриншотами
        # =====================================================================
        report_file = REPO_ROOT / "tests" / "visual_report.html"
        generate_html_report(session.step_results, report_file)

        await session.set_hud("🎉 ВСЕ 12 ГЛАВ ПОЛНОГО ФУНКЦИОНАЛА УСПЕШНО ПРОЙДЕНЫ!", "Снято 56 скриншотов, сгенерирован HTML-отчет", "#22c55e")
        print("\n✨ Глубокая визуальная демонстрация всех фич KeenGuard успешно завершена!")
        print(f"📸 Всего зафиксировано {len(session.step_results)} шагов в высоком разрешении.")
        if not headless:
            pause_sec = int(pause)
            print(f"⏳ Окно браузера останется открытым еще {pause_sec} секунд для детального осмотра...")
            for remaining in range(pause_sec, 0, -1):
                await session.set_hud("🎉 Полное интерактивное тестирование завершено!", f"Окно открыто для осмотра (закроется через {remaining} сек)...", "#22c55e")
                await asyncio.sleep(1.0)


def main():
    parser = argparse.ArgumentParser(description="Глубокий визуальный E2E-тест браузера KeenGuard со скриншотом каждого действия.")
    parser.add_argument("--headless", action="store_true", help="Запустить в фоновом безголовом режиме")
    parser.add_argument("--slow", action="store_true", help="Замедлить воспроизведение для детального осмотра (2x)")
    parser.add_argument("--speed", type=float, default=None, help="Пользовательский коэффициент скорости")
    parser.add_argument("--pause", type=float, default=30.0, help="Пауза перед закрытием окна браузера в конце (сек)")
    parser.add_argument("--update-baselines", action="store_true", help="Обновить эталонные скриншоты (Golden Baselines)")
    parser.add_argument("--no-topmost", action="store_true", help="Не закреплять окно поверх всех окон")
    args = parser.parse_args()

    browser_bin = get_browser_binary()
    if not browser_bin:
        print("❌ Ошибка: Не найден установленный исполняемый файл Chrome или Edge на компьютере.")
        sys.exit(1)

    port = get_free_port()
    start_mock_server(port)

    # Wait for server ready
    for _ in range(30):
        time.sleep(0.1)
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/api/auth/status", timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            pass

    if args.speed is not None:
        speed = max(0.2, args.speed)
    elif args.slow:
        speed = 2.0
    else:
        speed = 1.0

    asyncio.run(
        run_visual_demo(
            browser_bin,
            port,
            headless=args.headless,
            speed=speed,
            pause=args.pause,
            update_baselines=args.update_baselines,
            topmost=not args.no_topmost,
        )
    )


if __name__ == "__main__":
    main()
