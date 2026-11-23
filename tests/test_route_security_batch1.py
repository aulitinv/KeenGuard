"""Unit tests verifying Route Security Batch 1 fixes:
1. SSRF and secret exfiltration prevention in /api/telegram/test and /api/dns/provider/test.
2. Secret masking in /api/settings and protection against overwriting with masked strings.
3. Password synchronization between .env, SQLite, and config_service, plus session revocation.
4. CSV Formula Injection (DDE) sanitization in /api/export/devices and /api/export/events.
5. Technical realism in /api/network/topology (quarantine on Bridge0 remains on Bridge0).
6. Traffic L7 Summary using router_manager and correct DB columns.
7. Domain and IP validation for DNS sinkholes and security parameter bounds.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from httpx import AsyncClient, ASGITransport

from keenguard.config import settings
from keenguard.core.config_service import config_service
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.web.app import app
from keenguard.web.auth import (
    hash_password,
    create_session,
    validate_session,
    COOKIE_NAME,
    _active_sessions,
)


@pytest.fixture(autouse=True)
def reset_route_test_state():
    """Reset configuration, sessions, and database state for test isolation."""
    _active_sessions.clear()
    orig_token = settings.telegram_bot_token
    orig_chat_id = settings.telegram_chat_id
    orig_api_url = settings.telegram_api_url
    orig_proxy = settings.telegram_proxy
    orig_pw_hash = settings.web_password_hash
    orig_pw = settings.web_password
    orig_auth_enabled = settings.web_auth_enabled
    orig_exempt = settings.web_auth_exempt_localhost

    yield

    _active_sessions.clear()
    settings.telegram_bot_token = orig_token
    settings.telegram_chat_id = orig_chat_id
    settings.telegram_api_url = orig_api_url
    settings.telegram_proxy = orig_proxy
    settings.web_password_hash = orig_pw_hash
    settings.web_password = orig_pw
    settings.web_auth_enabled = orig_auth_enabled
    settings.web_auth_exempt_localhost = orig_exempt


# =========================================================================
# 1. SSRF & Secret Exfiltration Prevention in Telegram Test
# =========================================================================

@pytest.mark.asyncio
async def test_telegram_test_ssrf_and_token_protection():
    settings.telegram_bot_token = "123456:SECRET_STORED_TOKEN"
    settings.telegram_api_url = "https://api.telegram.org"
    settings.telegram_proxy = None

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # Invalid scheme for api_url
        res = await ac.post("/api/telegram/test", json={"api_url": "ftp://malicious.org"})
        assert res.status_code == 400
        assert "Недопустимая схема Telegram API URL" in res.json()["detail"]

        # Invalid scheme for proxy
        res = await ac.post("/api/telegram/test", json={"proxy": "javascript://alert(1)"})
        assert res.status_code == 400
        assert "Недопустимая схема прокси" in res.json()["detail"]

        # Changed api_url without explicit token -> blocked exfiltration
        res = await ac.post("/api/telegram/test", json={"api_url": "https://attacker-controlled.site"})
        assert res.status_code == 400
        assert "необходимо явно указать token" in res.json()["detail"]

        # Changed proxy without explicit token -> blocked exfiltration
        res = await ac.post("/api/telegram/test", json={"proxy": "http://evil-proxy:8080"})
        assert res.status_code == 400
        assert "необходимо явно указать token" in res.json()["detail"]

        # Unchanged URL/proxy with stored token -> allowed and calls notifier
        with patch("keenguard.web.routes.settings.notifier.send_test_message", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = {"ok": True, "message": "Test message sent"}
            res = await ac.post("/api/telegram/test", json={})
            assert res.status_code == 200
            assert mock_send.await_count == 1
            assert mock_send.await_args.kwargs["token"] == "123456:SECRET_STORED_TOKEN"


# =========================================================================
# 2. Secret Masking in /api/settings & Stored Token Protection
# =========================================================================

@pytest.mark.asyncio
async def test_settings_secret_masking_and_no_overwrite():
    settings.telegram_bot_token = "987654:VERY_SECRET_TOKEN"
    settings.telegram_proxy = "http://myuser:secretpassword@myproxy.net:8080"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # GET /api/settings must return masked token and proxy password
        res = await ac.get("/api/settings")
        assert res.status_code == 200
        data = res.json()
        assert data["telegram_bot_token"] == "••••••••"
        assert data["telegram_bot_token_set"] is True
        assert "secretpassword" not in data["telegram_proxy"]
        assert "myuser:••••••••@myproxy.net:8080" in data["telegram_proxy"]

        # POST /api/settings with masked token should NOT overwrite real token
        post_res = await ac.post("/api/settings", json={
            "telegram_bot_token": "••••••••",
            "telegram_proxy": "http://myuser:••••••••@myproxy.net:8080"
        })
        assert post_res.status_code == 200
        assert settings.telegram_bot_token == "987654:VERY_SECRET_TOKEN"
        assert settings.telegram_proxy == "http://myuser:secretpassword@myproxy.net:8080"


# =========================================================================
# 3. DNS Provider Test Secret Exfiltration Protection
# =========================================================================

@pytest.mark.asyncio
async def test_dns_provider_test_secret_protection():
    settings.adguard_url = "http://192.168.1.5:3000"
    settings.adguard_password = "SuperSecretAdguardPassword"

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # Changing URL with masked password must be rejected
        res = await ac.post("/api/dns/provider/test", json={
            "provider": "adguard_home",
            "config_override": {
                "adguard_url": "http://attacker.example.com",
                "adguard_password": "••••••••"
            }
        })
        assert res.status_code == 400
        assert "Нельзя использовать маскированный пароль" in res.json()["detail"]

        # Non-string password must not cause AttributeError
        res = await ac.post("/api/dns/provider/test", json={
            "provider": "adguard_home",
            "config_override": {
                "adguard_url": "http://192.168.1.5:3000",
                "adguard_password": None
            }
        })
        # Should not raise 500 error; reaches provider test
        assert res.status_code in (200, 400, 502)


# =========================================================================
# 4. Password Sync Between .env, SQLite, config_service & Session Revocation
# =========================================================================

@pytest.mark.asyncio
async def test_password_change_and_config_sync():
    old_pw = "OldPassword123!"
    new_pw = "NewPassword456!"
    old_hash = hash_password(old_pw)

    settings.web_password_hash = old_hash
    settings.web_password = ""
    settings.web_auth_enabled = "true"
    settings.web_auth_exempt_localhost = True

    # Pre-populate config_service cache
    config_service._cache["web_password_hash"] = old_hash

    # Create two active sessions
    token1 = create_session()
    token2 = create_session()
    assert validate_session(token1) is True
    assert validate_session(token2) is True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1", cookies={COOKIE_NAME: token1}) as ac:
        # Wrong old password returns 400
        res = await ac.post("/api/auth/change_password", json={
            "old_password": "WrongPassword",
            "new_password": new_pw
        })
        assert res.status_code == 400
        assert "Неверный старый пароль" in res.json()["detail"]

        # Valid password change
        res = await ac.post("/api/auth/change_password", json={
            "old_password": old_pw,
            "new_password": new_pw
        })
        assert res.status_code == 200

        # Current session survives, other session is revoked
        assert validate_session(token1) is True
        assert validate_session(token2) is False

        # Config service cache is synced
        assert config_service.web_password_hash == settings.web_password_hash

        # Re-initializing config_service does NOT overwrite password hash with old value
        await config_service.initialize()
        assert config_service.web_password_hash == settings.web_password_hash


# =========================================================================
# 5. CSV Formula Injection Sanitization
# =========================================================================

@pytest.mark.asyncio
async def test_csv_formula_injection_sanitization():
    # Insert malicious device record
    malicious_dev = DeviceRecord(
        mac="00:11:22:33:44:55",
        ip="192.168.1.99",
        hostname="+cmd|' /C calc'!A0",
        custom_name="=2+5",
        vendor="@EvilVendor",
        profile="standard"
    )
    await db.upsert_device(malicious_dev)

    # Insert malicious security event
    malicious_event = SecurityEvent(
        target_mac="00:11:22:33:44:55",
        event_type="test_event",
        severity="info",
        description="-FormulaPayload"
    )
    await db.record_event(malicious_event)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # Export devices CSV
        dev_res = await ac.get("/api/export/devices?format=csv")
        assert dev_res.status_code == 200
        csv_text = dev_res.text
        # Formulas should be prefixed with single quote "'"
        assert "'=2+5" in csv_text
        assert "'@EvilVendor" in csv_text

        # Export events CSV
        evt_res = await ac.get("/api/export/events?format=csv")
        assert evt_res.status_code == 200
        evt_text = evt_res.text
        assert "'-FormulaPayload" in evt_text

        # Bounds validation on export events limit (le=5000)
        invalid_limit_res = await ac.get("/api/export/events?limit=99999")
        assert invalid_limit_res.status_code == 422


# =========================================================================
# 6. Technical Realism in Topology Map (Rule 1 AGENTS.md)
# =========================================================================

@pytest.mark.asyncio
async def test_topology_quarantine_device_not_moved_to_guest():
    """
    Devices with profile='quarantine' physically connected to Bridge0 must NOT
    be falsely represented on Bridge1 / Guest Wi-Fi in the topology graph.
    """
    quarantine_dev = DeviceRecord(
        mac="AA:BB:CC:DD:EE:99",
        ip="192.168.1.199",
        hostname="Quarantine-IoT",
        profile="quarantine",
        segment="Home"
    )
    await db.upsert_device(quarantine_dev)

    mock_host = MagicMock()
    mock_host.mac = "AA:BB:CC:DD:EE:99"
    mock_host.ip = "192.168.1.199"
    mock_host.hostname = "Quarantine-IoT"
    mock_host.name = "Quarantine-IoT"
    mock_host.interface = "Bridge0"
    mock_host.link = "up"
    mock_host.active = True

    mock_router_mgr = MagicMock()
    mock_router_mgr.get_hosts = AsyncMock(return_value=[mock_host])
    mock_router_mgr.get_system_info = AsyncMock(return_value=MagicMock(model="Keenetic Extra", firmware_version="4.2.1"))
    mock_router_mgr.get_wan_ip = AsyncMock(return_value="198.51.100.1")
    mock_router_mgr.get_network_segments = AsyncMock(return_value=[
        {"id": "home", "name": "Домашняя сеть", "interface": "Bridge0", "security_level": "trusted"},
        {"id": "guest", "name": "Гостевая сеть", "interface": "Bridge1", "security_level": "isolated"}
    ])
    mock_router_mgr.get_guest_wifi_status = AsyncMock(return_value={"enabled": True, "ssid": "Guest_WiFi"})

    with patch("keenguard.web.routes.topology.router_manager", mock_router_mgr):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
            res = await ac.get("/api/network/topology")
            assert res.status_code == 200
            data = res.json()
            nodes = data["nodes"]

            # Locate the quarantine device node
            q_node = next((n for n in nodes if n.get("mac") == "AA:BB:CC:DD:EE:99"), None)
            assert q_node is not None
            # Must remain on main segment (segment_Bridge0), NOT guest (segment_Bridge1)
            assert q_node["segment_id"] == "segment_Bridge0"
            assert q_node["parent_ap"] != "ap_guest"


# =========================================================================
# 7. Traffic L7 Summary
# =========================================================================

@pytest.mark.asyncio
async def test_traffic_l7_summary_uses_router_manager():
    mock_router_mgr = MagicMock()
    mock_router_mgr.get_dns_cache = AsyncMock(return_value=[
        {"domain": "api.example.com", "ip": "93.184.216.34"}
    ])
    mock_router_mgr.get_nat_table = AsyncMock(return_value=[
        {"src_ip": "192.168.1.105", "dst_ip": "93.184.216.34", "proto": "tcp", "dst_port": 443}
    ])

    with patch("keenguard.web.routes.audit.router_manager", mock_router_mgr):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
            res = await ac.get("/api/traffic/l7-summary")
            assert res.status_code == 200
            data = res.json()
            assert "apps_breakdown" in data
            assert "categories_breakdown" in data
            assert "active_flows_count" in data


# =========================================================================
# 8. Domain Validation & Path Traversal / Security Limits
# =========================================================================

@pytest.mark.asyncio
async def test_sinkhole_validation_and_audit_limits():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # IP address as domain -> 400
        res = await ac.post("/api/dns/sinkhole/block", json={"domain": "192.168.1.1"})
        assert res.status_code == 400

        # Local domain -> 400
        res = await ac.post("/api/dns/sinkhole/block", json={"domain": "myrouter.lan"})
        assert res.status_code == 400

        # TV sinkhole toggle with IP address -> 400
        res = await ac.post("/api/tv/sinkhole/toggle", json={"domain": "10.0.0.1", "block": True})
        assert res.status_code == 400

        # Audit forbidden WAN MAC -> 400
        res = await ac.post("/api/audit/02:00:00:00:00:01/start", json={"duration_seconds": 30})
        assert res.status_code == 400
        assert "Аудит системного интерфейса WAN запрещен" in res.json()["detail"]

        # Events limit > 500 -> 422
        res = await ac.get("/api/events?limit=999")
        assert res.status_code == 422

        # IoT payloads offset < 0 -> 422
        res = await ac.get("/api/iot/payloads?offset=-5")
        assert res.status_code == 422

        # PCAP path traversal blocked
        res = await ac.post("/api/packets/pcap/load", json={"filename": "../secret.pcap"})
        assert res.status_code in (400, 404)
