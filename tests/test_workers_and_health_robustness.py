"""Tests for background workers, RouterHealthMonitor state transitions, and auth robustness."""
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
import httpx

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.web.workers import (
    RouterHealthMonitor,
    do_keenetic_poll,
    get_poll_lock,
)
from keenguard.core.keenetic.base import KeeneticBaseClient
from keenguard.web.ws import ws_manager


@pytest.mark.asyncio
async def test_router_health_monitor_state_transitions():
    """Validates router health transitions: online -> offline -> online with DB and WS notifications."""
    monitor = RouterHealthMonitor()
    monitor.is_connected = True

    broadcast_mock = AsyncMock()
    with patch.object(ws_manager, "broadcast", new=broadcast_mock):
        # 1. Connection Failure
        await monitor.update_status(connected=False, error="Gateway Unreachable Timeout")
        assert monitor.is_connected is False
        assert monitor.last_error == "Gateway Unreachable Timeout"
        assert monitor.failure_count == 1

        # Verify offline event was recorded
        events = await db.get_recent_events(limit=5)
        offline_events = [e for e in events if e.event_type == "router_offline"]
        assert len(offline_events) >= 1
        assert "Gateway Unreachable Timeout" in offline_events[0].description

        # Verify WS broadcast for offline status
        broadcast_mock.assert_awaited()
        last_ws = broadcast_mock.await_args_list[-1].args[0]
        assert last_ws["type"] == "router_status_change"
        assert last_ws["connected"] is False

        # 2. Connection Restored
        await monitor.update_status(connected=True, model="Keenetic Extra", version="4.2.1")
        assert monitor.is_connected is True
        assert monitor.failure_count == 0
        assert monitor.last_error is None

        # Verify online event was recorded
        events = await db.get_recent_events(limit=5)
        online_events = [e for e in events if e.event_type == "router_online"]
        assert len(online_events) >= 1
        assert "Keenetic Extra" in online_events[0].description

        # Verify WS broadcast for online status
        last_ws = broadcast_mock.await_args_list[-1].args[0]
        assert last_ws["type"] == "router_status_change"
        assert last_ws["connected"] is True
        assert last_ws["model"] == "Keenetic Extra"


@pytest.mark.asyncio
async def test_keenetic_auth_failure_modes():
    """Validates that authentication failures return structured error dicts without crashes."""
    client = KeeneticBaseClient(host="192.168.1.1", password="")

    # 1. Empty password
    res = await client.authenticate(password="")
    assert res["status"] == "error"
    assert "Пароль пуст" in res["message"]

    # 2. HTTP 500 error on initial challenge
    client.password = "dummy_pass"
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=httpx.Response(500))):
        res = await client.authenticate()
        assert res["status"] == "error"
        assert "HTTP 500" in res["message"]

    # 3. Missing challenge headers on 401
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=httpx.Response(401, headers={}))):
        res = await client.authenticate()
        assert res["status"] == "error"
        assert "X-NDM-Challenge" in res["message"]

    # 4. Bad credentials (POST /auth returns 401)
    mock_challenge_resp = httpx.Response(
        401,
        headers={
            "X-NDM-Challenge": "test_challenge",
            "X-NDM-Realm": "Keenetic",
            "Set-Cookie": "sub_id=test_sub"
        },
        request=httpx.Request("GET", "http://192.168.1.1/auth")
    )
    mock_auth_fail_resp = httpx.Response(
        401,
        text="Forbidden",
        request=httpx.Request("POST", "http://192.168.1.1/auth")
    )
    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_challenge_resp)), \
         patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_auth_fail_resp)):
        res = await client.authenticate()
        assert res["status"] == "error"
        assert "Неверный логин или пароль" in res["message"] or "HTTP 401" in res["message"]

    # 5. Network transport timeout
    with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=httpx.ConnectTimeout("Connection timed out"))):
        res = await client.authenticate()
        assert res["status"] in ("error", "unreachable")
        assert "Не удалось подключиться" in res["message"] or "Connection" in res["message"]


@pytest.mark.asyncio
async def test_do_keenetic_poll_new_device_quarantine():
    """Validates that do_keenetic_poll detects new devices and executes quarantine policies."""
    from keenguard.core.keenetic.models import HotspotHost

    # Seed an existing device so is_initial_ingestion is False
    existing_dev = DeviceRecord(
        mac="00:11:22:33:44:00",
        ip="192.168.1.10",
        hostname="Existing-PC",
        profile="trusted",
        is_online=True
    )
    await db.upsert_device(existing_dev)

    new_mac = "00:AA:22:33:44:99"
    new_ip = "192.168.1.99"

    mock_hosts = [HotspotHost(
        mac=new_mac,
        ip=new_ip,
        name="Untrusted-Device",
        link="up",
        active=True,
        rxbytes=1000,
        txbytes=500,
        access="permit"
    )]

    settings.new_device_policy_mode = "global"
    settings.new_device_quarantine_wan = True
    settings.new_device_isolate_lan = True
    settings.new_device_auto_audit = True
    settings.new_device_audit_duration = 30

    wan_mock = AsyncMock(return_value=True)
    lan_mock = AsyncMock(return_value=True)
    audit_mock = AsyncMock()

    with patch("keenguard.web.workers.get_keenetic_client") as mock_client_getter, \
         patch("keenguard.core.profiles.profile_manager.toggle_wan", new=wan_mock), \
         patch("keenguard.core.profiles.profile_manager.toggle_lan_isolation", new=lan_mock), \
         patch("keenguard.core.audit.audit_manager.start_audit", new=audit_mock):

        client_mock = MagicMock()
        client_mock.get_hotspot_hosts = AsyncMock(return_value=mock_hosts)
        client_mock.get_upnp_mappings = AsyncMock(return_value=[])
        client_mock.get_nat_table = AsyncMock(return_value=[])
        client_mock.get_dns_cache = AsyncMock(return_value=[])
        mock_client_getter.return_value = client_mock

        # Run poller
        await do_keenetic_poll()

        # Check that new device was quarantined
        wan_mock.assert_awaited_once_with(new_mac, True)
        lan_mock.assert_awaited_once_with(new_mac, True)
        audit_mock.assert_awaited_once()

        # Check device was recorded in DB
        dev = await db.get_device(new_mac)
        assert dev is not None
        assert dev.mac == new_mac
        assert dev.is_blocked_wan is True
        assert dev.is_isolated_lan is True
