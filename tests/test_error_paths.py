"""Unit tests for system resilience and graceful handling of error paths (Phase 6.1)."""
import pytest
import httpx
from unittest.mock import patch, MagicMock
from keenguard.core.keenetic import keenetic_client
from keenguard.core.notifier import notifier
from keenguard.core.dns_providers.nextdns import NextDnsProvider


@pytest.mark.asyncio
async def test_keenetic_connect_timeout():
    """Verify graceful handling when router connection times out during authentication."""
    keenetic_client.mock_mode = False
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectTimeout("Connection to 192.168.1.1:80 timed out")):
        result = await keenetic_client.authenticate(host="192.168.1.1", user="admin", password="password123")
        assert result.get("status") == "unreachable"
        assert "Не удалось подключиться" in result.get("message", "")


@pytest.mark.asyncio
async def test_keenetic_connect_error():
    """Verify graceful handling when router is network-unreachable."""
    keenetic_client.mock_mode = False
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectError("Network is unreachable")):
        result = await keenetic_client.authenticate(host="192.168.1.1", user="admin", password="password123")
        assert result.get("status") == "unreachable"
        assert "Не удалось подключиться" in result.get("message", "")


@pytest.mark.asyncio
async def test_keenetic_malformed_ndm_response():
    """Verify graceful handling when router RCI returns malformed JSON or unexpected schema."""
    keenetic_client.mock_mode = False
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = "invalid non-dict non-list response"

    with patch.object(keenetic_client, "_send_request", return_value=mock_resp):
        # Should not raise exception, falls back to safe default
        wifi_info = await keenetic_client.get_wifi_security()
        assert isinstance(wifi_info, dict)
        assert "grade" in wifi_info

        dns_cache = await keenetic_client.get_dns_cache()
        assert isinstance(dns_cache, list)


@pytest.mark.asyncio
async def test_telegram_rate_limit_429():
    """Verify notifier gracefully handles Telegram HTTP 429 Too Many Requests."""
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.json.return_value = {
        "ok": False,
        "error_code": 429,
        "description": "Too Many Requests: retry after 60"
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        result = await notifier.send_message(
            text="Test Alert",
            token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            chat_id="987654321"
        )
        assert result.get("status") == "error"
        assert "Too Many Requests" in result.get("message", "")


@pytest.mark.asyncio
async def test_telegram_network_connect_error():
    """Verify notifier handles network disconnection or DNS failure gracefully."""
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Failed to resolve api.telegram.org")):
        result = await notifier.send_message(
            text="Test Alert",
            token="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            chat_id="987654321"
        )
        assert result.get("status") == "error"
        assert "Сетевая ошибка" in result.get("message", "")


@pytest.mark.asyncio
async def test_nextdns_api_timeout():
    """Verify NextDNS provider handles API timeout without crashing or data loss."""
    provider = NextDnsProvider(api_key="test_api_key", profile_id="test_profile")

    with patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Read timed out")):
        status = await provider.test_connection()
        assert status.is_connected is False
        assert "Таймаут" in status.error_message

        logs = await provider.fetch_blocked_logs()
        assert logs == []


@pytest.mark.asyncio
async def test_nextdns_api_http_error():
    """Verify NextDNS provider handles HTTP 500 / 503 errors gracefully."""
    provider = NextDnsProvider(api_key="test_api_key", profile_id="test_profile")
    mock_resp = MagicMock()
    mock_resp.status_code = 503

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        logs = await provider.fetch_blocked_logs()
        assert logs == []
