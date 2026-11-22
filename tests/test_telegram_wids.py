"""Unit tests for WIDS Telegram alert integration and interactive callback handling."""
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

from keenguard.config import settings
from keenguard.core.notifier import TelegramNotifier, TelegramBotWorker
from keenguard.core.wids import wids_service
from keenguard.db.models import SecurityEvent


@pytest.mark.asyncio
async def test_wids_deauth_flood_alert_keyboard():
    """Verify that wifi_deauth_flood event generates PMF and Silence inline buttons."""
    notifier = TelegramNotifier()
    event = SecurityEvent(
        event_type="wifi_deauth_flood",
        severity="critical",
        target_mac="NETWORK",
        description="Обнаружен Deauth-флуд: атака на беспроводной эфир",
        details={"event_count": 8, "affected_macs": ["AA:BB:CC:DD:EE:01"]}
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"status": "ok"}
        await notifier.send_alert(event)

        assert mock_send.called
        call_kwargs = mock_send.call_args[1]
        reply_markup = call_kwargs.get("reply_markup")
        assert reply_markup is not None
        assert "inline_keyboard" in reply_markup

        btn_data = [btn["callback_data"] for row in reply_markup["inline_keyboard"] for btn in row]
        assert "wids:enable_pmf" in btn_data
        assert "wids:silence_deauth:3600" in btn_data


@pytest.mark.asyncio
async def test_wids_evil_twin_alert_keyboard():
    """Verify that wifi_evil_twin event generates WPA3 and Rescan inline buttons."""
    notifier = TelegramNotifier()
    event = SecurityEvent(
        event_type="wifi_evil_twin",
        severity="critical",
        target_mac="NETWORK",
        source_mac="00:11:22:33:44:55",
        description="Обнаружен клон сети (Evil Twin): Keenetic-Home",
        details={"ssid": "Keenetic-Home", "bssid": "00:11:22:33:44:55"}
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"status": "ok"}
        await notifier.send_alert(event)

        assert mock_send.called
        call_kwargs = mock_send.call_args[1]
        reply_markup = call_kwargs.get("reply_markup")
        assert reply_markup is not None
        assert "inline_keyboard" in reply_markup

        btn_data = [btn["callback_data"] for row in reply_markup["inline_keyboard"] for btn in row]
        assert "wids:enable_wpa3" in btn_data
        assert "wids:rescan" in btn_data


@pytest.mark.asyncio
async def test_wids_callback_enable_pmf():
    """Verify that clicking 'wids:enable_pmf' invokes backend.set_wifi_pmf('required')."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.core.routers.manager.router_manager.get_backend") as mock_get_backend:

        mock_backend = MagicMock()
        mock_backend.set_wifi_pmf = AsyncMock(return_value=True)
        mock_get_backend.return_value = mock_backend

        cb = {
            "id": "q_pmf",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 501, "text": "Deauth Flood Alert"},
            "data": "wids:enable_pmf"
        }
        await worker._handle_callback(cb)

        mock_backend.set_wifi_pmf.assert_called_once_with("required")
        assert mock_answer.called
        ans_text = mock_answer.call_args[1]["text"]
        assert "PMF (802.11w)" in ans_text
        assert "Обязательно" in ans_text


@pytest.mark.asyncio
async def test_wids_callback_silence_deauth():
    """Verify that clicking 'wids:silence_deauth:3600' silences deauth alerts."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    # Reset any previous silence
    wids_service.deauth_silenced_until = None
    assert wids_service.is_deauth_silenced() is False

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit:

        cb = {
            "id": "q_silence",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 502, "text": "Deauth Flood Alert"},
            "data": "wids:silence_deauth:3600"
        }
        await worker._handle_callback(cb)

        assert wids_service.is_deauth_silenced() is True
        assert mock_answer.called
        ans_text = mock_answer.call_args[1]["text"]
        assert "заглушены на 1 ч" in ans_text


@pytest.mark.asyncio
async def test_wids_callback_enable_wpa3():
    """Verify that clicking 'wids:enable_wpa3' invokes backend.set_wifi_wpa3(True)."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.core.routers.manager.router_manager.get_backend") as mock_get_backend:

        mock_backend = MagicMock()
        mock_backend.set_wifi_wpa3 = AsyncMock(return_value=True)
        mock_get_backend.return_value = mock_backend

        cb = {
            "id": "q_wpa3",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 503, "text": "Evil Twin Alert"},
            "data": "wids:enable_wpa3"
        }
        await worker._handle_callback(cb)

        mock_backend.set_wifi_wpa3.assert_called_once_with(True)
        assert mock_answer.called
        ans_text = mock_answer.call_args[1]["text"]
        assert "WPA3-SAE" in ans_text


@pytest.mark.asyncio
async def test_wids_callback_rescan():
    """Verify that clicking 'wids:rescan' runs WIDS audit and reports findings."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.core.routers.manager.router_manager.get_backend") as mock_get_backend:

        mock_backend = MagicMock()
        mock_backend.get_wifi_security = AsyncMock(return_value={
            "networks": [{"ssid": "MyNet", "security": "WPA3", "pmf": "required"}]
        })
        mock_backend.get_system_log = AsyncMock(return_value=[])
        mock_backend.get_wlan_scan = AsyncMock(return_value=[])
        mock_get_backend.return_value = mock_backend

        cb = {
            "id": "q_rescan",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 504, "text": "Evil Twin Alert"},
            "data": "wids:rescan"
        }
        await worker._handle_callback(cb)

        assert mock_answer.called
        ans_text = mock_answer.call_args[1]["text"]
        assert "Сканирование эфира завершено" in ans_text
        assert "100/100" in ans_text
