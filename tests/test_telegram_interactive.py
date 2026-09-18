import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from keenguard.config import settings
from keenguard.core.notifier import TelegramNotifier, TelegramBotWorker
from keenguard.db.models import SecurityEvent


@pytest.mark.asyncio
async def test_telegram_send_alert_inline_buttons():
    """Test that send_alert creates actionable inline buttons for critical and warning events."""
    notifier = TelegramNotifier()

    # 1. UPnP event -> must contain delete UPnP button
    upnp_event = SecurityEvent(
        event_type="upnp_detected",
        severity="critical",
        target_mac="00:11:22:33:44:55",
        target_ip="192.168.1.50",
        description="Камера открыла порт TCP/554 через UPnP!"
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"status": "ok"}
        await notifier.send_alert(upnp_event)

        assert mock_send.called
        call_kwargs = mock_send.call_args[1]
        reply_markup = call_kwargs.get("reply_markup")
        assert reply_markup is not None
        assert "inline_keyboard" in reply_markup
        btn_data = [btn["callback_data"] for row in reply_markup["inline_keyboard"] for btn in row]
        assert any(d.startswith("del_upnp:") for d in btn_data)


@pytest.mark.asyncio
async def test_telegram_bot_unauthorized_callback_rejected():
    """Test that callbacks from unauthorized chat IDs or user IDs are rejected."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"):
        with patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer:
            query = {
                "id": "query_1",
                "from": {"id": "999999999"},  # Hacker / unauthorized user
                "message": {"chat": {"id": "999999999"}, "message_id": 42, "text": "Alert"},
                "data": "quarantine:00:11:22:33:44:55"
            }
            await worker._handle_callback(query)

            mock_answer.assert_called_once_with("query_1", text="Доступ запрещен!")


@pytest.mark.asyncio
async def test_telegram_bot_authorized_actions():
    """Test executing authorized action buttons (UPnP delete, Audit, Quarantine, Trust, Block DNS)."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"):
        with patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_answer, \
             patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
             patch("keenguard.core.keenetic.keenetic_client.add_dns_sinkhole", new_callable=AsyncMock) as mock_sinkhole, \
             patch("keenguard.core.keenetic.keenetic_client.delete_upnp_mapping", new_callable=AsyncMock) as mock_del_upnp, \
             patch("keenguard.core.profiles.profile_manager.quarantine_device", new_callable=AsyncMock) as mock_quar, \
             patch("keenguard.core.profiles.profile_manager.trust_device", new_callable=AsyncMock) as mock_trust:

            mock_sinkhole.return_value = True
            mock_del_upnp.return_value = True
            mock_quar.return_value = True
            mock_trust.return_value = True

            # 1. Block DNS callback
            cb_sink = {
                "id": "q_sink",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 101, "text": "Suspicious domain"},
                "data": "block_dns:evil-telemetry.com"
            }
            await worker._handle_callback(cb_sink)
            mock_sinkhole.assert_called_once_with("evil-telemetry.com")
            assert "заблокирован" in mock_answer.call_args[1]["text"]

            # 2. UPnP Delete callback
            cb_upnp = {
                "id": "q_upnp",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 102, "text": "UPnP warning"},
                "data": "del_upnp:tcp:554"
            }
            await worker._handle_callback(cb_upnp)
            mock_del_upnp.assert_called_once_with("tcp", 554)

            # 3. Quarantine callback
            cb_quar = {
                "id": "q_quar",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 103, "text": "New device warning"},
                "data": "quarantine:AA:BB:CC:DD:EE:FF"
            }
            await worker._handle_callback(cb_quar)
            mock_quar.assert_called_once_with("AA:BB:CC:DD:EE:FF", reason="Telegram Bot Callback")

            # 4. Trust callback
            cb_trust = {
                "id": "q_trust",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 104, "text": "New device warning"},
                "data": "trust:AA:BB:CC:DD:EE:FF"
            }
            await worker._handle_callback(cb_trust)
            mock_trust.assert_called_once_with("AA:BB:CC:DD:EE:FF")


@pytest.mark.asyncio
async def test_telegram_navigation_buttons_and_digest():
    """Test that /status and /devices messages send real inline buttons, and /digest triggers send_digest_to_telegram."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(settings, "telegram_enabled", True):

        # 1. /status command -> must send message with inline keyboard
        with patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
            msg_status = {"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "/status"}
            await worker._handle_message(msg_status)
            assert mock_send.called
            args, kwargs = mock_send.call_args
            reply_markup = kwargs.get("reply_markup")
            assert reply_markup is not None
            assert "inline_keyboard" in reply_markup
            btn_data = [btn["callback_data"] for row in reply_markup["inline_keyboard"] for btn in row]
            assert "cmd:status" in btn_data
            assert "cmd:devices" in btn_data
            assert "cmd:digest" in btn_data

        # 2. /digest command -> must invoke digest_generator.send_digest_to_telegram(force=True)
        with patch("keenguard.core.digest.digest_generator.send_digest_to_telegram", new_callable=AsyncMock) as mock_digest:
            mock_digest.return_value = {"status": "ok"}
            msg_digest = {"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "/digest"}
            await worker._handle_message(msg_digest)
            mock_digest.assert_called_once_with(force=True)

        # 3. callback cmd:digest -> must invoke answer_callback_query and send_digest_to_telegram
        with patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
             patch("keenguard.core.digest.digest_generator.send_digest_to_telegram", new_callable=AsyncMock) as mock_digest:
            cb_digest = {
                "id": "q_digest",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 104, "text": "Current status"},
                "data": "cmd:digest"
            }
            await worker._handle_callback(cb_digest)
            mock_ans.assert_called_once_with("q_digest", text="Формирую сводку безопасности...")
            mock_digest.assert_called_once_with(force=True)

        # 4. callback cmd:devices -> updates message with inline keyboard
        with patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
             patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit:
            cb_devs = {
                "id": "q_devs",
                "from": {"id": "123456789"},
                "message": {"chat": {"id": "123456789"}, "message_id": 105, "text": "Status text"},
                "data": "cmd:devices"
            }
            await worker._handle_callback(cb_devs)
            assert mock_ans.called
            assert mock_edit.called
            call_kwargs = mock_edit.call_args[1]
            assert "inline_keyboard" in call_kwargs.get("reply_markup", {})

