"""Unit tests for Telegram Bot enhancements: interactive device cards, router controls, PCAP documents, quiet hours, and DNS management."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from keenguard.config import settings
from keenguard.core.notifier import TelegramNotifier, TelegramBotWorker
from keenguard.db.models import SecurityEvent, DeviceRecord


@pytest.mark.asyncio
async def test_telegram_send_document(tmp_path):
    """Test send_document method with real file and mock httpx."""
    notifier = TelegramNotifier()
    test_file = tmp_path / "test_capture.pcap"
    test_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00")

    with patch.object(settings, "telegram_bot_token", "fake_token"), \
         patch.object(settings, "telegram_chat_id", "123456789"), \
         patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True, "result": {"message_id": 99}}
        mock_post.return_value = mock_resp

        res = await notifier.send_document(
            file_path=test_file,
            caption="<b>Test capture</b>",
            disable_notification=True
        )

        assert res["status"] == "ok"
        assert mock_post.called
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs["data"]["chat_id"] == "123456789"
        assert call_kwargs["data"]["caption"] == "<b>Test capture</b>"
        assert call_kwargs["data"]["disable_notification"] is True
        assert "document" in call_kwargs["files"]
        doc_tuple = call_kwargs["files"]["document"]
        assert doc_tuple[0] == "test_capture.pcap"
        assert doc_tuple[1] == b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"

    # Test file not found error
    missing_file = tmp_path / "nonexistent.pcap"
    res_err = await notifier.send_document(file_path=missing_file)
    assert res_err["status"] == "error"
    assert "Файл не найден" in res_err["message"]


@pytest.mark.asyncio
async def test_telegram_min_severity_filter():
    """Test that events below telegram_min_severity are skipped."""
    notifier = TelegramNotifier()

    info_event = SecurityEvent(
        event_type="test_info",
        severity="info",
        description="Normal background event"
    )
    warn_event = SecurityEvent(
        event_type="test_warning",
        severity="warning",
        description="Suspicious port scan"
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(settings, "telegram_min_severity", "warning"), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        
        # Info event should be skipped
        sent_info = await notifier.send_alert(info_event)
        assert sent_info is False
        assert not mock_send.called

        # Warning event should be delivered
        mock_send.return_value = {"status": "ok"}
        sent_warn = await notifier.send_alert(warn_event)
        assert sent_warn is True
        assert mock_send.called


@pytest.mark.asyncio
async def test_telegram_quiet_hours():
    """Test that non-critical alerts are sent silently during quiet hours."""
    notifier = TelegramNotifier()

    warn_event = SecurityEvent(
        event_type="test_warning",
        severity="warning",
        description="Non-critical nighttime alert"
    )
    crit_event = SecurityEvent(
        event_type="test_critical",
        severity="critical",
        description="Critical intrusion alert!"
    )

    fake_now = MagicMock()
    fake_now.hour = 2  # 02:00 AM (inside quiet hours 23:00 - 08:00)

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(settings, "telegram_quiet_hours_enabled", True), \
         patch.object(settings, "telegram_quiet_hours_start", 23), \
         patch.object(settings, "telegram_quiet_hours_end", 8), \
         patch("keenguard.core.notifier.datetime") as mock_dt, \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        
        mock_dt.now.return_value = fake_now
        mock_send.return_value = {"status": "ok"}

        # Warning should have disable_notification=True
        await notifier.send_alert(warn_event)
        assert mock_send.call_args[1]["disable_notification"] is True

        mock_send.reset_mock()

        # Critical should have disable_notification=False (loud alert)
        await notifier.send_alert(crit_event)
        assert mock_send.call_args[1]["disable_notification"] is False


@pytest.mark.asyncio
async def test_telegram_alert_pcap_and_unblock_buttons():
    """Test that alerts include unblock DNS button and pcap download button when applicable."""
    notifier = TelegramNotifier()

    dns_event = SecurityEvent(
        event_type="dns_sinkhole",
        severity="warning",
        description="Blocked sinkhole request",
        details={"domain": "tracking.example.com", "pcap_file": "audit_123.pcap"}
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = {"status": "ok"}
        await notifier.send_alert(dns_event)

        assert mock_send.called
        reply_markup = mock_send.call_args[1]["reply_markup"]
        btn_data = [btn["callback_data"] for row in reply_markup["inline_keyboard"] for btn in row]
        assert "unblock_dns:tracking.example.com" in btn_data
        assert "send_pcap_file:audit_123.pcap" in btn_data


@pytest.mark.asyncio
async def test_telegram_router_controls():
    """Test /router command, guest Wi-Fi toggle, and safe reboot two-stage confirmation."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.core.keenetic.keenetic_client.get_guest_wifi_status", new_callable=AsyncMock) as mock_gw_status, \
         patch("keenguard.core.keenetic.keenetic_client.toggle_guest_wifi", new_callable=AsyncMock) as mock_gw_toggle, \
         patch("keenguard.core.keenetic.keenetic_client.reboot_router", new_callable=AsyncMock) as mock_reboot:

        mock_gw_status.return_value = {"enabled": True, "interface": "GuestWiFi"}
        mock_gw_toggle.return_value = True
        mock_reboot.return_value = True

        # 1. Message: /router
        msg_router = {"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "/router"}
        await worker._handle_message(msg_router)
        assert mock_send.called
        text_sent, kwargs = mock_send.call_args
        assert "Управление роутером" in text_sent[0]
        btn_data = [btn["callback_data"] for row in kwargs["reply_markup"]["inline_keyboard"] for btn in row]
        assert "router:guest_toggle:0" in btn_data
        assert "router:reboot_prompt" in btn_data

        # 2. Callback: toggle guest Wi-Fi to off
        cb_toggle = {
            "id": "q_gw",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 10, "text": "Router"},
            "data": "router:guest_toggle:0"
        }
        await worker._handle_callback(cb_toggle)
        mock_gw_toggle.assert_called_once_with(False)
        assert mock_edit.called

        # 3. Callback: reboot prompt (stage 1 - warning)
        cb_prompt = {
            "id": "q_reb_p",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 11, "text": "Router"},
            "data": "router:reboot_prompt"
        }
        await worker._handle_callback(cb_prompt)
        prompt_text = mock_edit.call_args[1]["text"]
        assert "ВНИМАНИЕ: Перезагрузка роутера" in prompt_text
        prompt_btns = [btn["callback_data"] for row in mock_edit.call_args[1]["reply_markup"]["inline_keyboard"] for btn in row]
        assert "router:reboot_confirm" in prompt_btns

        # 4. Callback: reboot confirm (stage 2 - execute)
        cb_confirm = {
            "id": "q_reb_c",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 12, "text": "Warning"},
            "data": "router:reboot_confirm"
        }
        await worker._handle_callback(cb_confirm)
        mock_reboot.assert_called_once()
        confirm_text = mock_edit.call_args[1]["text"]
        assert "Команда на перезагрузку отправлена" in confirm_text


@pytest.mark.asyncio
async def test_telegram_interactive_device_cards():
    """Test device list buttons, device detail card, WAN toggling, and profile menu."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    mock_dev = DeviceRecord(
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.55",
        hostname="Living-Room-TV",
        vendor="LG Electronics",
        profile="smart_tv",
        is_blocked_wan=False,
        is_isolated_lan=False,
        is_online=True
    )

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.db.database.db.get_all_devices", new_callable=AsyncMock) as mock_get_all, \
         patch("keenguard.db.database.db.get_device", new_callable=AsyncMock) as mock_get_dev, \
         patch("keenguard.core.profiles.profile_manager.toggle_wan", new_callable=AsyncMock) as mock_toggle_wan, \
         patch("keenguard.core.profiles.profile_manager.apply_policy", new_callable=AsyncMock) as mock_apply_pol:

        mock_get_all.return_value = [mock_dev]
        mock_get_dev.return_value = mock_dev
        mock_toggle_wan.return_value = True
        mock_apply_pol.return_value = mock_dev

        # 1. /devices lists clickable device buttons
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "/devices"})
        assert mock_send.called
        btns = [btn["callback_data"] for row in mock_send.call_args[1]["reply_markup"]["inline_keyboard"] for btn in row]
        assert "dev:AA:BB:CC:11:22:33" in btns

        # 2. dev:AA:BB:CC:11:22:33 displays detail card
        cb_dev = {
            "id": "q_dev",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 20, "text": "Devices"},
            "data": "dev:AA:BB:CC:11:22:33"
        }
        await worker._handle_callback(cb_dev)
        assert mock_edit.called
        card_text = mock_edit.call_args[1]["text"]
        assert "Living-Room-TV" in card_text
        card_btns = [btn["callback_data"] for row in mock_edit.call_args[1]["reply_markup"]["inline_keyboard"] for btn in row]
        assert "wan_toggle:AA:BB:CC:11:22:33:block" in card_btns
        assert "prof_menu:AA:BB:CC:11:22:33" in card_btns
        assert "send_pcap:AA:BB:CC:11:22:33" in card_btns

        # 3. wan_toggle:AA:BB:CC:11:22:33:block
        cb_wan = {
            "id": "q_wan",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 21, "text": "Card"},
            "data": "wan_toggle:AA:BB:CC:11:22:33:block"
        }
        await worker._handle_callback(cb_wan)
        mock_toggle_wan.assert_called_once_with("AA:BB:CC:11:22:33", block=True)

        # 4. prof_menu:AA:BB:CC:11:22:33
        cb_menu = {
            "id": "q_prof",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 22, "text": "Card"},
            "data": "prof_menu:AA:BB:CC:11:22:33"
        }
        await worker._handle_callback(cb_menu)
        prof_btns = [btn["callback_data"] for row in mock_edit.call_args[1]["reply_markup"]["inline_keyboard"] for btn in row]
        assert "set_prof:AA:BB:CC:11:22:33:smart_tv" in prof_btns
        assert "set_prof:AA:BB:CC:11:22:33:quarantine" in prof_btns

        # 5. set_prof:AA:BB:CC:11:22:33:quarantine
        cb_set_prof = {
            "id": "q_set",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 23, "text": "Profile menu"},
            "data": "set_prof:AA:BB:CC:11:22:33:quarantine"
        }
        await worker._handle_callback(cb_set_prof)
        mock_apply_pol.assert_called_once_with("AA:BB:CC:11:22:33", policy_id="quarantine")


@pytest.mark.asyncio
async def test_telegram_dns_unblock_and_text_prompt():
    """Test DNS unblock callback and raw domain text message prompt."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(settings, "telegram_enabled", True), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch("keenguard.core.keenetic.keenetic_client.remove_dns_sinkhole", new_callable=AsyncMock) as mock_rm_sink:

        mock_rm_sink.return_value = True

        # 1. Callback unblock_dns:ad.tracker.com
        cb_unblock = {
            "id": "q_unb",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 30, "text": "Blocked alert"},
            "data": "unblock_dns:ad.tracker.com"
        }
        await worker._handle_callback(cb_unblock)
        mock_rm_sink.assert_called_once_with("ad.tracker.com")
        assert "разблокирован" in mock_ans.call_args[1]["text"]

        # 2. Text message: analytics.google.com -> offers block/unblock buttons
        msg_domain = {
            "from": {"id": "123456789"},
            "chat": {"id": "123456789"},
            "text": "analytics.google.com"
        }
        await worker._handle_message(msg_domain)
        assert mock_send.called
        text_sent, kwargs = mock_send.call_args
        assert "Управление DNS для домена" in text_sent[0]
        btns = [btn["callback_data"] for row in kwargs["reply_markup"]["inline_keyboard"] for btn in row]
        assert "block_dns:analytics.google.com" in btns
        assert "unblock_dns:analytics.google.com" in btns
        assert "dismiss" in btns
