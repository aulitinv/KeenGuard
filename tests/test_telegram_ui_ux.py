"""Unit tests for Telegram Bot UI/UX enhancements.

Covers:
- render_progress_bar helper function and edge cases
- get_main_reply_keyboard layout and persistence
- _build_status_payload with ASCII bars and metrics
- _build_devices_payload with category filtering and pagination
- Callback handlers for dev_cat and dev_page
- Smart search in _handle_message by IP, MAC, and keywords
- _wait_and_notify_audit_completion background notification and PCAP delivery
- SecurityDigestGenerator integration with progress bars
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

from keenguard.config import settings
from keenguard.core.notifier import (
    TelegramNotifier,
    TelegramBotWorker,
    render_progress_bar,
    get_main_reply_keyboard,
)
from keenguard.db.models import DeviceRecord, AuditReportRecord
from keenguard.core.digest import SecurityDigestGenerator


def test_render_progress_bar():
    """Test progress bar rendering for various ratios and edge cases."""
    # 0 total -> all empty
    assert render_progress_bar(0, 0) == "[░░░░░░░░░░]"
    assert render_progress_bar(5, 0) == "[░░░░░░░░░░]"

    # 50%
    assert render_progress_bar(5, 10) == "[█████░░░░░]"

    # 80%
    assert render_progress_bar(8, 10) == "[████████░░]"

    # 100%
    assert render_progress_bar(10, 10) == "[██████████]"

    # Overflow clamped to 100%
    assert render_progress_bar(15, 10) == "[██████████]"

    # Negative clamped to 0%
    assert render_progress_bar(-3, 10) == "[░░░░░░░░░░]"

    # Custom length
    assert render_progress_bar(1, 4, length=8) == "[██░░░░░░]"


def test_get_main_reply_keyboard():
    """Test main reply keyboard structure and persistence."""
    kb = get_main_reply_keyboard()
    assert kb.get("resize_keyboard") is True
    assert kb.get("is_persistent") is True
    keyboard_matrix = kb.get("keyboard", [])
    assert len(keyboard_matrix) == 2
    row0_texts = [btn["text"] for btn in keyboard_matrix[0]]
    row1_texts = [btn["text"] for btn in keyboard_matrix[1]]
    assert "📊 Статус сети" in row0_texts
    assert "📱 Устройства" in row0_texts
    assert "⚙️ Роутер" in row1_texts
    assert "🛡️ Дайджест" in row1_texts


@pytest.mark.asyncio
async def test_build_status_payload():
    """Test _build_status_payload output containing progress bars and router metrics."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    mock_devs = [
        DeviceRecord(mac="AA:11:22:33:44:55", ip="192.168.1.50", is_online=True, profile="smart_tv"),
        DeviceRecord(mac="BB:11:22:33:44:56", ip="192.168.1.55", is_online=False, profile="camera"),
    ]

    with patch("keenguard.db.database.db.get_all_devices", new_callable=AsyncMock) as mock_get_devs, \
         patch("keenguard.core.keenetic.keenetic_client.get_guest_wifi_status", new_callable=AsyncMock) as mock_guest, \
         patch("keenguard.core.keenetic.keenetic_client.last_model", "Keenetic Hero 4G"):

        mock_get_devs.return_value = mock_devs
        mock_guest.return_value = {"enabled": True, "interface": "GuestWiFi"}

        text, keyboard = await worker._build_status_payload()

        assert "KeenGuard Security Status" in text
        assert "Keenetic Hero 4G" in text
        assert "192.168.1.1 (Bridge0)" in text
        assert "Устройства онлайн:" in text
        assert "1</b> из <b>2" in text
        assert "Гостевой Wi-Fi:</b> ✅ Включена" in text
        assert "inline_keyboard" in keyboard


@pytest.mark.asyncio
async def test_build_devices_payload_categories_and_pagination():
    """Test device payload with category filtering, counts, and pagination."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    # 8 devices: 3 smart_tv, 2 camera, 2 iot, 1 other, 1 blocked
    mock_devs = [
        DeviceRecord(mac=f"AA:00:00:00:00:0{i}", ip=f"192.168.1.{10+i}", hostname=f"TV-{i}", is_online=True, profile="smart_tv")
        for i in range(3)
    ] + [
        DeviceRecord(mac=f"BB:00:00:00:00:0{i}", ip=f"192.168.1.{20+i}", hostname=f"Cam-{i}", is_online=True, profile="camera")
        for i in range(2)
    ] + [
        DeviceRecord(mac=f"CC:00:00:00:00:0{i}", ip=f"192.168.1.{30+i}", hostname=f"IoT-{i}", is_online=True, profile="iot_sensor")
        for i in range(2)
    ] + [
        DeviceRecord(mac="DD:00:00:00:00:99", ip="192.168.1.99", hostname="BlockedPC", is_online=True, profile="untrusted", is_blocked_wan=True)
    ]

    with patch("keenguard.db.database.db.get_all_devices", new_callable=AsyncMock) as mock_get_devs:
        mock_get_devs.return_value = mock_devs

        # 1. Category "all": 8 online items -> Page 0 (6 items), Page 1 (2 items)
        text_all, kb_all = await worker._build_devices_payload(category="all", page=0)
        assert "Страница 1 из 2" in text_all
        all_btns = [btn for row in kb_all["inline_keyboard"] for btn in row]
        cat_btn_texts = [b["text"] for b in all_btns if b["callback_data"].startswith("dev_cat:")]
        assert any("Все (8)" in t for t in cat_btn_texts)
        assert any("ТВ (3)" in t for t in cat_btn_texts)
        assert any("Камеры (2)" in t for t in cat_btn_texts)
        assert any("IoT (2)" in t for t in cat_btn_texts)
        assert any("Блок (1)" in t for t in cat_btn_texts)

        # Pagination row is present when total_pages > 1
        page_btn_texts = [b["text"] for b in all_btns]
        assert any("◀️ Пред." in t for t in page_btn_texts)
        assert any("След. ▶️" in t for t in page_btn_texts)

        # 2. Category "cameras": 2 items -> 1 page, pagination row should NOT be present
        text_cam, kb_cam = await worker._build_devices_payload(category="cameras", page=0)
        assert "Камеры" in text_cam
        assert "Страница 1 из 1" in text_cam
        cam_btns = [b for row in kb_cam["inline_keyboard"] for b in row]
        cam_page_texts = [b["text"] for b in cam_btns]
        assert not any("◀️ Пред." in t for t in cam_page_texts)
        assert not any("След. ▶️" in t for t in cam_page_texts)

        # 3. Category "blocked": 1 item
        text_blk, kb_blk = await worker._build_devices_payload(category="blocked", page=0)
        assert "BlockedPC" in text_blk


@pytest.mark.asyncio
async def test_callbacks_dev_cat_and_dev_page():
    """Test callback interactions for dev_cat and dev_page."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "answer_callback_query", new_callable=AsyncMock) as mock_ans, \
         patch.object(notifier, "edit_message_text", new_callable=AsyncMock) as mock_edit, \
         patch.object(worker, "_build_devices_payload", new_callable=AsyncMock) as mock_build:

        mock_build.return_value = ("Devices Text", {"inline_keyboard": []})

        # 1. dev_cat:media:0
        cb_cat = {
            "id": "q_cat",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 40, "text": "Old"},
            "data": "dev_cat:media:0"
        }
        await worker._handle_callback(cb_cat)
        mock_build.assert_called_with(category="media", page=0)
        assert mock_edit.called

        mock_build.reset_mock()
        mock_edit.reset_mock()

        # 2. dev_page:all:1
        cb_page = {
            "id": "q_page",
            "from": {"id": "123456789"},
            "message": {"chat": {"id": "123456789"}, "message_id": 41, "text": "Old"},
            "data": "dev_page:all:1"
        }
        await worker._handle_callback(cb_page)
        mock_build.assert_called_with(category="all", page=1)
        assert mock_edit.called


@pytest.mark.asyncio
async def test_handle_message_smart_search():
    """Test smart search in _handle_message for IP, MAC, and text keywords."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    tv_dev = DeviceRecord(
        mac="AA:BB:CC:11:22:33",
        ip="192.168.1.75",
        hostname="Living-Room-TV",
        custom_name="Smart OLED TV",
        vendor="LG Electronics",
        profile="smart_tv",
        is_online=True
    )
    phone_dev = DeviceRecord(
        mac="CC:DD:EE:44:55:66",
        ip="192.168.1.115",
        hostname="Phone-Alex",
        custom_name="Samsung S25",
        vendor="Samsung Electronics",
        profile="trusted",
        is_online=True
    )
    other_dev = DeviceRecord(
        mac="11:22:33:44:55:66",
        ip="192.168.1.125",
        hostname="Kitchen-TV",
        custom_name="Small Kitchen TV",
        vendor="Xiaomi",
        profile="smart_tv",
        is_online=True
    )

    with patch.object(settings, "telegram_chat_id", "123456789"), \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send, \
         patch("keenguard.db.database.db.get_all_devices", new_callable=AsyncMock) as mock_all, \
         patch("keenguard.db.database.db.get_device", new_callable=AsyncMock) as mock_get_dev:

        mock_all.return_value = [tv_dev, phone_dev, other_dev]
        mock_get_dev.side_effect = lambda mac: next((d for d in [tv_dev, phone_dev, other_dev] if d.mac == mac), None)

        # 1. /start sends welcome with persistent keyboard and status payload
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "/start"})
        assert mock_send.call_count >= 2
        first_call_kwargs = mock_send.call_args_list[0][1]
        assert first_call_kwargs["reply_markup"].get("is_persistent") is True

        mock_send.reset_mock()

        # 2. Search by IP: "192.168.1.75"
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "192.168.1.75"})
        assert mock_send.called
        sent_text = mock_send.call_args[0][0]
        assert "Smart OLED TV" in sent_text or "AA:BB:CC:11:22:33" in sent_text

        mock_send.reset_mock()

        # 3. Search by unknown IP
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "192.168.1.250"})
        sent_text = mock_send.call_args[0][0]
        assert "не найдено" in sent_text

        mock_send.reset_mock()

        # 4. Search by MAC: "CC:DD:EE:44:55:66"
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "CC:DD:EE:44:55:66"})
        assert mock_send.called
        sent_text = mock_send.call_args[0][0]
        assert "Samsung S25" in sent_text or "CC:DD:EE:44:55:66" in sent_text

        mock_send.reset_mock()

        # 5. Search by keyword with single match: "s25"
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "s25"})
        sent_text = mock_send.call_args[0][0]
        assert "Samsung S25" in sent_text

        mock_send.reset_mock()

        # 6. Search by keyword with multiple matches: "TV" (matches Smart OLED TV and Kitchen-TV)
        await worker._handle_message({"from": {"id": "123456789"}, "chat": {"id": "123456789"}, "text": "TV"})
        sent_text = mock_send.call_args[0][0]
        reply_markup = mock_send.call_args[1].get("reply_markup", {})
        assert "Найдено устройств: 2" in sent_text
        btn_callbacks = [b["callback_data"] for row in reply_markup.get("inline_keyboard", []) for b in row]
        assert "dev:AA:BB:CC:11:22:33" in btn_callbacks
        assert "dev:11:22:33:44:55:66" in btn_callbacks


@pytest.mark.asyncio
async def test_wait_and_notify_audit_completion(tmp_path):
    """Test automated background audit notification with summary card and PCAP upload."""
    notifier = TelegramNotifier()
    worker = TelegramBotWorker(notifier)

    pcap_file = tmp_path / "audit_test.pcap"
    pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00")

    mock_report = AuditReportRecord(
        id="audit_123",
        mac="AA:BB:CC:11:22:33",
        duration_seconds=60,
        total_packets=125,
        total_bytes=1048576,  # 1.0 MB
        risk_level="high",
        summary="Выявлена передача данных на неизвестные внешние серверы.",
        pcap_file=pcap_file.name
    )

    mock_dev = DeviceRecord(
        mac="AA:BB:CC:11:22:33",
        hostname="Smart-Camera",
        ip="192.168.1.95"
    )

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep, \
         patch.object(settings, "pcap_dir", tmp_path), \
         patch("keenguard.db.database.db.get_audit_reports", new_callable=AsyncMock) as mock_get_rep, \
         patch("keenguard.db.database.db.get_device", new_callable=AsyncMock) as mock_get_dev, \
         patch.object(notifier, "send_message", new_callable=AsyncMock) as mock_send, \
         patch.object(notifier, "send_document", new_callable=AsyncMock) as mock_send_doc:

        mock_get_rep.return_value = [mock_report]
        mock_get_dev.return_value = mock_dev
        mock_send.return_value = {"status": "ok"}
        mock_send_doc.return_value = {"status": "ok"}

        await worker._wait_and_notify_audit_completion(
            mac="AA:BB:CC:11:22:33",
            duration_seconds=60,
            chat_id="123456789"
        )

        mock_sleep.assert_called_once_with(62)
        assert mock_send.called
        card_text = mock_send.call_args[0][0]
        assert "Аудит трафика завершен" in card_text
        assert "Smart-Camera" in card_text
        assert "Высокий" in card_text
        assert "1.00 МБ" in card_text

        # PCAP delivery verified
        assert mock_send_doc.called
        doc_path = mock_send_doc.call_args[0][0]
        assert doc_path == pcap_file
        caption = mock_send_doc.call_args[1].get("caption", "")
        assert "Дамп трафика аудита" in caption


@pytest.mark.asyncio
async def test_digest_generator_progress_bars():
    """Test that SecurityDigestGenerator uses render_progress_bar in output."""
    generator = SecurityDigestGenerator()

    fake_stats = {
        "total_devices": 10,
        "online_devices": 8,
        "event_counts": [{"severity": "warning", "cnt": 2}],
        "top_incidents": [],
        "audit_count": 1,
        "high_risk_audits": 0,
        "has_hubs_or_vacuums": False
    }

    with patch("keenguard.db.database.db.get_digest_stats", new_callable=AsyncMock) as mock_stats:
        mock_stats.return_value = fake_stats

        digest = await generator.generate_digest(hours=24)

        assert digest["score"] == 90  # 100 - (2 * 5) = 90
        assert "█" in digest["telegram_text"]
        assert "░" in digest["telegram_text"]
        assert "Индекс безопасности:" in digest["telegram_text"]
        assert "Устройства онлайн:" in digest["telegram_text"]
