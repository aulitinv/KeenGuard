import asyncio
from datetime import datetime
import json
import logging
from pathlib import Path
import re
from typing import Optional, Dict, Any, List, Union, Tuple
import httpx

from keenguard.config import settings
from keenguard.db.models import SecurityEvent

logger = logging.getLogger("keenguard.notifier")

SEVERITY_ICONS = {
    "critical": "🚨",
    "warning": "⚠️",
    "info": "ℹ️"
}

SEVERITY_TITLES = {
    "critical": "КРИТИЧЕСКИЙ ИНЦИДЕНТ",
    "warning": "ПРЕДУПРЕЖДЕНИЕ",
    "info": "УВЕДОМЛЕНИЕ"
}


def render_progress_bar(current: int, total: int, length: int = 10) -> str:
    """Renders a clean Unicode progress bar like [████████░░]."""
    if total <= 0:
        filled = 0
    else:
        ratio = max(0.0, min(1.0, current / total))
        filled = int(round(ratio * length))
    return f"[{'█' * filled}{'░' * (length - filled)}]"


def get_main_reply_keyboard() -> Dict[str, Any]:
    """Returns the persistent main navigation keyboard."""
    return {
        "keyboard": [
            [{"text": "📊 Статус сети"}, {"text": "📱 Устройства"}],
            [{"text": "⚙️ Роутер"}, {"text": "🛡️ Дайджест"}]
        ],
        "resize_keyboard": True,
        "is_persistent": True
    }


class TelegramNotifier:
    def __init__(self):
        self.http_timeout = 8.0

    async def send_message(self, text: str, token: Optional[str] = None,
                           chat_id: Optional[str] = None,
                           reply_markup: Optional[Dict[str, Any]] = None,
                           disable_notification: bool = False,
                           api_url: Optional[str] = None,
                           proxy: Optional[str] = None) -> Dict[str, Any]:
        """Sends a text message with HTML formatting and optional inline keyboard to Telegram chat."""
        t_token = token or settings.telegram_bot_token
        t_chat = chat_id or settings.telegram_chat_id
        raw_url = (api_url or settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        t_proxy = proxy if proxy is not None else settings.telegram_proxy

        if not t_token or not t_chat:
            return {"status": "error", "message": "Telegram Bot Token или Chat ID не настроены"}

        url = f"{raw_url}/bot{t_token}/sendMessage"
        payload: Dict[str, Any] = {
            "chat_id": t_chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "disable_notification": disable_notification
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup

        try:
            client_kwargs = {"timeout": self.http_timeout}
            if t_proxy and t_proxy.strip():
                client_kwargs["proxy"] = t_proxy.strip()
            async with httpx.AsyncClient(**client_kwargs) as client:
                res = await client.post(url, json=payload)
                data = res.json()
                if res.status_code == 200 and data.get("ok"):
                    logger.info("Telegram message successfully delivered to %s", t_chat)
                    return {"status": "ok", "message": "Сообщение успешно отправлено", "result": data.get("result")}
                else:
                    err = data.get("description", f"HTTP {res.status_code}")
                    logger.warning("Telegram API error: %s", err)
                    return {"status": "error", "message": f"Ошибка Telegram: {err}"}
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.error("Failed to deliver Telegram notification: %s", e)
            return {"status": "error", "message": f"Сетевая ошибка отправки: {str(e)}"}

    async def send_document(self, file_path: Union[str, Path],
                            caption: Optional[str] = None,
                            token: Optional[str] = None,
                            chat_id: Optional[str] = None,
                            disable_notification: bool = False,
                            api_url: Optional[str] = None,
                            proxy: Optional[str] = None) -> Dict[str, Any]:
        """Sends a document (e.g. .pcap, log, report) to Telegram chat via multipart/form-data."""
        t_token = token or settings.telegram_bot_token
        t_chat = chat_id or settings.telegram_chat_id
        raw_url = (api_url or settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        t_proxy = proxy if proxy is not None else settings.telegram_proxy

        if not t_token or not t_chat:
            return {"status": "error", "message": "Telegram Bot Token или Chat ID не настроены"}

        path_obj = Path(file_path)
        if not path_obj.exists() or not path_obj.is_file():
            return {"status": "error", "message": f"Файл не найден: {path_obj.name}"}

        url = f"{raw_url}/bot{t_token}/sendDocument"
        data: Dict[str, Any] = {
            "chat_id": t_chat,
            "disable_notification": disable_notification
        }
        if caption:
            data["caption"] = caption
            data["parse_mode"] = "HTML"

        try:
            client_kwargs = {"timeout": 30.0}
            if t_proxy and t_proxy.strip():
                client_kwargs["proxy"] = t_proxy.strip()
            async with httpx.AsyncClient(**client_kwargs) as client:
                with open(path_obj, "rb") as f:
                    file_content = f.read()
                files = {"document": (path_obj.name, file_content, "application/octet-stream")}
                res = await client.post(url, data=data, files=files)
                res_data = res.json()
                if res.status_code == 200 and res_data.get("ok"):
                    logger.info("Telegram document %s successfully delivered to %s", path_obj.name, t_chat)
                    return {"status": "ok", "message": "Документ успешно отправлен", "result": res_data.get("result")}
                else:
                    err = res_data.get("description", f"HTTP {res.status_code}")
                    logger.warning("Telegram API sendDocument error: %s", err)
                    return {"status": "error", "message": f"Ошибка Telegram: {err}"}
        except (httpx.HTTPError, OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.error("Failed to deliver Telegram document: %s", e)
            return {"status": "error", "message": f"Сетевая ошибка отправки: {str(e)}"}

    async def answer_callback_query(self, callback_query_id: str, text: str = "Выполнено",
                                    token: Optional[str] = None, api_url: Optional[str] = None) -> bool:
        """Acknowledges a callback query from an inline keyboard button."""
        t_token = token or settings.telegram_bot_token
        if not t_token:
            return False
        raw_url = (api_url or settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        url = f"{raw_url}/bot{t_token}/answerCallbackQuery"
        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                res = await client.post(url, json={"callback_query_id": callback_query_id, "text": text})
                return res.status_code == 200
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.debug("Failed to answer callback query: %s", e)
            return False

    async def edit_message_text(self, chat_id: Union[int, str], message_id: int, text: str,
                                reply_markup: Optional[Dict[str, Any]] = None,
                                token: Optional[str] = None, api_url: Optional[str] = None) -> bool:
        """Updates text of an existing message in Telegram."""
        t_token = token or settings.telegram_bot_token
        if not t_token:
            return False
        raw_url = (api_url or settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        url = f"{raw_url}/bot{t_token}/editMessageText"
        payload: Dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        try:
            async with httpx.AsyncClient(timeout=self.http_timeout) as client:
                res = await client.post(url, json=payload)
                return res.status_code == 200
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.debug("Failed to edit message text: %s", e)
            return False

    async def send_alert(self, event: SecurityEvent) -> bool:
        """Formats and sends a security alert with contextual action buttons to Telegram."""
        if not settings.telegram_enabled:
            return False

        # Check minimum severity threshold
        severity_weights = {"info": 1, "warning": 2, "critical": 3}
        min_sev = (settings.telegram_min_severity or "info").lower()
        event_weight = severity_weights.get((event.severity or "info").lower(), 1)
        min_weight = severity_weights.get(min_sev, 1)
        if event_weight < min_weight:
            logger.debug("Skipping Telegram alert: event severity '%s' below threshold '%s'", event.severity, min_sev)
            return False

        # Check quiet hours (silent notifications)
        disable_notif = False
        if settings.telegram_quiet_hours_enabled and (event.severity or "info").lower() != "critical":
            cur_hour = datetime.now().hour
            start_h = int(settings.telegram_quiet_hours_start)
            end_h = int(settings.telegram_quiet_hours_end)
            if start_h <= end_h:
                in_quiet = start_h <= cur_hour < end_h
            else:
                in_quiet = cur_hour >= start_h or cur_hour < end_h
            if in_quiet:
                disable_notif = True
                logger.debug("Quiet hours active (%02d:00-%02d:00); sending alert silently", start_h, end_h)

        icon = SEVERITY_ICONS.get(event.severity, "🔔")
        title = SEVERITY_TITLES.get(event.severity, "СОБЫТИЕ")

        lines = [
            f"{icon} <b>KeenGuard: {title}</b>",
            "",
            f"<b>Событие:</b> <code>{event.event_type}</code>",
            f"<b>Описание:</b> {event.description}",
        ]

        if event.target_ip or event.target_mac:
            target_str = f"{event.target_ip or ''} ({event.target_mac or ''})".strip()
            lines.append(f"<b>Устройство:</b> <code>{target_str}</code>")

        if event.source_ip or event.source_mac:
            source_str = f"{event.source_name or event.source_ip or ''} ({event.source_mac or ''})".strip()
            lines.append(f"<b>Источник:</b> <code>{source_str}</code>")

        lines.append(f"<b>Время:</b> <i>{event.timestamp[:19].replace('T', ' ')} UTC</i>")

        # Generate contextual inline keyboard buttons
        keyboard = []
        if event.event_type == "upnp_detected":
            ext_port = None
            proto = "tcp"
            if event.details:
                ext_port = event.details.get("ext_port")
                proto = str(event.details.get("protocol", "tcp")).lower()
            if not ext_port and event.description:
                m = re.search(r'(tcp|udp)/(\d+)', event.description, re.IGNORECASE)
                if m:
                    proto = m.group(1).lower()
                    ext_port = int(m.group(2))
                else:
                    m2 = re.search(r'порт\s+(\d+)', event.description, re.IGNORECASE)
                    if m2:
                        ext_port = int(m2.group(1))
            if ext_port:
                keyboard.append([{"text": f"🚫 Закрыть порт {proto.upper()}/{ext_port}", "callback_data": f"del_upnp:{proto}:{ext_port}"}])
        elif event.event_type == "camera_leak" and event.target_mac:
            keyboard.append([{"text": "🔍 Запустить аудит (5 мин)", "callback_data": f"audit:{event.target_mac}:300"}])
        elif event.event_type == "new_device" and event.target_mac:
            keyboard.append([
                {"text": "🔒 В карантин (WAN)", "callback_data": f"quarantine:{event.target_mac}"},
                {"text": "✅ Свое устройство", "callback_data": f"trust:{event.target_mac}"}
            ])
        elif event.event_type in ("rogue_dns", "ad_threat") and event.details and event.details.get("domain"):
            dom = event.details["domain"]
            keyboard.append([{"text": f"🚫 Заблокировать {dom[:20]}", "callback_data": f"block_dns:{dom}"}])
        elif event.event_type in ("dns_sinkhole", "sinkhole_blocked", "dns_blocked") and event.details and event.details.get("domain"):
            dom = event.details["domain"]
            keyboard.append([{"text": f"✅ Разблокировать {dom[:20]}", "callback_data": f"unblock_dns:{dom}"}])

        pcap_file = getattr(event, "pcap_file", None) or (event.details.get("pcap_file") if event.details else None)
        if pcap_file:
            keyboard.append([{"text": "📦 Скачать PCAP файл", "callback_data": f"send_pcap_file:{pcap_file}"}])

        reply_markup = {"inline_keyboard": keyboard} if keyboard else None
        text = "\n".join(lines)
        res = await self.send_message(text, reply_markup=reply_markup, disable_notification=disable_notif)
        return res.get("status") == "ok"

    async def setup_bot_commands(self) -> bool:
        """Registers bot command list and configures the native [Menu] button in Telegram."""
        t_token = settings.telegram_bot_token
        if not t_token or not settings.telegram_enabled:
            return False
        raw_url = (settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        t_proxy = settings.telegram_proxy

        commands = [
            {"command": "status", "description": "📊 Статус роутера и сети"},
            {"command": "devices", "description": "📱 Список устройств онлайн"},
            {"command": "router", "description": "⚙️ Управление роутером"},
            {"command": "digest", "description": "🛡️ Сводка безопасности"},
        ]
        try:
            client_kwargs = {"timeout": self.http_timeout}
            if t_proxy and t_proxy.strip():
                client_kwargs["proxy"] = t_proxy.strip()
            async with httpx.AsyncClient(**client_kwargs) as client:
                await client.post(f"{raw_url}/bot{t_token}/setMyCommands", json={"commands": commands})
                await client.post(f"{raw_url}/bot{t_token}/setChatMenuButton", json={"menu_button": {"type": "commands"}})
                logger.info("Telegram [Menu] button and commands successfully registered.")
                return True
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            logger.debug("Failed to set Telegram bot commands: %s", e)
            return False

    async def send_test_message(self, token: str, chat_id: str,
                                api_url: Optional[str] = None,
                                proxy: Optional[str] = None) -> Dict[str, Any]:
        """Validates credentials by sending a test ping message."""
        text = (
            "🛡️ <b>KeenGuard Security Bot</b>\n\n"
            "✅ Связь с системой мониторинга Keenetic успешно установлена!\n"
            "Вы будете получать оперативные оповещения о подозрительной активности, "
            "новых устройствах и обрывах связи с роутером.\n\n"
            "Доступные команды:\n"
            "/status — статус роутера и сети\n"
            "/devices — список устройств онлайн\n"
            "/router — управление роутером\n"
            "/digest — отправка сводки безопасности"
        )
        return await self.send_message(text, token=token, chat_id=chat_id, api_url=api_url, proxy=proxy)
from keenguard.core.telegram_bot import TelegramBotWorker

notifier = TelegramNotifier()
telegram_notifier = notifier
telegram_bot_worker = TelegramBotWorker(notifier)

__all__ = [
    "SEVERITY_ICONS",
    "SEVERITY_TITLES",
    "render_progress_bar",
    "get_main_reply_keyboard",
    "TelegramNotifier",
    "TelegramBotWorker",
    "notifier",
    "telegram_notifier",
    "telegram_bot_worker",
]


