import asyncio
import logging
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

class TelegramNotifier:
    def __init__(self):
        self.http_timeout = 8.0

    async def send_message(self, text: str, token: Optional[str] = None,
                           chat_id: Optional[str] = None,
                           reply_markup: Optional[Dict[str, Any]] = None,
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
            "disable_web_page_preview": True
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
        except Exception as e:
            logger.error("Failed to deliver Telegram notification: %s", e)
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
        except Exception as e:
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
        except Exception as e:
            logger.debug("Failed to edit message text: %s", e)
            return False

    async def send_alert(self, event: SecurityEvent) -> bool:
        """Formats and sends a security alert with contextual action buttons to Telegram."""
        if not settings.telegram_enabled:
            return False

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

        reply_markup = {"inline_keyboard": keyboard} if keyboard else None
        text = "\n".join(lines)
        res = await self.send_message(text, reply_markup=reply_markup)
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
        except Exception as e:
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
            "/digest — отправка сводки безопасности"
        )
        return await self.send_message(text, token=token, chat_id=chat_id, api_url=api_url, proxy=proxy)


class TelegramBotWorker:
    """Background polling worker that listens for Telegram button clicks and commands."""
    def __init__(self, notifier_instance: TelegramNotifier):
        self.notifier = notifier_instance
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.last_update_id = 0

    async def start(self):
        if self.running or not settings.telegram_enabled or not settings.telegram_bot_token:
            return
        self.running = True
        try:
            await self.notifier.setup_bot_commands()
        except Exception as ex:
            logger.debug("setup_bot_commands error on start: %s", ex)
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("Telegram interactive bot worker started.")

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("Telegram interactive bot worker stopped.")

    async def _poll_loop(self):
        while self.running:
            try:
                updates = await self._fetch_updates()
                for u in updates:
                    await self._process_update(u)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Telegram polling loop error: %s", e)
                await asyncio.sleep(5)

    async def _fetch_updates(self) -> List[Dict[str, Any]]:
        t_token = settings.telegram_bot_token
        if not t_token:
            await asyncio.sleep(5)
            return []
        raw_url = (settings.telegram_api_url or "https://api.telegram.org").strip().rstrip("/")
        if not raw_url.startswith(("http://", "https://")):
            raw_url = f"https://{raw_url}"
        url = f"{raw_url}/bot{t_token}/getUpdates"
        params = {"offset": self.last_update_id + 1, "timeout": 15}
        try:
            async with httpx.AsyncClient(timeout=25.0) as client:
                res = await client.get(url, params=params)
                if res.status_code == 200:
                    data = res.json()
                    if data.get("ok"):
                        return data.get("result", [])
        except Exception as e:
            logger.debug("Telegram getUpdates error: %s", e)
        await asyncio.sleep(3)
        return []

    async def _process_update(self, update: Dict[str, Any]):
        uid = update.get("update_id", 0)
        if uid > self.last_update_id:
            self.last_update_id = uid

        if "callback_query" in update:
            await self._handle_callback(update["callback_query"])
        elif "message" in update:
            await self._handle_message(update["message"])

    async def _build_status_payload(self) -> Tuple[str, Dict[str, Any]]:
        from keenguard.core.keenetic import keenetic_client
        from keenguard.db.database import db

        devices = await db.get_all_devices()
        online_count = sum(1 for d in devices if d.is_online)
        total_count = len(devices)
        model = keenetic_client.last_model or "Keenetic"
        text = (
            f"🛡️ <b>KeenGuard Status</b>\n\n"
            f"<b>Роутер:</b> {model}\n"
            f"<b>Устройств онлайн:</b> {online_count} из {total_count}\n"
            f"<b>Сеть:</b> 192.168.1.1 (Bridge0)\n\n"
            f"<i>Выберите действие с помощью кнопок ниже:</i>"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Обновить статус", "callback_data": "cmd:status"},
                    {"text": f"📱 Устройства ({online_count})", "callback_data": "cmd:devices"}
                ],
                [
                    {"text": "🛡️ Сводка безопасности (Дайджест)", "callback_data": "cmd:digest"}
                ]
            ]
        }
        return text, keyboard

    async def _build_devices_payload(self) -> Tuple[str, Dict[str, Any]]:
        from keenguard.db.database import db

        devices = await db.get_all_devices()
        online_devs = [d for d in devices if d.is_online]
        lines = [f"📱 <b>Устройства онлайн ({len(online_devs)} из {len(devices)}):</b>", ""]
        for d in online_devs[:20]:
            name = d.custom_name or d.hostname or d.vendor or d.mac
            lines.append(f"• <b>{name}</b> ({d.ip or 'No IP'}) — <code>{d.profile}</code> [<code>{d.segment or 'Home'}</code>]")
        if not online_devs:
            lines.append("Нет активных устройств онлайн.")

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Обновить список", "callback_data": "cmd:devices"},
                    {"text": "📊 Статус сети", "callback_data": "cmd:status"}
                ],
                [
                    {"text": "🛡️ Сводка безопасности (Дайджест)", "callback_data": "cmd:digest"}
                ]
            ]
        }
        return "\n".join(lines), keyboard

    async def _handle_callback(self, query: Dict[str, Any]):
        qid = query.get("id", "")
        user_id = str(query.get("from", {}).get("id", ""))
        trusted_chat = str(settings.telegram_chat_id).strip()
        data = query.get("data", "")
        msg = query.get("message", {})
        chat_id = msg.get("chat", {}).get("id")
        mid = msg.get("message_id")
        orig_text = msg.get("text", "")

        # Strict security check: only accept from authorized chat_id
        if user_id != trusted_chat and str(chat_id) != trusted_chat:
            logger.warning("Unauthorized Telegram callback attempt from user_id: %s", user_id)
            await self.notifier.answer_callback_query(qid, text="Доступ запрещен!")
            return

        # 1. Navigation & Command Buttons
        if data == "cmd:status":
            await self.notifier.answer_callback_query(qid, text="Статус обновлен")
            text, keyboard = await self._build_status_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
            return
        elif data == "cmd:devices":
            await self.notifier.answer_callback_query(qid, text="Список устройств загружен")
            text, keyboard = await self._build_devices_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
            return
        elif data == "cmd:digest":
            await self.notifier.answer_callback_query(qid, text="Формирую сводку безопасности...")
            from keenguard.core.digest import digest_generator
            await digest_generator.send_digest_to_telegram(force=True)
            return

        # 2. Contextual Alert Action Buttons
        action_result = "✅ Действие выполнено"
        from keenguard.core.keenetic import keenetic_client
        from keenguard.core.profiles import profile_manager
        from keenguard.core.audit import audit_manager

        try:
            if data.startswith("del_upnp:"):
                parts = data.split(":")
                proto = parts[1]
                port = int(parts[2])
                await keenetic_client.delete_upnp_mapping(proto, port)
                action_result = f"🚫 Порт UPnP {proto.upper()}/{port} закрыт на роутере"
            elif data.startswith("audit:"):
                rest = data.split(":", 1)[1]
                mac, dur_str = rest.rsplit(":", 1)
                dur = int(dur_str)
                await audit_manager.start_audit(mac=mac, duration_seconds=dur)
                action_result = f"🔍 Аудит трафика {mac} запущен на {dur // 60} мин"
            elif data.startswith("quarantine:"):
                mac = data.split(":", 1)[1]
                await profile_manager.quarantine_device(mac, reason="Telegram Bot Callback")
                action_result = f"🔒 Устройство {mac} отправлено в карантин"
            elif data.startswith("trust:"):
                mac = data.split(":", 1)[1]
                await profile_manager.trust_device(mac)
                action_result = f"✅ Устройству {mac} назначен профиль 'Доверенное'"
            elif data.startswith("block_dns:"):
                domain = data.split(":", 1)[1]
                await keenetic_client.add_dns_sinkhole(domain)
                action_result = f"🚫 Домен {domain} заблокирован на Keenetic (0.0.0.0)"
        except Exception as ex:
            logger.error("Error executing Telegram action %s: %s", data, ex)
            action_result = f"❌ Ошибка выполнения: {ex}"

        await self.notifier.answer_callback_query(qid, text=action_result)
        if chat_id and mid and orig_text:
            new_text = orig_text + f"\n\n<b>{action_result}</b>"
            await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=new_text, reply_markup=None)

    async def _handle_message(self, message: Dict[str, Any]):
        user_id = str(message.get("from", {}).get("id", ""))
        chat_id = message.get("chat", {}).get("id")
        text = (message.get("text") or "").strip()
        trusted_chat = str(settings.telegram_chat_id).strip()

        if user_id != trusted_chat and str(chat_id) != trusted_chat:
            return

        clean_cmd = text.split("@")[0].lower().strip()

        try:
            if clean_cmd in ("/status", "/start", "status", "статус", "📊 статус", "📊 статус сети"):
                text_msg, keyboard = await self._build_status_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/devices", "devices", "устройства", "📱 устройства", "📱 устройства онлайн"):
                text_msg, keyboard = await self._build_devices_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/digest", "digest", "дайджест", "сводка", "🛡️ дайджест", "🛡️ дайджест безопасности", "🛡️ сводка безопасности"):
                from keenguard.core.digest import digest_generator
                await digest_generator.send_digest_to_telegram(force=True)
            else:
                text_msg, keyboard = await self._build_status_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
        except Exception as ex:
            logger.error("Error processing Telegram message '%s': %s", text, ex, exc_info=True)
            await self.notifier.send_message(f"❌ Ошибка обработки команды: {ex}")


notifier = TelegramNotifier()
telegram_bot_worker = TelegramBotWorker(notifier)

