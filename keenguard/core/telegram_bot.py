"""Stateful Telegram bot polling worker, interactive menus, callbacks, and inline builders."""
import asyncio
from datetime import datetime
import html
import json
import logging
from pathlib import Path
import re
from typing import Optional, Dict, Any, List, Tuple, Union
import aiosqlite
import httpx

from keenguard.config import settings
from keenguard.core.domain_analyzer import is_ip_address_string, is_forbidden_or_local_domain

logger = logging.getLogger("keenguard.telegram_bot")


class TelegramBotWorker:
    """Background polling worker that listens for Telegram button clicks and commands."""
    def __init__(self, notifier_instance: Any):
        self.notifier = notifier_instance
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.last_update_id = 0
        self._client: Optional[httpx.AsyncClient] = None
        self._client_proxy: Optional[str] = None

    async def _get_client(self, timeout: float = 25.0, proxy: Optional[str] = None) -> httpx.AsyncClient:
        """Retrieves or creates a pooled httpx.AsyncClient respecting proxy settings."""
        target_proxy = proxy or settings.telegram_proxy
        is_closed = getattr(self._client, "is_closed", False)
        if self._client is None or is_closed or self._client_proxy != target_proxy:
            if self._client and not is_closed and hasattr(self._client, "aclose"):
                await self._client.aclose()
            client_kwargs: Dict[str, Any] = {"timeout": timeout}
            if target_proxy:
                client_kwargs["proxy"] = target_proxy
            self._client = httpx.AsyncClient(**client_kwargs)
            self._client_proxy = target_proxy
        return self._client

    def _is_authorized(self, user_id: str, chat_id: Optional[Union[int, str]]) -> bool:
        """Strict authorization: verifies user or group against trusted settings."""
        trusted_chat = str(settings.telegram_chat_id).strip()
        if not trusted_chat:
            return False
        allowed_users = set(str(u).strip() for u in getattr(settings, "telegram_allowed_user_ids", []) if str(u).strip())
        if user_id in allowed_users:
            return True
        if not trusted_chat.startswith("-"):
            return user_id == trusted_chat
        else:
            if str(chat_id) != trusted_chat:
                return False
            return user_id in allowed_users if allowed_users else True

    async def start(self):
        if self.running or not settings.telegram_enabled or not settings.telegram_bot_token:
            return
        self.running = True
        try:
            await self.notifier.setup_bot_commands()
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as ex:
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
        if self._client and not getattr(self._client, "is_closed", False) and hasattr(self._client, "aclose"):
            await self._client.aclose()
            self._client = None
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
                logger.exception("Telegram polling loop error: %s", e)
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
            client = await self._get_client(timeout=25.0, proxy=settings.telegram_proxy)
            res = await client.get(url, params=params)
            if res.status_code == 200:
                data = res.json()
                if data.get("ok"):
                    return data.get("result", [])
        except (httpx.HTTPError, json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
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
        from keenguard.core.notifier import render_progress_bar
        from keenguard.core.routers.manager import router_manager
        from keenguard.db.database import db

        devices = await db.get_all_devices()
        online_count = sum(1 for d in devices if d.is_online)
        total_count = len(devices)
        backend = router_manager.get_backend()
        sys_info = await backend.get_system_info()
        platform_raw = backend.platform_name
        model_raw = sys_info.model or platform_raw
        platform = html.escape(str(platform_raw))
        model = html.escape(str(model_raw))
        host_ip = html.escape(str(getattr(backend, "host", "192.168.1.1")))

        # ASCII visual indicators
        dev_bar = render_progress_bar(online_count, total_count) if total_count > 0 else "[──────────]"
        guest_info = await backend.get_guest_wifi_status()
        guest_status = "✅ Включена" if guest_info.get("enabled") else "❌ Выключена"
        qh_status = (
            f"🌙 Активны ({settings.telegram_quiet_hours_start:02d}:00–{settings.telegram_quiet_hours_end:02d}:00)"
            if settings.telegram_quiet_hours_enabled else "🔔 Выключены"
        )

        text = (
            f"🛡️ <b>KeenGuard Security Status</b>\n\n"
            f"<b>Платформа:</b> {platform}\n"
            f"<b>Роутер:</b> {model}\n"
            f"<b>Сеть:</b> <code>{host_ip}</code> ({platform})\n"
            f"<b>Устройства онлайн:</b> {dev_bar} <b>{online_count}</b> из <b>{total_count}</b>\n"
            f"<b>Гостевой Wi-Fi:</b> {guest_status}\n"
            f"<b>Тихие часы:</b> {qh_status}\n\n"
            f"<i>Выберите раздел или используйте кнопки ниже:</i>"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Обновить статус", "callback_data": "cmd:status"},
                    {"text": f"📱 Устройства ({online_count})", "callback_data": "cmd:devices"}
                ],
                [
                    {"text": "⚙️ Управление роутером", "callback_data": "cmd:router"},
                    {"text": "🛡️ Сводка безопасности", "callback_data": "cmd:digest"}
                ]
            ]
        }
        return text, keyboard

    async def _build_devices_payload(self, category: str = "all", page: int = 0) -> Tuple[str, Dict[str, Any]]:
        from keenguard.db.database import db

        devices = await db.get_all_devices()
        online_devs = [d for d in devices if d.is_online]

        # Category counts
        cat_counts = {
            "all": len(online_devs),
            "media": sum(1 for d in online_devs if d.profile == "smart_tv"),
            "cameras": sum(1 for d in online_devs if d.profile == "camera"),
            "iot": sum(1 for d in online_devs if "iot" in d.profile or d.profile == "smart_home_hub"),
            "blocked": sum(1 for d in online_devs if d.is_blocked_wan)
        }

        # Filter devices
        if category == "media":
            filtered = [d for d in online_devs if d.profile == "smart_tv"]
        elif category == "cameras":
            filtered = [d for d in online_devs if d.profile == "camera"]
        elif category == "iot":
            filtered = [d for d in online_devs if "iot" in d.profile or d.profile == "smart_home_hub"]
        elif category == "blocked":
            filtered = [d for d in online_devs if d.is_blocked_wan]
        else:
            category = "all"
            filtered = online_devs

        cat_titles = {
            "all": "Все",
            "media": "Медиа/ТВ",
            "cameras": "Камеры",
            "iot": "IoT",
            "blocked": "Заблокированные"
        }

        PAGE_SIZE = 6
        total_pages = max(1, (len(filtered) + PAGE_SIZE - 1) // PAGE_SIZE)
        curr_page = max(0, min(page, total_pages - 1))
        page_items = filtered[curr_page * PAGE_SIZE : (curr_page + 1) * PAGE_SIZE]

        lines = [
            f"📱 <b>Устройства онлайн</b> (<i>{cat_titles.get(category, 'Все')}</i>: {len(filtered)})",
            f"<i>Страница {curr_page + 1} из {total_pages}</i>",
            ""
        ]
        for d in page_items:
            name = html.escape(str(d.custom_name or d.hostname or d.vendor or d.mac))
            ip_str = html.escape(str(d.ip or 'No IP'))
            prof_str = html.escape(str(d.profile))
            seg_str = html.escape(str(d.segment or 'Home'))
            status_icon = "🚫" if d.is_blocked_wan else "🌐"
            lines.append(f"• <b>{name}</b> ({ip_str}) — {status_icon} <code>{prof_str}</code> [<code>{seg_str}</code>]")

        if not filtered:
            lines.append("<i>В данной категории нет активных устройств.</i>")

        # 1. Filter buttons row 1
        filter_row_1 = [
            {"text": f"{'🔘' if category=='all' else '⚪'} Все ({cat_counts['all']})", "callback_data": "dev_cat:all:0"},
            {"text": f"{'🔘' if category=='media' else '📺'} ТВ ({cat_counts['media']})", "callback_data": "dev_cat:media:0"},
            {"text": f"{'🔘' if category=='cameras' else '📹'} Камеры ({cat_counts['cameras']})", "callback_data": "dev_cat:cameras:0"},
        ]
        # Filter buttons row 2
        filter_row_2 = [
            {"text": f"{'🔘' if category=='iot' else '💡'} IoT ({cat_counts['iot']})", "callback_data": "dev_cat:iot:0"},
            {"text": f"{'🔘' if category=='blocked' else '🚫'} Блок ({cat_counts['blocked']})", "callback_data": "dev_cat:blocked:0"},
        ]

        # 2. Device buttons (in pairs of 2)
        dev_btn_rows = []
        cur_row = []
        for d in page_items:
            name = d.custom_name or d.hostname or d.vendor or d.mac
            btn_label = f"📱 {name[:14]}"
            cur_row.append({"text": btn_label, "callback_data": f"dev:{d.mac}"})
            if len(cur_row) == 2:
                dev_btn_rows.append(cur_row)
                cur_row = []
        if cur_row:
            dev_btn_rows.append(cur_row)

        # 3. Pagination controls (if multiple pages)
        pagination_row = []
        if total_pages > 1:
            prev_pg = max(0, curr_page - 1)
            next_pg = min(total_pages - 1, curr_page + 1)
            pagination_row = [
                {"text": "◀️ Пред.", "callback_data": f"dev_page:{category}:{prev_pg}"},
                {"text": f"{curr_page + 1}/{total_pages}", "callback_data": f"dev_page:{category}:{curr_page}"},
                {"text": "След. ▶️", "callback_data": f"dev_page:{category}:{next_pg}"},
            ]

        keyboard_rows = [filter_row_1, filter_row_2]
        keyboard_rows.extend(dev_btn_rows)
        if pagination_row:
            keyboard_rows.append(pagination_row)

        keyboard_rows.append([
            {"text": "🔄 Обновить", "callback_data": f"dev_page:{category}:{curr_page}"},
            {"text": "📊 Статус сети", "callback_data": "cmd:status"}
        ])
        keyboard_rows.append([
            {"text": "⚙️ Управление роутером", "callback_data": "cmd:router"}
        ])

        keyboard = {"inline_keyboard": keyboard_rows}
        return "\n".join(lines), keyboard

    async def _build_device_detail_payload(self, mac: str) -> Tuple[str, Dict[str, Any]]:
        from keenguard.db.database import db
        clean_mac = mac.upper()
        clean_mac_esc = html.escape(clean_mac)
        dev = await db.get_device(clean_mac)
        if not dev:
            return f"❌ Устройство с MAC <code>{clean_mac_esc}</code> не найдено.", {
                "inline_keyboard": [[{"text": "◀️ К списку устройств", "callback_data": "cmd:devices"}]]
            }

        name = html.escape(str(dev.custom_name or dev.hostname or dev.vendor or dev.mac))
        mac_esc = html.escape(str(dev.mac))
        ip_esc = html.escape(str(dev.ip or 'Не назначен'))
        vendor_esc = html.escape(str(dev.vendor or 'Неизвестно'))
        prof_esc = html.escape(str(dev.profile))
        seg_esc = html.escape(str(dev.segment or 'Home'))
        wan_status = "🚫 Заблокирован" if dev.is_blocked_wan else "🌐 Разрешен"
        lan_status = "🔒 Изолирован" if dev.is_isolated_lan else "🏠 Локальная сеть (Bridge0)"

        lines = [
            f"📱 <b>Карточка устройства</b>",
            "",
            f"<b>Имя:</b> {name}",
            f"<b>MAC:</b> <code>{mac_esc}</code>",
            f"<b>IP:</b> <code>{ip_esc}</code>",
            f"<b>Вендор:</b> {vendor_esc}",
            f"<b>Профиль:</b> <code>{prof_esc}</code>",
            f"<b>Сегмент:</b> <code>{seg_esc}</code>",
            f"<b>Доступ в WAN:</b> {wan_status}",
            f"<b>Изоляция LAN:</b> {lan_status}",
            "",
            "<i>Выберите действие:</i>"
        ]

        wan_toggle_text = "🌐 Разрешить WAN" if dev.is_blocked_wan else "🚫 Заблокировать WAN"
        wan_action = "allow" if dev.is_blocked_wan else "block"

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": wan_toggle_text, "callback_data": f"wan_toggle:{clean_mac}:{wan_action}"},
                    {"text": "🔍 Аудит (5 мин)", "callback_data": f"audit:{clean_mac}:300"}
                ],
                [
                    {"text": "🛡️ Сменить профиль", "callback_data": f"prof_menu:{clean_mac}"},
                    {"text": "📦 Скачать PCAP", "callback_data": f"send_pcap:{clean_mac}"}
                ],
                [
                    {"text": "◀️ К списку устройств", "callback_data": "cmd:devices"}
                ]
            ]
        }
        return "\n".join(lines), keyboard

    async def _build_prof_menu_payload(self, mac: str) -> Tuple[str, Dict[str, Any]]:
        from keenguard.db.database import db
        clean_mac = mac.upper()
        clean_mac_esc = html.escape(clean_mac)
        dev = await db.get_device(clean_mac)
        name = html.escape(str((dev.custom_name or dev.hostname or clean_mac) if dev else clean_mac))
        cur_prof = html.escape(str(dev.profile if dev else "unknown"))
        text = (
            f"🛡️ <b>Смена профиля безопасности</b>\n\n"
            f"Устройство: <b>{name}</b> (<code>{clean_mac_esc}</code>)\n"
            f"Текущий профиль: <code>{cur_prof}</code>\n\n"
            f"<i>Выберите новый профиль:</i>"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🛡️ Доверенное", "callback_data": f"set_prof:{clean_mac}:trusted"},
                    {"text": "🔒 Карантин", "callback_data": f"set_prof:{clean_mac}:quarantine"}
                ],
                [
                    {"text": "📺 Smart TV", "callback_data": f"set_prof:{clean_mac}:smart_tv"},
                    {"text": "📹 Камера", "callback_data": f"set_prof:{clean_mac}:camera"}
                ],
                [
                    {"text": "💡 IoT Local-Only", "callback_data": f"set_prof:{clean_mac}:iot_no_internet"},
                    {"text": "🤖 IoT Cloud", "callback_data": f"set_prof:{clean_mac}:iot_cloud"}
                ],
                [
                    {"text": "◀️ Назад к устройству", "callback_data": f"dev:{clean_mac}"}
                ]
            ]
        }
        return text, keyboard

    async def _build_router_payload(self) -> Tuple[str, Dict[str, Any]]:
        from keenguard.core.routers.manager import router_manager
        backend = router_manager.get_backend()
        guest_info = await backend.get_guest_wifi_status()
        guest_up = guest_info.get("enabled", False)
        guest_label = "✅ Включена" if guest_up else "❌ Выключена"
        guest_btn_text = "📶 Выключить гостевой Wi-Fi" if guest_up else "📶 Включить гостевой Wi-Fi"
        guest_action = "0" if guest_up else "1"

        sys_info = await backend.get_system_info()
        platform_esc = html.escape(str(backend.platform_name))
        model_esc = html.escape(str(sys_info.model or backend.platform_name))
        guest_iface_esc = html.escape(str(guest_info.get('interface', 'GuestWiFi')))
        text = (
            f"⚙️ <b>Управление роутером ({platform_esc})</b>\n\n"
            f"<b>Модель:</b> {model_esc}\n"
            f"<b>Гостевая сеть Wi-Fi:</b> {guest_label}\n"
            f"<b>Интерфейс:</b> <code>{guest_iface_esc}</code>\n\n"
            f"<i>Выберите действие:</i>"
        )
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": guest_btn_text, "callback_data": f"router:guest_toggle:{guest_action}"}
                ],
                [
                    {"text": "🔄 Перезагрузить роутер", "callback_data": "router:reboot_prompt"}
                ],
                [
                    {"text": "📊 Статус сети", "callback_data": "cmd:status"},
                    {"text": "📱 Устройства", "callback_data": "cmd:devices"}
                ]
            ]
        }
        return text, keyboard

    async def _handle_callback(self, query: Dict[str, Any]):
        qid = query.get("id", "")
        user_id = str(query.get("from", {}).get("id", ""))
        trusted_chat = str(settings.telegram_chat_id).strip()
        data = query.get("data", "")
        msg = query.get("message", {})
        chat_id = msg.get("chat", {}).get("id")
        mid = msg.get("message_id")
        orig_text = msg.get("text", "")

        # Strict security check: only accept from authorized user or group
        if not self._is_authorized(user_id, chat_id):
            logger.warning("Unauthorized Telegram callback attempt from user_id: %s, chat_id: %s", user_id, chat_id)
            await self.notifier.answer_callback_query(qid, text="Доступ запрещен!")
            return

        if data.startswith(("cmd:", "dev_cat:", "dev_page:")):
            await self._handle_nav_callback(data, qid, chat_id, mid)
        elif data.startswith("router:"):
            await self._handle_router_callback(data, qid, chat_id, mid)
        elif data.startswith(("dev:", "wan_toggle:", "prof_menu:", "set_prof:")):
            await self._handle_device_callback(data, qid, chat_id, mid)
        elif data.startswith(("send_pcap:", "send_pcap_file:")):
            await self._handle_pcap_callback(data, qid, chat_id, mid, trusted_chat)
        else:
            await self._handle_action_callback(data, qid, chat_id, mid, orig_text, trusted_chat)

    async def _handle_nav_callback(self, data: str, qid: str, chat_id: Optional[int], mid: Optional[int]):
        """Handles navigation and status view callback queries."""
        if data == "cmd:status":
            await self.notifier.answer_callback_query(qid, text="Статус обновлен")
            text, keyboard = await self._build_status_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data == "cmd:devices":
            await self.notifier.answer_callback_query(qid, text="Список устройств загружен")
            text, keyboard = await self._build_devices_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data.startswith("dev_cat:"):
            parts = data.split(":")
            cat = parts[1]
            pg = int(parts[2]) if len(parts) > 2 else 0
            await self.notifier.answer_callback_query(qid, text=f"Фильтр: {cat}")
            text, keyboard = await self._build_devices_payload(category=cat, page=pg)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data.startswith("dev_page:"):
            parts = data.split(":")
            cat = parts[1]
            pg = int(parts[2]) if len(parts) > 2 else 0
            await self.notifier.answer_callback_query(qid, text=f"Страница {pg + 1}")
            text, keyboard = await self._build_devices_payload(category=cat, page=pg)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data == "cmd:router":
            await self.notifier.answer_callback_query(qid, text="Меню роутера")
            text, keyboard = await self._build_router_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data == "cmd:digest":
            await self.notifier.answer_callback_query(qid, text="Формирую сводку безопасности...")
            from keenguard.core.digest import digest_generator
            await digest_generator.send_digest_to_telegram(force=True)

    async def _handle_router_callback(self, data: str, qid: str, chat_id: Optional[int], mid: Optional[int]):
        """Handles router actions: guest Wi-Fi toggle, reboot prompt, reboot confirm."""
        if data.startswith("router:guest_toggle:"):
            val = data.split(":")[-1] == "1"
            from keenguard.core.routers.manager import router_manager
            backend = router_manager.get_backend()
            await backend.toggle_guest_wifi(val)
            try:
                from keenguard.web.ws import ws_manager
                await ws_manager.broadcast({"type": "refresh"})
            except Exception:
                pass
            action_result = "📶 Гостевая сеть включена" if val else "📶 Гостевая сеть выключена"
            await self.notifier.answer_callback_query(qid, text=action_result)
            text, keyboard = await self._build_router_payload()
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data == "router:reboot_prompt":
            await self.notifier.answer_callback_query(qid, text="Подтвердите перезагрузку")
            text = (
                "⚠️ <b>ВНИМАНИЕ: Перезагрузка роутера!</b>\n\n"
                "Все сетевые соединения будут временно разорваны (1-2 минуты).\n"
                "Доступ к интернету и устройствам пропадет на время перезагрузки.\n\n"
                "Вы действительно хотите перезагрузить роутер?"
            )
            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "⚠️ ДА, перезагрузить", "callback_data": "router:reboot_confirm"},
                        {"text": "❌ Отмена", "callback_data": "cmd:router"}
                    ]
                ]
            }
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data == "router:reboot_confirm":
            await self.notifier.answer_callback_query(qid, text="Перезагрузка начата")
            from keenguard.core.routers.manager import router_manager
            backend = router_manager.get_backend()
            reboot_ok = await backend.reboot_router()
            if reboot_ok:
                res_text = "🔄 <b>Команда на перезагрузку отправлена.</b>\nРоутер перезагружается, связь восстановится через 1-2 минуты."
            else:
                res_text = "❌ <b>Не удалось отправить команду перезагрузки на роутер.</b>"
            keyboard = {
                "inline_keyboard": [
                    [{"text": "⚙️ Управление роутером", "callback_data": "cmd:router"}]
                ]
            }
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=res_text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(res_text, reply_markup=keyboard)

    async def _handle_device_callback(self, data: str, qid: str, chat_id: Optional[int], mid: Optional[int]):
        """Handles device inspector, WAN toggle, and policy selection callbacks."""
        if data.startswith("dev:"):
            mac = data.split(":", 1)[1]
            await self.notifier.answer_callback_query(qid, text="Карточка устройства")
            text, keyboard = await self._build_device_detail_payload(mac)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data.startswith("wan_toggle:"):
            rest = data.split(":", 1)[1]
            mac, action = rest.rsplit(":", 1)
            block = (action == "block")
            from keenguard.core.profiles import profile_manager
            await profile_manager.toggle_wan(mac, block=block)
            try:
                from keenguard.web.ws import ws_manager
                await ws_manager.broadcast({"type": "refresh"})
            except Exception:
                pass
            clean_mac_esc = html.escape(mac)
            ans = f"🚫 WAN заблокирован для {clean_mac_esc}" if block else f"🌐 WAN разрешен для {clean_mac_esc}"
            await self.notifier.answer_callback_query(qid, text=ans)
            text, keyboard = await self._build_device_detail_payload(mac)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data.startswith("prof_menu:"):
            mac = data.split(":", 1)[1]
            await self.notifier.answer_callback_query(qid, text="Выбор профиля")
            text, keyboard = await self._build_prof_menu_payload(mac)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)
        elif data.startswith("set_prof:"):
            rest = data.split(":", 1)[1]
            mac, target_prof = rest.rsplit(":", 1)
            from keenguard.core.profiles import profile_manager
            await profile_manager.apply_policy(mac, policy_id=target_prof)
            try:
                from keenguard.web.ws import ws_manager
                await ws_manager.broadcast({"type": "refresh"})
            except Exception:
                pass
            await self.notifier.answer_callback_query(qid, text=f"Профиль изменен на {target_prof}")
            text, keyboard = await self._build_device_detail_payload(mac)
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=text, reply_markup=keyboard)
            else:
                await self.notifier.send_message(text, reply_markup=keyboard)

    async def _handle_pcap_callback(self, data: str, qid: str, chat_id: Optional[int], mid: Optional[int], trusted_chat: str):
        """Handles sending PCAP dumps directly into Telegram chat."""
        if data.startswith("send_pcap:"):
            mac = data.split(":", 1)[1].upper()
            from keenguard.db.database import db
            reports = await db.get_audit_reports(mac=mac, limit=5)
            pcap_found = None
            for r in reports:
                if r.pcap_file:
                    cand = settings.pcap_dir / r.pcap_file
                    if cand.exists() and cand.is_file():
                        pcap_found = cand
                        break
            if not pcap_found:
                clean_raw = mac.replace(":", "").lower()
                for p in sorted(settings.pcap_dir.glob("*.pcap*"), reverse=True):
                    if clean_raw in p.name.lower():
                        pcap_found = p
                        break

            if pcap_found:
                await self.notifier.answer_callback_query(qid, text="Отправляю дамп .pcap...")
                clean_mac_esc = html.escape(mac)
                pcap_name_esc = html.escape(pcap_found.name)
                caption = f"📦 <b>Дамп трафика для</b> <code>{clean_mac_esc}</code>\nФайл: <code>{pcap_name_esc}</code>"
                await self.notifier.send_document(pcap_found, caption=caption, chat_id=chat_id or trusted_chat)
            else:
                await self.notifier.answer_callback_query(qid, text="Дампы .pcap для устройства не найдены. Запустите аудит трафика.")
        elif data.startswith("send_pcap_file:"):
            fname = data.split(":", 1)[1]
            safe_name = Path(fname).name
            target = settings.pcap_dir / safe_name
            if target.exists() and target.is_file():
                await self.notifier.answer_callback_query(qid, text="Отправляю файл дампа...")
                safe_name_esc = html.escape(safe_name)
                caption = f"📦 <b>Файл дампа трафика:</b> <code>{safe_name_esc}</code>"
                await self.notifier.send_document(target, caption=caption, chat_id=chat_id or trusted_chat)
            else:
                await self.notifier.answer_callback_query(qid, text=f"Файл {safe_name} не найден на сервере.")

    async def _handle_action_callback(self, data: str, qid: str, chat_id: Optional[int], mid: Optional[int], orig_text: str, trusted_chat: str):
        """Handles contextual alert action buttons (UPnP delete, audit, quarantine, sinkhole)."""
        action_result = "✅ Действие выполнено"
        from keenguard.core.routers.manager import router_manager
        from keenguard.core.profiles import profile_manager
        from keenguard.core.audit import audit_manager

        if data == "dismiss":
            await self.notifier.answer_callback_query(qid, text="Отменено")
            if chat_id and mid:
                await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text="❌ Действие отменено.", reply_markup=None)
            return

        try:
            backend = router_manager.get_backend()
            broadcast_refresh = False
            if data.startswith("del_upnp:"):
                parts = data.split(":")
                proto = parts[1]
                port = int(parts[2])
                await backend.delete_upnp_mapping(proto, port)
                action_result = f"🚫 Порт UPnP {proto.upper()}/{port} закрыт на роутере"
                broadcast_refresh = True
            elif data == "wids:enable_pmf":
                if hasattr(backend, "set_wifi_pmf"):
                    ok = await backend.set_wifi_pmf("required")
                    if ok:
                        action_result = "🛡️ PMF (802.11w) переведён в режим 'Обязательно' (Mandatory). Защита активирована."
                        broadcast_refresh = True
                    else:
                        action_result = "⚠️ Не удалось включить PMF автоматически. Включите 802.11w в настройках роутера."
                else:
                    action_result = "🛡️ Рекомендуется включить 802.11w (PMF: Required) в веб-интерфейсе роутера."
            elif data.startswith("wids:silence_deauth"):
                parts = data.split(":")
                secs = int(parts[2]) if len(parts) > 2 else 3600
                from keenguard.core.wids import wids_service
                wids_service.silence_deauth(seconds=secs)
                action_result = f"🔕 Оповещения Deauth-флуда заглушены на {secs // 3600} ч."
                broadcast_refresh = True
            elif data == "wids:enable_wpa3":
                if hasattr(backend, "set_wifi_wpa3"):
                    ok = await backend.set_wifi_wpa3(True)
                    if ok:
                        action_result = "🔒 Режим WPA3-SAE активирован на Wi-Fi интерфейсах роутера."
                        broadcast_refresh = True
                    else:
                        action_result = "⚠️ Не удалось включить WPA3 автоматически. Включите WPA3-Personal в настройках роутера."
                else:
                    action_result = "🔒 Переведите сеть в режим WPA3-Personal (SAE) для защиты от поддельных точек доступа."
            elif data == "wids:rescan":
                from keenguard.core.wids import wids_service
                from keenguard.db.database import db
                report = await wids_service.run_wids_audit(backend, db=db, notify=False)
                threats = report.get("threats_count", 0)
                grade = report.get("grade", "A")
                score = report.get("score", 100)
                action_result = f"📡 Сканирование эфира завершено: Оценка {grade} ({score}/100), угроз: {threats}."
            elif data.startswith("audit:"):
                rest = data.split(":", 1)[1]
                mac, dur_str = rest.rsplit(":", 1)
                dur = int(dur_str)
                await audit_manager.start_audit(mac=mac, duration_seconds=dur)
                action_result = f"🔍 Аудит трафика {html.escape(mac)} запущен на {dur // 60} мин"
                asyncio.create_task(self._wait_and_notify_audit_completion(
                    mac=mac,
                    duration_seconds=dur,
                    chat_id=str(chat_id or trusted_chat)
                ))
            elif data.startswith("quarantine:"):
                mac = data.split(":", 1)[1]
                await profile_manager.quarantine_device(mac, reason="Telegram Bot Callback")
                action_result = f"🔒 Устройство {html.escape(mac)} отправлено в карантин"
                broadcast_refresh = True
            elif data.startswith("trust:"):
                mac = data.split(":", 1)[1]
                await profile_manager.trust_device(mac)
                action_result = f"✅ Устройству {html.escape(mac)} назначен профиль 'Доверенное'"
                broadcast_refresh = True
            elif data.startswith("block_dns:"):
                domain = data.split(":", 1)[1].strip().lower().strip(".")
                if is_ip_address_string(domain):
                    action_result = f"⚠️ Ошибка: '{html.escape(domain)}' является IP-адресом, а не доменным именем."
                elif is_forbidden_or_local_domain(domain):
                    action_result = f"⚠️ Запрещено блокировать локальные или системные домены управления роутером."
                else:
                    await backend.add_dns_sinkhole(domain)
                    action_result = f"🚫 Домен {html.escape(domain)} заблокирован в Sinkhole (0.0.0.0)"
                    broadcast_refresh = True
            elif data.startswith("unblock_dns:"):
                domain = data.split(":", 1)[1].strip().lower().strip(".")
                await backend.remove_dns_sinkhole(domain)
                action_result = f"✅ Домен {html.escape(domain)} разблокирован"
                broadcast_refresh = True

            if broadcast_refresh:
                try:
                    from keenguard.web.ws import ws_manager
                    await ws_manager.broadcast({"type": "refresh"})
                except Exception as ws_err:
                    logger.debug("WS broadcast error after bot action: %s", ws_err)
        except (httpx.HTTPError, ConnectionError, RuntimeError, aiosqlite.Error, KeyError, TypeError, ValueError) as ex:
            logger.error("Error executing Telegram action %s: %s", data, ex)
            action_result = f"❌ Ошибка выполнения: {html.escape(str(ex))}"

        await self.notifier.answer_callback_query(qid, text=action_result)
        if chat_id and mid and orig_text:
            new_text = orig_text + f"\n\n<b>{action_result}</b>"
            await self.notifier.edit_message_text(chat_id=chat_id, message_id=mid, text=new_text, reply_markup=None)

    async def _wait_and_notify_audit_completion(self, mac: str, duration_seconds: int, chat_id: str):
        """Waits for audit duration to elapse, then delivers summary card and PCAP to chat."""
        try:
            await asyncio.sleep(duration_seconds + 2)
            from keenguard.db.database import db
            clean_mac = mac.upper()
            reports = await db.get_audit_reports(mac=clean_mac, limit=1)
            if not reports:
                logger.debug("No audit report found after timer for %s", clean_mac)
                return
            report = reports[0]
            dev = await db.get_device(clean_mac)
            dev_name = html.escape(str((dev.custom_name or dev.hostname or dev.vendor or clean_mac) if dev else clean_mac))
            clean_mac_esc = html.escape(clean_mac)

            risk_icons = {"low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}
            risk_labels = {"low": "Низкий", "medium": "Средний", "high": "Высокий", "critical": "Критический"}
            r_icon = risk_icons.get(report.risk_level.lower(), "ℹ️")
            r_label = html.escape(str(risk_labels.get(report.risk_level.lower(), report.risk_level)))

            mb_transferred = report.total_bytes / (1024 * 1024)
            dur_min = max(1, duration_seconds // 60)
            summary_esc = html.escape(str(report.summary or 'Проверка завершена без критических замечаний.'))

            lines = [
                f"✅ <b>Аудит трафика завершен ({dur_min} мин)</b>",
                "",
                f"<b>Устройство:</b> <b>{dev_name}</b> (<code>{clean_mac_esc}</code>)",
                f"<b>Уровень риска:</b> {r_icon} {r_label}",
                f"<b>Передано данных:</b> {mb_transferred:.2f} МБ ({report.total_packets} пакетов)",
                f"<b>Итог:</b> {summary_esc}"
            ]

            keyboard = {
                "inline_keyboard": [
                    [
                        {"text": "📱 Карточка устройства", "callback_data": f"dev:{clean_mac}"},
                        {"text": "📊 Статус сети", "callback_data": "cmd:status"}
                    ]
                ]
            }

            text_summary = "\n".join(lines)
            await self.notifier.send_message(text_summary, chat_id=chat_id, reply_markup=keyboard)

            # If PCAP file was generated, automatically upload it
            if report.pcap_file:
                pcap_path = settings.pcap_dir / report.pcap_file
                if pcap_path.exists() and pcap_path.is_file():
                    pcap_esc = html.escape(str(report.pcap_file))
                    caption = f"📦 <b>Дамп трафика аудита:</b> <code>{pcap_esc}</code> ({dev_name})"
                    await self.notifier.send_document(pcap_path, caption=caption, chat_id=chat_id)
        except (httpx.HTTPError, OSError, json.JSONDecodeError, aiosqlite.Error, KeyError, TypeError, ValueError) as e:
            logger.error("Failed to deliver audit completion notification for %s: %s", mac, e)

    async def _handle_message(self, message: Dict[str, Any]):
        user_id = str(message.get("from", {}).get("id", ""))
        chat_id = message.get("chat", {}).get("id")
        text = (message.get("text") or "").strip()
        trusted_chat = str(settings.telegram_chat_id).strip()

        if not self._is_authorized(user_id, chat_id):
            return

        clean_cmd = text.split("@")[0].lower().strip()

        try:
            from keenguard.core.notifier import get_main_reply_keyboard
            if clean_cmd in ("/start", "start", "/help", "помощь"):
                welcome_text = (
                    "🛡️ <b>KeenGuard Security Bot</b>\n\n"
                    "Система оперативного контроля и защиты сети роутера Keenetic.\n\n"
                    "• Используйте кнопки быстрого доступа внизу экрана.\n"
                    "• Чтобы найти устройство, введите его <b>IP</b> или <b>имя</b> (например, <code>s25</code>, <code>tv</code>).\n"
                    "• Чтобы заблокировать домен в Sinkhole, отправьте имя домена."
                )
                await self.notifier.send_message(welcome_text, reply_markup=get_main_reply_keyboard())
                text_msg, keyboard = await self._build_status_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/status", "status", "статус", "📊 статус", "📊 статус сети"):
                text_msg, keyboard = await self._build_status_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/devices", "devices", "устройства", "📱 устройства", "📱 устройства онлайн"):
                text_msg, keyboard = await self._build_devices_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/router", "router", "роутер", "⚙️ управление роутером", "⚙️ роутер"):
                text_msg, keyboard = await self._build_router_payload()
                await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif clean_cmd in ("/digest", "digest", "дайджест", "сводка", "🛡️ дайджест", "🛡️ дайджест безопасности", "🛡️ сводка безопасности"):
                from keenguard.core.digest import digest_generator
                await digest_generator.send_digest_to_telegram(force=True)
            elif re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}$', text.strip()):
                clean_dom = text.strip().lower().strip(".")
                if is_ip_address_string(clean_dom):
                    from keenguard.db.database import db
                    devices = await db.get_all_devices()
                    target = next((d for d in devices if d.ip == clean_dom), None)
                    if target:
                        detail_text, detail_kb = await self._build_device_detail_payload(target.mac)
                        await self.notifier.send_message(detail_text, reply_markup=detail_kb)
                    else:
                        await self.notifier.send_message(f"❌ Устройство с IP <code>{html.escape(clean_dom)}</code> не найдено в сети.")
                elif is_forbidden_or_local_domain(clean_dom):
                    clean_dom_esc = html.escape(clean_dom)
                    await self.notifier.send_message(
                        f"⚠️ Домен <code>{clean_dom_esc}</code> является системным или локальным доменом управления роутером и защищен от блокировки."
                    )
                else:
                    clean_dom_esc = html.escape(clean_dom)
                    text_msg = (
                        f"🌐 <b>Управление DNS для домена:</b> <code>{clean_dom_esc}</code>\n\n"
                        f"Выберите действие для добавления или снятия блокировки через Keenetic Sinkhole (0.0.0.0):"
                    )
                    keyboard = {
                        "inline_keyboard": [
                            [
                                {"text": "🚫 Заблокировать (Sinkhole)", "callback_data": f"block_dns:{clean_dom}"},
                                {"text": "✅ Разблокировать", "callback_data": f"unblock_dns:{clean_dom}"}
                            ],
                            [
                                {"text": "❌ Отмена", "callback_data": "dismiss"}
                            ]
                        ]
                    }
                    await self.notifier.send_message(text_msg, reply_markup=keyboard)
            elif re.match(r'^(?:192\.168\.\d+\.\d+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', text.strip()):
                # Direct search by IP
                from keenguard.db.database import db
                devices = await db.get_all_devices()
                target = next((d for d in devices if d.ip == text.strip()), None)
                if target:
                    detail_text, detail_kb = await self._build_device_detail_payload(target.mac)
                    await self.notifier.send_message(detail_text, reply_markup=detail_kb)
                else:
                    await self.notifier.send_message(f"❌ Устройство с IP <code>{html.escape(text.strip())}</code> не найдено в сети.")
            elif re.match(r'^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$', text.strip()):
                # Direct search by MAC
                detail_text, detail_kb = await self._build_device_detail_payload(text.strip().upper())
                await self.notifier.send_message(detail_text, reply_markup=detail_kb)
            else:
                # Smart search by keyword (hostname / vendor / custom_name)
                from keenguard.db.database import db
                devices = await db.get_all_devices()
                kw = text.strip().lower()
                matches = [
                    d for d in devices
                    if kw in (d.custom_name or "").lower()
                    or kw in (d.hostname or "").lower()
                    or kw in (d.vendor or "").lower()
                ]
                if len(matches) == 1:
                    detail_text, detail_kb = await self._build_device_detail_payload(matches[0].mac)
                    await self.notifier.send_message(detail_text, reply_markup=detail_kb)
                elif len(matches) > 1:
                    clean_kw = html.escape(text.strip())
                    lines = [f"🔍 <b>Найдено устройств: {len(matches)} по запросу «{clean_kw}»:</b>", ""]
                    match_buttons = []
                    for d in matches[:8]:
                        name_raw = d.custom_name or d.hostname or d.vendor or d.mac
                        name_esc = html.escape(str(name_raw))
                        ip_esc = html.escape(str(d.ip or 'No IP'))
                        prof_esc = html.escape(str(d.profile))
                        lines.append(f"• <b>{name_esc}</b> ({ip_esc}) — <code>{prof_esc}</code>")
                        match_buttons.append([{"text": f"📱 {name_raw[:20]} ({d.ip or 'No IP'})", "callback_data": f"dev:{d.mac}"}])
                    match_buttons.append([{"text": "📱 Все устройства", "callback_data": "cmd:devices"}])
                    await self.notifier.send_message("\n".join(lines), reply_markup={"inline_keyboard": match_buttons})
                else:
                    text_msg, keyboard = await self._build_status_payload()
                    await self.notifier.send_message(text_msg, reply_markup=keyboard)
        except (httpx.HTTPError, ConnectionError, RuntimeError, aiosqlite.Error, KeyError, TypeError, ValueError) as ex:
            logger.error("Error processing Telegram message '%s': %s", text, ex, exc_info=True)
            await self.notifier.send_message(f"❌ Ошибка обработки команды: {html.escape(str(ex))}")
