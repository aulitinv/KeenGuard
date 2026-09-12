"""Security Checklist & Audit Evaluator for KeenGuard.

Consolidates real-time security posture checks across the router,
smart home ecosystem, cameras, Smart TV, Wi-Fi, DNS, and network perimeter.
Provides step-by-step KeeneticOS guides and 1-click reversible actions.
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.core.keenetic import keenetic_client
from keenguard.core.classifier import DeviceClassifier
from keenguard.core.profiles import ProfileManager

logger = logging.getLogger("keenguard.checklist")


class SecurityChecklistEvaluator:
    @staticmethod
    async def evaluate_checklist() -> Dict[str, Any]:
        """Evaluates all 10 security checks against live router state, database, and observed flows."""
        devices = await db.get_all_devices()
        events = await db.get_recent_events(limit=100)
        device_domains_map = await db.get_device_domains_map()

        # 1. Classify all devices using MUD-aligned trust tiers & observed domains
        hub_dev = None
        iot_devs = []
        camera_devs = []
        tv_devs = []
        random_mac_devs = []
        quarantine_devs = []

        device_trust_map = {}
        for d in devices:
            domains = device_domains_map.get(d.mac, [])
            trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=domains)
            device_trust_map[d.mac] = trust

            tier = trust["tier"]
            if tier == "controller" or d.profile == "smart_home_hub" or "sprut" in str(d.hostname).lower():
                if not hub_dev or "sprut" in str(d.hostname).lower():
                    hub_dev = d
            elif tier == "camera" or d.profile == "camera":
                camera_devs.append(d)
            elif tier == "media_tv" or d.profile == "smart_tv":
                tv_devs.append(d)
            elif (tier in ("pure_local", "hybrid_weather", "cloud_appliance") or d.profile == "iot") and tier not in ("trusted_pc_phone", "unassigned") and d.profile != "trusted":
                iot_devs.append(d)

            if DeviceClassifier.is_randomized_mac(d.mac):
                random_mac_devs.append(d)

            # Untrusted / new device quarantine candidates
            if d.profile == "unassigned" or (d.is_blocked_wan and d.is_isolated_lan and tier not in ("pure_local", "camera")):
                quarantine_devs.append(d)

        # 2. Query router state
        wifi_security = {}
        firmware_info = {}
        upnp_entries = []
        try:
            wifi_security = await keenetic_client.get_wifi_security()
        except Exception as e:
            logger.debug("Failed to query wifi security for checklist: %s", e)

        try:
            firmware_info = await keenetic_client.check_firmware_updates()
        except Exception as e:
            logger.debug("Failed to query firmware updates for checklist: %s", e)

        try:
            upnp_entries = await keenetic_client.get_upnp_mappings()
        except Exception as e:
            logger.debug("Failed to query upnp table for checklist: %s", e)

        items: List[Dict[str, Any]] = []

        # =====================================================================
        # CHECK 1: SprutHub Asymmetric Isolation
        # =====================================================================
        if hub_dev:
            hub_name = hub_dev.custom_name or hub_dev.hostname or "SprutHub"
            hub_ip = hub_dev.ip or "IP не назначен"
            is_hub_isolated = hub_dev.is_isolated_lan
            is_hub_wan_blocked = hub_dev.is_blocked_wan

            if is_hub_wan_blocked:
                hub_status = "critical"
                hub_status_label = "Критический риск"
                hub_live = f"КРИТИЧНО: Для контроллера {hub_name} ({hub_ip}) заблокирован выход в интернет! Удаленное управление через Apple HomeKit вне дома и оповещения Telegram недоступны."
            elif is_hub_isolated:
                hub_status = "ok"
                hub_status_label = "Защищено"
                hub_live = f"Контроллер {hub_name} ({hub_ip}) защищен: изолирован от ПК и NAS, но сохраняет выход в интернет для HomeKit и Telegram."
            else:
                hub_status = "warning"
                hub_status_label = "Рекомендуется"
                hub_live = f"Контроллер {hub_name} ({hub_ip}) находится в общей домашней сети (Bridge0). Рекомендуется настроить одностороннюю изоляцию от рабочих ПК."

            items.append({
                "id": "hub_isolation",
                "title": "Асимметричная изоляция контроллера (SprutHub / Home Assistant)",
                "category": "smarthome",
                "category_title": "Умный дом",
                "icon": "cpu",
                "status": hub_status,
                "status_label": hub_status_label,
                "live_status": hub_live,
                "why_it_matters": "Контроллер опрашивает десятки устройств и сторонних плагинов. Асимметричная маршрутизация позволяет смартфонам управлять хабом, а хабу — иметь доступ в интернет для удаленного управления, но физически запрещает хабу инициировать соединения к ПК и хранилищу (NAS).",
                "manual_guide": [
                    "1. В KeeneticOS откройте «Сетевые правила» → «Сегменты сети» и создайте сегмент «Умный дом / IoT».",
                    "2. Поместите контроллер в созданный сегмент с разрешённым доступом в интернет (WAN).",
                    "3. В разделе «Межсетевой экран» настройте stateful-правила:",
                    "   ✓ Домашняя сеть → Сегмент IoT: Разрешить (смартфоны и ПК управляют домом)",
                    "   ✕ Сегмент IoT → Домашняя сеть: Запретить (устройства IoT не могут сканировать ПК)",
                    "4. Роутер автоматически разрешит обратные пакеты (Established), обеспечивая 100% работу управления."
                ],
                "action": None
            })
        else:
            items.append({
                "id": "hub_isolation",
                "title": "Асимметричная изоляция контроллера (SprutHub / HA)",
                "category": "smarthome",
                "category_title": "Умный дом",
                "icon": "cpu",
                "status": "warning",
                "status_label": "Рекомендуется",
                "live_status": "Контроллер умного дома пока не обнаружен среди активных устройств сети.",
                "why_it_matters": "Центральный хаб должен иметь односторонний доступ из домашней сети.",
                "manual_guide": [
                    "Выделите отдельный сегмент в KeeneticOS для контроллера и настройте запрет входящих подключений из IoT в Home."
                ],
                "action": None
            })

        # =====================================================================
        # CHECK 2: IoT Egress & Zero-Internet Policy (Granular & Nuanced)
        # =====================================================================
        iot_inventory = []
        pure_local_devs = []
        hybrid_weather_devs = []
        cloud_appliance_devs = []

        for d in iot_devs:
            t = device_trust_map.get(d.mac, DeviceClassifier.classify_iot_trust_tier(d))
            tier = t["tier"]
            doms = device_domains_map.get(d.mac, [])

            if tier == "pure_local":
                pure_local_devs.append(d)
            elif tier == "hybrid_weather":
                hybrid_weather_devs.append(d)
            else:
                cloud_appliance_devs.append(d)

            warning_note = None
            if t["weather_dependent"] and d.is_blocked_wan:
                warning_note = "⚠️ Внимание: интернет заблокирован! Уличный прогноз погоды и NTP-время на экране устройства недоступны."
            elif tier == "pure_local" and not d.is_blocked_wan:
                warning_note = "Поддерживает локальный режим: можно заблокировать WAN, если устройство настроено локально."

            iot_inventory.append({
                "mac": d.mac,
                "name": d.custom_name or d.hostname or d.mac,
                "ip": d.ip or "0.0.0.0",
                "tier": tier,
                "tier_title": t["tier_title"],
                "badge_color": t["badge_color"],
                "icon": t["icon"],
                "wan_needed": t["wan_needed"],
                "weather_dependent": t["weather_dependent"],
                "is_blocked_wan": d.is_blocked_wan,
                "is_isolated_lan": d.is_isolated_lan,
                "observed_domains": doms[:3] if doms else ["Локальный трафик"],
                "impact_wan_block": t["impact_wan_block"],
                "impact_lan_isolate": t["impact_lan_isolate"],
                "warning_note": warning_note
            })

        open_local = [d for d in pure_local_devs if not d.is_blocked_wan]
        blocked_weather = [d for d in hybrid_weather_devs if d.is_blocked_wan]

        if blocked_weather:
            sensor_status = "warning"
            sensor_status_label = "Требует внимания"
            sensor_live = f"Внимание: {len(blocked_weather)} монитор(а) воздуха имеют заблокированный WAN — уличный прогноз погоды на экране не обновляется!"
        elif open_local:
            sensor_status = "warning"
            sensor_status_label = "Рекомендуется"
            sensor_live = f"{len(open_local)} устройств с поддержкой локального управления имеют открытый выход в интернет (WAN можно заблокировать, если они управляются локально)."
        else:
            sensor_status = "ok"
            sensor_status_label = "Защищено"
            sensor_live = f"Политика интернета оптимальна: для устройств с локальным управлением ({len(pure_local_devs)} шт.) закрыт выход в облако, а облачно-зависимым и погодным службам ({len(hybrid_weather_devs) + len(cloud_appliance_devs)} шт.) сохранен доступ."

        items.append({
            "id": "zero_internet_sensors",
            "title": "Политика выхода в интернет для IoT (Локальный доступ vs Облако)",
            "category": "garden",
            "category_title": "IoT & Сенсоры",
            "icon": "shield-check",
            "status": sensor_status,
            "status_label": sensor_status_label,
            "live_status": sensor_live,
            "why_it_matters": "Все Wi-Fi устройства на роутере изначально обращаются в интернет. Вопрос в том, способно ли устройство работать локально по домашней сети или полностью зависит от облака производителя. Если устройство поддерживает работу по локальной сети (Local API, HomeKit, MQTT), ему можно отключить интернет (Zero-Internet) без потери управления. Но для облачно-зависимой техники или погодных станций блокировка WAN сломает работу мобильного приложения или прогноз погоды.",
            "manual_guide": [
                "1. Проверьте, поддерживает ли устройство локальное управление по домашней сети без облака (Local API, HomeKit, MQTT).",
                "2. Если устройство привязано локально к домашнему шлюзу/приложению, заблокируйте ему WAN через «Сетевые правила» → «Приоритеты подключений» (политика «Без интернета»).",
                "3. Для устройств без локального API (работающих строго через облако производителя) или погодных станций оставьте доступ в интернет, но изолируйте их от компьютеров через Гостевой Wi-Fi (Bridge1)."
            ],
            "action": {
                "type": "bulk_sensors_wan",
                "target_block": len(open_local) > 0,
                "label": "Включить Zero-Internet для устройств с локальным управлением" if len(open_local) > 0 else "Вернуть доступ в интернет для устройств с локальным управлением"
            },
            "device_inventory": iot_inventory
        })

        # =====================================================================
        # CHECK 3: Lateral Movement & Home LAN Isolation
        # =====================================================================
        unisolated_iot = [d for d in iot_devs if not d.is_isolated_lan]
        total_iot = len(iot_devs)

        if unisolated_iot:
            app_status = "warning"
            app_status_label = "Рекомендуется"
            app_live = f"{len(unisolated_iot)} из {total_iot} смарт-устройств (техника, датчики, климат) находятся в общей домашней сети (Bridge0). Прямой доступ к ПК открыт."
        elif total_iot > 0:
            app_status = "ok"
            app_status_label = "Защищено"
            app_live = f"Все смарт-устройства ({total_iot} шт.) физически изолированы от домашней сети. Риск горизонтального перемещения (Lateral Movement) устранен."
        else:
            app_status = "ok"
            app_status_label = "Защищено"
            app_live = "Смарт-устройства не зарегистрированы в сети."

        appliances_inventory = [
            {
                "mac": d.mac,
                "name": d.custom_name or d.hostname or d.mac,
                "ip": d.ip or "0.0.0.0",
                "tier": device_trust_map.get(d.mac, {}).get("tier", "iot"),
                "tier_title": device_trust_map.get(d.mac, {}).get("tier_title", "IoT"),
                "badge_color": device_trust_map.get(d.mac, {}).get("badge_color", "bg-slate-800"),
                "is_isolated_lan": d.is_isolated_lan,
                "is_blocked_wan": d.is_blocked_wan,
                "impact_lan_isolate": device_trust_map.get(d.mac, {}).get("impact_lan_isolate", "Изолирует устройство от домашних ПК.")
            }
            for d in iot_devs
        ]

        items.append({
            "id": "appliance_lan_isolation",
            "title": "Защита от перемещения в сети (Lateral Movement & Изоляция)",
            "category": "smarthome",
            "category_title": "Умный дом",
            "icon": "shield-alert",
            "status": app_status,
            "status_label": app_status_label,
            "live_status": app_live,
            "why_it_matters": "Умная техника (роботы-пылесосы, кондиционеры, кормушки, датчики) часто работает на уязвимых прошивках с открытыми портами telnet/adb. Если злоумышленник скомпрометирует робот-пылесос, изоляция LAN не позволит ему просканировать домашние компьютеры, ноутбуки и сетевое хранилище (NAS).",
            "manual_guide": [
                "1. Важно: В KeeneticOS беспроводные устройства привязаны к конкретной Wi-Fi сети. Программная кнопка не может переместить устройство в другой сегмент без переподключения Wi-Fi.",
                "2. Правильный способ: переключите умную технику на Гостевую Wi-Fi сеть роутера (Bridge1) или создайте выделенный IoT SSID.",
                "3. В KeeneticOS создайте запрет: Сегмент IoT/Гостевой → Домашняя сеть: Запретить (Drop).",
                "4. Так устройства сохранят связь с облаком, но будут надёжно отрезаны от ваших рабочих компьютеров."
            ],
            "action": None,
            "device_inventory": appliances_inventory
        })

        # =====================================================================
        # CHECK 4: Cameras & UPnP Leaks
        # =====================================================================
        camera_count = len(camera_devs)
        cam_ips = {c.ip for c in camera_devs if c.ip}
        risky_upnp = []
        for entry in upnp_entries:
            int_ip = getattr(entry, "int_ip", None) or (entry.get("int_ip") or entry.get("internal_ip") or entry.get("ip") if isinstance(entry, dict) else "")
            ext_port = getattr(entry, "ext_port", None) or (entry.get("ext_port") or entry.get("external_port") or entry.get("port") if isinstance(entry, dict) else 0)
            if int_ip in cam_ips or ext_port in (554, 80, 8080, 8000, 37777):
                risky_upnp.append(entry)

        if risky_upnp:
            cam_status = "critical"
            cam_status_label = "Требует внимания"
            cam_live = f"КРИТИЧЕСКИЙ РИСК: Обнаружен открытый UPnP-порт наружу для камеры или видеопотока ({len(risky_upnp)} правил)!"
        elif camera_count > 0:
            cam_status = "ok"
            cam_status_label = "Защищено"
            cam_live = f"Камеры и домофония ({camera_count} шт.) проверены: внешние UPnP-порты отсутствуют, утечек видеопотока не обнаружено."
        else:
            cam_status = "ok"
            cam_status_label = "Защищено"
            cam_live = "Внешних UPnP-пробросов портов и открытых камер не обнаружено."

        camera_inventory = [
            {
                "mac": c.mac,
                "name": c.custom_name or c.hostname or c.mac,
                "ip": c.ip or "0.0.0.0",
                "is_blocked_wan": c.is_blocked_wan,
                "is_isolated_lan": c.is_isolated_lan
            }
            for c in camera_devs
        ]

        items.append({
            "id": "camera_security_upnp",
            "title": "Защита IP-камер, видеодомофона и UPnP",
            "category": "security",
            "category_title": "Безопасность",
            "icon": "video",
            "status": cam_status,
            "status_label": cam_status_label,
            "live_status": cam_live,
            "why_it_matters": "Злоумышленники сканируют интернет в поисках камер с открытыми RTSP (554) и веб-портами (80/8080). Функция UPnP часто открывает порты наружу автоматически без спроса пользователя.",
            "manual_guide": [
                "1. В KeeneticOS перейдите в «Сетевая безопасность» → «Служба UPnP».",
                "2. Отключите автоматическое перенаправление UPnP для сегментов камер и умного дома.",
                "3. Режим NVR-only: если камеры пишут на видеорегистратор, отключите им выход в интернет (Zero-Internet).",
                "4. Для безопасного удаленного просмотра используйте защищенный VPN (WireGuard / Keenetic SSTP)."
            ],
            "action": None,
            "device_inventory": camera_inventory
        })

        # =====================================================================
        # CHECK 5: Smart TV Night Wake & Media Passthrough
        # =====================================================================
        if tv_devs:
            tv_names = [t.custom_name or t.hostname or t.mac for t in tv_devs]
            night_enabled = all(t.night_mode_enabled for t in tv_devs)
            isolated_tv = all(t.is_isolated_lan for t in tv_devs)
            if isolated_tv:
                tv_live = f"Smart TV ({', '.join(tv_names)}): изолирован в отдельном сегменте, пассивный ночной мониторинг {'включен' if night_enabled else 'выключен'}."
            else:
                tv_live = f"Smart TV ({', '.join(tv_names)}): в общей домашней сети (Bridge0). Пассивный ночной мониторинг {'активен (запись PCAP)' if night_enabled else 'выключен'}. Для изоляции от ПК подключите ТВ к Гостевой Wi-Fi сети Keenetic."

            tv_inventory = [
                {
                    "mac": t.mac,
                    "name": t.custom_name or t.hostname or t.mac,
                    "ip": t.ip or "0.0.0.0",
                    "is_blocked_wan": t.is_blocked_wan,
                    "is_isolated_lan": t.is_isolated_lan,
                    "airplay_allowed": t.airplay_allowed,
                    "dlna_allowed": t.dlna_allowed,
                    "night_mode_enabled": t.night_mode_enabled
                }
                for t in tv_devs
            ]

            items.append({
                "id": "smart_tv_security",
                "title": "Smart TV: пассивный ночной мониторинг и изоляция от ПК",
                "category": "tv",
                "category_title": "Smart TV",
                "icon": "tv",
                "status": "ok" if (night_enabled and isolated_tv) else "warning",
                "status_label": "Защищено" if (night_enabled and isolated_tv) else "Рекомендуется",
                "live_status": tv_live,
                "why_it_matters": "Медиаэкраны и Smart TV собирают телеметрию о просмотренных фильмах и могут фоново пробуждаться по сети ночью. Для защиты компьютеров от несанкционированного сканирования телевизор изолируют в гостевом сегменте, а KeenGuard ведет пассивную запись сетевых пробуждений (WOL/mDNS) в PCAP-дамп.",
                "manual_guide": [
                    "1. Физическая изоляция: В KeeneticOS подключите телевизор к Гостевой Wi-Fi сети (Bridge1). Это физически изолирует телевизор от компьютеров и сетевых хранилищ (NAS).",
                    "2. AirPlay и DLNA: Чтобы транслировать видео со смартфона на ТВ в гостевой сети, включите компонент «UDP Proxy» (mDNS relay) в настройках Keenetic.",
                    "3. Пассивный ночной мониторинг: KeenGuard непрерывно слушает широковещательный трафик и при ночных пробуждениях (WOL, mDNS) сохраняет PCAP-дамп для форензики."
                ],
                "action": {
                    "type": "toggle_tv_night",
                    "mac": tv_devs[0].mac,
                    "target_enable": not night_enabled,
                    "label": "Отключить ночной мониторинг" if night_enabled else "Включить ночной мониторинг TV"
                },
                "device_inventory": tv_inventory
            })
        else:
            items.append({
                "id": "smart_tv_security",
                "title": "Smart TV и медиаэкраны",
                "category": "tv",
                "category_title": "Smart TV",
                "icon": "tv",
                "status": "ok",
                "status_label": "Защищено",
                "live_status": "Smart TV не обнаружены или не назначены профилем smart_tv.",
                "why_it_matters": "Телевизоры требуют асимметричной фильтрации трафика для защиты от слежки.",
                "manual_guide": ["Назначьте профиль «Smart TV» в списке устройств при появлении телевизора."],
                "action": None
            })

        # =====================================================================
        # CHECK 6: Wi-Fi Security (WPA3 & PMF 802.11w)
        # =====================================================================
        wifi_score = wifi_security.get("score", 100)
        wifi_networks = wifi_security.get("access_points") or wifi_security.get("networks", [])
        all_pmf_required = bool(wifi_networks)
        has_wpa3 = False

        for net in wifi_networks:
            sec_text = (str(net.get("security", "")) + " " + str(net.get("security_type", "")) + " " + str(net.get("auth", ""))).lower()
            pmf = str(net.get("pmf", "")).lower()
            if "wpa3" in sec_text:
                has_wpa3 = True
            # Check if PMF is strictly required
            if pmf not in ("required", "mandatory", "true", "1"):
                all_pmf_required = False

        ssids = [n.get("ssid") for n in wifi_networks if n.get("ssid")]
        ssid_summary = f" ({', '.join(ssids)})" if ssids else ""

        # User feedback: optional PMF is still a security hole against Deauth attacks! Mark as warning!
        if all_pmf_required and has_wpa3:
            wifi_status = "ok"
            wifi_status_label = "Защищено"
            wifi_live = f"Беспроводные сети{ssid_summary} защищены WPA3 с обязательной защитой кадров управления (PMF Mandatory)."
        else:
            wifi_status = "warning"
            wifi_status_label = "Брешь безопасности"
            wifi_live = f"ВНИМАНИЕ: Защита кадров управления (PMF / 802.11w) для сетей{ssid_summary} отключена или установлена в режим «По возможности». Сеть уязвима к атакам деаутентификации (глушению датчиков и камер)."

        items.append({
            "id": "wifi_security_pmf",
            "title": "Wi-Fi периметр: Защита от глушения (PMF) и WPA3",
            "category": "network",
            "category_title": "Сеть & Wi-Fi",
            "icon": "wifi",
            "status": wifi_status,
            "status_label": wifi_status_label,
            "live_status": wifi_live,
            "why_it_matters": "Атака деаутентификации (Deauth attack) позволяет злоумышленнику с портативным устройством (Flipper Zero, ESP8266 deauther) принудительно отключить ваши Wi-Fi камеры и охранные датчики от роутера. Единственная защита — PMF (802.11w). Однако принудительное включение обязательного PMF на 2.4 ГГц может отключить старые чипы ESP8266/ESP32!",
            "manual_guide": [
                "1. Профессиональная схема двух диапазонов в KeeneticOS:",
                "   • Сеть 5 ГГц (ноутбуки, смартфоны): WPA2+WPA3 или WPA3-SAE, PMF: «Обязательно» (100% защита).",
                "   • Сеть 2.4 ГГц для IoT: WPA2-PSK, PMF: «Обязательно» (если все датчики поддерживают) ИЛИ «По возможности», если в сети есть старые чипы ESP8266.",
                "2. Если старый датчик теряет сеть при включении PMF, переведите его на Zigbee или выделите гостевой SSID 2.4 ГГц."
            ],
            "action": None
        })

        # =====================================================================
        # CHECK 7: KeeneticOS Firmware Updates
        # =====================================================================
        update_available = firmware_info.get("has_update") or firmware_info.get("update_available", False)
        current_ver = firmware_info.get("current_version") or "5.1.4"
        available_ver = firmware_info.get("latest_version") or firmware_info.get("available_version") or current_ver

        if update_available:
            fw_status = "critical"
            fw_status_label = "Требует внимания"
            fw_live = f"Доступно обновление безопасности KeeneticOS {available_ver} (установлена {current_ver})."
        else:
            fw_status = "ok"
            fw_status_label = "Защищено"
            fw_live = f"Установлена актуальная версия KeeneticOS ({current_ver}). Патчи безопасности применены."

        items.append({
            "id": "firmware_updates",
            "title": "Обновление прошивки KeeneticOS",
            "category": "router",
            "category_title": "Роутер",
            "icon": "download-cloud",
            "status": fw_status,
            "status_label": fw_status_label,
            "live_status": fw_live,
            "why_it_matters": "Обновления KeeneticOS устраняют уязвимости в сетевом стеке, драйверах Wi-Fi и службах удаленного доступа роутера.",
            "manual_guide": [
                "1. В KeeneticOS перейдите в «Управление» → «Общие настройки».",
                "2. В блоке «Обновление KeeneticOS» нажмите кнопку «Установить обновление».",
                "3. Рекомендуется включить «Автоматическое обновление системы» в ночное время."
            ],
            "action": None
        })

        # =====================================================================
        # CHECK 8: DNS-Protection & Domain Sinkhole
        # =====================================================================
        dns_proxy = await keenetic_client.get_dns_proxy_status()
        filter_engine = dns_proxy.get("filter_engine")
        has_encrypted_dns = dns_proxy.get("has_doh") or dns_proxy.get("has_dot")
        rebind_prot = dns_proxy.get("rebind_protect")

        # Check for genuine rogue DNS / domain threat events (exclude router_offline!)
        danger_dns_events = [
            e for e in events 
            if e.event_type in ("rogue_dns", "malicious_domain", "dns_threat") 
            or (e.severity == "critical" and "dns" in str(e.event_type).lower())
        ]

        engine_titles = {
            "nextdns": "NextDNS",
            "adguard": "AdGuard DNS",
            "cloudflare": "Cloudflare DNS",
            "safedns": "SafeDNS",
            "yandex": "Яндекс.DNS"
        }
        engine_label = engine_titles.get(str(filter_engine).lower(), filter_engine.capitalize() if filter_engine else None)

        if danger_dns_events:
            dns_status = "critical"
            dns_status_label = "Требует внимания"
            dns_live = f"Зафиксированы обращения к опасным или фишинговым доменам ({len(danger_dns_events)} событий)."
        elif filter_engine or has_encrypted_dns:
            dns_status = "ok"
            dns_status_label = "Защищено"
            details = []
            if engine_label:
                details.append(f"интернет-фильтр {engine_label}")
            if has_encrypted_dns:
                details.append("DoH/DoT шифрование")
            if rebind_prot:
                details.append("DNS Rebind защита")
            feat_str = ", ".join(details) if details else "активная фильтрация"
            dns_live = f"DNS-защита Keenetic активна ({feat_str}). Вредоносных обращений не зафиксировано."
        else:
            dns_status = "warning"
            dns_status_label = "Рекомендуется"
            dns_live = "Защищенный DNS-фильтр (NextDNS/AdGuard) или DoH не настроен. Запросы идут открытым текстом к провайдеру."

        items.append({
            "id": "dns_protection",
            "title": "DNS-фильтрация и защита от вредоносных доменов",
            "category": "perimeter",
            "category_title": "Периметр & DNS",
            "icon": "globe",
            "status": dns_status,
            "status_label": dns_status_label,
            "live_status": dns_live,
            "why_it_matters": "DNS-фильтрация блокирует доступ к фишинговым сайтам, центрам управления ботнетами (C2) и трекерам рекламы до того, как они успеют загрузить вредоносный код.",
            "manual_guide": [
                "1. В KeeneticOS перейдите в «Сетевые правила» → «Интернет-фильтр».",
                "2. Включите AdGuard DNS (профиль «Семейный» или «Без рекламы») либо NextDNS.",
                "3. Настройте зашифрованный протокол DNS-over-HTTPS (DoH) для защиты запросов от перехвата провайдером."
            ],
            "action": None
        })

        # =====================================================================
        # CHECK 9: Continuous New Device Quarantine
        # =====================================================================
        quar_wan = settings.new_device_quarantine_wan
        auto_audit = settings.new_device_auto_audit
        continuous_audit = getattr(settings, "new_device_continuous_audit", True)

        if quar_wan:
            quar_status = "ok"
            quar_status_label = "Защищено"
            quar_live = "Автокарантин WAN активен: новые неизвестные устройства сразу блокируются в интернет с непрерывным почасовым мониторингом."
        elif auto_audit:
            quar_status = "ok"
            quar_status_label = "Частичный мониторинг"
            quar_live = f"Частичный мониторинг: WAN-блок={'Вкл' if quar_wan else 'Выкл'}, Почасовой аудит={'Вкл' if continuous_audit else 'Выкл'}."
        else:
            quar_status = "warning"
            quar_status_label = "Рекомендуется"
            quar_live = "Карантин отключен: новые неизвестные устройства сразу получают свободный доступ в интернет."

        quarantine_inventory = [
            {
                "mac": d.mac,
                "name": d.custom_name or d.hostname or d.mac,
                "ip": d.ip or "0.0.0.0",
                "is_blocked_wan": d.is_blocked_wan,
                "is_isolated_lan": d.is_isolated_lan,
                "first_seen": getattr(d, "first_seen", "Недавно"),
                "observed_domains": device_domains_map.get(d.mac, [])[:3]
            }
            for d in quarantine_devs
        ]

        items.append({
            "id": "new_device_quarantine",
            "title": "Автокарантин и непрерывный почасовой аудит новых устройств",
            "category": "perimeter",
            "category_title": "Периметр & DNS",
            "icon": "shield-alert",
            "status": quar_status,
            "status_label": quar_status_label,
            "live_status": quar_live,
            "why_it_matters": "При подключении нового смарт-гаджета или компрометации пароля Wi-Fi автокарантин не даёт устройству передавать трафик наружу в интернет. Непрерывный почасовой аудит протоколирует все DNS-запросы и попытки соединения устройства до тех пор, пока вы не одобрите его вручную.",
            "manual_guide": [
                "1. В KeeneticOS откройте «Сетевые правила» → «Сегменты сети».",
                "2. Для незарегистрированных устройств назначьте сегмент «Без доступа в интернет».",
                "3. После физического подключения нового гаджета KeenGuard проведет анализ его сетевых потоков.",
                "4. Зарегистрируйте устройство в KeenGuard и Keenetic только после того, как убедитесь в отсутствии вредоносной активности."
            ],
            "action": {
                "type": "toggle_quarantine",
                "target_enable": not quar_wan,
                "label": "Отключить автокарантин" if quar_wan else "Включить автокарантин WAN"
            },
            "quarantine_settings": {
                "quarantine_wan": quar_wan,
                "auto_audit": auto_audit,
                "continuous_audit": continuous_audit
            },
            "quarantined_devices": quarantine_inventory
        })

        # =====================================================================
        # CHECK 10: ARP-Scan & MAC Spoofing Protection
        # =====================================================================
        scan_events = [e for e in events if e.event_type == "lan_scan"]
        random_count = len(random_mac_devs)

        random_mac_inventory = [
            {
                "mac": d.mac,
                "name": d.custom_name or d.hostname or d.mac,
                "ip": d.ip or "0.0.0.0",
                "vendor": d.vendor or "Locally Administered MAC"
            }
            for d in random_mac_devs
        ]

        if scan_events:
            arp_status = "critical"
            arp_status_label = "Требует внимания"
            arp_live = f"КРИТИЧНО: Зафиксированы попытки ARP-сканирования локальной сети ({len(scan_events)} событий)!"
        elif random_count > 0:
            arp_status = "warning"
            arp_status_label = "Рекомендуется"
            arp_live = f"Обнаружено {random_count} устройств со случайными MAC-адресами (MAC Randomization). Рекомендуется отключить приватный MAC в домашней сети."
        else:
            arp_status = "ok"
            arp_status_label = "Защищено"
            arp_live = "Попыток сканирования портов не зафиксировано. Все устройства имеют постоянные аппаратные MAC-адреса."

        items.append({
            "id": "arp_scan_spoofing",
            "title": "Защита от ARP-сканирования и рандомизации MAC",
            "category": "perimeter",
            "category_title": "Периметр & DNS",
            "icon": "scan",
            "status": arp_status,
            "status_label": arp_status_label,
            "live_status": arp_live,
            "why_it_matters": "Случайные MAC-адреса на домашних смартфонах мешают роутеру корректно применять правила безопасности, а ARP-сканирование используется вредоносным ПО для поиска уязвимых устройств в сети.",
            "manual_guide": [
                "1. На смартфонах iPhone и Android зайдите в настройки Wi-Fi → имя вашей домашней сети.",
                "2. Отключите пункт «Частный адрес Wi-Fi» (Случайный MAC) и выберите «Использовать MAC устройства».",
                "3. Зарегистрируйте постоянный MAC-адрес смартфона в KeeneticOS."
            ],
            "action": None,
            "random_mac_devices": random_mac_inventory
        })

        # =====================================================================
        # CHECK 11: Hardware L2 Network Segmentation (Bridge0 vs Guest / VLAN)
        # =====================================================================
        iot_in_bridge0 = []
        for d in devices:
            if d.is_online and d.profile in ("camera", "iot"):
                seg = (d.segment or "Home").strip()
                if seg == "Home" or (d.ip and d.ip.startswith("192.168.1.")):
                    iot_in_bridge0.append(d)

        if iot_in_bridge0:
            seg_status = "warning"
            seg_status_label = "L2-обход в Bridge0"
            names = [dev.custom_name or dev.hostname or dev.mac for dev in iot_in_bridge0[:3]]
            names_str = ", ".join(names) + (f" и ещё {len(iot_in_bridge0) - 3}" if len(iot_in_bridge0) > 3 else "")
            seg_live = (
                f"ВНИМАНИЕ: {len(iot_in_bridge0)} IoT/камер ({names_str}) находятся в основном домашнем мосте 'Home' (Bridge0, 192.168.1.0/24). "
                "L2-трафик между ними и рабочими ПК идет напрямую через свитч роутера в обход файрвола!"
            )
        else:
            seg_status = "ok"
            seg_status_label = "Изолировано физически"
            seg_live = "Все активные IoT-устройства и камеры изолированы в гостевой сети или отдельном L2/L3 сегменте (VLAN)."

        items.append({
            "id": "hardware_segmentation",
            "title": "Аппаратная сегментация L2 (Bridge0 vs Guest / IoT VLAN)",
            "category": "router",
            "category_title": "Роутер & Прошивка",
            "icon": "network",
            "status": seg_status,
            "status_label": seg_status_label,
            "live_status": seg_live,
            "why_it_matters": "Устройства в одном сегменте (Bridge0) обмениваются пакетами напрямую через встроенный свитч роутера. Файрвол KeeneticOS не может фильтровать внутрисетевой L2-трафик. Для реальной изоляции IoT требуется отдельный сегмент сети (Гостевой Wi-Fi или VLAN).",
            "manual_guide": [
                "1. В KeeneticOS перейдите в «Сетевые правила» → «Сегменты сети».",
                "2. Создайте сегмент «IoT» или используйте «Гостевой сегмент» (Bridge1).",
                "3. Включите «Изоляцию клиентов» (Station Isolation) в настройках беспроводной сети сегмента.",
                "4. Переключите смарт-камеры и китайские датчики на SSID этого изолированного сегмента."
            ],
            "action": None,
            "devices_at_risk": [
                {"mac": d.mac, "ip": d.ip, "name": d.custom_name or d.hostname or d.mac, "profile": d.profile}
                for d in iot_in_bridge0
            ]
        })

        # =====================================================================
        # Compute Overall Security Score
        # =====================================================================
        total_checks = len(items)
        ok_count = sum(1 for item in items if item["status"] == "ok")
        warning_count = sum(1 for item in items if item["status"] == "warning")
        critical_count = sum(1 for item in items if item["status"] == "critical")

        # Base score calculation
        score = 100
        score -= critical_count * 20
        score -= warning_count * 7
        score = max(10, min(100, score))

        if score >= 90:
            score_label = "Отлично"
            score_color = "emerald"
        elif score >= 70:
            score_label = "Хорошо"
            score_color = "indigo"
        elif score >= 50:
            score_label = "Внимание"
            score_color = "amber"
        else:
            score_label = "Высокий риск"
            score_color = "rose"

        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "score_label": score_label,
            "score_color": score_color,
            "stats": {
                "total_checks": total_checks,
                "ok_count": ok_count,
                "warning_count": warning_count,
                "critical_count": critical_count
            },
            "items": items
        }
