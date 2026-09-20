"""Device-focused security checks (Hub, IoT, LAN isolation, Cameras, Smart TV)."""
from typing import Dict, Any, List
from keenguard.core.checklist.context import ChecklistContext
from keenguard.core.classifier import DeviceClassifier


def evaluate_hub_isolation(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 1: SprutHub Asymmetric Isolation."""
    if ctx.hub_dev:
        hub_name = ctx.hub_dev.custom_name or ctx.hub_dev.hostname or "SprutHub"
        hub_ip = ctx.hub_dev.ip or "IP не назначен"
        is_hub_isolated = ctx.hub_dev.is_isolated_lan
        is_hub_wan_blocked = ctx.hub_dev.is_blocked_wan

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

        return {
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
        }
    else:
        return {
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
        }


def evaluate_iot_egress_policy(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 2: IoT Egress & Zero-Internet Policy (Granular & Nuanced)."""
    iot_inventory = []
    pure_local_devs = []
    hybrid_weather_devs = []
    cloud_appliance_devs = []

    for d in ctx.iot_devs:
        t = ctx.device_trust_map.get(d.mac, DeviceClassifier.classify_iot_trust_tier(d))
        tier = t["tier"]
        doms = ctx.device_domains_map.get(d.mac, [])

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

    return {
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
    }


def evaluate_lateral_movement_isolation(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 3: Lateral Movement & Home LAN Isolation."""
    unisolated_iot = [d for d in ctx.iot_devs if not d.is_isolated_lan]
    total_iot = len(ctx.iot_devs)

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
            "tier": ctx.device_trust_map.get(d.mac, {}).get("tier", "iot"),
            "tier_title": ctx.device_trust_map.get(d.mac, {}).get("tier_title", "IoT"),
            "badge_color": ctx.device_trust_map.get(d.mac, {}).get("badge_color", "bg-slate-800"),
            "is_isolated_lan": d.is_isolated_lan,
            "is_blocked_wan": d.is_blocked_wan,
            "impact_lan_isolate": ctx.device_trust_map.get(d.mac, {}).get("impact_lan_isolate", "Изолирует устройство от домашних ПК.")
        }
        for d in ctx.iot_devs
    ]

    return {
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
    }


def evaluate_camera_upnp_security(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 4: Cameras & UPnP Leaks."""
    camera_count = len(ctx.camera_devs)
    cam_ips = {c.ip for c in ctx.camera_devs if c.ip}
    risky_upnp = []
    for entry in ctx.upnp_entries:
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
        for c in ctx.camera_devs
    ]

    return {
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
    }


def evaluate_smart_tv_security(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 5: Smart TV Night Wake & Media Passthrough."""
    if ctx.tv_devs:
        tv_names = [t.custom_name or t.hostname or t.mac for t in ctx.tv_devs]
        night_enabled = all(t.night_mode_enabled for t in ctx.tv_devs)
        isolated_tv = all(t.is_isolated_lan for t in ctx.tv_devs)
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
            for t in ctx.tv_devs
        ]

        return {
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
                "mac": ctx.tv_devs[0].mac,
                "target_enable": not night_enabled,
                "label": "Отключить ночной мониторинг" if night_enabled else "Включить ночной мониторинг TV"
            },
            "device_inventory": tv_inventory
        }
    else:
        return {
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
        }
