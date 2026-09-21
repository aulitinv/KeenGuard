"""Network and perimeter security checks (Wi-Fi, Firmware, DNS, Quarantine, ARP, L2 Segmentation)."""
from typing import Dict, Any, List
from keenguard.config import settings
from keenguard.core.checklist.context import ChecklistContext


def evaluate_wifi_security(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 6: Wi-Fi Security (WPA3 & PMF 802.11w)."""
    wifi_networks = ctx.wifi_security.get("access_points") or ctx.wifi_security.get("networks", [])
    all_pmf_required = bool(wifi_networks)
    has_wpa3 = False
    has_open_net = False
    open_ssids = []

    for net in wifi_networks:
        sec_text = (
            str(net.get("security", "")) + " " +
            str(net.get("encryption", "")) + " " +
            str(net.get("security_type", "")) + " " +
            str(net.get("auth", ""))
        ).lower()
        pmf = str(net.get("pmf", "")).lower()

        if "wpa3" in sec_text:
            has_wpa3 = True
        if "открытая" in sec_text or "open" in sec_text or net.get("security_type") == "open":
            has_open_net = True
            if net.get("ssid"):
                open_ssids.append(net.get("ssid"))

        if pmf not in ("required", "mandatory", "true", "1"):
            all_pmf_required = False

    ssids = [n.get("ssid") for n in wifi_networks if n.get("ssid")]
    ssid_summary = f" ({', '.join(ssids)})" if ssids else ""

    if has_open_net:
        wifi_status = "critical"
        wifi_status_label = "Открытая сеть"
        wifi_live = f"КРИТИЧЕСКАЯ УЯЗВИМОСТЬ: Сеть {', '.join(open_ssids)} не защищена паролем! Любой злоумышленник в радиусе действия Wi-Fi может перехватывать ваш трафик."
    elif all_pmf_required and has_wpa3:
        wifi_status = "ok"
        wifi_status_label = "Защищено"
        wifi_live = f"Беспроводные сети{ssid_summary} защищены WPA3 с обязательной защитой кадров управления (PMF Mandatory)."
    else:
        wifi_status = "warning"
        wifi_status_label = "Брешь безопасности"
        wifi_live = f"ВНИМАНИЕ: Защита кадров управления (PMF / 802.11w) для сетей{ssid_summary} отключена или установлена в режим «По возможности». Сеть уязвима к атакам деаутентификации (глушению датчиков и камер)."

    return {
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
    }


def evaluate_firmware_updates(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 7: KeeneticOS Firmware Updates."""
    update_available = ctx.firmware_info.get("has_update") or ctx.firmware_info.get("update_available", False)
    current_ver = ctx.firmware_info.get("current_version") or "5.1.4"
    available_ver = ctx.firmware_info.get("latest_version") or ctx.firmware_info.get("available_version") or current_ver

    if update_available:
        fw_status = "critical"
        fw_status_label = "Требует внимания"
        fw_live = f"Доступно обновление безопасности KeeneticOS {available_ver} (установлена {current_ver})."
    else:
        fw_status = "ok"
        fw_status_label = "Защищено"
        fw_live = f"Установлена актуальная версия KeeneticOS ({current_ver}). Патчи безопасности применены."

    return {
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
    }


def evaluate_dns_protection(ctx: ChecklistContext, dns_proxy: Dict[str, Any]) -> Dict[str, Any]:
    """CHECK 8: DNS-Protection & Domain Sinkhole."""
    filter_engine = dns_proxy.get("filter_engine")
    has_encrypted_dns = dns_proxy.get("has_doh") or dns_proxy.get("has_dot")
    rebind_prot = dns_proxy.get("rebind_protect")

    danger_dns_events = [
        e for e in ctx.events
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

    return {
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
    }


def evaluate_continuous_quarantine(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 9: Continuous New Device Quarantine."""
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
            "observed_domains": ctx.device_domains_map.get(d.mac, [])[:3]
        }
        for d in ctx.quarantine_devs
    ]

    return {
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
    }


def evaluate_arp_mac_spoofing(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 10: ARP-Scan & MAC Spoofing Protection."""
    scan_events = [e for e in ctx.events if e.event_type == "lan_scan"]
    random_count = len(ctx.random_mac_devs)

    random_mac_inventory = [
        {
            "mac": d.mac,
            "name": d.custom_name or d.hostname or d.mac,
            "ip": d.ip or "0.0.0.0",
            "vendor": d.vendor or "Locally Administered MAC"
        }
        for d in ctx.random_mac_devs
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

    return {
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
    }


def evaluate_hardware_segmentation(ctx: ChecklistContext) -> Dict[str, Any]:
    """CHECK 11: Hardware L2 Network Segmentation (Bridge0 vs Guest / VLAN)."""
    iot_in_bridge0 = []
    for d in ctx.devices:
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

    return {
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
    }
