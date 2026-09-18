"""Automated DNS Domain Reputation and Security Analyzer for KeenGuard.

Classifies network domains queried by devices into security categories,
identifies IoT vendors, detects telemetry and advertising trackers, evaluates risk,
and provides remediation and inspection advice for Keenetic routers.
"""
import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Tuple

from keenguard.db.database import db

logger = logging.getLogger("keenguard.domain_analyzer")

# Category metadata definitions
CATEGORIES: Dict[str, Dict[str, Any]] = {
    "iot_cloud": {
        "name": "Облако IoT / Вендор",
        "badge_color": "emerald",
        "default_risk": "safe",
        "badge_text": "Безопасно",
        "recommendation": "Легитимный сервис умного устройства. Блокировка нарушит удаленное управление или функции умного дома."
    },
    "telemetry": {
        "name": "Телеметрия и трекинг",
        "badge_color": "amber",
        "default_risk": "telemetry",
        "badge_text": "Телеметрия",
        "recommendation": "Сбор аналитики, метрик или краш-репортов. Можно заблокировать через контентную фильтрацию Keenetic без потери ключевых функций."
    },
    "advertising": {
        "name": "Реклама и баннеры",
        "badge_color": "rose",
        "default_risk": "ad",
        "badge_text": "Реклама",
        "recommendation": "Рекламный трекер или рекламная сеть. Рекомендуется активировать AdGuard DNS или включить блокировку в Keenetic."
    },
    "system_dns": {
        "name": "Системный сервис / DNS",
        "badge_color": "blue",
        "default_risk": "safe",
        "badge_text": "Системный",
        "recommendation": "Базовая сетевая инфраструктура (DNS, синхронизация времени NTP, проверка портала). Блокировка нарушит сетевую работу."
    },
    "vpn_tunnel": {
        "name": "VPN / Сетевой туннель",
        "badge_color": "purple",
        "default_risk": "warning",
        "badge_text": "Туннель",
        "recommendation": "Используется для удаленного доступа или mesh-сети. Убедитесь, что туннель настроен авторизованным пользователем."
    },
    "cdn_media": {
        "name": "CDN / Веб-сервисы",
        "badge_color": "cyan",
        "default_risk": "safe",
        "badge_text": "Медиа/CDN",
        "recommendation": "Легитимная сеть доставки контента (CDN), видео, веб-сайт или облачный хостинг."
    },
    "suspicious": {
        "name": "Подозрительный / Высокий риск",
        "badge_color": "rose",
        "default_risk": "danger",
        "badge_text": "Подозрительно",
        "recommendation": "Подозрительный домен или потенциально нежелательная активность. Рекомендуется немедленно заблокировать домен на роутере."
    },
    "unknown": {
        "name": "Не классифицирован",
        "badge_color": "slate",
        "default_risk": "neutral",
        "badge_text": "Неизвестно",
        "recommendation": "Домен пока не встречен в известных каталогах. Проверьте репутацию через VirusTotal или Whois."
    }
}

# Known domain rules: (pattern, category, vendor, description, risk_level)
KNOWN_DOMAIN_RULES: List[Tuple[str, str, str, str, str]] = [
    # --- IoT & Smart Home Clouds ---
    ("dreame.tech", "iot_cloud", "Dreame Technology", "P2P-видеострим и локальное управление роботом-пылесосом Dreame", "safe"),
    ("dreame.iot.alibabacloud.com", "iot_cloud", "Dreame / Alibaba Cloud", "MQTT-брокер и облачная телеметрия пылесосов Dreame на Alibaba Cloud", "safe"),
    ("tuya.iot.cloud", "iot_cloud", "Tuya Smart", "Облачная платформа умного дома Tuya / Smart Life", "safe"),
    ("tuya.com", "iot_cloud", "Tuya Smart", "Облачная инфраструктура и API устройств Tuya", "safe"),
    ("tuyaeu.com", "iot_cloud", "Tuya Smart", "Европейский облачный брокер устройств умного дома Tuya / Smart Life", "safe"),
    ("tuyaus.com", "iot_cloud", "Tuya Smart", "Американский облачный брокер устройств умного дома Tuya / Smart Life", "safe"),
    ("smartlife.me", "iot_cloud", "Smart Life", "Сервер управления умным домом Smart Life", "safe"),
    ("qingping.iot.cloud", "iot_cloud", "Qingping", "Облачный сервис датчиков качества воздуха Qingping Air", "safe"),
    ("qingping.com", "iot_cloud", "Qingping", "Инфраструктура датчиков и устройств климата Qingping", "safe"),
    ("tantos.cloud", "iot_cloud", "Tantos", "Облачный сервис домофонии и IP-видеонаблюдения Tantos", "safe"),
    ("smartac.gree.com", "iot_cloud", "Gree Electric", "Управление кондиционерами и климатической техникой Gree / Smart AC", "safe"),
    ("keenetic.cloud", "iot_cloud", "Keenetic", "Облачный сервис управления роутерами Keenetic Cloud", "safe"),
    ("keenetic.net", "iot_cloud", "Keenetic", "Локальный веб-интерфейс или KeenDNS удаленный доступ Keenetic", "safe"),
    ("netcraze.io", "iot_cloud", "Keenetic Cloud", "Служба облачного управления Keenetic Cloud и связи с мобильным приложением (включая релеи KeenDNS)", "safe"),
    ("spruthub", "iot_cloud", "SprutHub", "Хаб автоматизации умного дома SprutHub", "safe"),
    ("alibabacloud.com", "iot_cloud", "Alibaba Cloud IoT", "Облачный брокер умных устройств и датчиков", "safe"),
    ("aliyuncs.com", "iot_cloud", "Alibaba Cloud", "Инфраструктура облачных сервисов Alibaba Cloud", "safe"),
    ("xiaomi.com", "iot_cloud", "Xiaomi", "Экосистема умных устройств Xiaomi Mi Home", "safe"),
    ("mi.com", "iot_cloud", "Xiaomi", "Серверы экосистемы Xiaomi", "safe"),
    ("roborock.com", "iot_cloud", "Roborock", "Облачный сервер роботов-пылесосов Roborock", "safe"),
    ("meethue.com", "iot_cloud", "Philips Hue", "Облачный сервер умного освещения Philips Hue", "safe"),
    ("ewelink.cc", "iot_cloud", "Sonoff / eWeLink", "Облако управления умными реле Sonoff / eWeLink", "safe"),
    ("coolkit.cc", "iot_cloud", "eWeLink", "Серверы авторизации и брокер устройств Sonoff", "safe"),
    ("shelly.cloud", "iot_cloud", "Shelly", "Облачный сервис умного дома Shelly", "safe"),
    ("espressif.com", "iot_cloud", "Espressif Systems", "Облачные обновления и библиотеки микроконтроллеров ESP32/ESP8266", "safe"),
    ("smartthings.com", "iot_cloud", "Samsung SmartThings", "Экосистема умного дома Samsung SmartThings", "safe"),
    ("home-assistant.io", "iot_cloud", "Home Assistant", "Серверы платформы умного дома Home Assistant", "safe"),
    ("home-connect.com", "iot_cloud", "Bosch Home Connect", "Облачная платформа умной бытовой техники Bosch / Siemens Home Connect", "safe"),
    ("bosch-home.com", "iot_cloud", "Bosch", "Серверы бытовой техники Bosch", "safe"),
    ("open-meteo.com", "iot_cloud", "Open-Meteo", "API метеоданных и прогноза погоды для систем умного дома", "safe"),
    ("wttr.in", "iot_cloud", "wttr.in Weather", "Служба метеоданных для скриптов и виджетов автоматизации", "safe"),
    ("lge.com", "iot_cloud", "LG Electronics", "Облачные сервисы и экосистема LG Smart TV (webOS)", "safe"),
    ("lgtvsdp.com", "iot_cloud", "LG Smart TV", "Платформа приложений и медиа-сервисов LG webOS SDP", "safe"),
    ("lgtvcommon.com", "iot_cloud", "LG Smart TV", "Инфраструктурные сервисы LG Smart TV", "safe"),
    ("hicloud.com", "iot_cloud", "Huawei Cloud", "Облачная платформа устройств и экосистемы Huawei HiCloud", "safe"),

    # --- Telemetry, Analytics & Crash Reporting ---
    ("app-measurement.com", "telemetry", "Google Firebase", "Google Firebase Analytics (сбор телеметрии мобильных приложений)", "telemetry"),
    ("crashlytics.com", "telemetry", "Google Crashlytics", "Сбор отчетов о сбоях и ошибках приложений Crashlytics", "telemetry"),
    ("firebaseio.com", "telemetry", "Google Firebase", "База данных реального времени и телеметрия Firebase", "telemetry"),
    ("adjust.com", "telemetry", "Adjust", "Платформа мобильной атрибуции и маркетинговой телеметрии Adjust", "telemetry"),
    ("appsflyer.com", "telemetry", "AppsFlyer", "Маркетинговая атрибуция и аналитика установок AppsFlyer", "telemetry"),
    ("branch.io", "telemetry", "Branch", "Аналитика диплинков и поведения пользователей Branch Metrics", "telemetry"),
    ("sentry.io", "telemetry", "Sentry", "Мониторинг ошибок и сбор сбоев программного обеспечения Sentry", "telemetry"),
    ("flurry.com", "telemetry", "Yahoo / Flurry", "Аналитическая платформа мобильных приложений Flurry", "telemetry"),
    ("mixpanel.com", "telemetry", "Mixpanel", "Продуктовая аналитика и трекинг действий пользователей Mixpanel", "telemetry"),
    ("amplitude.com", "telemetry", "Amplitude", "Система поведенческой аналитики Amplitude", "telemetry"),
    ("metrics.data.hicloud.com", "telemetry", "Huawei HiCloud", "Телеметрия и сбор данных устройств Huawei HiCloud", "telemetry"),
    ("tracking.miui.com", "telemetry", "Xiaomi MIUI", "Сбор телеметрии оболочки MIUI и устройств Xiaomi", "telemetry"),
    ("data.mistat.xiaomi.com", "telemetry", "Xiaomi MiStat", "Статистика использования и аналитика приложений Xiaomi", "telemetry"),
    ("appmetrica.yandex.net", "telemetry", "Yandex AppMetrica", "Аналитика мобильных приложений Яндекс AppMetrica", "telemetry"),
    ("metrika.yandex.ru", "telemetry", "Яндекс Метрика", "Счетчик веб-аналитики Яндекс Метрика", "telemetry"),
    ("google-analytics.com", "telemetry", "Google Analytics", "Сбор статистики посещаемости Google Analytics", "telemetry"),
    ("googletagmanager.com", "telemetry", "Google Tag Manager", "Диспетчер тегов и аналитических пикселей Google", "telemetry"),
    ("events.data.microsoft.com", "telemetry", "Microsoft Telemetry", "Сбор диагностической телеметрии Windows и Office", "telemetry"),
    ("settings-win.data.microsoft.com", "telemetry", "Microsoft Settings Telemetry", "Сбор телеметрии настроек Windows", "telemetry"),
    ("v10.events.data.microsoft.com", "telemetry", "Microsoft Telemetry", "Телеметрия компонентов Windows 10/11", "telemetry"),
    ("browser.pipe.aria.microsoft.com", "telemetry", "Microsoft Edge / Aria", "Телеметрия браузера Microsoft Edge и сервисов Aria", "telemetry"),
    ("samsungcloudsolution.com", "telemetry", "Samsung Smart TV", "Служба телеметрии и обновлений Samsung Smart TV", "telemetry"),
    ("samsungacr.com", "telemetry", "Samsung ACR", "Система автоматического распознавания контента Samsung Smart TV", "telemetry"),
    ("samsungqbe.com", "telemetry", "Samsung TV Telemetry", "Сбор диагностических данных телевизоров Samsung", "telemetry"),
    ("ngfts.lge.com", "telemetry", "LG Smart TV Telemetry", "Сбор телеметрии и краш-репортов LG Smart TV", "telemetry"),
    ("pinpu.online", "telemetry", "Pinpu / Webhook Proxy", "Внешний шлюз передачи данных или вебхуков", "telemetry"),
    ("mobicont.ru", "telemetry", "Mobicont", "Служба маршрутизации сообщений и шлюз передачи данных", "telemetry"),
    ("telemetry.mozilla.org", "telemetry", "Mozilla Telemetry", "Сбор телеметрии браузера Firefox", "telemetry"),

    # --- Advertising & Trackers ---
    ("doubleclick.net", "advertising", "Google DoubleClick", "Рекламная сеть и сервер показа баннеров Google DoubleClick", "ad"),
    ("googleads.g.doubleclick.net", "advertising", "Google Ads", "Сервер доставки рекламы Google Ads", "ad"),
    ("adservice.google.com", "advertising", "Google AdService", "Рекламный сервис Google AdService", "ad"),
    ("pagead2.googlesyndication.com", "advertising", "Google AdSense", "Показ контекстной рекламы Google AdSense", "ad"),
    ("an.yandex.ru", "advertising", "Рекламная сеть Яндекса", "Сервер рекламных баннеров и объявлений РСЯ", "ad"),
    ("adfox.ru", "advertising", "Яндекс AdFox", "Система управления интернет-рекламой AdFox", "ad"),
    ("unityads.unity3d.com", "advertising", "Unity Ads", "Рекламная сеть для мобильных игр Unity Ads", "ad"),
    ("applovin.com", "advertising", "AppLovin", "Мобильная рекламная и монетизационная платформа AppLovin", "ad"),
    ("adcolony.com", "advertising", "AdColony", "Мобильная видеорекламная сеть AdColony", "ad"),
    ("vungle.com", "advertising", "Liftoff / Vungle", "Рекламная сеть внутриигрового видео Vungle", "ad"),
    ("inmobi.com", "advertising", "InMobi", "Платформа мобильной рекламы и таргетинга InMobi", "ad"),
    ("criteo.com", "advertising", "Criteo", "Ретаргетинг и персонализированная баннерная реклама Criteo", "ad"),
    ("adnexus.net", "advertising", "AppNexus / Xandr", "Рекламная биржа и показ баннеров AppNexus / Xandr", "ad"),
    ("appnexus.com", "advertising", "AppNexus / Xandr", "Рекламная сеть AppNexus", "ad"),
    ("samsungadhub.com", "advertising", "Samsung AdHub", "Рекламная сеть Smart TV Samsung AdHub", "ad"),

    # --- System & DNS Services ---
    ("dns.google", "system_dns", "Google Public DNS", "Публичный защищенный DNS-резолвер Google (8.8.8.8 / 8.8.4.4)", "safe"),
    ("one.one.one.one", "system_dns", "Cloudflare DNS", "Публичный высокоскоростной DNS-резолвер Cloudflare (1.1.1.1)", "safe"),
    ("cloudflare-dns.com", "system_dns", "Cloudflare DNS", "Служба безопасного DNS через HTTPS (DoH) Cloudflare", "safe"),
    ("quad9.net", "system_dns", "Quad9 DNS", "Безопасный DNS-резолвер с фильтрацией вредоносных угроз Quad9", "safe"),
    ("adguard-dns.com", "system_dns", "AdGuard DNS", "DNS-сервер с блокировкой рекламы и трекеров AdGuard", "safe"),
    ("ntp.org", "system_dns", "NTP Pool Project", "Глобальный пул серверов синхронизации точного времени по протоколу NTP", "safe"),
    ("time.apple.com", "system_dns", "Apple Time", "Служба точного времени для устройств Apple", "safe"),
    ("time.windows.com", "system_dns", "Microsoft Time", "Служба точного времени операционных систем Windows", "safe"),
    ("time.google.com", "system_dns", "Google Time", "NTP-сервер точного времени Google", "safe"),
    ("connectivitycheck.gstatic.com", "system_dns", "Google Connectivity", "Проверка доступности интернета (Captive Portal) в Android / Chrome", "safe"),
    ("captive.apple.com", "system_dns", "Apple Captive Portal", "Проверка подключения к интернету в экосистеме Apple (iOS / macOS)", "safe"),
    ("msftconnecttest.com", "system_dns", "Microsoft Connectivity", "Проверка подключения к сети в Windows Network Location Awareness", "safe"),
    ("my.keenetic.net", "system_dns", "Keenetic Local", "Локальный веб-интерфейс вашего роутера Keenetic", "safe"),
    ("keenetic.ru", "system_dns", "Keenetic", "Портал проверки подключения и инфраструктурные сервисы роутеров Keenetic", "safe"),
    ("alidns.com", "system_dns", "Alibaba Cloud DNS", "Публичный защищенный DNS-резолвер Alibaba Cloud (223.5.5.5)", "safe"),
    ("use-application-dns.net", "system_dns", "Mozilla Firefox DoH", "Служебный домен Canary Firefox для проверки сетевых политик DoH", "safe"),
    ("awgm-dnscheck.test", "system_dns", "AmneziaWG Check", "Служебный проверочный хост сетевого протокола AmneziaWG", "safe"),
    ("kaspersky-labs.com", "system_dns", "Kaspersky Lab", "Серверы обновлений баз сигнатур Лаборатории Касперского", "safe"),
    ("kaspersky.com", "system_dns", "Kaspersky Lab", "Службы обновлений и антивирусных баз Kaspersky", "safe"),
    ("int08h.com", "system_dns", "Roughtime Network Time", "Криптографический протокол синхронизации точного времени Roughtime (IETF)", "safe"),
    ("nic.ru", "system_dns", "RU-CENTER DNS", "Авторитативные DNS-серверы регистратора RU-CENTER", "safe"),
    ("push.apple.com", "system_dns", "Apple Push Notifications", "Шлюз службы push-уведомлений Apple (APNs)", "safe"),
    ("courier.push.apple.com", "system_dns", "Apple APNs Courier", "Служба доставки push-уведомлений Apple iOS/macOS", "safe"),
    ("weather-data.apple.com", "system_dns", "Apple Weather", "Сервис погодных данных Apple WeatherKit", "safe"),
    ("apple-dns.net", "system_dns", "Apple DNS", "Служба разрешения DNS для инфраструктуры Apple", "safe"),
    ("windowsupdate.com", "system_dns", "Windows Update", "Серверы официальных обновлений безопасности Microsoft Windows", "safe"),
    ("update.microsoft.com", "system_dns", "Windows Update", "Центр обновления Microsoft Windows", "safe"),
    ("msftncsi.com", "system_dns", "Microsoft NCSI", "Индикатор состояния сетевого подключения Microsoft Windows NCSI", "safe"),
    ("example.com", "system_dns", "Example Domain", "Служебный тестовый домен (RFC 2606)", "safe"),

    # --- VPN & Network Tunnels ---
    ("tailscale.com", "vpn_tunnel", "Tailscale", "Релейный сервер координации или защищенного mesh-туннеля Tailscale", "warning"),
    ("wireguard.com", "vpn_tunnel", "WireGuard", "Службы протокола шифрования туннелей WireGuard", "warning"),
    ("zerotier.com", "vpn_tunnel", "ZeroTier", "Служба координации виртуальной SDN-сети ZeroTier", "warning"),
    ("ngrok.io", "vpn_tunnel", "ngrok", "Туннель для проброса локальных портов наружу ngrok (риск несанкционированного доступа)", "warning"),
    ("duckdns.org", "vpn_tunnel", "DuckDNS", "Бесплатная служба динамического DNS DuckDNS", "warning"),
    ("no-ip.com", "vpn_tunnel", "No-IP", "Служба динамического DNS No-IP", "warning"),
    ("no-ip.org", "vpn_tunnel", "No-IP", "Служба динамического DNS No-IP", "warning"),
    ("ddns.net", "vpn_tunnel", "No-IP DDNS", "Динамический хост No-IP DDNS", "warning"),
    ("ddnss.de", "vpn_tunnel", "DDNSS", "Служба динамического DNS DDNSS", "warning"),
    ("freeddns.org", "vpn_tunnel", "FreeDDNS", "Служба динамического DNS", "warning"),

    # --- Media, CDN & Web Platforms ---
    ("cloudfront.net", "cdn_media", "Amazon CloudFront", "Глобальная сеть доставки контента (CDN) Amazon CloudFront", "safe"),
    ("hwclouds-dns.com", "cdn_media", "Huawei Cloud", "Облачная серверная инфраструктура и DNS Huawei Cloud", "safe"),
    ("linodeusercontent.com", "cdn_media", "Linode / Akamai Cloud", "Облачные виртуальные серверы Linode / Akamai Cloud", "safe"),
    ("googleusercontent.com", "cdn_media", "Google Cloud Platform", "Облачные серверы и хранилище данных Google Cloud Platform (GCP)", "safe"),
    ("awsglobalaccelerator.com", "cdn_media", "AWS Global Accelerator", "Служба глобальной оптимизации маршрутов AWS для приложений и устройств", "safe"),
    ("anycast.net", "cdn_media", "Anycast Network", "Распределенная Anycast-сеть маршрутизации трафика", "safe"),
    ("gthost.com", "cdn_media", "GTHost", "Инфраструктура хостинга и серверных дата-центров GTHost", "safe"),
    ("hybridcloudspan.com", "cdn_media", "Hybrid Cloud", "Облачная платформа сетевой инфраструктуры", "safe"),
    ("ogital.net", "cdn_media", "Ogital Network", "Инфраструктура хостинга и дата-центров Ogital", "safe"),
    ("netplaza.fi", "cdn_media", "Netplaza", "Серверные дата-центры и хостинг Netplaza", "safe"),
    ("nwps.fi", "cdn_media", "NWPS Hosting", "Хостинг и облачные серверы NWPS", "safe"),
    ("dclabra.fi", "cdn_media", "DCLabra", "Облачные сервисы и серверные узлы DCLabra", "safe"),
    ("ademant.de", "cdn_media", "Ademant Hosting", "Немецкий серверный хостинг Ademant", "safe"),
    ("ip-91-134-56.eu", "cdn_media", "OVHcloud", "Европейские облачные дата-центры OVHcloud", "safe"),
    ("ovh.net", "cdn_media", "OVHcloud", "Европейские дата-центры OVHcloud", "safe"),
    ("ovhcloud.com", "cdn_media", "OVHcloud", "Облачный провайдер OVHcloud", "safe"),
    ("selectel.ru", "cdn_media", "Selectel", "Российский облачный провайдер Selectel", "safe"),
    ("selcdn.ru", "cdn_media", "Selectel CDN", "Сеть доставки контента Selectel", "safe"),
    ("cdnvideo.ru", "cdn_media", "CDNvideo", "Российская сеть доставки медиаконтента CDNvideo", "safe"),
    ("ngenix.net", "cdn_media", "Ngenix CDN", "Распределенная CDN-платформа Ngenix", "safe"),
    ("yandexcloud.net", "cdn_media", "Yandex Cloud", "Облачные сервисы Yandex Cloud", "safe"),
    ("aup.dk", "cdn_media", "AUP Datacenter", "Европейские облачные серверы AUP", "safe"),
    ("htel.cc", "cdn_media", "HTel Network", "Сетевая инфраструктура связи HTel", "safe"),
    ("obosnett.no", "cdn_media", "Obosnett", "Сетевой узел провайдера Obosnett", "safe"),
    ("as51430.net", "cdn_media", "Alt-N Hosting", "Серверный хостинг AS51430", "safe"),
    ("fxclub.org", "cdn_media", "Forex Club", "Серверы онлайн-платформы Forex Club", "safe"),
    ("valve.net", "cdn_media", "Valve / Steam", "Игровые серверы и сеть дистрибуции контента Steam / Valve", "safe"),
    ("steampowered.com", "cdn_media", "Valve / Steam", "Магазин и сервисы платформы Steam", "safe"),
    ("steamcommunity.com", "cdn_media", "Valve / Steam", "Сообщество и синхронизация платформы Steam", "safe"),
    ("epicgames.com", "cdn_media", "Epic Games", "Игровые сервисы и магазин Epic Games Store", "safe"),
    ("playstation.net", "cdn_media", "Sony PlayStation", "Игровая сеть PlayStation Network (PSN)", "safe"),
    ("playstation.com", "cdn_media", "Sony PlayStation", "Службы экосистемы Sony PlayStation", "safe"),
    ("xboxlive.com", "cdn_media", "Microsoft Xbox", "Серверы игровой сети Xbox Live", "safe"),
    ("rutube.ru", "cdn_media", "RuTube", "Российский видеохостинг RuTube", "safe"),
    ("kinopoisk.ru", "cdn_media", "Кинопоиск", "Онлайн-кинотеатр Кинопоиск (Яндекс)", "safe"),
    ("ivi.ru", "cdn_media", "Иви (ivi)", "Онлайн-кинотеатр Иви", "safe"),
    ("okko.tv", "cdn_media", "Okko", "Мультимедийный сервис Okko", "safe"),
    ("kion.ru", "cdn_media", "KION", "Онлайн-кинотеатр KION", "safe"),
    ("premier.one", "cdn_media", "Premier", "Онлайн-кинотеатр Premier", "safe"),
    ("twitch.tv", "cdn_media", "Twitch", "Стриминговая платформа Twitch", "safe"),
    ("spotify.com", "cdn_media", "Spotify", "Музыкальный стриминговый сервис Spotify", "safe"),
    ("aaplimg.com", "cdn_media", "Apple Media CDN", "Сеть доставки медиа и графических ресурсов Apple", "safe"),
    ("avito.ru", "cdn_media", "Авито", "Пользовательские сервисы платформы Авито", "safe"),
    ("akamaitechnologies.com", "cdn_media", "Akamai Technologies", "Глобальная сеть доставки контента (CDN) Akamai", "safe"),
    ("akamaihd.net", "cdn_media", "Akamai CDN", "Медиа-сервер доставки видео и контента Akamai HD", "safe"),
    ("cloudflare.com", "cdn_media", "Cloudflare", "CDN-сеть и защита от DDoS-атак Cloudflare", "safe"),
    ("1e100.net", "cdn_media", "Google Infrastructure", "Обратная PTR-зона серверов инфраструктуры Google", "safe"),
    ("google.com", "cdn_media", "Google Services", "Сервисы и поисковая инфраструктура Google", "safe"),
    ("googleapis.com", "cdn_media", "Google APIs", "Шлюз программных интерфейсов Google APIs", "safe"),
    ("gstatic.com", "cdn_media", "Google Static", "Статические ресурсы (шрифты, скрипты, стили) Google", "safe"),
    ("youtube.com", "cdn_media", "YouTube", "Видеохостинг YouTube", "safe"),
    ("googlevideo.com", "cdn_media", "Google Video CDN", "Серверы доставки видеопотоков YouTube", "safe"),
    ("apple.com", "cdn_media", "Apple Services", "Сервисы и обновления экосистемы Apple", "safe"),
    ("icloud.com", "cdn_media", "Apple iCloud", "Облачное хранилище и синхронизация данных Apple iCloud", "safe"),
    ("apple-cloudkit.com", "cdn_media", "Apple CloudKit", "Облачная база данных и синхронизация приложений Apple CloudKit", "safe"),
    ("vk.com", "cdn_media", "VKontakte", "Социальная сеть и медиа-сервисы ВКонтакте", "safe"),
    ("userapi.com", "cdn_media", "VK Static", "Хранилище медиафайлов и изображений ВКонтакте", "safe"),
    ("vk.me", "cdn_media", "VK Messenger", "Серверы обмена сообщениями ВКонтакте", "safe"),
    ("telegram.org", "cdn_media", "Telegram", "Серверы и дата-центры мессенджера Telegram", "safe"),
    ("t.me", "cdn_media", "Telegram", "Сервис коротких ссылок мессенджера Telegram", "safe"),
    ("facebook.com", "cdn_media", "Meta / Facebook", "Инфраструктура и серверы платформы Meta / Facebook", "safe"),
    ("fbcdn.net", "cdn_media", "Meta CDN", "Сеть доставки медиаконтента Facebook / Instagram", "safe"),
    ("instagram.com", "cdn_media", "Meta / Instagram", "Сервисы и API платформы Instagram", "safe"),
    ("whatsapp.net", "cdn_media", "Meta / WhatsApp", "Серверы передачи сообщений WhatsApp", "safe"),
    ("yandex.ru", "cdn_media", "Яндекс", "Поисковые и пользовательские сервисы Яндекс", "safe"),
    ("yandex.net", "cdn_media", "Яндекс CDN", "Распределенная инфраструктура доставки сервисов Яндекс", "safe"),
    ("mail.ru", "cdn_media", "VK Group / Mail.ru", "Почтовые и контентные сервисы Mail.ru", "safe"),
    ("amazonaws.com", "cdn_media", "Amazon AWS", "Облачная платформа веб-сервисов Amazon AWS", "safe"),
    ("azure.com", "cdn_media", "Microsoft Azure", "Облачные вычисления и инфраструктура Microsoft Azure", "safe"),
    ("your-server.de", "cdn_media", "Hetzner Online", "Дата-центры и серверный хостинг Hetzner Online", "safe"),

    # --- Smart TV Telemetry & Ad Trackers ---
    ("emp.lgsmartad.com", "advertising", "LG webOS Ad Server", "Сервер баннеров LG webOS Ad Server", "ad"),
    ("lgtvcommon.com", "telemetry", "LG Cloud Gateway", "LG Cloud Gateway (сбор логов и диагностика)", "telemetry"),
    ("smartshare.lgtvsdp.com", "telemetry", "LG SDP Platform", "LG SDP Platform (фоновая телеметрия сервисов)", "telemetry"),
    ("ibs.lgappstv.com", "telemetry", "LG App Store Analytics", "LG App Store Analytics (трекинг кликов и приложений)", "telemetry"),
    ("rdx2.lgtvsdp.com", "telemetry", "LG Live Plus (ACR)", "LG Live Plus / ACR (распознавание контента)", "telemetry"),
    ("ad.lgappstv.com", "advertising", "LG Content Store Ads", "LG Content Store Ads (реклама в каталоге)", "ad"),
    ("aic.lgtvcommon.com", "telemetry", "LG ThinQ Voice Analytics", "LG AI ThinQ Voice Analytics (поведенческий профиль)", "telemetry"),
    ("ngfts.lge.com", "telemetry", "LG Smart TV Telemetry", "Сбор телеметрии и краш-репортов LG Smart TV", "telemetry"),
    ("samsungacr.com", "telemetry", "Samsung ACR", "Система автоматического распознавания контента Samsung Smart TV", "telemetry"),
    ("samsungads.com", "advertising", "Samsung Ads", "Платформа таргетированной рекламы Samsung Ads", "ad"),
    ("samsungcloudplatform.com", "telemetry", "Samsung Cloud Platform", "Облачная телеметрия сервисов платформы Samsung", "telemetry"),
    ("log-config.samsungcloud.com", "telemetry", "Samsung Log Config", "Динамическая конфигурация сбора логов Samsung", "telemetry"),
    ("config.samsungcloud.com", "telemetry", "Samsung Config", "Удаленная настройка параметров трекинга", "telemetry"),
    ("samsungcloudsolution.com", "telemetry", "Samsung Smart TV", "Служба телеметрии и обновлений Samsung Smart TV", "telemetry"),
    ("samsungqbe.com", "telemetry", "Samsung TV Telemetry", "Сбор диагностических данных телевизоров Samsung", "telemetry"),
    ("gpm.samsungqbe.com", "telemetry", "Samsung QBE Metrics", "Samsung QBE Metrics (метрики системных процессов)", "telemetry"),
    ("adservice.google.com", "advertising", "Google AdService", "Рекламный сервис Google AdService", "ad"),
    ("pagead2.googlesyndication.com", "advertising", "Google AdSense", "Показ контекстной рекламы Google AdSense", "ad"),
    ("ad.xiaomi.com", "advertising", "Xiaomi PatchWall Ads", "Рекламные карточки и промо в оболочке PatchWall", "ad"),
    ("tracking.miui.com", "telemetry", "Xiaomi MIUI", "Сбор телеметрии оболочки MIUI и устройств Xiaomi", "telemetry"),
    ("data.mistat.xiaomi.com", "telemetry", "Xiaomi MiStat", "Статистика использования и аналитика приложений Xiaomi", "telemetry"),
    ("api.ad.xiaomi.com", "advertising", "Xiaomi Ad Engine", "API персонализированной рекламы Xiaomi", "ad"),
    ("o2o.api.xiaomi.com", "telemetry", "Xiaomi O2O Recommendations", "Сервер товарных рекомендаций и таргетинга Xiaomi", "telemetry"),
    ("metrics.apple.com", "telemetry", "Apple Diagnostics Metrics", "Системная диагностическая телеметрия Apple", "telemetry"),
    ("notes-analytics-events.apple.com", "telemetry", "Apple Analytics Events", "Сбор событий аналитики и взаимодействий", "telemetry"),
    ("xp.apple.com", "telemetry", "Apple App Store XP", "Аналитика переходов и покупок в App Store", "telemetry"),

    # --- High Risk & Suspicious ---
    ("exampleadultsite.com", "suspicious", "Adult / Test", "Тестовый домен контента 18+ для проверки родительского контроля", "danger"),
    ("russianbridesnetwork.com", "suspicious", "Dating / Spambot", "Подозрительный спам-домен или хост генерации трафика", "danger"),
]

# Subdomain heuristics token matching
HEURISTIC_TOKENS: List[Tuple[re.Pattern, str, str, str, str]] = [
    (re.compile(r"(^|\.)(ad|ads|banner|popunder|adservice|adserver)\.", re.I), "advertising", "Рекламный сервис", "Обнаружены признаки показа баннеров или рекламы", "ad"),
    (re.compile(r"(^|\.)(telemetry|analytics|metrics|metric|tracking|stats|stat|crash|sentry|logger|diagnostics|collector)\.", re.I), "telemetry", "Служба аналитики", "Сбор пользовательской активности, телеметрии или краш-репортов", "telemetry"),
    (re.compile(r"(^|\.)(iot|smart|broker|p2p|device|smarthome)\.", re.I), "iot_cloud", "IoT-платформа", "Сервис межмашинного взаимодействия (M2M) или умного дома", "safe"),
    (re.compile(r"(^|\.)(dns|ntp|time|portal|captive|gateway)\.", re.I), "system_dns", "Системная служба", "Служебный инфраструктурный запрос (время, DNS, портал)", "safe"),
    (re.compile(r"\.in-addr\.arpa$", re.I), "system_dns", "Обратный DNS (rDNS PTR)", "Служебный инфраструктурный запрос разрешения IP-адреса", "safe"),
    (re.compile(r"(^|\.)(derp|vpn|tunnel|relay|wireguard|mesh)\.", re.I), "vpn_tunnel", "Сетевой релей / VPN", "Используется для маршрутизации или туннелирования трафика", "warning"),
    (re.compile(r"(^|\.)(cdn|edge|cache|proxy|origin|static|media|video|stream|compute|cloud|hosting|vps)\.", re.I), "cdn_media", "Сеть доставки CDN / Хостинг", "Распределенная доставка контента или облачные серверные узлы", "safe"),
    (re.compile(r"(\b(customer|clients|dynamic|static|rev|vps|host|infra)\b|\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3})", re.I), "cdn_media", "Хостинг / Провайдер (rDNS)", "Обратная PTR-запись IP-адреса хостинга или провайдера", "safe"),
]


SINKHOLE_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1", "0.0.0.0/0"}


# Smart TV Brand DNS Sinkhole Presets
TV_BRAND_PRESETS: Dict[str, Dict[str, Any]] = {
    "tv_lg": {
        "id": "tv_lg",
        "name": "LG webOS Smart TV",
        "icon": "tv",
        "keywords": ["lg", "oled", "webos", "lg electronics", "smarttv", "lg_smart_tv"],
        "manual_hint": (
            "На пульте Magic Remote: Настройки (шестерёнка) → Все настройки → Поддержка → "
            "Дополнительные настройки → «Live Plus» (отключить). Затем «Условия конфиденциальности» → "
            "отключить «Персонализированная реклама» и «Просмотр телепередач/голосовая информация»."
        ),
        "doh_remedy_hint": (
            "Для блокировки зашитого DoT (DNS-over-TLS) на порту 853 добавьте в Keenetic правило: "
            "Запретить TCP/UDP 853 для IP вашего телевизора LG."
        ),
        "domains": [
            {"domain": "emp.lgsmartad.com", "name": "LG Ad Server", "category": "advertising", "risk": "ad", "description": "Сервер баннеров LG webOS Ad Server"},
            {"domain": "lgtvcommon.com", "name": "LG Cloud Gateway", "category": "telemetry", "risk": "telemetry", "description": "LG Cloud Gateway (сбор логов и диагностика)"},
            {"domain": "smartshare.lgtvsdp.com", "name": "LG SDP Platform", "category": "telemetry", "risk": "telemetry", "description": "LG SDP Platform (фоновая телеметрия сервисов)"},
            {"domain": "ibs.lgappstv.com", "name": "LG App Store Analytics", "category": "telemetry", "risk": "telemetry", "description": "LG App Store Analytics (трекинг кликов и приложений)"},
            {"domain": "rdx2.lgtvsdp.com", "name": "LG Live Plus (ACR)", "category": "telemetry", "risk": "telemetry", "description": "LG Live Plus / ACR (распознавание контента)"},
            {"domain": "ad.lgappstv.com", "name": "LG Content Store Ads", "category": "advertising", "risk": "ad", "description": "LG Content Store Ads (реклама в каталоге)"},
            {"domain": "aic.lgtvcommon.com", "name": "LG ThinQ Voice Analytics", "category": "telemetry", "risk": "telemetry", "description": "LG AI ThinQ Voice Analytics (поведенческий профиль)"},
            {"domain": "ngfts.lge.com", "name": "LG Crash & Diagnostics", "category": "telemetry", "risk": "telemetry", "description": "LG Crash & Diagnostics (сбор дампов и краш-репортов)"},
        ]
    },
    "tv_samsung": {
        "id": "tv_samsung",
        "name": "Samsung Tizen Smart TV",
        "icon": "monitor",
        "keywords": ["samsung", "tizen", "smart hub", "samsung electronics", "sec_"],
        "manual_hint": (
            "На пульте Samsung: Настройки → Все настройки → Общие и конфиденциальность → "
            "Условия и положения → Снять галочки с: «Службы распознавания контента (ACR)», "
            "«Служба голосового распознавания» и «Реклама на основе интересов»."
        ),
        "doh_remedy_hint": (
            "Samsung Tizen может использовать DoH/DoT. Заблокируйте исходящий порт 853 для Samsung TV "
            "в настройках сетевых правил Keenetic."
        ),
        "domains": [
            {"domain": "samsungacr.com", "name": "Samsung ACR Engine", "category": "telemetry", "risk": "telemetry", "description": "Samsung ACR (распознавание эфира и передач в реальном времени)"},
            {"domain": "samsungads.com", "name": "Samsung Ads", "category": "advertising", "risk": "ad", "description": "Платформа таргетированной рекламы Samsung Ads"},
            {"domain": "samsungcloudplatform.com", "name": "Samsung Cloud Platform", "category": "telemetry", "risk": "telemetry", "description": "Облачная телеметрия сервисов платформы Samsung"},
            {"domain": "log-config.samsungcloud.com", "name": "Samsung Log Config", "category": "telemetry", "risk": "telemetry", "description": "Динамическая конфигурация сбора логов Samsung"},
            {"domain": "config.samsungcloud.com", "name": "Samsung Config", "category": "telemetry", "risk": "telemetry", "description": "Удаленная настройка параметров трекинга"},
            {"domain": "samsungcloudsolution.com", "name": "Samsung Cloud Solution", "category": "telemetry", "risk": "telemetry", "description": "Сбор телеметрии и диагностических данных"},
            {"domain": "samsungqbe.com", "name": "Samsung QBE Diagnostics", "category": "telemetry", "risk": "telemetry", "description": "Диагностические логи ошибок и сбоев Tizen"},
            {"domain": "gpm.samsungqbe.com", "name": "Samsung QBE Metrics", "category": "telemetry", "risk": "telemetry", "description": "Samsung QBE Metrics (метрики системных процессов)"},
        ]
    },
    "tv_android_google": {
        "id": "tv_android_google",
        "name": "Android TV & Google TV",
        "icon": "bot",
        "keywords": ["android", "google", "chromecast", "sony", "bravia", "philips", "tcl", "hisense", "mibox"],
        "manual_hint": (
            "В меню: Настройки → Аккаунты и вход → [Аккаунт Google] → «Реклама» → "
            "включить «Удалить рекламный идентификатор». В Настройки → Система → "
            "Об устройстве → отключить «Использование и диагностика»."
        ),
        "doh_remedy_hint": (
            "Для Chromecast и Android TV с жестким 8.8.8.8 настройте в Keenetic перенаправление (DNAT) "
            "всех DNS-запросов (порт 53) на локальный адрес роутера 192.168.1.1."
        ),
        "domains": [
            {"domain": "adservice.google.com", "name": "Google AdService", "category": "advertising", "risk": "ad", "description": "Сервис рекламы и спонсорского промо на главном экране"},
            {"domain": "pagead2.googlesyndication.com", "name": "Google AdSense", "category": "advertising", "risk": "ad", "description": "Баннерная реклама Google AdSense в приложениях"},
            {"domain": "google-analytics.com", "name": "Google Analytics", "category": "telemetry", "risk": "telemetry", "description": "Google Analytics для Smart TV"},
            {"domain": "firebaselogging.googleapis.com", "name": "Firebase Logging", "category": "telemetry", "risk": "telemetry", "description": "Диагностическое логирование Firebase"},
            {"domain": "app-measurement.com", "name": "App Measurement", "category": "telemetry", "risk": "telemetry", "description": "Трекинг событий и аналитика мобильных приложений ТВ"},
            {"domain": "doubleclick.net", "name": "Google DoubleClick", "category": "advertising", "risk": "ad", "description": "Глобальная сеть показа баннеров Google"},
        ]
    },
    "tv_xiaomi": {
        "id": "tv_xiaomi",
        "name": "Xiaomi PatchWall & Mi TV",
        "icon": "smartphone",
        "keywords": ["xiaomi", "patchwall", "redmi", "mitv", "mi_box", "mi box"],
        "manual_hint": (
            "В меню Xiaomi: Настройки устройства → Конфиденциальность → «Использование и диагностика» (отключить); "
            "Настройки PatchWall → «Персонализация» (отключить)."
        ),
        "doh_remedy_hint": (
            "Оболочка PatchWall периодически обращается к IP-адресам напрямую. Блокировка 0.0.0.0 "
            "останавливает доменные баннеры и сбор логов MiStat."
        ),
        "domains": [
            {"domain": "ad.xiaomi.com", "name": "Xiaomi PatchWall Ads", "category": "advertising", "risk": "ad", "description": "Рекламные карточки и промо в оболочке PatchWall"},
            {"domain": "tracking.miui.com", "name": "MIUI TV Tracking", "category": "telemetry", "risk": "telemetry", "description": "Сбор телеметрии оболочки PatchWall / MIUI TV"},
            {"domain": "data.mistat.xiaomi.com", "name": "MiStat Analytics", "category": "telemetry", "risk": "telemetry", "description": "Статистика кликов и использования приложений MiStat"},
            {"domain": "api.ad.xiaomi.com", "name": "Xiaomi Ad Engine", "category": "advertising", "risk": "ad", "description": "API персонализированной рекламы Xiaomi"},
            {"domain": "o2o.api.xiaomi.com", "name": "Xiaomi O2O Recommendations", "category": "telemetry", "risk": "telemetry", "description": "Сервер товарных рекомендаций и таргетинга Xiaomi"},
        ]
    },
    "tv_apple": {
        "id": "tv_apple",
        "name": "Apple TV (tvOS)",
        "icon": "apple",
        "keywords": ["apple tv", "appletv", "apple-tv"],
        "manual_hint": (
            "В меню приставки: Настройки → Основные → Конфиденциальность → "
            "«Делиться аналитикой Apple TV» (выключить) и «Отслеживание» (запретить приложениям запрашивать разрешение)."
        ),
        "doh_remedy_hint": (
            "Критические домены Apple (appleid, icloud, push, appletv) защищены от блокировки "
            "для сохранения стабильности AirPlay и стриминга Apple TV+."
        ),
        "domains": [
            {"domain": "metrics.apple.com", "name": "Apple Diagnostics Metrics", "category": "telemetry", "risk": "telemetry", "description": "Системная диагностическая телеметрия Apple"},
            {"domain": "notes-analytics-events.apple.com", "name": "Apple Analytics Events", "category": "telemetry", "risk": "telemetry", "description": "Сбор событий аналитики и взаимодействий"},
            {"domain": "xp.apple.com", "name": "Apple App Store XP", "category": "telemetry", "risk": "telemetry", "description": "Аналитика переходов и покупок в App Store"},
        ]
    }
}


def detect_tv_brand(device_info: Dict[str, Any]) -> Optional[str]:
    """
    Detects Smart TV brand preset from device attributes (hostname, vendor, custom_name, model).
    Returns preset_id ('tv_lg', 'tv_samsung', 'tv_android_google', 'tv_xiaomi', 'tv_apple') or None.
    """
    if not device_info:
        return None

    fields_to_check = [
        str(device_info.get("custom_name") or ""),
        str(device_info.get("hostname") or ""),
        str(device_info.get("vendor") or ""),
        str(device_info.get("model") or "")
    ]
    haystack = " ".join(fields_to_check).lower()

    # Match Apple TV first to avoid generic match with other Apple devices
    for keyword in TV_BRAND_PRESETS["tv_apple"]["keywords"]:
        if keyword in haystack:
            return "tv_apple"

    # Match other brands
    for preset_id, preset in TV_BRAND_PRESETS.items():
        if preset_id == "tv_apple":
            continue
        for keyword in preset["keywords"]:
            if keyword in haystack:
                return preset_id

    return None


def get_tv_brand_presets(active_sinkholes: Optional[set] = None) -> List[Dict[str, Any]]:
    """
    Returns list of brand presets enriched with domain active statuses and counts.
    """
    active_set = set(d.lower().strip() for d in active_sinkholes) if active_sinkholes else set()
    result = []
    for preset_id, preset in TV_BRAND_PRESETS.items():
        enriched_domains = []
        active_count = 0
        for item in preset["domains"]:
            dom = item["domain"].lower().strip()
            is_active = dom in active_set
            if is_active:
                active_count += 1
            enriched_domains.append({
                "domain": dom,
                "name": item["name"],
                "category": item["category"],
                "risk": item["risk"],
                "description": item["description"],
                "is_active": is_active
            })
        result.append({
            "id": preset_id,
            "name": preset["name"],
            "icon": preset["icon"],
            "manual_hint": preset["manual_hint"],
            "doh_remedy_hint": preset.get("doh_remedy_hint", ""),
            "domains": enriched_domains,
            "total_count": len(enriched_domains),
            "active_count": active_count,
            "is_fully_blocked": active_count == len(enriched_domains) if enriched_domains else False
        })
    return result


class DomainAnalyzer:
    """Intelligent classification and reputation inspection engine for network domains."""

    def __init__(self):
        self._custom_rules: Dict[str, Dict[str, Any]] = {}
        self._db_signatures: Dict[str, Dict[str, Any]] = {}
        self._sinkhole_cache: Dict[str, Tuple[Optional[str], float]] = {}
        self._last_sync: float = 0.0

    @staticmethod
    def is_sinkhole_ip(ip: Optional[str]) -> bool:
        """Determines whether an IP address represents a DNS sinkhole (e.g. 0.0.0.0 or 127.0.0.1)."""
        if not ip:
            return False
        clean_ip = str(ip).strip()
        return clean_ip in SINKHOLE_IPS

    async def check_domain_sinkhole_async(self, domain: str, dns_server: str = "192.168.1.1", timeout: float = 0.3) -> Optional[str]:
        """Checks if a domain resolves to a sinkhole IP on the router DNS server (e.g. NextDNS / AdGuard)."""
        if not domain or "." not in domain:
            return None
        clean_d = domain.lower().strip().strip(".")
        import time
        now = time.time()
        cached = self._sinkhole_cache.get(clean_d)
        if cached and (now - cached[1] < 600):  # 10 min cache
            return cached[0]

        import asyncio, socket, struct
        loop = asyncio.get_running_loop()

        def _query():
            ID = 0x4321
            flags = 0x0100
            header = struct.pack('!HHHHHH', ID, flags, 1, 0, 0, 0)
            qname = b''.join(bytes([len(p)]) + p.encode() for p in clean_d.split('.')) + b'\x00'
            packet = header + qname + struct.pack('!HH', 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(packet, (dns_server, 53))
                data, _ = s.recvfrom(512)
                ans_offset = 12 + len(qname) + 4
                if len(data) >= ans_offset + 12:
                    rdlen = struct.unpack('!H', data[ans_offset+10:ans_offset+12])[0]
                    ip = socket.inet_ntoa(data[ans_offset+12:ans_offset+12+rdlen])
                    return ip
            except Exception:
                return None
            finally:
                s.close()
            return None

        resolved_ip = None
        try:
            resolved_ip = await loop.run_in_executor(None, _query)
        except Exception:
            resolved_ip = None

        self._sinkhole_cache[clean_d] = (resolved_ip, now)
        return resolved_ip

    async def check_sinkholes_batch(self, domains: List[str], dns_server: str = "192.168.1.1") -> Dict[str, Optional[str]]:
        """Batch checks multiple domains against the router sinkhole resolver."""
        tasks = [self.check_domain_sinkhole_async(d, dns_server=dns_server) for d in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        res_map = {}
        for d, r in zip(domains, results):
            if isinstance(r, str):
                res_map[d] = r
            else:
                res_map[d] = None
        return res_map

    def analyze_domain(
        self,
        domain: str,
        ip: Optional[str] = None,
        is_blocked: Optional[bool] = None,
        blocked_reason: Optional[str] = None,
        blocked_by_provider: Optional[str] = None,
        filter_list: Optional[str] = None,
        tracker_category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronously analyzes a domain using local signatures, custom overrides, and heuristics."""
        if is_blocked is None:
            is_blocked = self.is_sinkhole_ip(ip)
        if is_blocked and not blocked_reason:
            if blocked_by_provider:
                blocked_reason = f"Заблокирован {blocked_by_provider} (0.0.0.0)"
            else:
                blocked_reason = "Заблокирован DNS-фильтром (0.0.0.0)"

        if not domain:
            return self._build_verdict(
                "unknown", domain or "", ip=ip,
                is_blocked=is_blocked, blocked_reason=blocked_reason,
                blocked_by_provider=blocked_by_provider, filter_list=filter_list,
                tracker_category=tracker_category,
            )

        clean_d = domain.lower().strip().strip(".")

        # 1. Check custom user rules first (highest priority)
        if clean_d in self._custom_rules:
            custom = self._custom_rules[clean_d]
            cat_id = custom.get("category", "unknown")
            return self._build_verdict(
                cat_id, clean_d,
                vendor="Пользовательское правило",
                description=custom.get("description") or f"Пользовательская классификация ({cat_id})",
                risk_level=custom.get("risk_level"),
                ip=ip,
                is_custom=True,
                is_blocked=is_blocked,
                blocked_reason=blocked_reason,
                blocked_by_provider=blocked_by_provider,
                filter_list=filter_list,
                tracker_category=tracker_category,
            )

        # 2. Check dynamic database signatures (e.g. from online updates)
        if clean_d in self._db_signatures:
            sig = self._db_signatures[clean_d]
            cat_id = sig.get("category", "unknown")
            return self._build_verdict(
                cat_id, clean_d,
                vendor=sig.get("source", "Обновленная база"),
                description=sig.get("description") or f"Сигнатура безопасности ({cat_id})",
                risk_level=sig.get("risk_level"),
                ip=ip,
                is_blocked=is_blocked,
                blocked_reason=blocked_reason,
                blocked_by_provider=blocked_by_provider,
                filter_list=filter_list,
                tracker_category=tracker_category,
            )

        # 3. Exact or suffix match against built-in curated catalog
        for pattern, cat, vendor, desc, risk in KNOWN_DOMAIN_RULES:
            if clean_d == pattern or clean_d.endswith("." + pattern) or (pattern in clean_d and "." not in pattern):
                return self._build_verdict(
                    cat, clean_d,
                    vendor=vendor,
                    description=desc,
                    risk_level=risk,
                    ip=ip,
                    is_blocked=is_blocked,
                    blocked_reason=blocked_reason,
                    blocked_by_provider=blocked_by_provider,
                    filter_list=filter_list,
                    tracker_category=tracker_category,
                )

        # 4. Heuristic token inspection on subdomains
        for regex, cat, vendor, desc, risk in HEURISTIC_TOKENS:
            if regex.search(clean_d):
                return self._build_verdict(
                    cat, clean_d,
                    vendor=vendor,
                    description=desc,
                    risk_level=risk,
                    ip=ip,
                    is_blocked=is_blocked,
                    blocked_reason=blocked_reason,
                    blocked_by_provider=blocked_by_provider,
                    filter_list=filter_list,
                    tracker_category=tracker_category,
                )

        # 5. Fallback heuristics: IP or unknown
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_d):
            return self._build_verdict(
                "system_dns", clean_d,
                vendor="Прямой IP-адрес",
                description="Прямое обращение по IPv4 без доменного имени",
                risk_level="warning",
                ip=clean_d,
                is_blocked=is_blocked,
                blocked_reason=blocked_reason,
                blocked_by_provider=blocked_by_provider,
                filter_list=filter_list,
                tracker_category=tracker_category,
            )

        # Default unknown
        return self._build_verdict(
            "unknown", clean_d,
            vendor="Неизвестный сервис",
            description="Домен отсутствует в известных каталогах безопасности",
            risk_level="neutral",
            ip=ip,
            is_blocked=is_blocked,
            blocked_reason=blocked_reason,
            blocked_by_provider=blocked_by_provider,
            filter_list=filter_list,
            tracker_category=tracker_category,
        )

    def _build_verdict(
        self,
        category_id: str,
        domain: str,
        vendor: Optional[str] = None,
        description: Optional[str] = None,
        risk_level: Optional[str] = None,
        ip: Optional[str] = None,
        is_custom: bool = False,
        is_blocked: bool = False,
        blocked_reason: Optional[str] = None,
        blocked_by_provider: Optional[str] = None,
        filter_list: Optional[str] = None,
        tracker_category: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Constructs a complete diagnostic verdict structure for the domain."""
        cat_meta = CATEGORIES.get(category_id, CATEGORIES["unknown"])
        actual_risk = risk_level or cat_meta["default_risk"]

        # Formulate badge text and color based on risk and category
        badge_text = cat_meta["badge_text"]
        badge_color = cat_meta["badge_color"]

        if actual_risk == "danger":
            badge_color = "rose"
            badge_text = "Высокий риск"
        elif actual_risk == "warning":
            badge_color = "purple"
            badge_text = "Внимание"
        elif actual_risk == "ad":
            badge_color = "rose"
            badge_text = "Реклама"
        elif actual_risk == "telemetry":
            badge_color = "amber"
            badge_text = "Телеметрия"

        # External threat intel and reputation check links
        vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
        whois_url = f"https://who.is/whois/{domain}"
        abuse_url = f"https://www.abuseipdb.com/check/{ip}" if ip else None

        # Keenetic security recommendation tip
        keenetic_tip = ""
        if is_blocked:
            if blocked_by_provider:
                provider_display_names = {
                    "nextdns": "NextDNS",
                    "controld": "Control D",
                    "adguard_home": "AdGuard Home",
                    "pihole": "Pi-hole",
                    "keenetic_sinkhole": "Keenetic 0.0.0.0",
                }
                p_name = provider_display_names.get(blocked_by_provider, blocked_by_provider)
                rule_info = f" ({filter_list})" if filter_list else ""
                keenetic_tip = f"Запрос заблокирован провайдером безопасности {p_name}{rule_info}. Обращение к узлу перехвачено на DNS-уровне, пакеты не выходили в интернет."
            else:
                keenetic_tip = "Домен заблокирован и перенаправлен в 0.0.0.0 сетевым фильтром. Запросы от клиентов не выходят в интернет."
        elif actual_risk in ("ad", "telemetry"):
            keenetic_tip = "Для блокировки: перейдите в веб-интерфейс Keenetic -> 'Сетевые правила' -> 'Интернет-фильтр' и назначьте профиль AdGuard DNS / NextDNS, либо добавьте домен в чёрный список."
        elif actual_risk in ("danger", "warning"):
            keenetic_tip = "Рекомендуется проверить подключенные устройства и заблокировать домен в «Сетевые правила» → «Интернет-фильтр» (или через чёрный список NextDNS / AdGuard), либо заблокировать IP-адрес узла в «Межсетевом экране»."
        elif category_id == "iot_cloud":
            keenetic_tip = "Легитимный домен умного дома. Рекомендуется разрешить и добавить устройство в изолированный сегмент IoT."
        else:
            keenetic_tip = "Штатный сетевой трафик. Особых действий со стороны администратора сети не требуется."

        # Determine block safety rating and plain explanation
        if actual_risk == "ad" or category_id == "advertising":
            block_safety = "safe"
            safety_label = "Безопасно блокировать"
            safety_color = "emerald"
            impact_explanation = "Рекламный сервис. Блокировка полностью безопасна: баннеры и рекламные ролики перестанут загружаться, сайты и приложения продолжат работать штатно."
        elif actual_risk == "telemetry" or category_id == "telemetry":
            block_safety = "telemetry_safe"
            safety_label = "Блокировка без потери функций"
            safety_color = "amber"
            impact_explanation = "Сбор телеметрии и аналитики. Блокировка безопасна: устройство перестанет передавать метрики и профиль использования, основные функции продолжат работать."
        elif actual_risk == "danger" or category_id == "suspicious":
            block_safety = "threat"
            safety_label = "Рекомендуется заблокировать"
            safety_color = "rose"
            impact_explanation = "Потенциально вредоносный или опасный сервис. Рекомендуется заблокировать для защиты устройств сети."
        elif category_id in ("iot_cloud", "system_dns", "vpn_tunnel"):
            block_safety = "dangerous"
            safety_label = "Опасно блокировать"
            safety_color = "rose"
            impact_explanation = "Критическая инфраструктура или облако умного дома. Внимание! Блокировка нарушит связь с устройством или работу сети."
        else:
            block_safety = "neutral"
            safety_label = "Не классифицирован"
            safety_color = "slate"
            impact_explanation = "Назначение домена точно не определено. Перед блокировкой проверьте репутацию."

        return {
            "domain": domain,
            "ip": ip,
            "category": category_id,
            "category_name": cat_meta["name"],
            "risk_level": actual_risk,
            "badge_text": badge_text,
            "badge_color": badge_color,
            "block_safety": block_safety,
            "safety_label": safety_label,
            "safety_color": safety_color,
            "impact_explanation": impact_explanation,
            "vendor": vendor or "Неизвестный вендор",
            "description": description or cat_meta["recommendation"],
            "recommendation": cat_meta["recommendation"],
            "keenetic_tip": keenetic_tip,
            "is_custom": is_custom,
            "is_blocked": is_blocked,
            "blocked_badge": "🛡️ Заблокирован (0.0.0.0)" if is_blocked else "",
            "blocked_reason": blocked_reason or ("Заблокирован DNS-фильтром (0.0.0.0)" if is_blocked else ""),
            "blocked_by_provider": blocked_by_provider,
            "filter_list": filter_list,
            "tracker_category": tracker_category,
            "external_links": {
                "virustotal": vt_url,
                "whois": whois_url,
                "abuseipdb": abuse_url
            }
        }

    async def load_custom_rules_and_signatures(self, database=None):
        """Loads custom user overrides and cached signatures from SQLite database."""
        try:
            target_db = database or db
            self._custom_rules = await target_db.get_custom_domain_rules()
            self._db_signatures = await target_db.get_domain_signatures()
            logger.debug("Loaded %d custom domain rules and %d signatures",
                         len(self._custom_rules), len(self._db_signatures))
        except Exception as e:
            logger.warning("Could not load custom domain rules or signatures from db: %s", e)

    async def update_signatures_from_online(self, database=None) -> Dict[str, Any]:
        """Fetches curated open threat & blocklists and caches signatures to SQLite."""
        target_db = database or db
        import httpx

        fetched_count = 0
        sources = [
            # AdGuard DNS filter list (official mirror)
            ("https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/filter.txt", "adguard"),
            # StevenBlack unified hosts mirror for adware & malware
            ("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "stevenblack")
        ]

        new_signatures: List[Dict[str, Any]] = []

        # Default fallback curated seed signatures if offline
        curated_seeds = [
            {"pattern": "report.appmetrica.yandex.net", "category": "telemetry", "risk_level": "telemetry", "description": "Яндекс AppMetrica Аналитика", "source": "curated"},
            {"pattern": "appmetrica.yandex.net", "category": "telemetry", "risk_level": "telemetry", "description": "Яндекс AppMetrica Метрики", "source": "curated"},
            {"pattern": "mc.yandex.ru", "category": "telemetry", "risk_level": "telemetry", "description": "Яндекс Метрика", "source": "curated"},
            {"pattern": "an.yandex.ru", "category": "advertising", "risk_level": "ad", "description": "Рекламная сеть Яндекса", "source": "curated"},
            {"pattern": "clck.yandex.ru", "category": "telemetry", "risk_level": "telemetry", "description": "Яндекс Клик-Трекинг", "source": "curated"},
            {"pattern": "adservice.google.com", "category": "advertising", "risk_level": "ad", "description": "Google AdService", "source": "adguard"},
            {"pattern": "pagead2.googlesyndication.com", "category": "advertising", "risk_level": "ad", "description": "Google AdSense", "source": "adguard"},
            {"pattern": "googleads.g.doubleclick.net", "category": "advertising", "risk_level": "ad", "description": "Google DoubleClick Ads", "source": "adguard"},
            {"pattern": "app-measurement.com", "category": "telemetry", "risk_level": "telemetry", "description": "Firebase Analytics", "source": "curated"},
            {"pattern": "crashlytics.com", "category": "telemetry", "risk_level": "telemetry", "description": "Crashlytics Crash Reporting", "source": "curated"},
            {"pattern": "tracking.miui.com", "category": "telemetry", "risk_level": "telemetry", "description": "Xiaomi MIUI Tracking", "source": "curated"},
            {"pattern": "metrics.data.hicloud.com", "category": "telemetry", "risk_level": "telemetry", "description": "Huawei HiCloud Analytics", "source": "curated"},
            {"pattern": "samsungcloudsolution.com", "category": "telemetry", "risk_level": "telemetry", "description": "Samsung Smart TV Telemetry", "source": "curated"},
            {"pattern": "samsungadhub.com", "category": "advertising", "risk_level": "ad", "description": "Samsung AdHub", "source": "curated"},
            {"pattern": "ngfts.lge.com", "category": "telemetry", "risk_level": "telemetry", "description": "LG Smart TV Telemetry", "source": "curated"},
            {"pattern": "scribe.logs.roku.com", "category": "telemetry", "risk_level": "telemetry", "description": "Roku Telemetry Logging", "source": "curated"},
            {"pattern": "tracker.adjust.com", "category": "telemetry", "risk_level": "telemetry", "description": "Adjust Tracking", "source": "curated"},
            {"pattern": "api.amplitude.com", "category": "telemetry", "risk_level": "telemetry", "description": "Amplitude Product Analytics", "source": "curated"},
            {"pattern": "badsite.top", "category": "suspicious", "risk_level": "danger", "description": "Подозрительный хост", "source": "blocklist"},
            {"pattern": "coinhive.com", "category": "suspicious", "risk_level": "danger", "description": "Веб-майнер криптовалют", "source": "blocklist"},
        ]

        seen_patterns = set()
        for seed in curated_seeds:
            new_signatures.append(seed)
            seen_patterns.add(seed["pattern"].lower())

        # Attempt online download with timeout (parse real domains skipping comment headers)
        async with httpx.AsyncClient(timeout=6.0) as client:
            for url, source_name in sources:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        lines = resp.text.splitlines()
                        parsed_for_source = 0
                        for line in lines:
                            line = line.strip()
                            if not line or line.startswith(("#", "!", ";")):
                                continue
                            parts = line.split()
                            target_domain = None
                            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                                cand = parts[1].strip()
                                if cand not in ("localhost", "localhost.localdomain", "broadcasthost", "local", "0.0.0.0"):
                                    target_domain = cand
                            elif line.startswith("||") and line.endswith("^"):
                                target_domain = line[2:-1].strip()

                            if target_domain and "." in target_domain and len(target_domain) > 3:
                                d_lower = target_domain.lower()
                                if d_lower not in seen_patterns:
                                    seen_patterns.add(d_lower)
                                    new_signatures.append({
                                        "pattern": d_lower,
                                        "category": "advertising" if ("ad" in d_lower or "promo" in d_lower) else "telemetry",
                                        "risk_level": "ad" if ("ad" in d_lower or "promo" in d_lower) else "telemetry",
                                        "description": f"Блокировочный список {source_name}",
                                        "source": source_name
                                    })
                                    parsed_for_source += 1
                                    if parsed_for_source >= 5000:
                                        break
                        fetched_count += parsed_for_source
                        if parsed_for_source > 0:
                            break
                except Exception as ex:
                    logger.debug("Online sync from %s failed (offline or slow): %s", url, ex)

        # Save to DB and refresh memory cache
        await target_db.save_domain_signatures(new_signatures)
        await self.load_custom_rules_and_signatures(database=target_db)

        return {
            "success": True,
            "total_signatures": len(self._db_signatures),
            "updated_count": len(new_signatures),
            "source": "online_and_curated" if fetched_count > 0 else "curated_offline"
        }


# Global analyzer singleton
domain_analyzer = DomainAnalyzer()