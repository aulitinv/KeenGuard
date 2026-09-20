"""
Incident & Traffic Investigation Engine (Investigator).
Provides step-by-step security investigations, DNS-to-IP correlation,
multi-OS client diagnostics (Windows, Linux, macOS, Android, iOS, webOS, Tizen, IoT),
threat intelligence deep links (VirusTotal, AbuseIPDB, IPinfo), and actionable remediation
with strict technical realism regarding VPN and DoH/DoT constraints.
"""

import json
import logging
from pathlib import Path
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("keenguard.core.investigator")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load_known_system_services() -> List[Dict[str, Any]]:
    """Loads known legitimate system service categories from static JSON catalog."""
    json_path = _DATA_DIR / "known_system_services.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load known system services from %s: %s", json_path, e)
    return []


# Known legitimate service categories for destination IPs and ports
KNOWN_SYSTEM_SERVICES = load_known_system_services()


class IncidentInvestigator:
    """Core intelligence and workflow orchestrator for security incident investigations."""

    @staticmethod
    def detect_device_os(hostname: Optional[str], vendor: Optional[str], profile: Optional[str]) -> str:
        """
        Determines client device operating system based on hostname, vendor, and profile.
        Returns one of: 'windows', 'linux', 'macos', 'android', 'ios', 'webos', 'tizen', 'iot', 'unknown'.
        """
        h_lower = (hostname or "").lower()
        v_lower = (vendor or "").lower()
        p_lower = (profile or "").lower()

        # 1. Smart TVs
        if any(k in h_lower for k in ["lgwebos", "webos"]) or ("lg" in v_lower and ("tv" in p_lower or "tv" in h_lower)):
            return "webos"
        if any(k in h_lower for k in ["tizen", "samsungtv"]) or ("samsung" in v_lower and ("tv" in p_lower or "display" in v_lower or "tv" in h_lower)):
            return "tizen"
        if p_lower == "smart_tv" or any(k in h_lower for k in ["smarttv", "smart-tv", "tv-", "-tv", "androidtv", "appletv"]):
            return "smart_tv"

        # 2. Apple iOS / iPadOS vs macOS
        if any(k in h_lower for k in ["iphone", "ipad"]) or ("apple" in v_lower and any(k in h_lower for k in ["phone", "pad"])):
            return "ios"
        if any(k in h_lower for k in ["macbook", "imac", "mac-mini", "macpro", "mac"]) or ("apple" in v_lower and any(k in h_lower for k in ["mac", "os-x", "macos"])):
            return "macos"

        # 3. Android devices
        if any(k in h_lower for k in ["galaxy", "pixel", "redmi", "xiaomi", "huawei", "honor", "sm-s", "sm-a", "sm-m", "sm-f", "sm-g", "sm-x", "sm-t", "android"]):
            return "android"
        if any(k in v_lower for k in ["samsung", "xiaomi", "huawei", "google"]) and p_lower in ("mobile", "unassigned", "trusted"):
            return "android"

        # 4. Windows PC
        if any(k in h_lower for k in ["desktop-", "laptop-", "win-", "pc-", "nb-"]) or "windows" in h_lower:
            return "windows"

        # 5. Linux / Raspberry Pi / Smart Hubs
        if any(k in h_lower for k in ["spruthub", "homeassistant", "hassio", "raspberry", "rpi", "ubuntu", "debian", "arch", "server"]):
            return "linux"
        if "raspberry pi" in v_lower or p_lower == "smart_home_hub":
            return "linux"

        # 6. IoT Dumb / Smart appliances
        if p_lower in ("iot", "camera") or any(k in h_lower for k in ["vacuum", "dreame", "airpurifier", "qingping", "ac-", "tuya", "cam", "dishwasher"]):
            return "iot"

        return "windows" if "pc" in p_lower else "unknown"

    @staticmethod
    def generate_intel_links(target: str, is_ip: bool = True) -> Dict[str, str]:
        """Generates direct query URLs for major threat intelligence and WHOIS services."""
        clean_target = target.strip().strip("/")
        encoded = urllib.parse.quote(clean_target)

        if is_ip:
            return {
                "virustotal": f"https://www.virustotal.com/gui/ip-address/{encoded}",
                "abuseipdb": f"https://www.abuseipdb.com/check/{encoded}",
                "ipinfo": f"https://ipinfo.io/{encoded}",
                "cisco_talos": f"https://talosintelligence.com/reputation_center/lookup?search={encoded}",
                "shodan": f"https://www.shodan.io/host/{encoded}",
            }
        else:
            return {
                "virustotal": f"https://www.virustotal.com/gui/domain/{encoded}",
                "whois": f"https://who.is/whois/{encoded}",
                "urlscan": f"https://urlscan.io/search/#domain:{encoded}",
                "cisco_talos": f"https://talosintelligence.com/reputation_center/lookup?search={encoded}",
            }

    @staticmethod
    def get_os_diagnostic_playbook(os_type: str, target_ip: str, target_port: int, protocol: str = "TCP") -> Dict[str, Any]:
        """
        Generates actionable local diagnosis commands and step-by-step instructions
        for the user based on client device operating system.
        """
        proto_lower = protocol.lower()
        has_specific_ip = bool(target_ip and target_ip not in ("192.168.1.1", "0.0.0.0", "127.0.0.1", "::", "::1"))

        if os_type == "windows":
            if has_specific_ip:
                step1_desc = f"Откройте PowerShell и выполните команду, чтобы определить PID процесса, подключенного к {target_ip}:{target_port}:"
                step1_cmd = f'Get-NetTCPConnection -RemoteAddress "{target_ip}" -ErrorAction SilentlyContinue | Select-Object OwningProcess, LocalPort, State, @{{Name="ProcessName";Expression={{(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}}}'
                step1_tip = "Команда сразу покажет имя исполняемого файла (например, chrome, svchost, discord, steam)."
                step2_desc = "Если PowerShell недоступен, найдите PID через netstat:"
                step2_cmd = f'netstat -ano | findstr "{target_ip}"'
                step2_tip = "Последняя колонка — это идентификатор процесса (PID). Затем выполните tasklist | findstr <PID>."
            else:
                step1_desc = "Поиск всех активных внешних сетевых соединений в реальном времени (исключая роутер и локальную сеть):"
                step1_cmd = 'Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -ne "127.0.0.1" } | Select-Object OwningProcess, LocalPort, RemoteAddress, RemotePort, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}'
                step1_tip = "Команда выведет список всех программ на ПК, обменивающихся данными с внешним интернетом прямо сейчас."
                step2_desc = "Отобразить внешние подключения через классический netstat:"
                step2_cmd = 'netstat -ano | findstr "ESTABLISHED"'
                step2_tip = "Показывает активные соединения. Найдите внешний IP и PID в последней колонке, затем tasklist /fi \"PID eq <PID>\"."

            return {
                "os_name": "Windows (10 / 11 / Server)",
                "icon": "laptop",
                "recommended_method": "PowerShell",
                "steps": [
                    {
                        "title": "Способ 1: PowerShell (поиск процесса в реальном времени)",
                        "description": step1_desc,
                        "command": step1_cmd,
                        "tip": step1_tip
                    },
                    {
                        "title": "Способ 2: Классическая командная строка (CMD)",
                        "description": step2_desc,
                        "command": step2_cmd,
                        "tip": step2_tip
                    },
                    {
                        "title": "Способ 3: Графический инструмент (Монитор ресурсов)",
                        "description": "Нажмите Win + R, введите resmon и нажмите Enter. Перейдите во вкладку «Сеть» -> «Сетевая активность» и отфильтруйте по удаленному адресу.",
                        "command": "resmon.exe",
                        "tip": "В мониторе ресурсов видно полный путь к .exe файлу и отправляемый трафик."
                    }
                ]
            }

        elif os_type == "linux":
            if has_specific_ip:
                step1_desc = f"Определяет процесс с открытым сокетом к {target_ip}:{target_port}:"
                step1_cmd = f"sudo ss -tupn '( dst = {target_ip} )' 2>/dev/null"
                step2_desc = "Поиск открытых сетевых файлов ядра:"
                step2_cmd = f"sudo lsof -i @{target_ip}:{target_port}"
            else:
                step1_desc = "Определяет все процессы с открытыми сокетами к внешним серверам (вне локальной сети):"
                step1_cmd = "sudo ss -tupn state established '( ! dst 192.168.0.0/16 and ! dst 127.0.0.1 )' 2>/dev/null"
                step2_desc = "Поиск всех установленных интернет-соединений через lsof:"
                step2_cmd = "sudo lsof -i -nP | grep -i established"

            return {
                "os_name": "Linux (Ubuntu, Debian, Fedora, Arch, Raspberry Pi)",
                "icon": "terminal",
                "recommended_method": "Terminal (ss / lsof)",
                "steps": [
                    {
                        "title": "Способ 1: Утилита сокетов ss (быстро)",
                        "description": step1_desc,
                        "command": step1_cmd,
                        "tip": "В колонке users:((\"...\",pid=...)) будет указано точное имя процесса и PID."
                    },
                    {
                        "title": "Способ 2: Утилита lsof",
                        "description": step2_desc,
                        "command": step2_cmd,
                        "tip": "Показывает пользователя (USER), команду (COMMAND) и файловый дескриптор."
                    },
                    {
                        "title": "Способ 3: Системные службы systemd",
                        "description": "Если процесс найден как служба:",
                        "command": "systemctl status <имя_службы>",
                        "tip": "Позволяет понять, какой демон инициировал исходящую связь."
                    }
                ]
            }

        elif os_type == "macos":
            if has_specific_ip:
                step1_desc = f"Поиск приложения, удерживающего соединение с {target_ip}:"
                step1_cmd = f"sudo lsof -nP -i@{target_ip}:{target_port}"
            else:
                step1_desc = "Поиск приложений, удерживающих внешние соединения с интернетом прямо сейчас:"
                step1_cmd = "sudo lsof -nP -iTCP -sTCP:ESTABLISHED | grep -v '192.168.' | grep -v '127.0.0.1'"

            return {
                "os_name": "macOS (Apple Mac / MacBook)",
                "icon": "laptop",
                "recommended_method": "Terminal (lsof / nettop)",
                "steps": [
                    {
                        "title": "Способ 1: Терминал lsof",
                        "description": step1_desc,
                        "command": step1_cmd,
                        "tip": "Выведет имя приложения (например, Safari, Telegram, mDNSResponder, curl) и PID."
                    },
                    {
                        "title": "Способ 2: Интерактивный сетевой монитор nettop",
                        "description": "Консольный мониторинг сетевых сокетов в реальном времени:",
                        "command": "nettop -m tcp",
                        "tip": "В списке нажмите клавишу «c», чтобы свернуть процессы и найти адресата."
                    },
                    {
                        "title": "Способ 3: Мониторинг системы (Activity Monitor)",
                        "description": "Откройте «Мониторинг системы» (Activity Monitor) -> вкладка «Сеть». Отсортируйте по переданным байтам.",
                        "command": "open -a 'Activity Monitor'",
                        "tip": "Позволяет визуально завершить подозрительный процесс."
                    }
                ]
            }

        elif os_type == "android":
            adb_cmd = f'adb shell "dumpsys netstats detail | grep -E \'{target_ip}|{target_port}\'"' if has_specific_ip else 'adb shell "dumpsys netstats detail"'
            return {
                "os_name": "Android (Samsung One UI, Xiaomi HyperOS, Google Pixel)",
                "icon": "smartphone",
                "recommended_method": "Настройки телефона / ADB",
                "steps": [
                    {
                        "title": "Способ 1: Настройки использования данных на телефоне",
                        "description": "Откройте: «Настройки» -> «Подключения» -> «Использование данных» (или «Приложения» -> «Сетевая активность»).",
                        "command": None,
                        "tip": "Отсортируйте приложения по объему потребления мобильного и Wi-Fi трафика за сегодня."
                    },
                    {
                        "title": "Способ 2: Проверка встроенного Private DNS (DoT)",
                        "description": "Откройте: «Настройки» -> «Подключения» -> «Другие настройки сети» -> «Персональный DNS-сервер».",
                        "command": None,
                        "tip": "Если здесь указан сторонний провайдер, телефон обходит роутер по порту 853 TLS. Поставьте «Выкл», чтобы подчинить трафик роутеру."
                    },
                    {
                        "title": "Способ 3: Для продвинутых пользователей (через ADB)",
                        "description": "Если телефон подключен к ПК по USB с включенной отладкой:",
                        "command": adb_cmd,
                        "tip": "Показывает сетевую статистику и UID Android-приложений, совершавших вызовы."
                    }
                ]
            }

        elif os_type == "ios":
            return {
                "os_name": "Apple iOS / iPadOS (iPhone, iPad)",
                "icon": "smartphone",
                "recommended_method": "Отчет о конфиденциальности приложений",
                "steps": [
                    {
                        "title": "Способ 1: Встроенный отчет о конфиденциальности приложений",
                        "description": "Откройте на iPhone: «Настройки» -> «Конфиденциальность и безопасность» -> «Отчет о конфиденциальности приложений» (App Privacy Report).",
                        "command": None,
                        "tip": "Apple ведет журнал всех доменов и сетевых адресов, к которым обращалось каждое приложение за последние 7 дней."
                    },
                    {
                        "title": "Способ 2: Проверка фонового обновления контента",
                        "description": "Откройте: «Настройки» -> «Основные» -> «Обновление контента».",
                        "command": None,
                        "tip": "Отключите фоновую активность для приложений, которым не требуется постоянная связь с интернетом."
                    }
                ]
            }

        elif os_type in ("smart_tv", "webos", "tizen"):
            if os_type == "webos":
                tv_brand = "LG webOS"
            elif os_type == "tizen":
                tv_brand = "Samsung Tizen"
            else:
                tv_brand = "LG webOS / Samsung Tizen / Android TV"

            return {
                "os_name": f"Smart TV ({tv_brand})",
                "icon": "tv",
                "recommended_method": "Меню настроек телевизора (ACR & Телеметрия)",
                "steps": [
                    {
                        "title": "1. Природа сетевой активности: Фоновые службы прошивки ТВ",
                        "description": "В Smart TV сетевой трафик инициируется не пользовательскими программами, а системными демонами операционной системы (webOS, Tizen, Android TV). Даже когда приложения закрыты, телевизор выполняет скрытый сбор телеметрии, распознавание воспроизводимого видеоконтента (ACR) и проверку облачных обновлений.",
                        "command": None,
                        "tip": "На Smart TV нельзя открыть терминал или диспетчер задач. Защита и ограничение активности выполняются через системные разделы конфиденциальности в настройках ТВ."
                    },
                    {
                        "title": "2. Пошаговая инструкция: Отключение ACR (распознавание контента)",
                        "description": "• LG webOS: Все настройки (шестерёнка) → «Общие» → «Дополнительные настройки» (или «Служба ИИ») → отключите «Live Plus».\n• Samsung Tizen: Настройки → «Общие и конфиденциальность» → «Условия и конфиденциальность» → отключите «Службы просмотра» (Viewing Information Services).\n• Android TV / Google TV (Sony, Philips, TCL, Xiaomi): «Настройки устройства» → «Использование и диагностика» → отключите передачу данных.",
                        "command": None,
                        "tip": "Службы ACR каждые несколько секунд делают хеш-отпечатки кадров с экрана и передают их на серверы вендоров для подбора рекламы."
                    },
                    {
                        "title": "3. Пошаговая инструкция: Отзыв согласий на сбор рекламных данных и телеметрии",
                        "description": "• LG webOS: «Общие» → «Поддержка» (или «О телевизоре») → «Пользовательские соглашения» → снимите галочки с «Реклама на основе интересов» и «Голосовая информация».\n• Samsung Tizen: «Условия и конфиденциальность» → снимите галочки с «Реклама на основе интересов» (IBA) и «Голосовые службы».\n• Android TV / Google TV: «Настройки аккаунта Google» → «Реклама» → включите «Удалить рекламный идентификатор».",
                        "command": None,
                        "tip": "После отзыва согласий телевизор прекращает регулярную отправку маркетинговых отчетов на домены adhub, smartad, samsungacr.com и lgsmartad.com."
                    },
                    {
                        "title": "4. Ночная активность и дежурный режим ожидания (Standby / Quick Start+)",
                        "description": "• LG webOS: «Общие» → «Устройства» → «Управление питанием» → отключите «Быстрый старт+» (Quick Start+).\n• Samsung Tizen: «Общие» → «Сеть» → «Экспертные настройки» → отключите «Включение по Wi-Fi / LAN» (Power On with Mobile / Wake on LAN).\n• Android TV: «Настройки питания» → отключите «Быстрое включение / Сетевой режим ожидания».",
                        "command": None,
                        "tip": "Важно различать глубокий сон с обесточиванием модуля связи и дежурный режим ожидания (Standby). При включенном «Быстром старте» телевизор только гасит экран, но процессор и сетевой модуль продолжают работать круглые сутки, периодически просыпаясь для ночной телеметрии."
                    }
                ]
            }

        else:
            return {
                "os_name": "Умное устройство / IoT / Микроконтроллер",
                "icon": "cpu",
                "recommended_method": "Мобильное приложение управления",
                "steps": [
                    {
                        "title": "Проверка облачных интеграций в приложении устройства",
                        "description": "Откройте фирменное приложение (Mi Home, Dreamehome, Tuya, Smart Life, SprutHub).",
                        "command": None,
                        "tip": "Проверьте раздел «Обновление ПО» и сторонние привязки (Яндекс Алиса, Google Home, Telegram)."
                    },
                    {
                        "title": "Проверка локального опроса",
                        "description": "Для датчиков и хабов обращение к локальным портам (CoAP 5683, mDNS 5353, SSDP 1900) является нормальным для обнаружения соседей.",
                        "command": None,
                        "tip": "Если устройство шлет незашифрованный трафик наружу, рекомендуется перевести его в изолированный гостевой сегмент Wi-Fi."
                    }
                ]
            }

    @classmethod
    async def analyze_incident(
        cls,
        target_mac: Optional[str],
        target_ip: Optional[str],
        target_host: Optional[str],
        flows: List[Dict[str, Any]],
        db_conn: Any,
        audit_id: Optional[str] = None,
        event_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Conducts end-to-end investigation:
        1. Correlates flows with local DNS queries
        2. Classifies risks and detects false positives
        3. Builds OS-specific diagnostics playbooks
        4. Provides external threat intelligence links
        5. Formulates actionable advice with physical network reality caveats.
        """
        # 1. Fetch device metadata from DB if available
        device_meta = {}
        if db_conn and target_mac:
            try:
                cursor = await db_conn.execute("SELECT hostname, vendor, profile, custom_name, is_isolated_lan, segment, is_blocked_wan FROM devices WHERE mac = ?", (target_mac.upper(),))
                row = await cursor.fetchone()
                if row:
                    device_meta = {
                        "hostname": row[0] or target_host,
                        "vendor": row[1],
                        "profile": row[2],
                        "custom_name": row[3],
                        "is_isolated": bool(row[4]),
                        "segment": row[5] or "Bridge0",
                        "is_blocked_wan": bool(row[6]) if len(row) > 6 and row[6] is not None else False
                    }
            except Exception as e:
                logger.debug("Investigator db fetch device error: %s", e)

        hostname = device_meta.get("hostname") or target_host or "Unknown Device"
        vendor = device_meta.get("vendor") or ""
        profile = device_meta.get("profile") or "unassigned"

        os_type = cls.detect_device_os(hostname, vendor, profile)

        # 2. Correlate destination IPs with DNS query history
        ip_to_domain: Dict[str, str] = {}
        if db_conn and target_mac:
            try:
                cursor = await db_conn.execute(
                    "SELECT domain, ip FROM dns_queries WHERE mac = ? ORDER BY last_seen DESC LIMIT 200",
                    (target_mac.upper(),)
                )
                for d_row in await cursor.fetchall():
                    dom, resolved_ip = d_row[0], d_row[1]
                    if resolved_ip and resolved_ip != "0.0.0.0" and resolved_ip != "::":
                        ip_to_domain[resolved_ip] = dom
            except Exception as e:
                logger.debug("Investigator DNS correlation error: %s", e)

        # 3. Analyze flows and assess intelligence
        investigated_flows = []
        has_unencrypted_wan = False
        has_critical_port = False
        has_lan_probe = False
        findings = []

        for f in flows:
            dst_ip = f.get("dst_ip", "")
            dst_port = int(f.get("dst_port", 0))
            is_lan = bool(f.get("is_lan", False))
            is_encrypted = bool(f.get("is_encrypted", False))
            provider = f.get("provider", "")
            bytes_total = int(f.get("bytes_up", 0)) + int(f.get("bytes_down", 0))

            # Matched domain from DNS history
            correlated_domain = ip_to_domain.get(dst_ip)
            domain_label = correlated_domain or dst_ip

            # Evaluate system service patterns (OCSP, NCSI, etc.)
            system_match = None
            for sys_srv in KNOWN_SYSTEM_SERVICES:
                if dst_port in sys_srv["ports"]:
                    if any(kw in (correlated_domain or "").lower() or kw in provider.lower() or kw in dst_ip for kw in sys_srv["keywords"]):
                        system_match = sys_srv
                        break

            flow_risk = "safe"
            flow_verdict = "Зашифрованный легитимный трафик"

            if system_match:
                flow_risk = "safe" if system_match["risk"] == "safe" else "advisory"
                flow_verdict = system_match["name"]
            elif not is_encrypted and dst_port in (80, 1883) and not is_lan:
                has_unencrypted_wan = True
                flow_risk = "warning"
                flow_verdict = "Незащищенный открытый HTTP/MQTT"
            elif f.get("risk") == "critical" or dst_port in (22, 23, 445, 3389, 554):
                has_critical_port = True
                flow_risk = "critical"
                flow_verdict = f"Подозрительный порт администрирования ({dst_port})"
            elif is_lan and dst_ip != "192.168.1.1":
                has_lan_probe = True
                flow_risk = "advisory"
                flow_verdict = "Локальное межузловое взаимодействие"

            intel_links = cls.generate_intel_links(dst_ip, is_ip=True)
            domain_intel_links = cls.generate_intel_links(correlated_domain, is_ip=False) if correlated_domain else None

            investigated_flows.append({
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": f.get("protocol", "TCP"),
                "is_lan": is_lan,
                "is_encrypted": is_encrypted,
                "provider": provider,
                "bytes_total": bytes_total,
                "correlated_domain": correlated_domain,
                "domain_label": domain_label,
                "flow_risk": flow_risk,
                "flow_verdict": flow_verdict,
                "system_description": system_match["description"] if system_match else None,
                "intel_links": intel_links,
                "domain_intel_links": domain_intel_links,
            })

        # 4. Fetch recent DNS queries for device
        recent_dns = []
        if db_conn and target_mac:
            try:
                cursor = await db_conn.execute(
                    "SELECT domain, ip, last_seen FROM dns_queries WHERE mac = ? ORDER BY last_seen DESC LIMIT 20",
                    (target_mac.upper(),)
                )
                for d_row in await cursor.fetchall():
                    recent_dns.append({
                        "domain": d_row[0],
                        "ip": d_row[1],
                        "last_seen": d_row[2]
                    })
            except Exception as e:
                logger.debug("Investigator recent DNS error: %s", e)

        # 5. Overall severity verdict
        if has_critical_port:
            overall_verdict = "Угроза безопасности: подозрительные порты"
            severity_badge = "critical"
        elif has_unencrypted_wan:
            # Check if all unencrypted flows were legitimate OCSP/NCSI system checks
            all_known = all(f["system_description"] is not None for f in investigated_flows if f["flow_risk"] in ("warning", "advisory"))
            if all_known and os_type in ("windows", "macos", "linux"):
                overall_verdict = "Штатная фоновая проверка ОС (False Positive)"
                severity_badge = "safe"
                findings.append("Все зафиксированные открытые соединения относятся к проверке TLS-сертификатов (OCSP/CRL) и сетевой доступности Windows/браузера. Опасности нет.")
            else:
                overall_verdict = "Предупреждение: незашифрованные соединения"
                severity_badge = "warning"
                findings.append("Зафиксирована передача данных без шифрования (порт 80/1883). Убедитесь, что устройство не передает пароли открытым текстом.")
        elif not investigated_flows:
            overall_verdict = "Нет зафиксированных сессий аудита"
            severity_badge = "safe"
            findings.append("Для этого устройства еще не проводился аудит сетевых пакетов (нет сохраненных потоков).")
            if recent_dns:
                findings.append(f"В журнале роутера найдено {len(recent_dns)} недавних DNS-запросов от этого устройства.")
            else:
                findings.append("Запустите экспресс-аудит (1–5 мин) во вкладке «Аудит трафика» для захвата и анализа потоков.")
        else:
            overall_verdict = "Подозрительной активности не обнаружено"
            severity_badge = "safe"
            findings.append("Все соединения защищены современными криптографическими протоколами (TLS/SSL).")

        # 6. OS Diagnostics Playbook for the most prominent suspicious flow
        top_suspicious = next((f for f in investigated_flows if f["flow_risk"] in ("warning", "critical")), None)
        if not top_suspicious and investigated_flows:
            top_suspicious = investigated_flows[0]

        target_ip_focus = top_suspicious["dst_ip"] if top_suspicious else ""
        target_port_focus = top_suspicious["dst_port"] if top_suspicious else 80
        protocol_focus = top_suspicious["protocol"] if top_suspicious else "TCP"

        playbook = cls.get_os_diagnostic_playbook(os_type, target_ip_focus, target_port_focus, protocol_focus)

        # 7. Physical Reality & Limitations Caveats (Rule 1, 2, 3)
        technical_caveats = [
            {
                "title": "Влияние клиентского VPN (WireGuard, OpenVPN, VLESS, Outline)",
                "level": "warning",
                "severity": "warning",
                "icon": "shield-alert",
                "text": "Если на исследуемом устройстве включен VPN-клиент, ВЕСЬ его трафик и DNS шифруются на уровне ОС и идут в сквозном туннеле. Роутер Keenetic видит только зашифрованное соединение с сервером VPN. Никакие блокировки роутера (Sinkhole 0.0.0.0, DNS-фильтры) внутри туннеля работать НЕ БУДУТ, пока VPN активен.",
                "description": "Если на исследуемом устройстве включен VPN-клиент, ВЕСЬ его трафик и DNS шифруются на уровне ОС и идут в сквозном туннеле. Роутер Keenetic видит только зашифрованное соединение с сервером VPN. Никакие блокировки роутера (Sinkhole 0.0.0.0, DNS-фильтры) внутри туннеля работать НЕ БУДУТ, пока VPN активен.",
                "recommendation": "Для проверки или изоляции устройства отключите VPN на клиенте или настройте блокировки непосредственно в клиенте/сервере VPN."
            },
            {
                "title": "Ограничения мобильных устройств (DoT / Private DNS)",
                "level": "info",
                "severity": "info",
                "icon": "smartphone",
                "text": "Смартфоны на Android и iOS умеют использовать зашифрованный «Персональный DNS» (DNS-over-TLS на порт 853) напрямую в Google/Cloudflare. В таком режиме телефон намеренно обходит DNS роутера. Чтобы аппаратная блокировка на Keenetic сработала на 100%, отключите «Персональный DNS» в настройках телефона или закройте порт 853 в файрволе Keenetic.",
                "description": "Смартфоны на Android и iOS умеют использовать зашифрованный «Персональный DNS» (DNS-over-TLS на порт 853) напрямую в Google/Cloudflare. В таком режиме телефон намеренно обходит DNS роутера. Чтобы аппаратная блокировка на Keenetic сработала на 100%, отключите «Персональный DNS» в настройках телефона или закройте порт 853 в файрволе Keenetic.",
                "recommendation": "Отключите «Персональный DNS» в настройках смартфона (режим «Авто» или «Выкл») или добавьте правило закрытия TCP/853 на Keenetic."
            },
            {
                "title": "Физическая сегментация L2 локальной сети",
                "level": "info",
                "severity": "info",
                "icon": "network",
                "text": f"Устройство находится в сетевом мосте '{device_meta.get('segment', 'Bridge0')}'. Правила межсетевого экрана роутера контролируют только выход в интернет (WAN) и трафик между разными сегментами. Трафик между устройствами внутри одного L2-сегмента идет мимо шлюза Keenetic напрямую через коммутатор/Wi-Fi.",
                "description": f"Устройство находится в сетевом мосте '{device_meta.get('segment', 'Bridge0')}'. Правила межсетевого экрана роутера контролируют только выход в интернет (WAN) и трафик между разными сегментами. Трафик между устройствами внутри одного L2-сегмента идет мимо шлюза Keenetic напрямую через коммутатор/Wi-Fi.",
                "recommendation": "Для изоляции устройства от других ПК и телевизоров перенесите его в Гостевой сегмент (Bridge1) с изоляцией клиентов."
            }
        ]

        return {
            "audit_id": audit_id,
            "event_id": event_id,
            "target": {
                "mac": target_mac,
                "ip": target_ip,
                "hostname": hostname,
                "vendor": vendor,
                "profile": profile,
                "os_type": os_type,
                "segment": device_meta.get("segment", "Bridge0"),
                "is_isolated": device_meta.get("is_isolated", False),
                "is_blocked_wan": device_meta.get("is_blocked_wan", False),
            },
            "verdict": {
                "status": severity_badge,
                "summary": overall_verdict,
                "findings": findings,
            },
            "severity": severity_badge,
            "findings": findings,
            "flows_count": len(investigated_flows),
            "flows": investigated_flows,
            "recent_dns": recent_dns,
            "playbook": playbook,
            "caveats": technical_caveats,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

investigator = IncidentInvestigator()
