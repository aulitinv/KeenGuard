"""Device classifier based on MAC OUI prefixes and hostname heuristics."""
import json
import logging
from pathlib import Path
import re
from typing import Tuple, Optional, Any, List, Dict

logger = logging.getLogger("keenguard.core.classifier")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def is_valid_mac(mac: Optional[str]) -> bool:
    """Validates whether a given string is a valid IEEE 802 MAC address."""
    if not mac or not isinstance(mac, str):
        return False
    return bool(MAC_REGEX.match(mac.strip()))


def load_oui_database() -> Dict[str, Tuple[List[str], str]]:
    """Loads OUI prefixes and default device profiles from static JSON catalog."""
    json_path = _DATA_DIR / "oui_database.json"
    if json_path.exists():
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            return {vendor: (list(entry[0]), str(entry[1])) for vendor, entry in raw_data.items()}
        except Exception as e:
            logger.warning("Failed to load OUI catalog from %s: %s", json_path, e)
    return {}


OUI_DATABASE = load_oui_database()


class DeviceClassifier:
    is_valid_mac = staticmethod(is_valid_mac)

    @staticmethod
    def is_randomized_mac(mac: str) -> bool:
        """
        Detects Locally Administered Address (LAA / Private Wi-Fi address).
        In IEEE 802 MAC addresses, if the second least-significant bit of the
        first octet is 1, the address is locally administered (randomized).
        Examples: x2:xx:xx, x6:xx:xx, xA:xx:xx, xE:xx:xx.
        """
        try:
            first_byte = int(mac.split(":")[0], 16)
            return bool(first_byte & 0x02)
        except Exception:
            return False

    @classmethod
    def classify(cls, mac: str, hostname: Optional[str] = None, vendor_hint: Optional[str] = None) -> Tuple[str, str, bool]:
        """
        Returns (vendor_name, suggested_profile, is_random_mac).
        Profiles: 'trusted', 'smart_tv', 'camera', 'iot', 'unassigned'.
        """
        clean_mac = mac.upper().replace("-", ":")
        is_random = cls.is_randomized_mac(clean_mac)

        detected_vendor = vendor_hint or ("Locally Administered (Random MAC)" if is_random else "Unknown Vendor")
        suggested_profile = "unassigned"

        # Check OUI prefix
        prefix_3 = ":".join(clean_mac.split(":")[:3])
        for v_name, (prefixes, prof) in OUI_DATABASE.items():
            if prefix_3 in prefixes:
                detected_vendor = v_name
                suggested_profile = prof
                break

        # Hostname heuristics refinement
        if hostname:
            h_lower = hostname.lower()
            tokens = set(re.split(r"[-_.\s]+", h_lower))

            # Smart Home Hub / Controller keywords
            if any(k in h_lower for k in ["spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt", "aqara-hub", "lumi-gateway", "homepod"]):
                suggested_profile = "smart_home_hub"
                if "hub" not in detected_vendor.lower():
                    detected_vendor += " (Smart Home Hub)"

            # TV keywords
            elif "tv" in tokens or any(k in h_lower for k in ["smarttv", "smart-tv", "tizen", "webos", "bravia", "androidtv", "appletv", "chromecast", "mi-tv"]):
                suggested_profile = "smart_tv"
                if "tv" not in detected_vendor.lower():
                    detected_vendor += " (Smart TV)"

            # Camera & Video Intercom keywords
            elif any(k in tokens for k in ["cam", "ipc", "cctv", "nvr", "tantos", "doorbell", "intercom", "ezviz", "reolink", "uniview"]) or any(k in h_lower for k in ["camera", "rtsp", "dahua", "hikvision", "tantos", "doorbell", "intercom", "домофон", "видеодомофон", "камера"]):
                suggested_profile = "camera"
                if "tantos" in h_lower:
                    detected_vendor = "Tantos (Intercom / IP Camera)"
                elif "cam" not in detected_vendor.lower() and "intercom" not in detected_vendor.lower():
                    detected_vendor += " (Camera)"

            # IoT keywords (Appliances, Climate, Sensors, Relays)
            elif any(k in tokens for k in ["plug", "socket", "relay", "bulb", "lamp", "vacuum", "sensor", "feeder", "kettle"]) or any(k in h_lower for k in ["esp_", "tuya", "cleaner", "shelly", "sonoff", "dreame", "roborock", "qingping", "zhimi", "tasmota", "wled", "kormushka", "airpurifier"]):
                suggested_profile = "iot"
                if "iot" not in detected_vendor.lower():
                    detected_vendor += " (IoT Device)"

            # Phone / Tablet / Wearable keywords
            elif any(k in h_lower for k in ["iphone", "ipad", "galaxy", "pixel", "xiaomi", "redmi", "huawei", "honor", "oneplus", "s25", "s24", "s23", "s22", "s21", "sm-", "watch"]):
                suggested_profile = "trusted"
                # Samsung Galaxy Watch (SM-L... for Watch7/Ultra, SM-R... for Watch4/5/6)
                if any(k in h_lower for k in ["sm-l", "sm-r"]) or ("watch" in h_lower and any(k in h_lower for k in ["samsung", "galaxy"])):
                    if is_random:
                        detected_vendor = "Samsung Galaxy Watch (Random MAC)"
                    else:
                        detected_vendor = "Samsung Electronics (Galaxy Watch / Wearable)"
                # Samsung Galaxy Smartphones & Tablets (SM-S, SM-A, SM-F, SM-M, SM-X, SM-T, Galaxy S-series)
                elif any(k in h_lower for k in ["galaxy", "s25", "s24", "s23", "s22", "s21", "sm-s", "sm-a", "sm-m", "sm-f", "sm-x", "sm-t", "sm-g", "sm-n", "sm-"]):
                    if is_random:
                        detected_vendor = "Samsung Galaxy (Random MAC)"
                    else:
                        detected_vendor = "Samsung Electronics (Mobile)"
                elif any(k in h_lower for k in ["iphone", "ipad", "apple"]):
                    if is_random:
                        detected_vendor = "Apple Device (Random MAC)"
                    else:
                        detected_vendor = "Apple Inc."
                elif "pixel" in h_lower:
                    if is_random:
                        detected_vendor = "Google Pixel (Random MAC)"
                    else:
                        detected_vendor = "Google LLC"

        return detected_vendor, suggested_profile, is_random

    GENERIC_HOSTNAMES = {
        "", "unknown", "localhost", "none", "device", "keenetic", "unknown host", "generic",
        "router", "gateway", "repeater", "extender", "switch", "bridge", "printer", "accesspoint", "ap",
        "camera", "ipcam", "dvr", "nvr", "cctv", "smart-tv", "smarttv", "lgwebostv", "samsungtv", "androidtv", "appletv", "tv",
        "android", "iphone", "ipad", "macbook", "macbook-air", "macbook-pro", "imac", "apple-tv", "apple-watch",
        "galaxy", "galaxy-watch", "pixel", "windows", "linux", "pc", "desktop", "laptop", "notebook", "workstation",
        "xiaomi", "redmi", "huawei", "honor", "samsung", "apple", "google",
        "tasmota", "esp32", "esp8266", "espressif", "sonoff", "shelly", "shelly1", "shelly2", "tuya", "smart-life",
        "qingping", "qingping-air-monitor", "air-monitor", "tantos", "intercom",
        "raspberrypi", "homeassistant", "hassio", "haos", "spruthub", "hubitat", "zigbee2mqtt"
    }

    @classmethod
    def is_generic_hostname(cls, hostname: str) -> bool:
        """Returns True if the hostname is generic, a vendor/model default, or uninformative."""
        if not hostname:
            return True
        h = hostname.strip().lower()
        if h in cls.GENERIC_HOSTNAMES:
            return True
        # Prefix patterns like esp_xxxxxx, esp32-xxxxxx, tasmota-xxxx, shelly-xxxx
        for prefix in ("esp_", "esp-", "esp32-", "esp8266-", "espressif-", "tasmota-", "shelly-", "sonoff-", "tuya-", "android-"):
            if h.startswith(prefix):
                suffix = h[len(prefix):]
                # If suffix is hex-like / chip id, it's a factory default name
                if len(suffix) <= 12 and all(c in "0123456789abcdef-_" for c in suffix):
                    return True
        return False

    @classmethod
    def detect_mac_rotations(cls, devices: List[Any]) -> List[Dict[str, Any]]:
        """
        Correlates devices that share the same personalized (non-generic) hostname and exhibit
        MAC address randomization / rotation (e.g. Android Private Wi-Fi, iOS Private Wi-Fi).

        Per technical realism & Zero-Trust security (AGENTS.md):
        1. DOES NOT merge or collapse database records (at L2/DHCP each MAC is a separate network station).
        2. Strictly prevents False Positives:
           - Requires at least one randomized (LAA) MAC.
           - Forbids grouping if multiple distinct hardware (UAA) MACs are present.
           - Forbids grouping for generic/model hostnames (e.g. Qingping, Sonoff, iPad, SmartTV).
        3. Truthfully identifies:
           - hardware_mac (factory UAA MAC, if ever seen, else None);
           - active_mac (the MAC currently active/online on the network);
           - random_macs (list of LAA rotated addresses).
        """
        hostname_groups: Dict[str, List[Any]] = {}

        for d in devices:
            h = (getattr(d, "hostname", "") or (d.get("hostname") if isinstance(d, dict) else "") or "").strip()
            if cls.is_generic_hostname(h):
                continue
            hostname_groups.setdefault(h, []).append(d)

        rotation_groups = []
        for hname, dev_list in hostname_groups.items():
            if len(dev_list) < 2:
                continue

            unique_devs_by_mac: Dict[str, Any] = {}
            for dev in dev_list:
                mac = (getattr(dev, "mac", "") or (dev.get("mac") if isinstance(dev, dict) else "") or "").upper()
                if mac and mac not in unique_devs_by_mac:
                    unique_devs_by_mac[mac] = dev

            if len(unique_devs_by_mac) < 2:
                continue

            hardware_macs = []
            random_macs = []

            for mac in unique_devs_by_mac.keys():
                if cls.is_randomized_mac(mac):
                    random_macs.append(mac)
                else:
                    hardware_macs.append(mac)

            # Rule 1: Must have at least one randomized (LAA) address. If all are hardware UAA, it's NOT a MAC rotation.
            if not random_macs:
                continue

            # Rule 2: Cannot have multiple distinct hardware (UAA) MACs for a single client radio.
            if len(hardware_macs) > 1:
                continue

            hardware_mac = hardware_macs[0] if hardware_macs else None

            all_macs = []
            if hardware_mac:
                all_macs.append(hardware_mac)
            for rm in random_macs:
                if rm not in all_macs:
                    all_macs.append(rm)

            # Determine active_mac (the one currently connected / online)
            active_mac = None
            online_macs = []
            for mac, dev in unique_devs_by_mac.items():
                is_on = getattr(dev, "is_online", False) if not isinstance(dev, dict) else dev.get("is_online", False)
                ip = getattr(dev, "ip", None) if not isinstance(dev, dict) else dev.get("ip")
                if is_on:
                    online_macs.append((mac, ip or ""))

            if online_macs:
                # Prefer one with a valid non-zero IP
                valid_ips = [m for m, ip in online_macs if ip and ip != "0.0.0.0"]
                if valid_ips:
                    active_mac = valid_ips[0]
                else:
                    active_mac = online_macs[0][0]
            else:
                # All are offline; pick the most recently seen / last one in list
                active_mac = all_macs[-1]

            rotation_groups.append({
                "hostname": hname,
                "hardware_mac": hardware_mac,
                "active_mac": active_mac,
                "random_macs": random_macs,
                "all_macs": all_macs,
                "count": len(all_macs)
            })

        return rotation_groups

    @classmethod
    def classify_smarthome_device(cls, dev: Any) -> str:
        """
        Classifies an IoT device into one of the smart home roles:
        'controllers', 'garden', 'sensors', 'climate', 'appliances', 'security', 'other'.
        dev can be DeviceRecord or dict.
        """
        hname = ""
        cname = ""
        profile = ""
        vendor = ""

        if isinstance(dev, dict):
            hname = str(dev.get("hostname") or "").lower()
            cname = str(dev.get("custom_name") or "").lower()
            profile = str(dev.get("profile") or "").lower()
            vendor = str(dev.get("vendor") or "").lower()
        else:
            hname = str(getattr(dev, "hostname", "") or "").lower()
            cname = str(getattr(dev, "custom_name", "") or "").lower()
            profile = str(getattr(dev, "profile", "") or "").lower()
            vendor = str(getattr(dev, "vendor", "") or "").lower()

        combined = f"{hname} {cname} {vendor}".lower()

        # 0. Exclude Trusted Personal Devices (PCs, Smartphones, Wearables)
        trusted_keywords = (
            "iphone", "ipad", "galaxy", "pixel", "desktop", "laptop", "macbook", "notebook", "nb-",
            "sm-", "watch", "wearable", "phone", "tablet", "s25", "s24", "s23", "s22", "s21"
        )
        if profile == "trusted" or any(k in h for h in (hname, cname) for k in trusted_keywords) or "galaxy watch" in vendor:
            return "other"

        # 1. Controllers & Hubs
        if profile == "smart_home_hub" or any(k in combined for k in [
            "spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt", "aqara-hub", "lumi-gateway", "homepod", "bridge", "gateway", "controller"
        ]):
            return "controllers"

        # 2. Garden & Irrigation (датчики почвы, автополив, клапаны)
        if any(k in combined for k in [
            "soil", "garden", "irrigation", "watering", "moisture", "plant", "valve", "faucet", "sprinkler",
            "почв", "полив", "сад", "огород", "дача", "кран", "гидро"
        ]):
            return "garden"

        # 3. Climate & Air (кондиционеры, очистители воздуха, увлажнители)
        if any(k in combined for k in [
            "ac-", "ac_", "airp-", "airpurifier", "zhimi", "gree", "climate", "daikin", "midea", "haier",
            "conditioner", "purifier", "humidifier", "dehumidifier", "heater", "fan", "vent", "теплый пол", "климат"
        ]):
            return "climate"

        # 4. Environmental Sensors & Monitors (датчики качества воздуха, температуры, протечки)
        if any(k in combined for k in [
            "qingping", "sensor", "air-monitor", "airmonitor", "temp", "humidity", "co2", "pm25", "leak", "motion",
            "contact", "датчик", "протечк", "движен"
        ]):
            return "sensors"

        # 5. Home Appliances (робот-пылесос, посудомойка, кормушка, кофеварка, чайник, розетки)
        if any(k in combined for k in [
            "vacuum", "dreame", "roborock", "cleaner", "dishwasher", "bosch", "kormushka", "feeder", "washer",
            "dryer", "fridge", "coffee", "kettle", "plug", "socket", "розетк", "пылесос", "посудомой", "кормушк"
        ]):
            return "appliances"

        # 6. Security & Cameras (камеры, домофоны, дверные замки)
        if profile == "camera" or any(k in combined for k in [
            "cam", "ipc", "cctv", "nvr", "tantos", "doorbell", "intercom", "lock", "siren", "камер", "домофон", "замок"
        ]):
            return "security"

        # 7. Other / Uncategorized IoT
        return "other"

    @classmethod
    def classify_iot_trust_tier(cls, dev: Any, observed_domains: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Classifies any device into a 4-tier MUD-aligned IoT trust model:
        'pure_local', 'hybrid_weather', 'cloud_appliance', 'controller', 'camera', 'media_tv', 'trusted_pc_phone'.
        Provides granular impact analysis for WAN and LAN policy toggling.
        """
        if isinstance(dev, dict):
            hname = str(dev.get("hostname") or "").lower()
            cname = str(dev.get("custom_name") or "").lower()
            profile = str(dev.get("profile") or "").lower()
            vendor = str(dev.get("vendor") or "").lower()
        else:
            hname = str(getattr(dev, "hostname", "") or "").lower()
            cname = str(getattr(dev, "custom_name", "") or "").lower()
            profile = str(getattr(dev, "profile", "") or "").lower()
            vendor = str(getattr(dev, "vendor", "") or "").lower()

        combined = f"{hname} {cname} {vendor}".lower()
        domains_str = " ".join(observed_domains or []).lower()

        # 1. Trusted Personal Computers, Smartphones & Wearables
        trusted_keywords = (
            "iphone", "ipad", "galaxy", "pixel", "desktop", "laptop", "macbook", "notebook", "nb-",
            "sm-", "watch", "wearable", "phone", "tablet", "s25", "s24", "s23", "s22", "s21",
            "oneplus", "xiaomi", "redmi", "huawei", "honor"
        )
        if profile == "trusted" or any(k in h for h in (hname, cname) for k in trusted_keywords) or any(k in vendor for k in ["galaxy", "watch", "apple inc", "google llc"]):
            return {
                "tier": "trusted_pc_phone",
                "tier_title": "Доверенный ПК / Смартфон",
                "badge_color": "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20",
                "icon": "laptop",
                "wan_needed": True,
                "weather_dependent": False,
                "impact_wan_block": "ПК или смартфон потеряет доступ в интернет.",
                "impact_lan_isolate": "Устройство не сможет подключаться к сетевым папкам, принтерам и NAS.",
                "recommendation": "Основная домашняя сеть. Полный доступ в интернет, защита WPA3 и PMF."
            }

        # 2. Smart Home Hub / Automation Server
        if profile == "smart_home_hub" or any(k in combined for k in [
            "spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt", "aqara-hub", "lumi-gateway", "homepod"
        ]):
            return {
                "tier": "controller",
                "tier_title": "Контроллер умного дома",
                "badge_color": "bg-purple-500/10 text-purple-300 border border-purple-500/30",
                "icon": "cpu",
                "wan_needed": True,
                "weather_dependent": False,
                "impact_wan_block": "Отключит удаленный доступ через Apple HomeKit / Алису вне дома и отправку оповещений в Telegram.",
                "impact_lan_isolate": "Асимметричная изоляция: смартфоны управляют хабом, но хаб изолирован от ПК и NAS.",
                "recommendation": "Оставить WAN включенным. Настроить односторонний доступ из Home в сегмент IoT."
            }

        # 3. Video Surveillance & Intercom
        if profile == "camera" or any(k in combined for k in [
            "cam", "ipc", "cctv", "nvr", "tantos", "doorbell", "intercom", "камер", "домофон"
        ]):
            return {
                "tier": "camera",
                "tier_title": "Камера видеонаблюдения",
                "badge_color": "bg-rose-500/10 text-rose-300 border border-rose-500/30",
                "icon": "video",
                "wan_needed": False,
                "weather_dependent": False,
                "impact_wan_block": "Отключит китайские P2P-облака. Локальная запись на NVR и просмотр в SprutHub сохранятся.",
                "impact_lan_isolate": "Камера не сможет сканировать домашние компьютеры. Настоятельно рекомендуется.",
                "recommendation": "Режим NVR-only: отключить UPnP и WAN. Для удаленного просмотра использовать WireGuard/KeenDNS."
            }

        # 4. Smart TV & Media Players
        if profile == "smart_tv" or any(k in combined for k in [
            "tv", "smarttv", "tizen", "webos", "bravia", "androidtv", "appletv", "chromecast"
        ]):
            return {
                "tier": "media_tv",
                "tier_title": "Smart TV / Медиаэкран",
                "badge_color": "bg-indigo-500/10 text-indigo-300 border border-indigo-500/30",
                "icon": "tv",
                "wan_needed": True,
                "weather_dependent": False,
                "impact_wan_block": "Отключит онлайн-кинотеатры (Кинопоиск, YouTube, Netflix).",
                "impact_lan_isolate": "Асимметричный пропуск: прием AirPlay/DLNA (порт 8200 Keenetic) разрешен, доступ ТВ к ПК заблокирован.",
                "recommendation": "Разрешить WAN, настроить асимметричный медиа-пропуск (AirPlay/DLNA) и ночной аудит сна."
            }

        # 5. Air Quality Monitors & Weather Stations (Qingping, ClearGrass, etc.)
        if any(k in combined for k in [
            "qingping", "air-monitor", "airmonitor", "meteo", "weather", "погода", "метео", "co2", "pm25"
        ]) or any(k in domains_str for k in ["weather", "aqicn", "airvisual", "pool.ntp.org"]):
            return {
                "tier": "hybrid_weather",
                "tier_title": "Локальный опрос + Погода/NTP",
                "badge_color": "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",
                "icon": "cloud-sun",
                "wan_needed": True,
                "weather_dependent": True,
                "impact_wan_block": "⚠️ Локальный опрос датчиков сохранится, но внешние облачные службы (уличный прогноз погоды, точное время NTP) перестанут работать на экране устройства.",
                "impact_lan_isolate": "Защищает ПК от уязвимостей в прошивке. Опрос контроллером SprutHub/Home Assistant сохранится.",
                "recommendation": "Устройство обращается в интернет за внешней погодой и временем. Если они нужны на экране — WAN должен быть разрешен. Для защиты от сканирования изолируйте устройство в гостевом Wi-Fi сегменте."
            }

        # 6. Cloud Appliances (Vacuum, Dishwasher, Pet Feeder, Climate)
        if any(k in combined for k in [
            "vacuum", "dreame", "roborock", "cleaner", "dishwasher", "bosch", "kormushka", "feeder",
            "washer", "dryer", "fridge", "coffee", "kettle", "ac-", "ac_", "airp-", "airpurifier", "zhimi", "gree", "midea", "haier"
        ]) or any(k in domains_str for k in ["tuya", "dreame", "home-connect", "bshg", "io.mi.com"]):
            return {
                "tier": "cloud_appliance",
                "tier_title": "Облачно-зависимый прибор (Cloud-only)",
                "badge_color": "bg-amber-500/10 text-amber-300 border border-amber-500/20",
                "icon": "bot",
                "wan_needed": True,
                "weather_dependent": False,
                "impact_wan_block": "Устройство не имеет открытого локального API и управляется исключительно через облако производителя (Dreamehome, Mi Home, Tuya). При блокировке интернета прибор перестанет работать в приложении.",
                "impact_lan_isolate": "Предотвращает сканирование домашних ПК и сетевых папок вредоносным кодом из прошивки.",
                "recommendation": "Не блокируйте интернет: без облака вендора прибор не работает. Разрешите WAN, но изолируйте от домашних ПК (подключив к Гостевой Wi-Fi сети)."
            }

        # 7. Unassigned / Unknown devices (no confirmed IoT indicators)
        if profile == "unassigned":
            iot_indicators = [
                "esp", "tuya", "sonoff", "shelly", "tasmota", "wled", "zigbee", "zwave",
                "relay", "plug", "socket", "sensor", "switch", "bulb", "lamp", "led",
                "leak", "valve", "temp", "humidity", "co2", "soil", "meter", "metering",
                "cleaner", "vacuum", "feeder", "kettle"
            ]
            has_iot_indicator = any(k in combined for k in iot_indicators) or any(k in domains_str for k in ["tuya", "espressif", "mqtt"])
            if not has_iot_indicator:
                return {
                    "tier": "unassigned",
                    "tier_title": "Неопознанное устройство",
                    "badge_color": "bg-slate-500/10 text-slate-400 border border-slate-500/20",
                    "icon": "help-circle",
                    "wan_needed": True,
                    "weather_dependent": False,
                    "impact_wan_block": "Доступ в интернет будет заблокирован до выяснения назначения устройства.",
                    "impact_lan_isolate": "Рекомендуется изолировать устройство до выяснения его назначения.",
                    "recommendation": "Устройство не опознано. Назначьте подходящий профиль в разделе «Устройства» или держите в карантине."
                }

        # 8. Pure Local IoT Sensors & Actuators (Soil, Irrigation, Water Leak, Contact, Relays, etc.)
        return {
            "tier": "pure_local",
            "tier_title": "Локальный протокол (Local LAN / HomeKit)",
            "badge_color": "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20",
            "icon": "shield-check",
            "wan_needed": False,
            "weather_dependent": False,
            "impact_wan_block": "Устройство способно работать по локальной сети без облака. При блокировке WAN локальное управление по домашней сети сохранится, а отправка данных на внешние сервера прекратится.",
            "impact_lan_isolate": "Изолировано от ПК. Опрос хабом умного дома сохраняется.",
            "recommendation": "Если устройство настроено через локальный протокол (HomeKit, локальный API, MQTT), можно включить Zero-Internet (заблокировать WAN) для защиты от скрытой телеметрии."
        }


