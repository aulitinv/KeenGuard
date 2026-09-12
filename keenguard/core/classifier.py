"""Device classifier based on MAC OUI prefixes and hostname heuristics."""
import re
from typing import Tuple, Optional, Any, List, Dict

OUI_DATABASE = {
    # Smart TVs & Streaming Media
    "LG Electronics (TV/webOS)": (
        ["00:1C:62", "00:1E:75", "10:F9:6F", "20:3D:66", "58:A2:B5", "A8:23:FE", "CC:2D:83", "E8:F2:E2", "F4:42:8F", "70:80:79", "A8:92:2C", "34:FC:EF", "64:95:6C"],
        "smart_tv"
    ),
    "Samsung Visual Display (Tizen)": (
        ["00:12:47", "00:15:B9", "00:21:19", "08:37:3D", "14:49:E0", "40:16:3B", "64:1C:AE", "78:44:05", "84:25:19", "B4:79:A7", "D0:03:DF", "F4:7B:5E", "50:85:69", "64:6C:B2", "00:24:54", "00:26:37", "08:08:C2"],
        "smart_tv"
    ),
    "Sony Corporation (Bravia TV)": (
        ["00:01:4A", "00:13:A9", "00:19:C7", "00:24:BE", "F0:BF:97", "00:1D:BA", "70:9E:29", "FC:F1:36", "04:5D:4B"],
        "smart_tv"
    ),
    "Philips / TP Vision (Smart TV)": (
        ["00:08:22", "00:1A:E9", "00:90:3E", "18:8E:D5", "30:89:4A", "68:84:70"],
        "smart_tv"
    ),
    "TCL / TPV / Hisense (Smart TV)": (
        ["68:DF:DD", "D0:25:44", "00:26:4F", "F8:84:79", "60:F1:89", "88:29:9C", "7C:49:EB", "28:76:CD"],
        "smart_tv"
    ),
    "Roku / Streaming Stick": (
        ["00:0D:4B", "20:F5:43", "84:EA:99", "AC:AE:19", "B0:EE:45", "D8:31:34"],
        "smart_tv"
    ),

    # IP Cameras & Video Surveillance
    "Hikvision Surveillance": (
        ["C4:2F:90", "44:19:B6", "54:C4:15", "BC:AD:28", "B0:59:47", "18:68:CB", "74:1E:83", "00:12:12", "00:40:48", "28:57:BE", "A4:14:37"],
        "camera"
    ),
    "Dahua Technology": (
        ["3C:EF:8C", "4C:11:BF", "90:02:A9", "A0:BD:1D", "E0:50:8B", "B8:A3:86", "E4:53:D4", "00:1A:6B", "6C:19:8F"],
        "camera"
    ),
    "Reolink / Xiongmai / Anyka (IP Cam)": (
        ["EC:71:DB", "00:23:63", "00:12:16", "00:0F:7D", "00:30:1B", "58:02:03"],
        "camera"
    ),
    "TP-Link Tapo Camera": (
        ["54:AF:97", "78:8C:54", "30:DE:4B", "CC:32:E5", "AC:15:A2"],
        "camera"
    ),
    "Ezviz Inc.": (
        ["84:D8:1B", "A4:CF:99", "D8:0D:17"],
        "camera"
    ),
    "Axis Communications": (
        ["00:40:8C", "AC:CC:8E", "B8:A4:4F"],
        "camera"
    ),
    "Uniview Technologies": (
        ["34:8B:D5", "48:EA:63", "78:09:44"],
        "camera"
    ),

    # IoT / Smart Home chips & Vendors
    "Espressif (ESP8266 / ESP32)": (
        ["24:0A:C4", "30:AE:A4", "A4:CF:12", "EC:FA:BC", "84:F3:EB", "5C:CF:7F", "24:62:AB", "68:C6:3A", "84:0D:8E", "94:B9:7E", "A4:E5:7C", "BC:FF:4D", "D8:BC:38", "3C:61:05", "40:22:D8", "70:04:1D", "7C:DF:A1", "18:FE:34", "24:B2:DE", "2C:3A:E8", "30:83:98", "48:55:19", "48:3F:DA", "4C:75:25", "60:01:94", "68:B9:D3", "70:B3:D5", "80:7D:3A", "8C:AA:B5", "90:9A:4A", "A0:20:A6", "AC:67:B2", "B4:E6:2D", "C4:4F:33", "C4:DD:57", "CC:50:E3", "D4:F9:8D", "DC:4F:22", "E0:98:06", "E8:68:E7", "F4:CF:A2"],
        "iot"
    ),
    "Tuya Smart Inc.": (
        ["10:5A:F7", "70:8E:2F", "68:57:2D", "D4:A6:51", "50:8A:06", "7C:F6:66", "84:F7:03", "A0:92:08", "C8:2E:18", "00:50:56", "20:F4:1B", "2C:AA:8E", "68:5D:43", "74:C6:3B", "84:E3:42", "A4:C1:38", "B8:D8:12", "D8:1F:12"],
        "iot"
    ),
    "Xiaomi / Roborock / Dreame": (
        ["64:90:C1", "54:48:E6", "58:44:9C", "7C:49:EB", "04:CF:8C", "18:59:36", "34:80:0D", "50:EC:50", "78:11:DC", "00:EC:0A", "14:F6:5A", "28:6C:07", "34:CE:00", "44:23:7C", "50:64:2B", "78:02:F8", "8C:DE:52", "AC:C1:EE", "D4:97:0B"],
        "iot"
    ),
    "Sonoff / Itead": (
        ["60:01:94", "DC:4F:22", "C4:4F:33"],
        "iot"
    ),
    "Shelly / Allterco": (
        ["34:94:54", "48:55:19", "C4:5B:BE"],
        "iot"
    ),
    "Aqara / Lumi United": (
        ["54:EF:44", "04:CF:8C", "40:22:D8"],
        "iot"
    ),
    "BroadLink": (
        ["B4:43:0D", "EC:0B:C4", "34:EA:34"],
        "iot"
    ),
    "Qingping Electronics (IoT / Sensors)": (
        ["58:2D:34"],
        "iot"
    ),

    # Smart Home Controllers
    "Raspberry Pi Foundation (SprutHub/HA)": (
        ["B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1", "D8:3A:DD"],
        "smart_home_hub"
    ),

    # Network & Routers
    "Keenetic Limited": (
        ["50:FF:20", "28:28:5D", "00:19:CB", "40:4A:03", "EC:43:F6", "EE:43:F6"],
        "trusted"
    ),
    "TP-Link Technologies": (
        ["00:27:19", "14:CC:20", "18:A6:F7", "30:B5:C2", "50:3E:AA", "60:E3:27", "70:4F:57", "98:48:27", "C0:25:E9", "E8:48:B8"],
        "trusted"
    ),
    "ASUS Network": (
        ["04:D9:F5", "08:60:6E", "10:7B:44", "18:31:BF", "2C:FD:A1", "38:2C:4A", "74:D0:2B", "AC:9E:17"],
        "trusted"
    ),
    "MikroTik": (
        ["00:0C:42", "48:8F:5A", "64:D1:54", "74:4D:28", "CC:2D:E0"],
        "trusted"
    ),
    "Ubiquiti UniFi": (
        ["00:27:22", "04:18:D6", "24:A4:3C", "68:D7:9A", "74:83:C2", "80:2A:A8", "B4:FB:E4", "F0:9F:C2"],
        "trusted"
    ),

    # Trusted Mobile & PC
    "Apple Inc.": (
        ["00:17:F2", "00:1B:63", "00:1E:52", "00:25:00", "00:26:08", "F0:18:98", "AC:BC:32", "A4:83:E7", "38:F9:D3", "88:66:5A", "F4:0F:24", "D0:81:7A", "98:01:A7", "40:9C:28", "18:65:90", "28:E1:4C", "34:36:3B", "3C:07:54", "48:74:6E", "60:03:08", "68:FE:F7", "70:3E:AC", "80:49:71", "90:72:40", "A8:5B:78", "BC:D1:1F", "C8:3C:85", "E0:B9:BA", "F4:34:F0"],
        "trusted"
    ),
    "Google LLC": (
        ["3C:5A:B4", "54:60:09", "F4:F5:DB", "94:EB:CD", "48:D6:D5", "00:1A:11", "20:DF:B9", "D8:6C:63"],
        "trusted"
    ),
    "Intel Corporation": (
        ["00:1B:21", "00:1E:67", "00:21:6A", "3C:A9:F4", "8C:85:90", "A0:C5:89", "00:02:B3", "00:04:23", "00:0E:35", "34:13:E8", "48:51:B7", "68:05:CA", "84:A9:3E", "A4:4C:C8", "F8:63:3F"],
        "trusted"
    ),
    "Microsoft Corporation": (
        ["00:15:5D", "00:17:FA", "28:18:78", "7C:ED:8D", "DC:B4:C4"],
        "trusted"
    ),
    "Dell Inc.": (
        ["00:14:22", "14:18:77", "18:03:73", "24:B6:FD", "34:17:EB", "74:86:7A", "98:90:96", "B8:AC:6F", "D4:BE:D9"],
        "trusted"
    ),
    "HP Inc.": (
        ["00:1B:78", "10:60:4B", "2C:41:38", "3C:52:82", "40:B0:34", "70:5A:0F", "84:34:97", "A0:D3:C1", "D8:9D:67"],
        "trusted"
    ),
    "Lenovo": (
        ["00:59:07", "04:CF:4B", "08:71:90", "28:D0:EA", "40:B8:9A", "60:D8:19", "70:72:3C", "84:A9:C4", "A4:83:E7", "B8:85:84"],
        "trusted"
    ),
    "Samsung Electronics (Mobile)": (
        ["00:07:AB", "04:18:0F", "08:D4:2B", "10:1C:0C", "1C:5A:3E", "28:9A:4B", "30:CD:A7", "40:0E:85", "54:92:BE", "68:7D:B4", "78:40:E4", "84:25:DB", "90:18:7C", "A8:7C:01", "B0:72:BF", "CC:07:AB", "2C:DA:46", "50:01:D9", "BC:85:56", "E4:7C:F9", "00:1A:80"],
        "trusted"
    ),
    "ASRock Incorporation": (
        ["70:85:C2", "D0:50:99", "BC:EE:7B"],
        "trusted"
    )
}

class DeviceClassifier:
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


