"""Keenetic telemetry and status discovery mixin."""
import logging
from typing import Dict, Any, List, Optional
from keenguard.core.keenetic.models import HotspotHost

logger = logging.getLogger("keenguard.keenetic.telemetry")


class KeeneticTelemetryMixin:
    """Methods for discovering hosts, NAT flows, DNS cache, Wi-Fi posture, and firmware."""

    async def get_hotspot_hosts(self) -> List[HotspotHost]:
        """Pulls the current ARP & device table from Keenetic RAM."""
        if getattr(self, "mock_mode", False):
            hosts = []
            for h in getattr(self, "_mock_hosts", []):
                d = dict(h)
                if "segment" not in d:
                    iface = str(d.get("interface", "")).lower()
                    ip_str = str(d.get("ip", ""))
                    if "guest" in iface or "bridge1" in iface or (ip_str and not ip_str.startswith("192.168.1.") and ip_str != "0.0.0.0"):
                        d["segment"] = "Guest"
                    else:
                        d["segment"] = "Home"
                hosts.append(HotspotHost(**d))
            return hosts

        resp = await self._send_request("GET", "/rci/show/ip/hotspot")
        if resp and resp.status_code == 200:
            raw_hosts = resp.json().get("host", [])
            result = []
            for h in raw_hosts:
                iface = h.get("interface")
                if isinstance(iface, dict):
                    iface_name = iface.get("name") or iface.get("id") or "Bridge0"
                else:
                    iface_name = str(iface) if iface else None

                name_val = h.get("name")
                if isinstance(name_val, dict):
                    name_val = name_val.get("name") or name_val.get("id")

                hname_val = h.get("hostname")
                if isinstance(hname_val, dict):
                    hname_val = hname_val.get("name") or hname_val.get("id")

                seg_name = "Home"
                if iface_name:
                    if "guest" in iface_name.lower() or "bridge1" in iface_name.lower():
                        seg_name = "Guest"
                    elif iface_name in ("Home", "Bridge0"):
                        seg_name = "Home"
                    else:
                        seg_name = iface_name
                elif h.get("ip") and not str(h.get("ip")).startswith("192.168.1.") and h.get("ip") != "0.0.0.0":
                    seg_name = "Guest"

                result.append(HotspotHost(
                    mac=str(h.get("mac", "")).upper(),
                    ip=h.get("ip"),
                    name=name_val,
                    hostname=hname_val,
                    interface=iface_name,
                    link=h.get("link", "down"),
                    active=h.get("active", False),
                    rxbytes=int(h.get("rxbytes", 0) or 0),
                    txbytes=int(h.get("txbytes", 0) or 0),
                    uptime=int(h.get("uptime", 0) or 0),
                    access=str(h.get("access", "permit")),
                    registered=bool(h.get("registered", False)),
                    policy=h.get("policy"),
                    segment=seg_name
                ))
            return result
        return []

    async def get_nat_table(self) -> List[Dict[str, Any]]:
        """Pulls the live active NAT connection table from Keenetic."""
        if getattr(self, "mock_mode", False):
            return []
        resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"ip": {"nat": {}}}}])
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    return data[0].get("show", {}).get("ip", {}).get("nat", [])
            except Exception as e:
                logger.error("Error parsing Keenetic NAT table: %s", e)
        return []

    async def get_device_nat_connections(self, ip: str) -> List[Dict[str, Any]]:
        """Returns active NAT connections specifically for this device IP."""
        if not ip:
            return []
        nat_entries = await self.get_nat_table()
        return [e for e in nat_entries if e.get("src") == ip]

    async def get_dns_cache(self) -> List[Dict[str, Any]]:
        """Extracts the DNS proxy cache from Keenetic router."""
        if getattr(self, "mock_mode", False):
            return [
                {"domain": "gateway.fe.apple-dns.net", "ip": "17.248.190.245", "ttl": 300},
                {"domain": "api.dreame.tech", "ip": "47.91.78.162", "ttl": 60},
                {"domain": "pool.ntp.org", "ip": "194.226.177.202", "ttl": 120}
            ]
        payload = [{"show": {"ip": {"dns": {"proxy": {"cache": {}}}}}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        entries = []
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    raw_cache = data[0].get("show", {}).get("ip", {}).get("dns", {}).get("proxy", {}).get("cache", [])
                    if isinstance(raw_cache, list):
                        for item in raw_cache:
                            name = item.get("name") or item.get("domain")
                            if name:
                                entries.append({
                                    "domain": name,
                                    "ip": item.get("address") or item.get("ip"),
                                    "ttl": item.get("ttl", 0)
                                })
            except Exception as e:
                logger.debug("Error parsing DNS cache: %s", e)

        if not entries:
            try:
                p_resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"dns-proxy": {}}}])
                if p_resp and p_resp.status_code == 200:
                    p_data = p_resp.json()
                    if isinstance(p_data, list) and p_data:
                        status_list = p_data[0].get("show", {}).get("dns-proxy", {}).get("proxy-status", [])
                        for st in status_list:
                            cfg = st.get("proxy-config", "")
                            for line in cfg.splitlines():
                                line = line.strip()
                                if line.startswith("static_a = ") or line.startswith("static_aaaa = "):
                                    parts = line.split()
                                    if len(parts) >= 4 and "." in parts[2]:
                                        domain_name = parts[2]
                                        ip_val = parts[3]
                                        if ip_val in ("0.0.0.0", "127.0.0.1", "::", "::1"):
                                            continue
                                        if domain_name.endswith(".keenetic.net") or domain_name.endswith(".netcraze.io") or "dnscheck.test" in domain_name:
                                            continue
                                        entries.append({"domain": domain_name, "ip": ip_val, "ttl": 3600})
                                elif "#" in line and "@" in line:
                                    comment_part = line.split("#", 1)[1].strip()
                                    if "@" in comment_part:
                                        srv_host = comment_part.split("@", 1)[1].split()[0].strip()
                                        if "." in srv_host:
                                            entries.append({"domain": srv_host, "ip": None, "ttl": 3600})
            except Exception as e:
                logger.debug("Error in dns-proxy fallback: %s", e)

        return entries

    async def get_wifi_security(self) -> Dict[str, Any]:
        """Audits Wi-Fi configuration (WPA mode, WPS, Guest isolation) via Keenetic RCI."""
        if getattr(self, "mock_mode", False):
            return {
                "grade": "A+",
                "score": 100,
                "access_points": [
                    {
                        "interface": "WifiMaster0/AccessPoint0",
                        "ssid": "Keenetic-Home",
                        "band": "2.4 ГГц",
                        "security": "WPA3 / WPA2 mixed",
                        "security_type": "wpa3_mixed",
                        "wps": False,
                        "pmf": "optional"
                    }
                ],
                "networks": [
                    {
                        "interface": "WifiMaster0/AccessPoint0",
                        "ssid": "Keenetic-Home",
                        "band": "2.4 ГГц",
                        "security": "WPA3 / WPA2 mixed",
                        "security_type": "wpa3_mixed",
                        "wps": False,
                        "pmf": "optional"
                    }
                ],
                "wps_enabled": False,
                "pmf_enabled": True,
                "guest_network": {"configured": True, "isolated": True},
                "guest_network_enabled": True,
                "guest_isolation_enabled": True,
                "recommendations": ["Рекомендуется установить PMF в режим 'Обязательно' для защиты от Deauth-атак."]
            }

        ap_query = [{"show": {"interface": {}}}]
        resp = await self._send_request("POST", "/rci/", json_data=ap_query)
        if not resp or resp.status_code != 200:
            return {
                "grade": "C",
                "score": 60,
                "guest_network": {"configured": False, "isolated": False},
                "recommendations": ["Не удалось опросить статус Wi-Fi интерфейсов через RCI"]
            }

        try:
            raw_interfaces = resp.json()[0].get("show", {}).get("interface", {})
        except Exception as e:
            logger.debug("Error parsing interfaces JSON: %s", e)
            raw_interfaces = {}

        networks = []
        has_wps = False
        has_open_wifi = False
        all_pmf = True
        has_wpa3 = False
        has_guest = False
        guest_isolated = False

        for if_name, if_obj in raw_interfaces.items():
            if not isinstance(if_obj, dict):
                continue

            if "guest" in if_name.lower() or "bridge1" in if_name.lower():
                has_guest = True
                sec_lvl = str(if_obj.get("security-level", "")).lower()
                if (
                    if_obj.get("isolate")
                    or if_obj.get("isolate-private")
                    or if_obj.get("client-isolation")
                    or sec_lvl in ("protected", "guest")
                ):
                    guest_isolated = True

            if "AccessPoint" in if_name or "WifiMaster" in if_name:
                ssid = if_obj.get("ssid")
                if not ssid:
                    continue

                sec = str(if_obj.get("security", "") or "").lower()
                auth = str(if_obj.get("authentication", "") or "").lower()
                auth_type = str(if_obj.get("auth-type", "") or "").lower()
                enc = str(if_obj.get("encryption", "") or "").lower()
                sec_level = str(if_obj.get("security-level", "") or "").lower()
                pmf = str(if_obj.get("pmf", "") or "").lower()
                wps_state = if_obj.get("wps", False)

                if wps_state:
                    has_wps = True

                band = "5 ГГц" if ("5g" in if_name.lower() or "Master1" in if_name) else "2.4 ГГц"

                # Check all possible KeeneticOS security indicators
                combined = f"{sec} {auth} {auth_type} {enc} {sec_level}"
                has_wpa3_mode = "wpa3" in combined or "sae" in combined
                has_wpa2_mode = "wpa2" in combined or "psk2" in combined or "aes" in combined
                has_wpa1_mode = "wpa" in combined or "psk" in combined or "tkip" in combined
                is_explicit_open = (enc in ("none", "open", "disabled") or sec in ("none", "open") or sec_level in ("none", "open")) and not (has_wpa3_mode or has_wpa2_mode or has_wpa1_mode)

                if has_wpa3_mode and has_wpa2_mode:
                    has_wpa3 = True
                    sec_label = "WPA3 / WPA2 mixed"
                    sec_type = "wpa3_mixed"
                elif has_wpa3_mode:
                    has_wpa3 = True
                    sec_label = "WPA3-SAE"
                    sec_type = "wpa3"
                elif has_wpa2_mode:
                    sec_label = "WPA2-PSK (AES)"
                    sec_type = "wpa2"
                elif has_wpa1_mode:
                    sec_label = "WPA-PSK (Устаревший)"
                    sec_type = "wpa"
                elif is_explicit_open:
                    sec_label = "Открытая (Без пароля)"
                    sec_type = "open"
                    has_open_wifi = True
                else:
                    if enc and enc not in ("", "none"):
                        sec_label = enc.upper()
                        sec_type = "wpa2"
                    else:
                        sec_label = "WPA2-PSK (AES)"
                        sec_type = "wpa2"

                pmf_mode = pmf if pmf and pmf != "disabled" else ("optional" if has_wpa3_mode else "disabled")
                if pmf_mode not in ("required", "mandatory", "true", "1"):
                    all_pmf = False

                networks.append({
                    "interface": if_name,
                    "ssid": ssid,
                    "band": band,
                    "security": sec_label,
                    "encryption": sec_label,
                    "security_type": sec_type,
                    "wps": bool(wps_state),
                    "pmf": pmf_mode
                })

        score = 100
        recommendations = []

        if has_open_wifi:
            score -= 40
            recommendations.append("Обнаружена открытая Wi-Fi сеть без пароля. Немедленно включите шифрование WPA2/WPA3.")
        if has_wps:
            score -= 20
            recommendations.append("Включена функция WPS. Рекомендуется отключить WPS для защиты от атак перебора PIN (Pixie Dust).")
        if not has_wpa3:
            score -= 15
            recommendations.append("Включите современный протокол WPA3-SAE для защиты от подбора паролей по словарю.")
        if not all_pmf:
            score -= 15
            recommendations.append("Защита кадров управления (PMF / 802.11w) отключена или установлена в режим «По возможности». Сеть уязвима к деаутентификации.")
        if not has_guest or not guest_isolated:
            score -= 10
            recommendations.append("Рекомендуется настроить изолированную Гостевую сеть (Bridge1) для техники умного дома.")

        score = max(20, min(100, score))
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        return {
            "grade": grade,
            "score": score,
            "access_points": networks,
            "networks": networks,
            "wps_enabled": has_wps,
            "pmf_enabled": all_pmf,
            "guest_network": {"configured": has_guest, "isolated": guest_isolated},
            "guest_network_enabled": has_guest,
            "guest_isolation_enabled": guest_isolated,
            "recommendations": recommendations
        }

    async def check_firmware_updates(self) -> Dict[str, Any]:
        """Queries KeeneticOS cloud update status."""
        current_v = getattr(self, "last_version", "5.1.4") or "5.1.4"
        if getattr(self, "mock_mode", False):
            return {
                "status": "ok",
                "current_version": current_v,
                "latest_version": current_v,
                "available_version": current_v,
                "has_update": False,
                "update_available": False,
                "channel": "release",
                "message": "Установлена актуальная версия KeeneticOS."
            }

        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"version": {}}}])
            if not resp or resp.status_code != 200:
                return {
                    "status": "ok",
                    "update_available": False,
                    "has_update": False,
                    "current_version": current_v,
                    "latest_version": current_v,
                    "available_version": current_v,
                    "channel": "release",
                    "message": "Информация о версии недоступна."
                }

            data = resp.json()
            ver_info = data[0].get("show", {}).get("version", {}) if isinstance(data, list) and data else {}
            current_ver = ver_info.get("title") or ver_info.get("version") or current_v
            channel = ver_info.get("channel", "release")

            upd_resp = await self._send_request("POST", "/rci/", json_data=[{"components": {"list": {}}}])
            has_update = False
            latest_ver = current_ver

            if upd_resp and upd_resp.status_code == 200:
                upd_data = upd_resp.json()
                if isinstance(upd_data, list) and upd_data:
                    comp_info = upd_data[0].get("components", {}).get("list", {})
                    if comp_info.get("update_available") or comp_info.get("has_update") or comp_info.get("update"):
                        has_update = True
                        latest_ver = comp_info.get("available_version") or comp_info.get("version") or current_ver

            msg = f"Доступно обновление до {latest_ver}." if has_update else "Установлена актуальная версия KeeneticOS."
            return {
                "status": "ok",
                "update_available": has_update,
                "has_update": has_update,
                "current_version": current_ver,
                "latest_version": latest_ver,
                "available_version": latest_ver,
                "channel": channel,
                "message": msg
            }
        except Exception as e:
            logger.debug("Error checking firmware updates: %s", e)
            return {
                "status": "ok",
                "update_available": False,
                "has_update": False,
                "current_version": current_v,
                "latest_version": current_v,
                "available_version": current_v,
                "channel": "release",
                "message": "Ошибка проверки обновлений."
            }

    async def get_dns_proxy_status(self) -> Dict[str, Any]:
        """Queries the active DNS proxy status and filtering engine from KeeneticOS."""
        if getattr(self, "mock_mode", False):
            return {
                "active": True,
                "filter_engine": "adguard",
                "rebind_protect": True,
                "has_doh": True,
                "has_dot": False,
                "servers": ["94.140.14.14", "94.140.15.15"]
            }

        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"dns-proxy": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    proxy_info = data[0].get("show", {}).get("dns-proxy", {})
                    engine = proxy_info.get("engine") or proxy_info.get("filter")
                    rebind = bool(proxy_info.get("rebind-protect", True))
                    servers = []
                    has_doh = False
                    has_dot = False
                    for s in proxy_info.get("server", []):
                        addr = s.get("address")
                        if addr:
                            servers.append(addr)
                        proto = str(s.get("protocol", "")).lower()
                        if "doh" in proto or "https" in proto:
                            has_doh = True
                        if "dot" in proto or "tls" in proto:
                            has_dot = True

                    return {
                        "active": True,
                        "filter_engine": engine,
                        "rebind_protect": rebind,
                        "has_doh": has_doh,
                        "has_dot": has_dot,
                        "servers": servers
                    }
        except Exception as e:
            logger.debug("Error fetching dns-proxy status: %s", e)

        return {"active": False, "filter_engine": None, "rebind_protect": False, "has_doh": False, "has_dot": False, "servers": []}

    async def get_network_segments(self) -> List[Dict[str, Any]]:
        """Queries configured network segments and bridges from Keenetic."""
        if getattr(self, "mock_mode", False):
            return [
                {"id": "Home", "name": "Домашняя сеть", "interface": "Bridge0", "subnet": "192.168.1.0/24", "dhcp": True, "security_level": "trusted"},
                {"id": "Guest", "name": "Гостевая сеть", "interface": "Bridge1", "subnet": "192.168.2.0/24", "dhcp": True, "security_level": "isolated"}
            ]

        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"interface": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    ifaces = data[0].get("show", {}).get("interface", {})
                    segments = []
                    for if_name, if_obj in ifaces.items():
                        if not isinstance(if_obj, dict):
                            continue
                        if if_name.startswith("Bridge") or "bridge" in if_name.lower():
                            ip_addr = if_obj.get("address")
                            mask = if_obj.get("mask", "255.255.255.0")
                            descr = if_obj.get("description") or if_name
                            is_guest = "guest" in descr.lower() or if_name == "Bridge1"
                            segments.append({
                                "id": "Guest" if is_guest else ("Home" if if_name == "Bridge0" else if_name),
                                "name": descr,
                                "interface": if_name,
                                "address": ip_addr,
                                "mask": mask,
                                "subnet": f"{ip_addr}/{mask}" if ip_addr else "—",
                                "isolated": bool(if_obj.get("isolate") or is_guest),
                                "security_level": "isolated" if is_guest else "trusted"
                            })
                    return segments
        except Exception as e:
            logger.debug("Error fetching network segments: %s", e)

        return [
            {"id": "Home", "name": "Домашняя сеть", "interface": "Bridge0", "subnet": "192.168.1.0/24", "dhcp": True, "security_level": "trusted"},
            {"id": "Guest", "name": "Гостевая сеть", "interface": "Bridge1", "subnet": "192.168.2.0/24", "dhcp": True, "security_level": "isolated"}
        ]

    def evaluate_segment_risk(self, profile: str, segment: Optional[str], ip: Optional[str] = None) -> Dict[str, Any]:
        """
        Evaluates physical L2 segmentation risk for a device.
        Returns risk level, status title, and actionable advice.
        """
        clean_seg = (segment or "Home").strip()
        is_isolated = clean_seg == "Guest" or "guest" in clean_seg.lower() or (ip and not ip.startswith("192.168.1.") and ip != "0.0.0.0")

        if profile in ("camera", "iot"):
            if not is_isolated:
                return {
                    "risk_level": "high",
                    "level": "warning",
                    "status": "Высокий риск (L2-обход)",
                    "status_label": "L2-обход в Bridge0",
                    "badge_color": "rose",
                    "is_isolated": False,
                    "hardware_enforced": False,
                    "recommendation": (
                        "Устройство находится в основном мосте 'Home' (Bridge0, 192.168.1.0/24). "
                        "L2-трафик между клиентами идет напрямую в обход файрвола роутера. "
                        "Рекомендуется физически перенести устройство в сегмент 'Гостевая сеть' (Bridge1) или выделить отдельный IoT VLAN в KeeneticOS."
                    )
                }
            else:
                return {
                    "risk_level": "low",
                    "level": "safe",
                    "status": "Изолировано",
                    "status_label": "Физически изолирован",
                    "badge_color": "emerald",
                    "is_isolated": True,
                    "hardware_enforced": True,
                    "recommendation": "Устройство физически изолировано в выделенном сегменте. Прямой доступ к домашним клиентам аппаратно заблокирован на L2."
                }
        elif profile == "smart_tv":
            if not is_isolated:
                return {
                    "risk_level": "medium",
                    "level": "info",
                    "status": "Умеренный риск (L2 открыт)",
                    "status_label": "Домашняя сеть (Bridge0)",
                    "badge_color": "amber",
                    "is_isolated": False,
                    "hardware_enforced": False,
                    "recommendation": (
                        "Телевизор находится в общем домашнем сегменте Bridge0. Это обеспечивает прямую работу AirPlay и DLNA без mDNS-ретранслятора, "
                        "но позволяет устройству фоново сканировать домашнюю сеть даже в режиме Standby."
                    )
                }
            else:
                return {
                    "risk_level": "low",
                    "level": "safe",
                    "status": "Изолировано в гостевой сети",
                    "status_label": "Изолирован в гостевой сети",
                    "badge_color": "emerald",
                    "is_isolated": True,
                    "hardware_enforced": True,
                    "recommendation": "Телевизор в гостевом сегменте. Для работы AirPlay/DLNA убедитесь, что включен mDNS-ретранслятор."
                }
        elif profile in ("trusted", "smart_home_hub"):
            return {
                "risk_level": "low",
                "level": "safe",
                "status": "Доверенное",
                "status_label": "Доверенное",
                "badge_color": "emerald",
                "is_isolated": is_isolated,
                "hardware_enforced": True,
                "recommendation": "Доверенное устройство домашней сети."
            }
        else:
            return {
                "risk_level": "medium" if not is_isolated else "low",
                "level": "warning" if not is_isolated else "safe",
                "status": "Внимание (L2 Bridge0)" if not is_isolated else "Изолировано",
                "status_label": f"Сегмент {clean_seg}",
                "badge_color": "amber" if not is_isolated else "emerald",
                "is_isolated": is_isolated,
                "hardware_enforced": is_isolated,
                "recommendation": "Рекомендуется проверить сегмент размещения устройства."
            }
