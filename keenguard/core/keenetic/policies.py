"""Keenetic device policies, segment isolation, mDNS relay and DLNA access mixin."""
import logging
from typing import Dict, Any

logger = logging.getLogger("keenguard.keenetic.policies")


class KeeneticPoliciesMixin:
    """Methods for controlling device access policies, mDNS relays, and DLNA rules."""

    async def set_device_policy(self, mac: str, access: str = "permit") -> bool:
        """Sets device access policy: 'permit' or 'deny'."""
        logger.warning("HARDWARE MUTATION REQUEST: set_device_policy(mac=%s, access=%s)", mac, access)
        if getattr(self, "mock_mode", False):
            clean_mac = mac.upper()
            for h in getattr(self, "_mock_hosts", []):
                if str(h.get("mac", "")).upper() == clean_mac:
                    h["access"] = access
            return True

        payload = [{"ip": {"hotspot": {"host": {"mac": mac.lower(), "access": access}}}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        success = resp is not None and resp.status_code == 200
        if success:
            logger.warning("HARDWARE MUTATION APPLIED: Keenetic host %s access set to '%s'", mac, access)
        else:
            logger.error("HARDWARE MUTATION FAILED: Failed to set Keenetic host %s access to '%s'", mac, access)
        return success

    async def isolate_device_to_segment(self, mac: str, segment_id: str = "Guest") -> bool:
        """
        In KeeneticOS, Wi-Fi devices are bound to their physical SSID (Bridge0 for Home,
        Bridge1 for Guest). An API call cannot move a Wi-Fi client between SSIDs without reassociation.
        """
        clean_mac = mac.upper()
        if getattr(self, "mock_mode", False):
            for h in getattr(self, "_mock_hosts", []):
                if str(h.get("mac", "")).upper() == clean_mac:
                    if h.get("interface") == "Bridge0" or (h.get("ip") and h.get("ip").startswith("192.168.1.")):
                        return False
                    return True
            return False

        logger.info(
            "LAN isolation requested for %s. Note: In KeeneticOS, Wi-Fi devices must connect to Guest SSID.",
            mac
        )
        return False

    async def enable_mdns_relay(self) -> Dict[str, Any]:
        """
        Enable mDNS (Bonjour/AirPlay/Cast) relay between Home and Guest segments.
        Uses Keenetic's built-in UDP proxy component (KeeneticOS 3.1+).
        """
        if getattr(self, "mock_mode", False):
            return {"status": "ok", "method": "mock"}

        # Method 1: Configure UDP proxy for mDNS (port 5353)
        try:
            payload = [{"udp-proxy": {"listen": {"port": 5353}}}]
            resp = await self._send_request("POST", "/rci/", json_data=payload)
            if resp and resp.status_code == 200:
                logger.info("mDNS relay (UDP proxy port 5353) enabled on Keenetic")
                return {"status": "ok", "method": "udp-proxy"}
        except Exception as e:
            logger.debug("UDP proxy method failed: %s", e)

        # Method 2: Enable IGMP proxy
        try:
            payload2 = [{"ip": {"igmp": {"proxy": True}}}]
            resp2 = await self._send_request("POST", "/rci/", json_data=payload2)
            if resp2 and resp2.status_code == 200:
                logger.info("IGMP proxy enabled on Keenetic as mDNS relay fallback")
                return {"status": "ok", "method": "igmp-proxy"}
        except Exception as e:
            logger.debug("IGMP proxy method failed: %s", e)

        logger.warning(
            "Could not enable mDNS relay automatically. "
            "Install 'UDP Proxy' component in Keenetic UI: "
            "Система → Обновление компонентов → UDP Proxy"
        )
        return {
            "status": "warning",
            "method": None,
            "message": "Не удалось включить mDNS relay. "
                       "Установите компонент 'UDP Proxy' в настройках Keenetic "
                       "(Система → Обновление компонентов)."
        }

    async def set_dlna_access(self, mac: str, ip: str, allow: bool) -> bool:
        """
        Control DLNA (port 8200) access for a specific device via Keenetic ip policy.
        """
        if getattr(self, "mock_mode", False):
            return True

        comment = f"keenguard-dlna-{mac.replace(':', '').lower()}"

        if not allow and ip:
            payload = [{"ip": {"policy": {
                "deny": True,
                "protocol": "tcp",
                "src": ip,
                "dst": self.host,
                "dst-port": "8200",
                "comment": comment
            }}}]
        else:
            payload = [{"no": {"ip": {"policy": {"comment": comment}}}}]

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            action = "разрешён" if allow else "заблокирован"
            logger.info("DLNA access %s for %s (%s)", action, mac, ip)
            return True

        # Fallback: access-list
        if not allow and ip:
            payload2 = [{"access-list": {
                "keenguard-dlna": {
                    "deny": {"protocol": "tcp", "src": f"host {ip}",
                             "dst-port": "8200"}
                }
            }}]
            resp2 = await self._send_request("POST", "/rci/", json_data=payload2)
            if resp2 and resp2.status_code == 200:
                logger.info("DLNA access blocked via access-list for %s", mac)
                return True

        logger.warning("Could not enforce DLNA rule for %s via RCI.", mac)
        return False
