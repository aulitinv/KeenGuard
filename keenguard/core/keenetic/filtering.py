"""Keenetic network filtering, UPnP management, DNS sinkholes, and IP blackholing mixin."""
import ipaddress
import logging
from typing import Dict, Any, List, Optional, Tuple
from keenguard.core.keenetic.models import UPnPMapping, is_unsafe_ip_for_blackhole

logger = logging.getLogger("keenguard.keenetic.filtering")


class KeeneticFilteringMixin:
    """Methods for UPnP rules, DNS sinkholes, and IP blackholing."""

    async def get_upnp_mappings(self) -> List[UPnPMapping]:
        """Pulls current UPnP / NAT-PMP port forwarding rules."""
        if getattr(self, "mock_mode", False):
            return [UPnPMapping(**m) for m in getattr(self, "_mock_upnp", [])]

        resp = await self._send_request("GET", "/rci/show/upnp")
        if resp and resp.status_code == 200:
            raw = resp.json().get("rule", [])
            result = []
            for r in raw:
                iface = r.get("interface")
                if isinstance(iface, dict):
                    iface_str = iface.get("name") or iface.get("id")
                else:
                    iface_str = str(iface) if iface else None

                result.append(UPnPMapping(
                    interface=iface_str,
                    protocol=r.get("protocol", "tcp"),
                    ext_port=int(r.get("port", 0)),
                    int_ip=r.get("to-address", ""),
                    int_port=int(r.get("to-port", 0)),
                    description=r.get("description")
                ))
            return result
        return []

    get_upnp_table = get_upnp_mappings

    async def delete_upnp_mapping(self, protocol: str, ext_port: int) -> bool:
        """Deletes a dangerous UPnP port forwarding rule."""
        logger.warning("Deleting dangerous UPnP rule: %s port %d", protocol, ext_port)
        if getattr(self, "mock_mode", False):
            self._mock_upnp = [m for m in getattr(self, "_mock_upnp", []) if not (m.get("protocol") == protocol and m.get("ext_port") == ext_port)]
            return True

        payload = [{"no": "upnp", "rule": {"protocol": protocol, "port": ext_port}}]
        resp = await self._send_request("POST", "/rci/", json_data=payload)
        return resp is not None and resp.status_code == 200

    async def add_dns_sinkholes(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch blocks domains on Keenetic by creating static DNS host entries resolving to 0.0.0.0.
        Returns a tuple of (succeeded_domains, failed_domains).
        """
        valid_domains = []
        for d in domains:
            clean_d = d.lower().strip().strip(".")
            if not clean_d or "." not in clean_d:
                continue
            try:
                ipaddress.ip_address(clean_d)
                logger.warning("Rejecting IP address %s from DNS sinkhole (sinkhole requires domain names)", clean_d)
                continue
            except ValueError:
                pass
            if clean_d in ("localhost", "my.keenetic.net", "keenetic.net", "router") or clean_d.endswith((".keenetic.link", ".keenetic.pro", ".local", ".lan", ".home")):
                logger.warning("Rejecting router/local domain %s from DNS sinkhole", clean_d)
                continue
            if clean_d not in valid_domains:
                valid_domains.append(clean_d)

        if not valid_domains:
            return [], []

        logger.info("Adding %d Keenetic DNS sinkhole(s) -> 0.0.0.0: %s", len(valid_domains), valid_domains[:5])
        if getattr(self, "mock_mode", False):
            if not hasattr(self, "_mock_sinkholes"):
                self._mock_sinkholes = set()
            for d in valid_domains:
                self._mock_sinkholes.add(d)
            return valid_domains, []

        payload = [{"ip": {"host": {"domain": d, "address": "0.0.0.0"}}} for d in valid_domains]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, d in enumerate(valid_domains):
                        if idx < len(data):
                            item = data[idx]
                            host_res = item.get("ip", {}).get("host", {})
                            statuses = host_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    if s.get("status") == "error":
                                        has_error = True
                                        logger.warning("Keenetic RCI error adding sinkhole %s: %s", d, s.get("message"))
                                        break
                            if has_error:
                                failed.append(d)
                            else:
                                succeeded.append(d)
                        else:
                            succeeded.append(d)
                else:
                    succeeded = valid_domains
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI batch add response: %s", e)
                succeeded = valid_domains
        else:
            failed = valid_domains

        return succeeded, failed

    async def add_dns_sinkhole(self, domain: str) -> bool:
        """Blocks a single domain on Keenetic."""
        clean_d = domain.lower().strip().strip(".")
        if not clean_d or "." not in clean_d:
            return False
        succeeded, _ = await self.add_dns_sinkholes([clean_d])
        return clean_d in succeeded

    async def remove_dns_sinkholes(self, domains: List[str]) -> Tuple[List[str], List[str]]:
        """Batch removes static DNS sinkhole rules from Keenetic."""
        clean_domains = [d.lower().strip().strip(".") for d in domains if d.strip()]
        if not clean_domains:
            return [], []

        logger.info("Removing %d Keenetic DNS sinkhole(s): %s", len(clean_domains), clean_domains[:5])
        if getattr(self, "mock_mode", False):
            if hasattr(self, "_mock_sinkholes"):
                for d in clean_domains:
                    self._mock_sinkholes.discard(d)
            return clean_domains, []

        payload = [{"ip": {"host": {"domain": d, "address": "0.0.0.0", "no": True}}} for d in clean_domains]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, d in enumerate(clean_domains):
                        if idx < len(data):
                            item = data[idx]
                            host_res = item.get("ip", {}).get("host", {})
                            statuses = host_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    # code 22544392 is 'no such record', which still means the record is absent
                                    if s.get("status") == "error" and s.get("code") != "22544392":
                                        has_error = True
                                        logger.warning("Keenetic RCI error removing sinkhole %s: %s", d, s.get("message"))
                                        break
                            if has_error:
                                failed.append(d)
                            else:
                                succeeded.append(d)
                        else:
                            succeeded.append(d)
                else:
                    succeeded = clean_domains
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI batch remove response: %s", e)
                succeeded = clean_domains
        else:
            failed = clean_domains

        return succeeded, failed

    async def remove_dns_sinkhole(self, domain: str) -> bool:
        """Removes a single domain from Keenetic sinkhole."""
        clean_d = domain.lower().strip().strip(".")
        if not clean_d:
            return False
        succeeded, _ = await self.remove_dns_sinkholes([clean_d])
        return clean_d in succeeded

    async def get_active_sinkholes(self) -> List[str]:
        """Fetches all statically configured 0.0.0.0 host sinkholes from Keenetic."""
        if getattr(self, "mock_mode", False):
            return sorted(list(getattr(self, "_mock_sinkholes", set())))

        sinkholes = set()
        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"running-config": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    lines = data[0].get("show", {}).get("running-config", {}).get("message", [])
                    for line in lines:
                        clean_line = line.strip()
                        if clean_line.startswith("ip host ") and (" 0.0.0.0" in clean_line or " ::" in clean_line):
                            parts = clean_line.split()
                            if len(parts) >= 4:
                                sinkholes.add(parts[2].lower())
        except Exception as e:
            logger.debug("Error fetching active sinkholes from Keenetic: %s", e)

        return sorted(list(sinkholes))

    async def add_ip_blackholes(self, ips: List[str]) -> Tuple[List[str], List[str]]:
        """
        Batch blackholes malicious external IP addresses on Keenetic using static reject routes.
        """
        valid_ips = []
        rejected_ips = []
        for raw_ip in ips:
            clean_ip = raw_ip.strip()
            try:
                ip_obj = ipaddress.ip_address(clean_ip)
                if is_unsafe_ip_for_blackhole(ip_obj):
                    logger.warning("SAFETY CHECK: Refusing to blackhole unsafe or local IP %s", clean_ip)
                    rejected_ips.append(clean_ip)
                    continue
                if clean_ip not in valid_ips:
                    valid_ips.append(clean_ip)
            except ValueError:
                logger.warning("Invalid IP address provided for blackhole: %s", clean_ip)
                rejected_ips.append(clean_ip)

        if not valid_ips:
            return [], rejected_ips

        logger.info("Adding %d Keenetic IP blackhole(s) via reject route: %s", len(valid_ips), valid_ips[:5])
        if getattr(self, "mock_mode", False):
            if not hasattr(self, "_mock_ip_blackholes"):
                self._mock_ip_blackholes = set()
            for ip in valid_ips:
                self._mock_ip_blackholes.add(ip)
            return valid_ips, rejected_ips

        payload = [{"ip": {"route": {"destination": f"{ip}/32", "reject": True, "comment": "keenguard-blackhole"}}} for ip in valid_ips]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = list(rejected_ips)

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list):
                    for idx, ip in enumerate(valid_ips):
                        if idx < len(data):
                            item = data[idx]
                            route_res = item.get("ip", {}).get("route", {})
                            statuses = route_res.get("status", [])
                            has_error = False
                            if isinstance(statuses, list):
                                for s in statuses:
                                    if s.get("status") == "error":
                                        has_error = True
                                        logger.warning("Keenetic RCI error adding IP blackhole %s: %s", ip, s.get("message"))
                                        break
                            if has_error:
                                failed.append(ip)
                            else:
                                succeeded.append(ip)
                        else:
                            succeeded.append(ip)
                else:
                    succeeded = valid_ips
            except Exception as e:
                logger.debug("Error parsing Keenetic RCI IP blackhole add response: %s", e)
                succeeded = valid_ips
        else:
            failed.extend(valid_ips)

        return succeeded, failed

    async def remove_ip_blackholes(self, ips: List[str]) -> Tuple[List[str], List[str]]:
        """Batch removes static reject IP routes from Keenetic."""
        clean_ips = [ip.strip() for ip in ips if ip.strip()]
        if not clean_ips:
            return [], []

        logger.info("Removing %d Keenetic IP blackhole(s): %s", len(clean_ips), clean_ips[:5])
        if getattr(self, "mock_mode", False):
            if hasattr(self, "_mock_ip_blackholes"):
                for ip in clean_ips:
                    self._mock_ip_blackholes.discard(ip)
            return clean_ips, []

        payload = [{"no": {"ip": {"route": {"destination": f"{ip}/32", "reject": True}}}} for ip in clean_ips]
        payload.append({"system": {"configuration": {"save": {}}}})

        succeeded: List[str] = []
        failed: List[str] = []

        resp = await self._send_request("POST", "/rci/", json_data=payload)
        if resp and resp.status_code == 200:
            succeeded = clean_ips
        else:
            failed = clean_ips

        return succeeded, failed

    async def get_active_ip_blackholes(self) -> List[str]:
        """Fetches currently configured static reject IP routes from Keenetic running-config."""
        if getattr(self, "mock_mode", False):
            return sorted(list(getattr(self, "_mock_ip_blackholes", set())))

        blackholes = set()
        try:
            resp = await self._send_request("POST", "/rci/", json_data=[{"show": {"running-config": {}}}])
            if resp and resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list) and data:
                    lines = data[0].get("show", {}).get("running-config", {}).get("message", [])
                    for line in lines:
                        clean_line = line.strip()
                        if clean_line.startswith("ip route ") and "reject" in clean_line:
                            parts = clean_line.split()
                            if len(parts) >= 3:
                                target_ip = parts[2].split("/")[0]
                                try:
                                    ipaddress.ip_address(target_ip)
                                    blackholes.add(target_ip)
                                except ValueError:
                                    pass
        except Exception as e:
            logger.debug("Error fetching active IP blackholes from Keenetic: %s", e)
        return sorted(list(blackholes))
