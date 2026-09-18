"""Pi-hole FTL DNS Security Provider integration for KeenGuard (v5 and v6)."""
from datetime import datetime, timezone
import logging
from typing import List, Optional, Any
import httpx

from keenguard.core.dns_providers.base import (
    BaseDnsSecurityProvider,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)

logger = logging.getLogger("keenguard.dns_providers.pihole")

# Pi-hole v5 blocked status code mappings
PIHOLE_V5_BLOCKED_STATUSES = {
    1: "Pi-hole Gravity (Adlist)",
    4: "Pi-hole Regex Filter",
    5: "Pi-hole Exact Blacklist",
    6: "Pi-hole Upstream Filter",
    7: "Pi-hole Upstream Filter",
    8: "Pi-hole Upstream Filter",
    9: "Pi-hole Gravity (Live)",
    10: "Pi-hole Regex (Live)",
    11: "Pi-hole Exact Blacklist (Live)",
    15: "Pi-hole Database Blacklist",
    16: "Pi-hole Special Domain Block",
}


class PiHoleProvider(BaseDnsSecurityProvider):
    """Integration with Pi-hole DNS sinkhole running in local network."""

    def __init__(self, base_url: str = "", api_token: str = "", password: str = "", url: str = ""):
        self.base_url = (url or base_url).strip().rstrip("/")
        self.api_token = api_token.strip()
        self.password = password.strip()

    @property
    def provider_id(self) -> str:
        return "pihole"

    @property
    def display_name(self) -> str:
        return "Pi-hole"

    @property
    def is_cloud(self) -> bool:
        return False

    def _normalize_timestamp(self, ts_val: Any) -> str:
        if not ts_val:
            return datetime.now(timezone.utc).isoformat()
        try:
            val = float(ts_val)
            return datetime.fromtimestamp(val, timezone.utc).isoformat()
        except (ValueError, TypeError):
            return str(ts_val)

    async def test_connection(self) -> DnsProviderStatus:
        """Tests connectivity and checks blocked domain count on Pi-hole."""
        if not self.base_url:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Pi-hole",
                profile_or_version="",
                error_message="Не указан URL инсталляции Pi-hole",
            )

        # 1. Try Pi-hole v5 API endpoint
        v5_url = f"{self.base_url}/admin/api.php?summaryRaw"
        if self.api_token:
            v5_url += f"&auth={self.api_token}"

        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(v5_url)
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, dict) and "domains_being_blocked" in data:
                        status = data.get("status", "enabled")
                        blocked_count = int(data.get("domains_being_blocked", 0))
                        status_desc = f"Pi-hole v5 ({'Активен' if status == 'enabled' else 'Приостановлен'})"
                        return DnsProviderStatus(
                            is_connected=True,
                            provider_name="Pi-hole",
                            profile_or_version=status_desc,
                            active_filters_count=blocked_count,
                        )

                # 2. Try Pi-hole v6 API endpoint if v5 returned 404 or empty
                v6_url = f"{self.base_url}/api/stats/summary"
                headers = {}
                if self.api_token:
                    headers["Authorization"] = f"Bearer {self.api_token}"

                v6_resp = await client.get(v6_url, headers=headers)
                if v6_resp.status_code == 200:
                    data = v6_resp.json()
                    blocked_count = data.get("queries", {}).get("blocked", 0)
                    return DnsProviderStatus(
                        is_connected=True,
                        provider_name="Pi-hole",
                        profile_or_version="Pi-hole v6 (FTL REST API)",
                        active_filters_count=blocked_count,
                    )
                elif v6_resp.status_code in (401, 403):
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="Pi-hole",
                        profile_or_version="",
                        error_message="Ошибка авторизации: неверный API-токен Pi-hole (HTTP 401/403)",
                    )
                else:
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="Pi-hole",
                        profile_or_version="",
                        error_message=f"Сервер Pi-hole ответил кодом HTTP {resp.status_code}",
                    )
        except httpx.TimeoutException:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Pi-hole",
                profile_or_version="",
                error_message=f"Таймаут подключения к Pi-hole {self.base_url} (8с)",
            )
        except httpx.ConnectError:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Pi-hole",
                profile_or_version="",
                error_message=f"Не удалось подключиться к {self.base_url} (сервер Pi-hole недоступен)",
            )
        except Exception as e:
            logger.error("Pi-hole test connection error: %s", e)
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Pi-hole",
                profile_or_version="",
                error_message=f"Сетевая ошибка: {str(e)}",
            )

    async def fetch_blocked_logs(
        self, since_iso: Optional[str] = None, limit: int = 100
    ) -> List[UnifiedBlockedDnsQuery]:
        """Fetches blocked DNS queries from Pi-hole v5/v6 querylog."""
        if not self.base_url:
            return []

        results: List[UnifiedBlockedDnsQuery] = []
        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False) as client:
                # Attempt Pi-hole v5 querylog
                v5_url = f"{self.base_url}/admin/api.php?getAllQueries={min(limit, 500)}"
                if self.api_token:
                    v5_url += f"&auth={self.api_token}"

                resp = await client.get(v5_url)
                if resp.status_code == 200:
                    raw = resp.json()
                    data_rows = raw.get("data", []) if isinstance(raw, dict) else []
                    for row in data_rows:
                        if len(row) >= 5:
                            raw_ts, _qtype, domain, client_ip, status_code = row[0], row[1], row[2], row[3], row[4]
                            try:
                                status_int = int(status_code)
                            except (ValueError, TypeError):
                                status_int = 0

                            if status_int in PIHOLE_V5_BLOCKED_STATUSES:
                                clean_dom = str(domain).strip().lower().strip(".")
                                reason = PIHOLE_V5_BLOCKED_STATUSES[status_int]
                                results.append(
                                    UnifiedBlockedDnsQuery(
                                        domain=clean_dom,
                                        timestamp=self._normalize_timestamp(raw_ts),
                                        client_ip=str(client_ip) if client_ip else None,
                                        client_device_name=None,
                                        provider="pihole",
                                        block_reason=reason,
                                        filter_list="Pi-hole Gravity / Blacklist",
                                        tracker_category="Ad/Tracker Block",
                                    )
                                )
                    if results:
                        return results

                # If v5 did not return data, attempt Pi-hole v6 API
                v6_url = f"{self.base_url}/api/queries?blocked=true&count={min(limit, 500)}"
                headers = {}
                if self.api_token:
                    headers["Authorization"] = f"Bearer {self.api_token}"

                v6_resp = await client.get(v6_url, headers=headers)
                if v6_resp.status_code == 200:
                    v6_data = v6_resp.json()
                    queries = v6_data.get("queries", []) if isinstance(v6_data, dict) else []
                    for q in queries:
                        domain = str(q.get("domain", "")).strip().lower().strip(".")
                        if not domain:
                            continue
                        client_obj = q.get("client") or {}
                        c_ip = client_obj.get("ip") if isinstance(client_obj, dict) else str(client_obj)
                        c_name = client_obj.get("name") if isinstance(client_obj, dict) else None

                        results.append(
                            UnifiedBlockedDnsQuery(
                                domain=domain,
                                timestamp=self._normalize_timestamp(q.get("time")),
                                client_ip=c_ip,
                                client_device_name=c_name,
                                provider="pihole",
                                block_reason=q.get("status", "Gravity Block"),
                                filter_list="Pi-hole Gravity",
                                tracker_category="Ad/Tracker Block",
                            )
                        )
        except Exception as e:
            logger.error("Error fetching Pi-hole logs: %s", e)

        return results
