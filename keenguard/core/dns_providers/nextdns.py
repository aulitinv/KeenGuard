"""NextDNS Cloud Security Provider integration for KeenGuard."""
import logging
from typing import List, Optional
import httpx

from keenguard.core.dns_providers.base import (
    BaseDnsSecurityProvider,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)

logger = logging.getLogger("keenguard.dns_providers.nextdns")

NEXTDNS_API_BASE = "https://api.nextdns.io"


class NextDnsProvider(BaseDnsSecurityProvider):
    """Integration with NextDNS Cloud DoH/DoT service via official REST API."""

    def __init__(self, api_key: str = "", profile_id: str = ""):
        self.api_key = api_key.strip()
        self.profile_id = profile_id.strip()

    @property
    def provider_id(self) -> str:
        return "nextdns"

    @property
    def display_name(self) -> str:
        return "NextDNS"

    @property
    def is_cloud(self) -> bool:
        return True

    def _get_headers(self) -> dict:
        return {
            "X-Api-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "KeenGuard-NextDNS-Client/1.0",
        }

    async def test_connection(self) -> DnsProviderStatus:
        """Verifies API key and profile existence on NextDNS."""
        if not self.api_key or not self.profile_id:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="NextDNS",
                profile_or_version="",
                error_message="Не указан API Key или Profile ID",
            )

        url = f"{NEXTDNS_API_BASE}/profiles/{self.profile_id}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    profile_name = data.get("name", self.profile_id)
                    blocklists = data.get("security", {}).get("blocklists", [])
                    return DnsProviderStatus(
                        is_connected=True,
                        provider_name="NextDNS",
                        profile_or_version=f"Профиль: {profile_name} ({self.profile_id})",
                        active_filters_count=len(blocklists),
                    )
                elif resp.status_code in (401, 403):
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="NextDNS",
                        profile_or_version=self.profile_id,
                        error_message="Ошибка авторизации: неверный API-ключ NextDNS (HTTP 401/403)",
                    )
                elif resp.status_code == 404:
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="NextDNS",
                        profile_or_version=self.profile_id,
                        error_message=f"Профиль NextDNS '{self.profile_id}' не найден (HTTP 404)",
                    )
                else:
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="NextDNS",
                        profile_or_version=self.profile_id,
                        error_message=f"Ошибка сервера NextDNS: HTTP {resp.status_code}",
                    )
        except httpx.TimeoutException:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="NextDNS",
                profile_or_version=self.profile_id,
                error_message="Таймаут соединения с сервером NextDNS (10с)",
            )
        except Exception as e:
            logger.error("NextDNS test connection error: %s", e)
            return DnsProviderStatus(
                is_connected=False,
                provider_name="NextDNS",
                profile_or_version=self.profile_id,
                error_message=f"Сетевая ошибка: {str(e)}",
            )

    async def fetch_blocked_logs(
        self, since_iso: Optional[str] = None, limit: int = 100
    ) -> List[UnifiedBlockedDnsQuery]:
        """Fetches blocked domain queries from NextDNS analytics log."""
        if not self.api_key or not self.profile_id:
            return []

        url = f"{NEXTDNS_API_BASE}/profiles/{self.profile_id}/logs"
        params = {
            "status": "blocked",
            "limit": min(limit, 1000),
        }
        if since_iso:
            params["after"] = since_iso

        results: List[UnifiedBlockedDnsQuery] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self._get_headers(), params=params)
                if resp.status_code != 200:
                    logger.warning("NextDNS logs fetch failed: HTTP %s", resp.status_code)
                    return []

                data = resp.json().get("data", [])
                for entry in data:
                    domain = entry.get("domain", "").strip().lower().strip(".")
                    if not domain:
                        continue

                    # Ensure status is blocked if field is present
                    st = entry.get("status")
                    if st and st != "blocked":
                        continue

                    reasons = entry.get("reasons", [])
                    reason_names = [
                        r.get("name") for r in reasons if isinstance(r, dict) and r.get("name")
                    ]
                    filter_name = ", ".join(reason_names) if reason_names else "NextDNS Blocklist"
                    block_reason = filter_name

                    tracker_data = entry.get("tracker")
                    tracker_cat = (
                        tracker_data.get("category")
                        if isinstance(tracker_data, dict)
                        else (tracker_data if isinstance(tracker_data, str) else None)
                    )

                    results.append(
                        UnifiedBlockedDnsQuery(
                            domain=domain,
                            timestamp=entry.get("timestamp", ""),
                            client_ip=entry.get("clientIp"),
                            client_device_name=entry.get("deviceName"),
                            provider="nextdns",
                            block_reason=block_reason,
                            filter_list=filter_name,
                            tracker_category=tracker_cat,
                        )
                    )
        except Exception as e:
            logger.error("Error fetching NextDNS blocked logs: %s", e)

        return results
