"""AdGuard Home On-Premise / LAN Security Provider integration for KeenGuard."""
import logging
from typing import List, Optional
import httpx

from keenguard.core.dns_providers.base import (
    BaseDnsSecurityProvider,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)

logger = logging.getLogger("keenguard.dns_providers.adguard")


class AdGuardHomeProvider(BaseDnsSecurityProvider):
    """Integration with AdGuard Home instances running on router, LAN or VPS."""

    def __init__(self, base_url: str = "", username: str = "", password: str = "", url: str = ""):
        self.base_url = (url or base_url).strip().rstrip("/")
        self.username = username.strip()
        self.password = password.strip()

    @property
    def provider_id(self) -> str:
        return "adguard_home"

    @property
    def display_name(self) -> str:
        return "AdGuard Home"

    @property
    def is_cloud(self) -> bool:
        return False

    def _get_auth(self) -> Optional[tuple]:
        if self.username and self.password:
            return (self.username, self.password)
        return None

    async def test_connection(self) -> DnsProviderStatus:
        """Verifies reachability and credentials against AdGuard Home /control/status."""
        if not self.base_url:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="AdGuard Home",
                profile_or_version="",
                error_message="Не указан URL инсталляции AdGuard Home",
            )

        url = f"{self.base_url}/control/status"
        try:
            async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
                resp = await client.get(url, auth=self._get_auth())
                if resp.status_code == 200:
                    data = resp.json()
                    version = data.get("version", "v0.x")
                    protection = data.get("protection_enabled", True)

                    # Fetch active filters count if possible
                    filter_count = 0
                    try:
                        f_resp = await client.get(f"{self.base_url}/control/filtering/status", auth=self._get_auth())
                        if f_resp.status_code == 200:
                            f_data = f_resp.json()
                            filter_count = len([f for f in f_data.get("filters", []) if f.get("enabled")])
                    except Exception:
                        pass

                    status_desc = f"AdGuard Home {version} ({'Защита активна' if protection else 'Защита отключена'})"
                    return DnsProviderStatus(
                        is_connected=True,
                        provider_name="AdGuard Home",
                        profile_or_version=status_desc,
                        active_filters_count=filter_count,
                    )
                elif resp.status_code in (401, 403):
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="AdGuard Home",
                        profile_or_version="",
                        error_message="Ошибка авторизации: неверный логин или пароль AdGuard Home (HTTP 401/403)",
                    )
                else:
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="AdGuard Home",
                        profile_or_version="",
                        error_message=f"Ошибка сервера AdGuard Home: HTTP {resp.status_code}",
                    )
        except httpx.TimeoutException:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="AdGuard Home",
                profile_or_version="",
                error_message=f"Таймаут подключения к {self.base_url} (8с)",
            )
        except httpx.ConnectError:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="AdGuard Home",
                profile_or_version="",
                error_message=f"Не удалось подключиться к серверу {self.base_url} (порт закрыт или сервер недоступен)",
            )
        except Exception as e:
            logger.error("AdGuard Home test connection error: %s", e)
            return DnsProviderStatus(
                is_connected=False,
                provider_name="AdGuard Home",
                profile_or_version="",
                error_message=f"Сетевая ошибка: {str(e)}",
            )

    async def fetch_blocked_logs(
        self, since_iso: Optional[str] = None, limit: int = 100
    ) -> List[UnifiedBlockedDnsQuery]:
        """Fetches query log entries blocked by AdGuard Home rules."""
        if not self.base_url:
            return []

        url = f"{self.base_url}/control/querylog"
        params = {
            "response_status": "blocked",
            "limit": min(limit, 500),
        }

        results: List[UnifiedBlockedDnsQuery] = []
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                resp = await client.get(url, auth=self._get_auth(), params=params)
                if resp.status_code != 200:
                    logger.warning("AdGuard Home querylog fetch failed: HTTP %s", resp.status_code)
                    return []

                data = resp.json().get("data", [])
                for entry in data:
                    q = entry.get("question", {})
                    domain = (q.get("name") or q.get("host") or "").strip().lower().strip(".")
                    if not domain:
                        continue

                    # Filter out non-blocked queries
                    raw_reason = entry.get("reason", "FilteredBlackList")
                    if str(raw_reason).startswith("NotFiltered"):
                        continue

                    rules = entry.get("rules") or []
                    rule_text = entry.get("rule") or (rules[0].get("text") if rules and isinstance(rules[0], dict) else "AdGuard Filter")

                    client_info = entry.get("client_info") or {}
                    client_name = client_info.get("name") if isinstance(client_info, dict) else None

                    results.append(
                        UnifiedBlockedDnsQuery(
                            domain=domain,
                            timestamp=entry.get("time", ""),
                            client_ip=entry.get("client"),
                            client_device_name=client_name,
                            provider="adguard_home",
                            block_reason=raw_reason,
                            filter_list=rule_text,
                            tracker_category="Ad/Tracker Block",
                        )
                    )
        except Exception as e:
            logger.error("Error fetching AdGuard Home logs: %s", e)

        return results
