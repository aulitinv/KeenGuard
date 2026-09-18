"""Control D Cloud Security Provider integration for KeenGuard."""
from datetime import datetime, timezone
import logging
from typing import List, Optional, Any
import httpx

from keenguard.core.dns_providers.base import (
    BaseDnsSecurityProvider,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)

logger = logging.getLogger("keenguard.dns_providers.controld")

CONTROLD_API_BASE = "https://api.controld.com"


class ControlDProvider(BaseDnsSecurityProvider):
    """Integration with Control D Cloud DNS security platform."""

    def __init__(self, api_key: str = "", device_id: str = ""):
        self.api_key = api_key.strip()
        self.device_id = device_id.strip()

    @property
    def provider_id(self) -> str:
        return "controld"

    @property
    def display_name(self) -> str:
        return "Control D"

    @property
    def is_cloud(self) -> bool:
        return True

    def _get_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": "KeenGuard-ControlD-Client/1.0",
        }

    async def test_connection(self) -> DnsProviderStatus:
        """Verifies API key and retrieves device configuration on Control D."""
        if not self.api_key:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Control D",
                profile_or_version="",
                error_message="Не указан API Key для Control D",
            )

        url = f"{CONTROLD_API_BASE}/devices"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, headers=self._get_headers())
                if resp.status_code == 200:
                    data = resp.json().get("body", {})
                    devices = data.get("devices", [])
                    matched_dev = None
                    if self.device_id:
                        matched_dev = next(
                            (d for d in devices if str(d.get("PK")) == self.device_id or d.get("name") == self.device_id),
                            None
                        )

                    desc = f"Устройство: {matched_dev.get('name')} ({self.device_id})" if matched_dev else f"Всего профилей: {len(devices)}"
                    return DnsProviderStatus(
                        is_connected=True,
                        provider_name="Control D",
                        profile_or_version=desc,
                        active_filters_count=len(devices),
                    )
                elif resp.status_code in (401, 403):
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="Control D",
                        profile_or_version="",
                        error_message="Ошибка авторизации: неверный Bearer API-токен Control D (HTTP 401/403)",
                    )
                else:
                    return DnsProviderStatus(
                        is_connected=False,
                        provider_name="Control D",
                        profile_or_version="",
                        error_message=f"Ошибка сервера Control D: HTTP {resp.status_code}",
                    )
        except httpx.TimeoutException:
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Control D",
                profile_or_version="",
                error_message="Таймаут соединения с Control D (10с)",
            )
        except Exception as e:
            logger.error("Control D test connection error: %s", e)
            return DnsProviderStatus(
                is_connected=False,
                provider_name="Control D",
                profile_or_version="",
                error_message=f"Сетевая ошибка: {str(e)}",
            )

    def _normalize_timestamp(self, ts_val: Any) -> str:
        """Converts unix timestamp or raw date to ISO 8601 string."""
        if not ts_val:
            return datetime.now(timezone.utc).isoformat()
        if isinstance(ts_val, (int, float)):
            return datetime.fromtimestamp(ts_val, timezone.utc).isoformat()
        return str(ts_val)

    async def fetch_blocked_logs(
        self, since_iso: Optional[str] = None, limit: int = 100
    ) -> List[UnifiedBlockedDnsQuery]:
        """Fetches blocked activity log from Control D API."""
        if not self.api_key:
            return []

        url = f"{CONTROLD_API_BASE}/activity/log"
        params = {
            "action": "block",
            "limit": min(limit, 1000),
        }
        if self.device_id:
            params["device_id"] = self.device_id
        if since_iso:
            params["since"] = since_iso

        results: List[UnifiedBlockedDnsQuery] = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, headers=self._get_headers(), params=params)
                if resp.status_code != 200:
                    logger.warning("Control D log fetch failed: HTTP %s", resp.status_code)
                    return []

                body = resp.json().get("body", {})
                entries = body.get("activity", []) if isinstance(body, dict) else []
                for entry in entries:
                    domain = entry.get("domain", "").strip().lower().strip(".")
                    if not domain:
                        continue

                    # Filter blocked actions (0 = block in Control D, or "block"/"blocked")
                    act = entry.get("action")
                    if act is not None and act not in (0, "0", "block", "blocked"):
                        continue

                    rule_name = entry.get("rule_name") or entry.get("rule") or "Control D Policy"
                    category = entry.get("category") or rule_name

                    results.append(
                        UnifiedBlockedDnsQuery(
                            domain=domain,
                            timestamp=self._normalize_timestamp(entry.get("timestamp") or entry.get("time")),
                            client_ip=entry.get("source_ip") or entry.get("client_ip") or entry.get("ip"),
                            client_device_name=entry.get("device_name"),
                            provider="controld",
                            block_reason=category or rule_name,
                            filter_list=rule_name,
                            tracker_category=category,
                        )
                    )
        except Exception as e:
            logger.error("Error fetching Control D logs: %s", e)

        return results
