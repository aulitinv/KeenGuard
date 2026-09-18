"""Orchestrator and lifecycle manager for external DNS security providers."""
import asyncio
from datetime import datetime, timezone
import logging
from typing import Dict, Optional, Any, List

from keenguard.config import settings
from keenguard.core.dns_providers.base import (
    BaseDnsSecurityProvider,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)
from keenguard.core.dns_providers.nextdns import NextDnsProvider
from keenguard.core.dns_providers.controld import ControlDProvider
from keenguard.core.dns_providers.adguard import AdGuardHomeProvider
from keenguard.core.dns_providers.pihole import PiHoleProvider
from keenguard.db.database import db

logger = logging.getLogger("keenguard.dns_providers.manager")


class DnsSecurityManager:
    """Manages active DNS security provider, periodic synchronization, and LAN device resolution."""

    def __init__(self):
        self._providers: Dict[str, BaseDnsSecurityProvider] = {}
        self._active_provider_id: str = "none"
        self._sync_task: Optional[asyncio.Task] = None
        self._sync_lock = asyncio.Lock()
        self._ws_broadcast_fn = None
        self.reload_from_config()

    def set_ws_broadcast(self, fn):
        """Sets callback for broadcasting WebSocket events to UI."""
        self._ws_broadcast_fn = fn

    def reload_from_config(self):
        """Re-initializes all providers based on current application settings."""
        self._active_provider_id = getattr(settings, "dns_security_provider", "none") or "none"

        self._providers["nextdns"] = NextDnsProvider(
            api_key=getattr(settings, "nextdns_api_key", ""),
            profile_id=getattr(settings, "nextdns_profile_id", ""),
        )
        self._providers["controld"] = ControlDProvider(
            api_key=getattr(settings, "controld_api_key", ""),
            device_id=getattr(settings, "controld_device_id", ""),
        )
        self._providers["adguard_home"] = AdGuardHomeProvider(
            base_url=getattr(settings, "adguard_url", ""),
            username=getattr(settings, "adguard_username", ""),
            password=getattr(settings, "adguard_password", ""),
        )
        self._providers["pihole"] = PiHoleProvider(
            base_url=getattr(settings, "pihole_url", ""),
            api_token=getattr(settings, "pihole_api_token", ""),
            password=getattr(settings, "pihole_password", ""),
        )

    @property
    def active_provider_id(self) -> str:
        return self._active_provider_id

    def get_provider(self, provider_id: str) -> Optional[BaseDnsSecurityProvider]:
        return self._providers.get(provider_id)

    def get_active_provider(self) -> Optional[BaseDnsSecurityProvider]:
        if self._active_provider_id == "none":
            return None
        return self._providers.get(self._active_provider_id)

    def create_ephemeral_provider(self, provider_id: str, cfg: dict) -> Optional[BaseDnsSecurityProvider]:
        """Creates a temporary provider instance with explicit credentials for connection testing."""
        if provider_id == "nextdns":
            return NextDnsProvider(
                api_key=cfg.get("nextdns_api_key", ""),
                profile_id=cfg.get("nextdns_profile_id", ""),
            )
        elif provider_id == "controld":
            return ControlDProvider(
                api_key=cfg.get("controld_api_key", ""),
                device_id=cfg.get("controld_device_id", ""),
            )
        elif provider_id == "adguard_home":
            return AdGuardHomeProvider(
                base_url=cfg.get("adguard_url", ""),
                username=cfg.get("adguard_username", ""),
                password=cfg.get("adguard_password", ""),
            )
        elif provider_id == "pihole":
            return PiHoleProvider(
                base_url=cfg.get("pihole_url", ""),
                api_token=cfg.get("pihole_api_token", ""),
                password=cfg.get("pihole_password", ""),
            )
        return None

    async def test_provider(
        self, provider_id: str, config_override: Optional[dict] = None
    ) -> DnsProviderStatus:
        """Tests connection to a specified provider using either saved or supplied configuration."""
        if provider_id == "none":
            return DnsProviderStatus(
                is_connected=True,
                provider_name="Отключено",
                profile_or_version="Интеграция выключена",
            )

        provider = None
        if config_override:
            provider = self.create_ephemeral_provider(provider_id, config_override)
        if not provider:
            provider = self.get_provider(provider_id)

        if not provider:
            return DnsProviderStatus(
                is_connected=False,
                provider_name=provider_id,
                profile_or_version="",
                error_message=f"Неизвестный провайдер: {provider_id}",
            )

        return await provider.test_connection()

    async def sync_blocked_logs(self, limit: int = 150) -> Dict[str, Any]:
        """Synchronizes blocked query logs from the active provider and attributes them to LAN devices."""
        async with self._sync_lock:
            provider = self.get_active_provider()
            if not provider:
                return {
                    "success": False,
                    "count": 0,
                    "provider": "none",
                    "message": "Внешний DNS-провайдер отключен или не настроен",
                }

            provider_id = provider.provider_id
            now_iso = datetime.now(timezone.utc).isoformat()

            # 1. Fetch metadata of previous sync
            meta = await db.get_dns_provider_sync_meta(provider_id)
            since_ts = meta.get("last_record_timestamp") if meta else None

            # 2. Fetch blocked queries from provider
            try:
                queries = await provider.fetch_blocked_logs(since_iso=since_ts, limit=limit)
            except Exception as e:
                logger.error("Error fetching logs from %s: %s", provider_id, e)
                await db.update_dns_provider_sync_meta(
                    provider=provider_id,
                    last_sync_time=now_iso,
                    last_record_timestamp=since_ts or "",
                    total_synced=meta.get("total_blocked_synced", 0) if meta else 0,
                    last_status="error",
                    last_error=str(e),
                )
                return {
                    "success": False,
                    "count": 0,
                    "provider": provider_id,
                    "error": str(e),
                }

            if not queries:
                await db.update_dns_provider_sync_meta(
                    provider=provider_id,
                    last_sync_time=now_iso,
                    last_record_timestamp=since_ts or "",
                    total_synced=meta.get("total_blocked_synced", 0) if meta else 0,
                    last_status="success",
                    last_error=None,
                )
                return {
                    "success": True,
                    "count": 0,
                    "provider": provider_id,
                    "message": "Новых заблокированных запросов нет",
                }

            # 3. Build device lookup maps from KeenGuard DB for client attribution
            devices = await db.get_all_devices()
            ip_to_dev: Dict[str, Any] = {}
            name_to_dev: Dict[str, Any] = {}

            for d in devices:
                if d.ip:
                    ip_to_dev[d.ip.strip()] = d
                if d.hostname:
                    name_to_dev[d.hostname.strip().lower()] = d
                if d.custom_name:
                    name_to_dev[d.custom_name.strip().lower()] = d

            # 4. Ingest blocked records
            ingested_count = 0
            latest_record_ts = since_ts or ""

            for q in queries:
                matched_mac = None
                matched_ip = q.client_ip

                # Match by IP
                if q.client_ip and q.client_ip in ip_to_dev:
                    matched_mac = ip_to_dev[q.client_ip].mac
                # Or match by device name
                elif q.client_device_name:
                    clean_name = q.client_device_name.strip().lower()
                    if clean_name in name_to_dev:
                        matched_dev = name_to_dev[clean_name]
                        matched_mac = matched_dev.mac
                        if not matched_ip:
                            matched_ip = matched_dev.ip

                # Save into SQLite
                await db.record_blocked_dns_query(
                    domain=q.domain,
                    client_ip=matched_ip,
                    mac=matched_mac,
                    timestamp=q.timestamp or now_iso,
                    provider=q.provider,
                    block_reason=q.block_reason,
                    filter_list=q.filter_list,
                    tracker_category=q.tracker_category,
                )
                ingested_count += 1

                if q.timestamp and q.timestamp > latest_record_ts:
                    latest_record_ts = q.timestamp

            # 5. Update sync metadata
            prev_total = (meta.get("total_blocked_synced", 0) if meta else 0)
            new_total = prev_total + ingested_count
            await db.update_dns_provider_sync_meta(
                provider=provider_id,
                last_sync_time=now_iso,
                last_record_timestamp=latest_record_ts,
                total_synced=new_total,
                last_status="success",
                last_error=None,
            )

            # 6. Notify UI via WebSocket if available
            if self._ws_broadcast_fn:
                try:
                    await self._ws_broadcast_fn({
                        "type": "dns_provider_synced",
                        "provider": provider_id,
                        "ingested_count": ingested_count,
                        "total_synced": new_total,
                        "last_sync": now_iso,
                    })
                except Exception as ws_err:
                    logger.debug("WS broadcast error: %s", ws_err)

            return {
                "success": True,
                "count": ingested_count,
                "total_synced": new_total,
                "provider": provider_id,
                "last_sync": now_iso,
            }

    def start_background_sync(self, interval_seconds: int = 60):
        """Starts the background polling task if auto-sync is enabled."""
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()

        if self._active_provider_id == "none" or not getattr(settings, "dns_security_auto_sync", False):
            logger.info("DNS provider background sync is disabled")
            return

        interval = max(interval_seconds, 15)

        async def _sync_loop():
            logger.info("DNS provider background sync started (interval: %ds, provider: %s)", interval, self._active_provider_id)
            while True:
                try:
                    await asyncio.sleep(interval)
                    if self._active_provider_id != "none":
                        res = await self.sync_blocked_logs()
                        if res.get("count", 0) > 0:
                            logger.info("Synced %d blocked DNS queries from %s", res["count"], self._active_provider_id)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error("Error in DNS security sync loop: %s", e)
                    await asyncio.sleep(10)

        self._sync_task = asyncio.create_task(_sync_loop())

    def stop_background_sync(self):
        """Stops the background polling task."""
        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            self._sync_task = None
            logger.info("DNS provider background sync stopped")


# Global singleton instance
dns_security_manager = DnsSecurityManager()
