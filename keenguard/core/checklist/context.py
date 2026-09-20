"""Context builder for security checklist evaluation."""
import logging
from typing import Dict, Any, List, Optional
from keenguard.db.database import db
from keenguard.core.keenetic import keenetic_client
from keenguard.core.classifier import DeviceClassifier
from keenguard.db.models import DeviceRecord, SecurityEvent

logger = logging.getLogger("keenguard.checklist.context")


class ChecklistContext:
    """Holds pre-fetched database and router state for all checklist evaluators."""

    def __init__(self):
        self.devices: List[DeviceRecord] = []
        self.events: List[SecurityEvent] = []
        self.device_domains_map: Dict[str, List[str]] = {}
        self.hub_dev: Optional[DeviceRecord] = None
        self.iot_devs: List[DeviceRecord] = []
        self.camera_devs: List[DeviceRecord] = []
        self.tv_devs: List[DeviceRecord] = []
        self.random_mac_devs: List[DeviceRecord] = []
        self.quarantine_devs: List[DeviceRecord] = []
        self.device_trust_map: Dict[str, Any] = {}
        self.wifi_security: Dict[str, Any] = {}
        self.firmware_info: Dict[str, Any] = {}
        self.upnp_entries: List[Any] = []

    @classmethod
    async def load(cls) -> "ChecklistContext":
        ctx = cls()
        ctx.devices = await db.get_all_devices()
        ctx.events = await db.get_recent_events(limit=100)
        ctx.device_domains_map = await db.get_device_domains_map()

        for d in ctx.devices:
            domains = ctx.device_domains_map.get(d.mac, [])
            trust = DeviceClassifier.classify_iot_trust_tier(d, observed_domains=domains)
            ctx.device_trust_map[d.mac] = trust

            tier = trust["tier"]
            if tier == "controller" or d.profile == "smart_home_hub" or "sprut" in str(d.hostname).lower():
                if not ctx.hub_dev or "sprut" in str(d.hostname).lower():
                    ctx.hub_dev = d
            elif tier == "camera" or d.profile == "camera":
                ctx.camera_devs.append(d)
            elif tier == "media_tv" or d.profile == "smart_tv":
                ctx.tv_devs.append(d)
            elif (tier in ("pure_local", "hybrid_weather", "cloud_appliance") or d.profile == "iot") and tier not in ("trusted_pc_phone", "unassigned") and d.profile != "trusted":
                ctx.iot_devs.append(d)

            if DeviceClassifier.is_randomized_mac(d.mac):
                ctx.random_mac_devs.append(d)

            if d.profile == "unassigned" or (d.is_blocked_wan and d.is_isolated_lan and tier not in ("pure_local", "camera")):
                ctx.quarantine_devs.append(d)

        try:
            ctx.wifi_security = await keenetic_client.get_wifi_security()
        except Exception as e:
            logger.debug("Failed to query wifi security for checklist: %s", e)

        try:
            ctx.firmware_info = await keenetic_client.check_firmware_updates()
        except Exception as e:
            logger.debug("Failed to query firmware updates for checklist: %s", e)

        try:
            ctx.upnp_entries = await keenetic_client.get_upnp_mappings()
        except Exception as e:
            logger.debug("Failed to query upnp table for checklist: %s", e)

        return ctx
