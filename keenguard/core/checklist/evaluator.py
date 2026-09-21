"""Checklist evaluator orchestrating all 11 security checks."""
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from keenguard.core.checklist.context import ChecklistContext
from keenguard.core.checklist.device_checks import (
    evaluate_hub_isolation,
    evaluate_iot_egress_policy,
    evaluate_lateral_movement_isolation,
    evaluate_camera_upnp_security,
    evaluate_smart_tv_security,
)
from keenguard.core.checklist.network_checks import (
    evaluate_wifi_security,
    evaluate_firmware_updates,
    evaluate_dns_protection,
    evaluate_continuous_quarantine,
    evaluate_arp_mac_spoofing,
    evaluate_hardware_segmentation,
)
from keenguard.core.routers import router_manager

logger = logging.getLogger("keenguard.checklist.evaluator")


class SecurityChecklistEvaluator:
    @staticmethod
    async def evaluate_checklist() -> Dict[str, Any]:
        """Evaluates all security checks against live router state, database, and observed flows."""
        ctx = await ChecklistContext.load()

        dns_proxy = {}
        try:
            dns_proxy = await router_manager.get_backend().get_dns_proxy_status()
        except Exception as e:
            logger.debug("Failed querying dns proxy status for checklist: %s", e)

        items: List[Dict[str, Any]] = [
            evaluate_hub_isolation(ctx),
            evaluate_iot_egress_policy(ctx),
            evaluate_lateral_movement_isolation(ctx),
            evaluate_camera_upnp_security(ctx),
            evaluate_smart_tv_security(ctx),
            evaluate_wifi_security(ctx),
            evaluate_firmware_updates(ctx),
            evaluate_dns_protection(ctx, dns_proxy),
            evaluate_continuous_quarantine(ctx),
            evaluate_arp_mac_spoofing(ctx),
            evaluate_hardware_segmentation(ctx),
        ]

        total_checks = len(items)
        ok_count = sum(1 for item in items if item["status"] == "ok")
        warning_count = sum(1 for item in items if item["status"] == "warning")
        critical_count = sum(1 for item in items if item["status"] == "critical")

        score = 100
        score -= critical_count * 20
        score -= warning_count * 7
        score = max(10, min(100, score))

        if score >= 90:
            score_label = "Отлично"
            score_color = "emerald"
        elif score >= 70:
            score_label = "Хорошо"
            score_color = "indigo"
        elif score >= 50:
            score_label = "Внимание"
            score_color = "amber"
        else:
            score_label = "Высокий риск"
            score_color = "rose"

        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "score_label": score_label,
            "score_color": score_color,
            "stats": {
                "total_checks": total_checks,
                "ok_count": ok_count,
                "warning_count": warning_count,
                "critical_count": critical_count
            },
            "items": items
        }
