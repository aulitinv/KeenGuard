"""Security Digest generator for KeenGuard."""
from datetime import datetime, timezone
import logging
from typing import Dict, Any, Optional

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.core.notifier import notifier, render_progress_bar

logger = logging.getLogger("keenguard.digest")

class SecurityDigestGenerator:
    async def generate_digest(self, hours: int = 24) -> Dict[str, Any]:
        """Collects metrics and builds a comprehensive security digest."""
        stats = await db.get_digest_stats(hours=hours)

        total_devices = stats.get("total_devices") or 0
        online_devices = stats.get("online_devices") or 0
        event_counts = stats.get("event_counts") or []
        top_incidents = stats.get("top_incidents") or []
        audit_count = stats.get("audit_count") or 0
        high_risk_audits = stats.get("high_risk_audits") or 0

        critical_count = sum(e["cnt"] for e in event_counts if e["severity"] == "critical")
        warning_count = sum(e["cnt"] for e in event_counts if e["severity"] == "warning")
        info_count = sum(e["cnt"] for e in event_counts if e["severity"] == "info")
        total_issues = critical_count + warning_count

        # Compute Security Score (0 - 100)
        score = 100
        score -= critical_count * 15
        score -= warning_count * 5
        score -= high_risk_audits * 10
        score = max(10, min(100, score))

        if score >= 90:
            status_text = "Отлично"
            status_color = "emerald"
        elif score >= 70:
            status_text = "Хорошо"
            status_color = "indigo"
        elif score >= 50:
            status_text = "Внимание"
            status_color = "amber"
        else:
            status_text = "Высокий риск"
            status_color = "rose"

        recommendations = []
        if critical_count > 0:
            recommendations.append("Проверьте критические инциденты: зафиксированы попытки несанкционированного доступа или аномалии.")
        if high_risk_audits > 0:
            recommendations.append(f"Обнаружено {high_risk_audits} устройств с небезопасным трафиком. Включите им изоляцию от домашней сети.")
        if stats.get("has_hubs_or_vacuums"):
            recommendations.append("Для умных хабов и IoT-устройств настройте асимметричную сегментацию (LAN -> IoT разрешен, IoT -> LAN заблокирован).")
        if not recommendations:
            recommendations.append("Сеть защищена, подозрительной активности за отчетный период не зафиксировано.")

        has_issues = total_issues > 0 or high_risk_audits > 0

        # Build Telegram text representation (HTML)
        period_str = f"за последние {hours} ч." if hours < 48 else f"за последние {hours//24} дн."
        score_bar = render_progress_bar(score, 100)
        dev_bar = render_progress_bar(online_devices, total_devices) if total_devices > 0 else "[──────────]"
        telegram_lines = [
            f"🛡️ <b>Дайджест безопасности KeenGuard ({period_str})</b>\n",
            f"<b>Индекс безопасности:</b> {score_bar} <b>{score}/100</b> ({status_text})",
            f"<b>Устройства онлайн:</b>   {dev_bar} <b>{online_devices}</b> из {total_devices}",
            f"<b>Инциденты:</b> 🚨 Критических: {critical_count} | ⚠️ Предупреждений: {warning_count}",
        ]

        if audit_count > 0:
            telegram_lines.append(f"<b>Проведено проверок трафика:</b> {audit_count} (в зоне риска: {high_risk_audits})")

        if top_incidents:
            telegram_lines.append("\n<b>Последние инциденты:</b>")
            for inc in top_incidents[:3]:
                icon = "🚨" if inc["severity"] == "critical" else "⚠️"
                desc = inc.get("description", "")[:100]
                telegram_lines.append(f"• {icon} {desc}")

        telegram_lines.append("\n<b>Рекомендации:</b>")
        for rec in recommendations[:2]:
            telegram_lines.append(f"• {rec}")

        telegram_text = "\n".join(telegram_lines)

        return {
            "hours": hours,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "score": score,
            "status_text": status_text,
            "status_color": status_color,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "critical_count": critical_count,
            "warning_count": warning_count,
            "info_count": info_count,
            "has_issues": has_issues,
            "audit_count": audit_count,
            "high_risk_audits": high_risk_audits,
            "top_incidents": top_incidents,
            "recommendations": recommendations,
            "telegram_text": telegram_text
        }

    async def send_digest_to_telegram(self, hours: int = 24, force: bool = False) -> Dict[str, Any]:
        """
        Sends the digest to Telegram according to user settings.
        If condition is 'only_on_issues' and no issues were found, skipping (unless force=True).
        """
        digest = await self.generate_digest(hours=hours)

        if not force and settings.digest_condition == "only_on_issues" and not digest["has_issues"]:
            logger.info("Skipping digest send to Telegram: condition is 'only_on_issues' and no issues found.")
            return {"status": "skipped", "message": "Проблем не обнаружено. Дайджест пропущен согласно настройке 'только при инцидентах'."}

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "🔄 Обновить сводку", "callback_data": "cmd:digest"},
                    {"text": "📊 Статус сети", "callback_data": "cmd:status"}
                ],
                [
                    {"text": "📱 Устройства онлайн", "callback_data": "cmd:devices"}
                ]
            ]
        }
        res = await notifier.send_message(digest["telegram_text"], reply_markup=keyboard)
        return res

digest_generator = SecurityDigestGenerator()
digest_manager = digest_generator

