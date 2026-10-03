"""Report generation, risk assessment, and PCAP export for audit sessions."""
from datetime import datetime, timezone
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from scapy.all import Packet, wrpcap

from keenguard.config import settings as default_settings

logger = logging.getLogger("keenguard.audit.report")


def _get_settings():
    import sys
    audit_mod = sys.modules.get("keenguard.core.audit")
    if audit_mod and hasattr(audit_mod, "settings"):
        return audit_mod.settings
    return default_settings


def save_pcap_packets(packets: List[Packet], pcap_filename: str, pcap_dir: Optional[Path] = None) -> bool:
    """Writes packets to PCAP file on disk."""
    target_dir = pcap_dir or _get_settings().pcap_dir
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = target_dir / pcap_filename
        if packets:
            wrpcap(str(pcap_path), packets)
            return True
        elif pcap_path.exists():
            return True
        else:
            # Write empty PCAP header
            header = bytes([
                0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00
            ])
            with open(pcap_path, "wb") as f:
                f.write(header)
            return True
    except OSError as e:
        logger.error("Failed to dump audit PCAP %s: %s", pcap_filename, e)
        return False


def build_device_audit_report(session: Any) -> Dict[str, Any]:
    """Generates comprehensive audit report dictionary for a single device session."""
    session.end_time = datetime.now(timezone.utc)
    elapsed = int((session.end_time - session.start_time).total_seconds())

    findings: List[str] = []
    overall_risk = "low"

    unencrypted_flows = [f for f in session.flows.values() if f.get("dst_port") in [80, 1883] and not f.get("is_lan")]
    if unencrypted_flows:
        overall_risk = "medium"
        findings.append(f"Обнаружена передача данных без шифрования (HTTP/MQTT, порты 80/1883) на {len(unencrypted_flows)} хостов.")

    if session.lan_probes:
        overall_risk = "high"
        targets_str = ", ".join(p["target"] for p in session.lan_probes[:3])
        findings.append(f"Внимание: попытка обращения к локальным устройствам сети ({targets_str}).")

    crit_flows = [f for f in session.flows.values() if f.get("risk") == "critical"]
    if crit_flows:
        overall_risk = "high"
        ports_str = ", ".join(str(f["dst_port"]) for f in crit_flows)
        findings.append(f"Обнаружены попытки обращения к чувствительным портам администрирования ({ports_str}).")

    is_hub = session.profile == "smart_home_hub" or (
        session.profile == "unassigned" and any(k in (session.hostname or "").lower() for k in ["spruthub", "homeassistant", "hassio", "haos", "hubitat", "zigbee2mqtt"])
    )

    if is_hub:
        findings.append("Устройство идентифицировано как Хаб умного дома. Периферийный опрос локальных устройств (CoAP, mDNS, SSDP, UDP 54321) учтен как штатная работа контроллера.")

    if session.http_inspections:
        findings.append(f"Инспекция пакетов выявила {len(session.http_inspections)} незашифрованных HTTP-запросов (методы, хосты, пути URI).")

    if not findings:
        findings.append("Подозрительной активности не выявлено. Все внешние соединения защищены TLS/SSL или стандартным DNS.")

    pcap_saved = save_pcap_packets(session.packets, session.pcap_filename)

    recommendations: List[str] = []
    if is_hub:
        recommendations.append(
            "Совет по асимметричной сегментации Keenetic: для хабов умного дома настройте односторонний доступ в межсетевом экране Keenetic. "
            "Разрешите направление «Домашняя сеть -> IoT», но заблокируйте «IoT -> Домашняя сеть». "
            "Благодаря Stateful Firewall вы сможете подключаться к интерфейсу хаба из дома, а сам хаб не сможет опрашивать домашние компьютеры и NAS."
        )

    if overall_risk == "high" or session.lan_probes:
        if not is_hub:
            recommendations.append("Для надежной изоляции от ПК и сетевых дисков (NAS) переключите устройство на Гостевую Wi-Fi сеть Keenetic (Bridge1) или выделите отдельный сегмент IoT.")
        else:
            recommendations.append("Внимание: зафиксированы попытки обращения к локальным службам домашней сети. Проверьте установленные интеграции и дополнения хаба.")

    if unencrypted_flows:
        recommendations.append("Не передавайте учетные данные через незащищенные каналы данного устройства.")
    if not session.lan_probes and overall_risk == "low":
        recommendations.append("Устройство ведет себя штатно, коммуникация ограничена заявленными облачными сервисами.")

    auto_quarantined = getattr(session, "auto_quarantined", False)
    suspicious_reasons = getattr(session, "suspicious_reasons", [])

    return {
        "id": session.session_id,
        "mac": session.mac,
        "ip": session.ip,
        "hostname": session.hostname,
        "vendor": session.vendor,
        "capture_source": session.capture_source,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat(),
        "duration_seconds": elapsed,
        "total_bytes": session.total_bytes_up + session.total_bytes_down,
        "total_bytes_up": session.total_bytes_up,
        "total_bytes_down": session.total_bytes_down,
        "total_packets": session.total_packets_up + session.total_packets_down,
        "flows_count": len(session.flows),
        "flows": sorted(list(session.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True),
        "dns_queries": list(session.dns_queries.values()),
        "http_inspections": session.http_inspections,
        "lan_probes": session.lan_probes,
        "risk_level": "critical" if auto_quarantined else overall_risk,
        "overall_risk": "critical" if auto_quarantined else overall_risk,
        "findings": findings,
        "recommendations": recommendations,
        "pcap_file": session.pcap_filename if pcap_saved else None,
        "auto_quarantined": auto_quarantined,
        "suspicious_reasons": suspicious_reasons,
        "quarantined_devices": [
            {"mac": session.mac, "ip": session.ip, "hostname": session.hostname, "reason": r}
            for r in suspicious_reasons
        ] if auto_quarantined else []
    }


def build_network_audit_report(session: Any) -> Dict[str, Any]:
    """Generates comprehensive summary report dictionary for a network-wide audit session."""
    session.end_time = datetime.now(timezone.utc)
    elapsed = int((session.end_time - session.start_time).total_seconds())

    session.total_bytes_up = sum(d["bytes_up"] for d in session.device_stats.values())
    session.total_bytes_down = sum(d["bytes_down"] for d in session.device_stats.values())
    session.total_packets_up = sum(d["packets_up"] for d in session.device_stats.values())
    session.total_packets_down = sum(d["packets_down"] for d in session.device_stats.values())

    top_devices = sorted(
        list(session.device_stats.values()),
        key=lambda x: x["bytes_up"] + x["bytes_down"],
        reverse=True
    )

    provider_counts: Dict[str, Dict[str, Any]] = {}
    for f in session.flows.values():
        if not f.get("is_lan"):
            prov = f.get("provider", "WAN")
            if prov not in provider_counts:
                provider_counts[prov] = {
                    "provider": prov,
                    "name": prov,
                    "country": f.get("country", "WAN"),
                    "flag": f.get("flag", "🌐"),
                    "flows": 0,
                    "bytes": 0
                }
            provider_counts[prov]["flows"] += 1
            provider_counts[prov]["bytes"] += (f["bytes_up"] + f["bytes_down"])
    top_providers = sorted(list(provider_counts.values()), key=lambda x: x["flows"], reverse=True)[:10]

    crit_lat = [lm for lm in session.lateral_movements if lm.get("risk") == "critical"]
    unencrypted = [f for f in session.flows.values() if not f.get("is_encrypted") and not f.get("is_lan") and f.get("dst_port") not in (80, 53, 123)]

    findings: List[str] = []
    if session.quarantined_devices:
        findings.append(f"🚨 Автоматически изолировано {len(session.quarantined_devices)} устройств за подозрительную активность в LAN.")
    if crit_lat:
        findings.append(f"Обнаружено {len(crit_lat)} подозрительных попыток межузлового взаимодействия (Lateral Movement) на критические порты.")
    if unencrypted:
        findings.append(f"Зафиксировано {len(unencrypted)} незашифрованных потоков данных к внешним серверам.")
    if not findings:
        findings.append("Сетевой трафик в пределах нормы, критических аномалий не зафиксировано.")

    overall_risk = "critical" if (session.quarantined_devices or crit_lat) else ("high" if unencrypted else ("medium" if len(session.flows) > 50 else "low"))

    pcap_saved = save_pcap_packets(session.packets, session.pcap_filename)

    recommendations: List[str] = []
    if session.quarantined_devices:
        recommendations.append("Проверьте изолированные устройства во вкладке «Устройства». Ограничьте их доступ к домашнему сегменту.")
    if crit_lat:
        recommendations.append("Рекомендуется изолировать сегмент умного дома (IoT) в отдельный VLAN или гостевую Wi-Fi сеть Keenetic.")
    if not session.quarantined_devices and overall_risk == "low":
        recommendations.append("Сеть защищена, подозрительных перемещений между устройствами не обнаружено.")

    return {
        "id": session.session_id,
        "mac": "NETWORK",
        "is_network": True,
        "hostname": f"Сводный аудит сети ({session.scope})",
        "scope": session.scope,
        "start_time": session.start_time.isoformat(),
        "end_time": session.end_time.isoformat(),
        "duration_seconds": elapsed,
        "total_bytes": session.total_bytes_up + session.total_bytes_down,
        "total_bytes_up": session.total_bytes_up,
        "total_bytes_down": session.total_bytes_down,
        "total_packets": session.total_packets_up + session.total_packets_down,
        "total_flows": len(session.flows),
        "devices_count": len(session.device_stats),
        "devices_analyzed": len(session.device_stats),
        "top_devices": top_devices,
        "flows_count": len(session.flows),
        "flows": sorted(list(session.flows.values()), key=lambda x: x["bytes_up"] + x["bytes_down"], reverse=True)[:100],
        "top_providers": top_providers,
        "cloud_providers": top_providers,
        "lateral_movements": session.lateral_movements,
        "quarantined_devices": session.quarantined_devices,
        "dns_queries": list(session.dns_queries.values()),
        "risk_level": overall_risk,
        "overall_risk": overall_risk,
        "findings": findings,
        "recommendations": recommendations,
        "pcap_file": session.pcap_filename if pcap_saved else None
    }
