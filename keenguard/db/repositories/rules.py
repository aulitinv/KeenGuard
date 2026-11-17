"""Security Rules & Automations repository for KeenGuard Rules Engine."""
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
import aiosqlite

from keenguard.db.models import (
    SecurityRule,
    RuleSource,
    RuleDestination,
    RuleContext,
    RuleReaction,
    RuleTelemetry,
    RuleHitRecord,
)
from keenguard.db.repositories.base import BaseRepository

logger = logging.getLogger("keenguard.db.rules")

# Built-in Default Security Rules
BUILTIN_SECURITY_RULES: List[Dict[str, Any]] = [
    # --- ZONE 1: CORE FAILSAFE RULES (order_index 1..10, 🔒 LOCKED) ---
    {
        "id": "rule_core_dhcp",
        "order_index": 1,
        "name": "Core: DHCP Infrastructure",
        "description": "Защита служебного обмена DHCP (UDP 67/68) между роутером и клиентами сети",
        "enabled": True,
        "is_builtin": True,
        "category": "core",
        "source": {"invert": False, "device_macs": [], "profiles": [], "segments": [], "vendors": [], "properties": []},
        "destination": {"direction": "any", "invert_targets": False, "targets": [], "domains": [], "invert_ports": False, "ports": [67, 68], "protocols": ["UDP"]},
        "context": {"time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    },
    {
        "id": "rule_core_dns",
        "order_index": 2,
        "name": "Core: Router DNS Resolver",
        "description": "Разрешает стандартные DNS-запросы (UDP/TCP 53) к шлюзу роутера",
        "enabled": True,
        "is_builtin": True,
        "category": "core",
        "source": {"invert": False, "device_macs": [], "profiles": [], "segments": [], "vendors": [], "properties": []},
        "destination": {"direction": "lan_to_router", "invert_targets": False, "targets": [], "domains": [], "invert_ports": False, "ports": [53], "protocols": ["UDP", "TCP"]},
        "context": {"time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    },
    {
        "id": "rule_core_web",
        "order_index": 3,
        "name": "Core: KeenGuard Management UI",
        "description": "Защита веб-интерфейса KeenGuard (порт 9989) от случайной блокировки",
        "enabled": True,
        "is_builtin": True,
        "category": "core",
        "source": {"invert": False, "device_macs": [], "profiles": [], "segments": [], "vendors": [], "properties": []},
        "destination": {"direction": "any", "invert_targets": False, "targets": [], "domains": [], "invert_ports": False, "ports": [9989], "protocols": ["TCP"]},
        "context": {"time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    },

    # --- ZONE 2: MAIN RULES POOL (order_index 11..998, ↕️ REORDERABLE) ---
    {
        "id": "rule_smart_tv_media",
        "order_index": 20,
        "name": "Smart TV Media Stream (DLNA/Cast/AirPlay/Jellyfin/Plex)",
        "description": "Разрешает потоковое локальное видео с серверов Jellyfin, Plex, DLNA и AirPlay на Smart TV",
        "enabled": True,
        "is_builtin": True,
        "category": "media",
        "source": {"invert": False, "device_macs": [], "profiles": ["smart_tv"], "segments": [], "vendors": [], "properties": []},
        "destination": {
            "direction": "lan_to_lan",
            "invert_targets": False,
            "targets": [],
            "domains": [],
            "invert_ports": False,
            "ports": [8200, 8008, 8009, 7000, 7100, 8096, 8920, 32400],
            "protocols": ["TCP", "UDP"]
        },
        "context": {"volume_operator": ">", "volume_bytes": 0, "time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    },
    {
        "id": "rule_camera_nvr_stream",
        "order_index": 30,
        "name": "Camera RTSP/HTTP to NVR Only",
        "description": "Разрешает видеопотоки камер видеонаблюдения к локальному видеорегистратору (NVR)",
        "enabled": True,
        "is_builtin": True,
        "category": "perimeter",
        "source": {"invert": False, "device_macs": [], "profiles": ["camera"], "segments": [], "vendors": [], "properties": []},
        "destination": {
            "direction": "lan_to_lan",
            "invert_targets": False,
            "targets": [],
            "domains": [],
            "invert_ports": False,
            "ports": [554, 80, 8080, 8000],
            "protocols": ["TCP", "UDP"]
        },
        "context": {"time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    },
    {
        "id": "rule_block_mirai_botnet",
        "order_index": 50,
        "name": "Block Mirai Botnet Ports (Telnet/SMB/RDP)",
        "description": "Алерт и запись PCAP при попытке обращения к терминальным и червеобразным портам (Telnet 23, SMB 445, RDP 3389)",
        "enabled": True,
        "is_builtin": True,
        "category": "perimeter",
        "source": {"invert": False, "device_macs": [], "profiles": [], "segments": [], "vendors": [], "properties": []},
        "destination": {
            "direction": "any",
            "invert_targets": False,
            "targets": [],
            "domains": [],
            "invert_ports": False,
            "ports": [23, 445, 139, 3389],
            "protocols": ["TCP"]
        },
        "context": {"time_window": "always"},
        "reaction": {
            "severity": "CRITICAL",
            "action_mode": "alert",
            "notify_telegram": True,
            "telegram_mode": "immediate",
            "record_pcap_seconds": 60,
            "hardware_wan_block": False
        }
    },
    {
        "id": "rule_iot_local_cloud",
        "order_index": 60,
        "name": "IoT Home Automation & MQTT",
        "description": "Разрешает локальный и облачный обмен протоколов умного дома MQTT (1883/8883), CoAP (5683) и NTP",
        "enabled": True,
        "is_builtin": True,
        "category": "iot",
        "source": {"invert": False, "device_macs": [], "profiles": ["iot", "iot_cloud", "smart_home_hub"], "segments": [], "vendors": [], "properties": []},
        "destination": {
            "direction": "any",
            "invert_targets": False,
            "targets": [],
            "domains": [],
            "invert_ports": False,
            "ports": [1883, 8883, 5683, 123],
            "protocols": ["TCP", "UDP"]
        },
        "context": {"time_window": "always"},
        "reaction": {"severity": "INFO", "action_mode": "pass"}
    }
]


class RulesRepository(BaseRepository):
    """Database operations for Security Rules and Telemetry."""

    def _row_to_rule(self, r: aiosqlite.Row) -> SecurityRule:
        source_data = json.loads(r["source_json"]) if r["source_json"] else {}
        destination_data = json.loads(r["destination_json"]) if r["destination_json"] else {}
        context_data = json.loads(r["context_json"]) if r["context_json"] else {}
        reaction_data = json.loads(r["reaction_json"]) if r["reaction_json"] else {}

        telemetry = RuleTelemetry(
            hits_total=r["hits_total"] or 0,
            hits_24h=r["hits_24h"] or 0,
            last_hit_at=r["last_hit_at"],
            last_hit_summary=r["last_hit_summary"]
        )

        return SecurityRule(
            id=r["id"],
            order_index=r["order_index"],
            name=r["name"],
            description=r["description"] or "",
            enabled=bool(r["enabled"]),
            is_builtin=bool(r["is_builtin"]),
            category=r["category"] or "general",
            temporary_until=r["temporary_until"],
            source=RuleSource(**source_data),
            destination=RuleDestination(**destination_data),
            context=RuleContext(**context_data),
            reaction=RuleReaction(**reaction_data),
            telemetry=telemetry,
            created_at=r["created_at"] or datetime.now(timezone.utc).isoformat(),
            updated_at=r["updated_at"] or datetime.now(timezone.utc).isoformat()
        )

    async def get_rules(self, include_disabled: bool = True) -> List[SecurityRule]:
        """Returns all security rules ordered by order_index ASC."""
        query = "SELECT * FROM security_rules"
        if not include_disabled:
            query += " WHERE enabled = 1"
        query += " ORDER BY order_index ASC"

        async with self.get_connection() as conn:
            cursor = await conn.execute(query)
            rows = await cursor.fetchall()
            return [self._row_to_rule(r) for r in rows]

    async def get_rule(self, rule_id: str) -> Optional[SecurityRule]:
        """Fetches a specific security rule by ID."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT * FROM security_rules WHERE id = ?", (rule_id,))
            row = await cursor.fetchone()
            return self._row_to_rule(row) if row else None

    async def create_rule(self, rule: SecurityRule) -> SecurityRule:
        """Creates a new security rule."""
        now = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            # If order_index is 0 or unassigned, append after existing rules
            if rule.order_index <= 0:
                cursor = await conn.execute("SELECT COALESCE(MAX(order_index), 0) FROM security_rules WHERE order_index < 999")
                max_idx = (await cursor.fetchone())[0]
                rule.order_index = max_idx + 10

            await conn.execute("""
                INSERT INTO security_rules (
                    id, order_index, name, description, enabled, is_builtin, category,
                    temporary_until, source_json, destination_json, context_json,
                    reaction_json, hits_total, hits_24h, last_hit_at, last_hit_summary,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.id,
                rule.order_index,
                rule.name,
                rule.description,
                1 if rule.enabled else 0,
                1 if rule.is_builtin else 0,
                rule.category,
                rule.temporary_until,
                rule.source.model_dump_json(),
                rule.destination.model_dump_json(),
                rule.context.model_dump_json(),
                rule.reaction.model_dump_json(),
                rule.telemetry.hits_total,
                rule.telemetry.hits_24h,
                rule.telemetry.last_hit_at,
                rule.telemetry.last_hit_summary,
                rule.created_at or now,
                now
            ))
            await conn.commit()
            return rule

    save_rule = create_rule

    async def update_rule(self, rule: SecurityRule) -> Optional[SecurityRule]:
        """Updates an existing security rule."""
        now = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            cursor = await conn.execute("""
                UPDATE security_rules SET
                    order_index = ?,
                    name = ?,
                    description = ?,
                    enabled = ?,
                    category = ?,
                    temporary_until = ?,
                    source_json = ?,
                    destination_json = ?,
                    context_json = ?,
                    reaction_json = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                rule.order_index,
                rule.name,
                rule.description,
                1 if rule.enabled else 0,
                rule.category,
                rule.temporary_until,
                rule.source.model_dump_json(),
                rule.destination.model_dump_json(),
                rule.context.model_dump_json(),
                rule.reaction.model_dump_json(),
                now,
                rule.id
            ))
            if cursor.rowcount == 0:
                return None
            await conn.commit()
            return await self.get_rule(rule.id)

    async def delete_rule(self, rule_id: str) -> bool:
        """Deletes a custom security rule. Core failsafe rules cannot be deleted."""
        rule = await self.get_rule(rule_id)
        if not rule:
            return False
        if rule.is_builtin and rule.category == "core":
            logger.warning("Attempted to delete protected core failsafe rule: %s", rule_id)
            return False

        async with self.get_connection() as conn:
            cursor = await conn.execute("DELETE FROM security_rules WHERE id = ?", (rule_id,))
            await conn.execute("DELETE FROM security_rule_hits WHERE rule_id = ?", (rule_id,))
            await conn.commit()
            return cursor.rowcount > 0

    async def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enables or disables a security rule."""
        now = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            cursor = await conn.execute(
                "UPDATE security_rules SET enabled = ?, updated_at = ? WHERE id = ?",
                (1 if enabled else 0, now, rule_id)
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def reorder_rules(self, ordered_ids: List[str]) -> bool:
        """
        Atomically updates the execution order (order_index) for all rules.
        Preserves core rules at order_index 1..10.
        """
        async with self.get_connection() as conn:
            # Check core rules priority protection
            cursor = await conn.execute("SELECT id FROM security_rules WHERE category = 'core'")
            core_ids = {row[0] for row in await cursor.fetchall()}

            # Generate new indices starting from 10 for user/built-in rules
            new_order = {}
            core_idx = 1
            pool_idx = 15

            for r_id in ordered_ids:
                if r_id in core_ids:
                    new_order[r_id] = core_idx
                    core_idx += 1
                else:
                    new_order[r_id] = pool_idx
                    pool_idx += 10

            now = datetime.now(timezone.utc).isoformat()
            for r_id, idx in new_order.items():
                await conn.execute(
                    "UPDATE security_rules SET order_index = ?, updated_at = ? WHERE id = ?",
                    (idx, now, r_id)
                )
            await conn.commit()
            return True

    async def record_rule_hit(self, rule_id: str, hit: RuleHitRecord) -> bool:
        """
        Records a rule hit, increments total hits and 24h hits, and updates last_hit telemetry.
        Keeps max 500 recent hits per rule.
        """
        now = hit.timestamp or datetime.now(timezone.utc).isoformat()
        summary = hit.summary or f"{hit.src_ip or 'Any'} -> {hit.dst_ip or 'Any'}:{hit.port or 0} ({hit.protocol})"

        async with self.get_connection() as conn:
            # 1. Update rule telemetry
            await conn.execute("""
                UPDATE security_rules SET
                    hits_total = hits_total + 1,
                    hits_24h = hits_24h + 1,
                    last_hit_at = ?,
                    last_hit_summary = ?
                WHERE id = ?
            """, (now, summary, rule_id))

            # 2. Insert hit history record
            await conn.execute("""
                INSERT INTO security_rule_hits (
                    rule_id, timestamp, src_ip, src_mac, dst_ip, port, protocol, bytes_count, action_taken, summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id,
                now,
                hit.src_ip,
                hit.src_mac,
                hit.dst_ip,
                hit.port,
                hit.protocol,
                hit.bytes_count,
                hit.action_taken,
                summary
            ))

            # 3. Prune old hits (> 500 records per rule)
            await conn.execute("""
                DELETE FROM security_rule_hits
                WHERE rule_id = ? AND id NOT IN (
                    SELECT id FROM security_rule_hits
                    WHERE rule_id = ?
                    ORDER BY id DESC LIMIT 500
                )
            """, (rule_id, rule_id))

            await conn.commit()
            return True

    async def get_rule_hits(self, rule_id: str, limit: int = 20) -> List[RuleHitRecord]:
        """Retrieves recent hit history for a rule."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("""
                SELECT * FROM security_rule_hits
                WHERE rule_id = ?
                ORDER BY id DESC LIMIT ?
            """, (rule_id, limit))
            rows = await cursor.fetchall()
            return [
                RuleHitRecord(
                    id=r["id"],
                    rule_id=r["rule_id"],
                    timestamp=r["timestamp"],
                    src_ip=r["src_ip"],
                    src_mac=r["src_mac"],
                    dst_ip=r["dst_ip"],
                    port=r["port"],
                    protocol=r["protocol"] or "TCP",
                    bytes_count=r["bytes_count"] or 0,
                    action_taken=r["action_taken"] or "pass",
                    summary=r["summary"]
                )
                for r in rows
            ]
