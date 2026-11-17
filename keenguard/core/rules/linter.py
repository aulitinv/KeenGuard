"""Rule Linter and Conflict Analyzer for KeenGuard Rules Engine."""
from enum import Enum
from typing import List, Optional, Set
from pydantic import BaseModel, Field

from keenguard.db.models import SecurityRule
from keenguard.core.rules.matcher import parse_port_rule


class LinterSeverity(str, Enum):
    ERROR = "error"      # Critical priority violation that should prevent save unless forced
    WARNING = "warning"  # Shadowed or redundant rule that might not execute as expected
    INFO = "info"        # Optimization hint


class LinterIssue(BaseModel):
    """Validation issue found in the rules chain."""
    issue_type: str  # core_breach, shadowed_rule, direct_conflict, duplicate_rule
    severity: LinterSeverity = LinterSeverity.WARNING
    rule_id: str
    rule_name: str
    message: str
    conflicting_rule_id: Optional[str] = None
    conflicting_rule_name: Optional[str] = None


class RuleLinter:
    """Analyzes ordered security rules for logical flaws, shadowing, and ordering conflicts."""

    @staticmethod
    def validate_rules(rules: List[SecurityRule]) -> List[LinterIssue]:
        """
        Validates the sequence of rules and returns detected logical issues.
        Assumes rules are passed in their proposed execution order (order_index ASC).
        """
        issues: List[LinterIssue] = []
        if not rules:
            return issues

        sorted_rules = sorted(rules, key=lambda r: r.order_index)

        # 1. Check Core Priority Breach
        core_rules_seen = 0
        total_core_rules = sum(1 for r in sorted_rules if r.category == "core")
        for idx, rule in enumerate(sorted_rules):
            if rule.category == "core":
                core_rules_seen += 1
            elif core_rules_seen < total_core_rules:
                # A non-core rule was placed above some core rules!
                issues.append(LinterIssue(
                    issue_type="core_breach",
                    severity=LinterSeverity.ERROR,
                    rule_id=rule.id,
                    rule_name=rule.name,
                    message=f"Правило '{rule.name}' размещено выше системного ядра. Системные правила ядра должны выполняться первыми."
                ))

        # 2. Check Shadowing & Conflicts between pairs of active rules
        active_rules = [r for r in sorted_rules if r.enabled]
        for i in range(len(active_rules)):
            r_top = active_rules[i]
            top_ports = RuleLinter._extract_ports(r_top)

            for j in range(i + 1, len(active_rules)):
                r_bottom = active_rules[j]
                bottom_ports = RuleLinter._extract_ports(r_bottom)

                # Check if bottom rule is shadowed by top rule
                # Scenario A: Top rule is a broad Alert/Block, bottom rule is Pass on overlapping ports
                if r_top.reaction.action_mode == "alert" and r_bottom.reaction.action_mode == "pass":
                    if RuleLinter._sources_overlap(r_top, r_bottom):
                        if RuleLinter._directions_overlap(r_top, r_bottom):
                            overlapping_ports = top_ports.intersection(bottom_ports) if (top_ports and bottom_ports) else set()
                            if (not top_ports and not bottom_ports) or overlapping_ports or (not top_ports and bottom_ports):
                                issues.append(LinterIssue(
                                    issue_type="shadowed_rule",
                                    severity=LinterSeverity.WARNING,
                                    rule_id=r_bottom.id,
                                    rule_name=r_bottom.name,
                                    conflicting_rule_id=r_top.id,
                                    conflicting_rule_name=r_top.name,
                                    message=f"Разрешающее правило '{r_bottom.name}' частично или полностью перекрывается блокирующим правилом '{r_top.name}' выше и может не сработать. Рекомендуется поднять разрешающее правило выше."
                                ))

                # Scenario B: Direct identical conflict
                if RuleLinter._rules_have_identical_scope(r_top, r_bottom, top_ports, bottom_ports):
                    if r_top.reaction.action_mode != r_bottom.reaction.action_mode:
                        issues.append(LinterIssue(
                            issue_type="direct_conflict",
                            severity=LinterSeverity.WARNING,
                            rule_id=r_bottom.id,
                            rule_name=r_bottom.name,
                            conflicting_rule_id=r_top.id,
                            conflicting_rule_name=r_top.name,
                            message=f"Правило '{r_bottom.name}' имеет идентичные условия с правилом '{r_top.name}', но противоположное действие ({r_bottom.reaction.action_mode} против {r_top.reaction.action_mode})."
                        ))

        return issues

    @staticmethod
    def _extract_ports(rule: SecurityRule) -> Set[int]:
        ports: Set[int] = set()
        for p_spec in rule.destination.ports:
            ports.update(parse_port_rule(p_spec))
        return ports

    @staticmethod
    def _sources_overlap(top: SecurityRule, bottom: SecurityRule) -> bool:
        # If top has no source restriction (Any device), it covers bottom
        src_top = top.source
        src_bot = bottom.source

        if not src_top.invert and not (src_top.device_macs or src_top.profiles or src_top.segments or src_top.vendors):
            return True

        # Check overlapping MACs
        if src_top.device_macs and src_bot.device_macs:
            if any(m.upper() in [x.upper() for x in src_top.device_macs] for m in src_bot.device_macs):
                return True

        # Check overlapping profiles
        if src_top.profiles and src_bot.profiles:
            if any(p in src_top.profiles for p in src_bot.profiles):
                return True

        return False

    @staticmethod
    def _directions_overlap(top: SecurityRule, bottom: SecurityRule) -> bool:
        d_top = top.destination.direction
        d_bot = bottom.destination.direction
        if d_top == "any" or d_bot == "any":
            return True
        return d_top == d_bot

    @staticmethod
    def _rules_have_identical_scope(r1: SecurityRule, r2: SecurityRule, p1: Set[int], p2: Set[int]) -> bool:
        if r1.destination.direction != r2.destination.direction:
            return False
        if p1 != p2:
            return False
        if r1.source.invert != r2.source.invert:
            return False
        if set(r1.source.profiles) != set(r2.source.profiles):
            return False
        if set(m.upper() for m in r1.source.device_macs) != set(m.upper() for m in r2.source.device_macs):
            return False
        return True
