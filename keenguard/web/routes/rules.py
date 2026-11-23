"""REST API router for KeenGuard Rules Engine (Security Rules, Automations, Reordering, Linter, and Simulator)."""
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union

from fastapi import APIRouter, HTTPException, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from keenguard.db.models import (
    SecurityRule,
    RuleSource,
    RuleDestination,
    RuleContext,
    RuleReaction,
    RuleTelemetry,
    RuleHitRecord,
)
from keenguard.core.rules.matcher import rule_matcher, MatchResult
from keenguard.core.rules.linter import RuleLinter, LinterIssue
from keenguard.web.state import get_db
from keenguard.web.ws import ws_manager

logger = logging.getLogger("keenguard.web.routes.rules")

router = APIRouter(prefix="/api/rules", tags=["rules"])


class RuleCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = ""
    enabled: bool = True
    category: str = "custom"
    temporary_until: Optional[str] = None
    source: RuleSource = Field(default_factory=RuleSource)
    destination: RuleDestination = Field(default_factory=RuleDestination)
    context: RuleContext = Field(default_factory=RuleContext)
    reaction: RuleReaction = Field(default_factory=RuleReaction)


class RuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    category: Optional[str] = None
    temporary_until: Optional[str] = None
    source: Optional[RuleSource] = None
    destination: Optional[RuleDestination] = None
    context: Optional[RuleContext] = None
    reaction: Optional[RuleReaction] = None


class ReorderRequest(BaseModel):
    ordered_ids: List[str]
    force: bool = False


class ToggleRequest(BaseModel):
    enabled: Optional[bool] = None


class SimulationRequest(BaseModel):
    src_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    bytes_count: int = 0
    time_of_day: Optional[str] = "now"  # "now", "day", "night"


@router.get("", response_model=List[SecurityRule])
async def list_rules():
    """Returns all security rules sorted by execution order (order_index ASC)."""
    db = get_db()
    return await db.get_rules()


@router.post("", response_model=SecurityRule, status_code=status.HTTP_201_CREATED)
async def create_rule(req: RuleCreateRequest):
    """Creates a new custom security rule."""
    db = get_db()
    existing_rules = await db.get_rules()

    category = (req.category or "custom").strip().lower()
    if category == "core":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Создание правил с категорией 'core' запрещено"
        )

    rule_id = f"rule_custom_{uuid.uuid4().hex[:8]}"

    # Determine order_index in Zone 2 pool (before Zone 3 fallback)
    pool_rules = [r for r in existing_rules if r.order_index < 999]
    max_order = max([r.order_index for r in pool_rules], default=10)
    new_order = max(max_order + 10, 15)

    now = datetime.now(timezone.utc).isoformat()
    new_rule = SecurityRule(
        id=rule_id,
        order_index=new_order,
        name=req.name.strip() or "Новое правило",
        description=req.description or "",
        enabled=req.enabled,
        is_builtin=False,
        category=category,
        temporary_until=req.temporary_until,
        source=req.source,
        destination=req.destination,
        context=req.context,
        reaction=req.reaction,
        telemetry=RuleTelemetry(),
        created_at=now,
        updated_at=now,
    )

    saved = await db.save_rule(new_rule)
    all_rules = await db.get_rules()
    rule_matcher.load_rules(all_rules)

    await ws_manager.broadcast({"type": "rules_updated", "action": "created", "rule_id": rule_id})
    return saved


@router.put("/reorder")
async def reorder_rules(req: ReorderRequest):
    """
    Reorders the rules execution chain.
    Validates logical integrity using RuleLinter:
    - Rejects Zone 1 core rule breaches with 400 Bad Request.
    - Warns on shadowed/conflicting rules with 409 Conflict unless force=True.
    """
    db = get_db()
    all_rules = await db.get_rules()
    rules_by_id = {r.id: r for r in all_rules}

    # Construct proposed execution sequence for linter
    simulated_rules: List[SecurityRule] = []
    seen_ids = set()

    current_idx = 1
    for r_id in req.ordered_ids:
        if r_id in rules_by_id:
            r_copy = rules_by_id[r_id].model_copy(deep=True)
            r_copy.order_index = current_idx
            current_idx += 1
            simulated_rules.append(r_copy)
            seen_ids.add(r_id)

    # Append any unspecified rules at the end of the pool
    for r in all_rules:
        if r.id not in seen_ids:
            r_copy = r.model_copy(deep=True)
            r_copy.order_index = current_idx
            current_idx += 1
            simulated_rules.append(r_copy)

    # Lint proposed chain
    issues = RuleLinter.validate_rules(simulated_rules)
    has_core_breach = any(i.issue_type == "core_breach" for i in issues)

    if has_core_breach:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "error",
                "detail": "Недопустимое перемещение системных правил ядра (Зона 1). Системные правила должны оставаться первыми.",
                "issues": [i.model_dump() for i in issues],
            }
        )

    if issues and not req.force:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "status": "conflict",
                "detail": "Обнаружены конфликты порядка применения правил (перекрытие или затенение).",
                "issues": [i.model_dump() for i in issues],
            }
        )

    # Persist validated order
    await db.reorder_rules(req.ordered_ids)
    refreshed_rules = await db.get_rules()
    rule_matcher.load_rules(refreshed_rules)

    await ws_manager.broadcast({"type": "rules_updated", "action": "reordered"})
    return {
        "success": True,
        "status": "ok",
        "issues": [i.model_dump() for i in issues] if issues else [],
    }


@router.post("/lint")
async def lint_rules_chain(rules: List[SecurityRule]):
    """Analyzes a provided set of rules for shadowing, core breaches, and logical conflicts."""
    issues = RuleLinter.validate_rules(rules)
    return {
        "valid": len(issues) == 0,
        "issues": [i.model_dump() for i in issues]
    }


@router.post("/test")
async def test_rule_simulation(req: SimulationRequest):
    """
    Dry-run simulation of network flow against active rules without affecting hit counters.
    Useful for testing rule conditions and explaining match decisions.
    """
    sim_dt = None
    if req.time_of_day == "night":
        now = datetime.now()
        sim_dt = now.replace(hour=3, minute=0, second=0)
    elif req.time_of_day == "day":
        now = datetime.now()
        sim_dt = now.replace(hour=14, minute=0, second=0)

    db = get_db()
    devices = await db.get_all_devices()
    devices_map = {d.mac: d for d in devices}

    result = rule_matcher.evaluate_flow(
        src_mac=req.src_mac,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        port=req.port,
        protocol=req.protocol or "TCP",
        bytes_count=req.bytes_count,
        devices_map=devices_map,
        current_dt=sim_dt,
    )

    return {
        "matched": result.matched,
        "rule_id": result.rule_id,
        "rule_name": result.rule_name,
        "action_mode": result.action_mode,
        "severity": result.severity,
        "description": result.description,
        "notify_telegram": result.notify_telegram,
        "telegram_mode": result.telegram_mode,
        "record_pcap_seconds": result.record_pcap_seconds,
        "hardware_wan_block": result.hardware_wan_block,
        "apply_preset_id": result.apply_preset_id,
    }


@router.get("/{rule_id}", response_model=SecurityRule)
async def get_rule_details(rule_id: str):
    """Retrieves a single security rule by ID."""
    db = get_db()
    rule = await db.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")
    return rule


@router.put("/{rule_id}", response_model=SecurityRule)
async def update_rule(rule_id: str, req: RuleUpdateRequest):
    """Updates an existing security rule."""
    db = get_db()
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    req_cat = req.category.strip().lower() if req.category is not None else None
    if existing.category == "core":
        if req_cat is not None and req_cat != "core":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя изменить категорию системного правила ядра")
        if req.enabled is False:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя отключить системное правило ядра")
    elif req_cat == "core":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Нельзя назначить категорию 'core' пользовательскому правилу")

    updated_dict = existing.model_dump()
    req_dict = req.model_dump(exclude_unset=True)
    if req_cat is not None:
        req_dict["category"] = req_cat
    for k, v in req_dict.items():
        if v is not None or k in ("temporary_until", "description"):
            updated_dict[k] = v

    updated_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
    updated_rule = SecurityRule(**updated_dict)

    saved = await db.update_rule(updated_rule)
    if not saved:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Ошибка при сохранении правила")

    all_rules = await db.get_rules()
    rule_matcher.load_rules(all_rules)

    await ws_manager.broadcast({"type": "rules_updated", "action": "updated", "rule_id": rule_id})
    return saved


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str):
    """Deletes a custom security rule. Core failsafe rules cannot be deleted."""
    db = get_db()
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    if existing.category == "core":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Базовые системные правила Зоны 1 нельзя удалять",
        )

    deleted = await db.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Не удалось удалить правило")

    all_rules = await db.get_rules()
    rule_matcher.load_rules(all_rules)

    await ws_manager.broadcast({"type": "rules_updated", "action": "deleted", "rule_id": rule_id})
    return {"success": True, "deleted_id": rule_id}


@router.post("/{rule_id}/toggle")
async def toggle_rule_enabled(rule_id: str, req: Optional[ToggleRequest] = None):
    """Toggles active status of a security rule."""
    db = get_db()
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")

    target_enabled = not existing.enabled if req is None or req.enabled is None else req.enabled
    if existing.category == "core" and not target_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Базовые системные правила Зоны 1 нельзя отключать",
        )

    await db.toggle_rule(rule_id, target_enabled)
    all_rules = await db.get_rules()
    rule_matcher.load_rules(all_rules)

    await ws_manager.broadcast({
        "type": "rules_updated",
        "action": "toggled",
        "rule_id": rule_id,
        "enabled": target_enabled,
    })
    return {"success": True, "id": rule_id, "enabled": target_enabled}


@router.get("/{rule_id}/hits", response_model=List[RuleHitRecord])
async def get_rule_hits(rule_id: str, limit: int = Query(20, ge=1, le=200)):
    """Retrieves recent hit history for a rule."""
    db = get_db()
    existing = await db.get_rule(rule_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Правило не найдено")
    return await db.get_rule_hits(rule_id, limit=limit)
