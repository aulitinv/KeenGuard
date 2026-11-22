// ============================================================================
// RULES ENGINE (ДВИЖОК ПРАВИЛ И ФИЛЬТРОВ СЕТЕВОЙ БЕЗОПАСНОСТИ)
// ============================================================================

let rulesList = [];
let rulesOriginalSnapshot = [];
let hasUnsavedRuleChanges = false;
let draggedRuleIndex = null;
let currentEditingRuleId = null;

function escapeRuleHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function formatRuleVolume(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
}

async function loadRules() {
    try {
        const res = await fetch('/api/rules');
        if (!res.ok) {
            console.error('Failed to load rules:', res.status);
            return;
        }
        rulesList = await res.json();
        rulesOriginalSnapshot = JSON.parse(JSON.stringify(rulesList));
        hasUnsavedRuleChanges = false;
        hideDraftBar();

        updateRulesStats();
        updateRulesBadgeOnly();
        renderRulesTable();
    } catch (e) {
        console.error('Error in loadRules:', e);
    }
}

async function updateRulesBadgeOnly() {
    try {
        const badge = document.getElementById('rules-count-badge');
        if (!badge) return;
        if (rulesList && rulesList.length > 0) {
            const active = rulesList.filter(r => r.enabled).length;
            badge.textContent = `${active}/${rulesList.length}`;
            return;
        }
        const res = await fetch('/api/rules');
        if (res.ok) {
            const list = await res.json();
            const active = list.filter(r => r.enabled).length;
            badge.textContent = `${active}/${list.length}`;
        }
    } catch (e) {
        console.debug('Could not update rules badge:', e);
    }
}

function updateRulesStats() {
    const totalEl = document.getElementById('rules-stat-total');
    const activeEl = document.getElementById('rules-stat-active');
    const pctEl = document.getElementById('rules-stat-active-pct');
    const hits24El = document.getElementById('rules-stat-hits24');
    const hitsTotalEl = document.getElementById('rules-stat-hits-total');
    const statusEl = document.getElementById('rules-stat-status');
    const statusSubEl = document.getElementById('rules-stat-status-sub');

    const total = rulesList.length;
    const active = rulesList.filter(r => r.enabled).length;
    const hits24 = rulesList.reduce((sum, r) => sum + (r.telemetry?.hits_24h || 0), 0);
    const hitsTotal = rulesList.reduce((sum, r) => sum + (r.telemetry?.hits_total || 0), 0);

    if (totalEl) totalEl.textContent = total;
    if (activeEl) activeEl.textContent = active;
    if (pctEl) pctEl.textContent = total > 0 ? `${Math.round((active / total) * 100)}%` : '0%';
    if (hits24El) hits24El.textContent = hits24.toLocaleString();
    if (hitsTotalEl) hitsTotalEl.textContent = hitsTotal.toLocaleString();

    if (statusEl && statusSubEl) {
        if (hasUnsavedRuleChanges) {
            statusEl.className = 'text-sm font-bold text-amber-400 flex items-center space-x-1.5';
            statusEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Не сохранено</span>';
            statusSubEl.textContent = 'Есть локальные изменения порядка правил';
        } else {
            statusEl.className = 'text-sm font-bold text-emerald-400 flex items-center space-x-1.5';
            statusEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span>Синхронизировано</span>';
            statusSubEl.textContent = 'Конфликтов не обнаружено';
        }
    }
}

function filterRulesTable() {
    renderRulesTable();
}

function renderRulesTable() {
    const tbody = document.getElementById('rules-table-body');
    const emptyState = document.getElementById('rules-empty-state');
    if (!tbody) return;

    const query = (document.getElementById('rules-search-input')?.value || '').trim().toLowerCase();
    const categoryFilter = document.getElementById('rules-category-filter')?.value || 'all';
    const modeFilter = document.getElementById('rules-mode-filter')?.value || 'all';

    tbody.innerHTML = '';

    const filtered = rulesList.filter(r => {
        if (categoryFilter !== 'all' && r.category !== categoryFilter) return false;
        if (modeFilter !== 'all' && r.reaction?.action_mode !== modeFilter) return false;
        if (query) {
            const nameMatch = (r.name || '').toLowerCase().includes(query);
            const descMatch = (r.description || '').toLowerCase().includes(query);
            const portsMatch = (r.destination?.ports || []).some(p => String(p).includes(query));
            const targetsMatch = (r.destination?.targets || []).some(t => String(t).toLowerCase().includes(query));
            const srcProfileMatch = (r.source?.profiles || []).some(p => String(p).toLowerCase().includes(query));
            if (!nameMatch && !descMatch && !portsMatch && !targetsMatch && !srcProfileMatch) {
                return false;
            }
        }
        return true;
    });

    if (filtered.length === 0) {
        if (emptyState) emptyState.classList.remove('hidden');
        return;
    }
    if (emptyState) emptyState.classList.add('hidden');

    filtered.forEach((r, idx) => {
        const tr = document.createElement('tr');
        const isCore = r.category === 'core';
        const isAlert = r.reaction?.action_mode === 'alert';

        tr.className = `group hover:bg-slate-800/40 transition duration-150 select-none ${!r.enabled ? 'opacity-50' : ''}`;
        tr.dataset.id = r.id;
        tr.dataset.index = idx;

        if (!isCore) {
            tr.setAttribute('draggable', 'true');
            tr.addEventListener('dragstart', (e) => onRuleDragStart(e, idx));
            tr.addEventListener('dragover', (e) => onRuleDragOver(e, idx));
            tr.addEventListener('dragleave', onRuleDragLeave);
            tr.addEventListener('drop', (e) => onRuleDrop(e, idx));
            tr.addEventListener('dragend', onRuleDragEnd);
        }

        // 1. Drag Handle
        let dragHandleHtml = '';
        if (isCore) {
            dragHandleHtml = `<span class="text-slate-600 cursor-not-allowed flex items-center justify-center p-1" title="Системное ядро зафиксировано"><i data-lucide="lock" class="w-3.5 h-3.5"></i></span>`;
        } else {
            dragHandleHtml = `<span class="cursor-grab active:cursor-grabbing text-slate-500 group-hover:text-slate-300 flex items-center justify-center p-1" title="Перетащите для изменения приоритета (HTML5 Drag)"><i data-lucide="grip-vertical" class="w-4 h-4"></i></span>`;
        }

        // 2. Order Index Badge
        let orderBadgeHtml = '';
        if (isCore) {
            orderBadgeHtml = `<span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/20">#${r.order_index}</span>`;
        } else {
            orderBadgeHtml = `<span class="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">#${r.order_index}</span>`;
        }

        // 3. Name & Category
        let catBadge = '';
        if (r.category === 'core') {
            catBadge = `<span class="px-1.5 py-0.2 rounded text-[10px] uppercase font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">ЯДРО</span>`;
        } else if (r.is_builtin) {
            catBadge = `<span class="px-1.5 py-0.2 rounded text-[10px] uppercase font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">ШАБЛОН</span>`;
        } else {
            catBadge = `<span class="px-1.5 py-0.2 rounded text-[10px] uppercase font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">КАСТОМ</span>`;
        }

        const nameHtml = `
            <div>
                <div class="flex items-center space-x-2">
                    <span class="font-semibold text-slate-200 group-hover:text-white transition">${escapeRuleHtml(r.name)}</span>
                    ${catBadge}
                </div>
                ${r.description ? `<p class="text-[11px] text-slate-400 line-clamp-1 mt-0.5">${escapeRuleHtml(r.description)}</p>` : ''}
            </div>
        `;

        // 4. Conditions (ЕСЛИ)
        let srcPill = '';
        if (r.source?.invert) {
            srcPill += `<span class="text-amber-400 font-bold text-[10px] mr-1">КРОМЕ:</span>`;
        }
        if (r.source?.profiles && r.source.profiles.length > 0) {
            srcPill += r.source.profiles.map(p => `<span class="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[10px] mr-1">${p}</span>`).join('');
        }
        if (r.source?.device_macs && r.source.device_macs.length > 0) {
            srcPill += `<span class="px-1.5 py-0.2 rounded bg-slate-800 text-indigo-300 border border-slate-700 text-[10px] font-mono mr-1">${r.source.device_macs.length} MAC</span>`;
        }
        if (!srcPill) srcPill = `<span class="text-slate-500 text-[11px]">Все</span>`;

        let dirPill = '';
        const dir = r.destination?.direction || 'any';
        if (dir === 'lan_to_lan') dirPill = `<span class="px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[10px]">LAN ➔ LAN</span>`;
        else if (dir === 'lan_to_wan') dirPill = `<span class="px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20 text-[10px]">LAN ➔ WAN</span>`;
        else if (dir === 'lan_to_router') dirPill = `<span class="px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-[10px]">LAN ➔ Router</span>`;
        else dirPill = `<span class="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">Любое</span>`;

        let portsPill = '';
        if (r.destination?.invert_ports) {
            portsPill += `<span class="text-amber-400 font-bold text-[10px] mr-1">КРОМЕ:</span>`;
        }
        if (r.destination?.ports && r.destination.ports.length > 0) {
            const portsStr = r.destination.ports.slice(0, 4).join(', ') + (r.destination.ports.length > 4 ? ` +${r.destination.ports.length - 4}` : '');
            portsPill += `<span class="px-1.5 py-0.2 rounded bg-slate-800 text-white font-mono border border-slate-700 text-[10px] mr-1">${portsStr}</span>`;
        }
        const protos = (r.destination?.protocols || []).join('/');
        if (protos) {
            portsPill += `<span class="text-slate-400 text-[10px]">${protos}</span>`;
        }

        let ctxPill = '';
        if (r.context?.volume_operator && r.context?.volume_bytes > 0) {
            ctxPill += `<span class="px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px] mr-1">${r.context.volume_operator} ${formatRuleVolume(r.context.volume_bytes)}</span>`;
        }
        if (r.context?.time_window === 'night_only') {
            ctxPill += `<span class="px-1.5 py-0.2 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 text-[10px] mr-1">🌙 Ночь</span>`;
        } else if (r.context?.time_window === 'day_only') {
            ctxPill += `<span class="px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px] mr-1">☀️ День</span>`;
        }

        const conditionsHtml = `
            <div class="space-y-1">
                <div class="flex items-center space-x-1.5 flex-wrap">
                    <span class="text-slate-400 text-[10px]">Ист:</span>
                    ${srcPill}
                    <span class="text-slate-600">|</span>
                    ${dirPill}
                </div>
                <div class="flex items-center space-x-1.5 flex-wrap">
                    <span class="text-slate-400 text-[10px]">Порт:</span>
                    ${portsPill || '<span class="text-slate-500 text-[10px]">Любой</span>'}
                    ${ctxPill ? `<span class="text-slate-600">|</span> ${ctxPill}` : ''}
                </div>
            </div>
        `;

        // 5. Reaction (ТО)
        let modeBadge = '';
        if (!isAlert) {
            modeBadge = `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center space-x-1 w-fit"><i data-lucide="check" class="w-3 h-3"></i><span>Разрешить</span></span>`;
        } else {
            const sevColor = r.reaction?.severity === 'CRITICAL' ? 'rose' : (r.reaction?.severity === 'WARNING' ? 'amber' : 'blue');
            modeBadge = `<span class="px-2 py-0.5 rounded-full text-[11px] font-bold bg-${sevColor}-500/20 text-${sevColor}-300 border border-${sevColor}-500/30 flex items-center space-x-1 w-fit"><i data-lucide="alert-triangle" class="w-3 h-3"></i><span>Инцидент (${r.reaction?.severity || 'WARN'})</span></span>`;
        }

        let actionIcons = '';
        if (r.reaction?.notify_telegram) {
            actionIcons += `<span title="Уведомление в Telegram (${r.reaction.telegram_mode || 'digest'})" class="p-1 rounded bg-slate-800 text-sky-400 border border-slate-700"><i data-lucide="bell" class="w-3 h-3"></i></span>`;
        }
        if (r.reaction?.record_pcap_seconds > 0) {
            actionIcons += `<span title="Захват PCAP ${r.reaction.record_pcap_seconds}s" class="p-1 rounded bg-slate-800 text-cyan-400 border border-slate-700"><i data-lucide="file-video" class="w-3 h-3"></i></span>`;
        }
        if (r.reaction?.hardware_wan_block) {
            actionIcons += `<span title="Блокировка WAN на роутере" class="p-1 rounded bg-slate-800 text-rose-400 border border-slate-700"><i data-lucide="shield-alert" class="w-3 h-3"></i></span>`;
        }
        if (r.reaction?.apply_preset_id) {
            actionIcons += `<span title="Смена пресета на ${r.reaction.apply_preset_id}" class="p-1 rounded bg-slate-800 text-amber-400 border border-slate-700"><i data-lucide="shield" class="w-3 h-3"></i></span>`;
        }

        const reactionHtml = `
            <div class="space-y-1">
                ${modeBadge}
                ${actionIcons ? `<div class="flex items-center space-x-1 pt-0.5">${actionIcons}</div>` : ''}
            </div>
        `;

        // 6. Hits Telemetry
        const hitsTotal = r.telemetry?.hits_total || 0;
        const hits24h = r.telemetry?.hits_24h || 0;
        const hitsBadge = `
            <button onclick="openRuleHitsDrawer('${r.id}', '${escapeRuleHtml(r.name)}')" class="px-2.5 py-1 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition flex items-center space-x-1.5 mx-auto cursor-pointer" title="Посмотреть историю срабатываний">
                <i data-lucide="activity" class="w-3.5 h-3.5 text-cyan-400"></i>
                <span class="font-mono font-semibold">${hitsTotal}</span>
                <span class="text-[10px] text-slate-400">(+${hits24h})</span>
            </button>
        `;

        // 7. Status Toggle
        const toggleHtml = `
            <label class="relative inline-flex items-center cursor-pointer justify-center w-full">
                <input type="checkbox" ${r.enabled ? 'checked' : ''} ${isCore ? 'disabled' : ''} onchange="toggleRule('${r.id}', this.checked)" class="sr-only peer">
                <div class="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[calc(50%-16px)] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-emerald-500 ${isCore ? 'opacity-40 cursor-not-allowed' : ''}"></div>
            </label>
        `;

        // 8. Actions
        let actionButtons = `
            <div class="flex items-center justify-end space-x-1">
        `;
        if (!isCore) {
            actionButtons += `
                <button onclick="moveRuleUp(${idx})" class="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer" title="Переместить выше">
                    <i data-lucide="chevron-up" class="w-3.5 h-3.5"></i>
                </button>
                <button onclick="moveRuleDown(${idx})" class="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer" title="Переместить ниже">
                    <i data-lucide="chevron-down" class="w-3.5 h-3.5"></i>
                </button>
            `;
        }
        actionButtons += `
            <button onclick="openRuleModal('${r.id}')" class="p-1.5 rounded-lg text-slate-400 hover:text-indigo-400 hover:bg-slate-800 transition cursor-pointer" title="Редактировать правило">
                <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
            </button>
        `;
        if (!isCore) {
            actionButtons += `
                <button onclick="deleteRule('${r.id}')" class="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition cursor-pointer" title="Удалить правило">
                    <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                </button>
            `;
        }
        actionButtons += `</div>`;

        tr.innerHTML = `
            <td class="py-3 px-3 text-center">${dragHandleHtml}</td>
            <td class="py-3 px-3 text-center">${orderBadgeHtml}</td>
            <td class="py-3 px-4">${nameHtml}</td>
            <td class="py-3 px-4">${conditionsHtml}</td>
            <td class="py-3 px-4">${reactionHtml}</td>
            <td class="py-3 px-4 text-center">${hitsBadge}</td>
            <td class="py-3 px-3 text-center">${toggleHtml}</td>
            <td class="py-3 px-4 text-right">${actionButtons}</td>
        `;

        tbody.appendChild(tr);
    });

    if (window.lucide && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
    }
}

// HTML5 Drag and Drop handlers
function onRuleDragStart(e, idx) {
    if (rulesList[idx].category === 'core') {
        e.preventDefault();
        return;
    }
    draggedRuleIndex = idx;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(idx));
    e.currentTarget.classList.add('opacity-40', 'bg-indigo-950/40');
}

function onRuleDragOver(e, idx) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const targetRule = rulesList[idx];
    if (targetRule.category === 'core') return;
    e.currentTarget.classList.add('border-t-2', 'border-indigo-400');
}

function onRuleDragLeave(e) {
    e.currentTarget.classList.remove('border-t-2', 'border-indigo-400');
}

function onRuleDrop(e, targetIdx) {
    e.preventDefault();
    e.currentTarget.classList.remove('border-t-2', 'border-indigo-400');

    if (draggedRuleIndex === null || draggedRuleIndex === targetIdx) return;
    if (rulesList[targetIdx].category === 'core') {
        showToast('Нельзя размещать правила выше системного ядра Зоны 1', 'warning');
        return;
    }

    const moved = rulesList.splice(draggedRuleIndex, 1)[0];
    rulesList.splice(targetIdx, 0, moved);

    hasUnsavedRuleChanges = true;
    showDraftBar();
    updateRulesStats();
    renderRulesTable();
}

function onRuleDragEnd(e) {
    e.currentTarget.classList.remove('opacity-40', 'bg-indigo-950/40', 'border-t-2', 'border-indigo-400');
    draggedRuleIndex = null;
}

// Accessible Move Up/Down buttons
function moveRuleUp(idx) {
    if (idx <= 0) return;
    const targetIdx = idx - 1;
    if (rulesList[targetIdx].category === 'core') {
        showToast('Правила ядра Зоны 1 должны оставаться первыми', 'warning');
        return;
    }
    const temp = rulesList[idx];
    rulesList[idx] = rulesList[targetIdx];
    rulesList[targetIdx] = temp;

    hasUnsavedRuleChanges = true;
    showDraftBar();
    updateRulesStats();
    renderRulesTable();
}

function moveRuleDown(idx) {
    if (idx >= rulesList.length - 1) return;
    const targetIdx = idx + 1;
    const temp = rulesList[idx];
    rulesList[idx] = rulesList[targetIdx];
    rulesList[targetIdx] = temp;

    hasUnsavedRuleChanges = true;
    showDraftBar();
    updateRulesStats();
    renderRulesTable();
}

// Draft Bar & Reorder persistence
function showDraftBar() {
    const bar = document.getElementById('rules-draft-bar');
    if (bar) bar.classList.remove('hidden');
}

function hideDraftBar() {
    const bar = document.getElementById('rules-draft-bar');
    if (bar) bar.classList.add('hidden');
}

function discardRuleChanges() {
    rulesList = JSON.parse(JSON.stringify(rulesOriginalSnapshot));
    hasUnsavedRuleChanges = false;
    hideDraftBar();
    updateRulesStats();
    renderRulesTable();
    showToast('Изменения порядка правил отменены', 'info');
}

async function saveRuleOrder(force = false) {
    const btn = document.getElementById('btn-save-rule-order');
    if (btn) btn.disabled = true;

    try {
        const ordered_ids = rulesList.map(r => r.id);
        const res = await fetch('/api/rules/reorder', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ordered_ids, force })
        });
        const data = await res.json();

        if (res.status === 409) {
            // Linter conflict warning (shadowed rules)
            openRuleConflictModal(data.issues || []);
            return;
        }

        if (!res.ok) {
            showToast(data.detail || 'Ошибка при сохранении порядка правил', 'error');
            return;
        }

        hasUnsavedRuleChanges = false;
        hideDraftBar();
        closeRuleConflictModal();
        showToast('Порядок правил успешно сохранен и применен в памяти!', 'success');
        await loadRules();
    } catch (e) {
        console.error('saveRuleOrder error:', e);
        showToast('Сетевая ошибка при сохранении порядка правил', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Soft Validation Conflict Modal
function openRuleConflictModal(issues) {
    const modal = document.getElementById('rule-conflict-modal');
    const container = document.getElementById('rule-conflict-issues-list');
    if (!modal || !container) return;

    container.innerHTML = '';
    issues.forEach(i => {
        const div = document.createElement('div');
        div.className = 'p-3 rounded-xl bg-slate-800/80 border border-amber-500/30 text-xs space-y-1';
        div.innerHTML = `
            <div class="flex items-center space-x-1.5 text-amber-300 font-semibold">
                <i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i>
                <span>${escapeRuleHtml(i.rule_name)}</span>
            </div>
            <p class="text-slate-300">${escapeRuleHtml(i.message)}</p>
            ${i.conflicting_rule_name ? `<p class="text-[11px] text-slate-400">Конфликт с правилом: <strong class="text-slate-200">${escapeRuleHtml(i.conflicting_rule_name)}</strong></p>` : ''}
        `;
        container.appendChild(div);
    });

    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeRuleConflictModal() {
    const modal = document.getElementById('rule-conflict-modal');
    if (modal) modal.classList.add('hidden');
}

// Rule Builder Modal (ЕСЛИ -> ТО)
function openRuleModal(ruleId = null) {
    currentEditingRuleId = ruleId;
    const modal = document.getElementById('rule-modal');
    const title = document.getElementById('rule-modal-title');
    const form = document.getElementById('rule-builder-form');
    if (!modal || !form) return;

    form.reset();

    if (ruleId) {
        const rule = rulesList.find(r => r.id === ruleId);
        if (!rule) return;
        if (title) title.textContent = `Редактирование правила #${rule.order_index}`;

        document.getElementById('rule-form-id').value = rule.id;
        document.getElementById('rule-form-order').value = rule.order_index;
        document.getElementById('rule-form-name').value = rule.name || '';
        document.getElementById('rule-form-desc').value = rule.description || '';
        document.getElementById('rule-form-category').value = rule.category || 'custom';

        // Source
        document.getElementById('rule-form-src-invert').checked = !!rule.source?.invert;
        const profs = rule.source?.profiles || [];
        document.querySelectorAll('input[name="rule-src-profile"]').forEach(cb => {
            cb.checked = profs.includes(cb.value);
        });
        document.getElementById('rule-form-src-macs').value = (rule.source?.device_macs || []).join(', ');

        // Destination
        document.getElementById('rule-form-direction').value = rule.destination?.direction || 'any';
        document.getElementById('rule-form-dst-invert-ports').checked = !!rule.destination?.invert_ports;
        document.getElementById('rule-form-ports').value = (rule.destination?.ports || []).join(', ');
        const protos = rule.destination?.protocols || ['TCP', 'UDP'];
        document.querySelectorAll('input[name="rule-protocol"]').forEach(cb => {
            cb.checked = protos.includes(cb.value);
        });
        document.getElementById('rule-form-targets').value = (rule.destination?.targets || []).join(', ');

        // Context
        document.getElementById('rule-form-vol-op').value = rule.context?.volume_operator || '';
        document.getElementById('rule-form-vol-val').value = Math.round((rule.context?.volume_bytes || 0) / 1024);
        document.getElementById('rule-form-time-window').value = rule.context?.time_window || 'always';

        // Reaction
        const isAlert = rule.reaction?.action_mode === 'alert';
        document.querySelector(`input[name="rule-action-mode"][value="${isAlert ? 'alert' : 'pass'}"]`).checked = true;
        document.getElementById('rule-form-severity').value = rule.reaction?.severity || 'WARNING';

        document.getElementById('rule-form-tg-notify').checked = !!rule.reaction?.notify_telegram;
        document.getElementById('rule-form-tg-mode').value = rule.reaction?.telegram_mode || 'digest';
        document.getElementById('rule-form-pcap-sec').value = rule.reaction?.record_pcap_seconds || 0;
        document.getElementById('rule-form-wan-block').checked = !!rule.reaction?.hardware_wan_block;
        document.getElementById('rule-form-apply-preset').value = rule.reaction?.apply_preset_id || '';
    } else {
        if (title) title.textContent = 'Создание нового правила безопасности';
        document.getElementById('rule-form-id').value = '';
        document.getElementById('rule-form-order').value = 0;
        document.getElementById('rule-form-category').value = 'custom';
        document.querySelector('input[name="rule-action-mode"][value="pass"]').checked = true;
        document.querySelectorAll('input[name="rule-protocol"]').forEach(cb => cb.checked = true);
    }

    onRuleActionModeChange();
    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeRuleModal() {
    const modal = document.getElementById('rule-modal');
    if (modal) modal.classList.add('hidden');
    currentEditingRuleId = null;
}

function onRuleActionModeChange() {
    const isAlert = document.querySelector('input[name="rule-action-mode"]:checked')?.value === 'alert';
    const sevContainer = document.getElementById('rule-severity-container');
    const measuresContainer = document.getElementById('rule-reactive-measures');

    const passLabel = document.getElementById('label-action-pass');
    const alertLabel = document.getElementById('label-action-alert');

    if (isAlert) {
        if (sevContainer) {
            sevContainer.classList.remove('opacity-50', 'pointer-events-none');
        }
        if (measuresContainer) {
            measuresContainer.classList.remove('opacity-50', 'pointer-events-none');
        }
        if (alertLabel) {
            alertLabel.className = 'flex items-center space-x-2 p-2.5 rounded-xl border border-rose-500/40 bg-rose-500/10 text-rose-300 cursor-pointer font-medium text-xs';
        }
        if (passLabel) {
            passLabel.className = 'flex items-center space-x-2 p-2.5 rounded-xl border border-slate-700 bg-slate-800/80 text-slate-300 cursor-pointer font-medium text-xs hover:border-slate-600';
        }
    } else {
        if (sevContainer) {
            sevContainer.classList.add('opacity-50', 'pointer-events-none');
        }
        if (measuresContainer) {
            measuresContainer.classList.add('opacity-50', 'pointer-events-none');
        }
        if (passLabel) {
            passLabel.className = 'flex items-center space-x-2 p-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 cursor-pointer font-medium text-xs';
        }
        if (alertLabel) {
            alertLabel.className = 'flex items-center space-x-2 p-2.5 rounded-xl border border-slate-700 bg-slate-800/80 text-slate-300 cursor-pointer font-medium text-xs hover:border-slate-600';
        }
    }
}

async function submitRuleForm(e) {
    if (e && e.preventDefault) e.preventDefault();

    const ruleId = document.getElementById('rule-form-id').value;
    const name = document.getElementById('rule-form-name').value.trim();
    if (!name) {
        showToast('Пожалуйста, укажите название правила', 'warning');
        return;
    }

    const description = document.getElementById('rule-form-desc').value.trim();
    const category = document.getElementById('rule-form-category').value;

    // Source
    const srcInvert = document.getElementById('rule-form-src-invert').checked;
    const selectedProfiles = Array.from(document.querySelectorAll('input[name="rule-src-profile"]:checked')).map(cb => cb.value);
    const macsRaw = document.getElementById('rule-form-src-macs').value;
    const deviceMacs = macsRaw ? macsRaw.split(',').map(m => m.trim().toUpperCase()).filter(Boolean) : [];

    // Destination
    const direction = document.getElementById('rule-form-direction').value;
    const invertPorts = document.getElementById('rule-form-dst-invert-ports').checked;
    const portsRaw = document.getElementById('rule-form-ports').value;
    const ports = [];
    if (portsRaw) {
        portsRaw.split(',').forEach(p => {
            const clean = p.trim();
            if (clean.includes('-')) {
                ports.push(clean);
            } else if (clean && !isNaN(clean)) {
                ports.push(parseInt(clean, 10));
            }
        });
    }
    const protocols = Array.from(document.querySelectorAll('input[name="rule-protocol"]:checked')).map(cb => cb.value);
    const targetsRaw = document.getElementById('rule-form-targets').value;
    const targets = targetsRaw ? targetsRaw.split(',').map(t => t.trim()).filter(Boolean) : [];

    // Context
    const volOp = document.getElementById('rule-form-vol-op').value || null;
    const volValKb = parseFloat(document.getElementById('rule-form-vol-val').value) || 0;
    const volumeBytes = volValKb * 1024;
    const timeWindow = document.getElementById('rule-form-time-window').value;

    // Reaction
    const actionMode = document.querySelector('input[name="rule-action-mode"]:checked')?.value || 'pass';
    const severity = document.getElementById('rule-form-severity').value;
    const notifyTg = document.getElementById('rule-form-tg-notify').checked;
    const tgMode = document.getElementById('rule-form-tg-mode').value;
    const pcapSec = parseInt(document.getElementById('rule-form-pcap-sec').value, 10) || 0;
    const wanBlock = document.getElementById('rule-form-wan-block').checked;
    const applyPreset = document.getElementById('rule-form-apply-preset').value || null;

    const payload = {
        name,
        description,
        enabled: true,
        category,
        source: {
            invert: srcInvert,
            device_macs: deviceMacs,
            profiles: selectedProfiles
        },
        destination: {
            direction,
            invert_ports: invertPorts,
            ports,
            protocols,
            targets
        },
        context: {
            volume_operator: volOp,
            volume_bytes: volumeBytes,
            time_window: timeWindow
        },
        reaction: {
            action_mode: actionMode,
            severity,
            notify_telegram: notifyTg,
            telegram_mode: tgMode,
            record_pcap_seconds: pcapSec,
            hardware_wan_block: wanBlock,
            apply_preset_id: applyPreset
        }
    };

    try {
        let res;
        if (ruleId) {
            res = await fetch(`/api/rules/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } else {
            res = await fetch('/api/rules', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        if (!res.ok) {
            const err = await res.json();
            showToast(err.detail || 'Ошибка сохранения правила', 'error');
            return;
        }

        closeRuleModal();
        showToast(ruleId ? 'Правило обновлено!' : 'Правило создано!', 'success');
        await loadRules();
    } catch (e) {
        console.error('submitRuleForm error:', e);
        showToast('Сетевая ошибка при сохранении правила', 'error');
    }
}

async function deleteRule(ruleId) {
    const rule = rulesList.find(r => r.id === ruleId);
    if (!rule) return;
    if (rule.category === 'core') {
        showToast('Базовые системные правила Зоны 1 нельзя удалять', 'error');
        return;
    }

    if (!confirm(`Удалить правило "${rule.name}"? Это действие нельзя отменить.`)) {
        return;
    }

    try {
        const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
        if (!res.ok) {
            const err = await res.json();
            showToast(err.detail || 'Не удалось удалить правило', 'error');
            return;
        }
        showToast('Правило удалено', 'success');
        await loadRules();
    } catch (e) {
        console.error('deleteRule error:', e);
        showToast('Сетевая ошибка при удалении правила', 'error');
    }
}

async function toggleRule(ruleId, enabled) {
    try {
        const res = await fetch(`/api/rules/${ruleId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!res.ok) {
            const err = await res.json();
            showToast(err.detail || 'Не удалось переключить статус правила', 'error');
            await loadRules();
            return;
        }
        const rule = rulesList.find(r => r.id === ruleId);
        if (rule) rule.enabled = enabled;
        updateRulesStats();
        updateRulesBadgeOnly();
        renderRulesTable();
        showToast(`Правило ${enabled ? 'включено' : 'отключено'}`, 'info');
    } catch (e) {
        console.error('toggleRule error:', e);
        await loadRules();
    }
}

// Hit Telemetry Drawer
async function openRuleHitsDrawer(ruleId, ruleName) {
    const modal = document.getElementById('rule-hits-drawer');
    const nameEl = document.getElementById('rule-hits-modal-name');
    const totalEl = document.getElementById('rule-hits-modal-total');
    const hits24El = document.getElementById('rule-hits-modal-24h');
    const tbody = document.getElementById('rule-hits-modal-body');
    const emptyEl = document.getElementById('rule-hits-modal-empty');
    if (!modal || !tbody) return;

    const rule = rulesList.find(r => r.id === ruleId);
    if (nameEl) nameEl.textContent = ruleName || ruleId;
    if (totalEl) totalEl.textContent = rule?.telemetry?.hits_total || 0;
    if (hits24El) hits24El.textContent = rule?.telemetry?.hits_24h || 0;

    tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-400">Загрузка истории...</td></tr>';
    if (emptyEl) emptyEl.classList.add('hidden');
    modal.classList.remove('hidden');

    try {
        const res = await fetch(`/api/rules/${ruleId}/hits?limit=20`);
        if (!res.ok) throw new Error('Fetch failed');
        const hits = await res.json();

        tbody.innerHTML = '';
        if (hits.length === 0) {
            if (emptyEl) emptyEl.classList.remove('hidden');
            return;
        }

        hits.forEach(h => {
            const tr = document.createElement('tr');
            const timeStr = h.timestamp ? new Date(h.timestamp).toLocaleTimeString() : '—';
            const actionBadge = h.action_taken === 'pass'
                ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300">PASS</span>`
                : `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300">ALERT</span>`;

            tr.innerHTML = `
                <td class="py-2 px-2 text-slate-400 font-mono">${timeStr}</td>
                <td class="py-2 px-2 text-slate-200 font-mono">${escapeRuleHtml(h.src_ip || '—')}</td>
                <td class="py-2 px-2 text-slate-200 font-mono">${escapeRuleHtml(h.dst_ip || '—')}</td>
                <td class="py-2 px-2 text-cyan-300 font-mono">${h.port || '—'} / ${h.protocol || 'TCP'}</td>
                <td class="py-2 px-2 text-right text-slate-400 font-mono">${formatRuleVolume(h.bytes_count)}</td>
                <td class="py-2 px-2 text-center">${actionBadge}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" class="py-4 text-center text-rose-400">Ошибка при загрузке истории</td></tr>';
    }
}

function closeRuleHitsDrawer() {
    const modal = document.getElementById('rule-hits-drawer');
    if (modal) modal.classList.add('hidden');
}

// Traffic Flow Simulator Modal
function openRuleSimModal() {
    const modal = document.getElementById('rule-sim-modal');
    const resultBox = document.getElementById('sim-result-box');
    if (!modal) return;
    if (resultBox) resultBox.classList.add('hidden');
    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeRuleSimModal() {
    const modal = document.getElementById('rule-sim-modal');
    if (modal) modal.classList.add('hidden');
}

async function runRuleSimulation() {
    const srcIp = document.getElementById('sim-src-ip').value.trim();
    const dstIp = document.getElementById('sim-dst-ip').value.trim();
    const port = parseInt(document.getElementById('sim-port').value, 10) || null;
    const protocol = document.getElementById('sim-proto').value;
    const bytesCount = parseInt(document.getElementById('sim-bytes').value, 10) || 0;
    const timeOfDay = document.getElementById('sim-time').value;
    const resultBox = document.getElementById('sim-result-box');

    if (!srcIp || !dstIp) {
        showToast('Укажите IP источника и назначения', 'warning');
        return;
    }

    try {
        const res = await fetch('/api/rules/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                src_ip: srcIp,
                dst_ip: dstIp,
                port,
                protocol,
                bytes_count: bytesCount,
                time_of_day: timeOfDay
            })
        });

        if (!res.ok) {
            showToast('Ошибка при выполнении симуляции', 'error');
            return;
        }

        const data = await res.json();
        if (!resultBox) return;

        resultBox.classList.remove('hidden');

        if (data.matched) {
            const isAlert = data.action_mode === 'alert';
            resultBox.className = `p-4 rounded-xl border ${isAlert ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'} space-y-2 text-xs`;
            resultBox.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="font-bold text-sm text-white flex items-center space-x-1.5">
                        <i data-lucide="${isAlert ? 'shield-alert' : 'shield-check'}" class="w-4 h-4"></i>
                        <span>СОВПАДЕНИЕ: ${escapeRuleHtml(data.rule_name)}</span>
                    </span>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase bg-slate-900 border border-slate-700">${data.action_mode.toUpperCase()}</span>
                </div>
                <p class="text-slate-300">${escapeRuleHtml(data.description || '')}</p>
                <div class="flex items-center space-x-2 text-[11px] pt-1">
                    <span class="text-slate-400">ID правила: <strong class="text-slate-200 font-mono">${data.rule_id}</strong></span>
                    ${data.severity ? `<span class="text-slate-400">| Уровень: <strong class="text-amber-300">${data.severity}</strong></span>` : ''}
                </div>
            `;
        } else {
            resultBox.className = 'p-4 rounded-xl border bg-slate-800/80 border-slate-700 text-slate-300 space-y-2 text-xs';
            resultBox.innerHTML = `
                <div class="flex items-center space-x-1.5 font-bold text-slate-200">
                    <i data-lucide="shield" class="w-4 h-4 text-slate-400"></i>
                    <span>НЕТ ПРЯМОГО СОВПАДЕНИЯ (Зона 3 Fallback)</span>
                </div>
                <p class="text-slate-400">Поток не попал ни под одно явное правило Зоны 1 и Зоны 2. Применяется стандартный пресет безопасности и изоляция профиля устройства.</p>
            `;
        }

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('runRuleSimulation error:', e);
        showToast('Ошибка симуляции потока', 'error');
    }
}

// Guard against unsaved reordering changes on page reload/close
window.addEventListener('beforeunload', (e) => {
    if (typeof hasUnsavedRuleChanges !== 'undefined' && hasUnsavedRuleChanges) {
        e.preventDefault();
        e.returnValue = '';
    }
});



