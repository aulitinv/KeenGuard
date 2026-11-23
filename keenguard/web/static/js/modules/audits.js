// --- Traffic Audits Tab Functions ---
let activeAuditsCount = 0;

async function loadTrafficAuditsTab() {
    await populateAuditDeviceSelect();
    await loadActiveAudits();
    await loadAuditReports();
}

async function populateAuditDeviceSelect() {
    const select = document.getElementById('audit-launch-device');
    if (!select) return;

    try {
        if (!devicesList || devicesList.length === 0) {
            const res = await fetch('/api/devices');
            devicesList = await res.json();
        }

        const currentVal = select.value;
        select.innerHTML = `
            <option value="">-- Выберите цель мониторинга --</option>
            <optgroup label="🌐 Массовый сетевой аудит (Все соединения)">
                <option value="__ALL_NETWORK__">🌐 Вся домашняя сеть (все онлайн устройства)</option>
                <option value="__IOT_ONLY__">⚡ Только устройства Умного дома (IoT / Smart Home)</option>
                <option value="__UNTRUSTED__">🛡️ Недоверенные и изолированные устройства</option>
            </optgroup>
        `;

        const groupDev = document.createElement('optgroup');
        groupDev.label = '📱 Индивидуальный аудит устройств';

        const sorted = [...devicesList].sort((a, b) => {
            if (a.is_online !== b.is_online) return b.is_online ? 1 : -1;
            const nameA = a.custom_name || a.hostname || a.ip;
            const nameB = b.custom_name || b.hostname || b.ip;
            return nameA.localeCompare(nameB);
        });

        sorted.forEach(dev => {
            const opt = document.createElement('option');
            opt.value = dev.mac;
            const name = dev.custom_name || dev.hostname || 'Без имени';
            const status = dev.is_online ? '● Онлайн' : '○ Офлайн';
            const vendor = dev.vendor ? ` [${dev.vendor}]` : '';
            opt.textContent = `${name} — ${dev.ip} (${status})${vendor}`;
            groupDev.appendChild(opt);
        });

        select.appendChild(groupDev);

        if (currentVal) {
            select.value = currentVal;
        }
    } catch (e) {
        console.error('Failed to populate audit device select', e);
    }
}

async function startNetworkAuditQuick(scope = 'all', duration = 300) {
    try {
        const res = await fetch('/api/audit/network/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scope: scope, duration_seconds: duration })
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        showToast('Запущен аудит сетевого трафика!');
        switchTab('audits');
        await loadActiveAudits();
    } catch (e) {
        alert(`Ошибка запуска аудита всей сети: ${e.message}`);
    }
}

async function loadActiveAudits() {
    const container = document.getElementById('active-audits-container');
    const countBadge = document.getElementById('active-audits-count');
    const navBadge = document.getElementById('audits-active-badge');

    try {
        const res = await fetch('/api/audit/active');
        if (!res.ok) return;
        const activeList = await res.json();
        activeAuditsCount = activeList.length;

        if (countBadge) {
            countBadge.textContent = `${activeList.length} ${activeList.length === 1 ? 'сессия' : (activeList.length > 1 && activeList.length < 5 ? 'сессии' : 'сессий')}`;
        }

        if (navBadge) {
            if (activeList.length > 0) {
                navBadge.textContent = String(activeList.length);
                navBadge.classList.remove('hidden');
            } else {
                navBadge.classList.add('hidden');
            }
        }

        // Global Active DPI Capture Banner
        const dpiBanner = document.getElementById('global-active-dpi-banner');
        const dpiTarget = document.getElementById('global-dpi-target-text');
        const dpiTimer = document.getElementById('global-dpi-timer-text');
        if (dpiBanner) {
            if (activeList.length > 0) {
                const s = activeList[0];
                dpiBanner.classList.remove('hidden');
                if (dpiTarget) {
                    const targetName = (s.is_network || s.mac === 'NETWORK') ? 'Вся сеть (Все устройства)' : (s.hostname ? `${s.hostname} (${s.mac})` : (s.mac || 'Устройство'));
                    dpiTarget.textContent = targetName;
                }
                if (dpiTimer) {
                    if (s.duration_seconds > 0) {
                        const remaining = Math.max(0, s.duration_seconds - (s.elapsed_seconds || 0));
                        const m = Math.floor(remaining / 60);
                        const sec = String(remaining % 60).padStart(2, '0');
                        dpiTimer.innerHTML = `<i data-lucide="timer" class="w-3.5 h-3.5 text-rose-400"></i><span>Осталось: <b class="font-mono text-white text-sm">${m}:${sec}</b></span>`;
                    } else {
                        dpiTimer.innerHTML = `<i data-lucide="timer" class="w-3.5 h-3.5 text-amber-400"></i><span class="text-amber-300 font-medium">Бессрочный (ручной)</span>`;
                    }
                    if (window.lucide) lucide.createIcons();
                }
            } else {
                dpiBanner.classList.add('hidden');
            }
        }

        if (!container) return;

        if (activeList.length === 0) {
            container.innerHTML = `
                <div class="p-6 text-center text-slate-500 text-xs italic bg-surface-950/40 rounded-xl border border-slate-800/40">
                    Нет активных сессий аудита. Выберите устройство выше и нажмите «Начать аудит».
                </div>
            `;
            return;
        }

        container.innerHTML = activeList.map(session => {
            const isNet = session.is_network || session.mac === 'NETWORK';
            const elapsed = session.elapsed_seconds || 0;
            const totalSec = session.duration_seconds || 0;
            const timeLimitStr = totalSec > 0 ? formatDuration(totalSec) : '∞ Без ограничения (ручной)';
            const elapsedStr = `${Math.floor(elapsed / 60)}:${String(elapsed % 60).padStart(2, '0')}`;
            const progressPercent = totalSec > 0 ? Math.min(100, Math.round((elapsed / totalSec) * 100)) : 100;
            const bytesStr = formatBytes(session.total_bytes || 0);

            if (isNet) {
                const quarantinedBadge = (session.quarantined_count > 0) ?
                    `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">🚨 Изолировано: ${session.quarantined_count}</span>` : '';

                return `
                    <div class="p-4 rounded-xl bg-surface-950 border border-indigo-500/40 shadow-lg shadow-indigo-950/30 space-y-3 relative overflow-hidden">
                        <div class="absolute -right-10 -bottom-10 w-40 h-40 bg-indigo-600/10 rounded-full blur-2xl pointer-events-none"></div>
                        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div class="flex items-center space-x-3">
                                <div class="p-2.5 rounded-xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 text-cyan-300 border border-cyan-500/30 shrink-0">
                                    <i data-lucide="radio" class="w-6 h-6 animate-pulse text-cyan-400"></i>
                                </div>
                                <div>
                                    <div class="flex items-center space-x-2">
                                        <h4 class="font-bold text-sm text-white">📡 Сводный аудит сетевого трафика (${escapeHtml(session.scope || 'all')})</h4>
                                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-pulse">Идет захват сети</span>
                                        ${quarantinedBadge}
                                    </div>
                                    <div class="text-[11px] text-slate-400 font-mono mt-0.5">
                                        Охват: вся сеть роутера Keenetic &bull; Активных устройств: ${session.devices_count || 0}
                                    </div>
                                </div>
                            </div>
                            <div class="flex items-center space-x-2 shrink-0">
                                <button onclick="stopTrafficAuditFromTab('NETWORK')" class="px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition flex items-center space-x-1.5 shadow-md shadow-rose-900/30">
                                    <i data-lucide="square" class="w-3.5 h-3.5"></i>
                                    <span>Остановить и открыть отчет</span>
                                </button>
                            </div>
                        </div>

                        ${totalSec > 0 ? `
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div class="bg-gradient-to-r from-cyan-500 to-indigo-500 h-1.5 rounded-full transition-all duration-500" style="width: ${progressPercent}%"></div>
                            </div>
                        ` : `
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div class="bg-gradient-to-r from-cyan-500 via-indigo-500 to-cyan-500 h-1.5 rounded-full animate-pulse w-full"></div>
                            </div>
                        `}

                        <div class="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs pt-1">
                            <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                                <span class="text-[10px] text-slate-400 block">Время сессии</span>
                                <span class="font-semibold text-slate-200 font-mono">${elapsedStr} / ${timeLimitStr}</span>
                            </div>
                            <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                                <span class="text-[10px] text-slate-400 block">Хостов в охвате</span>
                                <span class="font-semibold text-indigo-400 font-mono">${session.devices_count || 0}</span>
                            </div>
                            <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                                <span class="text-[10px] text-slate-400 block">NAT-соединений</span>
                                <span class="font-semibold text-purple-400 font-mono">${session.flows_count || 0}</span>
                            </div>
                            <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                                <span class="text-[10px] text-slate-400 block">Пакеты</span>
                                <span class="font-semibold text-cyan-400 font-mono">${session.total_packets || 0}</span>
                            </div>
                            <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                                <span class="text-[10px] text-slate-400 block">Объем трафика</span>
                                <span class="font-semibold text-emerald-400 font-mono">${bytesStr}</span>
                            </div>
                        </div>
                    </div>
                `;
            }

            const devName = session.hostname || session.mac;
            const devIp = session.ip || 'IP не определен';

            return `
                <div class="p-4 rounded-xl bg-surface-950 border border-cyan-500/30 shadow-md shadow-cyan-950/20 space-y-3">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div class="flex items-center space-x-3">
                            <div class="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 shrink-0">
                                <i data-lucide="activity" class="w-5 h-5 animate-pulse"></i>
                            </div>
                            <div>
                                <div class="flex items-center space-x-2">
                                    <h4 class="font-bold text-sm text-white">${escapeHtml(devName)}</h4>
                                    <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 animate-pulse">Идет захват</span>
                                </div>
                                <div class="text-[11px] text-slate-400 font-mono mt-0.5">
                                    ${escapeHtml(devIp)} &bull; ${escapeHtml(session.mac)} ${session.vendor ? `&bull; ${escapeHtml(session.vendor)}` : ''}
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2 shrink-0">
                            <button data-mac="${escapeHtml(session.mac)}" onclick="stopTrafficAuditFromTab(this.dataset.mac)" class="px-3.5 py-1.5 rounded-xl bg-rose-600/90 hover:bg-rose-600 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-sm">
                                <i data-lucide="square" class="w-3.5 h-3.5"></i>
                                <span>Остановить и сформировать отчет</span>
                            </button>
                        </div>
                    </div>

                    <!-- Progress bar -->
                    ${totalSec > 0 ? `
                        <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div class="bg-cyan-500 h-1.5 rounded-full transition-all duration-500" style="width: ${progressPercent}%"></div>
                        </div>
                    ` : `
                        <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                            <div class="bg-gradient-to-r from-cyan-500 via-indigo-500 to-cyan-500 h-1.5 rounded-full animate-pulse w-full"></div>
                        </div>
                    `}

                    <!-- Live Metrics Cards -->
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs pt-1">
                        <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                            <span class="text-[10px] text-slate-400 block">Время сессии</span>
                            <span class="font-semibold text-slate-200 font-mono">${elapsedStr} / ${timeLimitStr}</span>
                        </div>
                        <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                            <span class="text-[10px] text-slate-400 block">NAT-соединений</span>
                            <span class="font-semibold text-indigo-400 font-mono">${session.flows_count || 0}</span>
                        </div>
                        <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                            <span class="text-[10px] text-slate-400 block">Пакеты</span>
                            <span class="font-semibold text-cyan-400 font-mono">${session.total_packets || 0}</span>
                        </div>
                        <div class="p-2 rounded-lg bg-surface-900 border border-slate-800/80">
                            <span class="text-[10px] text-slate-400 block">Объем данных</span>
                            <span class="font-semibold text-emerald-400 font-mono">${bytesStr}</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        lucide.createIcons();
    } catch (e) {
        console.error('Failed to load active audits', e);
    }
}

async function startTrafficAuditFromTab() {
    const select = document.getElementById('audit-launch-device');
    const durationSelect = document.getElementById('audit-launch-duration');
    const mac = select ? select.value : null;
    const duration = durationSelect ? parseInt(durationSelect.value, 10) : 300;

    if (!mac) {
        alert('Пожалуйста, выберите цель мониторинга из списка!');
        return;
    }

    try {
        if (mac === '__ALL_NETWORK__' || mac === '__IOT_ONLY__' || mac === '__UNTRUSTED__' || mac === 'NETWORK') {
            let scope = 'all';
            if (mac === '__IOT_ONLY__') scope = 'iot_only';
            else if (mac === '__UNTRUSTED__') scope = 'untrusted';

            const res = await fetch('/api/audit/network/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scope: scope, duration_seconds: duration })
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || `HTTP ${res.status}`);
            }
        } else {
            const res = await fetch(`/api/audit/${mac}/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ duration_seconds: duration })
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || `HTTP ${res.status}`);
            }
        }

        await loadActiveAudits();
    } catch (e) {
        alert(`Ошибка запуска аудита: ${e.message}`);
    }
}

async function stopTrafficAuditFromTab(mac) {
    try {
        const isNet = (mac === 'NETWORK' || mac === '__ALL_NETWORK__' || mac === '__IOT_ONLY__' || mac === '__UNTRUSTED__');
        const url = isNet ? '/api/audit/network/stop' : `/api/audit/${mac}/stop`;
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        const report = await res.json();
        await loadActiveAudits();
        await loadAuditReports();
        if (isNet || report.is_network || report.mac === 'NETWORK') {
            openNetworkAuditModal(report);
        } else {
            openAuditModal(report);
        }
    } catch (e) {
        alert(`Ошибка остановки аудита: ${e.message}`);
    }
}

function sortAuditReports(reports) {
    const { col, dir } = tableSortState.audits;
    const mult = dir === 'asc' ? 1 : -1;
    const riskWeights = { critical: 4, high: 3, medium: 2, warning: 2, low: 1, safe: 1, info: 1 };

    return [...reports].sort((a, b) => {
        let cmp = 0;
        if (col === 'device') {
            const nameA = a.hostname || a.ip || a.mac || '';
            const nameB = b.hostname || b.ip || b.mac || '';
            cmp = nameA.localeCompare(nameB, 'ru');
        } else if (col === 'date') {
            const tA = a.created_at ? new Date(a.created_at).getTime() : 0;
            const tB = b.created_at ? new Date(b.created_at).getTime() : 0;
            cmp = tA - tB;
        } else if (col === 'duration') {
            cmp = (a.duration_seconds || 0) - (b.duration_seconds || 0);
        } else if (col === 'traffic') {
            cmp = (a.total_bytes || 0) - (b.total_bytes || 0);
        } else if (col === 'risk') {
            const rA = riskWeights[a.risk_level] || 1;
            const rB = riskWeights[b.risk_level] || 1;
            cmp = rA - rB;
        } else if (col === 'summary') {
            cmp = (a.summary || '').localeCompare(b.summary || '', 'ru');
        }
        return cmp * mult;
    });
}

async function loadAuditReports() {
    const tbody = document.getElementById('audit-reports-tbody');
    if (!tbody) return;

    try {
        const res = await fetch('/api/audit/reports?limit=50');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        allAuditReports = await res.json();
        renderAuditReportsTable();
    } catch (e) {
        console.error('Failed to load audit reports', e);
    }
}

function renderAuditReportsTable() {
    const tbody = document.getElementById('audit-reports-tbody');
    if (!tbody) return;

    if (!allAuditReports || allAuditReports.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-8 text-center text-slate-500 italic">
                    История проверок пока пуста. Запустите первую сессию аудита выше!
                </td>
            </tr>
        `;
        return;
    }

    const sorted = sortAuditReports(allAuditReports);

    tbody.innerHTML = sorted.map(r => {
        const dateStr = new Date(r.created_at).toLocaleString('ru-RU', {
            day: '2-digit', month: '2-digit', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });

        const durationStr = formatDuration(r.duration_seconds || 0);
        const bytesStr = formatBytes(r.total_bytes || 0);
        const packetsStr = `${r.total_packets || 0} пак.`;

        let riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Безопасно</span>';
        if (r.risk_level === 'high' || r.risk_level === 'critical') {
            riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">Критично</span>';
        } else if (r.risk_level === 'medium' || r.risk_level === 'warning') {
            riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">Внимание</span>';
        }

        const pcapBtn = r.pcap_file ? `
            <a href="/api/audit/pcap/${encodeURIComponent(r.pcap_file)}" download="${escapeHtml(r.pcap_file)}" title="Скачать .PCAP файл" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition border border-slate-700 inline-flex items-center">
                <i data-lucide="download" class="w-3.5 h-3.5"></i>
            </a>
        ` : '';

        const isNet = r.is_network || r.mac === 'NETWORK';
        const hostHtml = isNet ?
            `<div class="font-medium text-cyan-300 flex items-center space-x-1.5"><i data-lucide="radio" class="w-3.5 h-3.5 text-cyan-400"></i><span>${escapeHtml(r.hostname || 'Сводный аудит сети')}</span></div>
             <div class="text-[11px] text-slate-400 font-mono mt-0.5">Охват: ${escapeHtml(r.scope || 'вся сеть')} &bull; Хостов: ${r.devices_analyzed || (r.top_devices ? r.top_devices.length : 0)}</div>` :
            `<div class="font-medium text-slate-200">${escapeHtml(r.hostname || 'Без имени')}</div>
             <div class="text-[11px] text-slate-400 font-mono mt-0.5">${escapeHtml(r.ip || '')} (${escapeHtml(r.mac || '')})</div>`;

        return `
            <tr class="hover:bg-slate-800/30 transition">
                <td class="py-3 px-4">
                    ${hostHtml}
                </td>
                <td class="py-3 px-4 text-slate-300 whitespace-nowrap">${dateStr}</td>
                <td class="py-3 px-4 text-slate-300 whitespace-nowrap">${durationStr}</td>
                <td class="py-3 px-4">
                    <div class="font-medium text-slate-200">${bytesStr}</div>
                    <div class="text-[11px] text-slate-500 font-mono">${packetsStr}</div>
                </td>
                <td class="py-3 px-4 whitespace-nowrap">${riskBadge}</td>
                <td class="py-3 px-4 text-slate-300 max-w-xs truncate" title="${escapeHtml(r.summary || '')}">
                    ${escapeHtml(r.summary || 'Штатная активность')}
                </td>
                <td class="py-3 px-4 text-right whitespace-nowrap">
                    <div class="flex items-center justify-end space-x-1.5">
                        <button data-report-id="${escapeHtml(r.id)}" onclick="openInvestigatorForAudit(this.dataset.reportId)" class="px-2.5 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 hover:text-rose-200 border border-rose-500/30 text-xs font-medium transition flex items-center space-x-1" title="Интерактивное расследование инцидента (Wizard)">
                            <i data-lucide="crosshair" class="w-3.5 h-3.5 text-rose-400"></i>
                            <span>Расследовать</span>
                        </button>
                        <button data-report-id="${escapeHtml(r.id)}" onclick="openAuditReportById(this.dataset.reportId)" class="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 hover:text-indigo-200 border border-indigo-500/30 text-xs font-medium transition flex items-center space-x-1">
                            <i data-lucide="eye" class="w-3.5 h-3.5"></i>
                            <span>Отчет</span>
                        </button>
                        ${pcapBtn}
                        <button data-report-id="${escapeHtml(r.id)}" onclick="deleteAuditReport(this.dataset.reportId, event)" class="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-800/50 transition inline-flex items-center" title="Удалить отчет">
                            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
    updateSortIndicators('audits');
}

async function openAuditReportById(reportId) {
    try {
        const res = await fetch(`/api/audit/report/${reportId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const report = await res.json();
        // Ensure ID is present on report object
        if (!report.id) report.id = reportId;
        if (report.is_network || report.mac === 'NETWORK') {
            openNetworkAuditModal(report);
        } else {
            openAuditModal(report);
        }
    } catch (e) {
        alert(`Не удалось загрузить отчет: ${e.message}`);
    }
}

let currentModalReportId = null;

function openAuditModal(report) {
    const modal = document.getElementById('audit-detail-modal');
    if (!modal) return;

    currentModalReportId = report.id || null;
    const delBtn = document.getElementById('btn-delete-audit-modal');
    if (delBtn) {
        if (currentModalReportId) {
            delBtn.classList.remove('hidden');
        } else {
            delBtn.classList.add('hidden');
        }
    }

    // Header info
    const hostEl = document.getElementById('audit-modal-hostname');
    if (hostEl) hostEl.textContent = report.hostname || report.mac || 'Устройство';
    const ipMacEl = document.getElementById('audit-modal-ip-mac');
    if (ipMacEl) ipMacEl.textContent = `${report.ip || ''} (${report.mac || ''})`;

    // Risk badge
    const badge = document.getElementById('audit-modal-risk-badge');
    const iconContainer = document.getElementById('audit-modal-risk-icon');
    const risk = (report.overall_risk || report.risk_level || 'low').toLowerCase();

    if (badge && iconContainer) {
        if (risk === 'high' || risk === 'critical') {
            badge.className = 'px-2 py-0.5 rounded text-xs font-bold border bg-rose-500/20 text-rose-300 border-rose-500/40';
            badge.textContent = 'Высокий риск';
            iconContainer.className = 'p-2 rounded-xl bg-rose-500/20 text-rose-400';
        } else if (risk === 'medium' || risk === 'warning') {
            badge.className = 'px-2 py-0.5 rounded text-xs font-bold border bg-amber-500/20 text-amber-300 border-amber-500/40';
            badge.textContent = 'Внимание';
            iconContainer.className = 'p-2 rounded-xl bg-amber-500/20 text-amber-400';
        } else {
            badge.className = 'px-2 py-0.5 rounded text-xs font-bold border bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
            badge.textContent = 'Безопасно';
            iconContainer.className = 'p-2 rounded-xl bg-emerald-500/20 text-emerald-400';
        }
    }

    // Capture source badge
    const srcBadge = document.getElementById('audit-modal-capture-source');
    if (srcBadge) {
        if (report.capture_source === 'router_hardware') {
            srcBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30';
            srcBadge.textContent = '🛡️ Аппаратный дамп Keenetic (L3/L4 WAN)';
            srcBadge.title = 'Захват сетевых пакетов выполнен на встроенном сниффере ядра KeeneticOS';
            srcBadge.classList.remove('hidden');
        } else {
            srcBadge.className = 'px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700';
            srcBadge.textContent = '📡 Локальный срез эфира (L2 Broadcast)';
            srcBadge.title = 'Широковещательный срез локальной сетевой карты ПК';
            srcBadge.classList.remove('hidden');
        }
    }

    // Findings
    const findingsList = document.getElementById('audit-modal-findings');
    if (findingsList) {
        const rawFindings = report.findings || (report.summary ? [report.summary] : ['Подозрительной сетевой активности не выявлено.']);
        const findings = Array.isArray(rawFindings) ? rawFindings : [String(rawFindings)];
        findingsList.innerHTML = findings.map(f => `
            <li class="flex items-start space-x-2">
                <span class="text-cyan-400 mt-0.5 shrink-0">&bull;</span>
                <span>${escapeHtml(f)}</span>
            </li>
        `).join('');
    }

    // Metrics
    const durSec = report.duration_seconds || 0;
    const durEl = document.getElementById('audit-modal-duration');
    if (durEl) durEl.textContent = formatDuration(durSec);
    const pktEl = document.getElementById('audit-modal-packets');
    if (pktEl) pktEl.textContent = String((report.total_packets_up || 0) + (report.total_packets_down || 0) || report.total_packets || 0);
    const totalBytes = (report.total_bytes_up || 0) + (report.total_bytes_down || 0) || report.total_bytes || 0;
    const bytesEl = document.getElementById('audit-modal-bytes');
    if (bytesEl) bytesEl.textContent = formatBytes(totalBytes);

    // L7 Applications Breakdown
    const appsSection = document.getElementById('audit-modal-apps-section');
    const appsList = document.getElementById('audit-modal-apps-list');
    if (appsSection && appsList) {
        const apps = report.apps_breakdown || [];
        if (apps.length > 0) {
            appsSection.classList.remove('hidden');
            appsList.innerHTML = apps.map(app => `
                <div class="p-2.5 rounded-xl bg-surface-950 border border-slate-800/80 flex items-center justify-between shadow-sm">
                    <div class="flex items-center space-x-2 truncate">
                        <div class="w-6 h-6 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 shrink-0">
                            <i data-lucide="${escapeHtml(app.icon || 'activity')}" class="w-3.5 h-3.5"></i>
                        </div>
                        <div class="truncate">
                            <div class="text-xs font-semibold text-slate-200 truncate">${escapeHtml(app.name)}</div>
                            <div class="text-[10px] text-slate-500 font-mono">${formatBytes(app.bytes)}</div>
                        </div>
                    </div>
                    <span class="text-xs font-bold text-cyan-400 shrink-0 ml-2 font-mono">${app.percentage}%</span>
                </div>
            `).join('');
        } else {
            appsSection.classList.add('hidden');
        }
    }

    // Flows table
    currentAuditModalFlows = report.flows ? Object.values(report.flows) : [];
    const flowsCntEl = document.getElementById('audit-modal-flows-count');
    if (flowsCntEl) flowsCntEl.textContent = String(currentAuditModalFlows.length);
    const tblSumEl = document.getElementById('audit-modal-table-summary');
    if (tblSumEl) tblSumEl.textContent = `${currentAuditModalFlows.length} соединений`;
    renderAuditModalFlowsTable();
    updateSortIndicators('audit_modal');

    // HTTP Inspection section
    const httpSec = document.getElementById('audit-modal-http-section');
    const httpTbody = document.getElementById('audit-modal-http-tbody');
    const httpCntEl = document.getElementById('audit-modal-http-count');
    const httpList = report.http_inspections || [];
    if (httpSec && httpTbody) {
        if (httpList.length > 0) {
            httpSec.classList.remove('hidden');
            if (httpCntEl) httpCntEl.textContent = `${httpList.length} запросов`;
            httpTbody.innerHTML = httpList.map(h => `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-1.5 px-3 font-bold text-amber-400">${escapeHtml(h.method || 'GET')}</td>
                    <td class="py-1.5 px-3 font-semibold text-slate-200 truncate max-w-[160px]" title="${escapeHtml(h.host)}">${escapeHtml(h.host)}</td>
                    <td class="py-1.5 px-3 text-slate-400 truncate max-w-[200px]" title="${escapeHtml(h.path)}">${escapeHtml(h.path)}</td>
                    <td class="py-1.5 px-3 text-cyan-300">${escapeHtml(h.category || 'Веб')}</td>
                    <td class="py-1.5 px-3 text-slate-500 truncate max-w-[140px]" title="${escapeHtml(h.user_agent)}">${escapeHtml(h.user_agent || '—')}</td>
                </tr>
            `).join('');
        } else {
            httpSec.classList.add('hidden');
        }
    }

    // DNS queries
    const dnsSection = document.getElementById('audit-modal-dns-section');
    const dnsContainer = document.getElementById('audit-modal-dns-tags');
    const rawDns = report.dns_queries ? (Array.isArray(report.dns_queries) ? report.dns_queries : Object.values(report.dns_queries)) : [];
    const dnsList = rawDns.map(d => typeof d === 'string' ? d : (d && d.domain ? d.domain : '')).filter(Boolean);

    if (dnsSection && dnsContainer) {
        if (dnsList.length > 0) {
            dnsSection.classList.remove('hidden');
            dnsContainer.innerHTML = dnsList.map(dom => `
                <button data-domain="${escapeHtml(dom)}" onclick="openDomainModal(this.dataset.domain)" class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-cyan-200 border border-slate-700 hover:border-cyan-500/50 font-mono transition cursor-pointer group shadow-sm" title="Нажмите для анализа репутации и инструкции по блокировке">
                    <span>${escapeHtml(dom)}</span>
                    <i data-lucide="shield-alert" class="w-3 h-3 text-cyan-400 opacity-60 group-hover:opacity-100"></i>
                </button>
            `).join('');
        } else {
            dnsSection.classList.add('hidden');
        }
    }

    // PCAP file download button
    const pcapContainer = document.getElementById('audit-modal-pcap-container');
    const pcapFile = report.pcap_file || report.pcap_filename;
    if (pcapFile) {
        pcapContainer.innerHTML = `
            <a href="/api/audit/pcap/${encodeURIComponent(pcapFile)}" download="${escapeHtml(pcapFile)}" class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-md shadow-cyan-600/20">
                <i data-lucide="download" class="w-3.5 h-3.5"></i>
                <span>Скачать PCAP-дамп</span>
            </a>
        `;
    } else {
        pcapContainer.innerHTML = '';
    }

    modal.classList.remove('hidden');
    lucide.createIcons();
}

function sortAuditModalFlows(flows) {
    const { col, dir } = tableSortState.audit_modal;
    const mult = dir === 'asc' ? 1 : -1;

    return [...flows].sort((a, b) => {
        let cmp = 0;
        if (col === 'dst') {
            const dstA = `${a.dst_ip || ''}:${a.dst_port || ''}`;
            const dstB = `${b.dst_ip || ''}:${b.dst_port || ''}`;
            cmp = dstA.localeCompare(dstB);
        } else if (col === 'service') {
            const sA = a.service || a.protocol || '';
            const sB = b.service || b.protocol || '';
            cmp = sA.localeCompare(sB, 'ru');
        } else if (col === 'provider') {
            const pA = a.provider || a.country || '';
            const pB = b.provider || b.country || '';
            cmp = pA.localeCompare(pB, 'ru');
        } else if (col === 'encryption') {
            cmp = (a.is_encrypted ? 1 : 0) - (b.is_encrypted ? 1 : 0);
        } else if (col === 'bytes') {
            const bA = (a.bytes_up || 0) + (a.bytes_down || 0);
            const bB = (b.bytes_up || 0) + (b.bytes_down || 0);
            cmp = bA - bB;
        }
        return cmp * mult;
    });
}

function renderAuditModalFlowsTable() {
    const flowsTbody = document.getElementById('audit-modal-flows-tbody');
    if (!flowsTbody) return;

    if (!currentAuditModalFlows || currentAuditModalFlows.length === 0) {
        flowsTbody.innerHTML = '<tr><td colspan="5" class="py-4 text-center text-slate-500 italic">Сетевых соединений во время сессии не зафиксировано.</td></tr>';
        return;
    }

    const sorted = sortAuditModalFlows(currentAuditModalFlows);
    flowsTbody.innerHTML = sorted.map(fl => {
        const encBadge = fl.is_encrypted ?
            '<span class="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">TLS/Шифровано</span>' :
            '<span class="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-300 border border-amber-500/20">Открытый (HTTP/MQTT)</span>';

        const providerStr = fl.provider || `${fl.flag || '🌐'} ${fl.country || 'WAN'}`;
        const flowBytes = (fl.bytes_up || 0) + (fl.bytes_down || 0);
        const appBadge = fl.app_name ? `<span class="ml-2 px-1.5 py-0.5 rounded text-[10px] bg-cyan-950/70 text-cyan-300 border border-cyan-800/40">${escapeHtml(fl.app_name)}</span>` : '';

        return `
            <tr class="hover:bg-slate-900/50">
                <td class="py-2 px-3 font-mono text-slate-200">${fl.dst_ip}:${fl.dst_port}</td>
                <td class="py-2 px-3 text-slate-300">
                    <div class="flex items-center">
                        <span>${escapeHtml(fl.service || fl.protocol || 'TCP')}</span>
                        ${appBadge}
                    </div>
                </td>
                <td class="py-2 px-3 text-slate-300">${escapeHtml(providerStr)}</td>
                <td class="py-2 px-3">${encBadge}</td>
                <td class="py-2 px-3 text-right font-mono text-slate-300">${formatBytes(flowBytes)}</td>
            </tr>
        `;
    }).join('');
}

function closeAuditModal() {
    const modal = document.getElementById('audit-detail-modal');
    if (modal) modal.classList.add('hidden');
}

async function deleteAuditReport(reportId, ev) {
    if (ev) ev.stopPropagation();
    if (!reportId) return;
    if (!confirm('Удалить этот отчет аудита и соответствующий PCAP-дамп?')) return;

    try {
        const res = await fetch(`/api/audit/reports/${reportId}`, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        showToast('Отчет аудита успешно удален');
        await loadAuditReports();
    } catch (e) {
        console.error('Failed to delete audit report', e);
        showToast('Ошибка при удалении отчета', true);
    }
}

async function deleteCurrentAuditReport() {
    if (!currentModalReportId) return;
    if (!confirm('Удалить данный отчет аудита и соответствующий PCAP-дамп?')) return;

    try {
        const res = await fetch(`/api/audit/reports/${currentModalReportId}`, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        closeAuditModal();
        showToast('Отчет аудита успешно удален');
        await loadAuditReports();
    } catch (e) {
        console.error('Failed to delete current audit report', e);
        showToast('Ошибка при удалении отчета', true);
    }
}

// --- Network Audit Modal Functions ---
let currentNetworkAuditReportId = null;

function openNetworkAuditModal(report) {
    const modal = document.getElementById('network-audit-detail-modal');
    if (!modal) return;

    currentNetworkAuditReportId = report.id || null;
    const delBtn = document.getElementById('btn-delete-net-audit-modal');
    if (delBtn) {
        if (currentNetworkAuditReportId) {
            delBtn.classList.remove('hidden');
        } else {
            delBtn.classList.add('hidden');
        }
    }

    // Risk badge and icon
    const risk = (report.overall_risk || report.risk_level || 'low').toLowerCase();
    const badge = document.getElementById('net-audit-modal-risk-badge');
    const iconContainer = document.getElementById('net-audit-modal-risk-icon');

    if (risk === 'high' || risk === 'critical') {
        if (badge) {
            badge.className = 'px-2.5 py-0.5 rounded text-xs font-bold border bg-rose-500/20 text-rose-300 border-rose-500/40';
            badge.textContent = 'КРИТИЧЕСКИЙ РИСК';
        }
        if (iconContainer) iconContainer.className = 'p-2.5 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/30';
    } else if (risk === 'medium' || risk === 'warning') {
        if (badge) {
            badge.className = 'px-2.5 py-0.5 rounded text-xs font-bold border bg-amber-500/20 text-amber-300 border-amber-500/40';
            badge.textContent = 'ВНИМАНИЕ';
        }
        if (iconContainer) iconContainer.className = 'p-2.5 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/30';
    } else {
        if (badge) {
            badge.className = 'px-2.5 py-0.5 rounded text-xs font-bold border bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
            badge.textContent = 'БЕЗОПАСНО';
        }
        if (iconContainer) iconContainer.className = 'p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20';
    }

    // Subtitle
    const devCount = report.devices_analyzed || (report.top_devices ? report.top_devices.length : 0);
    const subElem = document.getElementById('net-audit-modal-subtitle');
    if (subElem) {
        subElem.textContent = `${report.scope_description || 'Анализ сетевого сегмента'} • Устройств: ${devCount}`;
    }

    // Metrics
    if (document.getElementById('net-audit-modal-duration')) {
        document.getElementById('net-audit-modal-duration').textContent = formatDuration(report.duration_seconds || 0);
    }
    if (document.getElementById('net-audit-modal-devices-count')) {
        document.getElementById('net-audit-modal-devices-count').textContent = String(devCount);
    }
    if (document.getElementById('net-audit-modal-flows-count')) {
        document.getElementById('net-audit-modal-flows-count').textContent = String(report.total_flows || 0);
    }
    if (document.getElementById('net-audit-modal-packets')) {
        document.getElementById('net-audit-modal-packets').textContent = String(report.total_packets || 0);
    }
    if (document.getElementById('net-audit-modal-bytes')) {
        document.getElementById('net-audit-modal-bytes').textContent = formatBytes(report.total_bytes || 0);
    }

    // Auto-Quarantined Suspicious Devices
    const qSec = document.getElementById('net-audit-modal-quarantined-section');
    const qList = document.getElementById('net-audit-modal-quarantined-list');
    const quarantined = report.quarantined_devices || [];
    if (quarantined.length > 0) {
        if (qSec) qSec.classList.remove('hidden');
        if (qList) {
            qList.innerHTML = quarantined.map(q => `
                <div class="p-2.5 rounded-lg bg-rose-950/70 border border-rose-700/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                        <div class="flex items-center space-x-2">
                            <span class="font-bold text-white">${escapeHtml(q.hostname || q.mac)}</span>
                            <span class="text-slate-400 font-mono text-[11px]">${escapeHtml(q.ip || 'no-ip')} &bull; ${escapeHtml(q.mac)}</span>
                        </div>
                        <div class="text-[11px] text-rose-300 mt-0.5">${escapeHtml(q.reason || 'Зафиксирована подозрительная сетевая активность')}</div>
                    </div>
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white shrink-0 shadow-sm">КАРАНТИН WAN (ИНТЕРНЕТ)</span>
                </div>
            `).join('');
        }
    } else {
        if (qSec) qSec.classList.add('hidden');
    }

    // Findings
    const findingsList = document.getElementById('net-audit-modal-findings');
    if (findingsList) {
        const rawFindings = report.findings || (report.summary ? [report.summary] : ['Подозрительной активности в сети не зафиксировано.']);
        const findings = Array.isArray(rawFindings) ? rawFindings : [String(rawFindings)];
        findingsList.innerHTML = findings.map(f => `
            <li class="flex items-start space-x-2">
                <span class="text-cyan-400 mt-0.5 shrink-0">&bull;</span>
                <span>${escapeHtml(f)}</span>
            </li>
        `).join('');
    }

    // L7 Applications Breakdown
    const netAppsSection = document.getElementById('net-audit-modal-apps-section');
    const netAppsList = document.getElementById('net-audit-modal-apps-list');
    if (netAppsSection && netAppsList) {
        const apps = report.apps_breakdown || [];
        if (apps.length > 0) {
            netAppsSection.classList.remove('hidden');
            netAppsList.innerHTML = apps.map(app => `
                <div class="p-2.5 rounded-xl bg-surface-950 border border-slate-800/80 flex items-center justify-between shadow-sm">
                    <div class="flex items-center space-x-2 truncate">
                        <div class="w-6 h-6 rounded-lg bg-cyan-500/10 flex items-center justify-center text-cyan-400 shrink-0">
                            <i data-lucide="${escapeHtml(app.icon || 'activity')}" class="w-3.5 h-3.5"></i>
                        </div>
                        <div class="truncate">
                            <div class="text-xs font-semibold text-slate-200 truncate">${escapeHtml(app.name)}</div>
                            <div class="text-[10px] text-slate-500 font-mono">${formatBytes(app.bytes)}</div>
                        </div>
                    </div>
                    <span class="text-xs font-bold text-cyan-400 shrink-0 ml-2 font-mono">${app.percentage}%</span>
                </div>
            `).join('');
        } else {
            netAppsSection.classList.add('hidden');
        }
    }

    // Lateral Movement (LAN-to-LAN connections)
    const lateralTbody = document.getElementById('net-audit-modal-lateral-tbody');
    if (lateralTbody) {
        const movements = report.lateral_movements || [];
        if (movements.length > 0) {
            lateralTbody.innerHTML = movements.map(lm => {
                let badge = '<span class="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700">Инфо</span>';
                if (lm.risk === 'critical') {
                    badge = '<span class="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">Критический</span>';
                } else if (lm.risk === 'warning') {
                    badge = '<span class="px-1.5 py-0.2 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30">Внимание</span>';
                }
                return `
                    <tr class="hover:bg-slate-900/50">
                        <td class="py-2 px-3 text-slate-200">${escapeHtml(lm.src_ip || '')}</td>
                        <td class="py-2 px-3 text-slate-200">${escapeHtml(lm.dst_ip || '')}</td>
                        <td class="py-2 px-3 text-slate-300">${lm.dst_port || lm.port || ''} (${escapeHtml(lm.service || lm.proto || 'TCP')})</td>
                        <td class="py-2 px-3 text-right">${badge}</td>
                    </tr>
                `;
            }).join('');
        } else {
            lateralTbody.innerHTML = '<tr><td colspan="4" class="py-3 text-center text-slate-500 text-xs italic">Внутренних подозрительных соединений не обнаружено</td></tr>';
        }
    }

    // Top active devices in network
    const devTbody = document.getElementById('net-audit-modal-devices-tbody');
    if (devTbody) {
        const topDevs = report.top_devices || [];
        if (topDevs.length > 0) {
            devTbody.innerHTML = topDevs.map(d => {
                const bytesStr = formatBytes(d.bytes || 0);
                const categoryBadge = `<span class="px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-mono">${escapeHtml(d.category || 'Устройство')}</span>`;
                const statusBadge = d.is_quarantined ?
                    '<span class="px-1.5 py-0.2 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">Изолирован</span>' :
                    '<span class="px-1.5 py-0.2 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Активен</span>';

                return `
                    <tr class="hover:bg-slate-900/50">
                        <td class="py-2 px-3">
                            <div class="font-medium text-slate-200">${escapeHtml(d.hostname || d.mac)}</div>
                            <div class="text-[11px] text-slate-400 font-mono">${escapeHtml(d.ip || '')} &bull; ${escapeHtml(d.mac || '')}</div>
                        </td>
                        <td class="py-2 px-3">${categoryBadge}</td>
                        <td class="py-2 px-3 text-center font-mono text-purple-400">${d.flows || 0}</td>
                        <td class="py-2 px-3 text-right font-mono text-emerald-400">${bytesStr}</td>
                        <td class="py-2 px-3 text-right">${statusBadge}</td>
                    </tr>
                `;
            }).join('');
        } else {
            devTbody.innerHTML = '<tr><td colspan="5" class="py-3 text-center text-slate-500 text-xs italic">Нет данных об активности устройств</td></tr>';
        }
    }

    // Cloud Providers & GeoIP
    const provList = document.getElementById('net-audit-modal-providers-list');
    if (provList) {
        const providers = report.cloud_providers || [];
        if (providers.length > 0) {
            provList.innerHTML = providers.map(cp => {
                const provName = typeof cp === 'object' ? (cp.name || cp.provider || JSON.stringify(cp)) : String(cp);
                return `
                    <span class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs bg-surface-900 border border-slate-800 text-cyan-300">
                        <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                        <span class="font-medium">${escapeHtml(provName)}</span>
                        ${cp.flows ? `<span class="text-[10px] text-slate-500 font-mono">(${cp.flows} соед.)</span>` : ''}
                    </span>
                `;
            }).join('');
        } else {
            provList.innerHTML = '<span class="text-xs text-slate-500 italic">Облачные сервисы не зафиксированы</span>';
        }
    }

    // PCAP download button
    const pcapCont = document.getElementById('net-audit-modal-pcap-container');
    const pcapFile = report.pcap_file || report.pcap_filename;
    if (pcapCont) {
        if (pcapFile) {
            pcapCont.innerHTML = `
                <a href="/api/audit/pcap/${encodeURIComponent(pcapFile)}" download="${escapeHtml(pcapFile)}" class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-md shadow-cyan-600/20">
                    <i data-lucide="download" class="w-3.5 h-3.5"></i>
                    <span>Скачать сетевой PCAP-дамп</span>
                </a>
            `;
        } else {
            pcapCont.innerHTML = '';
        }
    }

    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeNetworkAuditModal() {
    const modal = document.getElementById('network-audit-detail-modal');
    if (modal) modal.classList.add('hidden');
}

async function deleteCurrentNetworkAuditReport() {
    if (!currentNetworkAuditReportId) return;
    if (!confirm('Удалить данный сетевой отчет аудита и соответствующий PCAP-дамп?')) return;

    try {
        const res = await fetch(`/api/audit/reports/${currentNetworkAuditReportId}`, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        closeNetworkAuditModal();
        showToast('Отчет аудита сети успешно удален');
        await loadAuditReports();
    } catch (e) {
        console.error('Failed to delete current network audit report', e);
        showToast('Ошибка при удалении отчета', true);
    }
}

function openClearAuditsModal() {
    const modal = document.getElementById('clear-audits-modal');
    if (modal) {
        const rAll = document.getElementById('clear-audits-scope-all');
        if (rAll) rAll.checked = true;
        modal.classList.remove('hidden');
        lucide.createIcons();
    }
}

function closeClearAuditsModal() {
    const modal = document.getElementById('clear-audits-modal');
    if (modal) modal.classList.add('hidden');
}

async function executeClearAudits() {
    const btn = document.getElementById('btn-confirm-clear-audits');
    const is7d = document.getElementById('clear-audits-scope-7d')?.checked;
    const url = is7d ? '/api/audit/reports?older_than_days=7' : '/api/audit/reports';

    if (btn) btn.disabled = true;
    try {
        const res = await fetch(url, {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        closeClearAuditsModal();
        showToast(`Архив аудитов очищен (удалено: ${data.deleted || 0})`);
        await loadAuditReports();
    } catch (e) {
        console.error('Failed to clear audit reports', e);
        showToast('Ошибка при очистке архива аудитов', true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

function openClearOfflineModal() {
    const modal = document.getElementById('clear-offline-devices-modal');
    if (modal) {
        modal.classList.remove('hidden');
        if (window.lucide) lucide.createIcons();
    }
}

function closeClearOfflineModal() {
    const modal = document.getElementById('clear-offline-devices-modal');
    if (modal) modal.classList.add('hidden');
}

async function confirmClearOfflineDevices() {
    try {
        const res = await fetch('/api/devices-offline', {
            method: 'DELETE'
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        closeClearOfflineModal();
        showToast(`Удалено неактивных записей: ${data.deleted_count || 0}`);
        await loadDevices();
    } catch (e) {
        console.error('Failed to clear offline devices', e);
        showToast('Ошибка при удалении офлайн-устройств', true);
    }
}

