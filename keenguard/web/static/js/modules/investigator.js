// ==========================================
// Incident Investigation Wizard (Frontend Logic)
// ==========================================
let currentInvestigationReport = null;
let currentInvestigationParams = null;
let investigatorIncidentsList = [];
let investigatorDevicesList = [];
let pendingInvestigatorTarget = null;

async function loadInvestigatorTab() {
    await loadInvestigatorIncidents();
}
window.loadInvestigatorTab = loadInvestigatorTab;

async function loadInvestigatorIncidents() {
    const select = document.getElementById('investigator-incident-select');
    if (!select) return;

    try {
        const res = await fetch('/api/investigator/incidents');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        investigatorIncidentsList = data.incidents || [];
        investigatorDevicesList = data.devices || [];

        let html = '<option value="">— Выберите аудит, инцидент или активное устройство —</option>';

        const audits = investigatorIncidentsList.filter(i => i.type === 'audit');
        if (audits.length > 0) {
            html += '<optgroup label="📊 Завершенные аудиты сетевого трафика">';
            audits.forEach(a => {
                const dateStr = a.created_at ? new Date(a.created_at).toLocaleString('ru-RU') : '';
                html += `<option value="audit:${a.id}">Аудит: ${escapeHtml(a.hostname || a.mac)} (${(a.risk_level || 'low').toUpperCase()}) — ${dateStr}</option>`;
            });
            html += '</optgroup>';
        }

        const events = investigatorIncidentsList.filter(i => i.type === 'event');
        if (events.length > 0) {
            html += '<optgroup label="🚨 События безопасности (Предупреждения / Критические)">';
            events.forEach(e => {
                html += `<option value="event:${e.event_id}">${escapeHtml(e.title)}</option>`;
            });
            html += '</optgroup>';
        }

        if (investigatorDevicesList.length > 0) {
            html += '<optgroup label="💻 Активные клиенты сети (Анализ хоста)">';
            investigatorDevicesList.forEach(d => {
                const name = d.hostname || d.ip || d.mac;
                html += `<option value="device:${d.mac}">${escapeHtml(name)} (${d.ip || 'Нет IP'}) [${escapeHtml(d.vendor || 'Unknown')}]</option>`;
            });
            html += '</optgroup>';
        }

        const currentVal = select.value;
        select.innerHTML = html;

        if (pendingInvestigatorTarget) {
            select.value = pendingInvestigatorTarget;
            pendingInvestigatorTarget = null;
            await onInvestigatorSelectChange();
        } else if (currentVal && select.querySelector(`option[value="${currentVal}"]`)) {
            select.value = currentVal;
        }
    } catch (e) {
        console.error('Failed to load investigator incidents', e);
        select.innerHTML = '<option value="">— Инцидентов или аудитов для анализа не выбрано —</option>';
    }
}
window.loadInvestigatorIncidents = loadInvestigatorIncidents;

async function onInvestigatorSelectChange() {
    const select = document.getElementById('investigator-incident-select');
    if (!select || !select.value) return;

    const val = select.value;
    const osSelect = document.getElementById('investigator-select-os');
    const osVal = (osSelect && osSelect.value !== 'auto') ? osSelect.value : undefined;

    let params = {};
    if (val.startsWith('audit:')) {
        params = { audit_id: val.replace('audit:', ''), target_os: osVal };
    } else if (val.startsWith('event:')) {
        params = { event_id: parseInt(val.replace('event:', ''), 10), target_os: osVal };
    } else if (val.startsWith('device:')) {
        params = { mac: val.replace('device:', ''), target_os: osVal };
    }

    await runInvestigation(params);
}
window.onInvestigatorSelectChange = onInvestigatorSelectChange;

async function onInvestigatorOsChange() {
    if (!currentInvestigationParams) return;
    const osSelect = document.getElementById('investigator-select-os');
    const osVal = osSelect ? osSelect.value : 'auto';
    currentInvestigationParams.target_os = (osVal !== 'auto') ? osVal : undefined;
    await runInvestigation(currentInvestigationParams);
}
window.onInvestigatorOsChange = onInvestigatorOsChange;

async function startInvestigatorManualRun() {
    const input = document.getElementById('investigator-manual-ip');
    const target = input ? input.value.trim() : '';
    if (!target) {
        alert('Пожалуйста, введите IP-адрес или домен для расследования!');
        return;
    }

    const osSelect = document.getElementById('investigator-select-os');
    const osVal = (osSelect && osSelect.value !== 'auto') ? osSelect.value : undefined;

    const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
    const params = {
        target_ip: isIp ? target : undefined,
        target_domain: !isIp ? target : undefined,
        target_os: osVal
    };

    await runInvestigation(params);
}
window.startInvestigatorManualRun = startInvestigatorManualRun;

async function runInvestigation(params) {
    currentInvestigationParams = { ...params };
    const loadingEl = document.getElementById('investigator-loading');
    const emptyEl = document.getElementById('investigator-empty');
    const reportEl = document.getElementById('investigator-report');

    if (loadingEl) loadingEl.classList.remove('hidden');
    if (emptyEl) emptyEl.classList.add('hidden');
    if (reportEl) reportEl.classList.add('hidden');

    try {
        const res = await fetch('/api/investigator/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        renderInvestigationReport(data.investigation);
    } catch (e) {
        console.error('Investigation analysis error', e);
        alert(`Ошибка анализа: ${e.message}`);
        if (loadingEl) loadingEl.classList.add('hidden');
        if (emptyEl) emptyEl.classList.remove('hidden');
    }
}
window.runInvestigation = runInvestigation;

function renderInvestigationReport(rep) {
    currentInvestigationReport = rep;
    const loadingEl = document.getElementById('investigator-loading');
    const emptyEl = document.getElementById('investigator-empty');
    const reportEl = document.getElementById('investigator-report');

    if (loadingEl) loadingEl.classList.add('hidden');
    if (emptyEl) emptyEl.classList.add('hidden');
    if (reportEl) reportEl.classList.remove('hidden');

    // Sync selector with active target
    const select = document.getElementById('investigator-incident-select');
    const target = rep.target || {};
    if (select) {
        if (rep.audit_id && select.querySelector(`option[value="audit:${rep.audit_id}"]`)) {
            select.value = `audit:${rep.audit_id}`;
        } else if (rep.event_id && select.querySelector(`option[value="event:${rep.event_id}"]`)) {
            select.value = `event:${rep.event_id}`;
        } else if (target.mac && select.querySelector(`option[value="device:${target.mac}"]`)) {
            select.value = `device:${target.mac}`;
        }
    }

    // 1. Target Device Banner
    const nameEl = document.getElementById('investigator-target-name');
    if (nameEl) nameEl.textContent = target.hostname || target.ip || target.mac || 'Целевой узел';

    const metaEl = document.getElementById('investigator-target-meta');
    if (metaEl) {
        metaEl.textContent = `IP: ${target.ip || '—'} • MAC: ${target.mac || '—'} • Вендор: ${target.vendor || 'Не указан'} • Профиль: ${target.profile || 'unassigned'} • ОС: ${rep.playbook?.os_name || target.os_type}`;
    }

    const badgeEl = document.getElementById('investigator-target-badge');
    const status = (typeof rep.verdict === 'object' && rep.verdict?.status) ? rep.verdict.status : (rep.severity || 'safe');
    if (badgeEl) {
        if (status === 'critical') {
            badgeEl.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30';
            badgeEl.textContent = 'КРИТИЧЕСКИЙ РИСК';
        } else if (status === 'warning') {
            badgeEl.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30';
            badgeEl.textContent = 'ПРЕДУПРЕЖДЕНИЕ';
        } else {
            badgeEl.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
            badgeEl.textContent = 'БЕЗОПАСНО';
        }
    }

    const verdictEl = document.getElementById('investigator-verdict-title');
    if (verdictEl) {
        const verdictSummary = (typeof rep.verdict === 'object' && rep.verdict?.summary) ?
            rep.verdict.summary :
            (typeof rep.verdict === 'string' ? rep.verdict : 'Штатная активность');
        verdictEl.textContent = verdictSummary;
    }

    const findingsContainer = document.getElementById('investigator-findings-list');
    if (findingsContainer) {
        const findingsList = (typeof rep.verdict === 'object' && rep.verdict?.findings) ?
            rep.verdict.findings :
            (rep.findings || []);
        findingsContainer.innerHTML = findingsList.map(f => `
            <div class="flex items-start space-x-2">
                <span class="text-indigo-400 font-bold shrink-0">•</span>
                <span>${escapeHtml(f)}</span>
            </div>
        `).join('');
    }

    // Set Target Icon based on OS type
    const iconEl = document.getElementById('investigator-target-icon');
    if (iconEl) {
        let iconName = 'laptop';
        if (target.os_type === 'linux') iconName = 'terminal';
        else if (target.os_type === 'android' || target.os_type === 'ios') iconName = 'smartphone';
        else if (target.os_type === 'smart_tv') iconName = 'tv';
        else if (target.os_type === 'iot') iconName = 'cpu';
        iconEl.setAttribute('data-lucide', iconName);
    }

    // 2. STEP 1: Flows and Correlated DNS Table
    const countEl = document.getElementById('investigator-flows-count');
    if (countEl) countEl.textContent = `${rep.flows_count || 0} соединений`;

    const flowsTbody = document.getElementById('investigator-flows-tbody');
    if (flowsTbody) {
        const flows = rep.flows || [];
        if (flows.length === 0) {
            flowsTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-8 px-4 text-center">
                        <div class="max-w-md mx-auto space-y-2.5">
                            <div class="text-slate-300 text-xs font-bold">Для устройства нет сохраненных сессий аудита потоков</div>
                            <p class="text-[11px] text-slate-400 leading-relaxed">
                                Пакетный сниффер еще не инспектировал сетевой трафик этого узла. Запустите 1-минутный экспресс-аудит или укажите внешний IP/домен вручную для анализа.
                            </p>
                            ${target.mac ? `
                                <div class="pt-2 flex items-center justify-center">
                                    <button type="button" onclick="openDeviceAuditModal('${escapeHtml(target.mac)}', '${escapeHtml(target.ip || '')}')" class="px-3.5 py-1.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow transition flex items-center space-x-1.5">
                                        <i data-lucide="play" class="w-3.5 h-3.5"></i>
                                        <span>Запустить экспресс-аудит (1 мин)</span>
                                    </button>
                                </div>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        } else {
            flowsTbody.innerHTML = flows.map(f => {
                const encBadge = f.is_encrypted ?
                    '<span class="text-emerald-400 font-medium flex items-center space-x-1"><i data-lucide="lock" class="w-3 h-3"></i><span>TLS/SSL</span></span>' :
                    (f.dst_port === 80 || f.dst_port === 1883 ?
                        '<span class="text-amber-400 font-medium flex items-center space-x-1"><i data-lucide="unlock" class="w-3 h-3"></i><span>Открытый (HTTP/MQTT)</span></span>' :
                        '<span class="text-slate-400 font-medium">Открытый</span>');

                let riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">Безопасно</span>';
                if (f.flow_risk === 'critical') {
                    riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">Критично</span>';
                } else if (f.flow_risk === 'warning') {
                    riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30 font-bold">Внимание</span>';
                } else if (f.flow_risk === 'advisory') {
                    riskBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-sky-500/20 text-sky-300 border border-sky-500/30 font-bold">Инфо</span>';
                }

                const domHtml = f.correlated_domain ?
                    `<div class="font-mono text-cyan-300 font-semibold flex items-center space-x-1"><i data-lucide="globe" class="w-3 h-3 text-cyan-400"></i><span>${escapeHtml(f.correlated_domain)}</span></div><div class="text-[10px] text-slate-500">Сопоставлено через DNS роутера</div>` :
                    `<div class="font-mono text-slate-400">Прямое обращение по IP</div>`;

                const links = f.intel_links || {};
                return `
                    <tr class="hover:bg-slate-800/30 transition">
                        <td class="py-2.5 px-3 font-mono font-bold text-slate-200">${f.dst_ip}:${f.dst_port}</td>
                        <td class="py-2.5 px-3">${domHtml}</td>
                        <td class="py-2.5 px-3">${encBadge}</td>
                        <td class="py-2.5 px-3">
                            <div class="font-medium text-slate-200">${escapeHtml(f.flow_verdict)}</div>
                            ${f.system_description ? `<div class="text-[10px] text-slate-400">${escapeHtml(f.system_description)}</div>` : ''}
                        </td>
                        <td class="py-2.5 px-3">${riskBadge}</td>
                        <td class="py-2.5 px-3 text-right">
                            <div class="flex items-center justify-end space-x-1.5">
                                ${links.virustotal ? `<a href="${links.virustotal}" target="_blank" rel="noopener noreferrer" class="px-2 py-1 rounded text-[10px] bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 border border-indigo-800/50 transition inline-flex items-center space-x-1" title="Проверить в VirusTotal"><span>VT</span><i data-lucide="external-link" class="w-2.5 h-2.5"></i></a>` : ''}
                                ${links.abuseipdb ? `<a href="${links.abuseipdb}" target="_blank" rel="noopener noreferrer" class="px-2 py-1 rounded text-[10px] bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-800/50 transition inline-flex items-center space-x-1" title="Проверить в AbuseIPDB"><span>Abuse</span><i data-lucide="external-link" class="w-2.5 h-2.5"></i></a>` : ''}
                                ${links.ipinfo ? `<a href="${links.ipinfo}" target="_blank" rel="noopener noreferrer" class="px-2 py-1 rounded text-[10px] bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition inline-flex items-center space-x-1" title="Геолокация и ASN в IPinfo"><span>IP</span><i data-lucide="external-link" class="w-2.5 h-2.5"></i></a>` : ''}
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    }

    // 3. STEP 2: Threat Intelligence Cards Grid
    const intelContainer = document.getElementById('investigator-intel-cards-container');
    if (intelContainer) {
        const flows = rep.flows || [];
        const seenHosts = new Set();
        const cards = [];

        flows.forEach(f => {
            const hostKey = f.correlated_domain || f.dst_ip;
            if (!hostKey || hostKey === '0.0.0.0' || hostKey === '127.0.0.1' || seenHosts.has(hostKey)) return;
            seenHosts.add(hostKey);

            const links = f.intel_links || {};
            const domLinks = f.domain_intel_links || {};

            cards.push(`
                <div class="p-4 rounded-xl bg-surface-950 border border-slate-800 space-y-3 shadow-sm hover:border-slate-700 transition">
                    <div class="flex items-start justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                        <div>
                            <h4 class="font-mono font-bold text-sm text-cyan-300 truncate max-w-[240px]" title="${escapeHtml(hostKey)}">${escapeHtml(hostKey)}</h4>
                            <p class="text-[11px] text-slate-400 font-mono mt-0.5">${f.dst_ip} • ${escapeHtml(f.provider || 'Внешний хост')}</p>
                        </div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-900 text-slate-400 border border-slate-800 shrink-0">Порт ${f.dst_port}</span>
                    </div>

                    <div class="flex flex-wrap gap-2 pt-1">
                        ${links.virustotal ? `<a href="${links.virustotal}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg text-xs font-medium bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/30 transition flex items-center space-x-1.5"><i data-lucide="shield-check" class="w-3.5 h-3.5 text-indigo-400"></i><span>VirusTotal</span></a>` : ''}
                        ${links.abuseipdb ? `<a href="${links.abuseipdb}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg text-xs font-medium bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 transition flex items-center space-x-1.5"><i data-lucide="alert-triangle" class="w-3.5 h-3.5 text-rose-400"></i><span>AbuseIPDB</span></a>` : ''}
                        ${links.ipinfo ? `<a href="${links.ipinfo}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center space-x-1.5"><i data-lucide="map-pin" class="w-3.5 h-3.5 text-cyan-400"></i><span>IPinfo (Гео)</span></a>` : ''}
                        ${links.cisco_talos ? `<a href="${links.cisco_talos}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center space-x-1.5"><i data-lucide="activity" class="w-3.5 h-3.5 text-emerald-400"></i><span>Cisco Talos</span></a>` : ''}
                        ${domLinks.whois ? `<a href="${domLinks.whois}" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center space-x-1.5"><i data-lucide="info" class="w-3.5 h-3.5 text-amber-400"></i><span>WHOIS</span></a>` : ''}
                    </div>
                </div>
            `);
        });

        if (cards.length === 0) {
            if (rep.recent_dns && rep.recent_dns.length > 0) {
                const dnsItems = rep.recent_dns.slice(0, 8).map(d => `
                    <button type="button" onclick="document.getElementById('investigator-manual-ip').value='${escapeHtml(d.domain)}'; startInvestigatorManualRun();" class="p-2.5 rounded-xl bg-surface-950 border border-slate-800 hover:border-indigo-500/50 text-left transition space-y-1">
                        <div class="font-mono text-xs font-bold text-cyan-300 truncate">${escapeHtml(d.domain)}</div>
                        <div class="text-[10px] text-slate-400 font-mono">${escapeHtml(d.ip || 'DNS-запрос')} • ${d.last_seen ? new Date(d.last_seen).toLocaleTimeString('ru-RU') : ''}</div>
                        <div class="text-[10px] text-indigo-400 flex items-center space-x-1 pt-0.5">
                            <i data-lucide="search" class="w-2.5 h-2.5"></i>
                            <span>Расследовать этот домен</span>
                        </div>
                    </button>
                `).join('');
                intelContainer.innerHTML = `
                    <div class="col-span-2 space-y-2">
                        <div class="text-xs font-bold text-slate-300 flex items-center space-x-2">
                            <i data-lucide="history" class="w-3.5 h-3.5 text-indigo-400"></i>
                            <span>Недавние обращения устройства (из журнала DNS роутера):</span>
                        </div>
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            ${dnsItems}
                        </div>
                    </div>
                `;
            } else {
                intelContainer.innerHTML = '<div class="col-span-2 text-center text-slate-500 text-xs py-4">Внешних адресов для анализа не обнаружено.</div>';
            }
        } else {
            intelContainer.innerHTML = cards.join('');
        }
    }

    // 4. STEP 3: Local OS Diagnostic Playbook
    renderPlaybookContent(rep.playbook, rep.target?.os_type);

    // 5. STEP 4: Technical Caveats & Remediation
    const caveatsContainer = document.getElementById('investigator-caveats-container');
    if (caveatsContainer) {
        const caveats = rep.caveats || [];
        caveatsContainer.innerHTML = caveats.map(c => {
            const desc = c.description || c.text || '';
            const isCrit = (c.severity === 'critical' || c.level === 'critical');
            const isWarn = (c.severity === 'warning' || c.level === 'warning');
            const bgBorder = isCrit ? 'bg-rose-950/30 border-rose-500/30 text-rose-200' :
                             (isWarn ? 'bg-amber-950/30 border-amber-500/30 text-amber-200' : 'bg-surface-950 border-slate-800 text-slate-300');
            const iconColor = isCrit ? 'text-rose-400' : (isWarn ? 'text-amber-400' : 'text-cyan-400');

            return `
                <div class="p-4 rounded-xl border ${bgBorder} space-y-2">
                    <div class="flex items-center space-x-2">
                        <i data-lucide="${escapeHtml(c.icon || 'alert-triangle')}" class="w-4 h-4 ${iconColor} shrink-0"></i>
                        <h4 class="font-bold text-xs ${iconColor}">${escapeHtml(c.title)}</h4>
                    </div>
                    <p class="text-xs text-slate-300 leading-relaxed">${escapeHtml(desc)}</p>
                    ${c.recommendation ? `
                        <div class="text-[11px] p-2 rounded-lg bg-surface-900/80 border border-slate-800 font-medium text-slate-200">
                            👉 <b>Что делать:</b> ${escapeHtml(c.recommendation)}
                        </div>
                    ` : ''}
                </div>
            `;
        }).join('');
    }

    // 6. STEP 4 Action 2: Keenetic Device Security Profile & WAN/LAN Actions
    const devStatusEl = document.getElementById('investigator-device-current-status');
    const devButtonsEl = document.getElementById('investigator-device-buttons');
    if (devStatusEl && devButtonsEl) {
        const target = rep.target;
        if (target && target.mac) {
            const wanBadge = target.is_blocked_wan ? 
                '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">Интернет (WAN) ЗАБЛОКИРОВАН</span>' : 
                '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Интернет (WAN) РАЗРЕШЕН</span>';
            const lanBadge = target.is_isolated ?
                '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">LAN Изолирован</span>' :
                '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300 border border-slate-700">LAN Общий</span>';

            devStatusEl.innerHTML = `
                <div class="flex items-center justify-between">
                    <span class="text-slate-400">Устройство:</span>
                    <span class="text-white font-bold">${escapeHtml(target.hostname || 'Клиент')}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-slate-400">MAC / Сегмент:</span>
                    <span class="text-cyan-300">${escapeHtml(target.mac)} • ${escapeHtml(target.segment || 'Bridge0')}</span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-slate-400">Профиль:</span>
                    <span class="text-indigo-300 font-bold uppercase">${escapeHtml(target.profile || 'unassigned')}</span>
                </div>
                <div class="flex items-center justify-between pt-1">
                    <span class="text-slate-400">Статус сети:</span>
                    <div class="flex space-x-1.5">${wanBadge} ${lanBadge}</div>
                </div>
            `;

            let buttonsHtml = '';
            const isSmartTv = (target.os_type === 'smart_tv' || target.os_type === 'webos' || target.os_type === 'tizen' || target.profile === 'smart_tv');

            if (isSmartTv) {
                if (target.profile !== 'smart_tv') {
                    buttonsHtml += `
                        <button type="button" onclick="applyInvestigatorProfile('${escapeHtml(target.mac)}', 'smart_tv')" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="tv" class="w-4 h-4"></i>
                            <span>Назначить профиль Smart TV</span>
                        </button>
                    `;
                }
                if (target.is_blocked_wan) {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', false)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="globe" class="w-4 h-4"></i>
                            <span>Разблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                } else {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', true)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="shield-ban" class="w-4 h-4"></i>
                            <span>Заблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                }
            } else if (target.os_type === 'iot') {
                if (target.profile !== 'iot') {
                    buttonsHtml += `
                        <button type="button" onclick="applyInvestigatorProfile('${escapeHtml(target.mac)}', 'iot')" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="cpu" class="w-4 h-4"></i>
                            <span>Назначить профиль IoT</span>
                        </button>
                    `;
                }
                if (target.is_blocked_wan) {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', false)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="globe" class="w-4 h-4"></i>
                            <span>Разблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                } else {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', true)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="shield-ban" class="w-4 h-4"></i>
                            <span>Заблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                }
            } else {
                if (target.is_blocked_wan) {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', false)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-emerald-700 hover:bg-emerald-600 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="globe" class="w-4 h-4"></i>
                            <span>Разблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                } else {
                    buttonsHtml += `
                        <button type="button" onclick="toggleInvestigatorWan('${escapeHtml(target.mac)}', true)" class="w-full px-3.5 py-2 rounded-xl text-xs font-semibold bg-rose-600 hover:bg-rose-500 text-white transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="shield-ban" class="w-4 h-4"></i>
                            <span>Заблокировать выход в интернет (WAN)</span>
                        </button>
                    `;
                }
                if (target.profile !== 'trusted') {
                    buttonsHtml += `
                        <button type="button" onclick="applyInvestigatorProfile('${escapeHtml(target.mac)}', 'trusted')" class="w-full px-3.5 py-2 rounded-xl text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition flex items-center justify-center space-x-2 shadow-sm">
                            <i data-lucide="check" class="w-4 h-4 text-emerald-400"></i>
                            <span>Назначить профиль «Доверенный»</span>
                        </button>
                    `;
                }
            }

            devButtonsEl.innerHTML = buttonsHtml;
        } else {
            devStatusEl.innerHTML = '<span class="text-slate-500 text-xs">Анализ отдельного IP-адреса без привязки к локальному MAC-адресу роутера.</span>';
            devButtonsEl.innerHTML = '<p class="text-[11px] text-slate-500 italic">Выберите устройство из выпадающего списка сверху, чтобы применить политики межсетевого экрана Keenetic.</p>';
        }
    }

    // Helper to test if a domain candidate is a valid blockable external FQDN (never an IP, never router)
    function isBlockableDomainCandidate(d) {
        if (!d || typeof d !== 'string') return false;
        const clean = d.trim().toLowerCase();
        if (!clean || !clean.includes('.')) return false;
        // Never allow IPv4 or IPv6
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':')) return false;
        // Never allow localhost or router management domains
        if (clean === 'localhost' || clean === 'my.keenetic.net' || clean === 'keenetic.net' || clean === 'router') return false;
        if (clean.endsWith('.keenetic.link') || clean.endsWith('.keenetic.pro') || clean.endsWith('.local') || clean.endsWith('.lan') || clean.endsWith('.home')) return false;
        // Basic domain characters check
        if (!/^[a-z0-9](?:[a-z0-9\-\._]*[a-z0-9])?$/.test(clean)) return false;
        return true;
    }

    // Helper to test if an IP candidate is a valid blockable external IPv4 (never private/LAN/multicast/loopback)
    function isBlockableIpCandidate(ip) {
        if (!ip || typeof ip !== 'string') return false;
        const clean = ip.trim();
        const match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
        if (!match) return false;
        const octets = match.slice(1).map(Number);
        if (octets.some(o => o > 255)) return false;
        const [a, b] = octets;
        if (a === 0 || a === 127) return false;
        if (a === 10) return false;
        if (a === 172 && b >= 16 && b <= 31) return false;
        if (a === 192 && b === 168) return false;
        if (a === 169 && b === 254) return false;
        if (a >= 224) return false;
        return true;
    }

    // Pre-fill block domain input ONLY with valid external domain names (NEVER IP addresses or router gateway)
    const blockInput = document.getElementById('investigator-block-input');
    if (blockInput) {
        blockInput.value = ''; // Default to empty so user sees placeholder
        const suspiciousFlow = (rep.flows || []).find(f => (f.flow_risk === 'warning' || f.flow_risk === 'critical') && isBlockableDomainCandidate(f.correlated_domain));
        if (suspiciousFlow && isBlockableDomainCandidate(suspiciousFlow.correlated_domain)) {
            blockInput.value = suspiciousFlow.correlated_domain;
        } else {
            const anyValidFlow = (rep.flows || []).find(f => isBlockableDomainCandidate(f.correlated_domain));
            if (anyValidFlow && isBlockableDomainCandidate(anyValidFlow.correlated_domain)) {
                blockInput.value = anyValidFlow.correlated_domain;
            } else if (rep.recent_dns && rep.recent_dns.length > 0) {
                const validDns = rep.recent_dns.find(d => isBlockableDomainCandidate(d.domain));
                if (validDns && isBlockableDomainCandidate(validDns.domain)) {
                    blockInput.value = validDns.domain;
                }
            }
        }
    }

    const statusEl = document.getElementById('investigator-block-status');
    if (statusEl) statusEl.classList.add('hidden');

    // Pre-fill block IP input ONLY with valid external IPv4 addresses (NEVER private/LAN/gateway)
    const ipBlockInput = document.getElementById('investigator-ip-block-input');
    if (ipBlockInput) {
        ipBlockInput.value = '';
        const suspIpFlow = (rep.flows || []).find(f => (f.flow_risk === 'warning' || f.flow_risk === 'critical') && isBlockableIpCandidate(f.remote_ip));
        if (suspIpFlow) {
            ipBlockInput.value = suspIpFlow.remote_ip;
        } else {
            const anyValidIpFlow = (rep.flows || []).find(f => isBlockableIpCandidate(f.remote_ip));
            if (anyValidIpFlow) {
                ipBlockInput.value = anyValidIpFlow.remote_ip;
            }
        }
    }

    const ipStatusEl = document.getElementById('investigator-ip-block-status');
    if (ipStatusEl) ipStatusEl.classList.add('hidden');

    if (window.lucide) lucide.createIcons();
}

function renderPlaybookContent(playbook, activeOs) {
    // Dynamic Step 3 Header & Subtitle
    const titleEl = document.getElementById('investigator-step3-title');
    const subtitleEl = document.getElementById('investigator-step3-subtitle');
    if (titleEl && subtitleEl) {
        if (activeOs === 'smart_tv' || activeOs === 'webos' || activeOs === 'tizen') {
            titleEl.textContent = 'Действия на ТВ («Кто инициирует трафик и как отключить слежку?»)';
            subtitleEl.textContent = 'Пошаговые инструкции для меню Smart TV: отключение ACR, отзыв согласий и режим ожидания (Standby)';
        } else if (activeOs === 'android' || activeOs === 'ios') {
            titleEl.textContent = 'Диагностика на смартфоне («Какое приложение шлет трафик?»)';
            subtitleEl.textContent = 'Встроенный аудит сетевой активности приложений и проверка обхода через Private DNS (DoT)';
        } else if (activeOs === 'iot') {
            titleEl.textContent = 'Диагностика умного устройства («Проверка интеграций и облаков»)';
            subtitleEl.textContent = 'Анализ фирменного мобильного приложения вендора и сетевого поведения хабов/датчиков';
        } else {
            titleEl.textContent = 'Локальная диагностика («Какая программа это делает?»)';
            subtitleEl.textContent = 'Готовые команды и инструкции для точного определения процесса на целевом устройстве';
        }
    }

    // Update OS switcher button styles
    const tabs = ['windows', 'linux', 'macos', 'android', 'ios', 'smart_tv', 'iot'];
    tabs.forEach(t => {
        const btn = document.getElementById(`inv-os-tab-${t}`);
        if (!btn) return;
        if (t === activeOs) {
            btn.className = 'px-2.5 py-1 rounded-lg text-xs font-bold transition bg-indigo-600 text-white shadow-sm';
        } else {
            btn.className = 'px-2.5 py-1 rounded-lg text-xs font-medium transition text-slate-400 hover:text-white';
        }
    });

    const container = document.getElementById('investigator-playbook-content');
    if (!container || !playbook) return;

    const steps = playbook.steps || [];
    container.innerHTML = steps.map((s, idx) => `
        <div class="p-4 rounded-xl bg-surface-950 border border-slate-800 space-y-2.5">
            <div class="flex items-center justify-between">
                <h4 class="font-bold text-xs text-slate-200 flex items-center space-x-2">
                    <span class="w-5 h-5 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center text-[10px] font-mono">${idx + 1}</span>
                    <span>${escapeHtml(s.title)}</span>
                </h4>
            </div>
            <p class="text-xs text-slate-400 leading-relaxed whitespace-pre-line">${escapeHtml(s.description)}</p>

            ${s.command ? `
                <div class="relative group">
                    <pre class="bg-surface-900 border border-slate-800 rounded-xl p-3 pr-24 text-xs font-mono text-cyan-300 overflow-x-auto select-all"><code>${escapeHtml(s.command)}</code></pre>
                    <button type="button" onclick="copyInvestigatorCommand(this, '${escapeHtml(s.command.replace(/'/g, "\\'"))}')" class="absolute right-2 top-2 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-[11px] font-medium border border-slate-700 transition flex items-center space-x-1 shadow">
                        <i data-lucide="copy" class="w-3 h-3"></i>
                        <span>Копировать</span>
                    </button>
                </div>
            ` : ''}

            ${s.tip ? `
                <div class="text-[11px] text-slate-400 flex items-start space-x-1.5 pt-0.5">
                    <span class="text-indigo-400 font-bold shrink-0">💡 Подсказка:</span>
                    <span>${escapeHtml(s.tip)}</span>
                </div>
            ` : ''}
        </div>
    `).join('');

    if (window.lucide) lucide.createIcons();
}

async function switchInvestigatorOS(osType) {
    if (!currentInvestigationParams) {
        currentInvestigationParams = { target_os: osType };
    } else {
        currentInvestigationParams.target_os = osType;
    }

    const osSelect = document.getElementById('investigator-select-os');
    if (osSelect) osSelect.value = osType;

    await runInvestigation(currentInvestigationParams);
}
window.switchInvestigatorOS = switchInvestigatorOS;

function copyInvestigatorCommand(btn, cmd) {
    if (!navigator.clipboard) {
        prompt('Скопируйте команду:', cmd);
        return;
    }
    navigator.clipboard.writeText(cmd).then(() => {
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="text-emerald-400 font-bold">✓ Скопировано!</span>';
        setTimeout(() => {
            btn.innerHTML = originalHtml;
            if (window.lucide) lucide.createIcons();
        }, 2000);
    }).catch(() => {
        prompt('Скопируйте команду:', cmd);
    });
}
window.copyInvestigatorCommand = copyInvestigatorCommand;

async function executeInvestigatorBlock() {
    const input = document.getElementById('investigator-block-input');
    const statusEl = document.getElementById('investigator-block-status');
    const target = input ? input.value.trim() : '';

    if (!target) {
        alert('Пожалуйста, укажите доменное имя для блокировки!');
        return;
    }

    // IP address validation - DNS sinkhole cannot block IPs!
    const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$|^[a-fA-F0-9:]+$/.test(target);
    if (isIp) {
        if (statusEl) {
            statusEl.classList.remove('hidden');
            statusEl.className = 'text-xs p-3 rounded-xl bg-amber-950/40 text-amber-200 border border-amber-500/30 flex items-start space-x-2.5';
            statusEl.innerHTML = '<i data-lucide="alert-triangle" class="w-4 h-4 text-amber-400 shrink-0 mt-0.5"></i><span><b>Недопустимый формат:</b> DNS Sinkhole блокирует только доменные имена (например, <code>samsungacr.com</code>), а не IP-адреса. Для блокировки доступа по IP используйте кнопку «Заблокировать выход в интернет (WAN)» или правила межсетевого экрана Keenetic.</span>';
            if (window.lucide) lucide.createIcons();
        }
        return;
    }

    if (!statusEl) return;
    statusEl.classList.remove('hidden');
    statusEl.className = 'text-xs p-3 rounded-xl bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-2';
    statusEl.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin text-cyan-400"></i><span>Отправка команды блокировки на Keenetic...</span>';
    if (window.lucide) lucide.createIcons();

    try {
        const res = await fetch('/api/investigator/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: target })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            statusEl.className = 'text-xs p-3 rounded-xl bg-emerald-950/40 text-emerald-200 border border-emerald-500/30 flex items-center space-x-2';
            statusEl.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 text-emerald-400 shrink-0"></i><span>${escapeHtml(data.message)}</span>`;
            showToast(`Домен ${target} заблокирован на Keenetic`, 'success');
        } else {
            statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/40 text-rose-200 border border-rose-500/30 flex items-center space-x-2';
            statusEl.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400 shrink-0"></i><span>Ошибка: ${escapeHtml(data.detail || data.message || 'Не удалось применить блокировку')}</span>`;
        }
    } catch (e) {
        statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/40 text-rose-200 border border-rose-500/30 flex items-center space-x-2';
        statusEl.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400 shrink-0"></i><span>Ошибка сети: ${escapeHtml(e.message)}</span>`;
    }
    if (window.lucide) lucide.createIcons();
}
window.executeInvestigatorBlock = executeInvestigatorBlock;

async function executeInvestigatorIpBlock(forceCdn = false) {
    const input = document.getElementById('investigator-ip-block-input');
    const statusEl = document.getElementById('investigator-ip-block-status');
    const target = input ? input.value.trim() : '';

    if (!target) {
        alert('Пожалуйста, укажите IPv4-адрес для блокировки!');
        return;
    }

    // IP validation
    const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(target);
    if (!isIpv4) {
        if (statusEl) {
            statusEl.classList.remove('hidden');
            statusEl.className = 'text-xs p-3 rounded-xl bg-amber-950/40 text-amber-200 border border-amber-500/30 flex items-start space-x-2.5';
            statusEl.innerHTML = '<i data-lucide="alert-triangle" class="w-4 h-4 text-amber-400 shrink-0 mt-0.5"></i><span><b>Недопустимый формат:</b> Аппаратный фильтр Keenetic принимает только IPv4-адреса (например, <code>198.51.100.25</code>). Для блокировки доменов используйте «Действие 1: DNS Sinkhole».</span>';
            if (window.lucide) lucide.createIcons();
        }
        return;
    }

    // Private IP check
    if (/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(target)) {
        if (statusEl) {
            statusEl.classList.remove('hidden');
            statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/40 text-rose-200 border border-rose-500/30 flex items-start space-x-2.5';
            statusEl.innerHTML = '<i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400 shrink-0 mt-0.5"></i><span><b>Запрещено:</b> Нельзя блокировать локальный или служебный IP-адрес (' + escapeHtml(target) + '). Это нарушит работу вашей домашней сети!</span>';
            if (window.lucide) lucide.createIcons();
        }
        return;
    }

    if (!statusEl) return;
    statusEl.classList.remove('hidden');
    statusEl.className = 'text-xs p-3 rounded-xl bg-slate-800 text-slate-300 border border-slate-700 flex items-center space-x-2';
    statusEl.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin text-amber-400"></i><span>Проверка и применение аппаратного маршрута reject...</span>';
    if (window.lucide) lucide.createIcons();

    try {
        const res = await fetch('/api/investigator/block_ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: target, reason: 'Заблокировано из Мастера расследований', force_cdn: forceCdn })
        });
        const data = await res.json();

        if (res.ok && data.status === 'cdn_warning') {
            statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/50 text-rose-200 border border-rose-500/40 space-y-2';
            statusEl.innerHTML = `
                <div class="flex items-start space-x-2">
                    <i data-lucide="alert-triangle" class="w-4 h-4 text-rose-400 shrink-0 mt-0.5"></i>
                    <div class="space-y-1 leading-relaxed">
                        <p class="font-semibold text-rose-300">Внимание: Обнаружен CDN / Cloud (${escapeHtml(data.provider || 'Shared')})</p>
                        <p class="text-[11px] text-rose-200">${escapeHtml(data.message)}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2 pt-1">
                    <button type="button" onclick="executeInvestigatorIpBlock(true)" class="px-2.5 py-1 bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg text-[11px] transition">
                        Всё равно заблокировать IP
                    </button>
                    <button type="button" onclick="document.getElementById('investigator-ip-block-status').classList.add('hidden')" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-[11px] transition">
                        Отмена
                    </button>
                </div>
            `;
            if (window.lucide) lucide.createIcons();
            return;
        }

        if (res.ok && data.status === 'ok') {
            statusEl.className = 'text-xs p-3 rounded-xl bg-emerald-950/40 text-emerald-200 border border-emerald-500/30 flex items-center space-x-2';
            statusEl.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 text-emerald-400 shrink-0"></i><span>${escapeHtml(data.message)}</span>`;
            showToast(`IP ${target} заблокирован на роутере Keenetic (Reject)`, 'success');
        } else {
            statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/40 text-rose-200 border border-rose-500/30 flex items-center space-x-2';
            statusEl.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400 shrink-0"></i><span>Ошибка: ${escapeHtml(data.detail || data.message || 'Не удалось применить блокировку')}</span>`;
        }
    } catch (e) {
        statusEl.className = 'text-xs p-3 rounded-xl bg-rose-950/40 text-rose-200 border border-rose-500/30 flex items-center space-x-2';
        statusEl.innerHTML = `<i data-lucide="alert-octagon" class="w-4 h-4 text-rose-400 shrink-0"></i><span>Ошибка сети: ${escapeHtml(e.message)}</span>`;
    }
    if (window.lucide) lucide.createIcons();
}
window.executeInvestigatorIpBlock = executeInvestigatorIpBlock;

async function applyInvestigatorProfile(mac, profileName) {
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/profile`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profile: profileName })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            showToast(`Устройству назначен профиль «${profileName}»`, 'success');
            if (currentInvestigationParams) {
                await runInvestigation(currentInvestigationParams);
            }
        } else {
            showToast(`Ошибка: ${data.detail || 'Не удалось применить профиль'}`, 'error');
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, 'error');
    }
}
window.applyInvestigatorProfile = applyInvestigatorProfile;

async function toggleInvestigatorWan(mac, block) {
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/toggle_wan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: block })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            showToast(block ? 'Интернет (WAN) заблокирован для устройства' : 'Интернет (WAN) разблокирован для устройства', 'success');
            if (currentInvestigationParams) {
                await runInvestigation(currentInvestigationParams);
            }
        } else {
            showToast(`Ошибка: ${data.detail || 'Не удалось изменить доступ к интернету'}`, 'error');
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, 'error');
    }
}
window.toggleInvestigatorWan = toggleInvestigatorWan;

// Quick Jump Helpers from Alerts, Audits, and Devices
function openInvestigatorForAudit(auditId) {
    pendingInvestigatorTarget = `audit:${auditId}`;
    switchTab('investigator');
}
window.openInvestigatorForAudit = openInvestigatorForAudit;

function openInvestigatorForEvent(eventId, ev) {
    if (ev && ev.stopPropagation) ev.stopPropagation();
    pendingInvestigatorTarget = `event:${eventId}`;
    switchTab('investigator');
}
window.openInvestigatorForEvent = openInvestigatorForEvent;

function openInvestigatorForDevice(mac) {
    pendingInvestigatorTarget = `device:${mac}`;
    switchTab('investigator');
}
window.openInvestigatorForDevice = openInvestigatorForDevice;

