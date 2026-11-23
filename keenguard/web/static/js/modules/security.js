// UPnP and Alerts
async function loadUpnp() {
    try {
        const res = await fetch('/api/upnp');
        upnpList = await res.json();
        const countSpan = document.getElementById('stat-upnp-count');
        const secSpan = document.getElementById('stat-upnp-security');
        if (countSpan) countSpan.textContent = upnpList.length;

        const container = document.getElementById('upnp-table-container');
        if (!container) return;

        if (upnpList.length === 0) {
            container.innerHTML = '<div class="text-slate-500 text-xs py-4 text-center">Активных UPnP пробросов портов нет. Роутер в безопасности.</div>';
            if (secSpan) secSpan.textContent = "Утечки не обнаружены";
        } else {
            if (secSpan) secSpan.textContent = `ВНИМАНИЕ: ${upnpList.length} пробросов открыто!`;
            container.innerHTML = `
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-xs">
                        <thead class="text-slate-400 border-b border-slate-800 pb-2">
                            <tr>
                                <th class="py-2">Внешний порт</th>
                                <th class="py-2">Локальный адрес</th>
                                <th class="py-2">Протокол</th>
                                <th class="py-2">Описание</th>
                                <th class="py-2 text-right">Действие</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/60">
                            ${upnpList.map(r => `
                                <tr>
                                    <td class="py-2.5 font-mono text-rose-400 font-bold">${Number(r.ext_port)}</td>
                                    <td class="py-2.5 font-mono text-slate-300">${escapeHtml(r.int_ip || r.client_ip || r.ip || '—')}:${Number(r.int_port || r.port || 0)}</td>
                                    <td class="py-2.5 uppercase font-mono">${escapeHtml(r.protocol)}</td>
                                    <td class="py-2.5 text-slate-400">${escapeHtml(r.description || 'N/A')}</td>
                                    <td class="py-2.5 text-right">
                                        <button data-protocol="${escapeHtml(r.protocol)}" data-port="${Number(r.ext_port)}" onclick="deleteUpnp(this.dataset.protocol, Number(this.dataset.port))" class="px-2.5 py-1 text-[11px] rounded bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border border-rose-500/30">
                                            Удалить
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }
    } catch (e) {
        console.error('Error loading UPnP', e);
    }
}

async function deleteUpnp(protocol, port) {
    if (!confirm(`Удалить UPnP правило для порта ${port}/${protocol}?`)) return;
    await fetch('/api/upnp/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protocol: protocol, ext_port: port })
    });
    upnpList = upnpList.filter(u => !(u.protocol === protocol && (u.ext_port === port || u.port === port)));
    await loadUpnp();
}

let currentEventTargetMac = null;
let currentModalEventId = null;

function closeEventModal() {
    const modal = document.getElementById('event-modal');
    if (modal) modal.classList.add('hidden');
}

function goToEventDevice() {
    if (currentEventTargetMac) {
        closeEventModal();
        openDeviceModal(currentEventTargetMac);
    }
}

async function openEventModal(eventId, timestamp) {
    if (!eventsList || eventsList.length === 0) {
        try {
            const res = await fetch('/api/events?limit=50');
            if (res.ok) {
                eventsList = await res.json();
            }
        } catch (err) {
            console.error('Failed to load events list for modal', err);
        }
    }
    if (!eventsList || eventsList.length === 0) return;
    const e = eventsList.find(ev => (eventId && ev.id == eventId) || (timestamp && ev.timestamp === timestamp)) || eventsList[0];
    if (!e) return;

    currentEventTargetMac = e.target_mac || null;
    currentModalEventId = e.id || null;

    const modal = document.getElementById('event-modal');
    if (!modal) return;

    // Severity & type styling
    const isCrit = e.severity === 'critical';
    const isWarn = e.severity === 'warning';
    const badgeColor = isCrit ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : isWarn ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-800 text-slate-300 border-slate-700';
    const iconContainer = document.getElementById('event-modal-icon-container');
    const icon = document.getElementById('event-modal-icon');

    if (iconContainer && icon) {
        if (isCrit) {
            iconContainer.className = 'p-2 rounded-xl bg-rose-500/10 text-rose-400';
            icon.setAttribute('data-lucide', 'alert-octagon');
        } else if (isWarn) {
            iconContainer.className = 'p-2 rounded-xl bg-amber-500/10 text-amber-400';
            icon.setAttribute('data-lucide', 'alert-triangle');
        } else {
            iconContainer.className = 'p-2 rounded-xl bg-indigo-500/10 text-indigo-400';
            icon.setAttribute('data-lucide', 'info');
        }
    }

    const typeBadge = document.getElementById('event-modal-type-badge');
    if (typeBadge) {
        typeBadge.className = `px-2 py-0.5 rounded text-xs font-bold border ${badgeColor}`;
        typeBadge.textContent = (e.event_type || 'EVENT').toUpperCase();
    }

    const sevBadge = document.getElementById('event-modal-severity-badge');
    if (sevBadge) {
        sevBadge.textContent = isCrit ? 'Критический инцидент' : isWarn ? 'Предупреждение' : 'Информационное событие';
        sevBadge.className = isCrit ? 'text-[11px] font-medium text-rose-400' : isWarn ? 'text-[11px] font-medium text-amber-400' : 'text-[11px] font-medium text-slate-400';
    }

    const timeEl = document.getElementById('event-modal-time');
    if (timeEl) timeEl.textContent = e.timestamp ? new Date(e.timestamp).toLocaleString() : '—';
    const descEl = document.getElementById('event-modal-description');
    if (descEl) descEl.textContent = e.description || '';

    // Target device box
    const devBox = document.getElementById('event-modal-device-box');
    if (devBox) {
        if (e.target_mac || e.target_ip) {
            devBox.classList.remove('hidden');
            let hostDisplay = 'Неизвестное устройство';
            if (devicesList && devicesList.length > 0 && e.target_mac) {
                const d = devicesList.find(dev => dev.mac.toUpperCase() === e.target_mac.toUpperCase());
                if (d) {
                    hostDisplay = d.custom_name || d.hostname || d.vendor || e.target_mac;
                }
            }
            const devName = document.getElementById('event-modal-device-name');
            if (devName) devName.textContent = hostDisplay;
            const devIpMac = document.getElementById('event-modal-device-ipmac');
            if (devIpMac) devIpMac.textContent = `${e.target_ip || 'IP не указан'} • ${e.target_mac || 'MAC не указан'}`;
            const gotoBtn = document.getElementById('event-modal-goto-device-btn');
            if (gotoBtn) {
                if (e.target_mac) {
                    gotoBtn.classList.remove('hidden');
                } else {
                    gotoBtn.classList.add('hidden');
                }
            }
        } else {
            devBox.classList.add('hidden');
        }
    }

    // Source device box
    const srcBox = document.getElementById('event-modal-source-box');
    if (srcBox) {
        const isSelf = (e.target_mac && e.source_mac && e.target_mac.toUpperCase() === e.source_mac.toUpperCase()) ||
                       (e.target_ip && e.source_ip && e.target_ip === e.source_ip);
        if (isSelf) {
            srcBox.classList.add('hidden');
        } else if (e.source_ip || e.source_mac || e.source_name) {
            srcBox.classList.remove('hidden');
            const srcStr = [e.source_name, e.source_ip, e.source_mac].filter(Boolean).join(' • ');
            const srcVal = document.getElementById('event-modal-source-val');
            if (srcVal) srcVal.textContent = srcStr;
        } else {
            srcBox.classList.add('hidden');
        }
    }

    // Details content rendering
    const detailsContainer = document.getElementById('event-modal-details-content');
    const extraActionsContainer = document.getElementById('event-modal-extra-actions');
    if (extraActionsContainer) {
        extraActionsContainer.innerHTML = `
            <button onclick="closeEventModal(); openInvestigatorForEvent(${e.id || 0});" class="px-3.5 py-2 rounded-xl bg-rose-600/20 text-rose-300 border border-rose-500/30 hover:bg-rose-600/30 text-xs font-medium flex items-center space-x-1.5 transition">
                <i data-lucide="crosshair" class="w-3.5 h-3.5 text-rose-400"></i>
                <span>Расследовать инцидент</span>
            </button>
        `;
    }

    let dt = e.details || {};
    if (typeof dt === 'string') {
        try { dt = JSON.parse(dt); } catch (err) { dt = {}; }
    }
    let detailsHtml = '';

    if (e.event_type === 'audit_completed') {
        const trafficStr = formatBytes(dt.total_bytes || 0);
        detailsHtml += `
            <div class="grid grid-cols-2 gap-2 pb-2.5 border-b border-slate-800">
                <div class="bg-surface-900 p-2.5 rounded-lg border border-slate-800/80">
                    <span class="text-slate-500 text-[11px] block">Активных потоков:</span>
                    <span class="font-bold text-base text-white">${dt.flows_count || 0}</span>
                </div>
                <div class="bg-surface-900 p-2.5 rounded-lg border border-slate-800/80">
                    <span class="text-slate-500 text-[11px] block">Трафик сессии:</span>
                    <span class="font-bold text-base text-white">${trafficStr}</span>
                </div>
            </div>
        `;
        if (dt.findings && Array.isArray(dt.findings) && dt.findings.length > 0) {
            detailsHtml += `
                <div class="pt-1">
                    <span class="text-amber-400 font-semibold text-xs block mb-1.5 flex items-center space-x-1.5">
                        <i data-lucide="alert-triangle" class="w-3.5 h-3.5"></i>
                        <span>Обнаруженные риски и аномалии:</span>
                    </span>
                    <ul class="space-y-1.5">
                        ${dt.findings.map(f => `<li class="text-slate-200 bg-amber-500/10 border border-amber-500/20 p-2.5 rounded-lg text-xs leading-relaxed">• ${escapeHtml(f)}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            detailsHtml += `<div class="text-emerald-400 text-xs py-1">Аномалий и угроз во время аудита не выявлено. Все соединения защищены.</div>`;
        }

        if (e.target_mac) {
            extraActionsContainer.innerHTML += `
                <button data-mac="${escapeHtml(e.target_mac)}" onclick="closeEventModal(); openDeviceModal(this.dataset.mac);" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20">
                    <i data-lucide="activity" class="w-3.5 h-3.5"></i>
                    <span>Открыть карточку устройства и аудит</span>
                </button>
            `;
        }
    } else if (e.event_type === 'tv_wake') {
        const isNight = dt.is_night;
        const isSelfCulprit = (dt.culprit_ip && dt.culprit_ip === e.target_ip) || (dt.culprit_mac && dt.culprit_mac === e.target_mac);
        const culpritDisplay = isSelfCulprit ? 'Не зафиксирован (Автономное пробуждение)' : (dt.culprit_ip || dt.culprit_mac || 'Не зафиксирован (Автономное пробуждение)');
        detailsHtml += `
            <div class="space-y-2">
                <div class="flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800">
                    <span class="text-slate-400">Статус времени суток:</span>
                    <span class="font-semibold ${isNight ? 'text-rose-400' : 'text-slate-300'}">${isNight ? '🌙 Ночной режим покоя (Подозрительно)' : '☀️ Дневное время'}</span>
                </div>
                <div class="flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800">
                    <span class="text-slate-400">Инициатор в локальной сети (WOL/AirPlay):</span>
                    <span class="font-mono text-slate-300 font-medium">${escapeHtml(culpritDisplay)}</span>
                </div>
                <div class="flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800">
                    <span class="text-slate-400">Захвачено пакетов в буфере:</span>
                    <span class="font-mono text-slate-300 font-bold">${dt.packet_dump_count || 0}</span>
                </div>
                <div class="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-[11px] leading-relaxed">
                    💡 <b>Криминалистический вердикт:</b> Телевизор проснулся без отправки внешних Magic Packet по сети. Типичные причины: внутренний таймер телевизора, фоновая проверка обновлений прошивки webOS/Tizen или проверка push-уведомлений от облачного сервиса производителя.
                </div>
            </div>
        `;

        if (e.target_mac) {
            extraActionsContainer.innerHTML += `
                <button data-mac="${escapeHtml(e.target_mac)}" onclick="closeEventModal(); openDeviceModal(this.dataset.mac);" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20">
                    <i data-lucide="tv" class="w-3.5 h-3.5"></i>
                    <span>Криминалистика ТВ</span>
                </button>
            `;
        }
    } else if (e.event_type === 'port_probe') {
        detailsHtml += `
            <div class="space-y-2">
                <div class="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
                    ⚠️ <b>Несанкционированное сканирование:</b> Зафиксирована попытка обращения к закрытому сервисному порту устройства.
                </div>
                <div class="grid grid-cols-2 gap-2 text-xs">
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Порт:</span> <span class="font-mono font-bold text-white">${escapeHtml(String(dt.port || 'Не указан'))}</span></div>
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Сервис:</span> <span class="font-bold text-white">${escapeHtml(dt.service || '')}</span></div>
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Протокол:</span> <span class="font-mono text-slate-300">${escapeHtml(dt.protocol || 'TCP')}</span></div>
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Статус:</span> <span class="text-emerald-400 font-bold">${dt.action === 'blocked' ? 'ЗАБЛОКИРОВАНО' : 'ОБНАРУЖЕНО'}</span></div>
                </div>
            </div>
        `;
    } else {
        const keys = Object.keys(dt);
        if (keys.length === 0) {
            detailsHtml = `<div class="text-slate-400 text-xs py-1">Дополнительных технических параметров не зафиксировано.</div>`;
        } else {
            detailsHtml = `
                <div class="space-y-1.5">
                    ${keys.map(k => `
                        <div class="flex items-center justify-between p-2 rounded-lg bg-surface-900 border border-slate-800/80 text-xs">
                            <span class="text-slate-400 font-mono text-[11px]">${escapeHtml(k)}:</span>
                            <span class="text-slate-200 font-mono font-medium">${escapeHtml(typeof dt[k] === 'object' ? JSON.stringify(dt[k]) : String(dt[k]))}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }
    }

    if (e.pcap_file) {
        extraActionsContainer.innerHTML += `
            <a href="/api/events/pcap/${encodeURIComponent(e.pcap_file)}" download="${escapeHtml(e.pcap_file)}" class="px-3.5 py-2 rounded-xl bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 text-xs font-medium flex items-center space-x-1.5 transition">
                <i data-lucide="download" class="w-3.5 h-3.5"></i>
                <span>Скачать дамп PCAP</span>
            </a>
        `;
    }

    detailsContainer.innerHTML = detailsHtml;

    modal.classList.remove('hidden');
    lucide.createIcons();
}

async function loadEvents() {
    try {
        const res = await fetch('/api/events?limit=50');
        eventsList = await res.json();
        const list = document.getElementById('all-events-list');
        if (!list) return;

        if (eventsList.length === 0) {
            list.innerHTML = '<div class="text-slate-500 text-xs py-4 text-center">Инцидентов безопасности не зафиксировано.</div>';
            return;
        }

        list.innerHTML = eventsList.map((e, idx) => {
            const isCrit = e.severity === 'critical';
            const isWarn = e.severity === 'warning';
            const badgeColor = isCrit ? 'bg-rose-500/20 text-rose-300 border-rose-500/30' : isWarn ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-slate-800 text-slate-300 border-slate-700';
            const timeStr = new Date(e.timestamp).toLocaleString();

            return `
                <div data-event-id="${Number(e.id || 0)}" data-timestamp="${escapeHtml(e.timestamp)}" onclick="openEventModal(Number(this.dataset.eventId), this.dataset.timestamp)" class="p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 hover:border-indigo-500/60 hover:bg-surface-900/90 transition flex items-start justify-between gap-3 text-xs cursor-pointer group shadow-sm">
                    <div class="space-y-1">
                        <div class="flex items-center space-x-2">
                            <span class="px-2 py-0.5 rounded font-medium border ${badgeColor}">${escapeHtml(e.event_type.toUpperCase())}</span>
                            <span class="text-slate-500">${timeStr}</span>
                        </div>
                        <p class="text-slate-200 font-medium">${escapeHtml(e.description)}</p>
                    </div>
                    <div class="flex items-center space-x-2 shrink-0 self-center">
                        ${e.pcap_file ? `<a href="/api/events/pcap/${encodeURIComponent(e.pcap_file)}" download="${escapeHtml(e.pcap_file)}" onclick="event.stopPropagation()" class="text-indigo-400 hover:underline shrink-0 px-2 py-1 bg-indigo-950/60 rounded border border-indigo-800/50">PCAP</a>` : ''}
                        <button data-event-id="${Number(e.id || 0)}" onclick="openInvestigatorForEvent(Number(this.dataset.eventId), event)" class="p-1.5 rounded-lg bg-surface-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-800/50 transition" title="Расследовать инцидент в Wizard">
                            <i data-lucide="crosshair" class="w-3.5 h-3.5 text-rose-400"></i>
                        </button>
                        <button data-event-id="${Number(e.id || 0)}" onclick="deleteEvent(Number(this.dataset.eventId), event)" class="p-1.5 rounded-lg bg-surface-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-800/50 transition" title="Удалить инцидент">
                            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                        </button>
                        <span class="text-[11px] text-indigo-400 group-hover:text-indigo-300 group-hover:translate-x-0.5 transition font-semibold flex items-center space-x-1 bg-indigo-500/10 px-2.5 py-1 rounded-lg border border-indigo-500/20">
                            <span>Детали</span>
                            <span>➔</span>
                        </span>
                    </div>
                </div>
            `;
        }).join('');

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error loading events', e);
    }
}

async function deleteEvent(id, ev) {
    if (ev) ev.stopPropagation();
    if (!id) return;
    if (!confirm('Вы уверены, что хотите удалить эту запись об инциденте?')) {
        return;
    }
    try {
        const res = await fetch(`/api/events/${id}`, { method: 'DELETE' });
        if (res.ok) {
            showToast('Инцидент успешно удален');
            await loadEvents();
        } else {
            showToast('Ошибка при удалении инцидента');
        }
    } catch (e) {
        console.error('Error deleting event', e);
        showToast('Ошибка сети при удалении инцидента');
    }
}

async function deleteCurrentEvent() {
    if (!currentModalEventId) return;
    if (!confirm('Вы уверены, что хотите удалить этот инцидент из журнала?')) {
        return;
    }
    try {
        const res = await fetch(`/api/events/${currentModalEventId}`, { method: 'DELETE' });
        if (res.ok) {
            closeEventModal();
            showToast('Инцидент успешно удален');
            await loadEvents();
        } else {
            showToast('Ошибка при удалении инцидента');
        }
    } catch (e) {
        console.error('Error deleting current event', e);
        showToast('Ошибка сети при удалении инцидента');
    }
}

function openClearEventsModal() {
    const modal = document.getElementById('clear-events-modal');
    if (modal) modal.classList.remove('hidden');
}

function closeClearEventsModal() {
    const modal = document.getElementById('clear-events-modal');
    if (modal) modal.classList.add('hidden');
}

async function executeClearEvents() {
    const selectedScope = document.querySelector('input[name="clear-events-scope"]:checked')?.value || 'all';
    let url = '/api/events';
    let confirmMsg = 'Вы действительно хотите полностью очистить весь журнал инцидентов?';

    if (selectedScope === 'info') {
        url += '?severity=info';
        confirmMsg = 'Удалить все информационные события (Info), сохранив Warning и Critical?';
    } else if (selectedScope === '7d') {
        url += '?older_than_days=7';
        confirmMsg = 'Удалить события старше 7 дней?';
    }

    if (!confirm(confirmMsg)) {
        return;
    }

    const btn = document.getElementById('btn-confirm-clear-events');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch(url, { method: 'DELETE' });
        const data = await res.json();
        closeClearEventsModal();
        showToast(`Журнал инцидентов очищен (удалено: ${data.deleted || 0})`);
        await loadEvents();
    } catch (e) {
        console.error('Error clearing events', e);
        showToast('Ошибка при очистке событий');
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Alerts Tab Loader
async function loadAlerts() {
    await loadUpnp();
    await loadEvents();
}

// Device Traffic Audit Frontend Logic
let auditTimerInterval = null;

async function checkDeviceAuditState(mac) {
    if (auditTimerInterval) clearInterval(auditTimerInterval);

    try {
        const res = await fetch(`/api/audit/${mac}/status`);
        const status = await res.json();

        if (status.is_active) {
            document.getElementById('modal-audit-idle').classList.add('hidden');
            document.getElementById('modal-audit-running').classList.remove('hidden');
            document.getElementById('modal-audit-result').classList.add('hidden');
            updateAuditProgressUI(status);

            if (auditTimerInterval) {
                clearInterval(auditTimerInterval);
                auditTimerInterval = null;
            }
            auditTimerInterval = setInterval(async () => {
                if (!currentDeviceMac) {
                    clearInterval(auditTimerInterval);
                    return;
                }
                const sRes = await fetch(`/api/audit/${currentDeviceMac}/status`);
                const s = await sRes.json();
                if (s.is_active) {
                    updateAuditProgressUI(s);
                } else {
                    clearInterval(auditTimerInterval);
                    loadLatestReport(currentDeviceMac);
                }
            }, 1000);
        } else {
            loadLatestReport(mac);
        }
    } catch (e) {
        resetModalAudit();
    }
}

async function loadLatestReport(mac) {
    try {
        const res = await fetch(`/api/audit/${mac}/latest_report`);
        if (res.ok) {
            const report = await res.json();
            renderAuditResult(report);
        } else {
            resetModalAudit();
        }
    } catch (e) {
        resetModalAudit();
    }
}

function updateAuditProgressUI(status) {
    const elapsed = status.elapsed_seconds || 0;
    const min = String(Math.floor(elapsed / 60)).padStart(2, '0');
    const sec = String(elapsed % 60).padStart(2, '0');
    document.getElementById('modal-audit-timer').textContent = `${min}:${sec}`;
    document.getElementById('modal-audit-live-flows').textContent = status.flows_count || 0;
    document.getElementById('modal-audit-live-bytes').textContent = formatBytes(status.total_bytes || 0);
}

async function startModalAudit() {
    if (!currentDeviceMac) return;
    const duration = parseInt(document.getElementById('modal-audit-duration').value, 10);
    try {
        const res = await fetch(`/api/audit/${currentDeviceMac}/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ duration_seconds: duration })
        });
        if (res.ok) {
            await checkDeviceAuditState(currentDeviceMac);
        }
    } catch (e) {
        alert('Не удалось запустить аудит: ' + e);
    }
}

async function stopModalAudit() {
    if (!currentDeviceMac) return;
    if (auditTimerInterval) clearInterval(auditTimerInterval);

    try {
        const res = await fetch(`/api/audit/${currentDeviceMac}/stop`, {
            method: 'POST'
        });
        if (res.ok) {
            const report = await res.json();
            renderAuditResult(report);
            if (activeTab === 'audits') loadAuditReports();
        }
    } catch (e) {
        alert('Ошибка остановки аудита: ' + e);
    }
}

function renderAuditResult(report) {
    const idleEl = document.getElementById('modal-audit-idle');
    if (idleEl) idleEl.classList.add('hidden');
    const runEl = document.getElementById('modal-audit-running');
    if (runEl) runEl.classList.add('hidden');
    const resEl = document.getElementById('modal-audit-result');
    if (resEl) resEl.classList.remove('hidden');

    const badge = document.getElementById('modal-audit-risk-badge');
    if (badge) {
        if (report.risk_level === 'high' || report.risk_level === 'critical') {
            badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30';
            badge.textContent = 'Высокий риск';
        } else if (report.risk_level === 'medium' || report.risk_level === 'warning') {
            badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30';
            badge.textContent = 'Предупреждение';
        } else {
            badge.className = 'px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
            badge.textContent = 'Безопасно';
        }
    }

    // Render Capture Source Badge
    const srcBadge = document.getElementById('modal-audit-capture-source');
    if (srcBadge) {
        if (report.capture_source === 'router_hardware') {
            srcBadge.className = 'px-2 py-0.5 rounded-full text-[9px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30';
            srcBadge.textContent = '🛡️ Keenetic L3/L4';
            srcBadge.title = 'Аппаратный захват пакетов на уровне ядра роутера (L3/L4 WAN)';
            srcBadge.classList.remove('hidden');
        } else {
            srcBadge.className = 'px-2 py-0.5 rounded-full text-[9px] font-mono bg-slate-800 text-slate-400 border border-slate-700';
            srcBadge.textContent = '📡 L2 Broadcast';
            srcBadge.title = 'Локальный срез эфира сетевой карты ПК';
            srcBadge.classList.remove('hidden');
        }
    }

    // Render HTTP Inspections if present
    const httpSec = document.getElementById('modal-audit-http-section');
    const httpListEl = document.getElementById('modal-audit-http-list');
    const httpCountEl = document.getElementById('modal-audit-http-count');
    const httpItems = report.http_inspections || [];
    if (httpSec && httpListEl) {
        if (httpItems.length > 0) {
            httpSec.classList.remove('hidden');
            if (httpCountEl) httpCountEl.textContent = `${httpItems.length}`;
            httpListEl.innerHTML = httpItems.map(h => `
                <div class="p-1.5 rounded bg-surface-900 border border-amber-900/30 flex items-center justify-between text-[10px]">
                    <div class="flex items-center space-x-1.5 truncate max-w-[260px]">
                        <span class="px-1 py-0.2 rounded bg-amber-500/20 text-amber-300 font-bold text-[9px]">${escapeHtml(h.method || 'GET')}</span>
                        <span class="font-semibold text-slate-300 truncate" title="${escapeHtml(h.host)}${escapeHtml(h.path)}">${escapeHtml(h.host)}</span>
                        <span class="text-slate-500 truncate">(${escapeHtml(h.category || '')})</span>
                    </div>
                    <span class="text-slate-400 text-[9px] truncate max-w-[80px]" title="${escapeHtml(h.path)}">${escapeHtml(h.path)}</span>
                </div>
            `).join('');
        } else {
            httpSec.classList.add('hidden');
        }
    }

    const totalTrafficStr = formatBytes(report.total_bytes || 0);
    const flowsList = report.flows ? (Array.isArray(report.flows) ? report.flows : Object.values(report.flows)) : [];
    const flowsSummaryEl = document.getElementById('modal-audit-flows-summary');
    if (flowsSummaryEl) {
        flowsSummaryEl.textContent = `${report.flows_count || flowsList.length} соединений (${totalTrafficStr})`;
    }

    const findingsContainer = document.getElementById('modal-audit-findings');
    if (findingsContainer) {
        const rawFindings = report.findings || (report.summary ? [report.summary] : ['Подозрительной сетевой активности не выявлено.']);
        const findings = Array.isArray(rawFindings) ? rawFindings : [String(rawFindings)];
        findingsContainer.innerHTML = findings.map(f => `<div>• ${escapeHtml(f)}</div>`).join('');
    }

    const recContainer = document.getElementById('modal-audit-recommendations');
    if (recContainer) {
        if (report.recommendations && report.recommendations.length > 0) {
            recContainer.innerHTML = report.recommendations.map(r => `<div class="flex items-start space-x-1.5"><span class="shrink-0">💡</span><span>${escapeHtml(r)}</span></div>`).join('');
            recContainer.classList.remove('hidden');
        } else {
            recContainer.classList.add('hidden');
        }
    }

    // Render DNS queries if present
    const dnsContainer = document.getElementById('modal-audit-dns-tags');
    const dnsSec = document.getElementById('modal-audit-dns-section');
    const rawDns = report.dns_queries ? (Array.isArray(report.dns_queries) ? report.dns_queries : Object.values(report.dns_queries)) : [];
    const dnsList = rawDns.map(d => typeof d === 'string' ? d : (d && d.domain ? d.domain : '')).filter(Boolean);

    if (dnsContainer && dnsSec) {
        if (dnsList.length > 0) {
            dnsSec.classList.remove('hidden');
            dnsContainer.innerHTML = dnsList.map(dom => `
                <button data-domain="${escapeHtml(dom)}" onclick="openDomainModal(this.dataset.domain)" class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 font-mono transition cursor-pointer" title="Нажмите для анализа и блокировки в Keenetic">
                    <span>${escapeHtml(dom)}</span>
                    <i data-lucide="shield-alert" class="w-2.5 h-2.5 text-cyan-400"></i>
                </button>
            `).join('');
        } else {
            dnsSec.classList.add('hidden');
        }
    }

    const flowsContainer = document.getElementById('modal-audit-flows-list');
    if (flowsList.length === 0) {
        if (flowsContainer) flowsContainer.innerHTML = '<div class="text-slate-500 text-[10px] italic py-2 text-center">Внешних соединений во время аудита не зафиксировано.</div>';
    } else {
        if (flowsContainer) {
            flowsContainer.innerHTML = flowsList.map(f => {
                const encIcon = f.is_encrypted ? '<span title="SSL/TLS Шифрование">🔒</span>' : (f.dst_port === 80 ? '<span title="Незащищенный открытый HTTP!">⚠️</span>' : '<span title="Открытый трафик">🌐</span>');
                const flowBytes = (f.bytes_up || 0) + (f.bytes_down || 0);
                return `
                    <div class="flex items-center justify-between p-1.5 rounded-lg bg-surface-900 border border-slate-800/80 text-[10px]">
                        <div class="flex items-center space-x-1.5 truncate max-w-[260px]">
                            <span>${encIcon}</span>
                            <span class="font-mono text-slate-300 font-semibold">${f.dst_ip}:${f.dst_port}</span>
                            <span class="text-slate-400 truncate">(${escapeHtml(f.provider || f.service)})</span>
                        </div>
                        <span class="text-slate-400 font-mono shrink-0">${formatBytes(flowBytes)}</span>
                    </div>
                `;
            }).join('');
        }
    }

    const pcapBtn = document.getElementById('modal-audit-pcap-btn');
    if (report.pcap_file) {
        pcapBtn.href = `/api/audit/pcap/${report.pcap_file}`;
        pcapBtn.classList.remove('hidden');
    } else {
        pcapBtn.classList.add('hidden');
    }

    lucide.createIcons();
}

function resetModalAudit() {
    if (auditTimerInterval) clearInterval(auditTimerInterval);
    document.getElementById('modal-audit-idle').classList.remove('hidden');
    document.getElementById('modal-audit-running').classList.add('hidden');
    document.getElementById('modal-audit-result').classList.add('hidden');
}


// ==========================================
// Security Checklist & Audit Hub Logic
// ==========================================
let securityChecklistData = null;
let activeSecurityFilter = 'all';
let lastRenderedSecurityItemsJson = null;
let lastRenderedSecurityFilter = 'all';
const openChecklistDetailsIds = new Set();

function handleChecklistDetailsToggle(id, isOpen) {
    if (isOpen) {
        openChecklistDetailsIds.add(id);
    } else {
        openChecklistDetailsIds.delete(id);
    }
}

async function loadSecurity() {
    try {
        const res = await fetch('/api/security/checklist');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        securityChecklistData = data;

        // 1. Update Metrics (safe DOM updates without clearing containers)
        const scoreEl = document.getElementById('sec-stat-score');
        const labelEl = document.getElementById('sec-stat-label');
        const okEl = document.getElementById('sec-stat-ok');
        const warnEl = document.getElementById('sec-stat-warn');
        const critEl = document.getElementById('sec-stat-crit');
        const badge = document.getElementById('security-count-badge');

        const score = data.score || 0;
        const stats = data.stats || {};

        if (scoreEl) scoreEl.textContent = `${score}%`;
        if (labelEl) {
            labelEl.textContent = data.score_label || 'Отлично';
            labelEl.className = `text-xs px-2 py-0.5 rounded-full bg-${data.score_color || 'emerald'}-500/20 text-${data.score_color || 'emerald'}-300 font-medium`;
        }
        if (okEl) okEl.textContent = stats.ok_count || 0;
        if (warnEl) warnEl.textContent = stats.warning_count || 0;
        if (critEl) critEl.textContent = stats.critical_count || 0;

        // Attention badge in top navigation
        const attentionCount = (stats.warning_count || 0) + (stats.critical_count || 0);
        if (badge) {
            if (attentionCount > 0) {
                badge.textContent = attentionCount;
                badge.className = stats.critical_count > 0
                    ? 'ml-1.5 px-1.5 py-0.2 rounded-full text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'ml-1.5 px-1.5 py-0.2 rounded-full text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30';
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }

        // Also update dashboard widget if elements exist
        loadSecurityScoreForDashboard(data);

        // 2. Render Cards only if items or filter actually changed (prevents collapsing accordions on poll)
        const items = data.items || [];
        const itemsJson = JSON.stringify(items);
        const container = document.getElementById('security-checklist-container');
        const needsRender = itemsJson !== lastRenderedSecurityItemsJson ||
                            activeSecurityFilter !== lastRenderedSecurityFilter ||
                            !container || container.children.length === 0;

        if (needsRender) {
            lastRenderedSecurityItemsJson = itemsJson;
            lastRenderedSecurityFilter = activeSecurityFilter;
            const filtered = activeSecurityFilter === 'all' ? items : items.filter(item => {
                if (activeSecurityFilter === 'smarthome') return item.category === 'smarthome' || item.category === 'garden';
                return item.category === activeSecurityFilter;
            });
            renderSecurityChecklist(filtered);
            lucide.createIcons();
        }
    } catch (e) {
        console.error('Error loading security checklist', e);
    }
}

async function loadSecurityScoreForDashboard(cachedData) {
    try {
        const data = cachedData || await (await fetch('/api/security/checklist')).json();
        const scoreEl = document.getElementById('dash-sec-score');
        const statusEl = document.getElementById('dash-sec-status');
        if (scoreEl) scoreEl.textContent = `${data.score || 0}%`;
        if (statusEl) {
            statusEl.textContent = data.score_label || 'Отлично';
            statusEl.className = `text-xs text-${data.score_color || 'emerald'}-400 font-medium`;
        }

        // Badge update
        const badge = document.getElementById('security-count-badge');
        const stats = data.stats || {};
        const attentionCount = (stats.warning_count || 0) + (stats.critical_count || 0);
        if (badge) {
            if (attentionCount > 0) {
                badge.textContent = attentionCount;
                badge.className = stats.critical_count > 0
                    ? 'ml-1.5 px-1.5 py-0.2 rounded-full text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'ml-1.5 px-1.5 py-0.2 rounded-full text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30';
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }
    } catch (e) {
        // Silent fail for dashboard poll
    }
}

function filterSecurity(cat) {
    activeSecurityFilter = cat;
    lastRenderedSecurityFilter = cat;
    document.querySelectorAll('.sec-filter-btn').forEach(btn => {
        if (btn.dataset.secFilter === cat) {
            btn.className = "sec-filter-btn active px-3 py-1.5 text-xs rounded-xl bg-indigo-600 text-white font-medium transition";
        } else {
            btn.className = "sec-filter-btn px-3 py-1.5 text-xs rounded-xl bg-surface-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition";
        }
    });

    if (!securityChecklistData || !securityChecklistData.items) return;
    const items = securityChecklistData.items;
    const filtered = cat === 'all' ? items : items.filter(item => {
        if (cat === 'smarthome') return item.category === 'smarthome' || item.category === 'garden';
        return item.category === cat;
    });
    renderSecurityChecklist(filtered);
    lucide.createIcons();
}

function renderSecurityChecklist(items) {
    const container = document.getElementById('security-checklist-container');
    if (!container) return;

    // Harvest currently open details before updating DOM
    container.querySelectorAll('details[data-check-id]').forEach(d => {
        const id = d.getAttribute('data-check-id');
        if (id) {
            if (d.open) openChecklistDetailsIds.add(id);
            else openChecklistDetailsIds.delete(id);
        }
    });

    if (!items || items.length === 0) {
        container.innerHTML = `
            <div class="py-12 text-center text-slate-500 text-sm bg-surface-900 rounded-2xl border border-slate-800/80">
                Проверки по выбранной категории не найдены.
            </div>
        `;
        return;
    }

    const statusStyles = {
        ok: {
            border: 'border-emerald-500/30 bg-surface-900',
            badge: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
            dot: 'bg-emerald-400',
            text: 'text-emerald-400'
        },
        warning: {
            border: 'border-amber-500/30 bg-surface-900',
            badge: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
            dot: 'bg-amber-400',
            text: 'text-amber-400'
        },
        critical: {
            border: 'border-rose-500/40 bg-surface-900 shadow-rose-950/20 shadow-lg',
            badge: 'bg-rose-500/10 text-rose-300 border border-rose-500/30 font-bold',
            dot: 'bg-rose-400 animate-pulse',
            text: 'text-rose-400'
        }
    };

    container.innerHTML = items.map(item => {
        const style = statusStyles[item.status] || statusStyles.warning;
        const isOpen = openChecklistDetailsIds.has(item.id);

        // Action button HTML
        let actionBtnHtml = '';
        if (item.action) {
            const act = item.action;
            if (act.type === 'bulk_sensors_wan') {
                actionBtnHtml = `
                    <button onclick="applyChecklistSensorsZeroInternet(${act.target_block}, 'autonomous_only')"
                            class="px-3 py-1.5 rounded-xl text-xs font-medium transition flex items-center space-x-1.5 ${act.target_block ? 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'}"
                            title="${act.target_block ? 'Блокирует WAN только для устройств с поддержкой локальной работы (сохраняя доступ облачным и погодным службам)' : 'Разрешить выход в интернет устройствам с локальным управлением'}">
                        <i data-lucide="${act.target_block ? 'shield-check' : 'globe'}" class="w-3.5 h-3.5"></i>
                        <span>${escapeHtml(act.label)}</span>
                    </button>
                `;
            } else if (act.type === 'toggle_tv_night') {
                actionBtnHtml = `
                    <button data-mac="${escapeHtml(act.mac)}" data-enable="${Boolean(act.target_enable)}" onclick="toggleChecklistTvNight(this.dataset.mac, this.dataset.enable === 'true')"
                            class="px-3 py-1.5 rounded-xl text-xs font-medium transition flex items-center space-x-1.5 ${act.target_enable ? 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'}">
                        <i data-lucide="${act.target_enable ? 'moon' : 'sun'}" class="w-3.5 h-3.5"></i>
                        <span>${escapeHtml(act.label)}</span>
                    </button>
                `;
            } else if (act.type === 'toggle_quarantine') {
                actionBtnHtml = `
                    <button onclick="toggleChecklistQuarantine(${act.target_enable})"
                            class="px-3 py-1.5 rounded-xl text-xs font-medium transition flex items-center space-x-1.5 ${act.target_enable ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-sm' : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'}">
                        <i data-lucide="${act.target_enable ? 'shield-alert' : 'unlock'}" class="w-3.5 h-3.5"></i>
                        <span>${escapeHtml(act.label)}</span>
                    </button>
                `;
            }
        }

        // Sub-inventory sections per check type
        let subSectionHtml = '';

        // CHECK 2: IoT Sensors Inventory with WAN/LAN controls & observed telemetry
        if (item.id === 'zero_internet_sensors' && item.device_inventory && item.device_inventory.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-3">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-2.5">
                        <div class="flex items-center space-x-2">
                            <i data-lucide="cpu" class="w-4 h-4 text-emerald-400"></i>
                            <span class="text-xs font-bold text-slate-200">Инвентарь IoT & Сенсоров (${item.device_inventory.length} шт.)</span>
                        </div>
                        <div class="text-[11px] text-slate-400">
                            Разделение устройств по возможности локальной работы vs зависимости от облака
                        </div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs border-collapse">
                            <thead>
                                <tr class="border-b border-slate-800/60 text-[11px] text-slate-400">
                                    <th class="py-1.5 px-2.5">Устройство</th>
                                    <th class="py-1.5 px-2.5">Категория / Поддержка LAN</th>
                                    <th class="py-1.5 px-2.5">Обнаруженные домены</th>
                                    <th class="py-1.5 px-2.5 text-center">Выход в WAN</th>
                                    <th class="py-1.5 px-2.5 text-center">Изоляция LAN</th>
                                    <th class="py-1.5 px-2.5">Влияние на работу</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/40">
                                ${item.device_inventory.map(dev => `
                                    <tr class="hover:bg-slate-900/50 transition">
                                        <td class="py-2.5 px-2.5">
                                            <div class="font-medium text-slate-200">${escapeHtml(dev.name)}</div>
                                            <div class="text-[10px] font-mono text-slate-400">${dev.ip}</div>
                                        </td>
                                        <td class="py-2.5 px-2.5">
                                            <span class="px-2 py-0.5 rounded-md text-[10px] font-medium ${dev.badge_color}">${escapeHtml(dev.tier_title)}</span>
                                        </td>
                                        <td class="py-2.5 px-2.5">
                                            <div class="text-[10px] font-mono text-slate-400 max-w-[150px] truncate" title="${escapeHtml(dev.observed_domains.join(', '))}">
                                                ${escapeHtml(dev.observed_domains.join(', '))}
                                            </div>
                                        </td>
                                        <td class="py-2.5 px-2.5 text-center">
                                            ${dev.is_blocked_wan 
                                                ? `<button data-mac="${escapeHtml(dev.mac)}" onclick="toggleChecklistDeviceDirect(this.dataset.mac, 'wan', false)" class="px-2.5 py-1 rounded-lg text-[10px] font-medium bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 inline-flex items-center space-x-1 transition" title="Интернет заблокирован. Нажмите, чтобы разрешить выход">
                                                     <i data-lucide="shield-off" class="w-3 h-3"></i><span>Блок WAN</span>
                                                   </button>`
                                                : `<button data-mac="${escapeHtml(dev.mac)}" onclick="toggleChecklistDeviceDirect(this.dataset.mac, 'wan', true)" class="px-2.5 py-1 rounded-lg text-[10px] font-medium bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 inline-flex items-center space-x-1 transition" title="Интернет разрешен. Нажмите, чтобы заблокировать">
                                                     <i data-lucide="globe" class="w-3 h-3"></i><span>WAN Открыт</span>
                                                   </button>`
                                            }
                                        </td>
                                        <td class="py-2.5 px-2.5 text-center">
                                            ${dev.is_isolated_lan
                                                ? `<span class="px-2 py-0.5 rounded-lg text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-flex items-center space-x-1" title="Изолирован в отдельном сегменте">
                                                     <i data-lucide="lock" class="w-3 h-3"></i><span>Изолирован</span>
                                                   </span>`
                                                : `<span class="px-2 py-0.5 rounded-lg text-[10px] font-medium bg-slate-800 text-slate-400 border border-slate-700 inline-flex items-center space-x-1" title="Подключен к общей сети Bridge0">
                                                     <i data-lucide="unlock" class="w-3 h-3 text-slate-500"></i><span>В Bridge0</span>
                                                   </span>`
                                            }
                                        </td>
                                        <td class="py-2.5 px-2.5 text-[10px]">
                                            ${dev.warning_note
                                                ? `<span class="text-amber-300 font-medium">${escapeHtml(dev.warning_note)}</span>`
                                                : `<span class="text-slate-400">${escapeHtml(dev.impact_wan_block)}</span>`
                                            }
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // CHECK 3: Appliance & Lateral Movement Inventory
        if (item.id === 'appliance_lan_isolation' && item.device_inventory && item.device_inventory.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-3">
                    <div class="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                        <div class="flex items-center space-x-2">
                            <i data-lucide="shield-alert" class="w-4 h-4 text-indigo-400"></i>
                            <span class="text-xs font-bold text-slate-200">Статус изоляции смарт-техники (${item.device_inventory.length} шт.)</span>
                        </div>
                        <div class="text-[11px] text-slate-400">Защита домашних ПК и сетевых дисков (NAS) от взлома IoT</div>
                    </div>
                    <div class="overflow-x-auto">
                        <table class="w-full text-left text-xs border-collapse">
                            <thead>
                                <tr class="border-b border-slate-800/60 text-[11px] text-slate-400">
                                    <th class="py-1.5 px-2.5">Прибор / Устройство</th>
                                    <th class="py-1.5 px-2.5">Тип</th>
                                    <th class="py-1.5 px-2.5 text-center">Изоляция LAN</th>
                                    <th class="py-1.5 px-2.5 text-center">Интернет</th>
                                    <th class="py-1.5 px-2.5">Назначение защиты</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/40">
                                ${item.device_inventory.map(dev => `
                                    <tr class="hover:bg-slate-900/50 transition">
                                        <td class="py-2.5 px-2.5">
                                            <div class="font-medium text-slate-200">${escapeHtml(dev.name)}</div>
                                            <div class="text-[10px] font-mono text-slate-400">${dev.ip}</div>
                                        </td>
                                        <td class="py-2.5 px-2.5">
                                            <span class="px-2 py-0.5 rounded-md text-[10px] font-medium ${dev.badge_color}">${escapeHtml(dev.tier_title)}</span>
                                        </td>
                                        <td class="py-2.5 px-2.5 text-center">
                                            ${dev.is_isolated_lan
                                                ? `<span class="px-2 py-0.5 rounded-lg text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 inline-flex items-center space-x-1" title="Изолирован в отдельном сегменте (Guest Wi-Fi)">
                                                     <i data-lucide="lock" class="w-3 h-3"></i><span>Изолирован</span>
                                                   </span>`
                                                : `<span class="px-2 py-0.5 rounded-lg text-[10px] font-medium bg-slate-800 text-slate-400 border border-slate-700 inline-flex items-center space-x-1" title="В общей сети Bridge0. Для изоляции переключите на Гостевой Wi-Fi">
                                                     <i data-lucide="unlock" class="w-3 h-3 text-slate-500"></i><span>В общей сети</span>
                                                   </span>`
                                            }
                                        </td>
                                        <td class="py-2.5 px-2.5 text-center">
                                            ${dev.is_blocked_wan
                                                ? `<span class="px-2 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-300 border border-rose-500/20">WAN Блок</span>`
                                                : `<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">WAN Доступен</span>`
                                            }
                                        </td>
                                        <td class="py-2.5 px-2.5 text-[10px] text-slate-400">
                                            ${escapeHtml(dev.impact_lan_isolate)}
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // CHECK 4: Cameras & UPnP Inventory
        if (item.id === 'camera_security_upnp' && item.device_inventory && item.device_inventory.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-2.5">
                    <div class="flex items-center justify-between border-b border-slate-800/80 pb-2">
                        <div class="flex items-center space-x-2">
                            <i data-lucide="video" class="w-4 h-4 text-rose-400"></i>
                            <span class="text-xs font-bold text-slate-200">Камеры наблюдения & Видеодомофоны (${item.device_inventory.length} шт.)</span>
                        </div>
                        <div class="text-[11px] text-slate-400">Режим NVR-only блокирует выход в интернет для защиты от китайских облаков</div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        ${item.device_inventory.map(c => `
                            <div class="p-3 rounded-lg bg-surface-900 border border-slate-800/80 flex items-center justify-between gap-2">
                                <div>
                                    <div class="font-medium text-xs text-slate-200">${escapeHtml(c.name)}</div>
                                    <div class="text-[10px] font-mono text-slate-400">${escapeHtml(c.ip)} • ${escapeHtml(c.mac)}</div>
                                </div>
                                <div class="flex items-center space-x-1.5">
                                    <button data-mac="${escapeHtml(c.mac)}" data-block="${!c.is_blocked_wan}" onclick="toggleChecklistDeviceDirect(this.dataset.mac, 'wan', this.dataset.block === 'true')" class="px-2 py-1 rounded text-[10px] font-medium transition ${c.is_blocked_wan ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}" title="Блокировать/разрешить интернет для камеры">
                                        ${c.is_blocked_wan ? 'NVR-only (WAN блок)' : 'WAN открыт'}
                                    </button>
                                    <span class="px-2 py-1 rounded text-[10px] font-medium ${c.is_isolated_lan ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-slate-800 text-slate-400 border border-slate-700'}" title="${c.is_isolated_lan ? 'Изолирована в отдельном сегменте' : 'В общей сети Bridge0'}">
                                        ${c.is_isolated_lan ? '🔒 Изолирована' : 'В Bridge0'}
                                    </span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // CHECK 5: Smart TV Inventory
        if (item.id === 'smart_tv_security' && item.device_inventory && item.device_inventory.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-2.5">
                    <div class="flex items-center justify-between border-b border-slate-800/80 pb-2">
                        <div class="flex items-center space-x-2">
                            <i data-lucide="tv" class="w-4 h-4 text-indigo-400"></i>
                            <span class="text-xs font-bold text-slate-200">Медиаэкраны и Smart TV (${item.device_inventory.length} шт.)</span>
                        </div>
                        <div class="text-[11px] text-slate-400">Пассивный ночной мониторинг пробуждений (WOL/mDNS)</div>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        ${item.device_inventory.map(t => `
                            <div class="p-3 rounded-lg bg-surface-900 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                                <div class="space-y-1.5">
                                    <div class="font-medium text-xs text-slate-200">${escapeHtml(t.name)}</div>
                                    <div class="text-[10px] font-mono text-slate-400">${escapeHtml(t.ip)} • ${escapeHtml(t.mac)}</div>
                                    <div class="flex items-center space-x-1.5 text-[9px]">
                                        ${t.is_isolated_lan 
                                            ? '<span class="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">🔒 Изолирован (Guest)</span>'
                                            : '<span class="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium" title="Подключите ТВ к Гостевой Wi-Fi сети Keenetic для изоляции от ПК">В общей сети (Bridge0)</span>'
                                        }
                                        ${t.is_blocked_wan 
                                            ? '<span class="px-1.5 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-medium">WAN Блок</span>'
                                            : '<span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">WAN Доступен</span>'
                                        }
                                    </div>
                                </div>
                                <div class="flex items-center space-x-1.5 self-end sm:self-auto">
                                    <button data-mac="${escapeHtml(t.mac)}" data-enable="${!t.night_mode_enabled}" onclick="toggleChecklistTvNight(this.dataset.mac, this.dataset.enable === 'true')" class="px-2.5 py-1 rounded text-[10px] font-medium transition ${t.night_mode_enabled ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700'}">
                                        ${t.night_mode_enabled ? '🌙 Ночной мониторинг вкл' : 'Сон выкл'}
                                    </button>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // CHECK 9: Modular Quarantine Controls & Active Quarantined Devices
        if (item.id === 'new_device_quarantine') {
            const qs = item.quarantine_settings || {};
            const qdevs = item.quarantined_devices || [];
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-3">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-800/80 pb-2">
                        <div class="flex items-center space-x-2">
                            <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
                            <span class="text-xs font-bold text-slate-200">Модульные правила автокарантина</span>
                        </div>
                        <span class="text-[10px] text-slate-400">Мгновенное применение к вновь подключившимся гаджетам</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                        <label class="flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition">
                            <div class="space-y-0.5">
                                <div class="text-xs font-semibold text-slate-200">Блокировка WAN</div>
                                <div class="text-[10px] text-slate-400">Запрет выхода в интернет</div>
                            </div>
                            <input type="checkbox" ${qs.quarantine_wan ? 'checked' : ''} onchange="toggleChecklistQuarantineRule('wan', this.checked)" class="rounded bg-slate-800 border-slate-700 text-indigo-600 focus:ring-indigo-500 h-4 w-4">
                        </label>
                        <label class="flex items-center justify-between p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 cursor-pointer hover:border-slate-700 transition">
                            <div class="space-y-0.5">
                                <div class="text-xs font-semibold text-slate-200">Почасовой аудит</div>
                                <div class="text-[10px] text-slate-400">Непрерывный лог до одобрения</div>
                            </div>
                            <input type="checkbox" ${qs.continuous_audit ? 'checked' : ''} onchange="toggleChecklistQuarantineRule('continuous_audit', this.checked)" class="rounded bg-slate-800 border-slate-700 text-indigo-600 focus:ring-indigo-500 h-4 w-4">
                        </label>
                    </div>
                    ${qdevs.length > 0 ? `
                        <div class="pt-2 border-t border-slate-800/60 space-y-2">
                            <div class="text-[11px] font-bold text-amber-400 flex items-center space-x-1.5">
                                <i data-lucide="clock" class="w-3.5 h-3.5"></i>
                                <span>Устройства под карантинным наблюдением (${qdevs.length} шт.):</span>
                            </div>
                            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                ${qdevs.map(qd => `
                                    <div class="p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 flex items-center justify-between">
                                        <div>
                                            <div class="font-medium text-xs text-slate-200">${escapeHtml(qd.name)}</div>
                                            <div class="text-[10px] font-mono text-slate-400">${escapeHtml(qd.ip)} • ${escapeHtml(qd.mac)}</div>
                                            <div class="text-[9px] text-slate-500">Домены: ${qd.observed_domains && qd.observed_domains.length > 0 ? escapeHtml(qd.observed_domains.join(', ')) : 'DNS-запросов нет'}</div>
                                        </div>
                                        <div class="flex items-center space-x-1">
                                            <button data-mac="${escapeHtml(qd.mac)}" onclick="openDeviceModal(this.dataset.mac)" class="px-2 py-1 rounded bg-indigo-600/20 text-indigo-300 text-[10px] hover:bg-indigo-600/30 transition">
                                                Проверить
                                            </button>
                                        </div>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // CHECK 10: Randomized MAC Devices
        if (item.id === 'arp_scan_spoofing' && item.random_mac_devices && item.random_mac_devices.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-2">
                    <div class="flex items-center space-x-2 border-b border-slate-800/60 pb-2">
                        <i data-lucide="alert-triangle" class="w-4 h-4 text-amber-400"></i>
                        <span class="text-xs font-bold text-amber-300">Обнаруженные устройства со случайным MAC-адресом (${item.random_mac_devices.length} шт.)</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                        ${item.random_mac_devices.map(d => `
                            <div class="p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 space-y-0.5">
                                <div class="font-medium text-xs text-slate-200 truncate">${escapeHtml(d.name)}</div>
                                <div class="text-[10px] font-mono text-slate-400">${d.ip} • ${d.mac}</div>
                                <div class="text-[9px] text-amber-400/90 font-mono">Частный LAA MAC (рекомендуется выключить)</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        // CHECK 11: Hardware L2 Segmentation Devices at Risk
        if (item.id === 'hardware_segmentation' && item.devices_at_risk && item.devices_at_risk.length > 0) {
            subSectionHtml = `
                <div class="mt-3.5 p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-2">
                    <div class="flex items-center space-x-2 border-b border-slate-800/60 pb-2">
                        <i data-lucide="shield-alert" class="w-4 h-4 text-rose-400"></i>
                        <span class="text-xs font-bold text-rose-300">Устройства в зоне риска в Bridge0 (L2-обход файрвола, ${item.devices_at_risk.length} шт.)</span>
                    </div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                        ${item.devices_at_risk.map(d => `
                            <div class="p-2.5 rounded-lg bg-surface-900 border border-slate-800/80 space-y-0.5">
                                <div class="font-medium text-xs text-slate-200 truncate">${escapeHtml(d.name)}</div>
                                <div class="text-[10px] font-mono text-slate-400">${d.ip || 'No IP'} • ${d.mac}</div>
                                <div class="text-[9px] text-rose-400/90 font-mono">Профиль: ${d.profile} • Рекомендуется вынос в Guest Wi-Fi</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return `
            <div class="bg-surface-900 border ${style.border} rounded-2xl p-5 space-y-4 shadow-sm transition hover:border-slate-700">
                <!-- Top Row: Icon, Title, Status, Action -->
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3.5">
                    <div class="flex items-center space-x-3.5">
                        <div class="p-2.5 rounded-xl ${style.badge}">
                            <i data-lucide="${item.icon}" class="w-5 h-5"></i>
                        </div>
                        <div>
                            <div class="flex items-center space-x-2">
                                <span class="text-[10px] uppercase font-bold tracking-wider text-slate-400 px-2 py-0.5 rounded bg-surface-950 border border-slate-800">${escapeHtml(item.category_title)}</span>
                                <h3 class="font-bold text-sm text-white">${escapeHtml(item.title)}</h3>
                            </div>
                            <div class="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
                                <span class="flex items-center space-x-1.5 px-2 py-0.5 rounded-md ${style.badge} text-[11px] font-medium">
                                    <span class="w-1.5 h-1.5 rounded-full ${style.dot}"></span>
                                    <span>${escapeHtml(item.status_label)}</span>
                                </span>
                                <span class="text-slate-300 font-mono text-[11px]">${escapeHtml(item.live_status)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2 self-end sm:self-auto shrink-0">
                        ${actionBtnHtml}
                    </div>
                </div>

                <!-- Live Context & Why it matters / Manual Guide -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs">
                    <div class="p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 space-y-1.5">
                        <span class="text-[11px] font-bold text-indigo-400 flex items-center space-x-1.5">
                            <i data-lucide="info" class="w-3.5 h-3.5"></i>
                            <span>Зачем это нужно:</span>
                        </span>
                        <p class="text-slate-300 leading-relaxed text-[11px]">${escapeHtml(item.why_it_matters)}</p>
                    </div>

                    <!-- Manual KeeneticOS Instructions Accordion -->
                    <details data-check-id="${item.id}" ${isOpen ? 'open' : ''} ontoggle="handleChecklistDetailsToggle('${item.id}', this.open)" class="p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 text-xs text-slate-300 group">
                        <summary class="cursor-pointer list-none select-none flex items-center justify-between font-semibold text-slate-200">
                            <span class="flex items-center space-x-1.5 text-[11px] text-amber-400">
                                <i data-lucide="sliders" class="w-3.5 h-3.5"></i>
                                <span>Пошаговая настройка в KeeneticOS (вручную)</span>
                            </span>
                        <span class="flex items-center space-x-1 text-[10px] text-slate-400">
                            <span class="group-open:hidden">Развернуть</span>
                            <span class="hidden group-open:inline">Свернуть</span>
                            <span class="inline-block group-open:rotate-180 transition-transform duration-200">▼</span>
                        </span>
                        </summary>
                        <div class="mt-2.5 pt-2.5 border-t border-slate-800/80 space-y-1 font-mono text-[10px] text-slate-300 leading-relaxed">
                            ${item.manual_guide.map(g => `<div>${escapeHtml(g)}</div>`).join('')}
                        </div>
                    </details>
                </div>

                <!-- Granular Device Inventory / Controls Sub-Card -->
                ${subSectionHtml}
            </div>
        `;
    }).join('');

    lucide.createIcons();
}



async function applyChecklistSensorsZeroInternet(targetBlock, mode = 'autonomous_only') {
    try {
        const res = await fetch('/api/security/checklist/apply-sensors-zero-internet', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ block: targetBlock, mode: mode })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const modeDesc = mode === 'autonomous_only' ? ' (для устройств с поддержкой локального управления)' : '';
        alert(`Режим Zero-Internet ${targetBlock ? 'включен' : 'отключен'}${modeDesc} для ${data.updated_count} устройств!`);
        await loadSecurity();
    } catch (e) {
        alert(`Ошибка настройки датчиков: ${e.message}`);
    }
}



async function toggleChecklistTvNight(mac, targetEnable) {
    try {
        const res = await fetch(`/api/devices/${mac}/toggle_night`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: targetEnable })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await loadSecurity();
    } catch (e) {
        alert(`Ошибка переключения ночного режима: ${e.message}`);
    }
}

async function toggleChecklistQuarantine(targetEnable) {
    try {
        const res = await fetch('/api/security/checklist/toggle-quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enable: targetEnable })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        alert(`Автокарантин новых устройств ${targetEnable ? 'включен' : 'отключен'}!`);
        await loadSecurity();
    } catch (e) {
        alert(`Ошибка настройки автокарантина: ${e.message}`);
    }
}

async function toggleChecklistQuarantineRule(rule, enabled) {
    try {
        const res = await fetch('/api/security/checklist/toggle-quarantine-rule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule: rule, enabled: enabled })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await loadSecurity();
    } catch (e) {
        alert(`Ошибка переключения правила автокарантина: ${e.message}`);
    }
}

async function toggleChecklistDeviceDirect(mac, target, enabled) {
    try {
        const res = await fetch('/api/security/checklist/device-toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac: mac, target: target, enabled: enabled })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await loadSecurity();
    } catch (e) {
        alert(`Ошибка переключения ${target.toUpperCase()} для ${mac}: ${e.message}`);
    }
}


// --- Interactive Security Wizard Logic ---
let currentWizardStep = 1;

function openSecurityWizard() {
    currentWizardStep = 1;
    wizardSetStep(1);
    const feedback = document.getElementById('wizard-apply-feedback');
    if (feedback) feedback.classList.add('hidden');
    const modal = document.getElementById('security-wizard-modal');
    if (modal) {
        modal.classList.remove('hidden');
        if (window.lucide) lucide.createIcons();
    }
}

function closeSecurityWizard() {
    const modal = document.getElementById('security-wizard-modal');
    if (modal) modal.classList.add('hidden');
}

function wizardSetStep(step) {
    currentWizardStep = step;
    for (let i = 1; i <= 5; i++) {
        const pane = document.getElementById(`wizard-step-view-${i}`);
        const indicator = document.getElementById(`wizard-step-indicator-${i}`);
        if (pane) {
            if (i === step) {
                pane.classList.remove('hidden');
            } else {
                pane.classList.add('hidden');
            }
        }
        if (indicator) {
            const badge = indicator.querySelector('span:first-child');
            if (i === step) {
                indicator.className = 'wizard-step-pill flex items-center space-x-1.5 text-indigo-400 font-semibold';
                if (badge) {
                    badge.className = 'w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-[11px] font-bold shadow-sm shadow-indigo-600/50';
                    badge.textContent = String(i);
                }
            } else if (i < step) {
                indicator.className = 'wizard-step-pill flex items-center space-x-1.5 text-emerald-400 font-medium';
                if (badge) {
                    badge.className = 'w-5 h-5 rounded-full bg-emerald-600/30 border border-emerald-500/50 text-emerald-300 flex items-center justify-center text-[11px]';
                    badge.innerHTML = '✓';
                }
            } else {
                indicator.className = 'wizard-step-pill flex items-center space-x-1.5 text-slate-500';
                if (badge) {
                    badge.className = 'w-5 h-5 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center text-[11px]';
                    badge.textContent = String(i);
                }
            }
        }
    }

    const prevBtn = document.getElementById('wizard-btn-prev');
    const nextBtn = document.getElementById('wizard-btn-next');

    if (prevBtn) {
        if (step > 1) prevBtn.classList.remove('hidden');
        else prevBtn.classList.add('hidden');
    }

    if (nextBtn) {
        if (step === 5) {
            nextBtn.innerHTML = `
                <i data-lucide="check" class="w-3.5 h-3.5"></i>
                <span>Применить политики</span>
            `;
            nextBtn.className = 'px-5 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs rounded-xl font-medium transition flex items-center space-x-1.5 shadow-md shadow-emerald-600/30';
            // Sync summaries
            const tvChecked = document.getElementById('wizard-opt-tv-night')?.checked ?? true;
            const sensorsChecked = document.getElementById('wizard-opt-zero-internet')?.checked ?? true;
            const sumTv = document.getElementById('wizard-sum-tv');
            const sumSensors = document.getElementById('wizard-sum-sensors');
            if (sumTv) {
                sumTv.textContent = tvChecked ? 'Включен' : 'Отключен';
                sumTv.className = tvChecked ? 'text-emerald-400 font-semibold font-mono' : 'text-slate-500 font-mono';
            }
            if (sumSensors) {
                sumSensors.textContent = sensorsChecked ? 'Включен' : 'Отключен';
                sumSensors.className = sensorsChecked ? 'text-emerald-400 font-semibold font-mono' : 'text-slate-500 font-mono';
            }
        } else {
            nextBtn.innerHTML = `
                <span>Далее</span>
                <i data-lucide="arrow-right" class="w-3.5 h-3.5" id="wizard-btn-next-icon"></i>
            `;
            nextBtn.className = 'px-5 py-2 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white text-xs rounded-xl font-medium transition flex items-center space-x-1.5 shadow-md shadow-indigo-600/30';
        }
    }

    if (window.lucide) lucide.createIcons();
}

function wizardNextStep() {
    if (currentWizardStep < 5) {
        wizardSetStep(currentWizardStep + 1);
    } else {
        applySecurityWizard();
    }
}

function wizardPrevStep() {
    if (currentWizardStep > 1) {
        wizardSetStep(currentWizardStep - 1);
    }
}

function copyWizardRule(ruleType) {
    let text = '';
    if (ruleType === 'firewall') {
        text = 'Home -> IoT: Permit (Любые протоколы)\nIoT -> Home: Drop (Запретить входящие)';
    } else if (ruleType === 'adguard_doh') {
        text = 'https://dns.adguard-dns.com/dns-query';
    }
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        alert('Правило скопировано в буфер обмена!');
    }).catch(() => {
        prompt('Скопируйте значение вручную:', text);
    });
}

async function applySecurityWizard() {
    const nextBtn = document.getElementById('wizard-btn-next');
    const feedback = document.getElementById('wizard-apply-feedback');
    if (nextBtn) {
        nextBtn.disabled = true;
        nextBtn.innerHTML = '<i data-lucide="loader-2" class="w-3.5 h-3.5 animate-spin"></i><span>Применение...</span>';
    }

    const payload = {
        tv_night_mode: Boolean(document.getElementById('wizard-opt-tv-night')?.checked),
        zero_internet_sensors: Boolean(document.getElementById('wizard-opt-zero-internet')?.checked),
        quarantine_enabled: Boolean(document.getElementById('wizard-opt-quarantine')?.checked),
        quarantine_continuous: Boolean(document.getElementById('wizard-opt-quarantine')?.checked)
    };

    try {
        const res = await fetch('/api/security/wizard/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            if (feedback) {
                feedback.className = 'p-3 rounded-xl text-xs font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center space-x-2';
                feedback.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 shrink-0 text-emerald-400"></i><span>${escapeHtml(data.message || 'Политики успешно применены!')} Обновлено устройств: TV=${Number(data.tv_updated_count || 0)}, Сенсоров=${Number(data.sensors_blocked_count || 0)}.</span>`;
                feedback.classList.remove('hidden');
                if (window.lucide) lucide.createIcons();
            }
            if (nextBtn) {
                nextBtn.innerHTML = '<i data-lucide="check" class="w-3.5 h-3.5"></i><span>Применено!</span>';
            }
            if (typeof loadSecurity === 'function') {
                setTimeout(loadSecurity, 600);
            }
            setTimeout(() => {
                closeSecurityWizard();
                if (nextBtn) nextBtn.disabled = false;
            }, 1800);
        } else {
            throw new Error(data.detail || 'Не удалось применить настройки');
        }
    } catch (e) {
        if (feedback) {
            feedback.className = 'p-3 rounded-xl text-xs font-medium bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center space-x-2';
            feedback.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4 shrink-0 text-rose-400"></i><span>Ошибка: ${escapeHtml(e.message)}</span>`;
            feedback.classList.remove('hidden');
            if (window.lucide) lucide.createIcons();
        }
        if (nextBtn) {
            nextBtn.disabled = false;
            nextBtn.innerHTML = '<span>Попробовать снова</span>';
        }
    }
}

