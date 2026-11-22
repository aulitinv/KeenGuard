// ==========================================
// Smart Home & IoT Management Tab Logic
// ==========================================
let smarthomeOverviewData = null;
let lastRenderedSmarthomeJson = null;
window.currentSmarthomeHubMac = null;

async function loadSmartHome() {
    try {
        const res = await fetch('/api/smarthome/overview');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        smarthomeOverviewData = data;

        const stats = data.stats || {};

        // 1. Metric Cards
        const statTotal = document.getElementById('sh-stat-total');
        const statOnline = document.getElementById('sh-stat-online');
        const statZero = document.getElementById('sh-stat-zero-count');
        const statZeroTotal = document.getElementById('sh-stat-zero-total');
        const statCloud = document.getElementById('sh-stat-cloud-count');
        const badge = document.getElementById('smarthome-count-badge');

        if (statTotal) statTotal.textContent = stats.total_devices || 0;
        if (statOnline) statOnline.textContent = `${stats.online_devices || 0} онлайн`;
        if (statZero) statZero.textContent = stats.zero_internet_devices || 0;
        if (statZeroTotal) statZeroTotal.textContent = `из ${stats.total_devices || 0} устройств`;
        if (statCloud) statCloud.textContent = stats.cloud_connections_count || 0;

        if (badge) {
            badge.textContent = stats.total_devices || 0;
            if (stats.total_devices > 0) {
                badge.classList.remove('hidden');
            } else {
                badge.classList.add('hidden');
            }
        }

        // 2. Hub Stat Card & SprutHub section
        const hubStatName = document.getElementById('sh-stat-hub-name');
        const hubStatStatus = document.getElementById('sh-stat-hub-status');
        const hubStatIp = document.getElementById('sh-stat-hub-ip');
        const hubTitle = document.getElementById('sh-hub-title');
        const hubMeta = document.getElementById('sh-hub-meta');
        const hubCard = document.getElementById('sh-hub-card');

        if (data.hub) {
            window.currentSmarthomeHubMac = data.hub.mac;
            const hName = data.hub.custom_name || data.hub.hostname || 'SprutHub';
            if (hubStatName) hubStatName.textContent = hName;
            if (hubStatStatus) {
                hubStatStatus.textContent = data.hub.is_online ? 'В сети' : 'Не в сети';
                hubStatStatus.className = data.hub.is_online
                    ? 'text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-medium'
                    : 'text-xs px-2 py-0.5 rounded-full bg-slate-700 text-slate-400 font-medium';
            }
            if (hubStatIp) hubStatIp.textContent = data.hub.ip || 'Нет IP';
            if (hubTitle) hubTitle.textContent = `${hName} (Контроллер умного дома)`;
            if (hubMeta) {
                hubMeta.textContent = `IP: ${data.hub.ip || '—'} | MAC: ${data.hub.mac || 'LAN Gateway'} | Производитель: ${data.hub.vendor || 'SprutHub'}`;
            }
            if (hubCard) hubCard.classList.remove('hidden');
        } else {
            window.currentSmarthomeHubMac = null;
            if (hubStatName) hubStatName.textContent = 'Не обнаружен';
            if (hubStatStatus) {
                hubStatStatus.textContent = '—';
                hubStatStatus.className = 'text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-medium';
            }
            if (hubStatIp) hubStatIp.textContent = '—';
            if (hubCard) hubCard.classList.add('hidden');
        }

        // 3. Render Categorized Device Sections & Cloud Table if data changed
        const currentSmarthomeJson = JSON.stringify({
            categories: data.categories,
            cloud: data.cloud_connections
        });
        const shContainer = document.getElementById('sh-categories-container');
        if (currentSmarthomeJson !== lastRenderedSmarthomeJson || !shContainer || shContainer.children.length === 0) {
            lastRenderedSmarthomeJson = currentSmarthomeJson;
            renderSmartHomeCategories(data.categories || {}, data.cloud_connections || []);
            renderSmartHomeCloudTable(data.cloud_connections || []);
            lucide.createIcons();
        }

        // 4. Load IoT Payload Forensics Table
        loadIotPayloads();
    } catch (e) {
        console.error('Error loading smart home overview', e);
    }
}

function renderSmartHomeCategories(categories, cloudConns) {
    const container = document.getElementById('sh-categories-container');
    if (!container) return;

    // Map cloud connection counts by MAC
    const cloudCountByMac = {};
    cloudConns.forEach(c => {
        if (c.mac) {
            cloudCountByMac[c.mac] = (cloudCountByMac[c.mac] || 0) + 1;
        }
    });

    // Desired category ordering
    const order = ['controllers', 'garden', 'climate', 'sensors', 'appliances', 'security', 'other'];

    const emptyMessages = {
        controllers: 'Контроллеры умного дома не обнаружены. Проверьте подключение хаба SprutHub или Home Assistant.',
        garden: 'Датчики автополива и влажности почвы не обнаружены. При подключении устройств с ключевыми словами soil, garden, полив, огород они появятся здесь автоматически.',
        climate: 'Климатические устройства (кондиционеры, увлажнители, очистители) не обнаружены.',
        sensors: 'Датчики температуры, влажности или качества воздуха не обнаружены.',
        appliances: 'Умная бытовая техника (пылесосы, кормушки, посудомойки) не обнаружена.',
        security: 'Камеры видеонаблюдения и охранные сенсоры не обнаружены.',
        other: 'Прочие неклассифицированные IoT-устройства отсутствуют.'
    };

    container.innerHTML = order.map(catKey => {
        const cat = categories[catKey];
        if (!cat) return '';

        const devs = cat.devices || [];
        const count = devs.length;

        let contentHtml = '';
        if (count === 0) {
            contentHtml = `
                <div class="py-4 px-4 rounded-xl border border-dashed border-slate-800/80 text-center text-xs text-slate-500 bg-surface-950/30">
                    ${emptyMessages[catKey] || 'Устройства в этой категории отсутствуют.'}
                </div>
            `;
        } else {
            contentHtml = `
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    ${devs.map(d => renderSmartHomeDeviceCard(d, cat, cloudCountByMac[d.mac] || 0)).join('')}
                </div>
            `;
        }

        return `
            <div class="bg-surface-900 border border-slate-800/80 rounded-2xl p-5 space-y-4">
                <div class="flex items-center justify-between border-b border-slate-800/60 pb-3">
                    <div class="flex items-center space-x-3">
                        <div class="p-2 rounded-xl ${cat.badge_color}">
                            <i data-lucide="${cat.icon}" class="w-4 h-4"></i>
                        </div>
                        <div>
                            <div class="flex items-center space-x-2">
                                <h3 class="font-bold text-sm text-white">${cat.title}</h3>
                                <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">${count}</span>
                            </div>
                            <p class="text-xs text-slate-400 mt-0.5">${cat.description}</p>
                        </div>
                    </div>
                </div>
                ${contentHtml}
            </div>
        `;
    }).join('');
}

function renderSmartHomeDeviceCard(d, cat, cloudCount) {
    const displayName = d.custom_name || d.hostname || d.ip || d.mac;
    const onlineDot = d.is_online ? 'bg-emerald-400' : 'bg-slate-600';
    const onlineText = d.is_online ? 'Online' : 'Offline';
    const isHub = cat.key === 'controllers' || d.profile === 'smart_home_hub';

    return `
        <div class="bg-surface-950 border border-slate-800 hover:border-slate-700 rounded-xl p-4 flex flex-col justify-between transition shadow-sm space-y-3">
            <div>
                <!-- Top row: Name & Online Status -->
                <div class="flex items-start justify-between gap-2">
                    <div class="min-w-0 flex-1">
                        <div class="flex items-center space-x-1.5">
                            <h4 class="font-bold text-sm text-white truncate" title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</h4>
                            ${isHub ? '<span class="px-1.5 py-0.2 rounded text-[9px] bg-indigo-500/20 text-indigo-300 font-bold border border-indigo-500/30">ХАБ</span>' : ''}
                        </div>
                        <p class="text-xs text-slate-400 font-mono truncate">${d.ip || 'Нет IP'} • ${d.mac}</p>
                    </div>
                    <div class="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-900 text-slate-300 border border-slate-800 shrink-0">
                        <span class="w-1.5 h-1.5 rounded-full ${onlineDot}"></span>
                        <span>${onlineText}</span>
                    </div>
                </div>

                <!-- Vendor & Cloud session pill -->
                <div class="mt-2.5 flex items-center justify-between text-xs">
                    <span class="text-slate-400 text-[11px] truncate max-w-[130px]">${escapeHtml(d.vendor || 'IoT Vendor')}</span>
                    ${cloudCount > 0
                        ? `<span class="px-2 py-0.5 rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px] font-medium flex items-center space-x-1" title="Обнаружено ${cloudCount} активных соединений с облачными серверами">
                             <i data-lucide="cloud" class="w-3 h-3"></i>
                             <span>${cloudCount} сессий</span>
                           </span>`
                        : `<span class="px-2 py-0.5 rounded-md bg-slate-900 text-slate-400 border border-slate-800 text-[10px] flex items-center space-x-1">
                             <i data-lucide="shield-check" class="w-3 h-3 text-emerald-400"></i>
                             <span>Без облаков</span>
                           </span>`
                    }
                </div>

                <!-- Security status indicators -->
                <div class="mt-2.5 flex flex-wrap gap-1.5">
                    ${d.is_blocked_wan
                        ? `<span class="px-2 py-0.5 text-[10px] rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium flex items-center space-x-1" title="Доступ в глобальный интернет полностью отключен">
                             <i data-lucide="shield" class="w-3 h-3"></i>
                             <span>Zero-Internet (WAN откл.)</span>
                           </span>`
                        : `<span class="px-2 py-0.5 text-[10px] rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/20 flex items-center space-x-1" title="Устройство может связываться с внешними серверами">
                             <i data-lucide="globe" class="w-3 h-3"></i>
                             <span>Интернет (WAN) открыт</span>
                           </span>`
                    }
                    ${d.is_isolated_lan
                        ? `<span class="px-2 py-0.5 text-[10px] rounded-md bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium flex items-center space-x-1" title="Изолировано от ПК и смартфонов в домашней сети">
                             <i data-lucide="lock" class="w-3 h-3"></i>
                             <span>LAN Изолирован</span>
                           </span>`
                        : `<span class="px-2 py-0.5 text-[10px] rounded-md bg-slate-900 text-slate-400 border border-slate-800 text-[10px] flex items-center space-x-1" title="Доступно в общей домашней сети">
                             <i data-lucide="unlock" class="w-3 h-3 text-slate-500"></i>
                             <span>LAN общий доступ</span>
                           </span>`
                    }
                </div>
            </div>

            <!-- Individual Step-by-Step Reversible Controls -->
            <div class="pt-3 border-t border-slate-800/60 space-y-2">
                <button onclick="toggleSmartHomeWan('${d.mac}', ${!d.is_blocked_wan})"
                        class="w-full px-2 py-1.5 rounded-xl text-xs font-medium transition flex items-center justify-center space-x-1.5 ${d.is_blocked_wan ? 'bg-slate-900 hover:bg-slate-800 text-emerald-400 border border-emerald-500/30' : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30'}"
                        title="${d.is_blocked_wan ? 'Разблокировать интернет: вернуть устройству доступ к облаку' : 'Безопасно заблокировать интернет (Zero-Internet). Опрос хабом SprutHub сохранится.'}">
                    <i data-lucide="${d.is_blocked_wan ? 'unlock' : 'shield-alert'}" class="w-3.5 h-3.5"></i>
                    <span>${d.is_blocked_wan ? 'Разблокировать интернет (Вернуть WAN)' : 'Включить Zero-Internet (Блок WAN)'}</span>
                </button>

                <button onclick="openDeviceModal('${d.mac}')"
                        class="w-full py-1 text-center text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 rounded-lg transition flex items-center justify-center space-x-1">
                    <i data-lucide="sliders" class="w-3 h-3 text-indigo-400"></i>
                    <span>Параметры и аудит трафика →</span>
                </button>
            </div>
        </div>
    `;
}

async function toggleSmartHomeWan(mac, block) {
    try {
        const res = await fetch(`/api/devices/${mac}/toggle_wan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: block })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await loadSmartHome();
    } catch (e) {
        console.error('Error toggling WAN for smart home device', e);
        alert(`Ошибка переключения WAN: ${e.message}`);
    }
}

async function toggleSmartHomeLan(mac, isolate) {
    try {
        const res = await fetch(`/api/devices/${mac}/toggle_lan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: isolate })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (data.needs_physical_segmentation) {
            showToast(data.message, 'warning');
            openIsolationWizard(mac);
        } else if (data.message) {
            showToast(data.message, 'info');
        }
        await loadSmartHome();
    } catch (e) {
        console.error('Error toggling LAN for smart home device', e);
        showToast(`Ошибка переключения LAN: ${e.message}`, 'error');
    }
}

async function openIsolationWizard(mac) {
    if (!mac) return;
    const modal = document.getElementById('isolation-wizard-modal');
    const container = document.getElementById('iso-wizard-steps-container');
    const subtitle = document.getElementById('iso-wizard-device-subtitle');
    if (!modal) return;

    modal.classList.remove('hidden');
    if (container) {
        container.innerHTML = '<div class="py-6 text-center text-slate-500 italic text-xs">Загрузка информации об устройстве и топологии...</div>';
    }

    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/isolation_guide`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (subtitle) {
            subtitle.textContent = `${data.name || data.mac} (${data.ip || 'Без IP'}) — ${data.is_wifi ? 'Wi-Fi узел' : 'Кабельный узел'}`;
        }

        if (container) {
            if (data.is_physically_isolated) {
                container.innerHTML = `
                    <div class="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-200 space-y-2">
                        <div class="flex items-center space-x-2 font-bold text-emerald-400">
                            <i data-lucide="check-circle" class="w-4 h-4"></i>
                            <span>Устройство уже аппаратно изолировано!</span>
                        </div>
                        <p class="text-slate-300 text-[11px]">
                            Устройство находится в изолированном сегменте <b>${escapeHtml(data.current_segment)}</b>. Прямой L2-доступ к основной домашней сети заблокирован роутером.
                        </p>
                    </div>
                `;
            } else {
                container.innerHTML = (data.steps || []).map((step, idx) => `
                    <div class="p-3.5 rounded-xl bg-surface-950 border border-slate-800 space-y-1.5">
                        <div class="flex items-center space-x-2">
                            <span class="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-300 flex items-center justify-center text-xs font-bold font-mono">${idx + 1}</span>
                            <span class="text-xs font-semibold text-white">${escapeHtml(step.title)}</span>
                        </div>
                        <p class="text-[11px] text-slate-400 pl-7 leading-relaxed">${escapeHtml(step.desc)}</p>
                    </div>
                `).join('');
            }
            if (window.lucide) lucide.createIcons();
        }
    } catch (e) {
        console.error('Error loading isolation guide:', e);
        if (container) {
            container.innerHTML = `<div class="p-4 text-center text-rose-400 text-xs">Не удалось загрузить рекомендации: ${escapeHtml(e.message)}</div>`;
        }
    }
}

function closeIsolationWizardModal() {
    const modal = document.getElementById('isolation-wizard-modal');
    if (modal) modal.classList.add('hidden');
}
window.openIsolationWizard = openIsolationWizard;
window.closeIsolationWizardModal = closeIsolationWizardModal;

function openSmartHomeHubModal() {
    if (window.currentSmarthomeHubMac) {
        openDeviceModal(window.currentSmarthomeHubMac);
        switchDeviceModalTab('policies');
    } else {
        alert('Контроллер умного дома не обнаружен.');
    }
}

function startSmartHomeHubAudit() {
    if (window.currentSmarthomeHubMac) {
        openDeviceModal(window.currentSmarthomeHubMac);
        switchDeviceModalTab('traffic');
    } else {
        alert('Контроллер умного дома не обнаружен.');
    }
}

function sortSmartHomeCloudConnections(conns) {
    const { col, dir } = tableSortState.smarthome;
    const mult = dir === 'asc' ? 1 : -1;
    const shRiskWeights = { danger: 6, ad: 5, telemetry: 4, warning: 3, info: 2, safe: 1 };

    return [...conns].sort((a, b) => {
        let cmp = 0;
        if (col === 'device') {
            const dA = a.device_name || a.src_ip || '';
            const dB = b.device_name || b.src_ip || '';
            cmp = dA.localeCompare(dB, 'ru');
        } else if (col === 'host') {
            const hA = a.domain || a.dst_ip || '';
            const hB = b.domain || b.dst_ip || '';
            cmp = hA.localeCompare(hB, 'ru');
        } else if (col === 'service') {
            const sA = a.cloud_vendor || a.category_title || '';
            const sB = b.cloud_vendor || b.category_title || '';
            cmp = sA.localeCompare(sB, 'ru');
        } else if (col === 'port') {
            cmp = (a.dport || 0) - (b.dport || 0);
        } else if (col === 'risk') {
            const rA = shRiskWeights[a.risk_level] || 0;
            const rB = shRiskWeights[b.risk_level] || 0;
            cmp = rA - rB;
        }
        return cmp * mult;
    });
}

function renderSmartHomeCloudTable(cloudConns) {
    if (cloudConns && Array.isArray(cloudConns)) {
        allShCloudConnections = cloudConns;
    }
    const conns = allShCloudConnections || [];
    const tbody = document.getElementById('sh-cloud-table-body');
    const countEl = document.getElementById('sh-cloud-table-count');
    if (countEl) countEl.textContent = `${conns.length} соединений`;
    if (!tbody) return;

    if (conns.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="py-8 text-center text-slate-500 text-xs">
                    Внешние облачные соединения умных устройств не обнаружены (все устройства отрезаны от облака или спят).
                </td>
            </tr>
        `;
        return;
    }

    const sorted = sortSmartHomeCloudConnections(conns);

    const riskBadges = {
        safe: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
        info: 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20',
        warning: 'bg-purple-500/10 text-purple-400 border border-purple-500/20',
        telemetry: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
        ad: 'bg-pink-500/10 text-pink-400 border border-pink-500/20',
        danger: 'bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold'
    };

    tbody.innerHTML = sorted.map(c => {
        const riskClass = riskBadges[c.risk_level] || riskBadges.warning;
        return `
            <tr class="border-b border-slate-800/40 hover:bg-surface-950/40 transition">
                <td class="py-2.5 px-3">
                    <div class="font-medium text-slate-200">${escapeHtml(c.device_name)}</div>
                    <div class="text-[11px] text-slate-400 font-mono">${c.src_ip}</div>
                </td>
                <td class="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                    <div class="truncate max-w-[200px]" title="${escapeHtml(c.domain)}">${escapeHtml(c.domain)}</div>
                    <div class="text-[10px] text-slate-500">${c.dst_ip}</div>
                </td>
                <td class="py-2.5 px-3 text-slate-300">
                    <div class="font-medium">${escapeHtml(c.cloud_vendor)}</div>
                    <div class="text-[10px] text-slate-500">${escapeHtml(c.category_title)}</div>
                </td>
                <td class="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                    ${c.dport} / ${c.protocol}
                </td>
                <td class="py-2.5 px-3">
                    <span class="px-2 py-0.5 rounded-full text-[10px] ${riskClass}">${c.risk_level.toUpperCase()}</span>
                </td>
                <td class="py-2.5 px-3 text-right">
                    ${c.is_blocked_wan 
                        ? `<span class="text-[10px] text-emerald-400 font-medium">WAN заблокирован</span>`
                        : `<button onclick="toggleSmartHomeWan('${c.mac}', true)" class="px-2 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-medium transition" title="Заблокировать выход в интернет для этого устройства">
                             Блок WAN
                           </button>`
                    }
                </td>
            </tr>
        `;
    }).join('');

    updateSortIndicators('smarthome');
}

