// Data Loaders
async function refreshAllData() {
    await Promise.allSettled([
        loadStatus(),
        loadDevices(),
        loadUpnp(),
        loadEvents()
    ]);
    if (activeTab === 'dashboard') {
        loadWifiAudit();
        checkRouterUpdates();
        updateLiveTrafficChart();
        loadSecurityScoreForDashboard();
        loadL7TrafficSummary();
    } else if (activeTab === 'dns') {
        if (typeof activeDnsSubTab !== 'undefined' && activeDnsSubTab === 'filter') {
            loadDnsFilterTab();
        } else {
            loadDnsQueries();
        }
    } else if (activeTab === 'audits') {
        loadTrafficAuditsTab();
    } else if (activeTab === 'smarthome') {
        loadSmartHome();
    } else if (activeTab === 'lan') {
        loadLanTab();
    } else if (activeTab === 'packets') {
        loadPacketInspectorLive();
    } else if (activeTab === 'security') {
        loadSecurity();
    } else if (activeTab === 'rules') {
        if (typeof loadRules === 'function' && !hasUnsavedRuleChanges) loadRules();
    }

    if (typeof updateRulesBadgeOnly === 'function') {
        updateRulesBadgeOnly();
    }
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
        if (!data || !data.router) return;
        currentRouterInfo = data.router;
        if (currentRouterInfo) {
            const rName = currentRouterInfo.model || 'Keenetic';
            const rIps = currentRouterInfo.router_ips || [currentRouterInfo.host || '192.168.1.1'];
            rIps.forEach(ip => deviceNameCache.registerMapping(ip, null, rName));
            (currentRouterInfo.router_macs || []).forEach(mac => deviceNameCache.registerMapping(null, mac, rName));
        }
        reRenderSnifferFeed();

        // Router status badge & alert banner
        const rDot = document.getElementById('router-status-dot');
        const rText = document.getElementById('router-status-text');
        const banner = document.getElementById('router-alert-banner');
        const bannerDesc = document.getElementById('router-alert-desc');

        const isRouterConnected = data.router.connected || data.router.status === 'ok';

        if (isRouterConnected) {
            rDot.className = 'w-2 h-2 rounded-full bg-emerald-400';
            rText.textContent = `${data.router.model || 'Keenetic'} (${data.router.version || 'KeeneticOS'})`;
            rText.className = 'text-emerald-400 font-medium';
            if (banner) banner.classList.add('hidden');
        } else {
            rDot.className = 'w-2 h-2 rounded-full bg-rose-500 animate-ping';
            rText.textContent = 'Роутер отключен';
            rText.className = 'text-rose-400 font-medium';
            if (banner) {
                banner.classList.remove('hidden');
                if (bannerDesc) bannerDesc.textContent = data.router.error || 'Потеряна связь с Keenetic API. Проверьте питание или подключение к сети.';
            }
        }

        // Platform title, model, and channel in Firmware card
        const isOwr = data.router.platform === 'openwrt';
        safeSetText('router-card-title', `Статус прошивки ${isOwr ? 'OpenWrt' : 'KeeneticOS'}`);
        safeSetText('router-card-model', data.router.model || (isOwr ? 'OpenWrt Device' : 'Keenetic'));
        safeSetText('router-card-channel', data.router.channel || (isOwr ? 'Официальный релиз OpenWrt' : 'Официальный релиз'));

        // WAN IP
        safeSetText('router-wan-ip', data.router.wan_ip || '—');

        // Firmware / OS version
        const osVer = data.router.version || '—';
        safeSetText('router-os-version', osVer);
        safeSetText('router-card-version', osVer);

        // Live Sniffer Mode
        safeSetText('sniffer-active-mode', data.sniffer?.mode === 'active' ? 'ACTIVE (Pcap/Raw)' : 'INACTIVE');

        // Memory usage
        if (data.router.memory && typeof data.router.memory.total_mb === 'number') {
            safeSetText('router-mem-usage', `${data.router.memory.used_mb} / ${data.router.memory.total_mb} МБ`);
        } else {
            safeSetText('router-mem-usage', '—');
        }

        // Active Devices Count
        const activeCount = data.router.active_hosts !== undefined ? data.router.active_hosts : (data.online_devices !== undefined ? data.online_devices : '—');
        safeSetText('router-active-devices', activeCount);

        // Night mode
        const nText = document.getElementById('night-status-text');
        if (data.night_mode) {
            nText.textContent = 'Ночной режим: АКТИВЕН';
            nText.className = 'text-indigo-400 font-bold';
        } else {
            nText.textContent = 'Ночной режим: День';
            nText.className = 'text-slate-300';
        }

        const onlineHosts = data.online_devices !== undefined ? data.online_devices : (devicesList.filter(d => d.is_online).length || 0);
        safeSetText('stat-online-devices', onlineHosts);
        const totalHosts = data.total_devices !== undefined ? data.total_devices : (devicesList.length || 0);
        safeSetText('stat-total-devices', `из ${totalHosts} хостов`);
        safeSetText('device-count-badge', totalHosts);
        document.getElementById('device-count-badge').textContent = data.total_devices;

        // Alerts count
        const alertBadge = document.getElementById('alerts-count-badge');
        if (data.critical_alerts > 0) {
            alertBadge.textContent = data.critical_alerts;
            alertBadge.classList.remove('hidden');
        } else {
            alertBadge.classList.add('hidden');
        }

    } catch (e) {
        console.error('Error fetching status', e);
    }
}

async function loadDevices() {
    try {
        const res = await fetch('/api/devices');
        devicesList = await res.json();
        deviceNameCache.registerDevices(devicesList);
        const devBadge = document.getElementById('device-count-badge');
        if (devBadge) devBadge.textContent = devicesList.length;
        const shBadge = document.getElementById('smarthome-count-badge');
        const shCount = devicesList.filter(d => ['smart_home_hub', 'iot', 'camera'].includes(d.profile)).length;
        if (shBadge && shCount > 0) {
            shBadge.textContent = shCount;
            shBadge.classList.remove('hidden');
        }
        applyDeviceFiltersAndRender();
        renderProfileBreakdown(devicesList);
        reRenderSnifferFeed();
    } catch (e) {
        console.error('Error loading devices', e);
    }
}

function renderProfileBreakdown(devices) {
    const list = document.getElementById('profile-breakdown-list');
    if (!list) return;

    const counts = {};
    Object.keys(PROFILES).forEach(k => { counts[k] = 0; });
    devices.forEach(d => {
        counts[d.profile] = (counts[d.profile] || 0) + 1;
    });

    list.innerHTML = Object.entries(PROFILES).map(([key, prof]) => {
        const count = counts[key] || 0;
        return `
            <div class="flex items-center justify-between p-2 rounded-xl bg-surface-950/60 border border-slate-800/60">
                <div class="flex items-center space-x-2.5">
                    <div class="p-1.5 rounded-lg ${prof.bg} ${prof.color}">
                        <i data-lucide="${prof.icon}" class="w-4 h-4"></i>
                    </div>
                    <span class="text-xs text-slate-300 font-medium">${prof.name}</span>
                </div>
                <span class="text-xs font-bold ${count > 0 ? 'text-white' : 'text-slate-500'}">${count}</span>
            </div>
        `;
    }).join('');
    lucide.createIcons();
}


// Wi-Fi Security Audit
async function loadWifiAudit() {
    try {
        const res = await fetch('/api/security/wifi');
        const data = await res.json();

        // 0. Update Card Subtitle
        const wifiSub = document.getElementById('wifi-card-subtitle');
        if (wifiSub) {
            const pName = data.platform === 'openwrt' ? 'OpenWrt' : (currentRouterInfo?.platform === 'openwrt' ? 'OpenWrt' : 'Keenetic');
            wifiSub.textContent = `Аудит радиоинтерфейсов ${pName}`;
        }

        // 1. Grade Badge
        const gradeBadge = document.getElementById('wifi-grade-badge');
        if (gradeBadge) {
            gradeBadge.textContent = `${data.grade} (${data.score}%)`;
            if (data.score >= 90) {
                gradeBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
            } else if (data.score >= 70) {
                gradeBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30';
            } else {
                gradeBadge.className = 'px-2.5 py-0.5 rounded-full text-xs font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30';
            }
        }

        // 2. Active Networks List
        const netList = document.getElementById('wifi-networks-list');
        const aps = (data.access_points && data.access_points.length > 0) ? data.access_points : (data.networks || []);
        if (netList) {
            if (aps.length > 0) {
                netList.innerHTML = aps.map(ap => {
                    const sec = ap.security || ap.encryption || 'WPA2-PSK';
                    const isWpa3 = sec.includes('WPA3');
                    const isOpen = sec.includes('Открытая') || ap.security_type === 'open' || ap.risk_level === 'critical';

                    let badgeClass = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
                    let iconName = 'shield-check';

                    if (isOpen) {
                        badgeClass = 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse';
                        iconName = 'shield-alert';
                    } else if (!isWpa3) {
                        badgeClass = 'bg-sky-500/15 text-sky-300 border-sky-500/30';
                        iconName = 'shield';
                    }

                    // Determine band with OpenWrt and Keenetic fallback
                    let bandText = ap.band;
                    if (!bandText) {
                        const iface = (ap.interface || '').toLowerCase();
                        const dev = (ap.device || '').toLowerCase();
                        const ssidLower = (ap.ssid || '').toLowerCase();
                        if (iface.includes('wifimaster1') || iface.includes('5g') || dev.includes('5g') || dev === 'radio0' || ssidLower.includes('5g')) {
                            bandText = '5 ГГц';
                        } else {
                            bandText = '2.4 ГГц';
                        }
                    }

                    return `
                        <div class="flex items-center justify-between bg-surface-950/70 border border-slate-800/70 rounded-xl px-3 py-2 transition hover:border-slate-700">
                            <div class="flex items-center space-x-2.5 min-w-0">
                                <div class="w-2 h-2 rounded-full ${isOpen ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'} shrink-0"></div>
                                <div class="min-w-0">
                                    <div class="flex items-center space-x-1.5">
                                        <span class="font-semibold text-xs text-white truncate max-w-[140px] sm:max-w-[200px] cursor-help" title="${escapeHtml(ap.ssid)}" data-tooltip="${escapeHtml(ap.ssid)}">${escapeHtml(ap.ssid)}</span>
                                        <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800/90 text-slate-400 shrink-0">${bandText}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="shrink-0 ml-2">
                                <span class="inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-0.5 rounded-lg border ${badgeClass}">
                                    <i data-lucide="${iconName}" class="w-3 h-3"></i>
                                    <span>${escapeHtml(sec)}</span>
                                </span>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                netList.innerHTML = '<div class="text-slate-500 text-xs italic py-2">Беспроводные точки доступа не активны</div>';
            }
        }

        // 3. Micro-indicators
        const wpsStatus = document.getElementById('wifi-wps-status');
        if (wpsStatus) {
            const hasWps = data.access_points && data.access_points.some(a => a.wps);
            if (hasWps) {
                wpsStatus.textContent = '⚠️ Включен';
                wpsStatus.className = 'text-[11px] font-semibold text-amber-400';
            } else {
                wpsStatus.textContent = '✓ Отключен';
                wpsStatus.className = 'text-[11px] font-semibold text-emerald-400';
            }
        }

        const guestStatus = document.getElementById('wifi-guest-status');
        if (guestStatus) {
            if (data.guest_network && data.guest_network.configured) {
                guestStatus.textContent = data.guest_network.isolated ? '✓ Изолирована' : '⚠️ Не изолирована';
                guestStatus.className = data.guest_network.isolated ? 'text-[11px] font-semibold text-emerald-400' : 'text-[11px] font-semibold text-amber-400';
            } else {
                guestStatus.textContent = 'Не настроена';
                guestStatus.className = 'text-[11px] font-semibold text-slate-500';
            }
        }

        const pmfStatus = document.getElementById('wifi-pmf-status');
        if (pmfStatus) {
            const pmfAudit = data.pmf_audit || data.wids?.pmf_audit;
            if (pmfAudit) {
                pmfStatus.textContent = pmfAudit.status === 'ok' ? '✓ Mandatory' : (pmfAudit.status === 'critical' ? '⚠️ Отключен' : '✓ Optional');
                pmfStatus.className = pmfAudit.status === 'ok'
                    ? 'text-[11px] font-semibold text-emerald-400'
                    : (pmfAudit.status === 'critical' ? 'text-[11px] font-semibold text-rose-400' : 'text-[11px] font-semibold text-amber-400');
            } else if (data.pmf_enabled) {
                pmfStatus.textContent = '✓ Mandatory';
                pmfStatus.className = 'text-[11px] font-semibold text-emerald-400';
            } else {
                pmfStatus.textContent = '⚠️ Optional';
                pmfStatus.className = 'text-[11px] font-semibold text-amber-400';
            }
        }

        const widsStatus = document.getElementById('wifi-wids-status');
        if (widsStatus) {
            const threats = (data.threats && data.threats.length > 0) ? data.threats : (data.wids?.all_incidents || []);
            if (threats.length > 0) {
                widsStatus.textContent = `🚨 Угроза (${threats.length})`;
                widsStatus.className = 'text-[11px] font-semibold text-rose-400 animate-pulse';
            } else {
                widsStatus.textContent = '✓ Чистый эфир';
                widsStatus.className = 'text-[11px] font-semibold text-emerald-400';
            }
        }

        // 4. Recommendation Box
        const recElem = document.getElementById('wifi-recommendations');
        const recIcon = document.getElementById('wifi-rec-icon');
        if (recElem) {
            if (data.recommendations && data.recommendations.length > 0) {
                recElem.textContent = data.recommendations[0];
            } else {
                recElem.textContent = 'Все активные Wi-Fi сети защищены современным шифрованием WPA3/WPA2.';
            }
            if (recIcon) {
                if (data.score >= 90) {
                    recIcon.setAttribute('data-lucide', 'shield-check');
                    recIcon.className = 'w-4 h-4 text-emerald-400 shrink-0 mt-0.5';
                } else if (data.score >= 70) {
                    recIcon.setAttribute('data-lucide', 'alert-triangle');
                    recIcon.className = 'w-4 h-4 text-amber-400 shrink-0 mt-0.5';
                } else {
                    recIcon.setAttribute('data-lucide', 'shield-alert');
                    recIcon.className = 'w-4 h-4 text-rose-400 shrink-0 mt-0.5';
                }
            }
        }

        if (window.lucide) {
            lucide.createIcons();
        }
    } catch (e) {
        console.error('Error loading wifi audit', e);
    }
}

// Router Updates
async function checkRouterUpdates() {
    try {
        const res = await fetch('/api/router/updates');
        const data = await res.json();

        const badge = document.getElementById('router-update-badge');
        const msg = document.getElementById('router-update-msg');
        const ver = document.getElementById('router-card-version');
        const channel = document.getElementById('router-card-channel');
        const model = document.getElementById('router-card-model');
        const title = document.getElementById('router-card-title');

        if (ver && data.current_version) ver.textContent = data.current_version;
        if (channel && data.channel) channel.textContent = data.channel;
        if (model && data.model) model.textContent = data.model;
        if (title) {
            const pName = data.platform === 'openwrt' ? 'OpenWrt' : 'KeeneticOS';
            title.textContent = `Статус прошивки ${pName}`;
        }

        const isUpd = data.has_update || data.update_available;
        if (isUpd) {
            if (badge) {
                badge.textContent = 'Доступно обновление!';
                badge.className = 'px-2 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse';
            }
            if (msg) msg.textContent = `Доступна версия ${data.latest_version || ''}`;
        } else {
            if (badge) {
                badge.textContent = 'Актуальна';
                badge.className = 'px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
            }
            if (msg) msg.textContent = data.message || 'Патчи безопасности актуальны';
        }
    } catch (e) {
        console.error('Error checking router updates', e);
    }
}

// Live Network Traffic Chart
async function updateLiveTrafficChart() {
    const ctx = document.getElementById('live-traffic-chart');
    if (!ctx) return;
    try {
        const res = await fetch('/api/traffic/live');
        if (!res.ok) return;
        const data = await res.json();
        if (!Array.isArray(data)) return;

        const labels = data.map(d => new Date(d.timestamp).toLocaleTimeString());
        const rxData = data.map(d => Math.max(0, Math.round(d.total_rx_kbps || 0)));
        const txData = data.map(d => Math.max(0, Math.round(d.total_tx_kbps || 0)));

        if (data.length > 0) {
            const latest = data[data.length - 1];
            const rxElem = document.getElementById('live-rx-rate');
            const txElem = document.getElementById('live-tx-rate');
            if (rxElem) rxElem.textContent = Math.max(0, Math.round(latest.total_rx_kbps || 0));
            if (txElem) txElem.textContent = Math.max(0, Math.round(latest.total_tx_kbps || 0));
        }

        if (liveTrafficChart) {
            liveTrafficChart.data.labels = labels;
            liveTrafficChart.data.datasets[0].data = rxData;
            liveTrafficChart.data.datasets[1].data = txData;
            liveTrafficChart.update('none');
        } else {
            liveTrafficChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Входящий (Kbps)',
                            data: rxData,
                            borderColor: '#34d399',
                            backgroundColor: 'rgba(52, 211, 153, 0.1)',
                            borderWidth: 2,
                            tension: 0.35,
                            fill: true,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                            pointHitRadius: 10
                        },
                        {
                            label: 'Исходящий (Kbps)',
                            data: txData,
                            borderColor: '#38bdf8',
                            backgroundColor: 'rgba(56, 189, 248, 0.1)',
                            borderWidth: 2,
                            tension: 0.35,
                            fill: true,
                            pointRadius: 0,
                            pointHoverRadius: 4,
                            pointHitRadius: 10
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: {
                        mode: 'index',
                        intersect: false
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.95)',
                            titleColor: '#cbd5e1',
                            bodyColor: '#f1f5f9',
                            borderColor: '#334155',
                            borderWidth: 1,
                            padding: 8,
                            displayColors: true
                        }
                    },
                    scales: {
                        x: { display: false },
                        y: {
                            display: true,
                            beginAtZero: true,
                            min: 0,
                            suggestedMax: 10,
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: {
                                color: '#64748b',
                                font: { size: 9 },
                                callback: function(val) {
                                    return val >= 0 ? val : '';
                                }
                            }
                        }
                    }
                }
            });
        }
    } catch (e) {
        console.error('Error updating live traffic chart', e);
    }
}


// ==========================================
// L7 Application Traffic Breakdown
// ==========================================

const L7_CATEGORY_NAMES = {
    streaming: 'Стриминг',
    communication: 'Связь',
    gaming: 'Игры',
    web: 'Веб',
    vpn: 'VPN / Защита',
    system: 'Система',
    p2p: 'P2P / Торренты',
    other: 'Прочее'
};

const L7_CATEGORY_COLORS = {
    streaming: '#8b5cf6',
    communication: '#10b981',
    gaming: '#f59e0b',
    web: '#06b6d4',
    vpn: '#3b82f6',
    system: '#6366f1',
    p2p: '#ec4899',
    other: '#64748b'
};

function getFlowsPlural(n) {
    if (n % 10 === 1 && n % 100 !== 11) return 'поток';
    if ([2, 3, 4].includes(n % 10) && ![12, 13, 14].includes(n % 100)) return 'потока';
    return 'потоков';
}

async function loadL7TrafficSummary() {
    const badgeEl = document.getElementById('l7-active-flows-badge');
    const volumeEl = document.getElementById('l7-total-volume');
    const barEl = document.getElementById('l7-category-bar');
    const legendEl = document.getElementById('l7-category-legend');
    const gridEl = document.getElementById('l7-apps-grid');

    if (!barEl || !gridEl) return;

    try {
        const res = await fetch('/api/traffic/l7-summary');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const totalBytes = data.total_bytes || 0;
        const activeFlows = data.active_flows_count || 0;
        const categories = data.categories_breakdown || [];
        const apps = data.apps_breakdown || [];

        if (badgeEl) {
            badgeEl.textContent = `${activeFlows} активных ${getFlowsPlural(activeFlows)}`;
        }
        if (volumeEl) {
            volumeEl.textContent = `Объем: ${formatBytes(totalBytes)}`;
        }

        // 1. Render Segmented Category Bar
        if (categories.length > 0 && totalBytes > 0) {
            barEl.innerHTML = categories.map(cat => {
                const color = L7_CATEGORY_COLORS[cat.category] || '#64748b';
                const pct = cat.percentage || 0;
                const name = L7_CATEGORY_NAMES[cat.category] || cat.category;
                return `<div style="width: ${pct}%; background-color: ${color};" class="h-full transition-all duration-300" title="${escapeHtml(name)}: ${pct}% (${formatBytes(cat.bytes)})"></div>`;
            }).join('');

            // Category Legend
            legendEl.innerHTML = categories.map(cat => {
                const color = L7_CATEGORY_COLORS[cat.category] || '#64748b';
                const name = L7_CATEGORY_NAMES[cat.category] || cat.category;
                return `
                    <div class="flex items-center space-x-1.5">
                        <span class="w-2.5 h-2.5 rounded-full shrink-0" style="background-color: ${color};"></span>
                        <span class="text-slate-300 font-medium">${escapeHtml(name)}</span>
                        <span class="text-slate-500 font-mono text-[11px]">${cat.percentage}%</span>
                    </div>
                `;
            }).join('');
        } else {
            barEl.innerHTML = `<div class="bg-slate-800 h-full w-full"></div>`;
            legendEl.innerHTML = `<span class="text-slate-500 italic text-[11px]">Ожидание активности сетевых сессий...</span>`;
        }

        // 2. Render Top Applications Grid
        if (apps.length > 0) {
            gridEl.innerHTML = apps.slice(0, 6).map(app => {
                const color = L7_CATEGORY_COLORS[app.category] || '#64748b';
                const catName = L7_CATEGORY_NAMES[app.category] || app.category;
                const iconName = app.icon || 'activity';

                return `
                    <div class="bg-surface-950/70 border border-slate-800 rounded-xl p-3 flex flex-col justify-between hover:border-slate-700 transition">
                        <div class="flex items-start justify-between gap-1 mb-2">
                            <div class="flex items-center space-x-2 min-w-0">
                                <div class="p-1.5 rounded-lg shrink-0" style="background-color: ${color}20; color: ${color};">
                                    <i data-lucide="${escapeHtml(iconName)}" class="w-4 h-4"></i>
                                </div>
                                <div class="min-w-0">
                                    <h4 class="font-bold text-xs text-white truncate" title="${escapeHtml(app.name)}">${escapeHtml(app.name)}</h4>
                                    <span class="text-[10px] text-slate-400 block truncate">${escapeHtml(catName)}</span>
                                </div>
                            </div>
                            <span class="text-xs font-mono font-bold shrink-0" style="color: ${color};">${app.percentage}%</span>
                        </div>
                        <div class="space-y-1.5 pt-1 border-t border-slate-800/60">
                            <div class="flex items-center justify-between text-[11px] font-mono text-slate-400">
                                <span>${formatBytes(app.bytes)}</span>
                                <span class="text-[10px] text-slate-500">${app.flow_count || 1} фл.</span>
                            </div>
                            <div class="w-full h-1.5 rounded-full bg-slate-900 overflow-hidden">
                                <div class="h-full rounded-full" style="width: ${app.percentage}%; background-color: ${color};"></div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        } else {
            gridEl.innerHTML = `<div class="text-slate-500 text-xs italic py-4 col-span-full">Нет активных потоков приложений для отображения.</div>`;
        }

        if (window.lucide) lucide.createIcons({ roots: [gridEl] });
    } catch (e) {
        console.error('Failed to load L7 traffic summary', e);
    }
}
window.loadL7TrafficSummary = loadL7TrafficSummary;


// Security Digest Modal
async function openDigestModal() {
    const modal = document.getElementById('digest-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    try {
        const res = await fetch('/api/security/digest?hours=24');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const score = data.score ?? 100;
        const scoreElem = document.getElementById('digest-score-value');
        if (scoreElem) scoreElem.textContent = score;

        const statusElem = document.getElementById('digest-score-status');
        if (statusElem) {
            statusElem.textContent = data.status_text || (score >= 80 ? 'Отлично' : (score >= 50 ? 'Внимание' : 'Опасно'));
            const col = data.status_color || (score >= 80 ? 'emerald' : (score >= 50 ? 'amber' : 'rose'));
            statusElem.className = `text-xs text-${col}-400 font-medium`;
        }

        const devElem = document.getElementById('digest-devices-value');
        const devOnline = data.online_devices ?? (devicesList.filter(d => d.is_online).length || 0);
        const devTotal = data.total_devices ?? (devicesList.length || 0);
        if (devElem) devElem.textContent = `${devOnline} / ${devTotal}`;
        const critElem = document.getElementById('digest-crit-cnt');
        if (critElem) critElem.textContent = data.critical_count ?? data.incidents?.critical ?? 0;
        const warnElem = document.getElementById('digest-warn-cnt');
        if (warnElem) warnElem.textContent = data.warning_count ?? data.incidents?.warning ?? 0;
        const infoElem = document.getElementById('digest-info-cnt');
        if (infoElem) infoElem.textContent = data.info_count ?? data.incidents?.info ?? 0;

        const recContainer = document.getElementById('digest-recommendations');
        if (recContainer) {
            if (data.recommendations && Array.isArray(data.recommendations) && data.recommendations.length > 0) {
                recContainer.innerHTML = data.recommendations.map(r => `
                    <div class="flex items-start space-x-2">
                        <span class="text-indigo-400 font-bold">•</span>
                        <span>${escapeHtml(r)}</span>
                    </div>
                `).join('');
            } else {
                recContainer.innerHTML = '<div>Угрозы отсутствуют. Сеть работает в штатном режиме.</div>';
            }
        }
        lucide.createIcons();
    } catch (e) {
        console.error('Error opening digest modal', e);
    }
}

function closeDigestModal() {
    document.getElementById('digest-modal').classList.add('hidden');
}

async function sendDigestToTelegram() {
    try {
        const res = await fetch('/api/security/digest/send?hours=24', { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            alert('Дайджест успешно отправлен в Telegram!');
        } else {
            alert(`Результат: ${data.message || 'Ошибка отправки'}`);
        }
    } catch (e) {
        alert(`Ошибка отправки: ${e}`);
    }
}

