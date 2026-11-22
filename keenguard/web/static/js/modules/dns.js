// ==========================================
// DNS Security Provider Management
// ==========================================
let currentSelectedDnsProvider = 'none';
let currentLoadedDnsConfig = null;

function selectDnsProviderCard(providerId) {
    currentSelectedDnsProvider = providerId || 'none';
    const providers = ['none', 'nextdns', 'controld', 'adguard_home', 'pihole'];

    providers.forEach(p => {
        const card = document.getElementById(`card-dns-prov-${p}`);
        if (card) {
            if (p === currentSelectedDnsProvider) {
                card.className = 'dns-prov-card p-3.5 rounded-xl border-2 border-indigo-500 bg-indigo-500/10 text-left transition cursor-pointer shadow-sm';
            } else {
                card.className = 'dns-prov-card p-3.5 rounded-xl border border-slate-800 bg-surface-950 text-left transition hover:border-slate-700 cursor-pointer';
            }
        }
        const fields = document.getElementById(`dns-fields-${p}`);
        if (fields) {
            fields.classList.toggle('hidden', p !== currentSelectedDnsProvider || p === 'none');
        }
    });

    const statusBadge = document.getElementById('dns-provider-status-badge');
    if (statusBadge) {
        if (currentSelectedDnsProvider === 'none') {
            statusBadge.textContent = 'Отключено';
            statusBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700';
        } else {
            const names = {
                'nextdns': 'NextDNS',
                'controld': 'Control D',
                'adguard_home': 'AdGuard Home',
                'pihole': 'Pi-hole'
            };
            statusBadge.textContent = `${names[currentSelectedDnsProvider] || currentSelectedDnsProvider} (Выбран)`;
            statusBadge.className = 'px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30';
        }
    }
}
window.selectDnsProviderCard = selectDnsProviderCard;

async function loadDnsProviderConfig() {
    try {
        const res = await fetch('/api/dns/provider/config');
        if (!res.ok) return;
        const cfg = await res.json();
        currentLoadedDnsConfig = cfg;

        selectDnsProviderCard(cfg.dns_security_provider || 'none');

        // NextDNS
        const nextProfile = document.getElementById('cfg-nextdns-profile-id');
        if (nextProfile) nextProfile.value = cfg.nextdns_profile_id || '';
        const nextKeySaved = document.getElementById('cfg-nextdns-key-saved');
        if (nextKeySaved) {
            nextKeySaved.classList.toggle('hidden', !cfg.nextdns_api_key || cfg.nextdns_api_key === '');
        }

        // Control D
        const cdDevice = document.getElementById('cfg-controld-device-id');
        if (cdDevice) cdDevice.value = cfg.controld_device_id || '';
        const cdKeySaved = document.getElementById('cfg-controld-key-saved');
        if (cdKeySaved) {
            cdKeySaved.classList.toggle('hidden', !cfg.controld_api_key || cfg.controld_api_key === '');
        }

        // AdGuard Home
        const adgUrl = document.getElementById('cfg-adguard-url');
        if (adgUrl) adgUrl.value = cfg.adguard_url || '';
        const adgUser = document.getElementById('cfg-adguard-username');
        if (adgUser) adgUser.value = cfg.adguard_username || '';
        const adgPassSaved = document.getElementById('cfg-adguard-pass-saved');
        if (adgPassSaved) {
            adgPassSaved.classList.toggle('hidden', !cfg.adguard_password || cfg.adguard_password === '');
        }

        // Pi-hole
        const piUrl = document.getElementById('cfg-pihole-url');
        if (piUrl) piUrl.value = cfg.pihole_url || '';
        const piTokenSaved = document.getElementById('cfg-pihole-token-saved');
        if (piTokenSaved) {
            piTokenSaved.classList.toggle('hidden', !cfg.pihole_api_token || cfg.pihole_api_token === '');
        }

        // Auto-sync & interval
        const autoSyncEl = document.getElementById('cfg-dns-auto-sync');
        if (autoSyncEl) autoSyncEl.checked = Boolean(cfg.dns_security_auto_sync);
        const intervalEl = document.getElementById('cfg-dns-sync-interval');
        if (intervalEl && cfg.dns_security_sync_interval) {
            intervalEl.value = String(cfg.dns_security_sync_interval);
        }

        await loadDnsProviderStatus();
    } catch (e) {
        console.error('Error loading DNS provider config', e);
    }
}
window.loadDnsProviderConfig = loadDnsProviderConfig;

async function loadDnsProviderStatus() {
    try {
        const res = await fetch('/api/dns/provider/status');
        if (!res.ok) return;
        const s = await res.json();

        const dot = document.getElementById('dns-provider-sync-dot');
        const statusText = document.getElementById('dns-provider-sync-status-text');
        const lastSyncTime = document.getElementById('dns-provider-last-sync-time');
        const totalCount = document.getElementById('dns-provider-total-synced-count');

        if (totalCount) {
            totalCount.textContent = s.total_blocked_queries_synced || 0;
        }

        if (lastSyncTime) {
            lastSyncTime.textContent = s.last_sync ? formatHumanFullDateTime(s.last_sync) : 'Никогда';
        }

        if (statusText && dot) {
            if (s.provider === 'none' || !s.provider) {
                statusText.textContent = 'Отключено';
                statusText.className = 'text-slate-400 font-semibold';
                dot.className = 'w-2 h-2 rounded-full bg-slate-500';
            } else if (s.status === 'syncing') {
                statusText.textContent = `Синхронизация (${s.provider})...`;
                statusText.className = 'text-amber-400 font-semibold animate-pulse';
                dot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-ping';
            } else if (s.status === 'error') {
                statusText.textContent = `Ошибка (${s.last_error || 'сбой'})`;
                statusText.className = 'text-rose-400 font-semibold';
                dot.className = 'w-2 h-2 rounded-full bg-rose-500';
            } else {
                statusText.textContent = `Активен (${s.provider})`;
                statusText.className = 'text-emerald-400 font-semibold';
                dot.className = 'w-2 h-2 rounded-full bg-emerald-400';
            }
        }
    } catch (e) {
        console.error('Error loading DNS provider status', e);
    }
}
window.loadDnsProviderStatus = loadDnsProviderStatus;

async function saveDnsProviderConfig() {
    const btn = document.getElementById('btn-save-dns-provider-config');
    if (btn) btn.disabled = true;

    try {
        const provider = currentSelectedDnsProvider || 'none';
        const autoSync = Boolean(document.getElementById('cfg-dns-auto-sync')?.checked);
        const syncInterval = parseInt(document.getElementById('cfg-dns-sync-interval')?.value || '60', 10);

        const payload = {
            dns_security_provider: provider,
            dns_security_auto_sync: autoSync,
            dns_security_sync_interval: syncInterval
        };

        const nextKeyVal = document.getElementById('cfg-nextdns-api-key')?.value?.trim();
        if (nextKeyVal) payload.nextdns_api_key = nextKeyVal;
        payload.nextdns_profile_id = document.getElementById('cfg-nextdns-profile-id')?.value?.trim() || '';

        const cdKeyVal = document.getElementById('cfg-controld-api-key')?.value?.trim();
        if (cdKeyVal) payload.controld_api_key = cdKeyVal;
        payload.controld_device_id = document.getElementById('cfg-controld-device-id')?.value?.trim() || '';

        const adgPassVal = document.getElementById('cfg-adguard-password')?.value;
        if (adgPassVal && adgPassVal.trim()) payload.adguard_password = adgPassVal.trim();
        payload.adguard_url = document.getElementById('cfg-adguard-url')?.value?.trim() || '';
        payload.adguard_username = document.getElementById('cfg-adguard-username')?.value?.trim() || '';

        const piTokenVal = document.getElementById('cfg-pihole-api-token')?.value?.trim();
        if (piTokenVal) payload.pihole_api_token = piTokenVal;
        payload.pihole_url = document.getElementById('cfg-pihole-url')?.value?.trim() || '';

        const res = await fetch('/api/dns/provider/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            showToast('Настройки DNS-безопасности успешно сохранены');
            // Clear secret inputs so they don't linger in DOM
            ['cfg-nextdns-api-key', 'cfg-controld-api-key', 'cfg-adguard-password', 'cfg-pihole-api-token'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            await loadDnsProviderConfig();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    } finally {
        if (btn) btn.disabled = false;
    }
}
window.saveDnsProviderConfig = saveDnsProviderConfig;

async function testDnsProviderConnection() {
    const btn = document.getElementById('btn-test-dns-provider');
    const resultBox = document.getElementById('dns-provider-test-result');

    if (btn) btn.disabled = true;
    if (resultBox) {
        resultBox.classList.remove('hidden', 'bg-emerald-500/10', 'border-emerald-500/30', 'text-emerald-300', 'bg-rose-500/10', 'border-rose-500/30', 'text-rose-300');
        resultBox.className = 'p-3.5 rounded-xl text-xs border bg-indigo-500/10 border-indigo-500/30 text-indigo-300 flex items-center space-x-2';
        resultBox.innerHTML = '<i data-lucide="loader-2" class="w-4 h-4 animate-spin text-indigo-400 shrink-0"></i><span>Выполняется запрос к API провайдера...</span>';
        if (window.lucide) lucide.createIcons();
    }

    try {
        const provider = currentSelectedDnsProvider || 'none';
        const overrides = {
            provider: provider
        };

        if (provider === 'nextdns') {
            overrides.profile_id = document.getElementById('cfg-nextdns-profile-id')?.value?.trim();
            const k = document.getElementById('cfg-nextdns-api-key')?.value?.trim();
            if (k) overrides.api_key = k;
        } else if (provider === 'controld') {
            const k = document.getElementById('cfg-controld-api-key')?.value?.trim();
            if (k) overrides.api_key = k;
            overrides.device_id = document.getElementById('cfg-controld-device-id')?.value?.trim();
        } else if (provider === 'adguard_home') {
            overrides.url = document.getElementById('cfg-adguard-url')?.value?.trim();
            overrides.username = document.getElementById('cfg-adguard-username')?.value?.trim();
            const p = document.getElementById('cfg-adguard-password')?.value;
            if (p && p.trim()) overrides.password = p.trim();
        } else if (provider === 'pihole') {
            overrides.url = document.getElementById('cfg-pihole-url')?.value?.trim();
            const t = document.getElementById('cfg-pihole-api-token')?.value?.trim();
            if (t) overrides.api_token = t;
        }

        const res = await fetch('/api/dns/provider/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(overrides)
        });
        const data = await res.json();

        if (data.ok) {
            resultBox.className = 'p-3.5 rounded-xl text-xs border bg-emerald-500/10 border-emerald-500/30 text-emerald-300 space-y-1';
            resultBox.innerHTML = `
                <div class="flex items-center space-x-2 font-semibold">
                    <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400 shrink-0"></i>
                    <span>${escapeHtml(data.message || 'Подключение успешно!')}</span>
                </div>
                ${data.details ? `<div class="text-[11px] text-emerald-400/80 font-mono mt-1">${escapeHtml(JSON.stringify(data.details))}</div>` : ''}
            `;
        } else {
            resultBox.className = 'p-3.5 rounded-xl text-xs border bg-rose-500/10 border-rose-500/30 text-rose-300 space-y-1';
            resultBox.innerHTML = `
                <div class="flex items-center space-x-2 font-semibold">
                    <i data-lucide="alert-triangle" class="w-4 h-4 text-rose-400 shrink-0"></i>
                    <span>Ошибка подключения: ${escapeHtml(data.error || 'Не удалось связаться с API')}</span>
                </div>
                ${data.details ? `<div class="text-[11px] text-rose-400/80 font-mono mt-1">${escapeHtml(JSON.stringify(data.details))}</div>` : ''}
            `;
        }
    } catch (e) {
        if (resultBox) {
            resultBox.className = 'p-3.5 rounded-xl text-xs border bg-rose-500/10 border-rose-500/30 text-rose-300';
            resultBox.innerHTML = `<span>Сетевой сбой при проверке: ${escapeHtml(e.message)}</span>`;
        }
    } finally {
        if (btn) btn.disabled = false;
        if (window.lucide) lucide.createIcons();
    }
}
window.testDnsProviderConnection = testDnsProviderConnection;

async function syncDnsProviderNow() {
    const btn = document.getElementById('btn-sync-dns-provider-now');
    if (btn) btn.disabled = true;

    try {
        showToast('Запуск синхронизации с DNS-провайдером...');
        const res = await fetch('/api/dns/provider/sync', { method: 'POST' });
        const data = await res.json();

        if (data.ok) {
            showToast(`Синхронизация завершена: импортировано ${data.synced || 0} заблокированных запросов`);
            await loadDnsProviderStatus();
            if (typeof loadDnsQueries === 'function') {
                await loadDnsQueries();
            }
        } else {
            showToast(`Ошибка синхронизации: ${data.error || 'Неизвестная ошибка'}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети при синхронизации: ${e.message}`, true);
    } finally {
        if (btn) btn.disabled = false;
    }
}
window.syncDnsProviderNow = syncDnsProviderNow;

function toggleDnsHelperAccordion(id) {
    const content = document.getElementById(`acc-content-${id}`);
    const icon = document.getElementById(`acc-icon-${id}`);
    if (content) {
        const isHidden = content.classList.contains('hidden');
        content.classList.toggle('hidden', !isHidden);
        if (icon) {
            icon.style.transform = isHidden ? 'rotate(180deg)' : 'rotate(0deg)';
        }
    }
}
window.toggleDnsHelperAccordion = toggleDnsHelperAccordion;


// DNS Queries & Automated Domain Security Inspection
let activeDnsCategory = 'all';
let currentInspectingDomain = null;
let currentInspectingDomainIsSinkholed = false;
let activeDnsSinkholes = [];
let activeDnsSubTab = localStorage.getItem('keenguard_dns_subtab') || 'log';
let allDnsSinkholeRules = [];
let allIpBlackholeRules = [];
let activeIpBlackholes = [];

async function loadDnsQueries() {
    try {
        const [res, sinkRes] = await Promise.all([
            fetch('/api/dns/queries?limit=150'),
            fetch('/api/dns/sinkholes')
        ]);
        allDnsQueries = await res.json();
        const sinkData = await sinkRes.json();
        activeDnsSinkholes = (sinkData && sinkData.sinkholes) || [];
        safeSetText('dns-active-sinkholes-count', activeDnsSinkholes.length);
        safeSetText('dns-subtab-log-badge', allDnsQueries.length);
        safeSetText('dns-subtab-filter-badge', activeDnsSinkholes.length);
        safeSetText('dns-log-shortcut-active-count', activeDnsSinkholes.length);
        safeSetText('dns-filter-active-count', activeDnsSinkholes.length);

        updateDnsCategoryCounters(allDnsQueries);
        applyDnsFilterAndRender();
    } catch (e) {
        console.error('Error loading DNS queries', e);
    }
}

function switchDnsSubTab(subtab) {
    activeDnsSubTab = subtab;
    localStorage.setItem('keenguard_dns_subtab', subtab);

    const logBtn = document.getElementById('dns-subtab-btn-log');
    const filterBtn = document.getElementById('dns-subtab-btn-filter');
    const ipBtn = document.getElementById('dns-subtab-btn-ip');
    const logContent = document.getElementById('dns-subtab-content-log');
    const filterContent = document.getElementById('dns-subtab-content-filter');
    const ipContent = document.getElementById('dns-subtab-content-ip');

    const inactiveClass = 'dns-subtab-btn px-4 py-2 rounded-xl text-xs font-medium transition flex items-center space-x-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60';
    const activeClass = 'dns-subtab-btn px-4 py-2 rounded-xl text-xs font-semibold transition flex items-center space-x-2 bg-indigo-600 text-white shadow-sm';

    if (logBtn) logBtn.className = (subtab === 'log') ? activeClass : inactiveClass;
    if (filterBtn) filterBtn.className = (subtab === 'filter') ? activeClass : inactiveClass;
    if (ipBtn) ipBtn.className = (subtab === 'ip_filter') ? activeClass : inactiveClass;

    if (logContent) logContent.classList.toggle('hidden', subtab !== 'log');
    if (filterContent) filterContent.classList.toggle('hidden', subtab !== 'filter');
    if (ipContent) ipContent.classList.toggle('hidden', subtab !== 'ip_filter');

    if (subtab === 'ip_filter') {
        loadIpBlackholesTab();
    } else if (subtab === 'filter') {
        loadDnsFilterTab();
    } else {
        loadDnsQueries();
    }

    if (window.lucide) lucide.createIcons();
}
window.switchDnsSubTab = switchDnsSubTab;

async function loadDnsFilterTab() {
    const tbody = document.getElementById('dns-filter-rules-tbody');
    const activeBadge = document.getElementById('dns-filter-active-count');
    const tableCountBadge = document.getElementById('dns-filter-table-count');
    const subtabFilterBadge = document.getElementById('dns-subtab-filter-badge');
    const shortcutCount = document.getElementById('dns-log-shortcut-active-count');
    const adsDetectedCount = document.getElementById('dns-preset-card-ads-detected');
    const tvDetectedCount = document.getElementById('dns-preset-card-tv-detected');

    try {
        const [sinkRes, adsRes, tvRes] = await Promise.allSettled([
            fetch('/api/dns/sinkholes'),
            fetch('/api/dns/sinkhole/preset_preview?preset=ads'),
            fetch('/api/dns/sinkhole/preset_preview?preset=tv_telemetry')
        ]);

        if (sinkRes.status === 'fulfilled' && sinkRes.value.ok) {
            const data = await sinkRes.value.json();
            allDnsSinkholeRules = data.rules || [];
            activeDnsSinkholes = data.sinkholes || [];

            const count = allDnsSinkholeRules.length;
            if (activeBadge) activeBadge.textContent = count;
            if (tableCountBadge) tableCountBadge.textContent = `${count} ${count === 1 ? 'правило' : (count >= 2 && count <= 4 ? 'правила' : 'правил')}`;
            if (subtabFilterBadge) subtabFilterBadge.textContent = count;
            if (shortcutCount) shortcutCount.textContent = count;

            filterDnsSinkholeRules();
        } else {
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-rose-400 italic font-sans">Ошибка загрузки правил с роутера Keenetic.</td></tr>';
            }
        }

        if (adsRes.status === 'fulfilled' && adsRes.value.ok) {
            const adsData = await adsRes.value.json();
            const count = (adsData.detected || []).length;
            if (adsDetectedCount) {
                adsDetectedCount.textContent = `${count} ${count === 1 ? 'домен' : (count >= 2 && count <= 4 ? 'домена' : 'доменов')}`;
            }
        }

        if (tvRes.status === 'fulfilled' && tvRes.value.ok) {
            const tvData = await tvRes.value.json();
            const count = (tvData.detected || []).length;
            if (tvDetectedCount) {
                tvDetectedCount.textContent = `${count} ${count === 1 ? 'домен' : (count >= 2 && count <= 4 ? 'домена' : 'доменов')}`;
            }
        }
    } catch (e) {
        console.error('Error loading DNS filter tab', e);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-rose-400 italic font-sans">Ошибка сети при получении данных фильтра.</td></tr>';
        }
    }
}

function filterDnsSinkholeRules() {
    const searchInput = document.getElementById('dns-filter-rules-search');
    const term = (searchInput ? searchInput.value : '').toLowerCase().trim();

    let filtered = allDnsSinkholeRules;
    if (term) {
        filtered = filtered.filter(r => {
            const dom = (r.domain || '').toLowerCase();
            const cat = (r.category_name || r.category || '').toLowerCase();
            const vendor = (r.vendor || '').toLowerCase();
            return dom.includes(term) || cat.includes(term) || vendor.includes(term);
        });
    }

    renderDnsSinkholeRulesTable(filtered);
}

function renderDnsSinkholeRulesTable(rules) {
    const tbody = document.getElementById('dns-filter-rules-tbody');
    if (!tbody) return;

    if (rules.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="5" class="py-8 text-center text-slate-500 italic font-sans">
                    ${allDnsSinkholeRules.length === 0
                        ? 'На роутере Keenetic пока нет активных правил 0.0.0.0. Выберите пресет выше или добавьте домен вручную.'
                        : 'Правила не найдены по текущему поисковому запросу.'}
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = rules.map(rule => {
        const dom = escapeHtml(rule.domain);
        const cat = escapeHtml(rule.category_name || rule.category || 'Пользовательская блокировка');
        const vendor = escapeHtml(rule.vendor || 'Ручное правило');
        const badgeColor = rule.badge_color || 'slate';

        const catBadgeClasses = {
            emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
            amber: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
            rose: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
            blue: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
            purple: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
            cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
            slate: 'bg-slate-800 text-slate-400 border-slate-700'
        }[badgeColor] || 'bg-slate-800 text-slate-400 border-slate-700';

        return `
            <tr class="hover:bg-slate-800/40 transition group">
                <td class="py-3 px-4">
                    <div class="flex items-center space-x-2.5">
                        <div class="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center shrink-0">
                            <i data-lucide="shield-ban" class="w-3.5 h-3.5"></i>
                        </div>
                        <div class="min-w-0">
                            <span class="text-white font-mono font-medium text-xs truncate block group-hover:text-indigo-300 transition">${dom}</span>
                            <span class="text-[10px] text-slate-500 font-sans">ip host ${dom} 0.0.0.0</span>
                        </div>
                    </div>
                </td>
                <td class="py-3 px-4 font-sans">
                    <span class="px-2 py-0.5 rounded-md text-[11px] font-medium border ${catBadgeClasses} inline-block whitespace-nowrap">
                        ${cat}
                    </span>
                </td>
                <td class="py-3 px-4 font-sans text-slate-400 text-xs">
                    ${vendor}
                </td>
                <td class="py-3 px-4 text-center">
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        0.0.0.0
                    </span>
                </td>
                <td class="py-3 px-4 text-right">
                    <button type="button" onclick="unblockDnsSinkholeFromTab('${dom}')" class="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 text-xs font-medium border border-rose-500/20 transition inline-flex items-center space-x-1" title="Удалить правило с роутера Keenetic">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                        <span>Удалить</span>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
}

async function addCustomDnsSinkholeFromTab() {
    const input = document.getElementById('tab-manual-sinkhole-input');
    if (!input) return;
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!domain || !domain.includes('.')) {
        showToast('Введите корректное доменное имя (например: ad.tracker.com)', 'warning');
        return;
    }

    const btn = document.getElementById('btn-tab-add-sinkhole');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/dns/sinkhole/block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            input.value = '';
            showToast(`🚫 Домен ${domain} заблокирован на Keenetic (0.0.0.0)`, 'success');
            await loadDnsFilterTab();
            loadDnsQueries();
        } else {
            showToast(data.detail || 'Не удалось заблокировать домен', 'error');
        }
    } catch (e) {
        console.error('Error adding custom sinkhole', e);
        showToast('Ошибка сети при добавлении правила', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function unblockDnsSinkholeFromTab(domain) {
    try {
        const res = await fetch('/api/dns/sinkhole/unblock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`✓ Домен ${domain} разблокирован на Keenetic`, 'info');
            await loadDnsFilterTab();
            loadDnsQueries();
        } else {
            showToast(data.detail || 'Ошибка удаления правила', 'error');
        }
    } catch (e) {
        console.error('Error unblocking sinkhole', e);
        showToast('Ошибка сети при удалении правила', 'error');
    }
}

async function unblockAllDnsSinkholesFromTab() {
    if (!confirm('Вы действительно хотите удалить ВСЕ статические DNS-блокировки (0.0.0.0) с роутера Keenetic?')) {
        return;
    }
    try {
        const res = await fetch('/api/dns/sinkhole/unblock_all', {
            method: 'POST'
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`🔄 Разблокировано ${data.unblocked_count} доменов на Keenetic`, 'info');
            await loadDnsFilterTab();
            loadDnsQueries();
        } else {
            showToast(data.detail || 'Ошибка очистки правил', 'error');
        }
    } catch (e) {
        console.error('Error unblocking all sinkholes', e);
        showToast('Ошибка сети при очистке блокировок', 'error');
    }
}

async function blockDnsSinkhole(domain, event) {
    if (event) event.stopPropagation();
    try {
        const res = await fetch('/api/dns/sinkhole/block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`🚫 Домен ${domain} заблокирован на Keenetic (0.0.0.0)`, 'success');
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Ошибка блокировки', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при блокировке домена', 'error');
    }
}

async function unblockDnsSinkhole(domain, event) {
    if (event) event.stopPropagation();
    try {
        const res = await fetch('/api/dns/sinkhole/unblock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`✓ Домен ${domain} разблокирован на Keenetic`, 'info');
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Ошибка разблокировки', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при разблокировке домена', 'error');
    }
}

// Hardware IP Blackhole Management (KeeneticOS L3 Reject Routes)
async function loadIpBlackholesTab() {
    const tbody = document.getElementById('ip-filter-rules-tbody');
    const activeBadge = document.getElementById('ip-filter-active-count');
    const tableCountBadge = document.getElementById('ip-filter-table-count');
    const subtabIpBadge = document.getElementById('dns-subtab-ip-badge');

    try {
        const res = await fetch('/api/firewall/ip_blackholes');
        if (res.ok) {
            const data = await res.json();
            allIpBlackholeRules = data.rules || [];
            activeIpBlackholes = (data.rules || []).filter(r => r.hardware_active).map(r => r.ip);

            const count = allIpBlackholeRules.length;
            const activeCount = data.router_active_count !== undefined ? data.router_active_count : activeIpBlackholes.length;

            if (activeBadge) activeBadge.textContent = activeCount;
            if (tableCountBadge) tableCountBadge.textContent = `${count} ${count === 1 ? 'маршрут' : (count >= 2 && count <= 4 ? 'маршрута' : 'маршрутов')}`;
            if (subtabIpBadge) subtabIpBadge.textContent = activeCount;

            filterIpBlackholeRules();
        } else {
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-rose-400 italic font-sans">Ошибка загрузки маршрутов reject с роутера Keenetic.</td></tr>';
            }
        }
    } catch (e) {
        console.error('Error loading IP blackholes', e);
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-rose-400 italic font-sans">Ошибка сети при получении маршрутов блокировки.</td></tr>';
        }
    }
}
window.loadIpBlackholesTab = loadIpBlackholesTab;

function filterIpBlackholeRules() {
    const searchInput = document.getElementById('ip-filter-rules-search');
    const term = (searchInput ? searchInput.value : '').toLowerCase().trim();

    let filtered = allIpBlackholeRules;
    if (term) {
        filtered = filtered.filter(r => {
            const ip = (r.ip || '').toLowerCase();
            const prov = (r.provider || '').toLowerCase();
            const reason = (r.reason || '').toLowerCase();
            const country = (r.country || '').toLowerCase();
            return ip.includes(term) || prov.includes(term) || reason.includes(term) || country.includes(term);
        });
    }

    renderIpBlackholesTable(filtered);
}
window.filterIpBlackholeRules = filterIpBlackholeRules;

function renderIpBlackholesTable(rules) {
    const tbody = document.getElementById('ip-filter-rules-tbody');
    if (!tbody) return;

    if (!rules || rules.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="py-8 text-center text-slate-500 italic font-sans">
                    ${allIpBlackholeRules.length === 0
                        ? 'На роутере Keenetic пока нет активных маршрутов reject. Добавьте внешний IP вручную выше.'
                        : 'Маршруты не найдены по текущему поисковому запросу.'}
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = rules.map(r => {
        const cdnBadge = r.is_cdn
            ? '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20 font-sans font-medium" title="Адрес принадлежит общему CDN — возможен сопутствующий сбой других сервисов"><i data-lucide="cloud-alert" class="w-3 h-3 mr-1"></i>Shared CDN</span>'
            : '<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-sans font-medium"><i data-lucide="server" class="w-3 h-3 mr-1"></i>Выделенный IP</span>';

        const hwStatus = r.hardware_active
            ? '<span class="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-sans font-medium"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span><span>Reject (Ядро)</span></span>'
            : '<span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-400 font-sans"><span>Не активен</span></span>';

        return `
            <tr class="hover:bg-surface-800/40 transition">
                <td class="py-3 px-4 text-slate-200 font-bold flex items-center space-x-2">
                    <i data-lucide="shield-alert" class="w-3.5 h-3.5 text-amber-400 shrink-0"></i>
                    <span>${escapeHtml(r.ip)}</span>
                </td>
                <td class="py-3 px-4 text-slate-300 font-sans">
                    <span class="mr-1.5">${escapeHtml(r.flag || '🌐')}</span>
                    <span>${escapeHtml(r.provider || r.country || 'Неизвестно')}</span>
                </td>
                <td class="py-3 px-4">
                    ${cdnBadge}
                </td>
                <td class="py-3 px-4 text-slate-400 font-sans truncate max-w-xs" title="${escapeHtml(r.reason || '')}">
                    ${escapeHtml(r.reason || 'Ручная блокировка')}
                </td>
                <td class="py-3 px-4 text-center">
                    ${hwStatus}
                </td>
                <td class="py-3 px-4 text-right">
                    <button type="button" onclick="unblockIpBlackholeFromTab('${escapeHtml(r.ip)}')" class="px-2.5 py-1 text-xs rounded-lg bg-rose-600/10 hover:bg-rose-600 text-rose-300 hover:text-white transition border border-rose-500/20 flex items-center space-x-1 ml-auto font-sans">
                        <i data-lucide="unlock" class="w-3 h-3"></i>
                        <span>Снять</span>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
}

let ipCheckDebounceTimer = null;
function checkManualIpCdnPreview(val) {
    clearTimeout(ipCheckDebounceTimer);
    const clean = (val || '').trim();
    const warnBox = document.getElementById('ip-filter-cdn-warning-box');
    const warnText = document.getElementById('ip-filter-cdn-warning-text');

    if (!clean || !/^(\d{1,3}\.){3}\d{1,3}$/.test(clean)) {
        if (warnBox) warnBox.classList.add('hidden');
        return;
    }

    ipCheckDebounceTimer = setTimeout(async () => {
        try {
            const res = await fetch('/api/firewall/ip_blackhole/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: clean })
            });
            const data = await res.json();
            if (res.ok && data.is_cdn) {
                if (warnBox && warnText) {
                    warnText.textContent = data.warning || `Внимание: IP принадлежит CDN (${data.provider}). Блокировка может сломать другие сайты!`;
                    warnBox.classList.remove('hidden');
                    if (window.lucide) lucide.createIcons();
                }
            } else {
                if (warnBox) warnBox.classList.add('hidden');
            }
        } catch (e) {
            // Silently ignore check errors in preview
        }
    }, 400);
}
window.checkManualIpCdnPreview = checkManualIpCdnPreview;

async function addCustomIpBlackholeFromTab(forceCdn = false) {
    const input = document.getElementById('ip-filter-manual-input');
    const reasonInput = document.getElementById('ip-filter-manual-reason');
    const warnBox = document.getElementById('ip-filter-cdn-warning-box');
    const warnText = document.getElementById('ip-filter-cdn-warning-text');
    const ip = input ? input.value.trim() : '';
    const reason = reasonInput ? reasonInput.value.trim() : '';

    if (!ip) {
        showToast('Введите IPv4 адрес для блокировки', 'warning');
        return;
    }

    // Prohibit private IP ranges client-side
    if (/^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip)) {
        showToast('Запрещено блокировать локальные или шлюзовые IP-адреса!', 'error');
        return;
    }

    try {
        const res = await fetch('/api/firewall/ip_blackhole/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, reason, force_cdn: forceCdn })
        });

        if (res.status === 409) {
            const errData = await res.json();
            if (warnBox && warnText) {
                warnText.textContent = errData.detail || 'IP-адрес принадлежит CDN. Подтвердите блокировку.';
                warnBox.classList.remove('hidden');
                if (window.lucide) lucide.createIcons();
            }
            return;
        }

        const data = await res.json();
        if (res.ok) {
            showToast(data.message || `IP ${ip} заблокирован на Keenetic`, 'success');
            if (input) input.value = '';
            if (reasonInput) reasonInput.value = '';
            if (warnBox) warnBox.classList.add('hidden');
            await loadIpBlackholesTab();
        } else {
            showToast(data.detail || 'Ошибка блокировки IP', 'error');
        }
    } catch (e) {
        console.error('Error blocking IP', e);
        showToast('Ошибка сети при блокировке IP', 'error');
    }
}
window.addCustomIpBlackholeFromTab = addCustomIpBlackholeFromTab;

async function unblockIpBlackholeFromTab(ip) {
    try {
        const res = await fetch('/api/firewall/ip_blackhole/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`✓ Маршрут для ${ip} удален с роутера`, 'info');
            await loadIpBlackholesTab();
        } else {
            showToast(data.detail || 'Ошибка разблокировки IP', 'error');
        }
    } catch (e) {
        console.error('Error unblocking IP', e);
        showToast('Ошибка сети при разблокировке IP', 'error');
    }
}
window.unblockIpBlackholeFromTab = unblockIpBlackholeFromTab;

async function unblockAllIpBlackholesFromTab() {
    if (!confirm('Вы действительно хотите удалить ВСЕ маршруты reject с роутера Keenetic? Это снимет все блокировки по IP.')) {
        return;
    }
    try {
        let removedCount = 0;
        for (const rule of allIpBlackholeRules) {
            if (rule.ip) {
                const res = await fetch('/api/firewall/ip_blackhole/unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip: rule.ip })
                });
                if (res.ok) removedCount++;
            }
        }
        showToast(`🔄 Удалено ${removedCount} маршрутов reject с роутера`, 'info');
        await loadIpBlackholesTab();
    } catch (e) {
        console.error('Error unblocking all IP rules', e);
        showToast('Ошибка сети при очистке IP маршрутов', 'error');
    }
}
window.unblockAllIpBlackholesFromTab = unblockAllIpBlackholesFromTab;

// State for DNS Preset Modal & Selective Blocking
let currentDnsPresetType = null;
let currentDnsPresetData = null;
let selectedDnsPresetDomains = new Set();

async function openDnsPresetModal(preset) {
    currentDnsPresetType = preset;
    selectedDnsPresetDomains.clear();

    const modal = document.getElementById('dns-preset-modal');
    if (!modal) return;

    const titleEl = document.getElementById('dns-preset-modal-title');
    const descEl = document.getElementById('dns-preset-modal-desc');
    const iconContainer = document.getElementById('dns-preset-modal-icon-container');
    const iconEl = document.getElementById('dns-preset-modal-icon');

    if (preset === 'ads') {
        if (titleEl) titleEl.textContent = 'Выборочная блокировка рекламы';
        if (descEl) descEl.textContent = 'Блокировка баннеров, рекламных сетей и видеовставок прямо на Keenetic';
        if (iconContainer) iconContainer.className = 'p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400';
        if (iconEl) iconEl.setAttribute('data-lucide', 'ban');
    } else {
        if (titleEl) titleEl.textContent = 'Отключение телеметрии Smart TV & IoT';
        if (descEl) descEl.textContent = 'Блокировка сбора данных LG webOS, Samsung Tizen, Xiaomi и Яндекс';
        if (iconContainer) iconContainer.className = 'p-2.5 rounded-xl bg-amber-500/10 text-amber-400';
        if (iconEl) iconEl.setAttribute('data-lucide', 'bell-off');
    }
    if (window.lucide) lucide.createIcons();

    modal.classList.remove('hidden');
    const detectedList = document.getElementById('dns-preset-detected-list');
    const curatedList = document.getElementById('dns-preset-curated-list');
    if (detectedList) detectedList.innerHTML = '<div class="p-4 text-center text-xs text-slate-400"><i class="animate-spin inline-block mr-1">⏳</i> Загрузка обнаруженных доменов сети...</div>';
    if (curatedList) curatedList.innerHTML = '<div class="p-4 text-center text-xs text-slate-400"><i class="animate-spin inline-block mr-1">⏳</i> Загрузка базы правил...</div>';

    updateDnsPresetCounter();

    try {
        const res = await fetch(`/api/dns/sinkhole/preset_preview?preset=${preset}`);
        if (!res.ok) throw new Error('Failed to load preset preview');
        currentDnsPresetData = await res.json();
        renderDnsPresetModalContent(currentDnsPresetData);
    } catch (e) {
        console.error('Error opening DNS preset modal', e);
        if (detectedList) detectedList.innerHTML = '<div class="p-3 text-xs text-rose-400">Ошибка загрузки данных пресета. Попробуйте еще раз.</div>';
    }
}

function closeDnsPresetModal() {
    const modal = document.getElementById('dns-preset-modal');
    if (modal) modal.classList.add('hidden');
    currentDnsPresetType = null;
    currentDnsPresetData = null;
    selectedDnsPresetDomains.clear();
}

function renderDnsPresetModalContent(data) {
    const detectedList = document.getElementById('dns-preset-detected-list');
    const curatedList = document.getElementById('dns-preset-curated-list');
    const detectedCountBadge = document.getElementById('dns-preset-detected-count-badge');
    const curatedCountBadge = document.getElementById('dns-preset-curated-count-badge');

    const detected = data.detected || [];
    const curated = data.curated || [];

    if (detectedCountBadge) detectedCountBadge.textContent = detected.length;
    if (curatedCountBadge) curatedCountBadge.textContent = curated.length;

    // 1. Detected section
    if (detected.length === 0) {
        detectedList.innerHTML = `
            <div class="p-3.5 rounded-xl bg-surface-950 border border-slate-800 text-xs text-slate-400 space-y-1">
                <div class="flex items-center space-x-2 text-slate-300 font-medium">
                    <i data-lucide="check-circle" class="w-4 h-4 text-emerald-400 shrink-0"></i>
                    <span>В недавней истории сети обращений не зафиксировано</span>
                </div>
                <p class="text-[11px] text-slate-400 pl-6 leading-relaxed">
                    На устройствах может быть активен блокировщик рекламы в браузере, приватный DNS (DoH/DoT), либо целевые устройства находились в спящем режиме.
                    Вы можете превентивно применить блокировку из рекомендованного каталога ниже.
                </p>
            </div>
        `;
    } else {
        let html = '';
        detected.forEach((item) => {
            const isAlreadyActive = Boolean(item.is_active);
            const dom = escapeHtml(item.domain);
            const isChecked = !isAlreadyActive;
            if (isChecked) selectedDnsPresetDomains.add(item.domain);

            const devicesHtml = (item.devices && item.devices.length > 0)
                ? item.devices.map(d => `<span class="px-1.5 py-0.2 bg-slate-800 rounded text-[10px] text-slate-300 font-sans">${escapeHtml(d)}</span>`).join(' ')
                : '<span class="text-[10px] text-slate-500">устройство не определено</span>';

            html += `
                <label class="flex items-center justify-between p-2.5 rounded-xl bg-surface-950 hover:bg-slate-800/60 border ${isChecked ? 'border-indigo-500/40' : 'border-slate-800'} transition cursor-pointer group">
                    <div class="flex items-center space-x-3 min-w-0">
                        <input type="checkbox" data-group="detected" data-domain="${dom}" ${isChecked ? 'checked' : ''} onchange="toggleDnsPresetDomain('${dom}', this.checked)" class="w-4 h-4 rounded border-slate-700 bg-surface-900 text-indigo-600 focus:ring-indigo-500/30 focus:ring-offset-0 transition cursor-pointer">
                        <div class="min-w-0">
                            <div class="flex items-center space-x-2">
                                <span class="font-mono font-medium text-xs text-white truncate">${dom}</span>
                                ${isAlreadyActive ? '<span class="px-1.5 py-0.2 rounded text-[9px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-sans">Уже в 0.0.0.0</span>' : ''}
                            </div>
                            <div class="flex items-center space-x-2 mt-0.5">
                                <span class="text-[10px] text-slate-400">Устройства:</span>
                                <div class="flex flex-wrap gap-1">${devicesHtml}</div>
                            </div>
                        </div>
                    </div>
                    <div class="text-right shrink-0 ml-3">
                        <span class="text-[10px] font-mono text-slate-400">${item.count || 1} запр.</span>
                    </div>
                </label>
            `;
        });
        detectedList.innerHTML = html;
    }

    // 2. Curated section
    if (curated.length === 0) {
        curatedList.innerHTML = '<div class="p-3 text-xs text-slate-500">Нет предустановленных правил для данного пресета.</div>';
    } else {
        let html = '';
        curated.forEach(item => {
            const isAlreadyActive = Boolean(item.is_active);
            const dom = escapeHtml(item.domain);
            const isChecked = !isAlreadyActive;
            if (isChecked) selectedDnsPresetDomains.add(item.domain);

            html += `
                <label class="flex items-center justify-between p-2 rounded-xl bg-surface-950 hover:bg-slate-800/60 border ${isChecked ? 'border-indigo-500/40' : 'border-slate-800/80'} transition cursor-pointer group">
                    <div class="flex items-center space-x-3 min-w-0">
                        <input type="checkbox" data-group="curated" data-domain="${dom}" ${isChecked ? 'checked' : ''} onchange="toggleDnsPresetDomain('${dom}', this.checked)" class="w-4 h-4 rounded border-slate-700 bg-surface-900 text-indigo-600 focus:ring-indigo-500/30 focus:ring-offset-0 transition cursor-pointer">
                        <div class="min-w-0">
                            <div class="flex items-center space-x-2">
                                <span class="font-mono font-medium text-xs text-slate-200 group-hover:text-white truncate">${dom}</span>
                                ${isAlreadyActive ? '<span class="px-1.5 py-0.2 rounded text-[9px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-sans">Активно</span>' : ''}
                                ${item.vendor ? `<span class="px-1.5 py-0.2 rounded text-[9px] bg-slate-800 text-slate-400 font-sans">${escapeHtml(item.vendor)}</span>` : ''}
                            </div>
                            ${item.description ? `<p class="text-[10px] text-slate-400 truncate mt-0.5">${escapeHtml(item.description)}</p>` : ''}
                        </div>
                    </div>
                </label>
            `;
        });
        curatedList.innerHTML = html;
    }

    if (window.lucide) lucide.createIcons();
    updateDnsPresetCounter();
}

function toggleDnsPresetDomain(domain, isChecked) {
    if (isChecked) {
        selectedDnsPresetDomains.add(domain);
    } else {
        selectedDnsPresetDomains.delete(domain);
    }
    updateDnsPresetCounter();
}

function toggleAllDnsPresetGroup(group, selectAll) {
    const checkboxes = document.querySelectorAll(`#dns-preset-modal input[data-group="${group}"]`);
    checkboxes.forEach(cb => {
        cb.checked = selectAll;
        const dom = cb.getAttribute('data-domain');
        if (dom) {
            if (selectAll) selectedDnsPresetDomains.add(dom);
            else selectedDnsPresetDomains.delete(dom);
        }
    });
    updateDnsPresetCounter();
}

function updateDnsPresetCounter() {
    const totalSelectedEl = document.getElementById('dns-preset-total-selected');
    const applyBtn = document.getElementById('btn-apply-dns-preset');
    const applyBtnText = document.getElementById('btn-apply-dns-preset-text');
    const count = selectedDnsPresetDomains.size;

    if (totalSelectedEl) totalSelectedEl.textContent = `${count} ${count === 1 ? 'домен' : (count >= 2 && count <= 4 ? 'домена' : 'доменов')}`;
    if (applyBtn) {
        applyBtn.disabled = count === 0;
    }
    if (applyBtnText) {
        applyBtnText.textContent = count > 0 ? `Применить на Keenetic (${count})` : 'Выберите домены';
    }
}

async function submitSelectedDnsPreset() {
    const domains = Array.from(selectedDnsPresetDomains);
    if (domains.length === 0) return;

    const applyBtn = document.getElementById('btn-apply-dns-preset');
    const applyBtnText = document.getElementById('btn-apply-dns-preset-text');
    const originalText = applyBtnText ? applyBtnText.textContent : 'Применить на Keenetic';

    if (applyBtn) applyBtn.disabled = true;
    if (applyBtnText) applyBtnText.textContent = 'Применение правил на Keenetic...';

    try {
        const res = await fetch('/api/dns/sinkhole/block_selected', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domains})
        });
        const data = await res.json();
        if (res.ok) {
            closeDnsPresetModal();
            if (data.blocked_count > 0) {
                showToast(`✅ Заблокировано ${data.blocked_count} доменов на Keenetic (0.0.0.0)`, 'success');
            } else if (data.failed_count > 0) {
                showToast(`⚠️ Не удалось заблокировать выбранные домены (${data.failed_count})`, 'warning');
            } else {
                showToast('Все выбранные домены уже заблокированы (0.0.0.0)', 'info');
            }
            await Promise.allSettled([loadDnsQueries(), loadDnsFilterTab()]);
        } else {
            showToast(data.detail || data.message || 'Ошибка применения правил на роутере', 'error');
            if (applyBtn) applyBtn.disabled = false;
            if (applyBtnText) applyBtnText.textContent = originalText;
        }
    } catch (e) {
        console.error('Error applying selected DNS sinkholes', e);
        showToast('Ошибка сети при отправке команд на Keenetic', 'error');
        if (applyBtn) applyBtn.disabled = false;
        if (applyBtnText) applyBtnText.textContent = originalText;
    }
}

// Backward-compatibility alias
function applyDnsPreset(preset) {
    openDnsPresetModal(preset);
}

// Active Rules Manager Modal Handlers
async function openDnsActiveRulesModal() {
    const modal = document.getElementById('dns-active-rules-modal');
    if (!modal) return;
    modal.classList.remove('hidden');
    await refreshDnsActiveRulesModal();
}

function closeDnsActiveRulesModal() {
    const modal = document.getElementById('dns-active-rules-modal');
    if (modal) modal.classList.add('hidden');
}

async function refreshDnsActiveRulesModal() {
    const container = document.getElementById('dns-active-rules-container');
    const badge = document.getElementById('dns-active-rules-modal-badge');
    if (container) container.innerHTML = '<div class="p-4 text-center text-xs text-slate-400"><i class="animate-spin inline-block mr-1">⏳</i> Запрос активных правил с Keenetic...</div>';

    try {
        const res = await fetch('/api/dns/sinkholes');
        if (!res.ok) throw new Error('Failed to load active sinkholes');
        const data = await res.json();
        const rules = data.rules || [];

        if (badge) badge.textContent = `${rules.length} ${rules.length === 1 ? 'правило' : (rules.length >= 2 && rules.length <= 4 ? 'правила' : 'правил')}`;

        if (rules.length === 0) {
            container.innerHTML = `
                <div class="p-5 text-center text-xs text-slate-400 bg-surface-950 rounded-xl border border-slate-800 space-y-1">
                    <p class="text-slate-300 font-medium">На роутере Keenetic пока нет активных статических правил 0.0.0.0</p>
                    <p class="text-[11px] text-slate-500">Воспользуйтесь кнопками пресетов (реклама / телеметрия) или добавьте домен вручную в поле выше.</p>
                </div>
            `;
            return;
        }

        let html = '';
        rules.forEach(rule => {
            const dom = escapeHtml(rule.domain);
            const vendor = escapeHtml(rule.vendor || '');
            const catName = escapeHtml(rule.category_name || rule.category || 'Пользовательская блокировка');
            html += `
                <div class="flex items-center justify-between p-2.5 rounded-xl bg-surface-950 border border-slate-800 hover:border-slate-700 transition">
                    <div class="flex items-center space-x-3 min-w-0">
                        <div class="w-7 h-7 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center shrink-0">
                            <i data-lucide="shield-ban" class="w-3.5 h-3.5"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="flex items-center space-x-2">
                                <span class="font-mono font-medium text-xs text-white truncate">${dom}</span>
                                <span class="px-1.5 py-0.2 rounded text-[9px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 shrink-0">0.0.0.0</span>
                            </div>
                            <div class="flex items-center space-x-2 mt-0.5">
                                <span class="text-[10px] text-slate-400">${catName}</span>
                                ${vendor ? `<span class="text-[10px] text-slate-500">• ${vendor}</span>` : ''}
                            </div>
                        </div>
                    </div>
                    <button type="button" onclick="unblockDnsSinkholeFromList('${dom}')" class="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 hover:text-rose-300 text-xs font-medium border border-rose-500/20 transition shrink-0 ml-3 flex items-center space-x-1" title="Удалить правило с роутера">
                        <i data-lucide="trash-2" class="w-3 h-3"></i>
                        <span>Удалить</span>
                    </button>
                </div>
            `;
        });
        container.innerHTML = html;
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error refreshing active rules', e);
        if (container) container.innerHTML = '<div class="p-3 text-xs text-rose-400">Ошибка при получении списка правил с Keenetic.</div>';
    }
}

async function addCustomDnsSinkholeRule() {
    const input = document.getElementById('manual-sinkhole-domain-input');
    if (!input) return;
    const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (!domain || !domain.includes('.')) {
        showToast('Введите корректное доменное имя (например: ad.tracker.com)', 'warning');
        return;
    }

    const btn = document.getElementById('btn-add-manual-sinkhole');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/dns/sinkhole/block', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            input.value = '';
            showToast(`🚫 Домен ${domain} заблокирован на Keenetic (0.0.0.0)`, 'success');
            await refreshDnsActiveRulesModal();
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') await loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Не удалось заблокировать домен', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при добавлении правила', 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function unblockDnsSinkholeFromList(domain) {
    try {
        const res = await fetch('/api/dns/sinkhole/unblock', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain})
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`✓ Домен ${domain} разблокирован на Keenetic`, 'info');
            await refreshDnsActiveRulesModal();
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') await loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Ошибка удаления правила', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при удалении правила', 'error');
    }
}

async function unblockAllDnsSinkholesFromModal() {
    if (!confirm('Вы действительно хотите удалить ВСЕ статические DNS-блокировки с роутера Keenetic?')) {
        return;
    }
    try {
        const res = await fetch('/api/dns/sinkhole/unblock_all', {
            method: 'POST'
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`🔄 Разблокировано ${data.unblocked_count} доменов на Keenetic`, 'info');
            await refreshDnsActiveRulesModal();
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') await loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Ошибка очистки правил', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при очистке блокировок', 'error');
    }
}

async function unblockAllDnsSinkholes() {
    if (!confirm('Вы действительно хотите удалить все статические DNS-блокировки с роутера Keenetic?')) {
        return;
    }
    try {
        const res = await fetch('/api/dns/sinkhole/unblock_all', {
            method: 'POST'
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`🔄 Разблокировано ${data.unblocked_count} доменов на Keenetic`, 'info');
            await loadDnsQueries();
            if (activeDnsSubTab === 'filter') await loadDnsFilterTab();
        } else {
            showToast(data.detail || 'Ошибка очистки правил', 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при очистке блокировок', 'error');
    }
}


function updateDnsCategoryCounters(queries) {
    const total = queries.length;
    let iot = 0, telemetry = 0, ads = 0, sys = 0, vpn = 0, suspicious = 0, cdn = 0, unknown = 0, blocked = 0;

    queries.forEach(q => {
        const cat = (q.analysis && q.analysis.category) || 'unknown';
        const risk = (q.analysis && q.analysis.risk_level) || 'neutral';
        const isBlocked = q.is_blocked || (q.analysis && q.analysis.is_blocked) || q.ip === '0.0.0.0';

        if (isBlocked) blocked++;

        if (cat === 'iot_cloud') iot++;
        else if (cat === 'telemetry') telemetry++;
        else if (cat === 'advertising') ads++;
        else if (cat === 'system_dns') sys++;
        else if (cat === 'vpn_tunnel') vpn++;
        else if (cat === 'suspicious' || risk === 'danger') suspicious++;
        else if (cat === 'cdn_media') cdn++;
        else unknown++;
    });

    const setTxt = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setTxt('dns-stat-total', total);
    setTxt('dns-stat-iot', iot);
    setTxt('dns-stat-telemetry', telemetry);
    setTxt('dns-stat-ads', ads);

    setTxt('dns-pill-cnt-all', total);
    setTxt('dns-pill-cnt-blocked', blocked);
    setTxt('dns-pill-cnt-iot', iot);
    setTxt('dns-pill-cnt-telemetry', telemetry);
    setTxt('dns-pill-cnt-ads', ads);
    setTxt('dns-pill-cnt-sys', sys);
    setTxt('dns-pill-cnt-vpn', vpn);
    setTxt('dns-pill-cnt-suspicious', suspicious);
    setTxt('dns-pill-cnt-cdn', cdn);
    setTxt('dns-pill-cnt-unknown', unknown);
}

function filterDnsByCategory(category) {
    activeDnsCategory = category;
    document.querySelectorAll('.dns-filter-pill').forEach(btn => {
        btn.classList.remove('active', 'bg-indigo-600', 'text-white');
        btn.classList.add('bg-surface-900', 'text-slate-300');
    });

    const activeBtn = document.getElementById(`dns-filter-${category}`);
    if (activeBtn) {
        activeBtn.classList.add('active', 'bg-indigo-600', 'text-white');
        activeBtn.classList.remove('bg-surface-900', 'text-slate-300');
    }

    applyDnsFilterAndRender();
}

function filterDnsQueries() {
    applyDnsFilterAndRender();
}

function sortDnsQueries(queries) {
    const { col, dir } = tableSortState.dns;
    const mult = dir === 'asc' ? 1 : -1;
    const riskMap = { danger: 4, critical: 4, warning: 3, medium: 3, suspicious: 2, info: 2, safe: 1, neutral: 1, ok: 1 };

    return [...queries].sort((a, b) => {
        let cmp = 0;
        if (col === 'domain') {
            cmp = (a.domain || '').localeCompare(b.domain || '', 'ru');
        } else if (col === 'category') {
            const catA = (a.analysis && a.analysis.category_name) || '';
            const catB = (b.analysis && b.analysis.category_name) || '';
            cmp = catA.localeCompare(catB, 'ru');
        } else if (col === 'safety') {
            const rA = riskMap[(a.analysis && a.analysis.risk_level) || ''] || 1;
            const rB = riskMap[(b.analysis && b.analysis.risk_level) || ''] || 1;
            cmp = rA - rB;
        } else if (col === 'devices') {
            const dA = a.devices ? a.devices.length : 0;
            const dB = b.devices ? b.devices.length : 0;
            cmp = dA - dB;
        } else if (col === 'count') {
            cmp = (a.count || 0) - (b.count || 0);
        } else if (col === 'last_seen') {
            const tA = a.last_seen ? new Date(a.last_seen).getTime() : 0;
            const tB = b.last_seen ? new Date(b.last_seen).getTime() : 0;
            cmp = tA - tB;
        }
        return cmp * mult;
    });
}

function applyDnsFilterAndRender() {
    const searchInput = document.getElementById('dns-search-input');
    const term = (searchInput ? searchInput.value : '').toLowerCase().trim();
    const hideBlockedToggle = document.getElementById('dns-hide-blocked-toggle');
    const hideBlocked = hideBlockedToggle ? hideBlockedToggle.checked : false;

    let filtered = allDnsQueries;

    // 0. Hide blocked (0.0.0.0) queries if toggle is checked
    if (hideBlocked) {
        filtered = filtered.filter(q => {
            const isBlocked = q.is_blocked || (q.analysis && q.analysis.is_blocked) || q.ip === '0.0.0.0';
            return !isBlocked;
        });
    }

    // 1. Filter by category
    if (activeDnsCategory !== 'all') {
        filtered = filtered.filter(q => {
            const isBlocked = q.is_blocked || (q.analysis && q.analysis.is_blocked) || q.ip === '0.0.0.0';
            if (activeDnsCategory === 'blocked') {
                return isBlocked;
            }
            const cat = (q.analysis && q.analysis.category) || 'unknown';
            const risk = (q.analysis && q.analysis.risk_level) || 'neutral';
            if (activeDnsCategory === 'suspicious') {
                return cat === 'suspicious' || risk === 'danger';
            }
            return cat === activeDnsCategory;
        });
    }

    // 2. Filter by search term
    if (term) {
        filtered = filtered.filter(q => {
            const dom = (q.domain || '').toLowerCase();
            const ip = (q.ip || '').toLowerCase();
            const desc = (q.analysis && q.analysis.description || '').toLowerCase();
            const vendor = (q.analysis && q.analysis.vendor || '').toLowerCase();
            const devMatch = (q.devices || []).some(d =>
                (d.hostname && d.hostname.toLowerCase().includes(term)) ||
                (d.custom_name && d.custom_name.toLowerCase().includes(term)) ||
                (d.ip && d.ip.includes(term))
            );
            return dom.includes(term) || ip.includes(term) || desc.includes(term) || vendor.includes(term) || devMatch;
        });
    }

    filtered = sortDnsQueries(filtered);
    renderDnsQueriesTable(filtered);
    updateSortIndicators('dns');
}

function renderDnsQueriesTable(queries) {
    const tbody = document.getElementById('dns-queries-tbody');
    if (!tbody) return;

    if (queries.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="py-8 text-center text-slate-500 italic font-sans">Домены не найдены по заданным критериям фильтра.</td></tr>';
        return;
    }

    tbody.innerHTML = queries.map(q => {
        const analysis = q.analysis || {};
        const categoryName = analysis.category_name || 'Не классифицирован';
        const badgeColor = analysis.badge_color || 'slate';
        const badgeText = analysis.badge_text || 'Нейтрально';
        const vendor = analysis.vendor || '';
        const description = analysis.description || '';
        const lastSeenStr = formatHumanTime(q.last_seen);
        const lastSeenFull = formatHumanFullDateTime(q.last_seen);

        const isBlocked = q.is_blocked || (analysis && analysis.is_blocked) || q.ip === '0.0.0.0';
        const isStaticSinkhole = Boolean(q.is_static_sinkhole || (analysis && analysis.is_static_sinkhole) || activeDnsSinkholes.includes((q.domain || '').toLowerCase().trim()));

        // Safety impact verdict & plain explanation
        const safetyLabel = analysis.safety_label || (isBlocked ? 'Заблокирован' : badgeText);
        const safetyColor = analysis.safety_color || (isBlocked ? 'rose' : badgeColor);
        const impactExplanation = analysis.impact_explanation || (isBlocked ? 'Домен заблокирован на DNS-уровне (0.0.0.0)' : 'Штатный сетевой трафик');

        // Badge styling
        const catBadgeClasses = {
            emerald: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
            amber: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
            rose: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
            blue: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
            purple: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
            cyan: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
            slate: 'bg-slate-800 text-slate-400 border-slate-700'
        }[badgeColor] || 'bg-slate-800 text-slate-400 border-slate-700';

        const safetyColorClasses = {
            emerald: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
            amber: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
            rose: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
            slate: 'bg-slate-800 text-slate-400 border-slate-700'
        }[safetyColor] || 'bg-slate-800 text-slate-400 border-slate-700';

        // Devices badges
        let devicesHtml = '<span class="text-slate-500 italic text-[11px]">—</span>';
        if (q.devices && q.devices.length > 0) {
            const firstDev = q.devices[0];
            const name = escapeHtml(firstDev.custom_name || firstDev.hostname || firstDev.ip || firstDev.mac || 'Устройство');
            if (q.devices.length === 1) {
                devicesHtml = `<span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-lg bg-surface-950 border border-slate-800 text-slate-300 text-[11px] font-sans" title="${escapeHtml(firstDev.mac)} (${escapeHtml(firstDev.ip || '')})">
                    <span class="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
                    <span class="truncate max-w-[140px]">${name}</span>
                </span>`;
            } else {
                devicesHtml = `<span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-lg bg-surface-950 border border-slate-800 text-slate-300 text-[11px] font-sans">
                    <span class="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
                    <span class="truncate max-w-[110px]">${name}</span>
                    <span class="text-indigo-400 font-bold ml-1">+${q.devices.length - 1}</span>
                </span>`;
            }
        }

        const providerName = (q.blocked_by_provider || (analysis && analysis.blocked_by_provider) || '').toLowerCase();
        let providerLabel = '';
        let providerColorClass = 'bg-rose-500/20 text-rose-300 border-rose-500/30';
        let providerIcon = 'shield-x';

        if (providerName === 'nextdns') {
            providerLabel = 'NextDNS';
            providerColorClass = 'bg-blue-500/20 text-blue-300 border-blue-500/30';
            providerIcon = 'shield-check';
        } else if (providerName === 'controld') {
            providerLabel = 'Control D';
            providerColorClass = 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
            providerIcon = 'shield-check';
        } else if (providerName === 'adguard_home' || providerName === 'adguard') {
            providerLabel = 'AdGuard';
            providerColorClass = 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
            providerIcon = 'shield-check';
        } else if (providerName === 'pihole') {
            providerLabel = 'Pi-hole';
            providerColorClass = 'bg-rose-500/20 text-rose-300 border-rose-500/30';
            providerIcon = 'shield-check';
        } else if (isStaticSinkhole) {
            providerLabel = 'Keenetic 0.0.0.0';
            providerColorClass = 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
            providerIcon = 'shield-check';
        } else if (isBlocked) {
            providerLabel = '0.0.0.0 Блок';
            providerColorClass = 'bg-rose-500/20 text-rose-300 border-rose-500/30';
            providerIcon = 'shield-x';
        }

        const blockedPillHtml = isBlocked
            ? `<span class="inline-flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] font-bold ${providerColorClass} shrink-0 ml-1.5 shadow-sm" title="${providerLabel ? 'Заблокирован: ' + providerLabel : '0.0.0.0'}">
                <i data-lucide="${providerIcon}" class="w-3 h-3"></i>
                <span>${providerLabel}</span>
               </span>`
            : '';

        const blockReasonDetail = q.filter_list || q.blocked_reason || (analysis && (analysis.filter_list || analysis.blocked_reason));
        const descText = isBlocked
            ? `🛡️ ${providerLabel ? providerLabel + ': ' : ''}${blockReasonDetail || 'Заблокирован (0.0.0.0)'}${description ? ' • ' + description : (vendor ? ' • ' + vendor : '')}`
            : (description || vendor || q.ip || '');

        const safetyBadgeHtml = isBlocked
            ? `<span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md text-[10px] font-bold border ${providerColorClass} cursor-help" title="${escapeHtml(impactExplanation)}">
                <i data-lucide="${providerIcon}" class="w-3 h-3"></i>
                <span>${isStaticSinkhole ? 'Заблокирован роутером' : (providerLabel ? `Заблокирован (${providerLabel})` : 'Заблокирован')}</span>
               </span>`
            : `<span class="inline-flex items-center space-x-1 px-2 py-0.5 rounded-md text-[10px] font-bold border ${safetyColorClasses} cursor-help" title="${escapeHtml(impactExplanation)}">
                <span>${escapeHtml(safetyLabel)}</span>
               </span>`;

        // 1-Click Keenetic Sinkhole action button
        let sinkholeBtnHtml = '';
        if (isStaticSinkhole) {
            sinkholeBtnHtml = `
                <button onclick="unblockDnsSinkhole('${escapeHtml(q.domain)}', event)" class="px-2 py-1 rounded-lg bg-emerald-500/15 hover:bg-rose-950/80 text-emerald-300 hover:text-rose-300 border border-emerald-500/30 hover:border-rose-700 text-[11px] font-semibold transition group/btn flex items-center space-x-1" title="Заблокирован на Keenetic (0.0.0.0). Нажмите для разблокировки">
                    <i data-lucide="check" class="w-3 h-3 text-emerald-400 group-hover/btn:hidden"></i>
                    <i data-lucide="unlock" class="w-3 h-3 text-rose-400 hidden group-hover/btn:inline"></i>
                    <span class="group-hover/btn:hidden">0.0.0.0</span>
                    <span class="hidden group-hover/btn:inline">Снять</span>
                </button>
            `;
        } else {
            sinkholeBtnHtml = `
                <button onclick="blockDnsSinkhole('${escapeHtml(q.domain)}', event)" class="px-2 py-1 rounded-lg bg-surface-950 hover:bg-rose-600 text-slate-300 hover:text-white border border-slate-700 hover:border-rose-500 text-[11px] font-medium transition flex items-center space-x-1 shadow-sm" title="Заблокировать на Keenetic (0.0.0.0 Sinkhole)">
                    <i data-lucide="ban" class="w-3 h-3 text-rose-400"></i>
                    <span>Блок</span>
                </button>
            `;
        }

        return `
            <tr class="hover:bg-slate-800/40 transition group cursor-pointer ${isBlocked ? 'bg-rose-950/10' : ''}" onclick="openDomainModal('${escapeHtml(q.domain)}')">
                <td class="py-3 px-4">
                    <div class="flex items-center space-x-2">
                        <span class="w-2 h-2 rounded-full ${isBlocked ? (isStaticSinkhole ? 'bg-indigo-400' : 'bg-rose-500 animate-pulse') : 'bg-' + badgeColor + '-400'} shrink-0"></span>
                        <div class="min-w-0">
                            <div class="flex items-center space-x-1">
                                <span class="text-white font-mono font-medium text-xs group-hover:text-indigo-300 transition truncate block">${escapeHtml(q.domain)}</span>
                                ${blockedPillHtml}
                            </div>
                            <span class="text-[11px] ${isBlocked ? 'text-rose-400/80 font-medium' : 'text-slate-400'} truncate block font-sans">${escapeHtml(descText)}</span>
                        </div>
                    </div>
                </td>
                <td class="py-3 px-4">
                    <span class="px-2 py-0.5 rounded-md text-[11px] font-medium border ${catBadgeClasses} inline-block whitespace-nowrap">
                        ${escapeHtml(categoryName)}
                    </span>
                </td>
                <td class="py-3 px-4 text-center">
                    ${safetyBadgeHtml}
                </td>
                <td class="py-3 px-4">
                    ${devicesHtml}
                </td>
                <td class="py-3 px-4 text-center font-bold text-slate-200 font-mono">${q.count || 1}</td>
                <td class="py-3 px-4 text-slate-400 font-mono text-[11px]" title="${escapeHtml(lastSeenFull)}">${lastSeenStr}</td>
                <td class="py-3 px-4 text-right" onclick="event.stopPropagation()">
                    <div class="flex items-center justify-end space-x-1.5">
                        ${sinkholeBtnHtml}
                        <button onclick="openDomainModal('${escapeHtml(q.domain)}')" class="px-2.5 py-1 bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white rounded-lg text-xs font-medium transition flex items-center space-x-1">
                            <i data-lucide="info" class="w-3.5 h-3.5"></i>
                            <span>Отчет</span>
                        </button>
                        <button onclick="deleteDnsQuery('${escapeHtml(q.domain)}', event)" class="p-1 rounded-lg bg-surface-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-800/50 transition" title="Удалить из истории">
                            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
}

// Domain Modal & Inspection Functions
async function openDomainModal(domain) {
    if (!domain) return;
    currentInspectingDomain = domain;

    const modal = document.getElementById('domain-detail-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    document.getElementById('domain-modal-name').textContent = domain;
    document.getElementById('domain-modal-vendor').textContent = 'Загрузка анализа...';
    document.getElementById('domain-modal-description').textContent = 'Анализ репутации и поиск устройств...';
    document.getElementById('domain-modal-keenetic-tip').textContent = '...';

    // Pre-populate devices from cached query list if available for immediate responsiveness
    const cachedQuery = (typeof allDnsQueries !== 'undefined' && Array.isArray(allDnsQueries))
        ? allDnsQueries.find(item => item.domain === domain)
        : null;

    if (cachedQuery && cachedQuery.devices && cachedQuery.devices.length > 0) {
        currentDomainModalDevices = cachedQuery.devices;
        const devCountElem = document.getElementById('domain-modal-devices-count');
        if (devCountElem) devCountElem.textContent = `${cachedQuery.devices.length} устройств(а)`;
        renderDomainModalDevicesTable();
    } else {
        const tbody = document.getElementById('domain-modal-devices-tbody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="py-3 text-center text-slate-500 italic">Загрузка связанных устройств...</td></tr>';
        const devCountElem = document.getElementById('domain-modal-devices-count');
        if (devCountElem) devCountElem.textContent = '0 устройств';
    }

    try {
        const res = await fetch(`/api/dns/analyze?domain=${encodeURIComponent(domain)}`);
        const data = await res.json();
        const analysis = data.analysis || {};
        const devices = (data.devices && data.devices.length > 0) ? data.devices : ((cachedQuery && cachedQuery.devices) || []);

        document.getElementById('domain-modal-name').textContent = analysis.domain || domain;
        document.getElementById('domain-modal-vendor').textContent = analysis.vendor || (domain.includes('samsung') ? 'Samsung Cloud Platform' : 'Неизвестный вендор');
        document.getElementById('domain-modal-description').textContent = analysis.description || analysis.recommendation || (domain.includes('telemetry') ? 'Сбор диагностических данных и активности устройства' : 'Описание недоступно.');
        document.getElementById('domain-modal-keenetic-tip').textContent = analysis.keenetic_tip || 'Рекомендаций по блокировке нет.';

        // Category & Risk badges
        const catBadge = document.getElementById('domain-modal-category-badge');
        const catTitle = analysis.category_name || (analysis.category === 'telemetry' ? 'Телеметрия' : analysis.category === 'streaming' ? 'Стриминг' : 'Сервисы');
        if (catBadge) catBadge.textContent = catTitle;

        const riskBadge = document.getElementById('domain-modal-risk-badge');
        const riskTitle = analysis.badge_text || (analysis.is_blocked ? 'Заблокирован' : analysis.risk_level === 'warning' ? 'Внимание' : 'Безопасно');
        if (riskBadge) riskBadge.textContent = riskTitle;

        const badgeColor = analysis.badge_color || 'slate';
        const colorClasses = {
            emerald: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
            amber: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
            rose: 'bg-rose-500/20 text-rose-300 border-rose-500/30',
            blue: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
            purple: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
            cyan: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30',
            slate: 'bg-slate-800 text-slate-400 border-slate-700'
        }[badgeColor] || 'bg-slate-800 text-slate-400 border-slate-700';

        if (catBadge) catBadge.className = `px-2 py-0.5 rounded text-xs font-bold border ${colorClasses}`;
        if (riskBadge) riskBadge.className = `px-2 py-0.5 rounded text-xs font-medium border ${colorClasses}`;

        // Populate Custom Override Fields
        const catSelect = document.getElementById('domain-custom-category');
        if (catSelect && analysis.category) catSelect.value = analysis.category;

        const riskSelect = document.getElementById('domain-custom-risk');
        if (riskSelect && analysis.risk_level) riskSelect.value = analysis.risk_level;

        const descInput = document.getElementById('domain-custom-desc');
        if (descInput) descInput.value = analysis.is_custom ? (analysis.description || '') : '';

        // Remediation & Safety Verdict
        const remBadge = document.getElementById('domain-remediation-safety-badge');
        const remImpact = document.getElementById('domain-remediation-impact');
        const remCode = document.getElementById('domain-remediation-code');
        const dName = analysis.domain || domain;

        if (remCode) {
            remCode.textContent = `ip host ${dName} 0.0.0.0`;
        }

        const cat = analysis.category || '';
        const risk = analysis.risk_level || '';

        if (data.is_blocked || analysis.is_blocked) {
            const providerName = (analysis.blocked_by_provider || data.blocked_by_provider || '').toLowerCase();
            const providerLabels = {
                'nextdns': 'NextDNS',
                'controld': 'Control D',
                'adguard_home': 'AdGuard Home',
                'adguard': 'AdGuard Home',
                'pihole': 'Pi-hole'
            };
            const pLabel = providerLabels[providerName] || (analysis.is_static_sinkhole ? 'Keenetic' : 'DNS');
            const filterName = analysis.filter_list || analysis.blocked_reason || data.filter_list || data.blocked_reason || '';

            if (remBadge) {
                remBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
                remBadge.textContent = `🛡️ Заблокирован (${pLabel}${filterName ? ': ' + filterName : ''})`;
            }
            if (remImpact) {
                remImpact.textContent = `Домен заблокирован службой фильтрации (${pLabel}). При обращении возвращается 0.0.0.0 — устройства не могут связаться с сервером и передать данные.`;
            }
            const tipEl = document.getElementById('domain-modal-keenetic-tip');
            if (tipEl) {
                tipEl.textContent = analysis.keenetic_tip || `✅ Домен уже находится в черном списке фильтрации (${pLabel}) и перенаправлен в 0.0.0.0. Дополнительных правил Keenetic не требуется.`;
            }
        } else if (cat === 'telemetry' || cat === 'advertising' || risk === 'ad' || risk === 'telemetry') {
            if (remBadge) {
                remBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
                remBadge.textContent = '🛡️ Блокировка безопасна (рекомендуется)';
            }
            if (remImpact) {
                remImpact.textContent = 'Отключение трекера заблокирует отправку маркетинговой аналитики и отчетов о ваших действиях. Видеостриминг (Кинопоиск, ivi, YouTube), воспроизведение и базовые функции приложений продолжат работать абсолютно штатно.';
            }
        } else if (risk === 'danger' || risk === 'warning' || cat === 'suspicious' || cat === 'vpn_tunnel') {
            if (remBadge) {
                remBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border bg-rose-500/20 text-rose-300 border-rose-500/40';
                remBadge.textContent = '🚨 Рекомендуется заблокировать';
            }
            if (remImpact) {
                remImpact.textContent = 'Подозрительный сетевой узел или сторонний туннель. Рекомендуется заблокировать для предотвращения утечек конфиденциальных данных и несанкционированного удаленного доступа.';
            }
        } else if (cat === 'iot_cloud') {
            if (remBadge) {
                remBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border bg-amber-500/20 text-amber-300 border-amber-500/40';
                remBadge.textContent = '⚠️ Блокировать с осторожностью';
            }
            if (remImpact) {
                remImpact.textContent = 'Это рабочий облачный сервер вендора умного дома. Блокировка может сделать невозможным удаленное управление устройством через мобильное приложение вне дома (хотя локальный опрос может сохраниться).';
            }
        } else {
            if (remBadge) {
                remBadge.className = 'px-2 py-0.5 rounded text-[10px] font-bold border bg-blue-500/20 text-blue-300 border-blue-500/40';
                remBadge.textContent = 'ℹ️ Штатная служба (не требует блокировки)';
            }
            if (remImpact) {
                remImpact.textContent = 'Легитимный системный трафик, CDN или служба проверки интернет-соединения. Блокировка может привести к потере доступа к сервису или ошибкам подключения.';
            }
        }

        // External links
        const ext = analysis.external_links || {};
        const vtLink = document.getElementById('domain-link-vt');
        if (vtLink && ext.virustotal) vtLink.href = ext.virustotal;

        const whoisLink = document.getElementById('domain-link-whois');
        if (whoisLink && ext.whois) whoisLink.href = ext.whois;

        const abuseLink = document.getElementById('domain-link-abuse');
        if (abuseLink) {
            if (ext.abuseipdb) {
                abuseLink.href = ext.abuseipdb;
                abuseLink.classList.remove('hidden');
            } else {
                abuseLink.classList.add('hidden');
            }
        }

        // Update 1-click Keenetic sinkhole button state in modal
        currentInspectingDomainIsSinkholed = Boolean(data.is_static_sinkhole || activeDnsSinkholes.includes((analysis.domain || domain).toLowerCase().trim()));
        const modalSinkBtn = document.getElementById('btn-modal-sinkhole-action');
        const modalSinkTxt = document.getElementById('btn-modal-sinkhole-text');
        const modalSinkIcon = document.getElementById('btn-modal-sinkhole-icon');
        if (modalSinkBtn && modalSinkTxt) {
            if (currentInspectingDomainIsSinkholed) {
                modalSinkBtn.className = 'px-3 py-2 rounded-lg bg-emerald-600/20 hover:bg-rose-900/80 text-emerald-300 hover:text-rose-200 border border-emerald-500/40 hover:border-rose-600 text-xs font-semibold transition flex items-center space-x-1.5 shrink-0 shadow-sm';
                modalSinkTxt.textContent = 'Разблокировать на Keenetic';
                if (modalSinkIcon) modalSinkIcon.setAttribute('data-lucide', 'unlock');
            } else {
                modalSinkBtn.className = 'px-3 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition flex items-center space-x-1.5 shrink-0 shadow-sm';
                modalSinkTxt.textContent = 'Заблокировать на Keenetic';
                if (modalSinkIcon) modalSinkIcon.setAttribute('data-lucide', 'shield-ban');
            }
        }

        // Render Accessing Devices
        const devCountElem = document.getElementById('domain-modal-devices-count');
        if (devCountElem) devCountElem.textContent = `${devices.length} устройств(а)`;

        currentDomainModalDevices = devices;
        renderDomainModalDevicesTable();
        updateSortIndicators('domain_modal');
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error analyzing domain in modal', e);
    }
}

async function toggleModalDnsSinkhole() {
    if (!currentInspectingDomain) return;
    if (currentInspectingDomainIsSinkholed) {
        await unblockDnsSinkhole(currentInspectingDomain);
    } else {
        await blockDnsSinkhole(currentInspectingDomain);
    }
    openDomainModal(currentInspectingDomain);
}

function sortDomainModalDevices(devices) {
    const { col, dir } = tableSortState.domain_modal;
    const mult = dir === 'asc' ? 1 : -1;

    return [...devices].sort((a, b) => {
        let cmp = 0;
        if (col === 'device') {
            const dA = a.custom_name || a.hostname || '';
            const dB = b.custom_name || b.hostname || '';
            cmp = dA.localeCompare(dB, 'ru');
        } else if (col === 'ip') {
            const ipA = a.ip || a.mac || '';
            const ipB = b.ip || b.mac || '';
            cmp = ipA.localeCompare(ipB, 'en');
        } else if (col === 'count') {
            cmp = (a.count || 0) - (b.count || 0);
        } else if (col === 'last_seen') {
            const tA = a.last_seen ? new Date(a.last_seen).getTime() : 0;
            const tB = b.last_seen ? new Date(b.last_seen).getTime() : 0;
            cmp = tA - tB;
        }
        return cmp * mult;
    });
}

function renderDomainModalDevicesTable() {
    const tbody = document.getElementById('domain-modal-devices-tbody');
    if (!tbody) return;

    if (!currentDomainModalDevices || currentDomainModalDevices.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-slate-500 italic text-xs">Нет данных об обращениях конкретных локальных устройств к этому домену.</td></tr>';
        return;
    }

    const sorted = sortDomainModalDevices(currentDomainModalDevices);
    tbody.innerHTML = sorted.map(d => {
        const name = escapeHtml(d.custom_name || d.hostname || 'Неизвестное устройство');
        const lastSeen = formatHumanTime(d.last_seen);
        const fullLastSeen = formatHumanFullDateTime(d.last_seen);
        return `
            <tr class="hover:bg-slate-800/30 transition text-xs">
                <td class="py-2.5 px-3">
                    <div class="font-bold text-white">${name}</div>
                    <div class="text-[10px] text-slate-400">${escapeHtml(d.vendor || d.profile || 'device')}</div>
                </td>
                <td class="py-2.5 px-3 font-mono text-slate-300 text-[11px]">
                    <div>${escapeHtml(d.ip || '—')}</div>
                    <div class="text-[10px] text-slate-500">${escapeHtml(d.mac || '')}</div>
                </td>
                <td class="py-2.5 px-3 text-center font-bold text-slate-200 font-mono">${d.count || 1}</td>
                <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px]" title="${escapeHtml(fullLastSeen)}">${lastSeen}</td>
            </tr>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons();
}

function closeDomainModal() {
    const modal = document.getElementById('domain-detail-modal');
    if (modal) modal.classList.add('hidden');
    currentInspectingDomain = null;
}

function copyDomainRemediationRule() {
    const codeElem = document.getElementById('domain-remediation-code');
    const feedback = document.getElementById('domain-copy-feedback');
    if (!codeElem) return;

    const text = codeElem.textContent.trim();
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            if (feedback) {
                feedback.classList.remove('hidden');
                setTimeout(() => feedback.classList.add('hidden'), 2500);
            }
        }).catch(err => {
            console.error('Clipboard copy failed', err);
            prompt('Скопируйте команду для Keenetic:', text);
        });
    } else {
        prompt('Скопируйте команду для Keenetic:', text);
    }
}

function inspectCustomDomain() {
    const input = document.getElementById('dns-inspect-input');
    const domain = (input ? input.value : '').trim();
    if (!domain) return;
    openDomainModal(domain);
}

async function saveCustomDomainRule() {
    if (!currentInspectingDomain) return;

    const category = document.getElementById('domain-custom-category').value;
    const risk_level = document.getElementById('domain-custom-risk').value;
    const description = document.getElementById('domain-custom-desc').value.trim();

    try {
        const res = await fetch('/api/dns/custom-rule', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain: currentInspectingDomain,
                category: category,
                risk_level: risk_level,
                description: description
            })
        });

        if (res.ok) {
            await loadDnsQueries();
            await openDomainModal(currentInspectingDomain);
            alert(`Пользовательское правило для ${currentInspectingDomain} успешно сохранено!`);
        }
    } catch (e) {
        console.error('Error saving custom domain rule', e);
    }
}

async function updateDomainSignatures(triggerBtn) {
    const btn = triggerBtn || document.getElementById('btn-header-update-signatures') || document.getElementById('btn-update-dns-sig');
    const textEl = document.getElementById('update-signatures-btn-text');
    const iconWrap = document.getElementById('update-signatures-btn-icon-wrap') || (btn ? btn.querySelector('span:first-child') : null);
    const originalText = 'Обновить базы из интернета';

    if (btn) {
        btn.disabled = true;
        btn.classList.add('opacity-75', 'cursor-not-allowed');
    }
    if (textEl) textEl.textContent = 'Загрузка баз (AdGuard + StevenBlack)...';
    if (iconWrap) iconWrap.classList.add('animate-spin');

    let count = 0;
    let isSuccess = false;

    try {
        const res = await fetch('/api/dns/update-signatures', { method: 'POST' });
        const data = await res.json();
        count = data.updated_count || data.total_signatures || 0;
        isSuccess = res.ok;
        showToast(`✅ Базы сигнатур обновлены: ${count.toLocaleString('ru-RU')} правил загружено`, 'success');
        await Promise.allSettled([
            loadDnsQueries(),
            (typeof loadDnsFilterTab === 'function' ? loadDnsFilterTab() : Promise.resolve())
        ]);
    } catch (e) {
        console.error('Error updating domain signatures', e);
        showToast('Не удалось загрузить базы из сети. Используются локальные сигнатуры.', 'warning');
    } finally {
        if (iconWrap) iconWrap.classList.remove('animate-spin');
        const allSpinners = document.querySelectorAll('#btn-header-update-signatures .animate-spin, #btn-update-dns-sig .animate-spin');
        allSpinners.forEach(el => el.classList.remove('animate-spin'));

        if (btn) {
            btn.disabled = false;
            btn.classList.remove('opacity-75', 'cursor-not-allowed');
        }

        if (textEl) {
            if (isSuccess && count > 0) {
                textEl.textContent = `✓ Базы обновлены (${count.toLocaleString('ru-RU')})`;
                setTimeout(() => {
                    if (textEl) textEl.textContent = originalText;
                }, 3500);
            } else {
                textEl.textContent = originalText;
            }
        }

        if (window.lucide) {
            lucide.createIcons();
        }
    }
}

async function deleteDnsQuery(domain, ev) {
    if (ev) ev.stopPropagation();
    if (!domain) return;
    if (!confirm(`Удалить домен "${domain}" и статистику обращений к нему?`)) {
        return;
    }
    try {
        const res = await fetch(`/api/dns/queries/${encodeURIComponent(domain)}`, { method: 'DELETE' });
        if (res.ok) {
            showToast(`Домен ${domain} удален из истории`);
            await loadDnsQueries();
        } else {
            showToast('Ошибка при удалении домена');
        }
    } catch (e) {
        console.error('Error deleting DNS query', e);
        showToast('Ошибка сети при удалении домена');
    }
}

async function deleteCurrentDomain() {
    if (!currentInspectingDomain) return;
    if (!confirm(`Удалить домен "${currentInspectingDomain}" и историю обращений из базы данных?`)) {
        return;
    }
    try {
        const res = await fetch(`/api/dns/queries/${encodeURIComponent(currentInspectingDomain)}`, { method: 'DELETE' });
        if (res.ok) {
            closeDomainModal();
            showToast(`Домен ${currentInspectingDomain} удален из истории`);
            await loadDnsQueries();
        } else {
            showToast('Ошибка при удалении домена');
        }
    } catch (e) {
        console.error('Error deleting current domain', e);
        showToast('Ошибка сети при удалении домена');
    }
}

function openClearDnsModal() {
    const modal = document.getElementById('clear-dns-modal');
    if (!modal) return;

    const catLabels = {
        all: 'Все',
        iot_cloud: 'Облака IoT',
        telemetry: 'Телеметрия',
        advertising: 'Реклама',
        system_dns: 'Системные / DNS',
        vpn_tunnel: 'VPN / Туннели',
        cdn_media: 'Медиа и CDN',
        suspicious: 'Подозрительные',
        unknown: 'Неизвестные'
    };
    const activeLabel = catLabels[activeDnsCategory] || activeDnsCategory || 'Все';
    const activeCatElem = document.getElementById('clear-dns-active-cat-name');
    if (activeCatElem) {
        activeCatElem.textContent = activeLabel;
    }

    if (activeDnsCategory && activeDnsCategory !== 'all') {
        const rad = document.getElementById('clear-dns-scope-active');
        if (rad) rad.checked = true;
    } else {
        const rad = document.getElementById('clear-dns-scope-all');
        if (rad) rad.checked = true;
    }
    onClearDnsScopeChange();
    modal.classList.remove('hidden');
}

function closeClearDnsModal() {
    const modal = document.getElementById('clear-dns-modal');
    if (modal) modal.classList.add('hidden');
}

function onClearDnsScopeChange() {
    const specificRad = document.getElementById('clear-dns-scope-category');
    const catSelect = document.getElementById('clear-dns-cat-select');
    if (catSelect && specificRad) {
        catSelect.disabled = !specificRad.checked;
        if (specificRad.checked) {
            catSelect.classList.remove('opacity-50');
        } else {
            catSelect.classList.add('opacity-50');
        }
    }
}

async function executeClearDns() {
    const scope = document.querySelector('input[name="clear-dns-scope"]:checked')?.value || 'all';
    let url = '/api/dns/queries';
    let confirmMsg = 'Вы действительно хотите полностью очистить всю историю DNS-запросов и счетчиков обращений?';

    if (scope === 'active') {
        if (activeDnsCategory && activeDnsCategory !== 'all') {
            url += `?category=${encodeURIComponent(activeDnsCategory)}`;
            const catElem = document.getElementById('clear-dns-active-cat-name');
            const catName = catElem ? catElem.textContent : activeDnsCategory;
            confirmMsg = `Удалить из истории все домены категории «${catName}»?`;
        }
    } else if (scope === 'specific') {
        const catSelect = document.getElementById('clear-dns-cat-select');
        const selectedCat = catSelect ? catSelect.value : 'unknown';
        url += `?category=${encodeURIComponent(selectedCat)}`;
        const selectedText = catSelect && catSelect.options[catSelect.selectedIndex] ? catSelect.options[catSelect.selectedIndex].text : selectedCat;
        confirmMsg = `Удалить из истории все домены категории «${selectedText}»?`;
    }

    if (!confirm(confirmMsg)) {
        return;
    }

    const btn = document.getElementById('btn-confirm-clear-dns');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch(url, { method: 'DELETE' });
        const data = await res.json();
        closeClearDnsModal();
        showToast(`История DNS очищена (удалено доменов: ${data.deleted || 0})`);
        await loadDnsQueries();
    } catch (e) {
        console.error('Error clearing DNS queries', e);
        showToast('Ошибка при очистке доменов');
    } finally {
        if (btn) btn.disabled = false;
    }
}

