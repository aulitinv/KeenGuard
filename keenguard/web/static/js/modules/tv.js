// Smart TV Forensics
async function loadTvForensics() {
    loadTvBrandPresets();
    // Update TV wake capture window badge from settings
    try {
        const sRes = await fetch('/api/settings');
        if (sRes.ok) {
            const s = await sRes.json();
            const badge = document.getElementById('tv-wake-window-label');
            if (badge) {
                const pre = s.tv_wake_pre_record_seconds !== undefined ? s.tv_wake_pre_record_seconds : 30;
                const post = s.tv_wake_post_record_seconds !== undefined ? s.tv_wake_post_record_seconds : 30;
                badge.textContent = `-${pre}с / +${post}с`;
            }
        }
    } catch (_) {}

    const container = document.getElementById('tv-quick-controls');
    const tvs = devicesList.filter(d => d.profile === 'smart_tv');

    if (tvs.length === 0) {
        container.innerHTML = `
            <div class="col-span-full p-4 rounded-xl bg-slate-800/40 text-slate-400 text-xs text-center">
                Smart TV еще не обнаружен или не выбран в списке устройств. Назначьте телевизору профиль "Smart TV" на вкладке "Устройства".
            </div>
        `;
    } else {
        container.innerHTML = tvs.map(tv => `
            <div class="bg-surface-950/80 border border-slate-800 rounded-xl p-4 space-y-3">
                <div class="flex items-center justify-between">
                    <span class="font-bold text-sm text-white">${escapeHtml(tv.custom_name || tv.hostname || tv.ip)}</span>
                    <span class="text-xs text-slate-400 font-mono">${escapeHtml(tv.ip)}</span>
                </div>
                <div class="space-y-2 text-xs">
                    <div class="flex items-center justify-between py-1 border-b border-slate-800/60">
                        <span class="text-slate-300">Сеть / Изоляция LAN</span>
                        ${tv.is_isolated_lan 
                            ? '<span class="px-2 py-0.5 rounded text-[11px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium">🔒 Изолирован (Guest)</span>' 
                            : '<span class="px-2 py-0.5 rounded text-[11px] bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium cursor-help" title="Для физической изоляции телевизора от ПК подключите его к Гостевой Wi-Fi сети Keenetic">🔓 В общей сети (Bridge0)</span>'
                        }
                    </div>
                    <div class="flex items-center justify-between py-1 border-b border-slate-800/60">
                        <span class="text-slate-300">AirPlay / Cast</span>
                        <span class="text-slate-200 font-medium text-[11px]">${tv.is_isolated_lan ? 'Требуется UDP Proxy' : 'Доступен (в одной сети)'}</span>
                    </div>
                    <div class="flex items-center justify-between py-1 border-b border-slate-800/60">
                        <span class="text-slate-300">Keenetic DLNA</span>
                        <span class="text-slate-200 font-medium text-[11px]">Порт 8200 роутера доступен</span>
                    </div>
                    <div class="pt-1">
                        <label class="flex items-center justify-between cursor-pointer">
                            <div>
                                <span class="text-slate-200 font-medium block">🌙 Пассивный ночной мониторинг</span>
                                <span class="text-[10px] text-slate-500 block">Запись PCAP при пробуждении (WOL/mDNS)</span>
                            </div>
                            <input type="checkbox" ${tv.night_mode_enabled ? 'checked' : ''} data-mac="${escapeHtml(tv.mac)}" onchange="toggleTvNight(this.dataset.mac, this.checked)" class="w-4 h-4 rounded text-indigo-600 shrink-0">
                        </label>
                    </div>
                </div>
            </div>
        `).join('');
    }

    // Load Forensics Events
    try {
        const res = await fetch('/api/events?limit=50');
        const events = await res.json();
        const tvEvents = events.filter(e => e.event_type.includes('wake') || e.event_type.includes('airplay') || e.event_type.includes('cast'));
        const list = document.getElementById('tv-forensics-list');

        let pcapCount = 0;
        events.forEach(e => { if (e.pcap_file) pcapCount++; });
        document.getElementById('tv-pcap-count').textContent = pcapCount;

        if (tvEvents.length === 0) {
            list.innerHTML = '<div class="text-slate-500 text-sm italic text-center py-6">Журнал событий пуст. Ночные инциденты отсутствуют.</div>';
        } else {
            list.innerHTML = tvEvents.map(e => {
                const isCrit = e.severity === 'critical';
                const isWarn = e.severity === 'warning';
                const border = isCrit ? 'border-rose-500/30 bg-rose-950/20' : isWarn ? 'border-amber-500/30 bg-amber-950/20' : 'border-slate-800 bg-surface-950/60';
                const timeStr = new Date(e.timestamp).toLocaleString();

                return `
                    <div class="border ${border} rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                        <div class="space-y-1">
                            <div class="flex items-center space-x-2">
                                <span class="text-xs font-semibold px-2 py-0.5 rounded ${isCrit ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-300'}">${escapeHtml(e.event_type.toUpperCase())}</span>
                                <span class="text-xs text-slate-500">${timeStr}</span>
                            </div>
                            <p class="text-sm font-medium text-slate-200">${escapeHtml(e.description)}</p>
                            ${e.source_ip ? `<p class="text-xs text-slate-400">Источник команды: <span class="font-mono text-indigo-300">${escapeHtml(e.source_ip)} (${escapeHtml(e.source_mac || 'MAC N/A')})</span></p>` : ''}
                        </div>
                        ${e.pcap_file ? `
                            <a href="/api/events/pcap/${encodeURIComponent(e.pcap_file)}" download="${escapeHtml(e.pcap_file)}" class="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 transition shrink-0">
                                <i data-lucide="download" class="w-3.5 h-3.5"></i>
                                <span>Скачать PCAP</span>
                            </a>
                        ` : ''}
                    </div>
                `;
            }).join('');
        }
        lucide.createIcons();
    } catch (e) {
        console.error('Error loading tv forensics', e);
    }
}

// ==========================================
// Smart TV Brand Presets & DNS Sinkholes
// ==========================================
let tvBrandPresetsData = null;
let activeTvBrandId = 'tv_lg';

async function loadTvBrandPresets() {
    try {
        const res = await fetch('/api/tv/brand_presets');
        if (!res.ok) return;
        tvBrandPresetsData = await res.json();

        if (!activeTvBrandId || !tvBrandPresetsData.presets.some(p => p.id === activeTvBrandId)) {
            activeTvBrandId = tvBrandPresetsData.suggested_brand || 'tv_lg';
        }

        renderTvBrandPresets();
    } catch (e) {
        console.error('Error loading TV brand presets', e);
    }
}

function renderTvBrandPresets() {
    if (!tvBrandPresetsData || !tvBrandPresetsData.presets) return;

    // 1. Update total active sinkholes badge
    safeSetText('tv-sinkholes-total-badge', `${tvBrandPresetsData.active_sinkholes_count || 0} активных правил 0.0.0.0`);

    // 2. Render brand tabs
    const tabsContainer = document.getElementById('tv-brand-preset-tabs');
    if (tabsContainer) {
        tabsContainer.innerHTML = tvBrandPresetsData.presets.map(p => {
            const isActiveTab = p.id === activeTvBrandId;
            const hasDetected = p.detected_devices && p.detected_devices.length > 0;
            const tabClass = isActiveTab
                ? 'bg-indigo-600 text-white shadow-sm'
                : 'bg-surface-950/60 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-slate-800';

            return `
                <button type="button" data-preset-id="${escapeHtml(p.id)}" onclick="switchTvBrandTab(this.dataset.presetId)" class="px-3.5 py-2 rounded-xl text-xs font-medium transition flex items-center space-x-2 shrink-0 ${tabClass}">
                    <span>${escapeHtml(p.name || p.brand || 'Smart TV')}</span>
                    ${hasDetected ? '<span class="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">В сети</span>' : ''}
                    <span class="px-1.5 py-0.2 rounded-full text-[10px] ${isActiveTab ? 'bg-indigo-700 text-indigo-100' : 'bg-slate-800 text-slate-400'}">${p.active_count ?? 0}/${p.total_count ?? p.blocked_domains_count ?? 0}</span>
                </button>
            `;
        }).join('');
    }

    // 3. Find active preset
    const preset = tvBrandPresetsData.presets.find(p => p.id === activeTvBrandId) || tvBrandPresetsData.presets[0];
    if (!preset) return;

    // Update block button labels
    safeSetText('btn-block-safe-tv-brand-label', `🟢 Заблокировать без риска (${preset.safe_count || 0})`);
    safeSetText('btn-block-tv-brand-label', `⛔ Блокировать ВСЕ (${preset.total_count || 0})`);

    // 4. Render active brand details (detected devices, troubleshooting guide, and remote hint)
    const detailsContainer = document.getElementById('tv-brand-preset-details');
    if (detailsContainer) {
        let detectedHtml = '';
        if (preset.detected_devices && preset.detected_devices.length > 0) {
            detectedHtml = `
                <div class="p-3.5 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex items-center justify-between">
                    <div class="flex items-center space-x-2.5">
                        <div class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></div>
                        <div>
                            <span class="text-xs font-semibold text-emerald-200">Обнаружен телевизор в сети:</span>
                            <span class="text-xs text-slate-300 ml-1 font-medium">${preset.detected_devices.map(d => `${escapeHtml(d.custom_name || d.hostname || d.ip)} (${d.ip})`).join(', ')}</span>
                        </div>
                    </div>
                    <span class="text-[11px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Рекомендуемый пресет</span>
                </div>
            `;
        }

        detailsContainer.innerHTML = `
            ${detectedHtml}

            <!-- Quick Troubleshooting & Safety Guide -->
            <div class="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-800/80 pb-2">
                    <div class="flex items-center space-x-2 text-indigo-300 font-semibold text-xs">
                        <i data-lucide="help-circle" class="w-4 h-4 text-indigo-400"></i>
                        <span>Шпаргалка: что безопасно блокировать, а что разблокировать при проблемах</span>
                    </div>
                    <span class="text-[10px] text-emerald-400/90 font-medium">Стриминг (YouTube, Кинопоиск), HDMI и DLNA не ломаются</span>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs">
                    <div class="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/20 space-y-1">
                        <div class="font-semibold text-emerald-300 flex items-center space-x-1.5 text-[11px]">
                            <span class="w-2 h-2 rounded-full bg-emerald-400 shrink-0"></span>
                            <span>🟢 Безопасно блокировать (Реклама & ACR)</span>
                        </div>
                        <p class="text-[11px] text-slate-300 leading-snug">Баннеры на экране, промо и шпионская ACR-слежка (Live Plus). Блокируются без риска для видео и приложений ТВ.</p>
                    </div>
                    <div class="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 space-y-1">
                        <div class="font-semibold text-amber-300 flex items-center space-x-1.5 text-[11px]">
                            <span class="w-2 h-2 rounded-full bg-amber-400 shrink-0"></span>
                            <span>🟡 Блокировать с осторожностью (Голос / Магазин)</span>
                        </div>
                        <p class="text-[11px] text-slate-300 leading-snug">Голосовой пульт (микрофон), магазин приложений или вход в учетную запись вендора. Блокируйте, если не пользуетесь ими.</p>
                    </div>
                    <div class="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-500/20 space-y-1">
                        <div class="font-semibold text-cyan-300 flex items-center space-x-1.5 text-[11px]">
                            <i data-lucide="life-buoy" class="w-3.5 h-3.5 text-cyan-400 shrink-0"></i>
                            <span>🔧 Что разблокировать при сбое</span>
                        </div>
                        <p class="text-[11px] text-slate-300 leading-snug">Не работает микрофон на пульте? Разблокируйте домен с пометкой <b>«Голосовой поиск»</b>. Ошибка магазина? Разблокируйте <b>«App Store»</b>.</p>
                    </div>
                </div>
            </div>

            <!-- Remote physical hint -->
            <div class="p-4 rounded-xl bg-indigo-950/20 border border-indigo-500/30 space-y-2">
                <div class="flex items-center space-x-2 text-indigo-300 font-semibold text-xs">
                    <i data-lucide="tv" class="w-4 h-4 shrink-0"></i>
                    <span>Физическое отключение ACR (распознавания контента) на пульте ${preset.name || preset.brand || 'телевизора'}</span>
                </div>
                <p class="text-xs text-slate-300 leading-relaxed font-sans">
                    ${escapeHtml(preset.manual_hint)}
                </p>
                ${preset.doh_remedy_hint ? `
                    <div class="pt-1 text-[11px] text-slate-400 flex items-start space-x-1.5 border-t border-indigo-500/10 mt-2">
                        <i data-lucide="shield-alert" class="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5"></i>
                        <span>${escapeHtml(preset.doh_remedy_hint)}</span>
                    </div>
                ` : ''}
            </div>
        `;
    }

    // 5. Render domains table
    const tbody = document.getElementById('tv-brand-preset-domains-tbody');
    if (tbody) {
        if (!preset.domains || preset.domains.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="py-6 text-center text-slate-500 italic">Нет доменов в пресете</td></tr>';
        } else {
            tbody.innerHTML = preset.domains.map(d => {
                const isBlocked = d.is_active;
                const isSafe = d.safety === 'safe';
                const safetyBadge = isSafe
                    ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">🟢 ${escapeHtml(d.safety_label || 'Безопасно блокировать')}</span>`
                    : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">🟡 ${escapeHtml(d.safety_label || 'Блокировать с осторожностью')}</span>`;

                const catColor = d.category === 'advertising' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20';
                const catText = d.category === 'advertising' ? 'Реклама' : 'Телеметрия / ACR';

                return `
                    <tr class="hover:bg-slate-800/30 transition">
                        <td class="py-3.5 px-4 align-top">
                            <div class="space-y-1.5">
                                <span class="font-mono text-white text-xs font-semibold select-all block">${escapeHtml(d.domain)}</span>
                                <div>${safetyBadge}</div>
                            </div>
                        </td>
                        <td class="py-3.5 px-4 align-top">
                            <div class="space-y-1.5">
                                <div>
                                    <span class="text-xs text-slate-100 font-semibold">${escapeHtml(d.name || '')}</span>
                                    <span class="text-[11px] text-slate-400 ml-1.5">${escapeHtml(d.description || '')}</span>
                                </div>
                                <div class="p-2 rounded-lg bg-surface-950/70 border border-slate-800/80 space-y-1 text-[11px]">
                                    <div class="flex items-start space-x-1.5 text-slate-300">
                                        <span class="text-slate-400 font-medium shrink-0">Влияние блокировки:</span>
                                        <span class="leading-relaxed">${escapeHtml(d.impact || 'Блокирует сетевой доступ к сервису.')}</span>
                                    </div>
                                    ${d.troubleshoot ? `
                                        <div class="flex items-start space-x-1.5 text-amber-300/90 pt-1 border-t border-slate-800/60">
                                            <span class="font-semibold shrink-0">💡 Если проблемы:</span>
                                            <span class="leading-relaxed">${escapeHtml(d.troubleshoot)}</span>
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        </td>
                        <td class="py-3.5 px-4 align-top">
                            <span class="px-2 py-0.5 rounded text-[11px] font-medium border ${catColor} inline-block whitespace-nowrap">${catText}</span>
                        </td>
                        <td class="py-3.5 px-4 text-center align-top">
                            ${isBlocked
                                ? '<span class="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"><i data-lucide="shield-check" class="w-3.5 h-3.5 mr-1"></i>0.0.0.0 (Блок)</span>'
                                : '<span class="inline-flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs text-slate-400 bg-slate-800/80 border border-slate-700">Пропускается</span>'
                            }
                        </td>
                        <td class="py-3.5 px-4 text-right align-top">
                            <button type="button" data-domain="${escapeHtml(d.domain)}" data-blocked="${!isBlocked}" onclick="toggleTvBrandDomain(this.dataset.domain, this.dataset.blocked === 'true')" class="px-3 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${isBlocked ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700' : 'bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30'}">
                                ${isBlocked ? 'Разблокировать' : '⛔ Блокировать'}
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }
    }

    if (window.lucide) {
        lucide.createIcons();
    }
}

function switchTvBrandTab(brandId) {
    activeTvBrandId = brandId;
    renderTvBrandPresets();
}

async function blockSelectedTvBrandPreset(onlySafe = false) {
    if (!activeTvBrandId) return;
    const btnId = onlySafe ? 'btn-block-safe-tv-brand-preset' : 'btn-block-tv-brand-preset';
    const btn = document.getElementById(btnId);
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/tv/sinkhole/block_preset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preset: activeTvBrandId, only_safe: Boolean(onlySafe), save_config: true })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || 'Пресет успешно применен (0.0.0.0)');
            await loadTvBrandPresets();
        } else {
            showToast(data.detail || 'Ошибка применения пресета', true);
        }
    } catch (e) {
        console.error('Error applying TV preset', e);
        showToast('Ошибка сетевого запроса к Keenetic', true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function unblockSelectedTvBrandPreset() {
    if (!activeTvBrandId) return;
    const btn = document.getElementById('btn-unblock-tv-brand-preset');
    if (btn) btn.disabled = true;

    try {
        const res = await fetch('/api/tv/sinkhole/unblock_preset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preset: activeTvBrandId, save_config: true })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || 'Правила пресета сняты');
            await loadTvBrandPresets();
        } else {
            showToast(data.detail || 'Ошибка снятия правил', true);
        }
    } catch (e) {
        console.error('Error unblocking TV preset', e);
        showToast('Ошибка сетевого запроса к Keenetic', true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function toggleTvBrandDomain(domain, shouldBlock) {
    try {
        const res = await fetch('/api/tv/sinkhole/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: domain, block: shouldBlock, save_config: true })
        });
        const data = await res.json();
        if (res.ok) {
            showToast(data.message || `Домен ${domain} обновлен`);
            await loadTvBrandPresets();
        } else {
            showToast(data.detail || 'Ошибка обновления правила', true);
        }
    } catch (e) {
        console.error('Error toggling TV domain sinkhole', e);
        showToast('Ошибка сетевого запроса к роутеру', true);
    }
}


async function toggleTvAirplay(mac, val) {
    await fetch(`/api/devices/${mac}/toggle_airplay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

async function toggleTvDlna(mac, val) {
    try {
        await fetch(`/api/devices/${mac}/toggle_dlna`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: val })
        });
        loadDevices();
    } catch (e) {
        console.error('Failed to toggle TV DLNA:', e);
    }
}

async function toggleTvNight(mac, val) {
    try {
        await fetch(`/api/devices/${mac}/toggle_night`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: val })
        });
        loadDevices();
    } catch (e) {
        console.error('Failed to toggle TV Night Mode:', e);
    }
}

