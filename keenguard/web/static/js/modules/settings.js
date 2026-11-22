// Settings Navigation & Sub-tab Switching
async function toggleSettingsTab(event) {
    if (event && event.preventDefault) event.preventDefault();
    const submenu = document.getElementById('settings-submenu');
    const chev = document.getElementById('settings-chevron');
    if (activeTab !== 'settings') {
        await switchTab('settings');
        if (submenu) submenu.classList.remove('hidden');
        if (chev) chev.classList.add('rotate-180');
    } else {
        if (submenu) {
            const isHidden = submenu.classList.toggle('hidden');
            if (chev) {
                if (isHidden) chev.classList.remove('rotate-180');
                else chev.classList.add('rotate-180');
            }
        }
    }
}
window.toggleSettingsTab = toggleSettingsTab;

async function navigateToSettingsSubTab(subtabId) {
    if (activeTab !== 'settings') {
        await switchTab('settings');
    }
    const submenu = document.getElementById('settings-submenu');
    if (submenu) submenu.classList.remove('hidden');
    const chev = document.getElementById('settings-chevron');
    if (chev) chev.classList.add('rotate-180');
    switchSettingsSubTab(subtabId);
}
window.navigateToSettingsSubTab = navigateToSettingsSubTab;

function switchSettingsSubTab(subtabId) {
    const tabs = ['router', 'new-devices', 'cameras', 'telegram', 'tv-night', 'schedules', 'storage', 'presets', 'dns-security', 'web-access'];
    if (!tabs.includes(subtabId)) subtabId = 'router';

    const subtabMeta = {
        'router': { title: 'Роутер', desc: 'Адрес и параметры доступа к роутеру для работы с RCI API' },
        'new-devices': { title: 'Новые устройства', desc: 'Политики изоляции, карантина и авто-аудита для подключаемых клиентов' },
        'cameras': { title: 'Камеры', desc: 'Детекция утечек в WAN, контроль локальных RTSP/ONVIF стримов и пороги битрейта' },
        'telegram': { title: 'Telegram & Тревоги', desc: 'Интеграция с Telegram-ботом, отправка алертов и шлюзы' },
        'tv-night': { title: 'Smart TV & Ночь', desc: 'Анализ ночных пробуждений, буфер предзаписи пакетов и дневной режим' },
        'schedules': { title: 'Расписание & Дайджест', desc: 'Ежедневный отчет безопасности и автоматический ночной экспресс-аудит' },
        'storage': { title: 'Хранилище & PCAP', desc: 'Управление дампом полезной нагрузки IoT и лимитами диска' },
        'presets': { title: 'Пресеты LAN', desc: 'Профили изоляции и надзора для устройств локальной сети' },
        'dns-security': { title: 'DNS-безопасность', desc: 'Интеграция с NextDNS, Control D, AdGuard Home и Pi-hole, синхронизация заблокированных запросов' },
        'web-access': { title: 'Сетевой доступ & Пароль', desc: 'Управление IP-привязкой (127.0.0.1 vs 0.0.0.0), защитой от брутфорса и паролем администратора' },
    };

    tabs.forEach(id => {
        const btn = document.getElementById(`subtab-btn-${id}`);
        const pane = document.getElementById(`settings-subpane-${id}`);
        if (id === subtabId) {
            if (btn) {
                btn.className = 'sidebar-subtab-btn settings-subtab-btn flex items-center space-x-2.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition w-full text-left bg-indigo-600 text-white shadow-sm';
            }
            if (pane) pane.classList.remove('hidden');
        } else {
            if (btn) {
                btn.className = 'sidebar-subtab-btn settings-subtab-btn flex items-center space-x-2.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition w-full text-left text-slate-400 hover:text-slate-200 hover:bg-slate-800/60';
            }
            if (pane) pane.classList.add('hidden');
        }
    });

    const titleEl = document.getElementById('settings-current-subtab-title');
    if (titleEl && subtabMeta[subtabId]) titleEl.textContent = subtabMeta[subtabId].title;
    const descEl = document.getElementById('settings-current-subtab-desc');
    if (descEl && subtabMeta[subtabId]) descEl.textContent = subtabMeta[subtabId].desc;

    if (subtabId === 'dns-security') {
        loadDnsProviderConfig();
        loadDnsProviderStatus();
    } else if (subtabId === 'storage') {
        loadIotStorageSettings();
    } else if (subtabId === 'web-access') {
        loadWebAccessSettings();
    }

    try {
        localStorage.setItem('keenguard_settings_subtab', subtabId);
    } catch (e) {}
    if (window.lucide) lucide.createIcons();
}
window.switchSettingsSubTab = switchSettingsSubTab;

let currentRouterPlatform = 'keenetic';

function switchRouterPlatform(platform) {
    currentRouterPlatform = platform || 'keenetic';
    const btnK = document.getElementById('btn-router-plat-keenetic');
    const btnO = document.getElementById('btn-router-plat-openwrt');
    const formK = document.getElementById('router-form-keenetic');
    const formO = document.getElementById('router-form-openwrt');
    const testBtnText = document.getElementById('btn-test-router-text');

    if (currentRouterPlatform === 'openwrt') {
        if (btnK) btnK.className = 'px-3 py-1 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition';
        if (btnO) btnO.className = 'px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        if (formK) formK.classList.add('hidden');
        if (formO) formO.classList.remove('hidden');
        if (testBtnText) testBtnText.textContent = 'Проверить связь с OpenWrt';
    } else {
        if (btnK) btnK.className = 'px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        if (btnO) btnO.className = 'px-3 py-1 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition';
        if (formK) formK.classList.remove('hidden');
        if (formO) formO.classList.add('hidden');
        if (testBtnText) testBtnText.textContent = 'Проверить связь с Keenetic';
    }
}
window.switchRouterPlatform = switchRouterPlatform;

// Settings
async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const s = await res.json();

        // Router Platform
        if (s.router_type) {
            switchRouterPlatform(s.router_type);
        }

        // Keenetic inputs
        const hostEl = document.getElementById('cfg-host');
        if (hostEl && s.router_host !== undefined) hostEl.value = s.router_host;
        const userEl = document.getElementById('cfg-user');
        if (userEl && s.router_user !== undefined) userEl.value = s.router_user;

        // OpenWrt inputs
        const owHostEl = document.getElementById('cfg-openwrt-host');
        if (owHostEl && s.openwrt_host !== undefined) owHostEl.value = s.openwrt_host;
        const owPortEl = document.getElementById('cfg-openwrt-port');
        if (owPortEl && s.openwrt_port !== undefined) owPortEl.value = s.openwrt_port;
        const owHttpsEl = document.getElementById('cfg-openwrt-https');
        if (owHttpsEl && s.openwrt_use_https !== undefined) owHttpsEl.checked = Boolean(s.openwrt_use_https);
        const owUserEl = document.getElementById('cfg-openwrt-user');
        if (owUserEl && s.openwrt_username !== undefined) owUserEl.value = s.openwrt_username;

        const owSavedBadge = document.getElementById('cfg-openwrt-password-saved-badge');
        const owPassInput = document.getElementById('cfg-openwrt-password');
        if (s.openwrt_has_password) {
            if (owSavedBadge) owSavedBadge.classList.remove('hidden');
            if (owPassInput) owPassInput.placeholder = "•••••••• (сохранен)";
        } else {
            if (owSavedBadge) owSavedBadge.classList.add('hidden');
            if (owPassInput) owPassInput.placeholder = "••••••••";
        }

        const nightStartEl = document.getElementById('cfg-night-start');
        if (nightStartEl && s.night_mode_start_hour !== undefined) nightStartEl.value = s.night_mode_start_hour;
        const nightEndEl = document.getElementById('cfg-night-end');
        if (nightEndEl && s.night_mode_end_hour !== undefined) nightEndEl.value = s.night_mode_end_hour;

        // Sniffer Engine Mode
        const snifferMode = s.sniffer_mode || 'conntrack_passive';
        const passRadio = document.getElementById('cfg-sniffer-passive');
        const actRadio = document.getElementById('cfg-sniffer-active');
        if (snifferMode === 'promiscuous_active') {
            if (actRadio) actRadio.checked = true;
        } else {
            if (passRadio) passRadio.checked = true;
        }

        const autoBlockWanEl = document.getElementById('cfg-night-auto-block-wan');
        if (autoBlockWanEl) autoBlockWanEl.checked = Boolean(s.night_mode_auto_block_wan);
        const tvInactivityEl = document.getElementById('cfg-night-tv-inactivity');
        if (tvInactivityEl && s.night_mode_tv_inactivity_minutes !== undefined) tvInactivityEl.value = s.night_mode_tv_inactivity_minutes;
        const notifyTvNeverSleptEl = document.getElementById('cfg-night-notify-tv-never-slept');
        if (notifyTvNeverSleptEl) notifyTvNeverSleptEl.checked = Boolean(s.night_mode_notify_tv_never_slept ?? s.night_mode_notify_tv_active ?? true);

        const preWakeEl = document.getElementById('cfg-tv-wake-pre');
        if (preWakeEl) preWakeEl.value = s.tv_wake_pre_record_seconds !== undefined ? s.tv_wake_pre_record_seconds : 30;
        const postWakeEl = document.getElementById('cfg-tv-wake-post');
        if (postWakeEl) postWakeEl.value = s.tv_wake_post_record_seconds !== undefined ? s.tv_wake_post_record_seconds : 30;
        const triggerTtlEl = document.getElementById('cfg-tv-wake-trigger-ttl');
        if (triggerTtlEl) triggerTtlEl.value = s.tv_wake_trigger_ttl_seconds !== undefined ? s.tv_wake_trigger_ttl_seconds : 60;

        const pre = s.tv_wake_pre_record_seconds !== undefined ? s.tv_wake_pre_record_seconds : 30;
        const post = s.tv_wake_post_record_seconds !== undefined ? s.tv_wake_post_record_seconds : 30;
        const tvBadge = document.getElementById('tv-wake-window-label');
        if (tvBadge) {
            tvBadge.textContent = `-${pre}с / +${post}с`;
        }
        const cfgTvBadge = document.getElementById('cfg-tv-wake-window-badge');
        if (cfgTvBadge) {
            cfgTvBadge.textContent = `-${pre}с / +${post}с`;
        }

        // New Device Policy (Modular Checkboxes)
        const qElem = document.getElementById('cfg-new-dev-quarantine');
        if (qElem) {
            qElem.checked = Boolean(s.new_device_quarantine_wan || (s.new_device_action && s.new_device_action.includes('quarantine')));
        }
        const aElem = document.getElementById('cfg-new-dev-audit');
        if (aElem) {
            aElem.checked = Boolean(s.new_device_auto_audit || (s.new_device_action && s.new_device_action.includes('audit')));
        }
        const durElem = document.getElementById('cfg-new-device-audit-duration');
        if (durElem && s.new_device_audit_duration) {
            durElem.value = String(Math.round(s.new_device_audit_duration / 60));
        }

        // Active Guard
        const guardElem = document.getElementById('cfg-audit-auto-quarantine');
        if (guardElem && s.audit_auto_quarantine_suspicious !== undefined) {
            guardElem.checked = Boolean(s.audit_auto_quarantine_suspicious);
        }

        // Load differentiated category policies
        await loadNewDevicePolicySettings();

        // Telegram Settings
        const tgEn = document.getElementById('cfg-telegram-enabled');
        if (tgEn) tgEn.checked = Boolean(s.telegram_enabled);
        const tgToken = document.getElementById('cfg-telegram-token');
        if (tgToken) tgToken.value = s.telegram_bot_token || '';
        const tgChat = document.getElementById('cfg-telegram-chat');
        if (tgChat) tgChat.value = s.telegram_chat_id || '';
        const tgUrl = document.getElementById('cfg-telegram-url');
        if (tgUrl) tgUrl.value = s.telegram_api_url || 'https://api.telegram.org';
        const tgProxy = document.getElementById('cfg-telegram-proxy');
        if (tgProxy) tgProxy.value = s.telegram_proxy || '';

        // Security Digest
        const digEn = document.getElementById('cfg-digest-enabled');
        if (digEn) digEn.checked = Boolean(s.digest_enabled);
        const digCond = document.getElementById('cfg-digest-condition');
        if (digCond && s.digest_condition) digCond.value = s.digest_condition;
        const digHour = document.getElementById('cfg-digest-hour');
        if (digHour && s.digest_schedule_hour !== undefined) digHour.value = s.digest_schedule_hour;

        // Scheduled Audit
        const saEn = document.getElementById('cfg-scheduled-audit-enabled');
        if (saEn) saEn.checked = Boolean(s.scheduled_audit_enabled);
        const saHour = document.getElementById('cfg-scheduled-audit-hour');
        if (saHour && s.scheduled_audit_hour !== undefined) saHour.value = s.scheduled_audit_hour;
        const saScope = document.getElementById('cfg-scheduled-audit-scope');
        if (saScope && s.scheduled_audit_scope) saScope.value = s.scheduled_audit_scope;
        const saDur = document.getElementById('cfg-scheduled-audit-duration');
        if (saDur && s.scheduled_audit_duration !== undefined) {
            const valStr = String(s.scheduled_audit_duration);
            if (!Array.from(saDur.options).some(o => o.value === valStr)) {
                const opt = document.createElement('option');
                opt.value = valStr;
                opt.textContent = `${Math.round(s.scheduled_audit_duration / 60)} мин (${valStr} с)`;
                saDur.appendChild(opt);
            }
            saDur.value = valStr;
        }

        const savedBadge = document.getElementById('cfg-password-saved-badge');
        const passHelp = document.getElementById('cfg-password-help');
        const passInput = document.getElementById('cfg-password');

        if (s.has_password) {
            if (savedBadge) savedBadge.classList.remove('hidden');
            if (passHelp) passHelp.textContent = "✓ Пароль сохранен в системе и используется для автоматического входа при каждом запуске.";
            if (passInput) passInput.placeholder = "•••••••• (сохранен)";
        } else {
            if (savedBadge) savedBadge.classList.add('hidden');
            if (passHelp) passHelp.textContent = "Введите пароль администратора роутера для работы с RCI API.";
            if (passInput) passInput.placeholder = "Пароль администратора Keenetic";
        }

        // Auto-quarantine, forensics and camera alerts
        const qScopeEl = document.getElementById('cfg-quarantine-scope');
        if (qScopeEl && s.auto_quarantine_scope) qScopeEl.value = s.auto_quarantine_scope;

        const tvDayEl = document.getElementById('cfg-tv-day-mode');
        if (tvDayEl && s.tv_day_tracking_mode) tvDayEl.value = s.tv_day_tracking_mode;

        const camWanEl = document.getElementById('cfg-camera-wan-notify');
        if (camWanEl) camWanEl.checked = s.camera_notify_wan_stream !== undefined ? Boolean(s.camera_notify_wan_stream) : true;

        const camLanEl = document.getElementById('cfg-camera-lan-notify');
        if (camLanEl) camLanEl.checked = Boolean(s.camera_notify_lan_stream);

        const camThreshEl = document.getElementById('cfg-camera-upload-threshold');
        if (camThreshEl && s.camera_upload_threshold_kbps !== undefined) camThreshEl.value = s.camera_upload_threshold_kbps;

        const macConfEl = document.getElementById('cfg-mac-conflict-enabled');
        if (macConfEl) macConfEl.checked = s.mac_conflict_detection_enabled !== undefined ? Boolean(s.mac_conflict_detection_enabled) : true;

        const dedupEl = document.getElementById('cfg-dedup-window');
        if (dedupEl && s.notification_dedup_window_seconds !== undefined) dedupEl.value = s.notification_dedup_window_seconds;

        // Load LAN Policy Presets
        await loadLanPresets();

        // IoT and PCAP storage settings
        await loadIotStorageSettings();

        // DNS Security provider settings
        await loadDnsProviderConfig();

        // Web UI access & auth settings
        await loadWebAccessSettings();

        // Restore active sub-tab (or default to 'router')
        try {
            const savedSubTab = localStorage.getItem('keenguard_settings_subtab') || 'router';
            switchSettingsSubTab(savedSubTab);
        } catch (e) {
            switchSettingsSubTab('router');
        }
    } catch (e) {
        console.error('Error loading settings', e);
    }
}

// Policy Mode & Configuration for New Devices
let currentDevicePolicyMode = 'category';
let currentLoadedCategories = {};

function setNewDevicePolicyMode(mode) {
    currentDevicePolicyMode = mode;
    const btnCat = document.getElementById('btn-policy-mode-cat');
    const btnGlob = document.getElementById('btn-policy-mode-global');
    const catCont = document.getElementById('new-dev-category-container');
    const globCont = document.getElementById('new-dev-global-container');

    if (mode === 'category') {
        if (btnCat) {
            btnCat.className = 'px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        }
        if (btnGlob) {
            btnGlob.className = 'px-3 py-1 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition';
        }
        if (catCont) catCont.classList.remove('hidden');
        if (globCont) globCont.classList.add('hidden');
    } else {
        if (btnCat) {
            btnCat.className = 'px-3 py-1 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition';
        }
        if (btnGlob) {
            btnGlob.className = 'px-3 py-1 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        }
        if (catCont) catCont.classList.add('hidden');
        if (globCont) globCont.classList.remove('hidden');
    }
}

async function loadNewDevicePolicySettings() {
    try {
        const res = await fetch('/api/settings/new_device_policy');
        if (!res.ok) return;
        const data = await res.json();

        setNewDevicePolicyMode(data.mode || 'category');

        const guardElem = document.getElementById('cfg-audit-auto-quarantine');
        if (guardElem) {
            guardElem.checked = data.audit_auto_quarantine_suspicious !== false;
        }

        if (data.global_policy) {
            const g = data.global_policy;
            if (document.getElementById('cfg-new-dev-quarantine')) {
                document.getElementById('cfg-new-dev-quarantine').checked = Boolean(g.quarantine_wan);
            }
            if (document.getElementById('cfg-new-dev-audit')) {
                document.getElementById('cfg-new-dev-audit').checked = Boolean(g.auto_audit);
            }
            if (document.getElementById('cfg-new-device-audit-duration') && g.audit_duration) {
                document.getElementById('cfg-new-device-audit-duration').value = String(Math.round(g.audit_duration / 60));
            }
        }

        const cats = data.categories || {};
        currentLoadedCategories = cats;
        const catMap = {
            trusted: 'trusted',
            iot: 'iot',
            camera: 'camera',
            random_mac: 'random',
            unknown: 'unknown'
        };

        for (const [key, prefix] of Object.entries(catMap)) {
            const pol = cats[key];
            if (!pol) continue;

            const wanEl = document.getElementById(`pol-${prefix}-wan`);
            if (wanEl) wanEl.checked = Boolean(pol.quarantine_wan);

            const auditEl = document.getElementById(`pol-${prefix}-audit`);
            if (auditEl) auditEl.checked = Boolean(pol.auto_audit);

            const durEl = document.getElementById(`pol-${prefix}-dur`);
            if (durEl && pol.audit_duration !== undefined) durEl.value = String(pol.audit_duration);

            const tgEl = document.getElementById(`pol-${prefix}-tg`);
            if (tgEl) tgEl.checked = Boolean(pol.telegram_alert);
        }
    } catch (e) {
        console.error('Failed to load new device policy settings', e);
    }
}

async function saveNewDevicePolicySettings() {
    const btn = document.getElementById('btn-save-new-dev-policy');
    if (btn) btn.disabled = true;

    try {
        const catMap = {
            trusted: 'trusted',
            iot: 'iot',
            camera: 'camera',
            random_mac: 'random',
            unknown: 'unknown'
        };

        const categories = {};
        for (const [key, prefix] of Object.entries(catMap)) {
            const existingCat = currentLoadedCategories[key] || {};
            categories[key] = {
                quarantine_wan: Boolean(document.getElementById(`pol-${prefix}-wan`)?.checked),
                isolate_lan: existingCat.isolate_lan !== undefined ? Boolean(existingCat.isolate_lan) : (key === 'camera' || key === 'random_mac'),
                auto_audit: Boolean(document.getElementById(`pol-${prefix}-audit`)?.checked),
                audit_duration: parseInt(document.getElementById(`pol-${prefix}-dur`)?.value || '300', 10),
                telegram_alert: Boolean(document.getElementById(`pol-${prefix}-tg`)?.checked)
            };
        }

        const globalDurMin = parseInt(document.getElementById('cfg-new-device-audit-duration')?.value || '60', 10);
        const global_policy = {
            quarantine_wan: Boolean(document.getElementById('cfg-new-dev-quarantine')?.checked),
            isolate_lan: false,
            auto_audit: Boolean(document.getElementById('cfg-new-dev-audit')?.checked),
            audit_duration: globalDurMin * 60
        };

        const auditAutoQuarantine = Boolean(document.getElementById('cfg-audit-auto-quarantine')?.checked);

        const payload = {
            mode: currentDevicePolicyMode,
            categories: categories,
            global_policy: global_policy,
            audit_auto_quarantine_suspicious: auditAutoQuarantine
        };

        const res = await fetch('/api/settings/new_device_policy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        showToast('Политики для новых устройств успешно сохранены!');
    } catch (e) {
        alert(`Ошибка при сохранении политик: ${e.message}`);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function saveSettings(e) {
    if (e && e.preventDefault) e.preventDefault();
    const passVal = document.getElementById('cfg-password')?.value || '';
    const durMinutes = parseInt(document.getElementById('cfg-new-device-audit-duration')?.value || '60', 10);
    const quarantineVal = document.getElementById('cfg-new-dev-quarantine') ? document.getElementById('cfg-new-dev-quarantine').checked : false;
    const auditVal = document.getElementById('cfg-new-dev-audit') ? document.getElementById('cfg-new-dev-audit').checked : false;

    // Compound action description
    const actionParts = [];
    if (quarantineVal) actionParts.push('quarantine_wan');
    if (auditVal) actionParts.push('auto_audit');
    const actionStr = actionParts.join(',') || 'notify';

    const catMap = {
        trusted: 'trusted',
        iot: 'iot',
        camera: 'camera',
        random_mac: 'random',
        unknown: 'unknown'
    };
    const categories = {};
    for (const [key, prefix] of Object.entries(catMap)) {
        const wanEl = document.getElementById(`pol-${prefix}-wan`);
        if (wanEl) {
            const existingCat = currentLoadedCategories[key] || {};
            categories[key] = {
                quarantine_wan: Boolean(wanEl.checked),
                isolate_lan: existingCat.isolate_lan !== undefined ? Boolean(existingCat.isolate_lan) : (key === 'camera' || key === 'random_mac'),
                auto_audit: Boolean(document.getElementById(`pol-${prefix}-audit`)?.checked),
                audit_duration: parseInt(document.getElementById(`pol-${prefix}-dur`)?.value || '300', 10),
                telegram_alert: Boolean(document.getElementById(`pol-${prefix}-tg`)?.checked)
            };
        }
    }

    const payload = {
        router_type: currentRouterPlatform,
        router_host: document.getElementById('cfg-host')?.value?.trim() || undefined,
        router_user: document.getElementById('cfg-user')?.value?.trim() || undefined,
        router_password: passVal && passVal.trim() ? passVal.trim() : null,
        openwrt_host: document.getElementById('cfg-openwrt-host')?.value?.trim() || undefined,
        openwrt_port: parseInt(document.getElementById('cfg-openwrt-port')?.value || '80', 10),
        openwrt_use_https: Boolean(document.getElementById('cfg-openwrt-https')?.checked),
        openwrt_username: document.getElementById('cfg-openwrt-user')?.value?.trim() || undefined,
        openwrt_password: (document.getElementById('cfg-openwrt-password')?.value || '').trim() || null,
        night_mode_start_hour: document.getElementById('cfg-night-start') ? parseInt(document.getElementById('cfg-night-start').value, 10) : undefined,
        night_mode_end_hour: document.getElementById('cfg-night-end') ? parseInt(document.getElementById('cfg-night-end').value, 10) : undefined,
        night_mode_auto_block_wan: document.getElementById('cfg-night-auto-block-wan') ? Boolean(document.getElementById('cfg-night-auto-block-wan').checked) : undefined,
        night_mode_tv_inactivity_minutes: document.getElementById('cfg-night-tv-inactivity') ? parseInt(document.getElementById('cfg-night-tv-inactivity').value, 10) : undefined,
        night_mode_notify_tv_never_slept: document.getElementById('cfg-night-notify-tv-never-slept') ? Boolean(document.getElementById('cfg-night-notify-tv-never-slept').checked) : undefined,
        tv_wake_pre_record_seconds: parseInt(document.getElementById('cfg-tv-wake-pre')?.value || '30', 10),
        tv_wake_post_record_seconds: parseInt(document.getElementById('cfg-tv-wake-post')?.value || '30', 10),
        tv_wake_trigger_ttl_seconds: parseInt(document.getElementById('cfg-tv-wake-trigger-ttl')?.value || '60', 10),
        tv_day_tracking_mode: document.getElementById('cfg-tv-day-mode')?.value || 'autonomous_only',
        new_device_action: currentDevicePolicyMode === 'global' ? actionStr : undefined,
        new_device_quarantine_wan: currentDevicePolicyMode === 'global' ? quarantineVal : undefined,
        new_device_isolate_lan: currentDevicePolicyMode === 'global' ? false : undefined,
        new_device_auto_audit: currentDevicePolicyMode === 'global' ? auditVal : undefined,
        new_device_audit_duration: currentDevicePolicyMode === 'global' ? durMinutes * 60 : undefined,
        new_device_policy_mode: currentDevicePolicyMode,
        new_device_category_policies: Object.keys(categories).length > 0 ? categories : null,
        audit_auto_quarantine_suspicious: Boolean(document.getElementById('cfg-audit-auto-quarantine')?.checked),
        telegram_enabled: document.getElementById('cfg-telegram-enabled') ? Boolean(document.getElementById('cfg-telegram-enabled').checked) : undefined,
        telegram_bot_token: document.getElementById('cfg-telegram-token')?.value?.trim() || undefined,
        telegram_chat_id: document.getElementById('cfg-telegram-chat')?.value?.trim() || undefined,
        telegram_api_url: (document.getElementById('cfg-telegram-url')?.value || '').trim() || undefined,
        telegram_proxy: (document.getElementById('cfg-telegram-proxy')?.value || '').trim() || undefined,
        digest_enabled: document.getElementById('cfg-digest-enabled') ? Boolean(document.getElementById('cfg-digest-enabled').checked) : undefined,
        digest_condition: document.getElementById('cfg-digest-condition')?.value || undefined,
        digest_schedule_hour: document.getElementById('cfg-digest-hour') ? parseInt(document.getElementById('cfg-digest-hour').value || '9', 10) : undefined,
        scheduled_audit_enabled: document.getElementById('cfg-scheduled-audit-enabled') ? Boolean(document.getElementById('cfg-scheduled-audit-enabled').checked) : undefined,
        scheduled_audit_hour: document.getElementById('cfg-scheduled-audit-hour') ? parseInt(document.getElementById('cfg-scheduled-audit-hour').value || '3', 10) : undefined,
        scheduled_audit_scope: document.getElementById('cfg-scheduled-audit-scope') ? document.getElementById('cfg-scheduled-audit-scope').value : 'all',
        scheduled_audit_duration: parseInt(document.getElementById('cfg-scheduled-audit-duration')?.value || '60', 10),
        auto_quarantine_scope: document.getElementById('cfg-quarantine-scope')?.value || 'iot_camera',
        camera_upload_threshold_kbps: parseFloat(document.getElementById('cfg-camera-upload-threshold')?.value || '1500'),
        camera_notify_wan_stream: Boolean(document.getElementById('cfg-camera-wan-notify')?.checked),
        camera_notify_lan_stream: Boolean(document.getElementById('cfg-camera-lan-notify')?.checked),
        mac_conflict_detection_enabled: Boolean(document.getElementById('cfg-mac-conflict-enabled')?.checked),
        notification_dedup_window_seconds: parseInt(document.getElementById('cfg-dedup-window')?.value || '60', 10),
        iot_payload_capture_enabled: document.getElementById('cfg-iot-capture-enabled') ? Boolean(document.getElementById('cfg-iot-capture-enabled').checked) : undefined,
        iot_payload_max_storage_gb: document.getElementById('cfg-iot-storage-max-gb') ? parseFloat(document.getElementById('cfg-iot-storage-max-gb').value || '1.0') : undefined,
        iot_payload_retention_days: document.getElementById('cfg-iot-retention-days') ? parseInt(document.getElementById('cfg-iot-retention-days').value || '7', 10) : undefined,
        web_host: document.getElementById('cfg-web-host-any')?.checked ? '0.0.0.0' : '127.0.0.1',
        web_auth_exempt_localhost: document.getElementById('cfg-web-auth-exempt-localhost') ? Boolean(document.getElementById('cfg-web-auth-exempt-localhost').checked) : true,
        sniffer_mode: document.querySelector('input[name="cfg-sniffer-mode"]:checked')?.value || 'conntrack_passive'
    };

    const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res.ok) {
        const data = await res.json();
        showToast('Все настройки успешно сохранены!');
        const passEl = document.getElementById('cfg-password');
        if (passEl) passEl.value = '';
        const owPassEl = document.getElementById('cfg-openwrt-password');
        if (owPassEl) owPassEl.value = '';
        await loadSettings();
        await refreshAllData();
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Ошибка при сохранении: ${err.detail || res.statusText}`, true);
    }
}

// Granular Settings Handlers
async function saveRouterSettings() {
    const payload = {
        router_type: currentRouterPlatform,
        sniffer_mode: document.querySelector('input[name="cfg-sniffer-mode"]:checked')?.value || 'conntrack_passive'
    };

    if (currentRouterPlatform === 'openwrt') {
        const host = document.getElementById('cfg-openwrt-host')?.value?.trim();
        const port = parseInt(document.getElementById('cfg-openwrt-port')?.value || '80', 10);
        const https = Boolean(document.getElementById('cfg-openwrt-https')?.checked);
        const user = document.getElementById('cfg-openwrt-user')?.value?.trim();
        const pass = document.getElementById('cfg-openwrt-password')?.value;

        if (!host || !user) {
            showToast('Укажите IP-адрес OpenWrt и имя пользователя (root)', true);
            return;
        }

        payload.openwrt_host = host;
        payload.openwrt_port = port;
        payload.openwrt_use_https = https;
        payload.openwrt_username = user;
        if (pass && pass.trim()) {
            payload.openwrt_password = pass.trim();
        }
    } else {
        const host = document.getElementById('cfg-host')?.value?.trim();
        const user = document.getElementById('cfg-user')?.value?.trim();
        const pass = document.getElementById('cfg-password')?.value;

        if (!host || !user) {
            showToast('Укажите IP-адрес роутера и имя пользователя', true);
            return;
        }

        payload.router_host = host;
        payload.router_user = user;
        if (pass && pass.trim()) {
            payload.router_password = pass.trim();
        }
    }

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            const platTitle = currentRouterPlatform === 'openwrt' ? 'OpenWrt' : 'Keenetic';
            showToast(`Настройки подключения к ${platTitle} сохранены`);
            const passEl = document.getElementById('cfg-password');
            if (passEl) passEl.value = '';
            const owPassEl = document.getElementById('cfg-openwrt-password');
            if (owPassEl) owPassEl.value = '';
            await loadSettings();
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    }
}
window.saveRouterSettings = saveRouterSettings;

async function saveCameraSettings() {
    const payload = {
        camera_notify_wan_stream: Boolean(document.getElementById('cfg-camera-wan-notify')?.checked),
        camera_notify_lan_stream: Boolean(document.getElementById('cfg-camera-lan-notify')?.checked),
        camera_upload_threshold_kbps: parseFloat(document.getElementById('cfg-camera-upload-threshold')?.value || '1500')
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Параметры камер видеонаблюдения сохранены');
            await loadSettings();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    }
}
window.saveCameraSettings = saveCameraSettings;

async function saveTelegramSettings() {
    const payload = {
        telegram_enabled: Boolean(document.getElementById('cfg-telegram-enabled')?.checked),
        telegram_bot_token: (document.getElementById('cfg-telegram-token')?.value || '').trim(),
        telegram_chat_id: (document.getElementById('cfg-telegram-chat')?.value || '').trim(),
        telegram_api_url: (document.getElementById('cfg-telegram-url')?.value || '').trim(),
        telegram_proxy: (document.getElementById('cfg-telegram-proxy')?.value || '').trim(),
        notification_dedup_window_seconds: parseInt(document.getElementById('cfg-dedup-window')?.value || '60', 10)
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Настройки Telegram сохранены');
            await loadSettings();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    }
}
window.saveTelegramSettings = saveTelegramSettings;

async function saveTvNightSettings() {
    const payload = {
        night_mode_start_hour: parseInt(document.getElementById('cfg-night-start')?.value || '23', 10),
        night_mode_end_hour: parseInt(document.getElementById('cfg-night-end')?.value || '7', 10),
        night_mode_auto_block_wan: Boolean(document.getElementById('cfg-night-auto-block-wan')?.checked),
        night_mode_tv_inactivity_minutes: parseInt(document.getElementById('cfg-night-tv-inactivity')?.value || '5', 10),
        night_mode_notify_tv_never_slept: Boolean(document.getElementById('cfg-night-notify-tv-never-slept')?.checked),
        tv_wake_pre_record_seconds: parseInt(document.getElementById('cfg-tv-wake-pre')?.value || '30', 10),
        tv_wake_post_record_seconds: parseInt(document.getElementById('cfg-tv-wake-post')?.value || '30', 10),
        tv_wake_trigger_ttl_seconds: parseInt(document.getElementById('cfg-tv-wake-trigger-ttl')?.value || '60', 10),
        tv_day_tracking_mode: document.getElementById('cfg-tv-day-mode')?.value || 'autonomous_only',
        auto_quarantine_scope: document.getElementById('cfg-quarantine-scope')?.value || 'iot_camera'
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Параметры ТВ и ночного режима сохранены');
            await loadSettings();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    }
}
window.saveTvNightSettings = saveTvNightSettings;

async function saveScheduleSettings() {
    const payload = {
        digest_enabled: Boolean(document.getElementById('cfg-digest-enabled')?.checked),
        digest_condition: document.getElementById('cfg-digest-condition')?.value || 'has_incidents',
        digest_schedule_hour: parseInt(document.getElementById('cfg-digest-hour')?.value || '9', 10),
        scheduled_audit_enabled: Boolean(document.getElementById('cfg-scheduled-audit-enabled')?.checked),
        scheduled_audit_hour: parseInt(document.getElementById('cfg-scheduled-audit-hour')?.value || '3', 10),
        scheduled_audit_scope: document.getElementById('cfg-scheduled-audit-scope')?.value || 'all',
        scheduled_audit_duration: parseInt(document.getElementById('cfg-scheduled-audit-duration')?.value || '60', 10)
    };

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Настройки расписаний и аудитов сохранены');
            await loadSettings();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || res.statusText}`, true);
        }
    } catch (e) {
        showToast(`Ошибка сети: ${e.message}`, true);
    }
}
window.saveScheduleSettings = saveScheduleSettings;

async function testTelegram() {
    const token = document.getElementById('cfg-telegram-token').value.trim();
    const chat = document.getElementById('cfg-telegram-chat').value.trim();
    const apiUrl = (document.getElementById('cfg-telegram-url')?.value || '').trim();
    const proxy = (document.getElementById('cfg-telegram-proxy')?.value || '').trim();
    const statusElem = document.getElementById('tg-test-status');

    if (!token || !chat) {
        alert('Заполните Bot Token и Chat ID перед отправкой тестового сообщения.');
        return;
    }

    statusElem.textContent = 'Отправка тестового пуша в Telegram...';
    statusElem.className = 'text-[11px] text-cyan-400';

    try {
        const res = await fetch('/api/telegram/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token, chat_id: chat, api_url: apiUrl, proxy: proxy })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            statusElem.textContent = '✓ Сообщение успешно доставлено!';
            statusElem.className = 'text-[11px] text-emerald-400 font-medium';
        } else {
            statusElem.textContent = `Ошибка: ${data.message}`;
            statusElem.className = 'text-[11px] text-rose-400 font-medium';
        }
    } catch (e) {
        statusElem.textContent = `Ошибка: ${e}`;
        statusElem.className = 'text-[11px] text-rose-400';
    }
}

async function testRouterConnection() {
    const payload = {
        router_type: currentRouterPlatform
    };

    if (currentRouterPlatform === 'openwrt') {
        const host = document.getElementById('cfg-openwrt-host')?.value?.trim();
        const port = parseInt(document.getElementById('cfg-openwrt-port')?.value || '80', 10);
        const https = Boolean(document.getElementById('cfg-openwrt-https')?.checked);
        const user = document.getElementById('cfg-openwrt-user')?.value?.trim();
        const password = document.getElementById('cfg-openwrt-password')?.value?.trim();

        payload.openwrt_host = host;
        payload.openwrt_port = port;
        payload.openwrt_use_https = https;
        payload.openwrt_username = user;
        payload.openwrt_password = password || null;
    } else {
        const host = document.getElementById('cfg-host')?.value?.trim();
        const user = document.getElementById('cfg-user')?.value?.trim();
        const password = document.getElementById('cfg-password')?.value?.trim();

        payload.router_host = host;
        payload.router_user = user;
        payload.router_password = password || null;
    }

    try {
        const res = await fetch('/api/test_connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.status === 'ok') {
            const platTitle = currentRouterPlatform === 'openwrt' ? 'OpenWrt' : 'Keenetic';
            alert(`Связь с ${platTitle} успешна!\nМодель: ${data.model}\nВерсия: ${data.version}\n\nПароль сохранен в системе и роутер подключен.`);
            const passEl = document.getElementById('cfg-password');
            if (passEl) passEl.value = '';
            const owPassEl = document.getElementById('cfg-openwrt-password');
            if (owPassEl) owPassEl.value = '';
            await loadSettings();
            await refreshAllData();
        } else {
            alert(`Ошибка связи с роутером:\n${data.message || 'Проверьте логин, пароль, IP или доступ к ubus/RCI'}`);
        }
    } catch (e) {
        alert(`Ошибка связи с сервером: ${e}`);
    }
}
window.testRouterConnection = testRouterConnection;
window.testKeeneticConnection = testRouterConnection;

