// ==========================================
// Command Palette (Ctrl+K / Cmd+K)
// ==========================================

let isCommandPaletteOpen = false;
let commandPaletteCategory = 'all';
let commandPaletteSelectedIndex = 0;
let commandPaletteMatches = [];

const COMMAND_PALETTE_ACTIONS = [
    {
        type: 'nav',
        id: 'nav_rules',
        category: 'navigation',
        title: 'Правила & Фильтры безопасности',
        subtitle: 'Конструктор правил файрвола, First-Match Win, приоритизация',
        icon: 'sliders',
        badge: 'Раздел',
        action: () => switchTab('rules')
    },

    {
        type: 'nav',
        id: 'nav_dashboard',
        category: 'navigation',
        title: 'Дашборд сети',
        subtitle: 'Главная панель, статус роутера, L7 трафик и эфир',
        icon: 'layout-dashboard',
        badge: 'Раздел',
        action: () => switchTab('dashboard')
    },
    {
        type: 'nav',
        id: 'nav_topology',
        category: 'navigation',
        title: 'Интерактивная топология сети',
        subtitle: 'Карта сегментов Bridge0 / Bridge1 и клиентов',
        icon: 'git-merge',
        badge: 'Раздел',
        action: () => switchTab('topology')
    },
    {
        type: 'nav',
        id: 'nav_devices',
        category: 'navigation',
        title: 'Устройства в сети',
        subtitle: 'Список хостов, профилей, шейпинга и изоляции',
        icon: 'laptop',
        badge: 'Раздел',
        action: () => switchTab('devices')
    },
    {
        type: 'nav',
        id: 'nav_lan',
        category: 'navigation',
        title: 'Локальные связи (LAN)',
        subtitle: 'Матрица связности и предотвращение ботнетов',
        icon: 'network',
        badge: 'Раздел',
        action: () => switchTab('lan')
    },
    {
        type: 'nav',
        id: 'nav_security',
        category: 'navigation',
        title: 'Центр безопасности & Чеклист',
        subtitle: '10 ключевых векторов защиты периметра',
        icon: 'shield-check',
        badge: 'Раздел',
        action: () => switchTab('security')
    },
    {
        type: 'nav',
        id: 'nav_alerts',
        category: 'navigation',
        title: 'Инциденты & UPnP аудит',
        subtitle: 'Журнал обнаруженных угроз и пробросов WAN',
        icon: 'alert-triangle',
        badge: 'Раздел',
        action: () => switchTab('alerts')
    },
    {
        type: 'nav',
        id: 'nav_dns',
        category: 'navigation',
        title: 'DNS & DoH/DoT защита',
        subtitle: 'Мониторинг запросов, sinkhole и DoH блокировка',
        icon: 'globe',
        badge: 'Раздел',
        action: () => switchTab('dns')
    },
    {
        type: 'nav',
        id: 'nav_investigator',
        category: 'navigation',
        title: 'Мастер расследований (Wizard)',
        subtitle: 'Пошаговый анализ сетевых инцидентов и аномалий',
        icon: 'crosshair',
        badge: 'Раздел',
        action: () => switchTab('investigator')
    },
    {
        type: 'nav',
        id: 'nav_audits',
        category: 'navigation',
        title: 'Аудит трафика устройств',
        subtitle: 'Глубокий анализ потоков и сохранение PCAP',
        icon: 'activity',
        badge: 'Раздел',
        action: () => switchTab('audits')
    },
    {
        type: 'nav',
        id: 'nav_packets',
        category: 'navigation',
        title: 'Инспектор сетевых пакетов',
        subtitle: 'Wireshark-анализ Ethernet/IP/L7 и Hex/ASCII дамп',
        icon: 'binary',
        badge: 'Раздел',
        action: () => switchTab('packets')
    },
    {
        type: 'nav',
        id: 'nav_tv',
        category: 'navigation',
        title: 'Smart TV & Криминалистика',
        subtitle: 'Ночные пробуждения, фоновая телеметрия и буфер',
        icon: 'tv',
        badge: 'Раздел',
        action: () => switchTab('tv_forensics')
    },
    {
        type: 'nav',
        id: 'nav_settings',
        category: 'navigation',
        title: 'Настройки системы',
        subtitle: 'Параметры Keenetic, Telegram-бот, учетная запись',
        icon: 'settings',
        badge: 'Раздел',
        action: () => switchTab('settings')
    },
    {
        type: 'action',
        id: 'action_sec_wizard',
        category: 'navigation',
        title: 'Запустить мастер экспресс-настройки',
        subtitle: 'Пошаговый аудит ролей и профилей безопасности',
        icon: 'sparkles',
        badge: 'Мастер',
        action: () => openSecurityWizard()
    },
    {
        type: 'action',
        id: 'action_toggle_sidebar',
        category: 'navigation',
        title: 'Свернуть / развернуть меню навигации',
        subtitle: 'Переключение компактного режима меню (Клавиша: [ )',
        icon: 'panel-left-close',
        badge: 'Интерфейс',
        action: () => toggleSidebar()
    },
    {
        type: 'action',
        id: 'action_full_audit',
        category: 'navigation',
        title: 'Запустить экспресс-аудит всей сети',
        subtitle: 'Переход в раздел аудита и старт сетевой сессии',
        icon: 'play',
        badge: 'Аудит',
        action: async () => {
            await switchTab('audits');
            if (typeof populateAuditDeviceSelect === 'function') {
                await populateAuditDeviceSelect();
            }
            const select = document.getElementById('audit-launch-device');
            if (select) select.value = '__ALL_NETWORK__';
            startTrafficAuditFromTab();
        }
    },
    {
        type: 'action',
        id: 'action_lock_panel',
        category: 'action',
        title: 'Заблокировать панель (Экран входа)',
        subtitle: 'Выйти из сессии администратора и показать окно авторизации',
        icon: 'lock',
        badge: 'Доступ',
        action: () => logout()
    }
];

function openCommandPalette() {
    const modal = document.getElementById('command-palette-modal');
    const input = document.getElementById('cmd-palette-input');
    if (!modal) return;

    modal.classList.remove('hidden');
    isCommandPaletteOpen = true;
    commandPaletteSelectedIndex = 0;

    if (input) {
        input.value = '';
        setTimeout(() => input.focus(), 50);
    }
    renderCommandPaletteResults();
}
window.openCommandPalette = openCommandPalette;

function closeCommandPalette() {
    const modal = document.getElementById('command-palette-modal');
    if (!modal) return;
    modal.classList.add('hidden');
    isCommandPaletteOpen = false;
}
window.closeCommandPalette = closeCommandPalette;

function clearCommandPaletteInput() {
    const input = document.getElementById('cmd-palette-input');
    if (input) {
        input.value = '';
        input.focus();
    }
    renderCommandPaletteResults();
}
window.clearCommandPaletteInput = clearCommandPaletteInput;

function setCommandPaletteCategory(cat) {
    commandPaletteCategory = cat;
    ['all', 'devices', 'navigation'].forEach(c => {
        const btn = document.getElementById(`cmd-cat-${c}`);
        if (!btn) return;
        if (c === cat) {
            btn.className = 'cmd-cat-chip px-2.5 py-1 rounded-lg font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 transition';
        } else {
            btn.className = 'cmd-cat-chip px-2.5 py-1 rounded-lg font-semibold bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 transition';
        }
    });
    commandPaletteSelectedIndex = 0;
    renderCommandPaletteResults();
}
window.setCommandPaletteCategory = setCommandPaletteCategory;

function renderCommandPaletteResults() {
    const input = document.getElementById('cmd-palette-input');
    const resultsContainer = document.getElementById('cmd-palette-results');
    const matchCountEl = document.getElementById('cmd-palette-match-count');
    const clearBtn = document.getElementById('cmd-palette-clear-btn');
    if (!resultsContainer) return;

    const query = (input?.value || '').trim().toLowerCase();
    if (clearBtn) {
        if (query) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
    }

    const matches = [];

    // 1. Match Devices
    if (commandPaletteCategory === 'all' || commandPaletteCategory === 'devices') {
        const devList = (typeof devicesList !== 'undefined' && Array.isArray(devicesList)) ? devicesList : ((typeof devices !== 'undefined' && Array.isArray(devices)) ? devices : []);
        devList.forEach(dev => {
            const name = (dev.custom_name || dev.hostname || dev.name || '').toLowerCase();
            const ip = (dev.ip || '').toLowerCase();
            const mac = (dev.mac || '').toLowerCase();
            const vendor = (dev.vendor || '').toLowerCase();
            const profile = (dev.profile || '').toLowerCase();

            if (!query || name.includes(query) || ip.includes(query) || mac.includes(query) || vendor.includes(query) || profile.includes(query)) {
                matches.push({
                    type: 'device',
                    id: dev.mac,
                    device: dev,
                    title: dev.custom_name || dev.hostname || dev.ip || dev.mac,
                    subtitle: `${dev.ip || 'Нет IP'} • ${dev.mac} • ${dev.vendor || 'Unknown Vendor'}`,
                    profile: dev.profile || 'unassigned',
                    is_online: dev.is_online,
                    is_blocked_wan: dev.is_blocked_wan,
                    action: () => {
                        closeCommandPalette();
                        openDeviceModal(dev.mac);
                    }
                });
            }
        });
    }

    // 2. Match Actions / Navigation
    if (commandPaletteCategory === 'all' || commandPaletteCategory === 'navigation') {
        COMMAND_PALETTE_ACTIONS.forEach(act => {
            const title = act.title.toLowerCase();
            const sub = act.subtitle.toLowerCase();
            if (!query || title.includes(query) || sub.includes(query) || act.id.includes(query)) {
                matches.push(act);
            }
        });
    }

    commandPaletteMatches = matches;
    if (matchCountEl) matchCountEl.textContent = `${matches.length} совпадений`;

    if (matches.length === 0) {
        resultsContainer.innerHTML = `
            <div class="text-center py-12 px-4 space-y-2">
                <i data-lucide="search-x" class="w-8 h-8 text-slate-600 mx-auto"></i>
                <h4 class="text-sm font-semibold text-slate-300">Ничего не найдено</h4>
                <p class="text-xs text-slate-500 max-w-sm mx-auto">
                    По запросу "${escapeHtml(query)}" устройств или системных команд не обнаружено. Попробуйте изменить поисковую фразу.
                </p>
            </div>
        `;
        if (window.lucide) lucide.createIcons({ roots: [resultsContainer] });
        return;
    }

    if (commandPaletteSelectedIndex >= matches.length) {
        commandPaletteSelectedIndex = Math.max(0, matches.length - 1);
    }

    resultsContainer.innerHTML = matches.map((item, idx) => {
        const isSelected = idx === commandPaletteSelectedIndex;
        const selectedCls = isSelected ? 'selected' : '';

        if (item.type === 'device') {
            const dev = item.device;
            const onlineDot = dev.is_online
                ? '<span class="w-2 h-2 rounded-full bg-emerald-400 shrink-0" title="Онлайн"></span>'
                : '<span class="w-2 h-2 rounded-full bg-slate-600 shrink-0" title="Офлайн"></span>';

            const blockedBadge = dev.is_blocked_wan
                ? '<span class="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/30">Блок WAN</span>'
                : '';

            return `
                <div class="cmd-item ${selectedCls} p-2.5 rounded-xl flex items-center justify-between gap-3 cursor-pointer group" onclick="executeCommandPaletteItem(${idx})">
                    <div class="flex items-center space-x-3 min-w-0">
                        ${onlineDot}
                        <div class="min-w-0">
                            <div class="flex items-center space-x-2">
                                <span class="font-bold text-xs text-white truncate">${escapeHtml(item.title)}</span>
                                <span class="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">${escapeHtml(item.profile)}</span>
                                ${blockedBadge}
                            </div>
                            <span class="text-[11px] text-slate-400 font-mono truncate block">${escapeHtml(item.subtitle)}</span>
                        </div>
                    </div>
                    <div class="flex items-center space-x-1.5 shrink-0">
                        <button data-mac="${escapeHtml(dev.mac)}" onclick="event.stopPropagation(); closeCommandPalette(); openDeviceModal(this.dataset.mac);" class="cmd-action-btn opacity-0 group-hover:opacity-100 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition" title="Открыть инспектор">
                            <i data-lucide="sliders" class="w-3.5 h-3.5"></i>
                        </button>
                        <button data-mac="${escapeHtml(dev.mac)}" onclick="event.stopPropagation(); closeCommandPalette(); switchTab('audits'); startDeviceAuditFromPalette(this.dataset.mac);" class="cmd-action-btn opacity-0 group-hover:opacity-100 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition" title="Запустить аудит">
                            <i data-lucide="activity" class="w-3.5 h-3.5"></i>
                        </button>
                        <button data-mac="${escapeHtml(dev.mac)}" onclick="event.stopPropagation(); closeCommandPalette(); switchTab('packets'); filterPacketsByDevice(this.dataset.mac);" class="cmd-action-btn opacity-0 group-hover:opacity-100 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition" title="Инспектор пакетов">
                            <i data-lucide="binary" class="w-3.5 h-3.5"></i>
                        </button>
                    </div>
                </div>
            `;
        }

        // Navigation or Action item
        return `
            <div class="cmd-item ${selectedCls} p-2.5 rounded-xl flex items-center justify-between gap-3 cursor-pointer group" onclick="executeCommandPaletteItem(${idx})">
                <div class="flex items-center space-x-3 min-w-0">
                    <div class="p-1.5 rounded-lg bg-indigo-500/10 text-indigo-400 shrink-0">
                        <i data-lucide="${escapeHtml(item.icon)}" class="w-4 h-4"></i>
                    </div>
                    <div class="min-w-0">
                        <span class="font-bold text-xs text-white truncate block">${escapeHtml(item.title)}</span>
                        <span class="text-[11px] text-slate-400 truncate block">${escapeHtml(item.subtitle)}</span>
                    </div>
                </div>
                <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 shrink-0">
                    ${escapeHtml(item.badge || 'Перейти')}
                </span>
            </div>
        `;
    }).join('');

    if (window.lucide) lucide.createIcons({ roots: [resultsContainer] });

    // Scroll selected into view
    const selectedEl = resultsContainer.querySelector('.cmd-item.selected');
    if (selectedEl) {
        selectedEl.scrollIntoView({ block: 'nearest' });
    }
}

function executeCommandPaletteItem(idx) {
    const item = commandPaletteMatches[idx];
    if (!item) return;
    closeCommandPalette();
    if (typeof item.action === 'function') {
        item.action();
    }
}
window.executeCommandPaletteItem = executeCommandPaletteItem;

async function startDeviceAuditFromPalette(mac) {
    await switchTab('audits');
    if (typeof populateAuditDeviceSelect === 'function') {
        await populateAuditDeviceSelect();
    }
    const select = document.getElementById('audit-launch-device');
    if (select) {
        select.value = mac;
    }
    startTrafficAuditFromTab();
}
window.startDeviceAuditFromPalette = startDeviceAuditFromPalette;

async function openDeviceAuditModal(mac, ip) {
    if (!mac) return;
    await switchTab('audits');
    if (typeof populateAuditDeviceSelect === 'function') {
        await populateAuditDeviceSelect();
    }
    const select = document.getElementById('audit-launch-device');
    if (select) {
        select.value = mac;
    }
    const durSelect = document.getElementById('audit-launch-duration');
    if (durSelect) {
        durSelect.value = '60'; // 1-minute express audit
    }
    startTrafficAuditFromTab();
    showToast(`Запуск 1-минутного экспресс-аудита для ${ip || mac}...`, 'info');
}
window.openDeviceAuditModal = openDeviceAuditModal;

function filterPacketsByDevice(mac) {
    const select = document.getElementById('pkt-device-select');
    if (select) {
        select.value = mac;
        onPacketDeviceSelectChange();
    }
}
window.filterPacketsByDevice = filterPacketsByDevice;

// Global hotkeys and event listeners
window.addEventListener('keydown', e => {
    // 1. Toggle Command Palette on Ctrl+K / Cmd+K
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isCommandPaletteOpen) {
            closeCommandPalette();
        } else {
            openCommandPalette();
        }
        return;
    }

    if (!isCommandPaletteOpen) return;

    if (e.key === 'Escape') {
        e.preventDefault();
        closeCommandPalette();
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (commandPaletteMatches.length > 0) {
            commandPaletteSelectedIndex = (commandPaletteSelectedIndex + 1) % commandPaletteMatches.length;
            renderCommandPaletteResults();
        }
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (commandPaletteMatches.length > 0) {
            commandPaletteSelectedIndex = (commandPaletteSelectedIndex - 1 + commandPaletteMatches.length) % commandPaletteMatches.length;
            renderCommandPaletteResults();
        }
    } else if (e.key === 'Enter') {
        e.preventDefault();
        executeCommandPaletteItem(commandPaletteSelectedIndex);
    }
});

// Setup input listeners on load
function initCommandPaletteInput() {
    const input = document.getElementById('cmd-palette-input');
    if (input) {
        input.addEventListener('input', () => {
            commandPaletteSelectedIndex = 0;
            renderCommandPaletteResults();
        });
    }
}
window.initCommandPaletteInput = initCommandPaletteInput;

// Close command palette on click outside
document.addEventListener('mousedown', e => {
    if (!isCommandPaletteOpen) return;
    const modal = document.getElementById('command-palette-modal');
    const content = modal?.querySelector('div.bg-surface-900');
    if (modal && !modal.classList.contains('hidden') && content && !content.contains(e.target)) {
        closeCommandPalette();
    }
});

