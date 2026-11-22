// ==========================================
// DOM Safe Guards & Fault-Tolerant Helpers
// ==========================================
function safeSetText(id, text) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = text !== null && text !== undefined ? text : '';
        return true;
    }
    return false;
}

function safeSetHtml(id, html) {
    const el = document.getElementById(id);
    if (el) {
        el.innerHTML = html !== null && html !== undefined ? html : '';
        return true;
    }
    return false;
}

function safeSetValue(id, val) {
    const el = document.getElementById(id);
    if (el) {
        el.value = val;
        return true;
    }
    return false;
}

function safeToggleClass(id, className, condition) {
    const el = document.getElementById(id);
    if (el) {
        el.classList.toggle(className, Boolean(condition));
        return true;
    }
    return false;
}

// ==========================================
// Multi-Column Table Sorting System
// ==========================================
const tableSortState = {
    devices: { col: 'name', dir: 'asc' },
    dns: { col: 'last_seen', dir: 'desc' },
    audits: { col: 'date', dir: 'desc' },
    smarthome: { col: 'risk', dir: 'desc' },
    domain_modal: { col: 'count', dir: 'desc' },
    audit_modal: { col: 'bytes', dir: 'desc' }
};

let deviceViewMode = localStorage.getItem('kg_device_view_mode') || 'grid';
let allAuditReports = [];
let allShCloudConnections = [];
let currentDomainModalDevices = [];
let currentAuditModalFlows = [];

function toggleSortTable(tableKey, colKey) {
    const state = tableSortState[tableKey];
    if (!state) return;

    if (state.col === colKey) {
        state.dir = state.dir === 'asc' ? 'desc' : 'asc';
    } else {
        state.col = colKey;
        const descDefaults = ['last_seen', 'date', 'created_at', 'duration', 'traffic', 'bytes', 'count', 'risk', 'safety', 'devices', 'status'];
        state.dir = descDefaults.includes(colKey) ? 'desc' : 'asc';
    }

    updateSortIndicators(tableKey);

    if (tableKey === 'devices') {
        const sel = document.getElementById('devices-sort-select');
        if (sel) {
            if (colKey === 'name') sel.value = state.dir === 'asc' ? 'name_asc' : 'name_desc';
            else if (colKey === 'status') sel.value = 'status_online';
            else if (colKey === 'ip') sel.value = 'ip_asc';
            else if (colKey === 'vendor') sel.value = 'vendor_asc';
        }
        applyDeviceFiltersAndRender();
    } else if (tableKey === 'dns') {
        applyDnsFilterAndRender();
    } else if (tableKey === 'audits') {
        renderAuditReportsTable();
    } else if (tableKey === 'smarthome') {
        renderSmartHomeCloudTable(allShCloudConnections);
    } else if (tableKey === 'domain_modal') {
        renderDomainModalDevicesTable();
    } else if (tableKey === 'audit_modal') {
        renderAuditModalFlowsTable();
    }
}

function updateSortIndicators(tableKey) {
    const state = tableSortState[tableKey];
    if (!state) return;

    const prefix = `sort-icon-${tableKey}-`;
    const icons = document.querySelectorAll(`[id^="${prefix}"]`);
    icons.forEach(el => {
        const col = el.id.substring(prefix.length);
        if (col === state.col) {
            el.textContent = state.dir === 'asc' ? '▲' : '▼';
            const colorClass = (tableKey === 'audits' || tableKey === 'devices') ? 'text-indigo-400' : 'text-cyan-400';
            el.className = `text-[10px] ${colorClass} font-mono font-bold`;
        } else {
            el.textContent = '⇅';
            el.className = 'text-[10px] text-slate-500 font-mono group-hover:text-slate-300';
        }
    });
}

// Profile labels & icons
const PROFILES = {
    trusted: { name: "Доверенный (ПК/Смартфон)", color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20", icon: "laptop" },
    smart_home_hub: { name: "Хаб умного дома", color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/20", icon: "server" },
    smart_tv: { name: "Smart TV (Медиаэкран)", color: "text-indigo-400", bg: "bg-indigo-500/10", border: "border-indigo-500/20", icon: "tv" },
    camera: { name: "Камера наблюдения", color: "text-rose-400", bg: "bg-rose-500/10", border: "border-rose-500/20", icon: "video" },
    iot: { name: "IoT / Умный дом", color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20", icon: "cpu" },
    unassigned: { name: "Не назначен", color: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/20", icon: "help-circle" }
};

document.addEventListener('DOMContentLoaded', () => {
    initSidebarState();
    checkAuthStatus();
    if (window.lucide && typeof lucide.createIcons === 'function') lucide.createIcons();
    updateDeviceViewModeButtons();
    updateSnifferDisplayModeButtons();
    const hideOfflineSaved = localStorage.getItem('kg_hide_offline') === 'true';
    const hideOfflineCb = document.getElementById('toggle-hide-offline-devices');
    if (hideOfflineCb) hideOfflineCb.checked = hideOfflineSaved;
    initSourceFilterCheckboxes();
    connectWebSocket();
    refreshAllData();
    loadLanPresets();
    initModalDismissHandlers();

    // Periodic refresh
    setInterval(() => {
        loadDevices();
        loadStatus();
        if (activeTab === 'alerts') loadEvents();
        if (activeTab === 'smarthome') loadSmartHome();
        if (activeTab === 'security') loadSecurity();
        if (activeTab === 'lan') {
            if (currentLanView === 'log') loadLanCommunications();
            else if (currentLanView === 'matrix') loadLanPingMatrix();
            else if (currentLanView === 'topo') loadLanTopology();
        }
        if (activeTab === 'packets') loadPacketInspectorLive();
        if (activeTab === 'tv_forensics') loadTvForensics();
        if (activeTab === 'dashboard') {
            loadWifiAudit();
            checkRouterUpdates();
            loadSecurityScoreForDashboard();
            loadL7TrafficSummary();
        }
    }, 10000);

    // Fast periodic refresh for live traffic chart on dashboard
    setInterval(() => {
        if (activeTab === 'dashboard') {
            updateLiveTrafficChart();
        }
    }, 3500);

    // Fast periodic refresh for active audit sessions
    setInterval(() => {
        if (activeTab === 'audits' || activeAuditsCount > 0) {
            loadActiveAudits();
        }
    }, 2500);
});

function initModalDismissHandlers() {
    const modalIds = [
        'device-modal',
        'command-palette-modal',
        'digest-modal',
        'event-modal',
        'domain-detail-modal',
        'audit-detail-modal',
        'network-audit-detail-modal',
        'security-wizard-modal',
        'clear-events-modal',
        'clear-dns-modal',
        'clear-audits-modal',
        'clear-offline-devices-modal',
        'packet-inspector-modal',
        'pcap-selector-modal',
        'device-setup-wizard-modal',
        'custom-preset-modal',
        'dns-preset-modal',
        'dns-active-rules-modal',
        'isolation-wizard-modal',
        'rule-modal',
        'rule-conflict-modal',
        'rule-hits-drawer',
        'rule-sim-modal'
    ];

    modalIds.forEach(id => {
        const m = document.getElementById(id);
        if (m) {
            m.addEventListener('click', (ev) => {
                if (ev.target === m) {
                    closeAnyModal(id);
                }
            });
        }
    });

    document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape') {
            for (let i = modalIds.length - 1; i >= 0; i--) {
                const m = document.getElementById(modalIds[i]);
                if (m && !m.classList.contains('hidden')) {
                    closeAnyModal(modalIds[i]);
                    break;
                }
            }
        }
    });
}

function closeAnyModal(id) {
    if (id === 'device-modal') closeDeviceModal();
    else if (id === 'command-palette-modal') closeCommandPalette();
    else if (id === 'digest-modal') closeDigestModal();
    else if (id === 'event-modal') closeEventModal();
    else if (id === 'domain-detail-modal') closeDomainModal();
    else if (id === 'audit-detail-modal') closeAuditModal();
    else if (id === 'network-audit-detail-modal') closeNetworkAuditModal();
    else if (id === 'security-wizard-modal') closeSecurityWizard();
    else if (id === 'clear-events-modal') closeClearEventsModal();
    else if (id === 'clear-dns-modal') closeClearDnsModal();
    else if (id === 'clear-audits-modal') closeClearAuditsModal();
    else if (id === 'clear-offline-devices-modal') closeClearOfflineModal();
    else if (id === 'packet-inspector-modal') closePacketInspectorModal();
    else if (id === 'pcap-selector-modal') closePcapSelectorModal();
    else if (id === 'device-setup-wizard-modal') closeDeviceWizard();
    else if (id === 'custom-preset-modal') closeCustomPresetModal();
    else if (id === 'dns-preset-modal') closeDnsPresetModal();
    else if (id === 'dns-active-rules-modal') closeDnsActiveRulesModal();
    else if (id === 'isolation-wizard-modal') closeIsolationWizardModal();
    else if (id === 'rule-modal') closeRuleModal();
    else if (id === 'rule-conflict-modal') closeRuleConflictModal();
    else if (id === 'rule-hits-drawer') closeRuleHitsModal();
    else if (id === 'rule-sim-modal') closeRuleSimModal();
}


// ==========================================
// Time & Date Formatting Utilities
// ==========================================
function parseTimestamp(timestamp) {
    if (!timestamp) return null;
    if (timestamp instanceof Date) return isNaN(timestamp.getTime()) ? null : timestamp;
    if (typeof timestamp === 'number') {
        const d = new Date(timestamp < 1e12 ? timestamp * 1000 : timestamp);
        return isNaN(d.getTime()) ? null : d;
    }
    if (typeof timestamp === 'string') {
        let s = timestamp.trim();
        if (!s || s === '--' || s === '—') return null;
        // Clamp microsecond chains (>3 digits after dot) to 3 digits for standard JS parsing
        s = s.replace(/(\.\d{3})\d+/, '$1');
        let d = new Date(s);
        if (!isNaN(d.getTime())) return d;
        d = new Date(s.replace(' ', 'T'));
        if (!isNaN(d.getTime())) return d;
    }
    return null;
}

function formatHumanTime(timestamp, options = {}) {
    const d = parseTimestamp(timestamp);
    if (!d) {
        if (typeof timestamp === 'string' && timestamp.includes('T')) {
            const timePart = timestamp.split('T')[1] || '';
            return timePart.split('.')[0].substring(0, 8) || timestamp;
        }
        return timestamp || '—';
    }

    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();

    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');
    const timeStr = `${hours}:${minutes}:${seconds}`;

    if (options.fullDateTime) {
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const year = d.getFullYear();
        return `${day}.${month}.${year} ${timeStr}`;
    }

    if (options.includeDate || (!isToday && options.dateIfOld !== false)) {
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        return `${day}.${month} ${timeStr}`;
    }

    return timeStr;
}

function formatHumanFullDateTime(timestamp) {
    const d = parseTimestamp(timestamp);
    if (!d) return timestamp ? String(timestamp) : '';
    const day = String(d.getDate()).padStart(2, '0');
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const year = d.getFullYear();
    const hours = String(d.getHours()).padStart(2, '0');
    const minutes = String(d.getMinutes()).padStart(2, '0');
    const seconds = String(d.getSeconds()).padStart(2, '0');
    const ms = String(d.getMilliseconds()).padStart(3, '0');
    return `${day}.${month}.${year} ${hours}:${minutes}:${seconds}.${ms}`;
}

// ==========================================
function isIpAddress(str) {
    if (!str || typeof str !== 'string') return false;
    const s = str.trim();
    if (s === '0.0.0.0' || s === '255.255.255.255') return true;
    return /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/.test(s);
}

function isMacAddress(str) {
    if (!str || typeof str !== 'string') return false;
    return /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(str.trim());
}


function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(sec) {
    const s = parseInt(sec, 10) || 0;
    if (s <= 0) return '0 сек';
    if (s < 60) return `${s} сек`;
    const m = Math.floor(s / 60);
    const rem = s % 60;
    if (rem === 0) return `${m} мин`;
    return `${m} мин ${rem} сек`;
}

