// KeenGuard Client Application Logic
let activeTab = 'dashboard';
let devicesList = [];
let upnpList = [];
let eventsList = [];
let allDnsQueries = [];
let currentDeviceMac = null;
let ws = null;
let liveTrafficChart = null;
let deviceTrafficChart = null;
let currentRouterInfo = null;

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
    }, 10000);

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
        'dns-active-rules-modal'
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
}

// WebSocket Connection
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            if (data.type === 'refresh' || data.type === 'device_updated' || data.type === 'device_deleted' || data.type === 'devices_pruned') {
                loadDevices();
                loadStatus();
                if (activeTab === 'smarthome') loadSmartHome();
                if (activeTab === 'security') loadSecurity();
                if (activeTab === 'audits') loadTrafficAuditsTab();
            } else if (data.type === 'router_status_change') {
                loadStatus();
                loadEvents();
                if (activeTab === 'smarthome') loadSmartHome();
                if (activeTab === 'security') loadSecurity();
            } else if (data.type === 'security_event' || data.type === 'event_deleted' || data.type === 'events_cleared') {
                loadEvents();
                loadStatus();
                if (activeTab === 'security') loadSecurity();
            } else if (data.type === 'presets_updated') {
                if (typeof loadLanPresets === 'function') loadLanPresets();
                if (activeTab === 'devices') loadDevices();
            } else if (data.type === 'audit_started' || data.type === 'audit_stopped' || data.type === 'network_audit_started' || data.type === 'network_audit_stopped' || data.type === 'audit_report_deleted' || data.type === 'audit_reports_cleared') {
                loadActiveAudits();
                if (activeTab === 'audits') loadAuditReports();
            } else if (data.type === 'sniffer_event') {
                appendSnifferFeed(data.event);
            } else if (data.type === 'dns_sinkhole_updated' || data.type === 'dns_preset_applied' || data.type === 'dns_all_unblocked' || data.type === 'dns_provider_synced' || data.type === 'dns_provider_config_saved' || data.type === 'dns_query_deleted' || data.type === 'dns_queries_cleared') {
                if (activeTab === 'tv_forensics') loadTvBrandPresets();
                if (activeTab === 'dns' && typeof loadDnsQueries === 'function') loadDnsQueries();
                if (typeof loadDnsProviderStatus === 'function') loadDnsProviderStatus();
            }
        } catch (e) {
            console.error('WS parse error', e);
        }
    };

    ws.onclose = () => {
        setTimeout(connectWebSocket, 3000);
    };
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

// Device Identity & Naming Cache
// ==========================================
const deviceNameCache = {
    ipToName: new Map(),
    macToName: new Map(),
    macToDev: new Map(),
    ipToDev: new Map(),

    registerDevice(dev) {
        if (!dev) return;
        const name = dev.custom_name || dev.hostname || dev.vendor || null;
        if (dev.mac) {
            const upperMac = dev.mac.toUpperCase();
            this.macToDev.set(upperMac, dev);
            if (name && name !== dev.mac && !isIpAddress(name) && !isMacAddress(name)) {
                this.macToName.set(upperMac, name);
            }
        }
        if (dev.ip && dev.ip !== '0.0.0.0' && dev.ip !== 'None') {
            this.ipToDev.set(dev.ip, dev);
            if (name && name !== dev.ip && !isIpAddress(name) && !isMacAddress(name)) {
                this.ipToName.set(dev.ip, name);
            }
        }
    },

    registerDevices(list) {
        if (!Array.isArray(list)) return;
        for (const dev of list) {
            this.registerDevice(dev);
        }
    },

    registerMapping(ip, mac, name) {
        if (!name || name === 'Unknown' || name === 'None' || isIpAddress(name) || isMacAddress(name)) return;
        if (ip && ip !== '0.0.0.0' && ip !== 'None' && name !== ip) {
            this.ipToName.set(ip, name);
        }
        if (mac) {
            const upperMac = mac.toUpperCase();
            if (name !== upperMac) this.macToName.set(upperMac, name);
        }
    },

    getName(ip, mac, fallbackName = null) {
        if (fallbackName && fallbackName !== ip && fallbackName !== mac && fallbackName !== 'Unknown' && fallbackName !== 'None' && !isIpAddress(fallbackName) && !isMacAddress(fallbackName)) {
            this.registerMapping(ip, mac, fallbackName);
            return fallbackName;
        }
        if (mac) {
            const upperMac = mac.toUpperCase();
            if (this.macToName.has(upperMac)) {
                const n = this.macToName.get(upperMac);
                if (n && !isIpAddress(n) && !isMacAddress(n) && n !== upperMac) return n;
            }
            const dev = this.macToDev.get(upperMac) || (Array.isArray(devicesList) ? devicesList.find(d => d.mac && d.mac.toUpperCase() === upperMac) : null);
            if (dev) {
                const n = dev.custom_name || dev.hostname || dev.vendor;
                if (n && !isIpAddress(n) && !isMacAddress(n) && n !== upperMac) {
                    this.macToName.set(upperMac, n);
                    return n;
                }
            }
        }
        if (ip && ip !== '0.0.0.0' && ip !== 'None') {
            // Check well-known multicast & broadcast addresses
            const MULTICAST_MAP = {
                '224.0.0.251': 'mDNS (Bonjour/Cast)',
                'ff02::fb': 'mDNS (Bonjour/Cast)',
                '239.255.255.250': 'SSDP (UPnP)',
                'ff02::c': 'SSDP (UPnP)',
                '224.0.0.252': 'LLMNR (Name Resolution)',
                'ff02::1:3': 'LLMNR (IPv6)',
                '224.0.0.1': 'Все узлы (All Hosts)',
                'ff02::1': 'Все узлы (IPv6)',
                '224.0.0.2': 'Все роутеры (All Routers)',
                'ff02::2': 'Все роутеры (IPv6)',
                '255.255.255.255': 'Широковещательный'
            };
            if (MULTICAST_MAP[ip]) return MULTICAST_MAP[ip];

            if (this.ipToName.has(ip)) {
                const n = this.ipToName.get(ip);
                if (n && !isIpAddress(n) && !isMacAddress(n) && n !== ip) return n;
            }
            const dev = this.ipToDev.get(ip) || (Array.isArray(devicesList) ? devicesList.find(d => d.ip === ip) : null);
            if (dev) {
                const n = dev.custom_name || dev.hostname || dev.vendor;
                if (n && !isIpAddress(n) && !isMacAddress(n) && n !== ip) {
                    this.ipToName.set(ip, n);
                    return n;
                }
            }
        }
        return null;
    }
};

function getDeviceDisplayMode() {
    return localStorage.getItem('kg_device_display_mode') || localStorage.getItem('kg_sniffer_display_mode') || 'name';
}
const getSnifferDisplayMode = getDeviceDisplayMode;

function updateAllDisplayModeButtons() {
    const currentMode = getDeviceDisplayMode();
    const prefixes = ['sniffer-mode-', 'lan-mode-', 'pkt-mode-', 'sh-iot-mode-'];
    ['name', 'ip', 'both'].forEach(m => {
        prefixes.forEach(p => {
            const btn = document.getElementById(`${p}${m}`);
            if (!btn) return;
            if (m === currentMode) {
                btn.className = 'px-2 py-0.5 rounded-md font-medium transition bg-indigo-600 text-white shadow-sm';
            } else {
                btn.className = 'px-2 py-0.5 rounded-md font-medium transition text-slate-400 hover:text-white';
            }
        });
    });
}
function updateSnifferDisplayModeButtons() {
    return updateAllDisplayModeButtons();
}
window.updateSnifferDisplayModeButtons = updateSnifferDisplayModeButtons;

async function setDeviceDisplayMode(mode) {
    localStorage.setItem('kg_device_display_mode', mode);
    localStorage.setItem('kg_sniffer_display_mode', mode);
    updateAllDisplayModeButtons();
    reRenderSnifferFeed();

    if (!devicesList || devicesList.length === 0) {
        await loadDevices();
    }

    if (activeTab === 'lan') {
        if (currentLanView === 'log') loadLanCommunications();
        else if (currentLanView === 'matrix') loadLanPingMatrix();
        else if (currentLanView === 'topo') loadLanTopology();
    } else if (activeTab === 'packets') {
        loadPacketInspectorLive(true);
    } else if (activeTab === 'smarthome') {
        loadIotPayloads();
    }
}
function setSnifferDisplayMode(mode) {
    return setDeviceDisplayMode(mode);
}
window.setSnifferDisplayMode = setSnifferDisplayMode;

function isRouterEntity(ip, mac) {
    const routerHost = currentRouterInfo?.host || '192.168.1.1';
    const routerIps = currentRouterInfo?.router_ips || [routerHost, '192.168.1.1', '192.168.2.1'];
    const routerMacs = (currentRouterInfo?.router_macs || []).map(m => m.toUpperCase());

    if (ip && (routerIps.includes(ip) || ip === '192.168.1.1' || ip === '192.168.2.1')) return true;
    if (mac && routerMacs.includes(mac.toUpperCase())) return true;
    return false;
}

function getRouterName() {
    if (currentRouterInfo?.model) {
        return currentRouterInfo.model;
    }
    return "Роутер Keenetic";
}

function isHubEntity(ip, mac) {
    if (!ip && !mac) return false;
    const cleanIp = (ip && ip !== 'None' && ip !== 'Unknown' && ip !== '0.0.0.0') ? ip : null;
    const cleanMac = mac ? mac.toUpperCase() : null;

    // A router is not a smart home hub
    if (isRouterEntity(cleanIp, cleanMac)) return false;

    // Helper to evaluate device record
    const checkDev = (dev) => {
        if (!dev) return false;
        if (dev.profile === 'smart_home_hub' || dev.security_profile === 'smart_home_hub') return true;
        const name = `${dev.custom_name || ''} ${dev.hostname || ''} ${dev.vendor || ''}`.toLowerCase();
        if (name.includes('spruthub') || name.includes('hub') || name.includes('хаб') || 
            name.includes('home assistant') || name.includes('homebridge') || name.includes('zigbee')) {
            return true;
        }
        return false;
    };

    // 1. Check in devicesList
    if (Array.isArray(devicesList) && devicesList.length > 0) {
        const dev = devicesList.find(d => 
            (cleanIp && d.ip === cleanIp) || 
            (cleanMac && d.mac && d.mac.toUpperCase() === cleanMac)
        );
        if (dev && checkDev(dev)) return true;
    }

    // 2. Check in deviceNameCache
    if (cleanMac) {
        const dev = deviceNameCache.macToDev.get(cleanMac);
        if (dev && checkDev(dev)) return true;
        const cachedName = (deviceNameCache.macToName.get(cleanMac) || '').toLowerCase();
        if (cachedName.includes('spruthub') || cachedName.includes('hub') || cachedName.includes('хаб') || cachedName.includes('home assistant')) {
            return true;
        }
    }

    if (cleanIp) {
        const dev = deviceNameCache.ipToDev.get(cleanIp);
        if (dev && checkDev(dev)) return true;
        const cachedName = (deviceNameCache.ipToName.get(cleanIp) || '').toLowerCase();
        if (cachedName.includes('spruthub') || cachedName.includes('hub') || cachedName.includes('хаб') || cachedName.includes('home assistant')) {
            return true;
        }
    }

    return false;
}

function getFilterPref(key, defaultVal = false) {
    const val = localStorage.getItem(`kg_filter_${key}`);
    if (val === null) return defaultVal;
    return val === 'true';
}

function setFilterPref(key, val) {
    localStorage.setItem(`kg_filter_${key}`, val ? 'true' : 'false');
    const map = {
        hideRouter: ['pkt-hide-router-src', 'lan-hide-router-src', 'sh-iot-hide-router-src'],
        hideHub: ['pkt-hide-hub-src', 'lan-hide-hub-src', 'sh-iot-hide-hub-src']
    };
    (map[key] || []).forEach(id => {
        const el = document.getElementById(id);
        if (el && el.checked !== val) el.checked = val;
    });
}

function togglePktFilterPref(key, val) {
    setFilterPref(key, val);
    loadPacketInspectorLive(true);
}

function toggleLanFilterPref(key, val) {
    setFilterPref(key, val);
    if (currentLanView === 'topo') {
        loadLanTopology();
    } else {
        loadLanCommunications();
    }
}

function toggleIotFilterPref(key, val) {
    setFilterPref(key, val);
    loadIotPayloads();
}

function initSourceFilterCheckboxes() {
    const hideRouter = getFilterPref('hideRouter');
    const hideHub = getFilterPref('hideHub');
    ['pkt-', 'lan-', 'sh-iot-'].forEach(prefix => {
        const rEl = document.getElementById(`${prefix}hide-router-src`);
        if (rEl) rEl.checked = hideRouter;
        const hEl = document.getElementById(`${prefix}hide-hub-src`);
        if (hEl) hEl.checked = hideHub;
    });
}

function formatDeviceIdentifier(ip, mac, mode = getDeviceDisplayMode(), fallbackName = null) {
    if (!ip && !mac) return 'Unknown';
    if (ip === '0.0.0.0') return '0.0.0.0';

    const cleanIp = (ip && ip !== 'None' && ip !== 'Unknown' && ip !== '0.0.0.0') ? ip : null;

    if (isRouterEntity(cleanIp, mac)) {
        const routerName = getRouterName();
        const rIp = cleanIp || currentRouterInfo?.host || '192.168.1.1';
        if (mode === 'name') return routerName;
        if (mode === 'both') return `${routerName} (${rIp})`;
        return rIp;
    }

    const name = deviceNameCache.getName(cleanIp, mac, fallbackName);
    const resolvedIp = cleanIp || (mac ? (deviceNameCache.macToDev.get(mac.toUpperCase())?.ip || null) : null);

    if (mode === 'name') {
        return name || resolvedIp || mac || 'Unknown';
    }
    if (mode === 'both') {
        if (name && resolvedIp && name !== resolvedIp) {
            return `${name} (${resolvedIp})`;
        }
        if (name && mac && name !== mac) {
            return `${name} (${mac})`;
        }
        return name || resolvedIp || mac || 'Unknown';
    }
    // mode === 'ip'
    if (resolvedIp) return resolvedIp;
    return name || mac || 'Unknown';
}

function renderDeviceCell(ip, mac, fallbackName, mode = getDeviceDisplayMode()) {
    const label = formatDeviceIdentifier(ip, mac, mode, fallbackName);
    const resolvedName = deviceNameCache.getName(ip, mac, fallbackName);
    let sub = '';
    if (mode === 'name') {
        sub = ip || mac || '';
    } else if (mode === 'ip') {
        sub = (resolvedName && resolvedName !== label && !isIpAddress(resolvedName)) ? resolvedName : (fallbackName && fallbackName !== label && !isIpAddress(fallbackName) ? fallbackName : (mac || ''));
    } else {
        // both
        sub = mac || '';
    }
    return `
        <div class="font-mono text-slate-200 truncate max-w-[180px]" title="${escapeHtml(label)}">${escapeHtml(label)}</div>
        ${sub && sub !== label ? `<div class="text-[10px] text-slate-400 truncate max-w-[180px]" title="${escapeHtml(sub)}">${escapeHtml(sub)}</div>` : ''}
    `;
}

function formatEventDescription(event, mode = getDeviceDisplayMode()) {
    if (!event) return '';
    const src = (event.source_ip === '0.0.0.0') ? '0.0.0.0' : formatDeviceIdentifier(event.source_ip, event.source_mac, mode);
    const dst = formatDeviceIdentifier(event.target_ip, event.target_mac, mode);
    const type = (event.event_type || '').toLowerCase();

    if (type === 'arp_probe') {
        return `ARP probe from ${src} looking for ${dst}`;
    }
    if (type === 'dial_activity') {
        return `DIAL (Second Screen / Cast) probe from ${src}`;
    }
    if (type === 'airplay_activity') {
        return `AirPlay discovery query/announcement from ${src}`;
    }
    if (type === 'cast_activity') {
        return `Google Cast discovery query from ${src}`;
    }
    if (type === 'wol_wake') {
        const targetDev = formatDeviceIdentifier(null, event.target_mac, mode);
        return `Wake-on-LAN magic packet sent to ${targetDev || event.target_mac} by ${src}`;
    }
    if (type === 'port_probe') {
        const svc = (event.details && event.details.service) ? ` to ${event.details.service}` : '';
        return `TCP SYN probe${svc}: ${src} -> ${dst}`;
    }

    let desc = event.description || '';
    if (event.source_ip && event.source_ip !== '0.0.0.0' && src) {
        desc = desc.replaceAll(event.source_ip, src);
    }
    if (event.target_ip && event.target_ip !== '0.0.0.0' && dst) {
        desc = desc.replaceAll(event.target_ip, dst);
    }
    return desc;
}

function reRenderSnifferFeed() {
    const feed = document.getElementById('live-sniffer-feed');
    if (!feed) return;
    const mode = getDeviceDisplayMode();
    Array.from(feed.children).forEach(line => {
        const descEl = line.querySelector('.feed-desc');
        if (!descEl) return;
        if (line.dataset.isDadConfirmed === "true") {
            const targetIp = line.dataset.dadTargetIp;
            const count = parseInt(line.dataset.dadCount || '1', 10);
            const targetLabel = formatDeviceIdentifier(targetIp, null, mode);
            descEl.textContent = `${targetLabel} подтвержден и занят (${count} ${count === 1 ? 'зонд' : (count < 5 ? 'зонда' : 'зондов')} DAD)`;
        } else if (line._event) {
            descEl.textContent = formatEventDescription(line._event, mode);
        }
    });
}

function appendSnifferFeed(event) {
    const feed = document.getElementById('live-sniffer-feed');
    if (!feed) return;

    if (feed.querySelector('.italic')) {
        feed.innerHTML = '';
    }

    const timeStr = formatHumanTime(event.timestamp || Date.now());
    const eventType = (event.event_type || '').toLowerCase();
    const desc = (event.description || '').trim();
    const mode = getDeviceDisplayMode();

    // 1. Resolve physical device identifiers for robust dual-stack (IPv4 & IPv6) deduplication
    const srcPhysicalId = (event.source_mac ? event.source_mac.toUpperCase() : null) ||
                          formatDeviceIdentifier(event.source_ip, event.source_mac, 'name') ||
                          event.source_ip || 'unknown';
    const dstPhysicalId = (event.target_mac ? event.target_mac.toUpperCase() : null) ||
                          formatDeviceIdentifier(event.target_ip, event.target_mac, 'name') ||
                          event.target_ip || '';
    const eventKey = `${eventType}|${srcPhysicalId}|${dstPhysicalId}`;

    // 2. Check top recent lines (up to 4) for matching eventKey or identical description
    let matchingLine = null;
    const recentLines = Array.from(feed.children).slice(0, 4);
    for (const line of recentLines) {
        if (line.dataset.eventKey === eventKey || (line.dataset.eventType === eventType && line.dataset.desc === desc)) {
            matchingLine = line;
            break;
        }
    }

    if (matchingLine) {
        const count = parseInt(matchingLine.dataset.count || '1', 10) + 1;
        matchingLine.dataset.count = String(count);

        // Update timestamp to latest
        const timeEl = matchingLine.querySelector('.feed-time');
        if (timeEl) timeEl.textContent = timeStr;

        // Prefer IPv4 over link-local IPv6 (fe80::) for readable display
        const isCurrentIpv6 = matchingLine._event && matchingLine._event.source_ip && matchingLine._event.source_ip.startsWith('fe80:');
        const isNewIpv4 = event.source_ip && !event.source_ip.includes(':') && event.source_ip !== '0.0.0.0';
        if (isNewIpv4 || !matchingLine._event || isCurrentIpv6) {
            matchingLine._event = event;
        }

        // Re-render description with current display mode
        const descEl = matchingLine.querySelector('.feed-desc');
        if (descEl) {
            descEl.textContent = formatEventDescription(matchingLine._event, mode);
        }

        // Update / create count badge
        let badgeEl = matchingLine.querySelector('.feed-count-badge');
        if (!badgeEl) {
            badgeEl = document.createElement('span');
            badgeEl.className = 'feed-count-badge ml-1.5 px-1.5 py-0.5 rounded-md text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 shrink-0';
            matchingLine.appendChild(badgeEl);
        }
        badgeEl.textContent = `×${count}`;

        // Keep active streaming line at top of feed
        if (matchingLine !== feed.firstElementChild) {
            feed.prepend(matchingLine);
        }
        return;
    }

    // Check if this is an ARP announcement immediately following DAD probes for the same target IP
    const firstLine = feed.firstElementChild;
    if (firstLine && eventType === 'arp_probe' && firstLine.dataset.eventType === 'arp_probe') {
        const targetIp = event.target_ip;
        if (targetIp && firstLine.dataset.targetIp === targetIp && firstLine.dataset.srcIp === '0.0.0.0' && event.source_ip === targetIp) {
            const count = parseInt(firstLine.dataset.count || '1', 10);
            firstLine.dataset.srcIp = event.source_ip;
            firstLine.dataset.desc = desc;
            firstLine.dataset.isDadConfirmed = "true";
            firstLine.dataset.dadTargetIp = targetIp;
            firstLine.dataset.dadCount = String(count);
            const targetLabel = formatDeviceIdentifier(targetIp, event.source_mac, mode);
            firstLine.innerHTML = `
                <span class="feed-time text-slate-500 text-[10px]">${timeStr}</span>
                <span class="text-emerald-400 font-medium">[ARP_DAD]</span>
                <span class="feed-desc text-slate-300 truncate flex-1">${escapeHtml(targetLabel)} подтвержден и занят (${count} ${count === 1 ? 'зонд' : (count < 5 ? 'зонда' : 'зондов')} DAD)</span>
                <span class="feed-count-badge ml-1.5 px-1.5 py-0.5 rounded-md text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shrink-0">✓ OK</span>
            `;
            return;
        }
    }

    let badgeColor = "text-slate-400";
    if (eventType === 'wol_wake') badgeColor = "text-amber-400 font-bold";
    else if (eventType.includes('airplay')) badgeColor = "text-indigo-400";
    else if (eventType.includes('cast') || eventType.includes('dial')) badgeColor = "text-cyan-400";
    else if (eventType === 'arp_probe') badgeColor = "text-sky-400";

    const line = document.createElement('div');
    line.className = "flex items-center space-x-2 py-0.5 border-b border-slate-800/40";
    line.dataset.eventType = eventType;
    line.dataset.desc = desc;
    line.dataset.eventKey = eventKey;
    line.dataset.count = "1";
    if (event.target_ip) line.dataset.targetIp = event.target_ip;
    if (event.source_ip) line.dataset.srcIp = event.source_ip;
    line._event = event;

    const formattedDesc = formatEventDescription(event, mode);

    line.innerHTML = `
        <span class="feed-time text-slate-500 text-[10px]">${timeStr}</span>
        <span class="${badgeColor}">[${(event.event_type || '').toUpperCase()}]</span>
        <span class="feed-desc text-slate-300 truncate flex-1">${escapeHtml(formattedDesc)}</span>
    `;

    feed.prepend(line);
    // Keep max 30 items
    while (feed.children.length > 30) {
        feed.removeChild(feed.lastChild);
    }
}

// Sidebar Collapse / Expand State and Handling
function toggleSidebar() {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;
    const isCollapsed = sidebar.classList.toggle('sidebar-collapsed');
    try {
        localStorage.setItem('kg_sidebar_collapsed', isCollapsed ? '1' : '0');
    } catch (e) {}

    updateSidebarUI(isCollapsed);
}

function updateSidebarUI(isCollapsed) {
    const toggleIcon = document.getElementById('sidebar-toggle-icon');
    if (toggleIcon) {
        toggleIcon.setAttribute('data-lucide', isCollapsed ? 'panel-left-open' : 'panel-left-close');
    }
    const footerIcon = document.getElementById('sidebar-footer-icon');
    if (footerIcon) {
        footerIcon.setAttribute('data-lucide', isCollapsed ? 'chevrons-right' : 'chevrons-left');
    }
    const toggleBtn = document.getElementById('sidebar-toggle-btn');
    if (toggleBtn) {
        toggleBtn.setAttribute('title', isCollapsed ? 'Развернуть меню' : 'Свернуть меню (Горячая клавиша: [ )');
    }
    const footerBtn = document.getElementById('sidebar-footer-toggle-btn');
    if (footerBtn) {
        footerBtn.setAttribute('title', isCollapsed ? 'Развернуть меню' : 'Свернуть меню (Горячая клавиша: [ )');
    }
    const footerText = document.querySelector('.sidebar-footer-text');
    if (footerText) {
        footerText.textContent = isCollapsed ? '' : 'Свернуть меню';
    }
    if (window.lucide) {
        lucide.createIcons();
    }
}

function initSidebarState() {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;
    let isCollapsed = false;
    try {
        const saved = localStorage.getItem('kg_sidebar_collapsed');
        if (saved !== null) {
            isCollapsed = saved === '1';
        } else if (window.innerWidth < 1024) {
            isCollapsed = true;
        }
    } catch (e) {}

    if (isCollapsed) {
        sidebar.classList.add('sidebar-collapsed');
    } else {
        sidebar.classList.remove('sidebar-collapsed');
    }
    updateSidebarUI(isCollapsed);

    // Keyboard shortcut '[' or 'Ctrl+B' to toggle sidebar
    document.addEventListener('keydown', (e) => {
        const tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
        if (tag === 'input' || tag === 'textarea' || tag === 'select' || (e.target && e.target.isContentEditable)) return;
        if (e.key === '[' || (e.ctrlKey && e.key.toLowerCase() === 'b')) {
            e.preventDefault();
            toggleSidebar();
        }
    });
}

// Navigation
async function switchTab(tabId) {
    activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    document.querySelectorAll('main > section').forEach(sec => sec.classList.add('hidden'));
    document.getElementById(`view-${tabId}`).classList.remove('hidden');
    updateAllDisplayModeButtons();
    initSourceFilterCheckboxes();

    // On mobile screens, automatically collapse sidebar drawer on navigation
    if (window.innerWidth < 1024) {
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar && !sidebar.classList.contains('sidebar-collapsed')) {
            toggleSidebar();
        }
    }

    if (tabId === 'devices') loadDevices();
    else if (tabId === 'security') loadSecurity();
    else if (tabId === 'smarthome') loadSmartHome();
    else if (tabId === 'lan') {
        if (!devicesList || devicesList.length === 0) await loadDevices();
        loadLanTab();
    }
    else if (tabId === 'packets') {
        if (!devicesList || devicesList.length === 0) await loadDevices();
        loadPacketInspectorLive(true);
    }
    else if (tabId === 'tv_forensics') loadTvForensics();
    else if (tabId === 'alerts') loadAlerts();
    else if (tabId === 'dns') {
        const savedSubTab = localStorage.getItem('keenguard_dns_subtab') || 'log';
        switchDnsSubTab(savedSubTab);
    }
    else if (tabId === 'audits') loadTrafficAuditsTab();
    else if (tabId === 'investigator') loadInvestigatorTab();
    else if (tabId === 'settings') {
        const submenu = document.getElementById('settings-submenu');
        if (submenu) submenu.classList.remove('hidden');
        const chev = document.getElementById('settings-chevron');
        if (chev) chev.classList.add('rotate-180');
        loadSettings();
    }
    else if (tabId === 'dashboard') {
        loadWifiAudit();
        checkRouterUpdates();
        updateLiveTrafficChart();
        loadSecurityScoreForDashboard();
    }

    if (tabId !== 'settings') {
        const submenu = document.getElementById('settings-submenu');
        if (submenu) submenu.classList.add('hidden');
        const chev = document.getElementById('settings-chevron');
        if (chev) chev.classList.remove('rotate-180');
    }

    lucide.createIcons();
}

// Data Loaders
async function refreshAllData() {
    await loadStatus();
    await loadDevices();
    await loadUpnp();
    await loadEvents();
    if (activeTab === 'dashboard') {
        loadWifiAudit();
        checkRouterUpdates();
        updateLiveTrafficChart();
        loadSecurityScoreForDashboard();
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
    }
}

async function loadStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
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

        // WAN IP
        safeSetText('router-wan-ip', data.router.wan_ip || '—');

        // KeeneticOS version
        const osVer = data.router.version || '—';
        safeSetText('router-os-version', osVer);
        safeSetText('router-card-version', osVer);

        // Live Sniffer Mode
        safeSetText('sniffer-active-mode', data.sniffer?.mode === 'active' ? 'ACTIVE (Pcap/Raw)' : 'INACTIVE');

        // Memory usage
        if (data.router.memory) {
            safeSetText('router-mem-usage', `${data.router.memory.used_mb} / ${data.router.memory.total_mb} МБ`);
        }

        // Active Devices Count
        if (data.router.active_hosts !== undefined) {
            safeSetText('router-active-devices', data.router.active_hosts);
        }

        // Night mode
        const nText = document.getElementById('night-status-text');
        if (data.night_mode) {
            nText.textContent = 'Ночной режим: АКТИВЕН';
            nText.className = 'text-indigo-400 font-bold';
        } else {
            nText.textContent = 'Ночной режим: День';
            nText.className = 'text-slate-300';
        }

        document.getElementById('stat-online-devices').textContent = data.online_devices;
        document.getElementById('stat-total-devices').textContent = `из ${data.total_devices} хостов`;
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

// ==========================================
// Device Inspection, Grouping & Presentation
// ==========================================
const DEVICE_GROUPS_CONFIG = [
    { key: 'trusted', title: 'Доверенные устройства (ПК, Смартфоны, Ноутбуки)', icon: 'laptop', color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20' },
    { key: 'smart_tv', title: 'Smart TV & Медиаэкраны', icon: 'tv', color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/20' },
    { key: 'camera', title: 'Камеры видеонаблюдения', icon: 'video', color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/20' },
    { key: 'smart_home_hub', title: 'Хабы и контроллеры умного дома', icon: 'server', color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
    { key: 'iot', title: 'IoT & Периферия умного дома', icon: 'cpu', color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
    { key: 'unassigned', title: 'Не назначенные / Прочие устройства', icon: 'help-circle', color: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20' }
];

let activeDeviceFilter = 'all';

function ipToNum(ip) {
    if (!ip) return 0;
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return 0;
    return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

function sortDevices(devs) {
    const { col, dir } = tableSortState.devices || { col: 'name', dir: 'asc' };
    const mult = dir === 'asc' ? 1 : -1;

    return [...devs].sort((a, b) => {
        // Primary partitioning: Active devices (Online) always sort above Offline devices,
        // unless the user explicitly chose to sort by status column.
        if (col !== 'status') {
            const onA = a.is_online ? 1 : 0;
            const onB = b.is_online ? 1 : 0;
            if (onA !== onB) return onB - onA;
        }

        let cmp = 0;
        if (col === 'name') {
            const nameA = a.custom_name || a.hostname || a.ip || a.mac || '';
            const nameB = b.custom_name || b.hostname || b.ip || b.mac || '';
            cmp = nameA.localeCompare(nameB, 'ru');
        } else if (col === 'status') {
            const statA = a.is_online ? 1 : 0;
            const statB = b.is_online ? 1 : 0;
            cmp = statA - statB;
            if (cmp === 0) {
                const nameA = a.custom_name || a.hostname || a.ip || a.mac || '';
                const nameB = b.custom_name || b.hostname || b.ip || b.mac || '';
                return nameA.localeCompare(nameB, 'ru');
            }
        } else if (col === 'ip') {
            cmp = ipToNum(a.ip) - ipToNum(b.ip);
        } else if (col === 'vendor') {
            const vA = a.vendor || '';
            const vB = b.vendor || '';
            cmp = vA.localeCompare(vB, 'ru');
        } else if (col === 'profile') {
            const pA = (PROFILES[a.profile] && PROFILES[a.profile].name) || '';
            const pB = (PROFILES[b.profile] && PROFILES[b.profile].name) || '';
            cmp = pA.localeCompare(pB, 'ru');
        }
        return cmp * mult;
    });
}

function setDeviceViewMode(mode) {
    deviceViewMode = mode;
    localStorage.setItem('kg_device_view_mode', mode);
    updateDeviceViewModeButtons();
    applyDeviceFiltersAndRender();
}

function updateDeviceViewModeButtons() {
    const btnGrid = document.getElementById('btn-device-view-grid');
    const btnTable = document.getElementById('btn-device-view-table');
    if (!btnGrid || !btnTable) return;

    if (deviceViewMode === 'grid') {
        btnGrid.className = 'px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 bg-indigo-600 text-white shadow-sm';
        btnTable.className = 'px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 text-slate-400 hover:text-white';
    } else {
        btnTable.className = 'px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 bg-indigo-600 text-white shadow-sm';
        btnGrid.className = 'px-2.5 py-1 rounded-lg text-xs font-medium transition flex items-center space-x-1.5 text-slate-400 hover:text-white';
    }
}

function changeDeviceSort(val) {
    if (val === 'name_asc') {
        tableSortState.devices = { col: 'name', dir: 'asc' };
    } else if (val === 'name_desc') {
        tableSortState.devices = { col: 'name', dir: 'desc' };
    } else if (val === 'status_online') {
        tableSortState.devices = { col: 'status', dir: 'desc' };
    } else if (val === 'ip_asc') {
        tableSortState.devices = { col: 'ip', dir: 'asc' };
    } else if (val === 'vendor_asc') {
        tableSortState.devices = { col: 'vendor', dir: 'asc' };
    }
    applyDeviceFiltersAndRender();
}

function toggleHideOffline(checked) {
    localStorage.setItem('kg_hide_offline', checked ? 'true' : 'false');
    applyDeviceFiltersAndRender();
}

function filterDevices(filter) {
    activeDeviceFilter = filter;
    document.querySelectorAll('.dev-filter-btn').forEach(btn => {
        const isOffline = btn.dataset.filter === 'offline';
        const flexCls = isOffline ? ' flex items-center space-x-1.5' : '';
        if (btn.dataset.filter === filter) {
            btn.className = `dev-filter-btn active px-3 py-1.5 text-xs rounded-xl bg-indigo-600 text-white font-medium transition${flexCls}`;
        } else {
            btn.className = `dev-filter-btn px-3 py-1.5 text-xs rounded-xl bg-surface-950 border border-slate-800 text-slate-400 hover:text-white transition${flexCls}`;
        }
    });
    applyDeviceFiltersAndRender();
}

function applyDeviceFiltersAndRender() {
    const searchInput = document.getElementById('devices-search-input');
    const term = (searchInput ? searchInput.value : '').toLowerCase().trim();

    // Update offline count badge on the "Офлайн" pill
    const totalOfflineCount = devicesList.filter(d => !d.is_online).length;
    const offlinePillCount = document.getElementById('devices-offline-pill-count');
    if (offlinePillCount) {
        offlinePillCount.textContent = totalOfflineCount;
    }

    let filtered = devicesList;

    if (term) {
        filtered = filtered.filter(d => {
            const name = (d.custom_name || '').toLowerCase();
            const host = (d.hostname || '').toLowerCase();
            const ip = (d.ip || '').toLowerCase();
            const mac = (d.mac || '').toLowerCase();
            const vendor = (d.vendor || '').toLowerCase();
            const profName = ((PROFILES[d.profile] && PROFILES[d.profile].name) || '').toLowerCase();
            return name.includes(term) || host.includes(term) || ip.includes(term) || mac.includes(term) || vendor.includes(term) || profName.includes(term);
        });
    }

    const hideOffline = localStorage.getItem('kg_hide_offline') === 'true';
    const hideOfflineCb = document.getElementById('toggle-hide-offline-devices');
    if (hideOfflineCb && hideOfflineCb.checked !== hideOffline) {
        hideOfflineCb.checked = hideOffline;
    }

    if (activeDeviceFilter === 'offline') {
        filtered = filtered.filter(d => !d.is_online);
    } else {
        if (activeDeviceFilter !== 'all') {
            filtered = filtered.filter(d => d.profile === activeDeviceFilter);
        }
        if (hideOffline) {
            filtered = filtered.filter(d => d.is_online);
        }
    }

    const onlineCount = filtered.filter(d => d.is_online).length;
    const onlineBadge = document.getElementById('devices-online-counter-badge');
    if (onlineBadge) {
        if (hideOffline && activeDeviceFilter !== 'offline') {
            onlineBadge.textContent = `${onlineCount} в сети (офлайн скрыты)`;
        } else {
            onlineBadge.textContent = `${onlineCount} из ${filtered.length} в сети`;
        }
    }

    renderDevicesGrouped(filtered);
}

function renderDevicesGrouped(devices) {
    const grid = document.getElementById('devices-grid');
    if (!grid) return;

    if (!devices || devices.length === 0) {
        if (activeDeviceFilter === 'offline') {
            grid.innerHTML = '<div class="text-center py-12 text-slate-500 text-sm bg-surface-900 border border-slate-800/80 rounded-2xl p-6">Все устройства находятся в сети! Неактивных или спящих записей нет.</div>';
        } else {
            grid.innerHTML = '<div class="text-center py-12 text-slate-500 text-sm bg-surface-900 border border-slate-800/80 rounded-2xl p-6">Устройства не найдены по заданным критериям фильтра.</div>';
        }
        return;
    }

    const grouped = {};
    DEVICE_GROUPS_CONFIG.forEach(g => { grouped[g.key] = []; });

    devices.forEach(d => {
        const pKey = d.profile && grouped[d.profile] ? d.profile : 'unassigned';
        grouped[pKey].push(d);
    });

    const groupsToShow = (activeDeviceFilter === 'all' || activeDeviceFilter === 'offline')
        ? DEVICE_GROUPS_CONFIG.filter(g => grouped[g.key].length > 0)
        : DEVICE_GROUPS_CONFIG.filter(g => g.key === activeDeviceFilter);

    if (groupsToShow.length === 0) {
        grid.innerHTML = '<div class="text-center py-12 text-slate-500 text-sm bg-surface-900 border border-slate-800/80 rounded-2xl p-6">В данной категории устройства отсутствуют.</div>';
        return;
    }

    let topBannerHtml = '';
    if (activeDeviceFilter === 'offline') {
        topBannerHtml = `
            <div class="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
                <div class="flex items-center space-x-3">
                    <div class="p-2 rounded-xl bg-amber-500/20 text-amber-300">
                        <i data-lucide="clock-alert" class="w-5 h-5"></i>
                    </div>
                    <div>
                        <h4 class="font-bold text-sm text-white">Ревизия неактивных устройств (${devices.length})</h4>
                        <p class="text-xs text-slate-300">Здесь показаны отключенные устройства, спящая техника и старые сессии ротированных MAC-адресов.</p>
                    </div>
                </div>
                <button onclick="openClearOfflineModal()" class="px-3.5 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold flex items-center space-x-1.5 transition shadow-sm shrink-0">
                    <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    <span>Очистить все офлайн</span>
                </button>
            </div>
        `;
    }

    grid.innerHTML = topBannerHtml + groupsToShow.map(g => {
        const groupDevs = grouped[g.key] || [];
        const sortedDevs = sortDevices(groupDevs);
        const onlineCount = sortedDevs.filter(d => d.is_online).length;

        let contentHtml = '';
        if (deviceViewMode === 'grid') {
            contentHtml = `
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    ${sortedDevs.map(d => renderDeviceCard(d)).join('')}
                </div>
            `;
        } else {
            contentHtml = `
                <div class="overflow-x-auto rounded-xl border border-slate-800/80 bg-surface-950 shadow-inner">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="bg-surface-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800 select-none">
                            <tr>
                                <th onclick="toggleSortTable('devices', 'name')" class="py-2.5 px-3.5 cursor-pointer hover:text-white transition group" title="Сортировать по имени">
                                    <div class="flex items-center space-x-1">
                                        <span>Устройство</span>
                                        <span id="sort-icon-devices-name" class="text-[10px] ${tableSortState.devices.col === 'name' ? 'text-indigo-400 font-bold' : 'text-slate-500'} font-mono">${tableSortState.devices.col === 'name' ? (tableSortState.devices.dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
                                    </div>
                                </th>
                                <th onclick="toggleSortTable('devices', 'status')" class="py-2.5 px-3 cursor-pointer hover:text-white transition group" title="Сортировать по статусу">
                                    <div class="flex items-center space-x-1">
                                        <span>Статус</span>
                                        <span id="sort-icon-devices-status" class="text-[10px] ${tableSortState.devices.col === 'status' ? 'text-indigo-400 font-bold' : 'text-slate-500'} font-mono">${tableSortState.devices.col === 'status' ? (tableSortState.devices.dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
                                    </div>
                                </th>
                                <th onclick="toggleSortTable('devices', 'ip')" class="py-2.5 px-3 cursor-pointer hover:text-white transition group" title="Сортировать по IP">
                                    <div class="flex items-center space-x-1">
                                        <span>IP / MAC</span>
                                        <span id="sort-icon-devices-ip" class="text-[10px] ${tableSortState.devices.col === 'ip' ? 'text-indigo-400 font-bold' : 'text-slate-500'} font-mono">${tableSortState.devices.col === 'ip' ? (tableSortState.devices.dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
                                    </div>
                                </th>
                                <th onclick="toggleSortTable('devices', 'vendor')" class="py-2.5 px-3 cursor-pointer hover:text-white transition group" title="Сортировать по производителю">
                                    <div class="flex items-center space-x-1">
                                        <span>Производитель</span>
                                        <span id="sort-icon-devices-vendor" class="text-[10px] ${tableSortState.devices.col === 'vendor' ? 'text-indigo-400 font-bold' : 'text-slate-500'} font-mono">${tableSortState.devices.col === 'vendor' ? (tableSortState.devices.dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
                                    </div>
                                </th>
                                <th class="py-2.5 px-3">Безопасность & Политики</th>
                                <th class="py-2.5 px-3 text-right">Действия</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-slate-800/60 font-sans">
                            ${sortedDevs.map(d => renderDeviceRow(d)).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        }

        return `
            <div class="bg-surface-900 border border-slate-800/80 rounded-2xl p-5 space-y-4 mb-6 shadow-sm">
                <!-- Group Header -->
                <div class="flex items-center justify-between border-b border-slate-800/60 pb-3">
                    <div class="flex items-center space-x-3">
                        <div class="p-2 rounded-xl ${g.bg} ${g.color}">
                            <i data-lucide="${g.icon}" class="w-4 h-4"></i>
                        </div>
                        <div>
                            <div class="flex items-center space-x-2.5">
                                <h3 class="font-bold text-sm text-white">${g.title}</h3>
                                <span class="px-2 py-0.5 rounded-full text-[11px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">${sortedDevs.length}</span>
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        <span class="text-xs font-mono ${onlineCount > 0 ? 'text-emerald-400' : 'text-slate-500'} font-medium">${onlineCount} в сети</span>
                    </div>
                </div>

                <!-- Group Content -->
                ${contentHtml}
            </div>
        `;
    }).join('');

    updateDeviceViewModeButtons();
    if (window.lucide) lucide.createIcons();
}

function renderMacRotationBadge(d) {
    if (!d) return '';
    if (d.rotation_group) {
        const rg = d.rotation_group;
        if (rg.role === 'hardware') {
            return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-medium whitespace-nowrap" title="Постоянный заводской MAC-адрес устройства (${rg.alias_count} адреса в сети)">Заводской MAC</span>`;
        } else if (rg.role === 'active_random') {
            return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-teal-500/15 text-teal-300 border border-teal-500/30 font-medium whitespace-nowrap" title="Текущий активный приватный MAC (Private Wi-Fi / LAA)">Приватный MAC</span>`;
        } else {
            return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-slate-800 text-slate-400 border border-slate-700 font-medium whitespace-nowrap" title="Предыдущий ротированный MAC устройства (не активен)">Ротация (история)</span>`;
        }
    } else if (d.is_random_mac) {
        return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20 font-medium whitespace-nowrap" title="Рандомизированный Wi-Fi MAC (LAA)">Случайный MAC</span>`;
    }
    return '';
}

function renderSegmentBadge(d) {
    if (!d) return '';
    const seg = (d.segment || 'Home').trim();
    const risk = d.segment_risk || {};
    const isGuest = seg.toLowerCase().includes('guest') || seg.toLowerCase().includes('гостев');

    if (isGuest) {
        return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-medium whitespace-nowrap" title="Гостевой сегмент (L2-изоляция включена)">Гостевая сеть</span>`;
    }
    if (risk.risk_level === 'high') {
        return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-rose-500/15 text-rose-300 border border-rose-500/30 font-semibold whitespace-nowrap cursor-help" title="${escapeHtml(risk.recommendation || 'Внимание: L2-трафик к ПК не фильтруется роутером')}">Домашняя (L2 риск)</span>`;
    } else if (risk.risk_level === 'medium') {
        return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-amber-500/15 text-amber-300 border border-amber-500/30 font-medium whitespace-nowrap cursor-help" title="${escapeHtml(risk.recommendation || 'Общий L2 с домашними ПК')}">Домашняя (L2 открыт)</span>`;
    }
    return `<span class="px-2 py-0.5 text-[10px] rounded-md bg-slate-800 text-slate-300 border border-slate-700 font-medium whitespace-nowrap" title="Основной сегмент Home (Bridge0)">Домашняя сеть</span>`;
}

function renderDeviceCard(d) {
    const prof = PROFILES[d.profile] || PROFILES.unassigned;
    const displayName = d.custom_name || d.hostname || d.ip || d.mac;
    const onlineDot = d.is_online ? 'bg-emerald-400' : 'bg-slate-600';
    const onlineText = d.is_online ? 'Online' : 'Offline';
    const dimmingClass = d.is_online ? '' : 'opacity-75 hover:opacity-100 transition-opacity';

    return `
        <div class="bg-surface-950 border border-slate-800 rounded-2xl p-4 hover:border-indigo-500/50 transition cursor-pointer flex flex-col justify-between group shadow-sm ${dimmingClass}" onclick="openDeviceModal('${d.mac}')">
            <div>
                <div class="flex items-start justify-between">
                    <div class="flex items-center space-x-3">
                        <div class="p-2.5 rounded-xl ${prof.bg} ${prof.color}">
                            <i data-lucide="${prof.icon}" class="w-5 h-5"></i>
                        </div>
                        <div>
                            <h4 class="font-bold text-sm text-white group-hover:text-indigo-300 transition truncate max-w-[170px]">${escapeHtml(displayName)}</h4>
                            <p class="text-xs text-slate-400 font-mono">${d.ip || 'Нет IP'} • ${d.mac}</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-800/80 text-slate-300 border border-slate-700">
                        <span class="w-1.5 h-1.5 rounded-full ${onlineDot}"></span>
                        <span>${onlineText}</span>
                    </div>
                </div>

                <div class="mt-3.5 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-xs">
                    <span class="text-slate-400">Профиль:</span>
                    <span class="px-2 py-0.5 rounded-lg ${prof.bg} ${prof.color} font-medium border ${prof.border} text-[11px]">${prof.name}</span>
                </div>

                <!-- Security badges -->
                <div class="mt-2.5 flex flex-wrap gap-1">
                    ${renderSegmentBadge(d)}
                    ${d.is_isolated_lan ? '<span class="px-2 py-0.5 text-[10px] rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium">LAN Изоляция</span>' : ''}
                    ${d.is_blocked_wan ? '<span class="px-2 py-0.5 text-[10px] rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-medium">WAN Заблокирован</span>' : ''}
                    ${d.is_isolated_lan && d.airplay_allowed ? '<span class="px-2 py-0.5 text-[10px] rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">AirPlay Relay</span>' : ''}
                    ${d.profile === 'smart_tv' && d.night_mode_enabled ? '<span class="px-2 py-0.5 text-[10px] rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">Ночной сон</span>' : ''}
                    ${renderMacRotationBadge(d)}
                </div>
            </div>

            <div class="mt-3.5 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-[11px] text-slate-500">
                <span class="truncate max-w-[140px]">${escapeHtml(d.vendor || 'Unknown Vendor')}</span>
                <span class="text-indigo-400 group-hover:text-indigo-300 font-medium flex items-center space-x-0.5">
                    <span>Настроить</span>
                    <span>→</span>
                </span>
            </div>
        </div>
    `;
}

function renderDeviceRow(d) {
    const prof = PROFILES[d.profile] || PROFILES.unassigned;
    const displayName = d.custom_name || d.hostname || d.ip || d.mac;
    const dimmingClass = d.is_online ? '' : 'opacity-75 hover:opacity-100 transition-opacity';

    const badges = [renderSegmentBadge(d)];
    if (d.is_blocked_wan) {
        badges.push('<span class="px-2 py-0.5 text-[10px] rounded-md bg-rose-500/10 text-rose-400 border border-rose-500/20 font-medium whitespace-nowrap">WAN Заблокирован</span>');
    }
    if (d.is_isolated_lan) {
        badges.push('<span class="px-2 py-0.5 text-[10px] rounded-md bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 font-medium whitespace-nowrap">LAN Изоляция</span>');
    }
    if (d.is_isolated_lan && d.airplay_allowed) {
        badges.push('<span class="px-2 py-0.5 text-[10px] rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 whitespace-nowrap">AirPlay</span>');
    }
    if (d.profile === 'smart_tv' && d.night_mode_enabled) {
        badges.push('<span class="px-2 py-0.5 text-[10px] rounded-md bg-purple-500/10 text-purple-400 border border-purple-500/20 whitespace-nowrap">Ночной сон</span>');
    }
    const rotBadge = renderMacRotationBadge(d);
    if (rotBadge) {
        badges.push(rotBadge);
    }
    if (badges.length === 0) {
        badges.push('<span class="text-slate-500 text-[11px] italic">Стандартный доступ</span>');
    }

    return `
        <tr class="hover:bg-slate-800/40 transition cursor-pointer group ${dimmingClass}" onclick="openDeviceModal('${d.mac}')">
            <td class="py-2.5 px-3.5">
                <div class="flex items-center space-x-2.5">
                    <div class="p-1.5 rounded-lg ${prof.bg} ${prof.color} shrink-0">
                        <i data-lucide="${prof.icon}" class="w-4 h-4"></i>
                    </div>
                    <div class="min-w-0">
                        <div class="font-bold text-white text-xs group-hover:text-indigo-300 transition truncate max-w-[200px]">${escapeHtml(displayName)}</div>
                        ${d.hostname && d.hostname !== displayName ? `<div class="text-[10px] text-slate-500 truncate max-w-[180px]">${escapeHtml(d.hostname)}</div>` : ''}
                    </div>
                </div>
            </td>
            <td class="py-2.5 px-3 whitespace-nowrap">
                <span class="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium ${d.is_online ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20' : 'bg-slate-800 text-slate-400 border border-slate-700'}">
                    <span class="w-1.5 h-1.5 rounded-full ${d.is_online ? 'bg-emerald-400' : 'bg-slate-500'}"></span>
                    <span>${d.is_online ? 'Online' : 'Offline'}</span>
                </span>
            </td>
            <td class="py-2.5 px-3 font-mono text-[11px] whitespace-nowrap">
                <div class="text-slate-200 font-medium">${d.ip || '—'}</div>
                <div class="text-[10px] text-slate-500">${d.mac}</div>
            </td>
            <td class="py-2.5 px-3 text-slate-400 text-xs truncate max-w-[140px]">
                ${escapeHtml(d.vendor || 'Неизвестен')}
            </td>
            <td class="py-2.5 px-3">
                <div class="flex flex-wrap gap-1">
                    ${badges.join('')}
                </div>
            </td>
            <td class="py-2.5 px-3 text-right whitespace-nowrap" onclick="event.stopPropagation()">
                <button onclick="openDeviceModal('${d.mac}')" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white text-xs font-medium transition flex items-center space-x-1 ml-auto">
                    <i data-lucide="sliders" class="w-3.5 h-3.5"></i>
                    <span>Параметры</span>
                </button>
            </td>
        </tr>
    `;
}

function renderDevicesGrid(devices) {
    renderDevicesGrouped(devices);
}

// Device Detail Modal Sub-Tabs
function switchDeviceModalTab(tab) {
    const polTab = document.getElementById('modal-tab-policies');
    const trafTab = document.getElementById('modal-tab-traffic');
    const polBtn = document.getElementById('modal-tab-btn-policies');
    const trafBtn = document.getElementById('modal-tab-btn-traffic');
    if (!polTab || !trafTab) return;

    if (tab === 'policies') {
        polTab.classList.remove('hidden');
        trafTab.classList.add('hidden');
        if (polBtn) polBtn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 flex items-center space-x-1.5 transition';
        if (trafBtn) trafBtn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 flex items-center space-x-1.5 transition';
    } else {
        polTab.classList.add('hidden');
        trafTab.classList.remove('hidden');
        if (trafBtn) trafBtn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 flex items-center space-x-1.5 transition';
        if (polBtn) polBtn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 flex items-center space-x-1.5 transition';
        if (currentDeviceMac) {
            loadDeviceTrafficChart(currentDeviceMac);
        }
    }
    lucide.createIcons();
}

// Device Detail Modal
async function openDeviceModal(mac) {
    if (!mac) return;
    currentDeviceMac = mac;
    switchDeviceModalTab('policies');
    const modal = document.getElementById('device-modal');
    if (!modal) return;
    modal.classList.remove('hidden');

    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}`);
        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }
        const data = await res.json();
        const d = data.device;
        if (!d) {
            showToast('Устройство не найдено или удалено', true);
            closeDeviceModal();
            return;
        }
        const prof = (d.profile && PROFILES[d.profile]) ? PROFILES[d.profile] : PROFILES.unassigned;

        const nameEl = document.getElementById('modal-dev-name');
        if (nameEl) nameEl.textContent = d.custom_name || d.hostname || d.mac;
        const macEl = document.getElementById('modal-dev-mac');
        if (macEl) macEl.textContent = d.mac;
        const ipEl = document.getElementById('modal-dev-ip');
        if (ipEl) ipEl.textContent = d.ip || 'Не назначен';
        const vendorEl = document.getElementById('modal-dev-vendor');
        if (vendorEl) vendorEl.textContent = d.vendor || 'Неизвестен';

        const profSelect = document.getElementById('modal-profile-select');
        if (profSelect) profSelect.value = d.profile || 'unassigned';
        const wanToggle = document.getElementById('modal-toggle-wan');
        if (wanToggle) wanToggle.checked = Boolean(d.is_blocked_wan);

        // LAN Policy Preset & Quarantine Override
        if (!allLanPresets || allLanPresets.length === 0) {
            await loadLanPresets();
        }
        const presetSelect = document.getElementById('modal-lan-preset-select');
        if (presetSelect) {
            presetSelect.value = d.preset_id || '';
        }

        const customPortsInput = document.getElementById('modal-custom-allowed-ports');
        if (customPortsInput) {
            customPortsInput.value = (d.custom_allowed_ports && Array.isArray(d.custom_allowed_ports)) 
                ? d.custom_allowed_ports.join(', ') 
                : '';
        }

        const nvrGroup = document.getElementById('modal-nvr-group');
        const nvrInput = document.getElementById('modal-nvr-ip');
        if (nvrGroup && nvrInput) {
            if (d.profile === 'camera') {
                nvrGroup.classList.remove('hidden');
                nvrInput.value = d.designated_nvr_ip || '';
            } else {
                nvrGroup.classList.add('hidden');
            }
        }

        const autoQuarSelect = document.getElementById('modal-auto-quarantine-override');
        if (autoQuarSelect) {
            autoQuarSelect.value = d.auto_quarantine_override || 'profile_default';
        }

        // LAN status indicator & Keenetic hardware segmentation reality
        const lanBadge = document.getElementById('modal-lan-badge');
        const lanSub = document.getElementById('modal-lan-subtitle');
        const risk = d.segment_risk || {};
        const seg = (d.segment || 'Home').trim();
        const isGuest = d.is_isolated_lan || seg.toLowerCase().includes('guest') || seg.toLowerCase().includes('гостев');

        if (lanBadge) {
            if (isGuest) {
                lanBadge.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">🔒 Изолирован (Гостевая сеть)</span>';
                if (lanSub) lanSub.textContent = "Аппаратная изоляция: L2-доступ к другим клиентам заблокирован роутером.";
            } else if (risk.risk_level === 'high') {
                lanBadge.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-rose-500/15 text-rose-300 border border-rose-500/30" title="L2-трафик идет в обход файрвола">⚠️ В Bridge0 (L2 риск)</span>';
                if (lanSub) lanSub.textContent = risk.recommendation || "L2-трафик между клиентами идет в обход файрвола роутера. Перенесите в Гостевую сеть Keenetic.";
            } else {
                lanBadge.innerHTML = `<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300 border border-slate-700">🔓 Сегмент: ${escapeHtml(seg)}</span>`;
                if (lanSub) lanSub.textContent = risk.recommendation || "В основном мосте Home (Bridge0).";
            }
        }

        // Smart TV specific options visibility
        const tvOptions = document.getElementById('modal-tv-options');
        if (tvOptions) {
            if (d.profile === 'smart_tv') {
                tvOptions.classList.remove('hidden');
                const airToggle = document.getElementById('modal-toggle-airplay');
                if (airToggle) airToggle.checked = Boolean(d.airplay_allowed);
                const dlnaToggle = document.getElementById('modal-toggle-dlna');
                if (dlnaToggle) dlnaToggle.checked = d.dlna_allowed !== false;
                const nightToggle = document.getElementById('modal-toggle-night');
                if (nightToggle) nightToggle.checked = Boolean(d.night_mode_enabled);
            } else {
                tvOptions.classList.add('hidden');
            }
        }

        const iconContainer = document.getElementById('modal-dev-icon');
        if (iconContainer) {
            iconContainer.className = `p-2 rounded-xl ${prof.bg} ${prof.color}`;
            iconContainer.innerHTML = `<i data-lucide="${prof.icon}" class="w-5 h-5"></i>`;
        }

        // MAC Randomization & Device Identity banner logic
        const rotBanner = document.getElementById('modal-mac-rotation-banner');
        const rotTitle = document.getElementById('modal-mac-rotation-title');
        const rotBody = document.getElementById('modal-mac-rotation-body');

        if (rotBanner && rotBody) {
            if (d.rotation_group || d.is_random_mac) {
                rotBanner.classList.remove('hidden');
                let html = '';
                if (d.rotation_group) {
                    const rg = d.rotation_group;
                    const role = rg.role;
                    if (rotTitle) {
                        if (role === 'hardware') {
                            rotTitle.textContent = `Заводской физический MAC («${escapeHtml(rg.hostname)}»)`;
                        } else if (role === 'active_random') {
                            rotTitle.textContent = `Активный приватный MAC («${escapeHtml(rg.hostname)}»)`;
                        } else {
                            rotTitle.textContent = `Ротированный MAC (история) («${escapeHtml(rg.hostname)}»)`;
                        }
                    }
                    html += `<p class="font-medium text-slate-200">Обнаружено <b>${rg.alias_count} MAC-адреса</b> с сетевым именем «${escapeHtml(rg.hostname)}».</p>`;
                    if (rg.hardware_mac) {
                        const isCurHw = (rg.hardware_mac === d.mac);
                        html += `<p class="font-mono text-[10px] text-slate-400">Постоянный заводской MAC: <span class="text-indigo-300 font-semibold">${rg.hardware_mac}</span>${isCurHw ? ' <span class="text-emerald-400">(открыт)</span>' : ''}</p>`;
                    }
                    if (rg.active_mac) {
                        const isCurAct = (rg.active_mac === d.mac);
                        html += `<p class="font-mono text-[10px] text-slate-400">Текущий активный MAC в сети: <span class="text-teal-300 font-semibold">${rg.active_mac}</span>${isCurAct ? ' <span class="text-teal-400">(это устройство)</span>' : ''}</p>`;
                    }
                    if (rg.other_macs && rg.other_macs.length > 0) {
                        html += `<p class="font-mono text-[10px] text-slate-400">Связанные адреса (алиасы): <span class="text-amber-300">${rg.other_macs.join(', ')}</span></p>`;
                    }
                } else {
                    if (rotTitle) rotTitle.textContent = 'Случайный MAC-адрес (Private Wi-Fi / LAA)';
                    html += '<p>Устройство использует программный случайный MAC-адрес (Locally Administered Address) для защиты приватности.</p>';
                }

                html += `<div class="mt-2 p-2.5 rounded-lg bg-surface-950/90 border border-amber-900/40 text-[10px] text-amber-200/90 space-y-1.5">
                    <p><b>⚠️ Zero-Trust контроль:</b> Сетевое имя передается в открытом виде и может быть подделано. Новый MAC-адрес не регистрируется в сети автоматически и не наследует привилегий.</p>
                    <p><b>Сетевые правила Keenetic:</b> При каждой смене MAC роутер выдает новый IP-адрес. Статический IP и профили фильтрации DNS в KeeneticOS привязаны к конкретному MAC.</p>
                    <p><b>Рекомендация:</b> Чтобы в домашней сети не слетал статический IP и правила блокировки, отключите Private Wi-Fi для домашней сети на телефоне: <i>Настройки &rarr; Wi-Fi &rarr; Шестеренка сети &rarr; «Тип MAC» &rarr; «MAC-адрес телефона»</i>.</p>
                </div>`;
                rotBody.innerHTML = html;
            } else {
                rotBanner.classList.add('hidden');
            }
        }

        // Smart Segmentation recommendation banner toggle
        const tipEl = document.getElementById('modal-segmentation-tip');
        if (tipEl) {
            const isSegmentable = d.profile === 'smart_home_hub' || d.profile === 'iot';
            if (isSegmentable) {
                tipEl.classList.remove('hidden');
                tipEl.removeAttribute('open'); // Keep collapsed by default so it stays compact
            } else {
                tipEl.classList.add('hidden');
            }
        }

        // Offline device deletion button
        const delDevBtn = document.getElementById('btn-delete-device-modal');
        if (delDevBtn) {
            if (!d.is_online) {
                delDevBtn.classList.remove('hidden');
            } else {
                delDevBtn.classList.add('hidden');
            }
        }

        lucide.createIcons();

        await checkDeviceAuditState(mac);
        loadDeviceTrafficChart(mac);

    } catch (e) {
        console.error('Error opening device modal', e);
    }
}

function closeDeviceModal() {
    if (auditTimerInterval) clearInterval(auditTimerInterval);
    document.getElementById('device-modal').classList.add('hidden');
    currentDeviceMac = null;
}

async function deleteCurrentDevice() {
    if (!currentDeviceMac) return;
    if (!confirm(`Удалить устройство (${currentDeviceMac}) из базы данных?`)) return;
    try {
        const res = await fetch(`/api/devices/${currentDeviceMac}`, { method: 'DELETE' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        closeDeviceModal();
        showToast('Устройство успешно удалено');
        await loadDevices();
    } catch (e) {
        console.error('Failed to delete device', e);
        showToast('Ошибка при удалении устройства', true);
    }
}

async function applyModalProfile() {
    if (!currentDeviceMac) return;
    const profileKey = document.getElementById('modal-profile-select').value;
    await saveModalUnifiedPolicy(profileKey);
}

async function toggleModalWan(val) {
    if (!currentDeviceMac) return;
    await fetch(`/api/devices/${currentDeviceMac}/toggle_wan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}


async function toggleModalAirplay(val) {
    if (!currentDeviceMac) return;
    await fetch(`/api/devices/${currentDeviceMac}/toggle_airplay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

async function toggleModalDlna(val) {
    if (!currentDeviceMac) return;
    await fetch(`/api/devices/${currentDeviceMac}/toggle_dlna`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

async function toggleModalNight(val) {
    if (!currentDeviceMac) return;
    await fetch(`/api/devices/${currentDeviceMac}/toggle_night`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

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
                    <span class="text-xs text-slate-400 font-mono">${tv.ip}</span>
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
                            <input type="checkbox" ${tv.night_mode_enabled ? 'checked' : ''} onchange="toggleTvNight('${tv.mac}', this.checked)" class="w-4 h-4 rounded text-indigo-600 shrink-0">
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
                                <span class="text-xs font-semibold px-2 py-0.5 rounded ${isCrit ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-300'}">${e.event_type.toUpperCase()}</span>
                                <span class="text-xs text-slate-500">${timeStr}</span>
                            </div>
                            <p class="text-sm font-medium text-slate-200">${escapeHtml(e.description)}</p>
                            ${e.source_ip ? `<p class="text-xs text-slate-400">Источник команды: <span class="font-mono text-indigo-300">${e.source_ip} (${e.source_mac || 'MAC N/A'})</span></p>` : ''}
                        </div>
                        ${e.pcap_file ? `
                            <a href="/api/events/pcap/${e.pcap_file}" download class="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 transition shrink-0">
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
    const totalBadge = document.getElementById('tv-sinkholes-total-badge');
    if (totalBadge) {
        safeSetText(totalBadge, `${tvBrandPresetsData.active_sinkholes_count || 0} активных правил 0.0.0.0`);
    }

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
                <button type="button" onclick="switchTvBrandTab('${p.id}')" class="px-3.5 py-2 rounded-xl text-xs font-medium transition flex items-center space-x-2 shrink-0 ${tabClass}">
                    <span>${p.name}</span>
                    ${hasDetected ? '<span class="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">В сети</span>' : ''}
                    <span class="px-1.5 py-0.2 rounded-full text-[10px] ${isActiveTab ? 'bg-indigo-700 text-indigo-100' : 'bg-slate-800 text-slate-400'}">${p.active_count}/${p.total_count}</span>
                </button>
            `;
        }).join('');
    }

    // 3. Find active preset
    const preset = tvBrandPresetsData.presets.find(p => p.id === activeTvBrandId) || tvBrandPresetsData.presets[0];
    if (!preset) return;

    // Update block button labels
    const safeLabel = document.getElementById('btn-block-safe-tv-brand-label');
    if (safeLabel) {
        safeSetText(safeLabel, `🟢 Блокировать безопасные (${preset.safe_count || 0})`);
    }
    const blockLabel = document.getElementById('btn-block-tv-brand-label');
    if (blockLabel) {
        safeSetText(blockLabel, `⛔ Блокировать ВСЕ (${preset.total_count || 0})`);
    }

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
                            <span>🟢 Безопасно (Реклама & ACR)</span>
                        </div>
                        <p class="text-[11px] text-slate-300 leading-snug">Баннеры на экране, промо и шпионская ACR-слежка (Live Plus). Блокируются без побочных эффектов для ТВ.</p>
                    </div>
                    <div class="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 space-y-1">
                        <div class="font-semibold text-amber-300 flex items-center space-x-1.5 text-[11px]">
                            <span class="w-2 h-2 rounded-full bg-amber-400 shrink-0"></span>
                            <span>🟡 С осторожностью (Голос / Магазин)</span>
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
                    <span>Физическое отключение ACR (распознавания контента) на пульте ${preset.name}</span>
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
                    ? `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">🟢 ${escapeHtml(d.safety_label || 'Безопасно')}</span>`
                    : `<span class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">🟡 ${escapeHtml(d.safety_label || 'С осторожностью')}</span>`;

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
                            <button type="button" onclick="toggleTvBrandDomain('${escapeHtml(d.domain)}', ${!isBlocked})" class="px-3 py-1.5 rounded-lg text-xs font-medium transition whitespace-nowrap ${isBlocked ? 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700' : 'bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30'}">
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
    await fetch(`/api/devices/${mac}/toggle_dlna`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

async function toggleTvNight(mac, val) {
    await fetch(`/api/devices/${mac}/toggle_night`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val })
    });
    loadDevices();
}

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
                                    <td class="py-2.5 font-mono text-rose-400 font-bold">${r.ext_port}</td>
                                    <td class="py-2.5 font-mono text-slate-300">${r.int_ip}:${r.int_port}</td>
                                    <td class="py-2.5 uppercase font-mono">${r.protocol}</td>
                                    <td class="py-2.5 text-slate-400">${escapeHtml(r.description || 'N/A')}</td>
                                    <td class="py-2.5 text-right">
                                        <button onclick="deleteUpnp('${r.protocol}', ${r.ext_port})" class="px-2.5 py-1 text-[11px] rounded bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border border-rose-500/30">
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
                <button onclick="closeEventModal(); openDeviceModal('${e.target_mac}');" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20">
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
                    <span class="font-mono text-slate-300 font-medium">${culpritDisplay}</span>
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
                <button onclick="closeEventModal(); openDeviceModal('${e.target_mac}');" class="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center space-x-1.5 transition shadow-lg shadow-indigo-600/20">
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
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Порт:</span> <span class="font-mono font-bold text-white">${dt.port || 'Не указан'}</span></div>
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Сервис:</span> <span class="font-bold text-white">${escapeHtml(dt.service || '')}</span></div>
                    <div class="p-2 rounded bg-surface-900 border border-slate-800/80"><span class="text-slate-500 block text-[10px]">Протокол:</span> <span class="font-mono text-slate-300">${dt.protocol || 'TCP'}</span></div>
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
            <a href="/api/events/pcap/${e.pcap_file}" download class="px-3.5 py-2 rounded-xl bg-indigo-600/20 text-indigo-300 border border-indigo-500/30 hover:bg-indigo-600/30 text-xs font-medium flex items-center space-x-1.5 transition">
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
                <div onclick="openEventModal(${e.id || 0}, '${escapeHtml(e.timestamp)}')" class="p-3.5 rounded-xl bg-surface-950 border border-slate-800/80 hover:border-indigo-500/60 hover:bg-surface-900/90 transition flex items-start justify-between gap-3 text-xs cursor-pointer group shadow-sm">
                    <div class="space-y-1">
                        <div class="flex items-center space-x-2">
                            <span class="px-2 py-0.5 rounded font-medium border ${badgeColor}">${e.event_type.toUpperCase()}</span>
                            <span class="text-slate-500">${timeStr}</span>
                        </div>
                        <p class="text-slate-200 font-medium">${escapeHtml(e.description)}</p>
                    </div>
                    <div class="flex items-center space-x-2 shrink-0 self-center">
                        ${e.pcap_file ? `<a href="/api/events/pcap/${e.pcap_file}" download onclick="event.stopPropagation()" class="text-indigo-400 hover:underline shrink-0 px-2 py-1 bg-indigo-950/60 rounded border border-indigo-800/50">PCAP</a>` : ''}
                        <button onclick="openInvestigatorForEvent(${e.id || 0}, event)" class="p-1.5 rounded-lg bg-surface-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-800/50 transition" title="Расследовать инцидент в Wizard">
                            <i data-lucide="crosshair" class="w-3.5 h-3.5 text-rose-400"></i>
                        </button>
                        <button onclick="deleteEvent(${e.id || 0}, event)" class="p-1.5 rounded-lg bg-surface-900 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-800 hover:border-rose-800/50 transition" title="Удалить инцидент">
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
                <button onclick="openDomainModal('${escapeHtml(dom)}')" class="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 font-mono transition cursor-pointer" title="Нажмите для анализа и блокировки в Keenetic">
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
    const tabs = ['router', 'new-devices', 'cameras', 'telegram', 'tv-night', 'schedules', 'storage', 'presets', 'dns-security'];
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
    }

    try {
        localStorage.setItem('keenguard_settings_subtab', subtabId);
    } catch (e) {}
    if (window.lucide) lucide.createIcons();
}
window.switchSettingsSubTab = switchSettingsSubTab;

// Settings
async function loadSettings() {
    try {
        const res = await fetch('/api/settings');
        const s = await res.json();
        const hostEl = document.getElementById('cfg-host');
        if (hostEl && s.router_host !== undefined) hostEl.value = s.router_host;
        const userEl = document.getElementById('cfg-user');
        if (userEl && s.router_user !== undefined) userEl.value = s.router_user;
        const nightStartEl = document.getElementById('cfg-night-start');
        if (nightStartEl && s.night_mode_start_hour !== undefined) nightStartEl.value = s.night_mode_start_hour;
        const nightEndEl = document.getElementById('cfg-night-end');
        if (nightEndEl && s.night_mode_end_hour !== undefined) nightEndEl.value = s.night_mode_end_hour;

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
        router_host: document.getElementById('cfg-host')?.value?.trim() || undefined,
        router_user: document.getElementById('cfg-user')?.value?.trim() || undefined,
        router_password: passVal && passVal.trim() ? passVal.trim() : null,
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
        iot_payload_retention_days: document.getElementById('cfg-iot-retention-days') ? parseInt(document.getElementById('cfg-iot-retention-days').value || '7', 10) : undefined
    };

    const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (res.ok) {
        const data = await res.json();
        showToast('Все настройки успешно сохранены!');
        document.getElementById('cfg-password').value = '';
        await loadSettings();
        await refreshAllData();
    } else {
        const err = await res.json().catch(() => ({}));
        showToast(`Ошибка при сохранении: ${err.detail || res.statusText}`, true);
    }
}

// Granular Settings Handlers
async function saveRouterSettings() {
    const host = document.getElementById('cfg-host')?.value?.trim();
    const user = document.getElementById('cfg-user')?.value?.trim();
    const pass = document.getElementById('cfg-password')?.value;

    if (!host || !user) {
        showToast('Укажите IP-адрес роутера и имя пользователя', true);
        return;
    }

    const payload = {
        router_host: host,
        router_user: user
    };
    if (pass && pass.trim()) {
        payload.router_password = pass.trim();
    }

    try {
        const res = await fetch('/api/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Настройки подключения к Keenetic сохранены');
            const passEl = document.getElementById('cfg-password');
            if (passEl) passEl.value = '';
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

async function testKeeneticConnection() {
    const host = document.getElementById('cfg-host').value.trim();
    const user = document.getElementById('cfg-user').value.trim();
    const password = document.getElementById('cfg-password').value.trim();

    try {
        const res = await fetch('/api/test_connection', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ router_host: host, router_user: user, router_password: password || null })
        });
        const data = await res.json();
        if (data.status === 'ok') {
            alert(`Связь с Keenetic успешна!\nМодель: ${data.model}\nВерсия: ${data.version}\n\nПароль сохранен в системе и роутер подключен.`);
            document.getElementById('cfg-password').value = '';
            await loadSettings();
            await refreshAllData();
        } else {
            alert(`Ошибка связи с роутером:\n${data.message || 'Проверьте логин, пароль или IP'}`);
        }
    } catch (e) {
        alert(`Ошибка связи с сервером: ${e}`);
    }
}

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

// Wi-Fi Security Audit
async function loadWifiAudit() {
    try {
        const res = await fetch('/api/security/wifi');
        const data = await res.json();

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
        if (netList) {
            if (data.access_points && data.access_points.length > 0) {
                netList.innerHTML = data.access_points.map(ap => {
                    const isWpa3 = ap.security && ap.security.includes('WPA3');
                    const isOpen = ap.security && (ap.security.includes('Открытая') || ap.security_type === 'open');

                    let badgeClass = 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
                    let iconName = 'shield-check';

                    if (isOpen) {
                        badgeClass = 'bg-rose-500/20 text-rose-300 border-rose-500/40 animate-pulse';
                        iconName = 'shield-alert';
                    } else if (!isWpa3) {
                        badgeClass = 'bg-sky-500/15 text-sky-300 border-sky-500/30';
                        iconName = 'shield';
                    }

                    const bandText = ap.band || (ap.interface && ap.interface.includes('WifiMaster1') ? '5 ГГц' : '2.4 ГГц');

                    return `
                        <div class="flex items-center justify-between bg-surface-950/70 border border-slate-800/70 rounded-xl px-3 py-2 transition hover:border-slate-700">
                            <div class="flex items-center space-x-2.5 min-w-0">
                                <div class="w-2 h-2 rounded-full ${isOpen ? 'bg-rose-500 animate-ping' : 'bg-emerald-400'} shrink-0"></div>
                                <div class="min-w-0">
                                    <div class="flex items-center space-x-1.5">
                                        <span class="font-semibold text-xs text-white truncate max-w-[130px] sm:max-w-[160px]">${escapeHtml(ap.ssid)}</span>
                                        <span class="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800/90 text-slate-400 shrink-0">${bandText}</span>
                                    </div>
                                </div>
                            </div>
                            <div class="shrink-0 ml-2">
                                <span class="inline-flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-0.5 rounded-lg border ${badgeClass}">
                                    <i data-lucide="${iconName}" class="w-3 h-3"></i>
                                    <span>${escapeHtml(ap.security)}</span>
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

        // 4. Recommendation Box
        const recElem = document.getElementById('wifi-recommendations');
        const recIcon = document.getElementById('wifi-rec-icon');
        if (recElem && data.recommendations && data.recommendations.length > 0) {
            recElem.textContent = data.recommendations[0];
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

        if (ver) ver.textContent = data.current_version;
        if (channel) channel.textContent = data.channel;

        if (data.has_update) {
            if (badge) {
                badge.textContent = 'Доступно обновление!';
                badge.className = 'px-2 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30 animate-pulse';
            }
            if (msg) msg.textContent = `Доступна KeeneticOS ${data.latest_version}`;
        } else {
            if (badge) {
                badge.textContent = 'Актуальна';
                badge.className = 'px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
            }
            if (msg) msg.textContent = 'Патчи безопасности актуальны';
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
        const data = await res.json();

        const labels = data.map(d => new Date(d.timestamp).toLocaleTimeString());
        const rxData = data.map(d => Math.round(d.total_rx_kbps || 0));
        const txData = data.map(d => Math.round(d.total_tx_kbps || 0));

        if (data.length > 0) {
            const latest = data[data.length - 1];
            const rxElem = document.getElementById('live-rx-rate');
            const txElem = document.getElementById('live-tx-rate');
            if (rxElem) rxElem.textContent = Math.round(latest.total_rx_kbps || 0);
            if (txElem) txElem.textContent = Math.round(latest.total_tx_kbps || 0);
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
                            fill: true
                        },
                        {
                            label: 'Исходящий (Kbps)',
                            data: txData,
                            borderColor: '#38bdf8',
                            backgroundColor: 'rgba(56, 189, 248, 0.1)',
                            borderWidth: 2,
                            tension: 0.35,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { display: false },
                        y: {
                            display: true,
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            ticks: { color: '#64748b', font: { size: 9 } }
                        }
                    }
                }
            });
        }
    } catch (e) {
        console.error('Error updating live traffic chart', e);
    }
}

// Device Traffic Chart
async function loadDeviceTrafficChart(mac) {
    const ctx = document.getElementById('device-traffic-chart');
    if (!ctx || typeof Chart === 'undefined') return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(mac)}/traffic?limit=30`);
        if (!res.ok) return;
        const rawHistory = await res.json();
        const history = Array.isArray(rawHistory) ? rawHistory : [];

        const labels = history.map(h => new Date(h.timestamp).toLocaleTimeString());
        const rxData = history.map(h => h.rx_rate_kbps || 0);
        const txData = history.map(h => h.tx_rate_kbps || 0);

        if (history.length > 0) {
            const latest = history[history.length - 1];
            const rateElem = document.getElementById('modal-traffic-rate-now');
            if (rateElem) {
                rateElem.textContent = `↓ ${latest.rx_rate_kbps || 0} Kbps  ↑ ${latest.tx_rate_kbps || 0} Kbps`;
            }
        }

        if (deviceTrafficChart) {
            deviceTrafficChart.destroy();
        }

        deviceTrafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels.length ? labels : ['0 сек'],
                datasets: [
                    {
                        label: 'Входящий (Rx)',
                        data: rxData.length ? rxData : [0],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        borderWidth: 1.5,
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Исходящий (Tx)',
                        data: txData.length ? txData : [0],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        borderWidth: 1.5,
                        tension: 0.3,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { display: false },
                    y: {
                        display: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 9 } }
                    }
                }
            }
        });
    } catch (e) {
        console.error('Error loading device traffic chart', e);
    }
}

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
        document.getElementById('domain-modal-vendor').textContent = analysis.vendor || 'Неизвестный вендор';
        document.getElementById('domain-modal-description').textContent = analysis.description || analysis.recommendation || 'Описание недоступно.';
        document.getElementById('domain-modal-keenetic-tip').textContent = analysis.keenetic_tip || 'Рекомендаций по блокировке нет.';

        // Category & Risk badges
        const catBadge = document.getElementById('domain-modal-category-badge');
        if (catBadge) catBadge.textContent = analysis.category_name || 'Категория';

        const riskBadge = document.getElementById('domain-modal-risk-badge');
        if (riskBadge) riskBadge.textContent = analysis.badge_text || 'Статус';

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

// Data Export
function exportData(type, format) {
    window.location.href = `/api/export/${type}?format=${format}`;
}

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
        if (devElem) devElem.textContent = `${data.online_devices ?? 0} / ${data.total_devices ?? 0}`;
        const critElem = document.getElementById('digest-crit-cnt');
        if (critElem) critElem.textContent = data.critical_count ?? 0;
        const warnElem = document.getElementById('digest-warn-cnt');
        if (warnElem) warnElem.textContent = data.warning_count ?? 0;
        const infoElem = document.getElementById('digest-info-cnt');
        if (infoElem) infoElem.textContent = data.info_count ?? 0;

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
                hubMeta.textContent = `IP: ${data.hub.ip || '—'} | MAC: ${data.hub.mac} | Производитель: ${data.hub.vendor || 'SprutHub'}`;
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
        await loadSmartHome();
    } catch (e) {
        console.error('Error toggling LAN for smart home device', e);
        alert(`Ошибка переключения LAN: ${e.message}`);
    }
}

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
                    <button onclick="toggleChecklistTvNight('${act.mac}', ${act.target_enable})"
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
                                                ? `<button onclick="toggleChecklistDeviceDirect('${dev.mac}', 'wan', false)" class="px-2.5 py-1 rounded-lg text-[10px] font-medium bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 inline-flex items-center space-x-1 transition" title="Интернет заблокирован. Нажмите, чтобы разрешить выход">
                                                     <i data-lucide="shield-off" class="w-3 h-3"></i><span>Блок WAN</span>
                                                   </button>`
                                                : `<button onclick="toggleChecklistDeviceDirect('${dev.mac}', 'wan', true)" class="px-2.5 py-1 rounded-lg text-[10px] font-medium bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 inline-flex items-center space-x-1 transition" title="Интернет разрешен. Нажмите, чтобы заблокировать">
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
                                    <div class="text-[10px] font-mono text-slate-400">${c.ip} • ${c.mac}</div>
                                </div>
                                <div class="flex items-center space-x-1.5">
                                    <button onclick="toggleChecklistDeviceDirect('${c.mac}', 'wan', ${!c.is_blocked_wan})" class="px-2 py-1 rounded text-[10px] font-medium transition ${c.is_blocked_wan ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}" title="Блокировать/разрешить интернет для камеры">
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
                                    <div class="text-[10px] font-mono text-slate-400">${t.ip} • ${t.mac}</div>
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
                                    <button onclick="toggleChecklistTvNight('${t.mac}', ${!t.night_mode_enabled})" class="px-2.5 py-1 rounded text-[10px] font-medium transition ${t.night_mode_enabled ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700 border border-slate-700'}">
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
                                            <div class="text-[10px] font-mono text-slate-400">${qd.ip} • ${qd.mac}</div>
                                            <div class="text-[9px] text-slate-500">Домены: ${qd.observed_domains && qd.observed_domains.length > 0 ? escapeHtml(qd.observed_domains.join(', ')) : 'DNS-запросов нет'}</div>
                                        </div>
                                        <div class="flex items-center space-x-1">
                                            <button onclick="openDeviceModal('${qd.mac}')" class="px-2 py-1 rounded bg-indigo-600/20 text-indigo-300 text-[10px] hover:bg-indigo-600/30 transition">
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

async function startNetworkAuditQuick(scope = 'all', duration = 0) {
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
                                    ${devIp} &bull; ${session.mac} ${session.vendor ? `&bull; ${escapeHtml(session.vendor)}` : ''}
                                </div>
                            </div>
                        </div>
                        <div class="flex items-center space-x-2 shrink-0">
                            <button onclick="stopTrafficAuditFromTab('${session.mac}')" class="px-3.5 py-1.5 rounded-xl bg-rose-600/90 hover:bg-rose-600 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-sm">
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
            <a href="/api/audit/pcap/${r.pcap_file}" download title="Скачать .PCAP файл" class="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 transition border border-slate-700 inline-flex items-center">
                <i data-lucide="download" class="w-3.5 h-3.5"></i>
            </a>
        ` : '';

        const isNet = r.is_network || r.mac === 'NETWORK';
        const hostHtml = isNet ?
            `<div class="font-medium text-cyan-300 flex items-center space-x-1.5"><i data-lucide="radio" class="w-3.5 h-3.5 text-cyan-400"></i><span>${escapeHtml(r.hostname || 'Сводный аудит сети')}</span></div>
             <div class="text-[11px] text-slate-400 font-mono mt-0.5">Охват: ${escapeHtml(r.scope || 'вся сеть')} &bull; Хостов: ${r.devices_analyzed || (r.top_devices ? r.top_devices.length : 0)}</div>` :
            `<div class="font-medium text-slate-200">${escapeHtml(r.hostname || 'Без имени')}</div>
             <div class="text-[11px] text-slate-400 font-mono mt-0.5">${r.ip || ''} (${r.mac})</div>`;

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
                        <button onclick="openInvestigatorForAudit('${r.id}')" class="px-2.5 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 hover:text-rose-200 border border-rose-500/30 text-xs font-medium transition flex items-center space-x-1" title="Интерактивное расследование инцидента (Wizard)">
                            <i data-lucide="crosshair" class="w-3.5 h-3.5 text-rose-400"></i>
                            <span>Расследовать</span>
                        </button>
                        <button onclick="openAuditReportById('${r.id}')" class="px-2.5 py-1.5 rounded-lg bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 hover:text-indigo-200 border border-indigo-500/30 text-xs font-medium transition flex items-center space-x-1">
                            <i data-lucide="eye" class="w-3.5 h-3.5"></i>
                            <span>Отчет</span>
                        </button>
                        ${pcapBtn}
                        <button onclick="deleteAuditReport('${r.id}', event)" class="p-1.5 rounded-lg bg-slate-800 hover:bg-rose-950/60 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-800/50 transition inline-flex items-center" title="Удалить отчет">
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
                <button onclick="openDomainModal('${escapeHtml(dom)}')" class="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-cyan-200 border border-slate-700 hover:border-cyan-500/50 font-mono transition cursor-pointer group shadow-sm" title="Нажмите для анализа репутации и инструкции по блокировке">
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
            <a href="/api/audit/pcap/${pcapFile}" download class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-md shadow-cyan-600/20">
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

        return `
            <tr class="hover:bg-slate-900/50">
                <td class="py-2 px-3 font-mono text-slate-200">${fl.dst_ip}:${fl.dst_port}</td>
                <td class="py-2 px-3 text-slate-300">${escapeHtml(fl.service || fl.protocol || 'TCP')}</td>
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
                            <span class="text-slate-400 font-mono text-[11px]">${q.ip || 'no-ip'} &bull; ${q.mac}</span>
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
                            <div class="text-[11px] text-slate-400 font-mono">${d.ip || ''} &bull; ${d.mac}</div>
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
                <a href="/api/audit/pcap/${encodeURIComponent(pcapFile)}" download class="px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition flex items-center space-x-1.5 shadow-md shadow-cyan-600/20">
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

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showToast(msg, isError = false) {
    let container = document.getElementById('kg-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'kg-toast-container';
        container.className = 'fixed bottom-5 right-5 z-[9999] flex flex-col space-y-2 pointer-events-none';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `px-4 py-2.5 rounded-xl text-xs font-medium shadow-xl transition-all duration-300 transform translate-y-2 opacity-0 pointer-events-auto flex items-center space-x-2 border ${
        isError ? 'bg-rose-950/90 text-rose-200 border-rose-500/50' : 'bg-slate-900/95 text-slate-100 border-indigo-500/40'
    }`;
    toast.innerHTML = `<span>${escapeHtml(msg)}</span>`;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.classList.remove('translate-y-2', 'opacity-0');
    });
    setTimeout(() => {
        toast.classList.add('opacity-0', 'translate-y-2');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
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
                feedback.innerHTML = `<i data-lucide="check-circle" class="w-4 h-4 shrink-0 text-emerald-400"></i><span>${data.message || 'Политики успешно применены!'} Обновлено устройств: TV=${data.tv_updated_count}, Сенсоров=${data.sensors_blocked_count}.</span>`;
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
            feedback.innerHTML = `<i data-lucide="alert-triangle" class="w-4 h-4 shrink-0 text-rose-400"></i><span>Ошибка: ${e.message}</span>`;
            feedback.classList.remove('hidden');
            if (window.lucide) lucide.createIcons();
        }
        if (nextBtn) {
            nextBtn.disabled = false;
            nextBtn.innerHTML = '<span>Попробовать снова</span>';
        }
    }
}

// ==========================================
// 11. LAN COMMUNICATIONS & PING MONITOR
// ==========================================

let currentLanView = 'log';
let lanLiveInterval = null;
let lanSearchDebounceTimer = null;

function switchLanView(view) {
    currentLanView = view;
    const logBtn = document.getElementById('lan-view-log-btn');
    const matrixBtn = document.getElementById('lan-view-matrix-btn');
    const topoBtn = document.getElementById('lan-view-topo-btn');

    const subLog = document.getElementById('lan-subview-log');
    const subMatrix = document.getElementById('lan-subview-matrix');
    const subTopo = document.getElementById('lan-subview-topo');

    // Reset styles
    [logBtn, matrixBtn, topoBtn].forEach(b => {
        if (b) {
            b.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 transition flex items-center space-x-1.5';
        }
    });

    const activeCls = 'px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 flex items-center space-x-1.5 transition';

    if (view === 'log') {
        if (logBtn) logBtn.className = activeCls;
        if (subLog) subLog.classList.remove('hidden');
        if (subMatrix) subMatrix.classList.add('hidden');
        if (subTopo) subTopo.classList.add('hidden');
        loadLanCommunications();
    } else if (view === 'matrix') {
        if (matrixBtn) matrixBtn.className = activeCls;
        if (subLog) subLog.classList.add('hidden');
        if (subMatrix) subMatrix.classList.remove('hidden');
        if (subTopo) subTopo.classList.add('hidden');
        loadLanPingMatrix();
    } else if (view === 'topo') {
        if (topoBtn) topoBtn.className = activeCls;
        if (subLog) subLog.classList.add('hidden');
        if (subMatrix) subMatrix.classList.add('hidden');
        if (subTopo) subTopo.classList.remove('hidden');
        loadLanTopology();
    }

    if (window.lucide) lucide.createIcons();
}

async function loadLanTab() {
    try {
        await loadLanStats();
        if (currentLanView === 'log') {
            await loadLanCommunications();
        } else if (currentLanView === 'matrix') {
            await loadLanPingMatrix();
        } else if (currentLanView === 'topo') {
            await loadLanTopology();
        }
    } catch (err) {
        console.error('Error loading LAN tab data:', err);
    }
}

async function loadLanStats() {
    try {
        const res = await fetch('/api/lan/stats');
        if (!res.ok) return;
        const data = await res.json();
        const s = data.stats || {};

        const pingsEl = document.getElementById('lan-stat-pings');
        const flowsEl = document.getElementById('lan-stat-flows');
        const arpEl = document.getElementById('lan-stat-arp');
        const chatterEl = document.getElementById('lan-stat-chatter');
        const chatterPktsEl = document.getElementById('lan-stat-chatter-pkts');
        const badgeEl = document.getElementById('lan-count-badge');

        if (pingsEl) pingsEl.textContent = (s.ping_requests_count || 0) + (s.ping_replies_count || 0);
        if (flowsEl) flowsEl.textContent = s.active_flows_count || 0;
        if (arpEl) arpEl.textContent = s.arp_queries_count || 0;

        if (s.top_communicating_pair) {
            const pair = s.top_communicating_pair;
            if (chatterEl) chatterEl.textContent = `${pair.src} <-> ${pair.dst}`;
            if (chatterPktsEl) chatterPktsEl.textContent = `${pair.packets || 0} пакетов (${pair.last_protocol || 'LAN'})`;
        } else {
            if (chatterEl) chatterEl.textContent = 'Нет активных пар';
            if (chatterPktsEl) chatterPktsEl.textContent = '0 пакетов';
        }

        const totalEvts = (s.ping_requests_count || 0) + (s.arp_queries_count || 0) + (s.active_flows_count || 0);
        if (badgeEl) {
            badgeEl.textContent = totalEvts;
            if (totalEvts > 0) badgeEl.classList.remove('hidden');
            else badgeEl.classList.add('hidden');
        }
    } catch (e) {
        console.error('Error in loadLanStats:', e);
    }
}

async function loadLanCommunications() {
    const body = document.getElementById('lan-events-body');
    if (!body) return;

    if (!devicesList || devicesList.length === 0) {
        await loadDevices();
    }

    try {
        const typeSelect = document.getElementById('lan-filter-type');
        const typeFilter = typeSelect ? typeSelect.value : 'all';

        let url = '/api/lan/communications?limit=150';
        if (typeFilter && typeFilter !== 'all') {
            url += `&comm_type=${encodeURIComponent(typeFilter)}`;
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const comms = data.communications || [];

        comms.forEach(c => {
            if (c.src_ip && c.src_name && !isIpAddress(c.src_name)) deviceNameCache.registerMapping(c.src_ip, c.src_mac, c.src_name);
            if (c.dst_ip && c.dst_name && !isIpAddress(c.dst_name)) deviceNameCache.registerMapping(c.dst_ip, c.dst_mac, c.dst_name);
        });

        const searchInput = document.getElementById('lan-filter-search');
        const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
        const mode = getDeviceDisplayMode();
        const hideRouter = getFilterPref('hideRouter');
        const hideHub = getFilterPref('hideHub');

        const filtered = comms.filter(c => {
            if (hideRouter && isRouterEntity(c.src_ip, c.src_mac)) return false;
            if (hideHub && isHubEntity(c.src_ip, c.src_mac)) return false;
            if (!query) return true;
            const srcLabel = formatDeviceIdentifier(c.src_ip, c.src_mac, 'both', c.src_name).toLowerCase();
            const dstLabel = formatDeviceIdentifier(c.dst_ip, c.dst_mac, 'both', c.dst_name).toLowerCase();
            return (
                (c.src_ip && c.src_ip.toLowerCase().includes(query)) ||
                (c.dst_ip && c.dst_ip.toLowerCase().includes(query)) ||
                (c.src_name && c.src_name.toLowerCase().includes(query)) ||
                (c.dst_name && c.dst_name.toLowerCase().includes(query)) ||
                srcLabel.includes(query) ||
                dstLabel.includes(query) ||
                (c.protocol && c.protocol.toLowerCase().includes(query)) ||
                (c.summary && c.summary.toLowerCase().includes(query))
            );
        });

        if (filtered.length === 0) {
            body.innerHTML = `
                <tr>
                    <td colspan="8" class="py-8 text-center text-slate-500 font-sans">
                        ${query ? 'По вашему фильтру ничего не найдено.' : 'Пока нет перехваченных коммуникаций в локальной сети.'}
                    </td>
                </tr>
            `;
            return;
        }

        body.innerHTML = filtered.map(item => {
            const timeStr = formatHumanTime(item.timestamp);
            const fullTime = formatHumanFullDateTime(item.timestamp);

            let protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 font-mono">${escapeHtml(item.protocol || 'IP')}</span>`;
            if (item.protocol === 'ICMP') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono">ICMP</span>`;
            } else if (item.protocol === 'ARP') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">ARP</span>`;
            } else if (item.protocol === 'MQTT') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">MQTT</span>`;
            } else if (item.protocol === 'HTTP') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">HTTP</span>`;
            } else if (item.protocol === 'DNS' || item.protocol === 'MDNS') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/30 font-mono">${escapeHtml(item.protocol)}</span>`;
            }

            let statusBadge = `<span class="text-[10px] text-slate-400 font-mono">${item.status || 'flow'}</span>`;
            if (item.status === 'replied') {
                const rtt = item.rtt_ms !== undefined && item.rtt_ms !== null ? `${item.rtt_ms} ms` : 'OK';
                statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">✓ ${rtt}</span>`;
            } else if (item.status === 'waiting') {
                statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20 font-mono animate-pulse">⏳ Ожидание</span>`;
            } else if (item.status === 'timeout') {
                statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20 font-mono">✕ Таймаут</span>`;
            }

            const pktAction = item.packet_id
                ? `<button onclick="openPacketInspectorModal('${escapeHtml(item.packet_id)}')" class="px-2 py-1 rounded-lg text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-white transition border border-slate-700 flex items-center space-x-1 float-right">
                    <i data-lucide="binary" class="w-3 h-3"></i>
                    <span>Пакет #${item.packet_id}</span>
                   </button>`
                : `<span class="text-slate-600 text-[11px]">—</span>`;

            return `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px]" title="${escapeHtml(fullTime)}">${escapeHtml(timeStr)}</td>
                    <td class="py-2.5 px-3">
                        ${renderDeviceCell(item.src_ip, item.src_mac, item.src_name, mode)}
                    </td>
                    <td class="py-2.5 px-1 text-center text-slate-600 font-mono">→</td>
                    <td class="py-2.5 px-3">
                        ${renderDeviceCell(item.dst_ip, item.dst_mac, item.dst_name, mode)}
                    </td>
                    <td class="py-2.5 px-3">${protoBadge}</td>
                    <td class="py-2.5 px-3 text-slate-300 text-xs break-all max-w-[280px]">
                        ${escapeHtml(item.summary || '—')}
                    </td>
                    <td class="py-2.5 px-3 text-center">${statusBadge}</td>
                    <td class="py-2.5 px-3 text-right">${pktAction}</td>
                </tr>
            `;
        }).join('');

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error loading LAN communications:', e);
        body.innerHTML = `
            <tr>
                <td colspan="8" class="py-8 text-center text-rose-400 font-sans">
                    Ошибка загрузки данных LAN: ${escapeHtml(e.message)}
                </td>
            </tr>
        `;
    }
}

async function loadLanPingMatrix() {
    const body = document.getElementById('lan-ping-matrix-body');
    if (!body) return;

    if (!devicesList || devicesList.length === 0) {
        await loadDevices();
    }

    try {
        const res = await fetch('/api/lan/ping_matrix');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const pairs = data.ping_matrix || [];

        pairs.forEach(m => {
            if (m.src_ip && m.src_name) deviceNameCache.registerMapping(m.src_ip, null, m.src_name);
            if (m.dst_ip && m.dst_name) deviceNameCache.registerMapping(m.dst_ip, null, m.dst_name);
        });

        const mode = getDeviceDisplayMode();

        if (pairs.length === 0) {
            body.innerHTML = `
                <tr>
                    <td colspan="9" class="py-8 text-center text-slate-500 font-sans">
                        Пока нет зарегистрированных пар пинг-мониторинга в сети.
                    </td>
                </tr>
            `;
            return;
        }

        body.innerHTML = pairs.map(m => {
            const successRate = m.success_rate !== undefined ? m.success_rate : 100.0;
            let rateBadge = `<span class="text-emerald-400 font-mono font-bold">${successRate}%</span>`;
            if (successRate < 95 && successRate >= 50) rateBadge = `<span class="text-amber-400 font-bold">${successRate}%</span>`;
            if (successRate < 50) rateBadge = `<span class="text-rose-400 font-bold">${successRate}%</span>`;

            let rttStr = '—';
            if (m.rtt_min_ms !== undefined && m.rtt_avg_ms !== undefined && m.rtt_max_ms !== undefined) {
                rttStr = `${m.rtt_min_ms} / <span class="font-bold text-cyan-300">${m.rtt_avg_ms}</span> / ${m.rtt_max_ms} ms`;
            }

            let statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">ОТЛИЧНО</span>`;
            if (m.status === 'DEGRADED') {
                statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">ПОТЕРИ</span>`;
            } else if (m.status === 'TIMEOUT' || successRate === 0) {
                statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">НЕТ ОТВЕТА</span>`;
            }

            const lastSeen = formatHumanTime(m.last_seen);
            const fullLastSeen = formatHumanFullDateTime(m.last_seen);

            return `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-2.5 px-3">
                        ${renderDeviceCell(m.src_ip, null, m.src_name, mode)}
                    </td>
                    <td class="py-2.5 px-3">
                        ${renderDeviceCell(m.dst_ip, null, m.dst_name, mode)}
                    </td>
                    <td class="py-2.5 px-3 text-center font-mono">${m.sent_count || 0}</td>
                    <td class="py-2.5 px-3 text-center font-mono text-emerald-400">${m.reply_count || 0}</td>
                    <td class="py-2.5 px-3 text-center font-mono text-rose-400">${m.loss_count || 0}</td>
                    <td class="py-2.5 px-3 text-center font-mono">${rateBadge}</td>
                    <td class="py-2.5 px-3 text-center font-mono text-slate-300">${rttStr}</td>
                    <td class="py-2.5 px-3 text-center">${statusBadge}</td>
                    <td class="py-2.5 px-3 text-right text-slate-400 font-mono text-[11px]" title="${escapeHtml(fullLastSeen)}">${escapeHtml(lastSeen)}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error('Error loading ping matrix:', e);
    }
}

async function loadLanTopology() {
    const container = document.getElementById('lan-topo-container');
    const countEl = document.getElementById('lan-topo-count');
    if (!container) return;

    if (!devicesList || devicesList.length === 0) {
        await loadDevices();
    }

    try {
        const res = await fetch('/api/lan/topology');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const edges = data.edges || data.links || [];
        const nodes = data.nodes || [];
        const mode = getDeviceDisplayMode();

        const nodesMap = new Map();
        nodes.forEach(n => {
            if (n.id) nodesMap.set(n.id, n);
            if (n.id && n.label) deviceNameCache.registerMapping(n.id, n.mac, n.label);
        });
        edges.forEach(e => {
            const sIp = e.src_ip || e.source;
            const dIp = e.dst_ip || e.target;
            const sName = e.src_name || nodesMap.get(sIp)?.label;
            const dName = e.dst_name || nodesMap.get(dIp)?.label;
            if (sIp && sName) deviceNameCache.registerMapping(sIp, e.src_mac || nodesMap.get(sIp)?.mac, sName);
            if (dIp && dName) deviceNameCache.registerMapping(dIp, e.dst_mac || nodesMap.get(dIp)?.mac, dName);
        });

        const hideRouter = getFilterPref('hideRouter');
        const hideHub = getFilterPref('hideHub');
        const typeSelect = document.getElementById('lan-filter-type');
        const typeFilter = typeSelect ? typeSelect.value : 'all';
        const searchInput = document.getElementById('lan-filter-search');
        const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

        const filteredEdges = edges.filter(edge => {
            const srcIp = edge.src_ip || edge.source;
            const dstIp = edge.dst_ip || edge.target;
            const srcNode = nodesMap.get(srcIp) || {};
            const dstNode = nodesMap.get(dstIp) || {};
            const srcMac = edge.src_mac || srcNode.mac;
            const dstMac = edge.dst_mac || dstNode.mac;

            // Router & Hub source filters (only hide when they are the source/initiator)
            if (hideRouter && isRouterEntity(srcIp, srcMac)) return false;
            if (hideHub && isHubEntity(srcIp, srcMac)) return false;

            // Protocol type filter
            const protos = edge.protocols || [];
            const protosLower = protos.map(p => String(p).toLowerCase());
            if (typeFilter === 'ping') {
                if (!protosLower.some(p => p.includes('icmp') || p.includes('ping'))) return false;
            } else if (typeFilter === 'arp') {
                if (!protosLower.some(p => p.includes('arp'))) return false;
            } else if (typeFilter === 'flows') {
                const hasFlow = protosLower.some(p => !p.includes('icmp') && !p.includes('arp'));
                if (!hasFlow && protosLower.length > 0) return false;
            }

            // Text search query
            if (query) {
                const srcName = edge.src_name || srcNode.label || '';
                const dstName = edge.dst_name || dstNode.label || '';
                const srcLabel = formatDeviceIdentifier(srcIp, srcMac, 'both', srcName).toLowerCase();
                const dstLabel = formatDeviceIdentifier(dstIp, dstMac, 'both', dstName).toLowerCase();
                const protosStr = protos.join(' ').toLowerCase();
                const match = (srcIp && srcIp.toLowerCase().includes(query)) ||
                              (dstIp && dstIp.toLowerCase().includes(query)) ||
                              srcLabel.includes(query) ||
                              dstLabel.includes(query) ||
                              protosStr.includes(query);
                if (!match) return false;
            }

            return true;
        });

        // Compute unique nodes among filtered edges
        const uniqueNodes = new Set();
        filteredEdges.forEach(e => {
            const s = e.src_ip || e.source;
            const d = e.dst_ip || e.target;
            if (s) uniqueNodes.add(s);
            if (d) uniqueNodes.add(d);
        });

        if (countEl) countEl.textContent = `${filteredEdges.length} связей (${uniqueNodes.size} устройств)`;

        if (filteredEdges.length === 0) {
            container.innerHTML = `
                <div class="col-span-full py-12 text-center text-slate-500 font-sans">
                    ${edges.length === 0 ? 'Пока не зафиксировано локальных связей между хостами.' : 'Нет связей, соответствующих выбранным фильтрам.'}
                </div>
            `;
            return;
        }

        container.innerHTML = filteredEdges.map(edge => {
            const srcIp = edge.src_ip || edge.source;
            const dstIp = edge.dst_ip || edge.target;
            const srcNode = nodesMap.get(srcIp) || {};
            const dstNode = nodesMap.get(dstIp) || {};
            const srcMac = edge.src_mac || srcNode.mac;
            const dstMac = edge.dst_mac || dstNode.mac;
            const srcName = edge.src_name || srcNode.label;
            const dstName = edge.dst_name || dstNode.label;
            const packets = edge.packet_count ?? edge.packets ?? 0;

            const protos = edge.protocols && edge.protocols.length > 0 ? edge.protocols.join(', ') : 'IP';
            const srcLabel = formatDeviceIdentifier(srcIp, srcMac, mode, srcName);
            const dstLabel = formatDeviceIdentifier(dstIp, dstMac, mode, dstName);

            return `
                <div class="bg-surface-950 border border-slate-800 rounded-xl p-3.5 space-y-2 hover:border-cyan-500/40 transition shadow-sm">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-1.5 font-mono text-xs font-semibold text-slate-200">
                            <span class="text-cyan-400 truncate max-w-[130px]" title="${escapeHtml(srcLabel)}">${escapeHtml(srcLabel)}</span>
                            <span class="text-slate-500">⇄</span>
                            <span class="text-indigo-400 truncate max-w-[130px]" title="${escapeHtml(dstLabel)}">${escapeHtml(dstLabel)}</span>
                        </div>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 font-semibold">${packets} пак.</span>
                    </div>
                    <div class="flex items-center justify-between text-[11px] text-slate-400">
                        <span>Протоколы: <span class="text-slate-300 font-medium">${escapeHtml(protos)}</span></span>
                        <span class="font-mono text-cyan-300">${edge.rtt_avg_ms ? edge.rtt_avg_ms + ' ms' : ''}</span>
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        console.error('Error loading LAN topology:', e);
    }
}

async function clearLanEvents() {
    if (!confirm('Вы действительно хотите очистить журнал локальных коммуникаций и матрицу пингов?')) return;
    try {
        const res = await fetch('/api/lan/clear', { method: 'POST' });
        if (res.ok) {
            showToast('Журнал локальных коммуникаций очищен', 'info');
            await loadLanTab();
        }
    } catch (e) {
        showToast('Ошибка при очистке: ' + e.message, 'error');
    }
}

function toggleLanLive(enabled) {
    if (lanLiveInterval) {
        clearInterval(lanLiveInterval);
        lanLiveInterval = null;
    }
    if (enabled) {
        lanLiveInterval = setInterval(() => {
            if (activeTab === 'lan') loadLanTab();
        }, 2000);
    }
}

function handleLanFilterChange() {
    if (currentLanView === 'topo') {
        loadLanTopology();
    } else if (currentLanView === 'matrix') {
        loadLanPingMatrix();
    } else {
        loadLanCommunications();
    }
}

function debounceLanSearch() {
    if (lanSearchDebounceTimer) clearTimeout(lanSearchDebounceTimer);
    lanSearchDebounceTimer = setTimeout(() => {
        if (currentLanView === 'topo') {
            loadLanTopology();
        } else {
            loadLanCommunications();
        }
    }, 250);
}

// ==========================================
// 12. IOT PAYLOAD FORENSICS & STORAGE
// ==========================================

let iotSearchDebounceTimer = null;

async function loadIotPayloads() {
    const body = document.getElementById('sh-iot-payload-body');
    if (!body) return;

    try {
        await ensureIotDeviceSelect();

        const devSelect = document.getElementById('sh-iot-device-select');
        const selectedDev = devSelect ? devSelect.value : '';

        const protoSelect = document.getElementById('sh-iot-proto-select');
        const selectedProto = protoSelect ? protoSelect.value : 'all';

        let url = selectedDev
            ? `/api/devices/${encodeURIComponent(selectedDev)}/payloads?limit=100`
            : '/api/iot/payloads?limit=100';

        if (selectedProto && selectedProto !== 'all') {
            url += `&protocol=${encodeURIComponent(selectedProto)}`;
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const payloads = data.payloads || [];

        // 1. Update Storage and Packet Count Badges
        if (data.storage) {
            const countBadge = document.getElementById('sh-iot-count-badge');
            const storageBadge = document.getElementById('sh-iot-storage-badge');
            const count = data.storage.count ?? data.storage.total_records ?? payloads.length;
            const totalMb = data.storage.total_mb ?? data.storage.payload_mb ?? 0;
            const maxGb = data.storage.max_storage_gb ?? 1.0;

            if (countBadge) {
                countBadge.textContent = `${Number(count).toLocaleString()} пакетов`;
            }
            if (storageBadge) {
                storageBadge.textContent = `${Number(totalMb).toFixed(1)} МБ / ${maxGb} ГБ`;
            }
            const shToggle = document.getElementById('sh-iot-capture-toggle');
            if (shToggle && data.storage.capture_enabled !== undefined) {
                shToggle.checked = Boolean(data.storage.capture_enabled);
            }
        }

        const searchInput = document.getElementById('sh-iot-search-input');
        const query = searchInput ? searchInput.value.trim().toLowerCase() : '';
        const hideRouter = getFilterPref('hideRouter');
        const hideHub = getFilterPref('hideHub');
        const isIpv6Address = (ip) => Boolean(ip && typeof ip === 'string' && ip.includes(':'));

        const filtered = payloads.filter(p => {
            if (hideRouter && (isRouterEntity(p.ip, p.mac) || isRouterEntity(p.src_ip, p.mac) || isRouterEntity(p.dst_ip, null))) return false;
            if (hideHub && (isHubEntity(p.ip, p.mac) || isHubEntity(p.src_ip, p.mac) || isHubEntity(p.dst_ip, null))) return false;
            if (!query) return true;
            return (
                (p.mac && p.mac.toLowerCase().includes(query)) ||
                (p.hostname && p.hostname.toLowerCase().includes(query)) ||
                (p.device_name && p.device_name.toLowerCase().includes(query)) ||
                (p.ip && p.ip.toLowerCase().includes(query)) ||
                (p.src_ip && p.src_ip.toLowerCase().includes(query)) ||
                (p.dst_ip && p.dst_ip.toLowerCase().includes(query)) ||
                (p.protocol && p.protocol.toLowerCase().includes(query)) ||
                (p.decoded_summary && p.decoded_summary.toLowerCase().includes(query))
            );
        });

        if (filtered.length === 0) {
            body.innerHTML = `
                <tr>
                    <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                        ${query ? 'По вашему запросу полезная нагрузка не найдена.' : 'Пока нет перехваченных пакетов полезной нагрузки IoT.'}
                    </td>
                </tr>
            `;
            return;
        }

        const currentMode = getDeviceDisplayMode();

        body.innerHTML = filtered.map(p => {
            const timeStr = formatHumanTime(p.timestamp);
            const fullTime = formatHumanFullDateTime(p.timestamp);

            let protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300 font-mono">${escapeHtml(p.protocol || 'RAW')}</span>`;
            if (p.protocol === 'MQTT') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30 font-mono">MQTT</span>`;
            } else if (p.protocol === 'HTTP') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono">HTTP</span>`;
            } else if (p.protocol === 'NTP') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">NTP</span>`;
            } else if (p.protocol === 'DNS' || p.protocol === 'MDNS') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/20 text-blue-300 border border-blue-500/30 font-mono">${escapeHtml(p.protocol)}</span>`;
            } else if (p.protocol === 'TLS') {
                protoBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">TLS</span>`;
            }

            const sizeStr = `${p.payload_len || (p.payload_hex ? Math.round(p.payload_hex.length / 2) : (p.byte_size || 0))} B`;

            const inspectBtn = p.packet_id
                ? `<button onclick="openPacketInspectorModal('${escapeHtml(p.packet_id)}')" class="px-2.5 py-1 rounded-lg text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-amber-300 hover:text-white transition border border-slate-700 flex items-center space-x-1 float-right">
                    <i data-lucide="binary" class="w-3 h-3"></i>
                    <span>Инспектор</span>
                   </button>`
                : `<span class="text-slate-600 text-[11px]">—</span>`;

            // Format destination label nicely respecting display mode and multicast (e.g. mDNS Multicast, Роутер Keenetic:80, 224.0.0.251:5353)
            let formattedDst = p.dst_ip || '—';
            const dstPortStr = p.dst_port ? `:${p.dst_port}` : '';
            if (p.dst_ip && p.dst_ip !== '0.0.0.0') {
                const rawDstIp = p.dst_ip;
                const isIpv6 = isIpv6Address(rawDstIp);
                const fullDstWithPort = isIpv6 ? `[${rawDstIp}]${dstPortStr}` : `${rawDstIp}${dstPortStr}`;

                if (isRouterEntity(rawDstIp, null)) {
                    const rName = getRouterName();
                    if (currentMode === 'name') formattedDst = `${rName}${dstPortStr}`;
                    else if (currentMode === 'both') formattedDst = `${rName} (${fullDstWithPort})`;
                    else formattedDst = fullDstWithPort;
                } else {
                    const dName = deviceNameCache.getName(rawDstIp, null, null);
                    if (dName && dName !== rawDstIp && !isIpAddress(dName)) {
                        if (currentMode === 'name') {
                            formattedDst = dName;
                        } else if (currentMode === 'both') {
                            formattedDst = `${dName} (${fullDstWithPort})`;
                        } else {
                            formattedDst = fullDstWithPort;
                        }
                    } else {
                        formattedDst = fullDstWithPort;
                    }
                }
            }

            const devCellHtml = renderDeviceCell(p.ip, p.mac, p.hostname || p.device_name || 'IoT Device', currentMode);

            return `
                <tr class="hover:bg-slate-800/40 transition">
                    <td class="py-2.5 px-3 text-slate-400 font-mono text-[11px]" title="${escapeHtml(fullTime)}">${escapeHtml(timeStr)}</td>
                    <td class="py-2.5 px-3">
                        ${devCellHtml}
                    </td>
                    <td class="py-2.5 px-3">${protoBadge}</td>
                    <td class="py-2.5 px-3 font-mono text-slate-300 text-xs truncate max-w-[180px]" title="${escapeHtml(p.dst_ip || '')}${escapeHtml(dstPortStr)}">
                        ${escapeHtml(formattedDst)}
                    </td>
                    <td class="py-2.5 px-3 text-slate-200 text-xs break-all max-w-[320px]">
                        <span class="font-mono text-amber-200/90">${escapeHtml(p.decoded_summary || '—')}</span>
                    </td>
                    <td class="py-2.5 px-3 text-right font-mono text-slate-400 text-xs">${escapeHtml(sizeStr)}</td>
                    <td class="py-2.5 px-3 text-right">${inspectBtn}</td>
                </tr>
            `;
        }).join('');

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error loading IoT payloads:', e);
    }
}

async function ensureIotDeviceSelect() {
    const sel = document.getElementById('sh-iot-device-select');
    if (!sel || sel.children.length > 1) return;

    try {
        const res = await fetch('/api/devices');
        if (!res.ok) return;
        const devs = await res.json();
        const iotDevs = devs.filter(d => ['iot', 'camera', 'smart_tv', 'smart_home_hub'].includes(d.security_profile));
        (iotDevs.length > 0 ? iotDevs : devs).forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.mac;
            opt.textContent = `${d.custom_name || d.hostname || 'IoT Device'} (${d.ip || d.mac})`;
            sel.appendChild(opt);
        });
    } catch (e) {}
}

function debounceIotSearch() {
    if (iotSearchDebounceTimer) clearTimeout(iotSearchDebounceTimer);
    iotSearchDebounceTimer = setTimeout(() => {
        loadIotPayloads();
    }, 250);
}

async function loadIotStorageSettings() {
    try {
        const res = await fetch('/api/settings/iot_storage');
        if (!res.ok) return;
        const data = await res.json();
        const cfg = data.config || {};
        const stats = data.storage_stats || {};

        const maxGbEl = document.getElementById('cfg-iot-storage-max-gb');
        const retDaysEl = document.getElementById('cfg-iot-retention-days');
        const capEnEl = document.getElementById('cfg-iot-capture-enabled');
        const shToggle = document.getElementById('sh-iot-capture-toggle');
        const shBadge = document.getElementById('sh-iot-storage-badge');
        const shCountBadge = document.getElementById('sh-iot-count-badge');
        const usageText = document.getElementById('cfg-iot-storage-usage-text');

        if (maxGbEl && cfg.max_storage_gb !== undefined) maxGbEl.value = cfg.max_storage_gb;
        if (retDaysEl && cfg.retention_days !== undefined) retDaysEl.value = cfg.retention_days;
        if (capEnEl && cfg.capture_enabled !== undefined) capEnEl.checked = Boolean(cfg.capture_enabled);
        if (shToggle && cfg.capture_enabled !== undefined) shToggle.checked = Boolean(cfg.capture_enabled);

        const mb = (stats.total_mb || 0).toFixed(2);
        const count = stats.total_records || 0;
        const maxGb = cfg.max_storage_gb || 1.0;

        if (shBadge) {
            shBadge.textContent = `${mb} МБ / ${maxGb} ГБ`;
        }
        if (shCountBadge) {
            shCountBadge.textContent = `${count} пакетов`;
        }
        if (usageText) {
            usageText.textContent = `${mb} МБ из ${maxGb} ГБ (${count} сохраненных пакетов)`;
        }
    } catch (e) {
        console.error('Error loading IoT storage settings:', e);
    }
}

async function toggleIotCapture(enabled) {
    try {
        const res = await fetch('/api/settings/iot_storage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ capture_enabled: Boolean(enabled) })
        });
        if (res.ok) {
            showToast(enabled ? 'Сбор полезной нагрузки IoT включен' : 'Сбор полезной нагрузки IoT отключен', 'info');
            await loadIotStorageSettings();
        }
    } catch (e) {
        showToast('Ошибка при изменении настройки сбора: ' + e.message, 'error');
    }
}

async function saveIotStorageSettings() {
    try {
        const maxGb = parseFloat(document.getElementById('cfg-iot-storage-max-gb')?.value || '1.0');
        const retDays = parseInt(document.getElementById('cfg-iot-retention-days')?.value || '7', 10);
        const capEn = Boolean(document.getElementById('cfg-iot-capture-enabled')?.checked);

        const res = await fetch('/api/settings/iot_storage', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                capture_enabled: capEn,
                max_storage_gb: maxGb,
                retention_days: retDays
            })
        });

        if (res.ok) {
            showToast('Параметры хранилища IoT успешно сохранены', 'success');
            await loadIotStorageSettings();
        } else {
            throw new Error('Не удалось сохранить настройки');
        }
    } catch (e) {
        showToast('Ошибка сохранения хранилища: ' + e.message, 'error');
    }
}

async function pruneIotPayloadsNow() {
    try {
        const maxGb = parseFloat(document.getElementById('cfg-iot-storage-max-gb')?.value || '1.0');
        const retDays = parseInt(document.getElementById('cfg-iot-retention-days')?.value || '7', 10);

        const res = await fetch('/api/iot/payloads/prune', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ max_storage_gb: maxGb, retention_days: retDays })
        });

        if (res.ok) {
            const data = await res.json();
            const pruned = data.pruned_count || 0;
            showToast(`Очищено ${pruned} устаревших пакетов`, 'success');
            await loadIotStorageSettings();
            await loadIotPayloads();
        }
    } catch (e) {
        showToast('Ошибка очистки хранилища: ' + e.message, 'error');
    }
}

// ==========================================
// 13. DEEP PACKET INSPECTOR (WIRESHARK-STYLE)
// ==========================================

let packetInspectorFrozen = true;
let currentSelectedPktId = null;
let currentInspectedPayloadText = '';
let currentInspectedHexDump = '';
let packetSearchDebounceTimer = null;

async function loadPacketInspectorLive(force = false) {
    if (packetInspectorFrozen && !force) return;

    if (!devicesList || devicesList.length === 0) {
        await loadDevices();
    }

    try {
        await ensurePacketDeviceSelect();

        const devSelect = document.getElementById('pkt-device-select');
        const selectedDev = devSelect ? devSelect.value : 'all';

        let url = selectedDev === 'all'
            ? '/api/packets/live?limit=100'
            : `/api/devices/${encodeURIComponent(selectedDev)}/packets?limit=100`;

        const protoSelect = document.getElementById('pkt-protocol-select');
        const protoFilter = protoSelect ? protoSelect.value : 'all';
        if (protoFilter && protoFilter !== 'all') {
            url += `&protocol=${encodeURIComponent(protoFilter)}`;
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const packets = data.packets || [];

        // Update PCAP banner if in PCAP inspection mode
        const pcapBanner = document.getElementById('pkt-pcap-banner');
        const pcapFilename = document.getElementById('pkt-pcap-filename');
        const pcapCount = document.getElementById('pkt-pcap-count');
        if (pcapBanner) {
            if (data.is_pcap) {
                pcapBanner.classList.remove('hidden');
                if (pcapFilename) pcapFilename.textContent = data.pcap_filename || 'dump.pcap';
                if (pcapCount) pcapCount.textContent = data.total_buffered || packets.length;
            } else {
                pcapBanner.classList.add('hidden');
            }
        }

        const totalBuffered = document.getElementById('pkt-total-buffered');
        const badge = document.getElementById('packets-count-badge');
        if (totalBuffered) totalBuffered.textContent = `Буфер: ${data.total_buffered || packets.length} пакетов`;
        if (badge) {
            badge.textContent = data.total_buffered || packets.length;
            if (packets.length > 0) badge.classList.remove('hidden');
            else badge.classList.add('hidden');
        }

        const body = document.getElementById('pkt-list-body');
        if (!body) return;

        const searchInput = document.getElementById('pkt-search-input');
        const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

        const mode = getDeviceDisplayMode();
        const hideRouter = getFilterPref('hideRouter');
        const hideHub = getFilterPref('hideHub');

        const filtered = packets.filter(p => {
            if (hideRouter && isRouterEntity(p.src, p.src_mac || null)) return false;
            if (hideHub && isHubEntity(p.src, p.src_mac || null)) return false;
            if (!query) return true;
            const srcFormatted = formatDeviceIdentifier(p.src, p.src_mac || null, 'both').toLowerCase();
            const dstFormatted = formatDeviceIdentifier(p.dst, p.dst_mac || null, 'both').toLowerCase();
            return (
                String(p.pkt_id).includes(query) ||
                (p.src && p.src.toLowerCase().includes(query)) ||
                (p.dst && p.dst.toLowerCase().includes(query)) ||
                srcFormatted.includes(query) ||
                dstFormatted.includes(query) ||
                (p.protocol && p.protocol.toLowerCase().includes(query)) ||
                (p.summary && p.summary.toLowerCase().includes(query))
            );
        });

        if (filtered.length === 0) {
            body.innerHTML = `
                <tr>
                    <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                        ${query ? 'По вашему фильтру пакеты не найдены.' : 'Ожидание пакетов в буфере сниффера...'}
                    </td>
                </tr>
            `;
            return;
        }

        body.innerHTML = filtered.map(p => {
            const isSelected = p.pkt_id === currentSelectedPktId;
            const rowClass = isSelected
                ? 'bg-indigo-950/60 border-l-4 border-indigo-500 cursor-pointer font-mono text-xs transition'
                : 'hover:bg-slate-800/50 cursor-pointer font-mono text-xs transition';

            let protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">${escapeHtml(p.protocol || 'IP')}</span>`;
            if (p.protocol === 'TCP' || p.protocol === 'HTTP') protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300">${escapeHtml(p.protocol)}</span>`;
            else if (p.protocol === 'UDP' || p.protocol === 'DNS') protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-blue-500/20 text-blue-300">${escapeHtml(p.protocol)}</span>`;
            else if (p.protocol === 'MQTT') protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/20 text-purple-300">MQTT</span>`;
            else if (p.protocol === 'ICMP') protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-cyan-500/20 text-cyan-300">ICMP</span>`;
            else if (p.protocol === 'ARP') protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300">ARP</span>`;

            const timeStr = formatHumanTime(p.timestamp);
            const fullTime = formatHumanFullDateTime(p.timestamp);
            const srcLabel = formatDeviceIdentifier(p.src, p.src_mac || null, mode);
            const dstLabel = formatDeviceIdentifier(p.dst, p.dst_mac || null, mode);

            return `
                <tr class="${rowClass}" data-pkt-id="${escapeHtml(p.pkt_id)}" onclick="selectPacketForInspection('${escapeHtml(p.pkt_id)}')" title="Нажмите для анализа слоев OSI и Hex-дампа">
                    <td class="py-2 px-2.5 text-slate-400">${escapeHtml(p.pkt_id)}</td>
                    <td class="py-2 px-3 text-slate-400 font-mono text-xs" title="${escapeHtml(fullTime)}">${escapeHtml(timeStr)}</td>
                    <td class="py-2 px-3 text-slate-200 font-mono truncate max-w-[150px]" title="${escapeHtml(srcLabel)}">${escapeHtml(srcLabel)}</td>
                    <td class="py-2 px-3 text-slate-200 font-mono truncate max-w-[150px]" title="${escapeHtml(dstLabel)}">${escapeHtml(dstLabel)}</td>
                    <td class="py-2 px-3">${protoBadge}</td>
                    <td class="py-2 px-2.5 text-right text-slate-400">${p.length || 0}</td>
                    <td class="py-2 px-4 text-slate-300 truncate max-w-md">${escapeHtml(p.summary || '—')}</td>
                </tr>
            `;
        }).join('');

        if (!currentSelectedPktId && filtered.length > 0) {
            selectPacketForInspection(filtered[0].pkt_id);
        }
    } catch (e) {
        console.error('Error in loadPacketInspectorLive:', e);
    }
}

async function ensurePacketDeviceSelect() {
    const sel = document.getElementById('pkt-device-select');
    if (!sel) return;

    if (!devicesList || devicesList.length === 0) {
        try {
            const res = await fetch('/api/devices');
            if (res.ok) {
                devicesList = await res.json();
                deviceNameCache.registerDevices(devicesList);
            }
        } catch (e) {}
    }

    if (sel.children.length <= 1 && devicesList && devicesList.length > 0) {
        devicesList.forEach(d => {
            const opt = document.createElement('option');
            opt.value = d.mac;
            opt.textContent = `${d.custom_name || d.hostname || 'Device'} (${d.ip || d.mac})`;
            sel.appendChild(opt);
        });
    }
}

function onPacketDeviceSelectChange() {
    loadPacketInspectorLive(true);
}

function debouncePacketSearch() {
    if (packetSearchDebounceTimer) clearTimeout(packetSearchDebounceTimer);
    packetSearchDebounceTimer = setTimeout(() => {
        loadPacketInspectorLive(true);
    }, 250);
}

function togglePacketFreeze() {
    packetInspectorFrozen = !packetInspectorFrozen;
    updatePacketFreezeBtnUI(packetInspectorFrozen);
    if (!packetInspectorFrozen) {
        loadPacketInspectorLive(true);
    }
}

function updatePacketFreezeBtnUI(isFrozen) {
    const btn = document.getElementById('pkt-freeze-btn');
    const icon = document.getElementById('pkt-freeze-icon');
    const txt = document.getElementById('pkt-freeze-text');

    if (isFrozen) {
        if (btn) {
            btn.className = 'px-3 py-2 rounded-xl text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center space-x-1.5 transition';
            btn.title = 'Захват на паузе. Нажмите для включения живого автообновления';
        }
        if (txt) txt.textContent = 'Возобновить автообновление';
        if (icon) icon.setAttribute('data-lucide', 'play');
    } else {
        if (btn) {
            btn.className = 'px-3 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center space-x-1.5 transition';
            btn.title = 'Автообновление активно. Нажмите для паузы';
        }
        if (txt) txt.textContent = 'Пауза захвата';
        if (icon) icon.setAttribute('data-lucide', 'pause');
    }
    if (window.lucide) lucide.createIcons();
}

function clearPacketInspectorBuffer() {
    const body = document.getElementById('pkt-list-body');
    if (body) {
        body.innerHTML = `
            <tr>
                <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                    Буфер очищен. Ожидание новых пакетов...
                </td>
            </tr>
        `;
    }
    const tree = document.getElementById('pkt-layer-tree');
    if (tree) tree.innerHTML = '<div class="py-12 text-center text-slate-500 font-sans">Пакет не выбран.</div>';
    const hex = document.getElementById('pkt-hex-pane');
    if (hex) hex.innerHTML = '<div class="py-12 text-center text-slate-500 font-sans">Дамп очищен.</div>';
    currentSelectedPktId = null;
}

async function selectPacketForInspection(pktId) {
    if (!pktId) return;
    currentSelectedPktId = pktId;
    const idBadge = document.getElementById('pkt-current-id-badge');
    if (idBadge) idBadge.textContent = `Пакет #${pktId}`;

    const rows = document.querySelectorAll('#pkt-list-body tr');
    rows.forEach(r => {
        if (r.getAttribute('data-pkt-id') === String(pktId)) {
            r.classList.add('bg-indigo-950/60', 'border-l-4', 'border-indigo-500');
            r.classList.remove('hover:bg-slate-800/50');
        } else {
            r.classList.remove('bg-indigo-950/60', 'border-l-4', 'border-indigo-500');
            r.classList.add('hover:bg-slate-800/50');
        }
    });

    try {
        const res = await fetch(`/api/packets/inspect/${encodeURIComponent(pktId)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        currentInspectedPayloadText = data.payload_str || '';
        currentInspectedHexDump = data.hexdump || '';

        renderPacketLayers(data.dissection, 'pkt-layer-tree');
        renderPacketHexDump(data.hexdump, data.hex_dump_lines, 'pkt-hex-pane');
    } catch (e) {
        console.error('Error inspecting packet:', e);
        const layersEl = document.getElementById('pkt-layer-tree');
        const hexEl = document.getElementById('pkt-hex-pane');
        if (layersEl) {
            layersEl.innerHTML = `
                <div class="py-12 px-4 text-center">
                    <div class="inline-flex p-3 rounded-2xl bg-amber-500/10 text-amber-400 mb-3">
                        <i data-lucide="clock-alert" class="w-6 h-6"></i>
                    </div>
                    <div class="text-sm font-medium text-slate-300 mb-1">Пакет вытеснен из буфера памяти</div>
                    <div class="text-xs text-slate-500 max-w-sm mx-auto">
                        Кольцевой буфер пакетов перезаписал этот пакет новыми данными сетевого трафика.
                    </div>
                </div>
            `;
        }
        if (hexEl) {
            hexEl.innerHTML = '<div class="text-slate-600 p-4 font-mono text-xs">// Дамп пакета недоступен (вытеснен из памяти)</div>';
        }
        if (window.lucide) lucide.createIcons();
    }
}

function renderPacketLayers(dissection, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!dissection || !dissection.layers || dissection.layers.length === 0) {
        container.innerHTML = '<div class="py-8 text-center text-slate-500 font-sans">Нет данных о слоях пакета.</div>';
        return;
    }

    container.innerHTML = dissection.layers.map((layer, idx) => {
        const isOpen = idx >= dissection.layers.length - 2;
        const fieldsHtml = Object.entries(layer.fields || {}).map(([k, v]) => {
            let valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
            return `
                <div class="flex items-start justify-between py-1 px-2 hover:bg-slate-800/60 rounded text-[11px] transition">
                    <span class="text-slate-400 font-medium">${escapeHtml(k)}:</span>
                    <span class="text-indigo-200 font-mono text-right max-w-xs break-all">${escapeHtml(valStr)}</span>
                </div>
            `;
        }).join('');

        return `
            <div class="border border-slate-800 rounded-xl overflow-hidden bg-surface-900/60">
                <button onclick="togglePacketLayerTree(this)" class="w-full flex items-center justify-between p-2.5 hover:bg-slate-800/50 transition text-left">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-indigo-500/20 text-indigo-300 font-mono">${escapeHtml(layer.layer_type || 'LAYER')}</span>
                        <span class="text-xs font-semibold text-slate-200">${escapeHtml(layer.name || 'Protocol')}</span>
                    </div>
                    <i data-lucide="chevron-down" class="w-4 h-4 text-slate-500 transition-transform ${isOpen ? 'rotate-180' : ''}"></i>
                </button>
                <div class="layer-fields divide-y divide-slate-800/50 p-2 bg-slate-950/40 ${isOpen ? '' : 'hidden'}">
                    ${fieldsHtml || '<div class="text-[11px] text-slate-500 italic p-1">Полей нет</div>'}
                </div>
            </div>
        `;
    }).join('');
}

function togglePacketLayerTree(btn) {
    const fieldsDiv = btn.nextElementSibling;
    const icon = btn.querySelector('i[data-lucide]');
    if (fieldsDiv) {
        fieldsDiv.classList.toggle('hidden');
    }
    if (icon) {
        icon.classList.toggle('rotate-180');
    }
}

function renderPacketHexDump(hexdumpStr, hexLines, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!hexLines || hexLines.length === 0) {
        container.innerHTML = `<pre class="font-mono text-xs text-slate-400 p-3">${escapeHtml(hexdumpStr || 'Нет данных')}</pre>`;
        return;
    }

    container.innerHTML = hexLines.map(line => {
        const hexSpans = (line.hex_bytes || []).map((h, i) => {
            const byteOffset = (line.offset || 0) + i;
            return `<span class="hover:bg-cyan-500/40 hover:text-cyan-300 rounded px-0.5 cursor-crosshair transition" data-byte="${byteOffset}" title="Смещение: 0x${byteOffset.toString(16).padStart(4, '0')} (${byteOffset})">${escapeHtml(h)}</span>`;
        }).join(' ');

        const offsetStr = `0x${(line.offset || 0).toString(16).padStart(4, '0')}`;

        return `
            <div class="flex items-center space-x-3 py-0.5 px-2 hover:bg-slate-900/60 rounded text-xs font-mono">
                <span class="text-slate-500 select-none w-14">${offsetStr}</span>
                <span class="text-slate-300 flex-1">${hexSpans}</span>
                <span class="text-cyan-400 select-none tracking-widest pl-2 border-l border-slate-800">${escapeHtml(line.ascii || '')}</span>
            </div>
        `;
    }).join('');
}

function copyPacketPayload() {
    if (!currentInspectedPayloadText) {
        showToast('Полезная нагрузка пуста', 'info');
        return;
    }
    navigator.clipboard.writeText(currentInspectedPayloadText).then(() => {
        showToast('Полезная нагрузка скопирована', 'success');
    }).catch(() => {
        prompt('Скопируйте:', currentInspectedPayloadText);
    });
}

function copyPacketHex() {
    if (!currentInspectedHexDump) {
        showToast('Hex дамп пуст', 'info');
        return;
    }
    navigator.clipboard.writeText(currentInspectedHexDump).then(() => {
        showToast('Hex дамп скопирован', 'success');
    }).catch(() => {
        prompt('Скопируйте:', currentInspectedHexDump);
    });
}

// Modal inspection methods
async function openPacketInspectorModal(pktId) {
    const modal = document.getElementById('packet-inspector-modal');
    if (!modal) return;

    modal.classList.remove('hidden');

    const protoEl = document.getElementById('modal-pkt-proto');
    const summaryEl = document.getElementById('modal-pkt-summary');
    const layersEl = document.getElementById('modal-packet-layers-container');
    const hexEl = document.getElementById('modal-packet-hexdump');

    if (protoEl) protoEl.textContent = '...';
    if (summaryEl) summaryEl.textContent = `#${pktId} | Загрузка структуры...`;
    if (layersEl) layersEl.innerHTML = '<div class="py-8 text-center text-slate-500">Загрузка структуры пакета...</div>';
    if (hexEl) hexEl.textContent = 'Загрузка...';

    try {
        const res = await fetch(`/api/packets/inspect/${encodeURIComponent(pktId)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        currentInspectedPayloadText = data.payload_str || '';
        currentInspectedHexDump = data.hexdump || '';

        if (protoEl) protoEl.textContent = data.protocol || 'RAW';
        if (summaryEl) summaryEl.textContent = `#${pktId} | ${data.src || '—'} → ${data.dst || '—'} (${data.length || 0} B)`;

        renderPacketLayers(data.dissection, 'modal-packet-layers-container');
        if (hexEl) hexEl.textContent = data.hexdump || '—';

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        if (protoEl) protoEl.textContent = 'НЕТ ДАННЫХ';
        if (summaryEl) summaryEl.textContent = `#${pktId} | Пакет вытеснен из буфера памяти (${e.message})`;
        if (layersEl) {
            layersEl.innerHTML = `
                <div class="py-12 px-4 text-center">
                    <div class="inline-flex p-3 rounded-2xl bg-amber-500/10 text-amber-400 mb-3">
                        <i data-lucide="clock-alert" class="w-6 h-6"></i>
                    </div>
                    <div class="text-sm font-medium text-slate-300 mb-1">Пакет больше недоступен в памяти</div>
                    <div class="text-xs text-slate-500 max-w-sm mx-auto">
                        Кольцевой буфер пакетов хранит последние сетевые события. Пакет был вытеснен новыми данными.
                    </div>
                </div>
            `;
        }
        if (hexEl) {
            hexEl.textContent = '// Дамп пакета недоступен (пакет был вытеснен из кольцевого буфера памяти)';
        }
        if (window.lucide) lucide.createIcons();
    }
}

function closePacketInspectorModal() {
    const modal = document.getElementById('packet-inspector-modal');
    if (modal) modal.classList.add('hidden');
}

function copyModalPacketPayload() {
    copyPacketPayload();
}

function copyModalPacketHex() {
    copyPacketHex();
}

// ==========================================
// 14. PCAP FILE VIEWER & DUMP INSPECTOR
// ==========================================

function openPcapSelectorModal() {
    const modal = document.getElementById('pcap-selector-modal');
    if (modal) modal.classList.remove('hidden');
    loadSavedPcapsList();
    if (window.lucide) lucide.createIcons();
}

function closePcapSelectorModal() {
    const modal = document.getElementById('pcap-selector-modal');
    if (modal) modal.classList.add('hidden');
}

function triggerPcapFileBrowse() {
    const input = document.getElementById('pkt-pcap-file-input');
    if (input) input.click();
}

async function loadSavedPcapsList() {
    const container = document.getElementById('pcap-saved-list');
    if (!container) return;
    container.innerHTML = '<div class="py-6 text-center text-slate-500 text-xs font-sans">Загрузка списка сохраненных дампов...</div>';

    try {
        const res = await fetch('/api/packets/pcap/saved');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const files = data.files || [];

        if (files.length === 0) {
            container.innerHTML = '<div class="py-6 text-center text-slate-500 text-xs font-sans">В директории data/pcaps/ сохраненных дампов пока нет. Вы можете запустить аудит устройства или ночную форензику ТВ.</div>';
            return;
        }

        container.innerHTML = files.map(f => {
            let catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-400">Файл</span>`;
            if (f.category === 'tv_wake') {
                catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-purple-500/20 text-purple-300">Форензика ТВ</span>`;
            } else if (f.category === 'audit') {
                catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-indigo-500/20 text-indigo-300">Аудит</span>`;
            }

            return `
                <div class="flex items-center justify-between p-3 rounded-xl bg-surface-950 border border-slate-800 hover:border-indigo-500/50 transition">
                    <div class="space-y-0.5 min-w-0 pr-2">
                        <div class="flex items-center space-x-2">
                            ${catBadge}
                            <span class="font-mono text-xs text-white truncate max-w-xs" title="${escapeHtml(f.filename)}">${escapeHtml(f.filename)}</span>
                        </div>
                        <div class="text-[11px] text-slate-400">
                            <span>${f.size_kb || 0} КБ</span> • <span>${escapeHtml(f.modified_human || '')}</span>
                        </div>
                    </div>
                    <button onclick="loadSavedPcapToInspector('${escapeHtml(f.filename)}')" class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shrink-0 transition flex items-center space-x-1">
                        <i data-lucide="eye" class="w-3.5 h-3.5"></i>
                        <span>Открыть</span>
                    </button>
                </div>
            `;
        }).join('');

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        container.innerHTML = `<div class="py-6 text-center text-rose-400 text-xs font-sans">Ошибка загрузки списка дампов: ${escapeHtml(e.message)}</div>`;
    }
}

async function loadSavedPcapToInspector(filename) {
    try {
        showToast(`Загрузка дампа ${filename}...`, 'info');
        const res = await fetch('/api/packets/pcap/load_saved', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filename })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        closePcapSelectorModal();
        showToast(`Дамп загружен: ${data.loaded_packets} пакетов`, 'success');

        // Freeze inspector so live packets don't overwrite the view
        packetInspectorFrozen = true;
        updatePacketFreezeBtnUI(true);

        await loadPacketInspectorLive(true);
    } catch (e) {
        showToast(`Ошибка загрузки PCAP: ${e.message}`, 'error');
    }
}

async function handlePcapFileUpload(input) {
    if (!input || !input.files || input.files.length === 0) return;
    const file = input.files[0];
    const formData = new FormData();
    formData.append('file', file);

    try {
        showToast(`Загрузка файла ${file.name}...`, 'info');
        const res = await fetch('/api/packets/pcap/upload', {
            method: 'POST',
            body: formData
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const data = await res.json();
        closePcapSelectorModal();
        showToast(`Файл обработан: ${data.loaded_packets} пакетов`, 'success');

        // Freeze inspector
        packetInspectorFrozen = true;
        updatePacketFreezeBtnUI(true);

        await loadPacketInspectorLive(true);
    } catch (e) {
        showToast(`Ошибка загрузки: ${e.message}`, 'error');
    } finally {
        input.value = '';
    }
}

async function exitPcapMode() {
    try {
        await fetch('/api/packets/pcap/clear', { method: 'POST' });
        const banner = document.getElementById('pkt-pcap-banner');
        if (banner) banner.classList.add('hidden');
        showToast('Возврат к живому сетевому буферу', 'info');
        await loadPacketInspectorLive(true);
    } catch (e) {
        showToast(`Ошибка выхода из режима PCAP: ${e.message}`, 'error');
    }
}

// ==========================================
// Device Modal: Granular Policy Handlers
// ==========================================
async function saveModalUnifiedPolicy(policyId) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ policy_id: policyId })
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            showToast('Политика безопасности устройства обновлена', 'success');
            await openDeviceModal(currentDeviceMac);
            loadDevices();
        } else {
            showToast(`Ошибка: ${data.detail || 'Не удалось обновить политику'}`, 'error');
        }
    } catch (e) {
        console.error('Error saving unified policy', e);
        showToast('Ошибка сети при обновлении политики', 'error');
    }
}
window.saveModalUnifiedPolicy = saveModalUnifiedPolicy;

async function saveModalCustomPorts(portsStr) {
    if (!currentDeviceMac) return;
    try {
        const rawPorts = (portsStr || '').split(/[,; ]+/).filter(Boolean);
        const validPorts = rawPorts.map(p => parseInt(p, 10)).filter(p => !isNaN(p) && p > 0 && p <= 65535);
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/lan-policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ custom_allowed_ports: validPorts })
        });
        if (res.ok) {
            showToast('Кастомные порты сохранены', 'success');
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка: ${err.detail || 'Не удалось сохранить порты'}`, 'error');
        }
    } catch (e) {
        console.error('Error saving custom ports', e);
        showToast('Ошибка сети при сохранении портов', 'error');
    }
}
window.saveModalCustomPorts = saveModalCustomPorts;

async function saveModalDevicePreset(presetId) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/lan-policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ preset_id: presetId || null })
        });
        if (res.ok) {
            showToast('Пресет сетевых политик обновлен', 'success');
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка: ${err.detail || 'Не удалось обновить пресет'}`, 'error');
        }
    } catch (e) {
        console.error('Error saving device preset', e);
        showToast('Ошибка сети при сохранении пресета', 'error');
    }
}

async function saveModalNvrIp(nvrIp) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/lan-policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ designated_nvr_ip: (nvrIp || '').trim() || null })
        });
        if (res.ok) {
            showToast('Доверенный NVR сохранен', 'success');
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка: ${err.detail || 'Не удалось сохранить NVR'}`, 'error');
        }
    } catch (e) {
        console.error('Error saving NVR IP', e);
        showToast('Ошибка сети при сохранении NVR', 'error');
    }
}

async function saveModalAutoQuarantine(override) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/lan-policy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ auto_quarantine_override: override })
        });
        if (res.ok) {
            showToast('Режим автокарантина обновлен', 'success');
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка: ${err.detail || 'Не удалось сохранить режим'}`, 'error');
        }
    } catch (e) {
        console.error('Error saving quarantine override', e);
        showToast('Ошибка сети при сохранении режима', 'error');
    }
}
window.saveModalDevicePreset = saveModalDevicePreset;
window.saveModalNvrIp = saveModalNvrIp;
window.saveModalAutoQuarantine = saveModalAutoQuarantine;

// ==========================================
// LAN Policy Presets Subsystem
// ==========================================
let allLanPresets = [];

async function loadLanPresets() {
    try {
        const res = await fetch('/api/presets');
        if (!res.ok) return;
        allLanPresets = await res.json();

        // 1. Render in Settings Tab
        const listCont = document.getElementById('settings-presets-list');
        if (listCont) {
            if (allLanPresets.length === 0) {
                listCont.innerHTML = '<div class="py-4 text-center text-slate-500 text-xs font-sans">Пресеты не найдены</div>';
            } else {
                listCont.innerHTML = allLanPresets.map(p => {
                    const isBuiltin = Boolean(p.is_builtin);
                    const rules = p.rules || {};
                    const allowed = rules.allowed_services || rules.allowed_ports || [];
                    const alertPorts = rules.alert_services || rules.alert_ports || [];
                    const blocked = rules.blocked_services || rules.quarantine_ports || [];

                    const allowedTags = allowed.map(s => `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-mono">${escapeHtml(String(s))}</span>`).join(' ');
                    const alertTags = alertPorts.map(s => `<span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 text-[10px] font-mono">${escapeHtml(String(s))}</span>`).join(' ');
                    const blockedTags = blocked.map(s => `<span class="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-mono">${escapeHtml(String(s))}</span>`).join(' ');

                    return `
                        <div class="p-3 bg-surface-950 rounded-xl border border-slate-800 hover:border-slate-700/80 transition space-y-2">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center space-x-2">
                                    <span class="font-bold text-slate-200 text-xs">${escapeHtml(p.name)}</span>
                                    <span class="px-2 py-0.2 rounded-full text-[10px] font-mono font-medium ${isBuiltin ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20' : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'}">
                                        ${isBuiltin ? 'Системный' : 'Пользовательский'}
                                    </span>
                                </div>
                                <div class="flex items-center space-x-1.5">
                                    ${!isBuiltin ? `
                                        <button type="button" onclick="openCustomPresetModal('${escapeHtml(p.id)}')" class="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition" title="Редактировать">
                                            <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
                                        </button>
                                        <button type="button" onclick="deleteCustomPreset('${escapeHtml(p.id)}')" class="p-1 text-slate-400 hover:text-rose-400 rounded hover:bg-slate-800 transition" title="Удалить">
                                            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                                        </button>
                                    ` : ''}
                                </div>
                            </div>
                            <p class="text-[11px] text-slate-400">${escapeHtml(p.description || '')}</p>
                            <div class="flex flex-wrap gap-1 pt-1 border-t border-slate-800/60 items-center">
                                <span class="text-[10px] text-slate-500 mr-1">Правила:</span>
                                ${allowedTags ? `<span class="text-[10px] text-emerald-400 mr-1">Разрешено:</span> ${allowedTags}` : ''}
                                ${alertTags ? `<span class="text-[10px] text-amber-400 ml-2 mr-1">Надзор:</span> ${alertTags}` : ''}
                                ${blockedTags ? `<span class="text-[10px] text-rose-400 ml-2 mr-1">Бан:</span> ${blockedTags}` : ''}
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }

        // 2. Update Preset dropdown in Device Detail Modal
        const modalSelect = document.getElementById('modal-lan-preset-select');
        if (modalSelect) {
            const currentVal = modalSelect.value;
            let opts = '<option value="">Автоматически (согласно политике)</option>';
            opts += allLanPresets.map(p => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
            modalSelect.innerHTML = opts;
            if (currentVal) modalSelect.value = currentVal;
        }

        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error loading LAN presets', e);
    }
}

function openCustomPresetModal(presetId = null) {
    const modal = document.getElementById('custom-preset-modal');
    if (!modal) return;

    const titleEl = document.getElementById('custom-preset-modal-title');
    const idInput = document.getElementById('preset-form-id');
    const nameInput = document.getElementById('preset-form-name');
    const descInput = document.getElementById('preset-form-desc');
    const allowedInput = document.getElementById('preset-form-allowed');
    const alertInput = document.getElementById('preset-form-alert');
    const quarInput = document.getElementById('preset-form-quarantine');

    if (presetId) {
        const p = allLanPresets.find(x => x.id === presetId);
        if (p) {
            if (titleEl) titleEl.textContent = 'Редактирование пресета';
            if (idInput) {
                idInput.value = p.id;
                idInput.disabled = true;
            }
            if (nameInput) nameInput.value = p.name;
            if (descInput) descInput.value = p.description || '';
            const rules = p.rules || {};
            if (allowedInput) allowedInput.value = (rules.allowed_ports || []).join(', ');
            if (alertInput) alertInput.value = (rules.alert_ports || []).join(', ');
            if (quarInput) quarInput.value = (rules.quarantine_ports || []).join(', ');
        }
    } else {
        if (titleEl) titleEl.textContent = 'Новый пресет сетевой политики LAN';
        if (idInput) {
            idInput.value = 'preset_custom_' + Math.floor(Math.random() * 1000);
            idInput.disabled = false;
        }
        if (nameInput) nameInput.value = '';
        if (descInput) descInput.value = '';
        if (allowedInput) allowedInput.value = '';
        if (alertInput) alertInput.value = '';
        if (quarInput) quarInput.value = '';
    }

    modal.classList.remove('hidden');
    if (window.lucide) lucide.createIcons();
}

function closeCustomPresetModal() {
    const modal = document.getElementById('custom-preset-modal');
    if (modal) modal.classList.add('hidden');
}

function parsePortList(str) {
    if (!str) return [];
    return str.split(',')
        .map(s => parseInt(s.trim(), 10))
        .filter(n => !isNaN(n) && n > 0 && n <= 65535);
}

async function saveCustomPresetForm(e) {
    e.preventDefault();
    const idInput = document.getElementById('preset-form-id');
    const nameInput = document.getElementById('preset-form-name');
    const descInput = document.getElementById('preset-form-desc');
    const allowedInput = document.getElementById('preset-form-allowed');
    const alertInput = document.getElementById('preset-form-alert');
    const quarInput = document.getElementById('preset-form-quarantine');

    const presetId = (idInput.value || '').trim();
    if (!presetId) {
        showToast('Укажите ID пресета', 'error');
        return;
    }

    const payload = {
        id: presetId,
        name: (nameInput.value || '').trim(),
        description: (descInput.value || '').trim(),
        rules: {
            allowed_ports: parsePortList(allowedInput.value),
            alert_ports: parsePortList(alertInput.value),
            quarantine_ports: parsePortList(quarInput.value)
        }
    };

    const isEdit = idInput.disabled;
    const url = isEdit ? `/api/presets/${encodeURIComponent(presetId)}` : '/api/presets';
    const method = isEdit ? 'PUT' : 'POST';

    try {
        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            showToast('Пресет успешно сохранен', 'success');
            closeCustomPresetModal();
            await loadLanPresets();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || 'Серверная ошибка'}`, 'error');
        }
    } catch (ex) {
        showToast(`Ошибка сети: ${ex.message}`, 'error');
    }
}

async function deleteCustomPreset(presetId) {
    if (!confirm(`Удалить пресет "${presetId}"?`)) return;
    try {
        const res = await fetch(`/api/presets/${encodeURIComponent(presetId)}`, {
            method: 'DELETE'
        });
        if (res.ok) {
            showToast('Пресет удален', 'success');
            await loadLanPresets();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Не удалось удалить: ${err.detail || 'Ошибка'}`, 'error');
        }
    } catch (e) {
        showToast('Ошибка сети при удалении пресета', 'error');
    }
}

// ==========================================
// Adaptive 5-Step Device Setup Wizard
// ==========================================
let currentDeviceWizardMac = null;
let currentDeviceWizardStep = 1;
let currentDeviceWizardData = null;
let currentDeviceWizardSelectedPreset = null;

async function openDeviceWizard(mac) {
    if (!mac) return;
    closeDeviceModal();
    currentDeviceWizardMac = mac;
    currentDeviceWizardStep = 1;

    try {
        const res = await fetch(`/api/wizard/device/${encodeURIComponent(mac)}`);
        if (!res.ok) {
            showToast('Не удалось загрузить данные мастера для этого устройства', 'error');
            return;
        }
        currentDeviceWizardData = await res.json();
        const d = currentDeviceWizardData.device;

        // Step 1 fields
        const nameEl = document.getElementById('wizard-dev-name');
        if (nameEl) nameEl.value = d.custom_name || d.hostname || '';
        const macEl = document.getElementById('wizard-dev-mac');
        if (macEl) macEl.textContent = d.mac;
        const ipEl = document.getElementById('wizard-dev-ip');
        if (ipEl) ipEl.textContent = d.ip || 'Не назначен';
        const vendorEl = document.getElementById('wizard-dev-vendor');
        if (vendorEl) vendorEl.textContent = d.vendor || 'Неизвестен';
        const profEl = document.getElementById('wizard-dev-profile');
        if (profEl) profEl.value = d.profile || 'unassigned';

        // Step 2: NVR Candidates
        const nvrSelect = document.getElementById('wizard-camera-nvr-select');
        const customNvrInput = document.getElementById('wizard-camera-nvr-custom');
        if (nvrSelect) {
            let nvrOpts = '<option value="">Указать IP вручную...</option>';
            if (currentDeviceWizardData.nvr_candidates && currentDeviceWizardData.nvr_candidates.length > 0) {
                nvrOpts += currentDeviceWizardData.nvr_candidates.map(c => `<option value="${escapeHtml(c.ip)}">${escapeHtml(c.name)} (${escapeHtml(c.ip)})</option>`).join('');
            }
            nvrSelect.innerHTML = nvrOpts;
            if (d.designated_nvr_ip) {
                const found = currentDeviceWizardData.nvr_candidates && currentDeviceWizardData.nvr_candidates.some(c => c.ip === d.designated_nvr_ip);
                if (found) {
                    nvrSelect.value = d.designated_nvr_ip;
                    if (customNvrInput) customNvrInput.classList.add('hidden');
                } else {
                    nvrSelect.value = '';
                    if (customNvrInput) {
                        customNvrInput.value = d.designated_nvr_ip;
                        customNvrInput.classList.remove('hidden');
                    }
                }
            } else {
                nvrSelect.value = '';
                if (customNvrInput) {
                    customNvrInput.value = '';
                    customNvrInput.classList.remove('hidden');
                }
            }
        }

        // Step 2: DLNA Candidates
        const dlnaSelect = document.getElementById('wizard-tv-dlna-select');
        if (dlnaSelect) {
            let dlnaOpts = '<option value="">Без явного медиасервера</option>';
            if (currentDeviceWizardData.dlna_candidates && currentDeviceWizardData.dlna_candidates.length > 0) {
                dlnaOpts += currentDeviceWizardData.dlna_candidates.map(c => `<option value="${escapeHtml(c.ip)}">${escapeHtml(c.name)} (${escapeHtml(c.ip)})</option>`).join('');
            }
            dlnaSelect.innerHTML = dlnaOpts;
        }

        // Step 2: TV values
        const tvDayMode = document.getElementById('wizard-tv-day-mode');
        if (tvDayMode) tvDayMode.value = d.tv_day_mode || 'autonomous_only';
        const tvPre = document.getElementById('wizard-tv-pre');
        if (tvPre) tvPre.value = d.tv_pre_record_seconds !== null && d.tv_pre_record_seconds !== undefined ? d.tv_pre_record_seconds : 30;
        const tvPost = document.getElementById('wizard-tv-post');
        if (tvPost) tvPost.value = d.tv_post_record_seconds !== null && d.tv_post_record_seconds !== undefined ? d.tv_post_record_seconds : 30;

        // Step 3: Presets
        currentDeviceWizardSelectedPreset = d.preset_id || currentDeviceWizardData.recommended_preset || 'preset_iot';
        renderDeviceWizardPresetsList();
        const customPorts = document.getElementById('wizard-custom-ports');
        if (customPorts) {
            customPorts.value = Array.isArray(d.custom_allowed_ports) ? d.custom_allowed_ports.join(', ') : (d.custom_allowed_ports || '');
        }

        // Step 4: Quarantine
        const quarEl = document.getElementById('wizard-quarantine-override');
        if (quarEl) quarEl.value = d.auto_quarantine_override || 'profile_default';
        const runAuditEl = document.getElementById('wizard-run-audit');
        if (runAuditEl) runAuditEl.checked = true;

        deviceWizardOnProfileChange();
        setDeviceWizardStep(1);

        const modal = document.getElementById('device-setup-wizard-modal');
        if (modal) modal.classList.remove('hidden');
        if (window.lucide) lucide.createIcons();
    } catch (e) {
        console.error('Error opening wizard', e);
        showToast('Ошибка запуска мастера настройки', 'error');
    }
}

function closeDeviceWizard() {
    const modal = document.getElementById('device-setup-wizard-modal');
    if (modal) modal.classList.add('hidden');
}

function renderDeviceWizardPresetsList() {
    const cont = document.getElementById('wizard-presets-list');
    if (!cont || !currentDeviceWizardData || !currentDeviceWizardData.presets) return;

    cont.innerHTML = currentDeviceWizardData.presets.map(p => {
        const isSelected = (p.id === currentDeviceWizardSelectedPreset);
        const rules = p.rules || {};
        const allowed = rules.allowed_services || rules.allowed_ports || [];

        return `
            <div onclick="deviceWizardSelectPreset('${escapeHtml(p.id)}')" class="p-2.5 rounded-xl border transition cursor-pointer flex items-start space-x-3 ${isSelected ? 'bg-indigo-950/40 border-indigo-500 shadow-md shadow-indigo-500/10' : 'bg-surface-950 border-slate-800 hover:border-slate-700'}">
                <input type="radio" name="wizard-preset-radio" value="${escapeHtml(p.id)}" ${isSelected ? 'checked' : ''} class="mt-0.5 text-indigo-600 bg-surface-900 border-slate-700">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center space-x-2">
                        <span class="font-bold text-slate-200 text-xs">${escapeHtml(p.name)}</span>
                        ${p.id === currentDeviceWizardData.recommended_preset ? '<span class="px-1.5 py-0.2 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">Рекомендуется</span>' : ''}
                    </div>
                    <p class="text-[11px] text-slate-400 mt-0.5 truncate">${escapeHtml(p.description || '')}</p>
                    ${allowed.length > 0 ? `<div class="text-[10px] text-emerald-400/90 font-mono mt-1 truncate">Разрешено: ${escapeHtml(allowed.slice(0, 4).join(', '))}${allowed.length > 4 ? '...' : ''}</div>` : ''}
                </div>
            </div>
        `;
    }).join('');
}

function deviceWizardSelectPreset(presetId) {
    currentDeviceWizardSelectedPreset = presetId;
    renderDeviceWizardPresetsList();
}

function deviceWizardOnProfileChange() {
    const prof = document.getElementById('wizard-dev-profile')?.value || 'unassigned';

    // Hide all step 2 sections
    const tvSec = document.getElementById('wizard-step2-tv');
    const camSec = document.getElementById('wizard-step2-camera');
    const iotSec = document.getElementById('wizard-step2-iot');
    const trSec = document.getElementById('wizard-step2-trusted');

    if (tvSec) tvSec.classList.add('hidden');
    if (camSec) camSec.classList.add('hidden');
    if (iotSec) iotSec.classList.add('hidden');
    if (trSec) trSec.classList.add('hidden');

    if (prof === 'smart_tv' && tvSec) tvSec.classList.remove('hidden');
    else if (prof === 'camera' && camSec) camSec.classList.remove('hidden');
    else if ((prof === 'iot' || prof === 'smart_home_hub') && iotSec) iotSec.classList.remove('hidden');
    else if (prof === 'trusted' && trSec) trSec.classList.remove('hidden');
    else if (iotSec) iotSec.classList.remove('hidden');

    // Auto-update recommended preset in Step 3
    const map = {
        smart_tv: 'preset_smart_tv',
        camera: 'preset_camera',
        iot: 'preset_iot',
        smart_home_hub: 'preset_iot',
        trusted: 'preset_trusted',
        guest: 'preset_isolated_guest'
    };
    if (map[prof]) {
        currentDeviceWizardSelectedPreset = map[prof];
        renderDeviceWizardPresetsList();
    }
}

function deviceWizardOnNvrSelectChange() {
    const sel = document.getElementById('wizard-camera-nvr-select');
    const inp = document.getElementById('wizard-camera-nvr-custom');
    if (!sel || !inp) return;
    if (!sel.value) {
        inp.classList.remove('hidden');
    } else {
        inp.classList.add('hidden');
        inp.value = sel.value;
    }
}

function setDeviceWizardStep(step) {
    currentDeviceWizardStep = step;

    // Subtitle
    const subEl = document.getElementById('dev-wizard-header-subtitle');
    const titles = [
        'Шаг 1 из 5: Базовая идентификация',
        'Шаг 2 из 5: Специфика профиля',
        'Шаг 3 из 5: Пресет сетевой политики LAN',
        'Шаг 4 из 5: Автокарантин и реагирование',
        'Шаг 5 из 5: Итог и физическая изоляция'
    ];
    if (subEl) subEl.textContent = titles[step - 1] || `Шаг ${step} из 5`;

    // Step indicators
    for (let i = 1; i <= 5; i++) {
        const stepDiv = document.getElementById(`dev-wizard-step-${i}`);
        if (stepDiv) {
            if (i === step) stepDiv.classList.remove('hidden');
            else stepDiv.classList.add('hidden');
        }

        const pill = document.getElementById(`dev-wizard-pill-${i}`);
        if (pill) {
            const numSpan = pill.querySelector('span:first-child');
            const txtSpan = pill.querySelector('span:last-child');
            if (i === step) {
                if (numSpan) numSpan.className = 'w-5 h-5 rounded-full flex items-center justify-center font-bold text-[11px] bg-indigo-600 text-white';
                if (txtSpan) txtSpan.className = 'font-bold text-white hidden sm:inline';
            } else if (i < step) {
                if (numSpan) numSpan.className = 'w-5 h-5 rounded-full flex items-center justify-center font-bold text-[11px] bg-indigo-900 text-indigo-300';
                if (txtSpan) txtSpan.className = 'font-medium text-slate-300 hidden sm:inline';
            } else {
                if (numSpan) numSpan.className = 'w-5 h-5 rounded-full flex items-center justify-center font-bold text-[11px] bg-slate-800 text-slate-400';
                if (txtSpan) txtSpan.className = 'font-medium text-slate-400 hidden sm:inline';
            }
        }
    }

    // Navigation button visibility
    const prevBtn = document.getElementById('dev-wizard-btn-prev');
    const nextBtn = document.getElementById('dev-wizard-btn-next');
    const finBtn = document.getElementById('dev-wizard-btn-finish');

    if (prevBtn) {
        if (step === 1) prevBtn.classList.add('hidden');
        else prevBtn.classList.remove('hidden');
    }
    if (nextBtn) {
        if (step === 5) nextBtn.classList.add('hidden');
        else nextBtn.classList.remove('hidden');
    }
    if (finBtn) {
        if (step === 5) finBtn.classList.remove('hidden');
        else finBtn.classList.add('hidden');
    }

    if (step === 5) {
        deviceWizardBuildSummary();
    }
    if (window.lucide) lucide.createIcons();
}

function deviceWizardNextStep() {
    if (currentDeviceWizardStep < 5) {
        setDeviceWizardStep(currentDeviceWizardStep + 1);
    }
}

function deviceWizardPrevStep() {
    if (currentDeviceWizardStep > 1) {
        setDeviceWizardStep(currentDeviceWizardStep - 1);
    }
}

function deviceWizardBuildSummary() {
    const summaryBox = document.getElementById('wizard-summary-box');
    const l2Warning = document.getElementById('wizard-l2-warning');
    if (!summaryBox || !currentDeviceWizardData) return;

    const name = document.getElementById('wizard-dev-name')?.value || 'Не задано';
    const prof = document.getElementById('wizard-dev-profile')?.value || 'unassigned';
    const preset = currentDeviceWizardData.presets?.find(p => p.id === currentDeviceWizardSelectedPreset);
    const presetName = preset ? preset.name : 'По умолчанию';

    let nvrText = '';
    if (prof === 'camera') {
        const sel = document.getElementById('wizard-camera-nvr-select')?.value;
        const cust = document.getElementById('wizard-camera-nvr-custom')?.value;
        const nvr = sel || cust || 'Не назначен';
        nvrText = `<div><b>Доверенный NVR:</b> <span class="font-mono text-cyan-300">${escapeHtml(nvr)}</span></div>`;
    }

    let tvText = '';
    if (prof === 'smart_tv') {
        const mode = document.getElementById('wizard-tv-day-mode')?.value || 'autonomous_only';
        const pre = document.getElementById('wizard-tv-pre')?.value || 30;
        const post = document.getElementById('wizard-tv-post')?.value || 30;
        tvText = `<div><b>Дневной режим ТВ:</b> ${escapeHtml(mode)}, PCAP: -${pre}с / +${post}с</div>`;
    }

    const quarVal = document.getElementById('wizard-quarantine-override')?.value || 'profile_default';
    const quarLabels = {
        profile_default: 'По умолчанию политики',
        always_quarantine: 'Всегда блокировать WAN при инциденте',
        never_quarantine: 'Только предупреждения (без блокировки)'
    };

    summaryBox.innerHTML = `
        <div><b>Имя:</b> ${escapeHtml(name)}</div>
        <div><b>Профиль:</b> <span class="capitalize text-indigo-300">${escapeHtml(prof)}</span></div>
        <div><b>Сетевой LAN пресет:</b> <span class="text-emerald-300">${escapeHtml(presetName)}</span></div>
        ${nvrText}
        ${tvText}
        <div><b>Реакция автокарантина:</b> ${escapeHtml(quarLabels[quarVal] || quarVal)}</div>
        <div><b>Проверочный аудит трафика:</b> ${document.getElementById('wizard-run-audit')?.checked ? 'Да (60 секунд)' : 'Нет'}</div>
    `;

    // Physical Realism L2 Warning (AGENTS.md)
    if (l2Warning) {
        if (currentDeviceWizardData.requires_guest_wifi_for_isolation) {
            l2Warning.classList.remove('hidden');
        } else {
            l2Warning.classList.add('hidden');
        }
    }
}

async function submitDeviceWizard() {
    if (!currentDeviceWizardMac) return;

    const name = document.getElementById('wizard-dev-name')?.value || null;
    const prof = document.getElementById('wizard-dev-profile')?.value || 'unassigned';
    const presetId = currentDeviceWizardSelectedPreset;
    const quarOverride = document.getElementById('wizard-quarantine-override')?.value || 'profile_default';
    const runAudit = Boolean(document.getElementById('wizard-run-audit')?.checked);

    let designatedNvr = null;
    if (prof === 'camera') {
        const sel = document.getElementById('wizard-camera-nvr-select')?.value;
        const cust = document.getElementById('wizard-camera-nvr-custom')?.value;
        designatedNvr = (sel || cust || '').trim() || null;
    }

    let tvPre = null;
    let tvPost = null;
    let tvDay = null;
    if (prof === 'smart_tv') {
        tvPre = parseInt(document.getElementById('wizard-tv-pre')?.value || '30', 10);
        tvPost = parseInt(document.getElementById('wizard-tv-post')?.value || '30', 10);
        tvDay = document.getElementById('wizard-tv-day-mode')?.value || 'autonomous_only';
    }

    const customPorts = parsePortList(document.getElementById('wizard-custom-ports')?.value);

    const payload = {
        custom_name: name,
        profile: prof,
        preset_id: presetId,
        designated_nvr_ip: designatedNvr,
        auto_quarantine_override: quarOverride,
        custom_allowed_ports: customPorts.length > 0 ? customPorts : null,
        tv_pre_record_seconds: tvPre,
        tv_post_record_seconds: tvPost,
        tv_day_mode: tvDay,
        run_initial_audit: runAudit,
        audit_duration_seconds: 60
    };

    try {
        const res = await fetch(`/api/wizard/device/${encodeURIComponent(currentDeviceWizardMac)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            const data = await res.json();
            closeDeviceWizard();
            showToast('Устройство успешно настроено через мастер!', 'success');
            if (data.audit_started) {
                showToast('Запущен экспресс-аудит сетевого трафика (60 сек)', 'info');
            }
            await refreshAllData();
        } else {
            const err = await res.json().catch(() => ({}));
            showToast(`Ошибка сохранения: ${err.detail || 'Не удалось применить настройки'}`, 'error');
        }
    } catch (e) {
        console.error('Error submitting wizard', e);
        showToast('Ошибка сети при сохранении настроек мастера', 'error');
    }
}

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
        select.innerHTML = '<option value="">Ошибка загрузки инцидентов</option>';
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
