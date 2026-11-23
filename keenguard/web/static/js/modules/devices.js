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
    return currentRouterPlatform === 'openwrt' ? "Роутер OpenWrt" : "Роутер Keenetic";
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
        <span class="${badgeColor}">[${escapeHtml((event.event_type || '').toUpperCase())}]</span>
        <span class="feed-desc text-slate-300 truncate flex-1">${escapeHtml(formattedDesc)}</span>
    `;

    feed.prepend(line);
    // Keep max 30 items
    while (feed.children.length > 30) {
        feed.removeChild(feed.lastChild);
    }
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
        <div class="bg-surface-950 border border-slate-800 rounded-2xl p-4 hover:border-indigo-500/50 transition cursor-pointer flex flex-col justify-between group shadow-sm ${dimmingClass}" data-mac="${escapeHtml(d.mac)}" onclick="openDeviceModal(this.dataset.mac)">
            <div>
                <div class="flex items-start justify-between">
                    <div class="flex items-center space-x-3">
                        <div class="p-2.5 rounded-xl ${prof.bg} ${prof.color}">
                            <i data-lucide="${prof.icon}" class="w-5 h-5"></i>
                        </div>
                        <div>
                            <h4 class="font-bold text-sm text-white group-hover:text-indigo-300 transition truncate max-w-[170px]">${escapeHtml(displayName)}</h4>
                            <p class="text-xs text-slate-400 font-mono">${escapeHtml(d.ip || 'Нет IP')} • ${escapeHtml(d.mac)}</p>
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
        <tr class="hover:bg-slate-800/40 transition cursor-pointer group ${dimmingClass}" data-mac="${escapeHtml(d.mac)}" onclick="openDeviceModal(this.dataset.mac)">
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
                <div class="text-slate-200 font-medium">${escapeHtml(d.ip || '—')}</div>
                <div class="text-[10px] text-slate-500">${escapeHtml(d.mac)}</div>
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
                <button data-mac="${escapeHtml(d.mac)}" onclick="openDeviceModal(this.dataset.mac)" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-indigo-600 text-slate-300 hover:text-white text-xs font-medium transition flex items-center space-x-1 ml-auto">
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

// Device Detail Modal Sub-Tabs (4 tabs: overview, policies, traffic, special)
function switchDeviceModalTab(tab) {
    const tabs = ['overview', 'policies', 'traffic', 'special'];
    const target = (tab === 'security' || tab === 'policies') ? 'policies' : tab;

    tabs.forEach(t => {
        const pane = document.getElementById(`modal-tab-${t}`);
        const btn = document.getElementById(`modal-tab-btn-${t}`);
        if (pane) {
            if (t === target) {
                pane.classList.remove('hidden');
            } else {
                pane.classList.add('hidden');
            }
        }
        if (btn) {
            if (t === target) {
                btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-indigo-400 bg-indigo-500/10 border border-indigo-500/30 flex items-center space-x-1.5 transition shrink-0';
            } else {
                btn.className = 'px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 flex items-center space-x-1.5 transition shrink-0';
            }
        }
    });

    if (target === 'traffic' && currentDeviceMac) {
        loadDeviceTrafficChart(currentDeviceMac);
    }
    if (window.lucide) lucide.createIcons();
}
window.switchDeviceModalTab = switchDeviceModalTab;
window.openDeviceModal = openDeviceModal;

// Device Detail Modal
async function openDeviceModal(mac) {
    if (!mac) return;
    currentDeviceMac = mac;
    switchDeviceModalTab('overview');
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

        // 1. Header & Identity
        const nameEl = document.getElementById('modal-dev-name');
        if (nameEl) nameEl.textContent = d.custom_name || d.hostname || d.mac;
        const macEl = document.getElementById('modal-dev-mac');
        if (macEl) macEl.textContent = d.mac;
        const iconContainer = document.getElementById('modal-dev-icon');
        if (iconContainer) {
            iconContainer.className = `p-2 rounded-xl ${prof.bg} ${prof.color}`;
            iconContainer.innerHTML = `<i data-lucide="${prof.icon}" class="w-5 h-5"></i>`;
        }

        // 2. Tab 1: Overview
        const ipEl = document.getElementById('modal-dev-ip');
        if (ipEl) ipEl.textContent = d.ip || 'Не назначен';
        const vendorEl = document.getElementById('modal-dev-vendor');
        if (vendorEl) vendorEl.textContent = d.vendor || 'Неизвестен';

        const macTypeEl = document.getElementById('modal-dev-mac-type');
        if (macTypeEl) {
            if (d.is_random_mac) {
                macTypeEl.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-amber-500/15 text-amber-300 border border-amber-500/30">Случайный (LAA)</span>';
            } else {
                macTypeEl.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">Заводской OUI</span>';
            }
        }

        const segDispEl = document.getElementById('modal-dev-segment-disp');
        if (segDispEl) {
            segDispEl.textContent = d.segment ? `${d.segment} (${d.segment.toLowerCase().includes('guest') ? 'Bridge1' : 'Bridge0'})` : 'Bridge0 (Home)';
        }

        const statusEl = document.getElementById('modal-dev-status-text');
        if (statusEl) {
            if (d.is_online) {
                statusEl.innerHTML = '<span class="text-emerald-400 font-bold">● В сети</span>';
            } else {
                statusEl.innerHTML = '<span class="text-slate-400 font-medium">○ Офлайн</span>';
            }
        }

        const rssiEl = document.getElementById('modal-dev-rssi-text');
        if (rssiEl) {
            if (d.rssi !== null && d.rssi !== undefined) {
                rssiEl.textContent = `${d.rssi} dBm`;
            } else if ((d.interface || '').toLowerCase().includes('eth') || (d.interface || '').toLowerCase().includes('port') || (d.interface || '').toLowerCase().includes('lan')) {
                rssiEl.textContent = 'Проводное (LAN)';
            } else {
                rssiEl.textContent = 'Wi-Fi';
            }
        }

        const bandEl = document.getElementById('modal-dev-band-text');
        if (bandEl) {
            const iface = (d.interface || '').toLowerCase();
            if (iface.includes('5g') || iface.includes('wifimaster1')) {
                bandEl.textContent = 'Wi-Fi 5 GHz';
            } else if (iface.includes('wifi') || iface.includes('wifimaster0')) {
                bandEl.textContent = 'Wi-Fi 2.4 GHz';
            } else if (iface.includes('eth') || iface.includes('lan') || iface.includes('port')) {
                bandEl.textContent = 'Ethernet LAN';
            } else {
                bandEl.textContent = d.interface || 'Локальный порт';
            }
        }

        const seenEl = document.getElementById('modal-dev-seen-text');
        if (seenEl) {
            const first = d.first_seen ? d.first_seen.substring(0, 10) : '-';
            const last = d.last_seen ? d.last_seen.substring(11, 16) : '-';
            seenEl.textContent = `Первый: ${first} • Активность: ${last}`;
        }

        const customNameInp = document.getElementById('modal-dev-custom-name-input');
        if (customNameInp) customNameInp.value = d.custom_name || '';

        // MAC Randomization Banner
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
                    const cleanHostname = rg.hostname || 'Без имени';
                    if (rotTitle) {
                        if (role === 'hardware') {
                            rotTitle.textContent = `Заводской физический MAC («${cleanHostname}»)`;
                        } else if (role === 'active_random') {
                            rotTitle.textContent = `Активный приватный MAC («${cleanHostname}»)`;
                        } else {
                            rotTitle.textContent = `Ротированный MAC (история) («${cleanHostname}»)`;
                        }
                    }
                    html += `<p class="font-medium text-slate-200">Обнаружено <b>${rg.alias_count} MAC-адреса</b> с сетевым именем «${escapeHtml(rg.hostname)}».</p>`;
                    if (rg.hardware_mac) {
                        const isCurHw = (rg.hardware_mac === d.mac);
                        html += `<p class="font-mono text-[10px] text-slate-400">Постоянный заводской MAC: <span class="text-indigo-300 font-semibold">${escapeHtml(rg.hardware_mac)}</span>${isCurHw ? ' <span class="text-emerald-400">(открыт)</span>' : ''}</p>`;
                    }
                    if (rg.active_mac) {
                        const isCurAct = (rg.active_mac === d.mac);
                        html += `<p class="font-mono text-[10px] text-slate-400">Текущий активный MAC в сети: <span class="text-teal-300 font-semibold">${escapeHtml(rg.active_mac)}</span>${isCurAct ? ' <span class="text-teal-400">(это устройство)</span>' : ''}</p>`;
                    }
                    if (rg.other_macs && rg.other_macs.length > 0) {
                        html += `<p class="font-mono text-[10px] text-slate-400">Связанные адреса (алиасы): <span class="text-amber-300">${escapeHtml(rg.other_macs.join(', '))}</span></p>`;
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

        // MAC Group actions & Linked WAN toggle box
        const rotActions = document.getElementById('modal-mac-rotation-actions');
        const wanLinkedBox = document.getElementById('modal-wan-linked-box');
        const wanLinkedCount = document.getElementById('modal-wan-linked-count');
        const wanApplyLinked = document.getElementById('modal-wan-apply-to-linked');

        if (d.rotation_group && d.rotation_group.alias_count > 1) {
            if (rotActions) rotActions.classList.remove('hidden');
            if (wanLinkedBox) {
                wanLinkedBox.classList.remove('hidden');
                if (wanLinkedCount) wanLinkedCount.textContent = String(d.rotation_group.alias_count);
                if (wanApplyLinked) wanApplyLinked.checked = false;
            }
        } else {
            if (rotActions) rotActions.classList.add('hidden');
            if (wanLinkedBox) wanLinkedBox.classList.add('hidden');
        }

        // 3. Tab 2: Security & Policies
        const profSelect = document.getElementById('modal-profile-select');
        if (profSelect) profSelect.value = d.profile || 'unassigned';
        const wanToggle = document.getElementById('modal-toggle-wan');
        if (wanToggle) wanToggle.checked = Boolean(d.is_blocked_wan);

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
        const customPortsStatus = document.getElementById('modal-custom-ports-status');
        if (customPortsStatus) customPortsStatus.classList.add('hidden');

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
                lanBadge.innerHTML = '<span class="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">🔒 Изолирован (Гостевая сеть / VLAN)</span>';
                if (lanSub) lanSub.textContent = "Аппаратная изоляция: L2-доступ к другим клиентам заблокирован роутером.";
            } else {
                lanBadge.innerHTML = `
                    <div class="flex flex-col items-end gap-1">
                        <span class="px-2 py-0.5 rounded text-[10px] font-medium bg-rose-500/15 text-rose-300 border border-rose-500/30 whitespace-nowrap">⚠️ В Bridge0 (L2 доступ)</span>
                        <button type="button" data-mac="${escapeHtml(d.mac)}" onclick="openIsolationWizard(this.dataset.mac)" class="px-2 py-0.5 rounded bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-300 text-[10px] font-medium border border-indigo-500/30 transition flex items-center space-x-1 whitespace-nowrap cursor-pointer">
                            <i data-lucide="help-circle" class="w-3 h-3"></i>
                            <span>Как изолировать?</span>
                        </button>
                    </div>
                `;
                if (lanSub) lanSub.textContent = "L2-трафик идет в обход файрвола роутера. Для реальной изоляции требуется перенос в Гостевую сеть или отдельный сегмент.";
            }
        }

        // Smart Segmentation recommendation banner toggle
        const tipEl = document.getElementById('modal-segmentation-tip');
        if (tipEl) {
            const isSegmentable = d.profile === 'smart_home_hub' || d.profile === 'iot';
            if (isSegmentable) {
                tipEl.classList.remove('hidden');
                tipEl.removeAttribute('open');
            } else {
                tipEl.classList.add('hidden');
            }
        }

        // 4. Tab 3: Traffic & Shaper
        const shaperBadge = document.getElementById('modal-shaper-badge');
        const shaperPreset = document.getElementById('modal-shaper-preset-select');
        const shaperCustom = document.getElementById('modal-shaper-custom-input');
        const curLimit = d.bandwidth_limit_kbps || 0;
        if (shaperBadge) {
            shaperBadge.textContent = curLimit > 0 ? (curLimit >= 1024 ? `${(curLimit / 1024).toFixed(1)} Мбит/с` : `${curLimit} Кбит/с`) : 'Без ограничений';
        }
        if (shaperPreset && shaperCustom) {
            const presetValues = ['0', '512', '2048', '5120', '15360'];
            if (presetValues.includes(String(curLimit))) {
                shaperPreset.value = String(curLimit);
                shaperCustom.classList.add('hidden');
                shaperCustom.value = '';
            } else {
                shaperPreset.value = 'custom';
                shaperCustom.classList.remove('hidden');
                shaperCustom.value = curLimit > 0 ? curLimit : '';
            }
        }

        // 5. Tab 4: Special (TV, Camera, Notes)
        const isSpecialDevice = (d.profile === 'smart_tv' || d.profile === 'camera');
        const specialBadge = document.getElementById('modal-special-badge');
        if (specialBadge) {
            if (isSpecialDevice) specialBadge.classList.remove('hidden');
            else specialBadge.classList.add('hidden');
        }

        const tvBlock = document.getElementById('modal-special-tv-block');
        if (tvBlock) {
            if (d.profile === 'smart_tv') {
                tvBlock.classList.remove('hidden');
                const airToggle = document.getElementById('modal-toggle-airplay');
                if (airToggle) airToggle.checked = Boolean(d.airplay_allowed);
                const dlnaToggle = document.getElementById('modal-toggle-dlna');
                if (dlnaToggle) dlnaToggle.checked = d.dlna_allowed !== false;
                const nightToggle = document.getElementById('modal-toggle-night');
                if (nightToggle) nightToggle.checked = Boolean(d.night_mode_enabled);
            } else {
                tvBlock.classList.add('hidden');
            }
        }

        const camBlock = document.getElementById('modal-special-camera-block');
        if (camBlock) {
            if (d.profile === 'camera') {
                camBlock.classList.remove('hidden');
                const nvrInput = document.getElementById('modal-nvr-ip');
                if (nvrInput) nvrInput.value = d.designated_nvr_ip || '';
            } else {
                camBlock.classList.add('hidden');
            }
        }

        const notesInp = document.getElementById('modal-dev-notes-input');
        if (notesInp) notesInp.value = d.notes || '';

        // Offline device deletion button
        const delDevBtn = document.getElementById('btn-delete-device-modal');
        if (delDevBtn) {
            if (!d.is_online) {
                delDevBtn.classList.remove('hidden');
            } else {
                delDevBtn.classList.add('hidden');
            }
        }

        if (window.lucide) lucide.createIcons();

        await checkDeviceAuditState(mac);
        loadDeviceTrafficChart(mac);

    } catch (e) {
        console.error('Error opening device modal', e);
    }
}

function onModalShaperPresetChange(val) {
    const customInp = document.getElementById('modal-shaper-custom-input');
    if (!customInp) return;
    if (val === 'custom') {
        customInp.classList.remove('hidden');
        customInp.focus();
    } else {
        customInp.classList.add('hidden');
        customInp.value = val;
    }
}
window.onModalShaperPresetChange = onModalShaperPresetChange;

async function applyModalSpeedLimit() {
    if (!currentDeviceMac) return;
    const select = document.getElementById('modal-shaper-preset-select');
    const customInp = document.getElementById('modal-shaper-custom-input');
    let speed = 0;
    if (select && select.value === 'custom' && customInp) {
        speed = parseInt(customInp.value, 10) || 0;
    } else if (select) {
        speed = parseInt(select.value, 10) || 0;
    }

    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/speed-limit`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ speed_kbps: speed })
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }
        const textSpeed = speed > 0 ? (speed >= 1024 ? `${(speed / 1024).toFixed(1)} Мбит/с` : `${speed} Кбит/с`) : 'Без ограничений';
        showToast(speed > 0 ? `Лимит скорости установлен: ${textSpeed}` : 'Ограничение скорости снято');
        const badge = document.getElementById('modal-shaper-badge');
        if (badge) badge.textContent = textSpeed;
        await loadDevices();
    } catch (e) {
        console.error('Failed to set speed limit', e);
        showToast(`Ошибка: ${e.message}`, true);
    }
}
window.applyModalSpeedLimit = applyModalSpeedLimit;

async function saveModalCustomName(name) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/rename`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ custom_name: (name || '').trim() })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        showToast('Имя устройства обновлено');
        const nameEl = document.getElementById('modal-dev-name');
        if (nameEl) nameEl.textContent = name.trim() || currentDeviceMac;
        await loadDevices();
    } catch (e) {
        console.error('Failed to rename device', e);
        showToast('Ошибка при переименовании устройства', true);
    }
}
window.saveModalCustomName = saveModalCustomName;

async function saveModalNotes(notes) {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${encodeURIComponent(currentDeviceMac)}/notes`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: notes || '' })
        });
        if (res.ok) {
            showToast('Заметка сохранена');
        } else {
            throw new Error(`HTTP ${res.status}`);
        }
    } catch (e) {
        console.error('Failed to save notes', e);
        showToast('Ошибка сохранения заметки', true);
    }
}
window.saveModalNotes = saveModalNotes;

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
    const applyLinked = Boolean(document.getElementById('modal-wan-apply-to-linked')?.checked);
    await fetch(`/api/devices/${currentDeviceMac}/toggle_wan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: val, apply_to_linked: applyLinked })
    });
    loadDevices();
}

async function applyGroupPolicy() {
    if (!currentDeviceMac) return;
    try {
        const res = await fetch(`/api/devices/${currentDeviceMac}/apply_policy_to_group`, {
            method: 'POST'
        });
        const data = await res.json();
        if (res.ok && data.status === 'ok') {
            showToast(`Политика безопасности применена ко всем адресам устройства (${data.count} обновлено)`);
            await loadDevices();
        } else {
            showToast(data.message || 'Ошибка применения политики', true);
        }
    } catch (e) {
        showToast(`Ошибка синхронизации группы: ${e.message}`, true);
    }
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
    try {
        await fetch(`/api/devices/${currentDeviceMac}/toggle_dlna`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: val })
        });
        loadDevices();
    } catch (e) {
        console.error('Failed to toggle DLNA:', e);
    }
}

async function toggleModalNight(val) {
    if (!currentDeviceMac) return;
    try {
        await fetch(`/api/devices/${currentDeviceMac}/toggle_night`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: val })
        });
        loadDevices();
    } catch (e) {
        console.error('Failed to toggle Night Mode:', e);
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
        const rxData = history.map(h => Math.max(0, h.rx_rate_kbps || 0));
        const txData = history.map(h => Math.max(0, h.tx_rate_kbps || 0));

        if (history.length > 0) {
            const latest = history[history.length - 1];
            const rateElem = document.getElementById('modal-traffic-rate-now');
            if (rateElem) {
                rateElem.textContent = `↓ ${Math.max(0, latest.rx_rate_kbps || 0)} Kbps  ↑ ${Math.max(0, latest.tx_rate_kbps || 0)} Kbps`;
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
                        fill: true,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHitRadius: 10
                    },
                    {
                        label: 'Исходящий (Tx)',
                        data: txData.length ? txData : [0],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        borderWidth: 1.5,
                        tension: 0.3,
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
                plugins: { legend: { display: false } },
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
    } catch (e) {
        console.error('Error loading device traffic chart', e);
    }
}


// Data Export
function exportData(type, format) {
    const link = document.createElement('a');
    link.href = `/api/export/${type}?format=${format}`;
    link.download = `${type}_export.${format}`;
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
        if (link && link.parentNode) link.parentNode.removeChild(link);
    }, 150);
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
            const statusEl = document.getElementById('modal-custom-ports-status');
            if (statusEl) {
                statusEl.classList.remove('hidden');
                if (typeof lucide !== 'undefined') lucide.createIcons();
                setTimeout(() => { statusEl.classList.add('hidden'); }, 3500);
            }
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
                                        <button type="button" data-preset-id="${escapeHtml(p.id)}" onclick="openCustomPresetModal(this.dataset.presetId)" class="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition" title="Редактировать">
                                            <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
                                        </button>
                                        <button type="button" data-preset-id="${escapeHtml(p.id)}" onclick="deleteCustomPreset(this.dataset.presetId)" class="p-1 text-slate-400 hover:text-rose-400 rounded hover:bg-slate-800 transition" title="Удалить">
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
            const allowed = rules.allowed_services || rules.allowed_ports || [];
            const alertPorts = rules.alert_services || rules.alert_ports || [];
            const blocked = rules.blocked_services || rules.quarantine_ports || [];
            if (allowedInput) allowedInput.value = allowed.join(', ');
            if (alertInput) alertInput.value = alertPorts.join(', ');
            if (quarInput) quarInput.value = blocked.join(', ');
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
        .map(s => {
            const trimmed = s.trim();
            if (!trimmed) return null;
            const n = parseInt(trimmed, 10);
            return (!isNaN(n) && String(n) === trimmed && n > 0 && n <= 65535) ? n : trimmed;
        })
        .filter(x => x !== null && x !== '');
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

    const isEdit = idInput.disabled;
    const existingPreset = isEdit ? allLanPresets.find(x => x.id === presetId) : null;
    const existingRules = existingPreset ? (existingPreset.rules || {}) : {};

    const allowed = parsePortList(allowedInput.value);
    const alertList = parsePortList(alertInput.value);
    const blocked = parsePortList(quarInput.value);

    // Numeric port subsets for backward compatibility
    const allowedPortsNum = allowed.filter(x => typeof x === 'number');
    const alertPortsNum = alertList.filter(x => typeof x === 'number');
    const quarPortsNum = blocked.filter(x => typeof x === 'number');

    const payload = {
        id: presetId,
        name: (nameInput.value || '').trim(),
        description: (descInput.value || '').trim(),
        rules: {
            allowed_services: allowed,
            alert_services: alertList,
            blocked_services: blocked,
            lan_to_lan_policy: existingRules.lan_to_lan_policy || (blocked.includes('*') ? 'isolated' : 'restricted'),
            // Backward compatibility
            allowed_ports: allowedPortsNum,
            alert_ports: alertPortsNum,
            quarantine_ports: quarPortsNum
        }
    };

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
            <div data-preset-id="${escapeHtml(p.id)}" onclick="deviceWizardSelectPreset(this.dataset.presetId)" class="p-2.5 rounded-xl border transition cursor-pointer flex items-start space-x-3 ${isSelected ? 'bg-indigo-950/40 border-indigo-500 shadow-md shadow-indigo-500/10' : 'bg-surface-950 border-slate-800 hover:border-slate-700'}">
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

