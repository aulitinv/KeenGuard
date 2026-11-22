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

            const srcClickable = srcMac ? `<button onclick="openDeviceModal('${escapeHtml(srcMac)}')" class="text-cyan-400 hover:text-cyan-300 hover:underline truncate max-w-[130px] text-left transition font-semibold" title="${escapeHtml(srcLabel)}">${escapeHtml(srcLabel)}</button>` : `<span class="text-cyan-400 truncate max-w-[130px]" title="${escapeHtml(srcLabel)}">${escapeHtml(srcLabel)}</span>`;
            const dstClickable = dstMac ? `<button onclick="openDeviceModal('${escapeHtml(dstMac)}')" class="text-indigo-400 hover:text-indigo-300 hover:underline truncate max-w-[130px] text-left transition font-semibold" title="${escapeHtml(dstLabel)}">${escapeHtml(dstLabel)}</button>` : `<span class="text-indigo-400 truncate max-w-[130px]" title="${escapeHtml(dstLabel)}">${escapeHtml(dstLabel)}</span>`;

            return `
                <div class="bg-surface-950 border border-slate-800 rounded-xl p-3.5 space-y-2 hover:border-cyan-500/40 transition shadow-sm">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-1.5 font-mono text-xs font-semibold text-slate-200">
                            ${srcClickable}
                            <span class="text-slate-500">⇄</span>
                            ${dstClickable}
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

