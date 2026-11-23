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
                <tr class="${rowClass}" data-pkt-id="${escapeHtml(p.pkt_id)}" onclick="selectPacketForInspection(this.dataset.pktId)" title="Нажмите для анализа слоев OSI и Hex-дампа">
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
        const fieldsEntries = Array.isArray(layer.fields)
            ? layer.fields.map(f => [f.name || f.key || 'Поле', f.value ?? f.val])
            : Object.entries(layer.fields || {});
        const fieldsHtml = fieldsEntries.map(([k, v]) => {
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
            if (f.category === 'tv_wake' || f.category === 'ТВ-форензика' || f.category === 'forensics') {
                catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-purple-500/20 text-purple-300">Форензика ТВ</span>`;
            } else if (f.category === 'audit' || f.category === 'Аудит устройства') {
                catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-indigo-500/20 text-indigo-300">Аудит</span>`;
            } else if (f.category === 'upload' || f.category === 'Загруженный дамп') {
                catBadge = `<span class="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-emerald-500/20 text-emerald-300">Загруженный</span>`;
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
                    <button data-filename="${escapeHtml(f.filename)}" onclick="loadSavedPcapToInspector(this.dataset.filename)" class="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shrink-0 transition flex items-center space-x-1">
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
        const loadedCount = data.loaded_packets ?? data.total_packets ?? 0;
        showToast(`Файл обработан: ${loadedCount} пакетов`, 'success');

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

