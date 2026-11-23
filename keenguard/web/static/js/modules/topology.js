// ==========================================
// TAB: INTERACTIVE NETWORK TOPOLOGY MAP (PLAN 09)
// ==========================================

let topologyData = null;
let topologyRawNodes = [];
let topologyRawLinks = [];
let topologyNodes = [];
let topologyLinks = [];
let currentTopologyFilter = 'all';
let isTopologyFullscreen = false;
let topologyTransform = { x: 0, y: 0, scale: 1 };
let isPanningTopology = false;
let panStart = { x: 0, y: 0 };
let draggedNode = null;
let topologyAnimFrame = null;

async function loadTopologyTab() {
    const realismNoteEl = document.getElementById('topology-realism-note');
    const devBadge = document.getElementById('topology-device-count-badge');
    const onlineBadge = document.getElementById('topology-online-badge');

    try {
        const res = await fetch('/api/network/topology');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        topologyData = await res.json();

        if (devBadge) devBadge.textContent = `${topologyData.meta?.total_devices || 0} устройств`;
        if (onlineBadge) onlineBadge.textContent = `${topologyData.meta?.online_devices || 0} онлайн`;
        if (realismNoteEl && topologyData.meta?.l2_realism_note) {
            realismNoteEl.textContent = topologyData.meta.l2_realism_note;
        }

        initTopologyGraph(topologyData);
    } catch (e) {
        console.error('Failed to load network topology', e);
        showToast(`Ошибка загрузки топологии: ${e.message}`, 'error');
    }
}
window.loadTopologyTab = loadTopologyTab;

function initTopologyGraph(data) {
    const svg = document.getElementById('topology-svg');
    if (!svg) return;

    topologyTransform = { x: 0, y: 0, scale: 1 };
    applyTopologyTransform();

    topologyRawNodes = JSON.parse(JSON.stringify(data.nodes || []));
    topologyRawLinks = JSON.parse(JSON.stringify(data.links || []));

    applyTopologyFilterAndRender(false);
    setupTopologyInteraction(svg);
}

function applyTopologyFilterAndRender(preservePositions = true) {
    const svg = document.getElementById('topology-svg');
    if (!svg) return;

    const width = svg.clientWidth || 900;
    const height = svg.clientHeight || 650;
    const cx = width / 2;
    const cy = height / 2;

    const existingPosMap = {};
    if (preservePositions && topologyNodes && topologyNodes.length) {
        topologyNodes.forEach(n => {
            existingPosMap[n.id] = { x: n.x, y: n.y, fixed: n.fixed };
        });
    }

    const filteredNodes = topologyRawNodes.filter(n => {
        if (n.type !== 'device') return true;
        if (currentTopologyFilter === 'online') {
            return n.is_online === true;
        }
        if (currentTopologyFilter === 'hide_trusted') {
            return n.profile !== 'trusted';
        }
        if (currentTopologyFilter === 'iot_tv') {
            return ['smart_tv', 'camera', 'iot'].includes(n.profile);
        }
        if (currentTopologyFilter === 'quarantine') {
            return n.profile === 'quarantine' || n.is_wan_blocked;
        }
        return true;
    });

    const validNodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredLinks = topologyRawLinks.filter(l => validNodeIds.has(l.source) && validNodeIds.has(l.target));

    const nodeMap = {};
    filteredNodes.forEach(n => {
        nodeMap[n.id] = n;
        n.vx = 0;
        n.vy = 0;

        if (existingPosMap[n.id]) {
            n.x = existingPosMap[n.id].x;
            n.y = existingPosMap[n.id].y;
            n.fixed = existingPosMap[n.id].fixed;
            return;
        }

        if (n.id === 'node_internet') {
            n.x = cx - 120;
            n.y = 80;
            n.fixed = true;
        } else if (n.id === 'node_dns') {
            n.x = cx + 120;
            n.y = 80;
            n.fixed = true;
        } else if (n.id === 'node_router') {
            n.x = cx;
            n.y = 170;
            n.fixed = true;
        } else if (n.id === 'segment_Bridge0') {
            n.x = cx - 220;
            n.y = 280;
            n.fixed = true;
        } else if (n.id === 'segment_Bridge1') {
            n.x = cx + 220;
            n.y = 280;
            n.fixed = true;
        } else if (n.id === 'ap_wifi_24') {
            n.x = cx - 340;
            n.y = 390;
            n.fixed = true;
        } else if (n.id === 'ap_wifi_5') {
            n.x = cx - 220;
            n.y = 390;
            n.fixed = true;
        } else if (n.id === 'ap_lan') {
            n.x = cx - 100;
            n.y = 390;
            n.fixed = true;
        } else if (n.id === 'ap_guest') {
            n.x = cx + 220;
            n.y = 390;
            n.fixed = true;
        } else {
            n.fixed = false;
        }
    });

    // Compute orderly fan coordinates for all client devices (prevent overlapping and initial jitter)
    const apChildren = {};
    filteredNodes.forEach(n => {
        if (!['node_internet', 'node_dns', 'node_router', 'segment_Bridge0', 'segment_Bridge1', 'ap_wifi_24', 'ap_wifi_5', 'ap_lan', 'ap_guest'].includes(n.id)) {
            const parentId = n.parent_ap || n.segment_id || 'ap_wifi_24';
            if (!apChildren[parentId]) apChildren[parentId] = [];
            apChildren[parentId].push(n);
        }
    });

    Object.entries(apChildren).forEach(([parentId, children]) => {
        const parent = nodeMap[parentId] || { x: cx, y: 390 };
        const total = children.length;
        children.forEach((n, idx) => {
            if (existingPosMap[n.id]) {
                n.x = existingPosMap[n.id].x;
                n.y = existingPosMap[n.id].y;
                n.fixed = existingPosMap[n.id].fixed;
                return;
            }
            let tier = 0;
            let tierIdx = idx;
            let tierTotal = total;
            if (total > 6) {
                tier = idx % 2;
                tierIdx = Math.floor(idx / 2);
                tierTotal = Math.ceil(total / 2);
            }
            const radius = 95 + tier * 65;
            const startAngle = Math.PI * 0.12;
            const endAngle = Math.PI * 0.88;
            const step = tierTotal > 1 ? (endAngle - startAngle) / (tierTotal - 1) : 0;
            const angle = tierTotal > 1 ? (startAngle + tierIdx * step) : Math.PI * 0.5;

            const spreadFactor = (parentId === 'ap_wifi_24' || total > 8) ? 1.8 : 1.45;
            n.x = parent.x + Math.cos(angle) * radius * spreadFactor;
            n.y = parent.y + Math.sin(angle) * radius;
            n.vx = 0;
            n.vy = 0;
            n.fixed = false;
        });
    });

    const mappedLinks = [];
    filteredLinks.forEach(l => {
        const src = nodeMap[l.source];
        const tgt = nodeMap[l.target];
        if (src && tgt) {
            mappedLinks.push({
                ...l,
                sourceNode: src,
                targetNode: tgt
            });
        }
    });

    topologyNodes = filteredNodes;
    topologyLinks = mappedLinks;

    // Update filter chip UI active states
    const filterIds = ['all', 'online', 'hide_trusted', 'iot_tv', 'quarantine'];
    filterIds.forEach(f => {
        const btn = document.getElementById(`topo-filter-${f}`);
        if (!btn) return;
        if (f === currentTopologyFilter) {
            btn.className = 'topo-filter-chip px-3 py-1 rounded-lg text-xs font-semibold bg-purple-500/20 text-purple-300 border border-purple-500/40 transition';
        } else {
            btn.className = 'topo-filter-chip px-3 py-1 rounded-lg text-xs font-semibold bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200 transition';
        }
    });

    buildTopologyDomElements();
    runTopologySimulation();
}

function setTopologyFilter(filter) {
    currentTopologyFilter = filter;
    applyTopologyFilterAndRender(true);
}
window.setTopologyFilter = setTopologyFilter;

function toggleTopologyFullscreen() {
    const card = document.getElementById('topology-container-card');
    const icon = document.getElementById('topology-fullscreen-icon');
    if (!card) return;

    isTopologyFullscreen = !isTopologyFullscreen;
    if (isTopologyFullscreen) {
        card.classList.add('topology-fullscreen');
        if (icon) {
            icon.setAttribute('data-lucide', 'shrink');
            if (window.lucide) lucide.createIcons({ roots: [icon.parentElement] });
        }
    } else {
        card.classList.remove('topology-fullscreen');
        if (icon) {
            icon.setAttribute('data-lucide', 'expand');
            if (window.lucide) lucide.createIcons({ roots: [icon.parentElement] });
        }
    }

    setTimeout(() => {
        resetTopologyView();
        if (topologyData) {
            applyTopologyFilterAndRender(false);
        }
    }, 100);
}
window.toggleTopologyFullscreen = toggleTopologyFullscreen;

window.addEventListener('keydown', e => {
    if (e.key === 'Escape' && isTopologyFullscreen) {
        toggleTopologyFullscreen();
    }
});

function runTopologySimulation() {
    let iterations = 45;

    function step() {
        if (iterations <= 0 && !draggedNode) {
            updateTopologyPositions();
            return;
        }

        // 1. Repulsion between non-fixed nodes (only when overlapping or too close, < 70px)
        const repulsionDist = 105;
        for (let i = 0; i < topologyNodes.length; i++) {
            const n1 = topologyNodes[i];
            for (let j = i + 1; j < topologyNodes.length; j++) {
                const n2 = topologyNodes[j];
                const dx = n2.x - n1.x;
                const dy = n2.y - n1.y;
                const distSq = dx * dx + dy * dy || 1;
                const dist = Math.sqrt(distSq);

                if (dist < repulsionDist) {
                    const force = (repulsionDist - dist) / dist * 0.12;
                    if (!n1.fixed && n1 !== draggedNode) {
                        n1.vx -= dx * force;
                        n1.vy -= dy * force;
                    }
                    if (!n2.fixed && n2 !== draggedNode) {
                        n2.vx += dx * force;
                        n2.vy += dy * force;
                    }
                }
            }
        }

        // 2. Gentle spring force along links
        topologyLinks.forEach(link => {
            const s = link.sourceNode;
            const t = link.targetNode;
            if (!s || !t) return;
            const dx = t.x - s.x;
            const dy = t.y - s.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const targetDist = link.type === 'client' ? 105 : 90;
            const diff = (dist - targetDist) / dist * 0.04;

            if (!s.fixed && s !== draggedNode) {
                s.vx += dx * diff;
                s.vy += dy * diff;
            }
            if (!t.fixed && t !== draggedNode) {
                t.vx -= dx * diff;
                t.vy -= dy * diff;
            }
        });

        // 3. Velocity integration with 55% damping (friction eliminates all jitter/shaking)
        topologyNodes.forEach(n => {
            if (!n.fixed && n !== draggedNode) {
                n.vx *= 0.55;
                n.vy *= 0.55;
                n.x += n.vx;
                n.y += n.vy;

                // Deterministic floor constraint: client devices stay below the AP level (y >= 440)
                if (n.type === 'device' && n.y < 440) {
                    n.y = 440;
                    if (n.vy < 0) n.vy = 0;
                }
            }
        });

        // Fast attribute mutation - ZERO DOM recreation or innerHTML destruction!
        updateTopologyPositions();
        iterations--;

        if (iterations > 0 || draggedNode) {
            topologyAnimFrame = requestAnimationFrame(step);
        }
    }

    if (topologyAnimFrame) cancelAnimationFrame(topologyAnimFrame);
    topologyAnimFrame = requestAnimationFrame(step);
}

function buildTopologyDomElements() {
    const boundariesGroup = document.getElementById('topology-boundaries');
    const linksGroup = document.getElementById('topology-links');
    const nodesGroup = document.getElementById('topology-nodes');
    if (!linksGroup || !nodesGroup) return;

    if (boundariesGroup) {
        boundariesGroup.innerHTML = `
            <g id="topo-boundary-b0" class="topology-boundary-group" pointer-events="none" style="display: none;">
                <rect class="b-box" rx="20" ry="20" fill="rgba(16, 185, 129, 0.03)" stroke="rgba(16, 185, 129, 0.3)" stroke-dasharray="6,4" stroke-width="1.5" />
                <rect class="b-header" rx="6" ry="6" fill="#064e3b" opacity="0.9" stroke="rgba(16, 185, 129, 0.5)" stroke-width="1" width="265" height="22" />
                <text class="b-title" fill="#34d399" font-size="10" font-weight="700" font-family="system-ui, sans-serif">
                    Bridge0: Домашний сегмент (L2 общий домен)
                </text>
            </g>
            <g id="topo-boundary-b1" class="topology-boundary-group" pointer-events="none" style="display: none;">
                <rect class="b-box" rx="20" ry="20" fill="rgba(245, 158, 11, 0.03)" stroke="rgba(245, 158, 11, 0.3)" stroke-dasharray="6,4" stroke-width="1.5" />
                <rect class="b-header" rx="6" ry="6" fill="#78350f" opacity="0.9" stroke="rgba(245, 158, 11, 0.5)" stroke-width="1" width="275" height="22" />
                <text class="b-title" fill="#fbbf24" font-size="10" font-weight="700" font-family="system-ui, sans-serif">
                    Bridge1: Гостевой сегмент (L2/L3 изоляция)
                </text>
            </g>
        `;
    }

    linksGroup.innerHTML = topologyLinks.map((l, idx) => {
        let strokeColor = '#334155';
        let strokeWidth = '1.5';
        let strokeDash = '';

        if (l.type === 'wan') {
            strokeColor = l.status === 'active' ? '#06b6d4' : '#64748b';
            strokeWidth = '2.5';
        } else if (l.type === 'dns') {
            strokeColor = '#10b981';
            strokeWidth = '2';
        } else if (l.type === 'trunk') {
            strokeColor = '#3b82f6';
            strokeWidth = '2.5';
        } else if (l.type === 'uplink') {
            strokeColor = '#64748b';
            strokeWidth = '1.5';
        } else if (l.type === 'client') {
            if (l.is_wan_blocked) {
                strokeColor = '#f43f5e';
                strokeWidth = '2';
            } else if (!l.is_online) {
                strokeColor = '#475569';
                strokeDash = 'stroke-dasharray="4,4"';
                strokeWidth = '1';
            } else {
                strokeColor = '#059669';
                strokeWidth = '1.5';
            }
        }

        return `<line id="topo-link-${idx}" stroke="${strokeColor}" stroke-width="${strokeWidth}" ${strokeDash} opacity="0.75" />`;
    }).join('');

    nodesGroup.innerHTML = topologyNodes.map(n => {
        let r = 18;
        let fill = '#0f172a';
        let stroke = '#64748b';
        let strokeWidth = '2';
        let labelColor = '#e2e8f0';

        if (n.type === 'router') {
            r = 28;
            fill = 'url(#grad-router)';
            stroke = '#06b6d4';
            strokeWidth = '3';
        } else if (n.type === 'wan') {
            r = 22;
            fill = '#1e1b4b';
            stroke = '#818cf8';
            strokeWidth = '2.5';
        } else if (n.type === 'dns') {
            r = 20;
            fill = '#064e3b';
            stroke = '#34d399';
            strokeWidth = '2';
        } else if (n.type === 'segment') {
            r = 24;
            if (n.id === 'segment_Bridge0') {
                fill = 'url(#grad-bridge0)';
                stroke = '#10b981';
            } else {
                fill = 'url(#grad-bridge1)';
                stroke = '#f59e0b';
            }
            strokeWidth = '2.5';
        } else if (n.type === 'access_point') {
            r = 18;
            fill = '#1e293b';
            stroke = '#94a3b8';
            strokeWidth = '1.5';
        } else if (n.type === 'device') {
            r = 16;
            if (n.is_wan_blocked || n.profile === 'quarantine') {
                fill = '#881337';
                stroke = '#f43f5e';
                strokeWidth = '2.5';
            } else if (!n.is_online) {
                fill = '#1e293b';
                stroke = '#475569';
                labelColor = '#94a3b8';
            } else if (n.profile === 'trusted') {
                fill = '#064e3b';
                stroke = '#10b981';
            } else if (['smart_tv', 'camera', 'iot'].includes(n.profile)) {
                fill = '#78350f';
                stroke = '#fbbf24';
            } else {
                fill = '#083344';
                stroke = '#22d3ee';
            }
        }

        const rawLabel = n.type === 'segment' ? (n.label || n.details?.interface || n.id || 'Сегмент') : (n.label || '');
        const shortLabel = rawLabel.length > 14 ? rawLabel.substring(0, 12) + '…' : rawLabel;
        const cursor = 'cursor-pointer';

        return `
            <g id="topo-node-${n.id}" class="topology-node-group ${cursor}" data-id="${n.id}" data-mac="${escapeHtml(n.mac || '')}" data-type="${escapeHtml(n.type || '')}" transform="translate(${n.x},${n.y})" style="cursor: pointer;">
                <circle r="${r + 14}" fill="transparent" class="topology-hit-circle" style="cursor: pointer;" />
                <circle r="${r + 4}" fill="${stroke}" opacity="0.15" />
                <circle r="${r}" fill="${fill}" stroke="${stroke}" stroke-width="${strokeWidth}" />
                <text y="${r + 14}" text-anchor="middle" font-size="10" font-weight="600" fill="${labelColor}" font-family="system-ui, sans-serif" style="text-shadow: 0 1px 3px rgba(0,0,0,0.9); cursor: pointer; user-select: none;">
                    ${escapeHtml(shortLabel)}
                </text>
            </g>
        `;
    }).join('');

    updateTopologyPositions();
}

function updateTopologyPositions() {
    // 1. Update Boundaries
    const b0Nodes = topologyNodes.filter(n => n.id === 'segment_Bridge0' || n.segment_id === 'segment_Bridge0' || ['ap_wifi_24', 'ap_wifi_5', 'ap_lan'].includes(n.id));
    const b0El = document.getElementById('topo-boundary-b0');
    if (b0El) {
        if (b0Nodes.length > 0) {
            let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
            b0Nodes.forEach(n => {
                if (n.x < minX) minX = n.x;
                if (n.x > maxX) maxX = n.x;
                if (n.y < minY) minY = n.y;
                if (n.y > maxY) maxY = n.y;
            });
            const pad = 55;
            const w = Math.max((maxX - minX) + pad * 2, 280);
            const h = (maxY - minY) + pad * 2;
            const x = minX - pad;
            const y = minY - pad;
            b0El.style.display = '';
            const box = b0El.querySelector('.b-box');
            if (box) { box.setAttribute('x', x); box.setAttribute('y', y); box.setAttribute('width', w); box.setAttribute('height', h); }
            const header = b0El.querySelector('.b-header');
            if (header) { header.setAttribute('x', x); header.setAttribute('y', y); }
            const text = b0El.querySelector('.b-title');
            if (text) { text.setAttribute('x', x + 10); text.setAttribute('y', y + 15); }
        } else {
            b0El.style.display = 'none';
        }
    }

    const b1Nodes = topologyNodes.filter(n => n.id === 'segment_Bridge1' || n.segment_id === 'segment_Bridge1' || n.id === 'ap_guest');
    const b1El = document.getElementById('topo-boundary-b1');
    if (b1El) {
        if (b1Nodes.length > 0) {
            let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
            b1Nodes.forEach(n => {
                if (n.x < minX) minX = n.x;
                if (n.x > maxX) maxX = n.x;
                if (n.y < minY) minY = n.y;
                if (n.y > maxY) maxY = n.y;
            });
            const pad = 55;
            const w = Math.max((maxX - minX) + pad * 2, 280);
            const h = (maxY - minY) + pad * 2;
            const x = minX - pad;
            const y = minY - pad;
            b1El.style.display = '';
            const box = b1El.querySelector('.b-box');
            if (box) { box.setAttribute('x', x); box.setAttribute('y', y); box.setAttribute('width', w); box.setAttribute('height', h); }
            const header = b1El.querySelector('.b-header');
            if (header) { header.setAttribute('x', x); header.setAttribute('y', y); }
            const text = b1El.querySelector('.b-title');
            if (text) { text.setAttribute('x', x + 10); text.setAttribute('y', y + 15); }
        } else {
            b1El.style.display = 'none';
        }
    }

    // 2. Update Links positions
    topologyLinks.forEach((l, idx) => {
        const line = document.getElementById(`topo-link-${idx}`);
        if (line && l.sourceNode && l.targetNode) {
            line.setAttribute('x1', l.sourceNode.x);
            line.setAttribute('y1', l.sourceNode.y);
            line.setAttribute('x2', l.targetNode.x);
            line.setAttribute('y2', l.targetNode.y);
        }
    });

    // 3. Update Nodes positions (via transform="translate(x, y)")
    topologyNodes.forEach(n => {
        const el = document.getElementById(`topo-node-${n.id}`);
        if (el) {
            el.setAttribute('transform', `translate(${n.x},${n.y})`);
        }
    });
}

function renderTopologyElements() {
    buildTopologyDomElements();
}

function setupTopologyInteraction(svg) {
    if (svg._topoInit) return;
    svg._topoInit = true;

    const tooltip = document.getElementById('topology-tooltip');

    let dragCandidate = null;
    let isDraggingNode = false;
    let hasJustDragged = false;
    let lastHandledNodeClickTime = 0;

    function handleTopologyNodeClick(n) {
        if (!n) return;
        const now = Date.now();
        if (now - lastHandledNodeClickTime < 350) return;
        lastHandledNodeClickTime = now;

        if (tooltip) tooltip.classList.add('hidden');

        if (n.type === 'device' && n.mac) {
            openDeviceModal(n.mac);
        } else if (n.type === 'router' || n.id === 'node_router') {
            switchTab('settings');
            showToast('Параметры роутера Keenetic в разделе «Настройки»', 'info');
        } else if (n.type === 'dns' || n.id === 'node_dns') {
            switchTab('dns');
            showToast('DNS трансляция: запросы и фильтрация', 'info');
        } else if (n.type === 'segment' || n.id?.startsWith('segment_')) {
            const segName = n.id === 'segment_Bridge1' 
                ? 'Гостевой сегмент (Bridge1): аппаратная L2 и L3 изоляция включена на роутере.' 
                : 'Домашний сегмент (Bridge0): общий L2 домен (L2 трафик идет напрямую в обход Keenetic).';
            showToast(segName, 'info');
        } else if (n.type === 'wan' || n.id === 'node_internet') {
            showToast(`Внешний WAN интерфейс: ${n.label || 'Интернет'}`, 'info');
        } else if (n.type === 'access_point' || n.id?.startsWith('ap_')) {
            showToast(`Точка подключения: ${n.label || n.id}`, 'info');
        }
    }

    svg.addEventListener('mousedown', e => {
        const targetNodeEl = e.target.closest('.topology-node-group');
        if (targetNodeEl) {
            const nodeId = targetNodeEl.getAttribute('data-id');
            const node = topologyNodes.find(n => n.id === nodeId);
            if (node) {
                // Do not immediately recreate DOM elements or drag; record as candidate
                dragCandidate = {
                    node: node,
                    startX: e.clientX,
                    startY: e.clientY
                };
                isDraggingNode = false;
                return;
            }
        }

        isPanningTopology = true;
        panStart = { x: e.clientX - topologyTransform.x, y: e.clientY - topologyTransform.y };
    });

    window.addEventListener('mousemove', e => {
        // Only initiate physics drag if mouse actually moved beyond threshold
        if (dragCandidate && !isDraggingNode) {
            const dist = Math.hypot(e.clientX - dragCandidate.startX, e.clientY - dragCandidate.startY);
            if (dist > 5) {
                isDraggingNode = true;
                draggedNode = dragCandidate.node;
                draggedNode.fixed = true;
                draggedNode.vx = 0;
                draggedNode.vy = 0;
                runTopologySimulation();
            }
        }

        if (draggedNode && isDraggingNode) {
            const rect = svg.getBoundingClientRect();
            draggedNode.x = (e.clientX - rect.left - topologyTransform.x) / topologyTransform.scale;
            draggedNode.y = (e.clientY - rect.top - topologyTransform.y) / topologyTransform.scale;
            draggedNode.vx = 0;
            draggedNode.vy = 0;
            updateTopologyPositions();
            return;
        }

        if (isPanningTopology) {
            topologyTransform.x = e.clientX - panStart.x;
            topologyTransform.y = e.clientY - panStart.y;
            applyTopologyTransform();
            return;
        }

        const targetNodeEl = e.target.closest('.topology-node-group');
        if (targetNodeEl && tooltip) {
            const nodeId = targetNodeEl.getAttribute('data-id');
            const n = topologyNodes.find(item => item.id === nodeId);
            if (n) {
                let statusBadge = '<span class="text-emerald-400 font-bold">● Онлайн</span>';
                if (n.is_wan_blocked) {
                    statusBadge = '<span class="text-rose-400 font-bold">🚫 WAN Заблокирован</span>';
                } else if (!n.is_online && n.type === 'device') {
                    statusBadge = '<span class="text-slate-400 font-bold">○ Офлайн</span>';
                }

                const segName = n.segment_id === 'segment_Bridge1' ? 'Гостевой (Bridge1 - Изолирован)' : 'Домашний (Bridge0 - Общий L2)';
                const ipMac = n.ip ? `${n.ip} • ${n.mac || ''}` : (n.details?.interface || '');

                let actionHint = '';
                if (n.type === 'device' && n.mac) {
                    actionHint = '<div class="text-[9px] text-cyan-400 mt-1 italic">Нажмите для перехода в настройки устройства</div>';
                } else if (n.type === 'router' || n.id === 'node_router') {
                    actionHint = '<div class="text-[9px] text-cyan-400 mt-1 italic">Нажмите для перехода в настройки роутера</div>';
                } else if (n.type === 'dns' || n.id === 'node_dns') {
                    actionHint = '<div class="text-[9px] text-cyan-400 mt-1 italic">Нажмите для перехода к DNS-запросам</div>';
                }

                tooltip.innerHTML = `
                    <div class="font-bold text-white text-xs flex items-center justify-between gap-2 border-b border-slate-800 pb-1">
                        <span>${escapeHtml(n.label || '')}</span>
                        ${statusBadge}
                    </div>
                    <div class="text-[11px] text-slate-400 font-mono">${escapeHtml(ipMac)}</div>
                    ${n.type === 'device' ? `<div class="text-[10px] text-slate-500">Сегмент: <span class="text-slate-300">${segName}</span></div>` : ''}
                    ${n.vendor ? `<div class="text-[10px] text-slate-500">Вендор: <span class="text-slate-300">${escapeHtml(n.vendor)}</span></div>` : ''}
                    ${actionHint}
                `;

                const rect = svg.getBoundingClientRect();
                tooltip.style.left = `${e.clientX - rect.left + 15}px`;
                tooltip.style.top = `${e.clientY - rect.top + 15}px`;
                tooltip.classList.remove('hidden');
                return;
            }
        }

        if (tooltip) tooltip.classList.add('hidden');
    });

    window.addEventListener('mouseup', () => {
        if (dragCandidate && !isDraggingNode) {
            const clickedNode = dragCandidate.node;
            dragCandidate = null;
            handleTopologyNodeClick(clickedNode);
        }

        if (isDraggingNode) {
            hasJustDragged = true;
            setTimeout(() => { hasJustDragged = false; }, 200);
        }

        dragCandidate = null;
        isDraggingNode = false;
        isPanningTopology = false;
        if (draggedNode) {
            draggedNode.fixed = true;
            draggedNode.vx = 0;
            draggedNode.vy = 0;
            draggedNode = null;
        }
    });

    // Touch event handling for mobile / tablet screens
    let touchCandidate = null;
    let isDraggingTouch = false;

    svg.addEventListener('touchstart', e => {
        if (e.touches.length === 1) {
            const touch = e.touches[0];
            const targetNodeEl = document.elementFromPoint(touch.clientX, touch.clientY)?.closest('.topology-node-group');
            if (targetNodeEl) {
                const nodeId = targetNodeEl.getAttribute('data-id');
                const node = topologyNodes.find(n => n.id === nodeId);
                if (node) {
                    touchCandidate = { node, startX: touch.clientX, startY: touch.clientY };
                    isDraggingTouch = false;
                }
            }
        }
    }, { passive: true });

    svg.addEventListener('touchmove', e => {
        if (touchCandidate && e.touches.length === 1) {
            const touch = e.touches[0];
            const dist = Math.hypot(touch.clientX - touchCandidate.startX, touch.clientY - touchCandidate.startY);
            if (dist > 8) {
                isDraggingTouch = true;
            }
        }
    }, { passive: true });

    svg.addEventListener('touchend', () => {
        if (touchCandidate && !isDraggingTouch) {
            const clickedNode = touchCandidate.node;
            touchCandidate = null;
            handleTopologyNodeClick(clickedNode);
        }
        touchCandidate = null;
        isDraggingTouch = false;
    });

    svg.addEventListener('wheel', e => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.1 : 0.9;
        zoomTopology(factor, e.clientX, e.clientY);
    });

    svg.addEventListener('click', e => {
        if (hasJustDragged) {
            e.stopPropagation();
            e.preventDefault();
            return;
        }
        const targetNodeEl = e.target.closest('.topology-node-group');
        if (targetNodeEl) {
            const nodeId = targetNodeEl.getAttribute('data-id');
            const n = topologyNodes.find(item => item.id === nodeId);
            if (n) {
                handleTopologyNodeClick(n);
            }
        }
    });
}

function applyTopologyTransform() {
    const vp = document.getElementById('topology-viewport');
    if (vp) {
        vp.setAttribute('transform', `translate(${topologyTransform.x}, ${topologyTransform.y}) scale(${topologyTransform.scale})`);
    }
}

function zoomTopology(factor, originX, originY) {
    const svg = document.getElementById('topology-svg');
    if (!svg) return;

    const rect = svg.getBoundingClientRect();
    const cx = originX !== undefined ? originX - rect.left : rect.width / 2;
    const cy = originY !== undefined ? originY - rect.top : rect.height / 2;

    const newScale = Math.min(Math.max(topologyTransform.scale * factor, 0.4), 2.5);
    const scaleDiff = newScale - topologyTransform.scale;

    topologyTransform.x -= (cx - topologyTransform.x) * (scaleDiff / topologyTransform.scale);
    topologyTransform.y -= (cy - topologyTransform.y) * (scaleDiff / topologyTransform.scale);
    topologyTransform.scale = newScale;

    applyTopologyTransform();
}
window.zoomTopology = zoomTopology;

function resetTopologyView() {
    topologyTransform = { x: 0, y: 0, scale: 1 };
    applyTopologyTransform();
}
window.resetTopologyView = resetTopologyView;

