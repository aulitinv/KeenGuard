// Sidebar Collapse / Expand State and Handling
function toggleSidebar(forcedState) {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;
    const shouldCollapse = (typeof forcedState === 'boolean')
        ? forcedState
        : !sidebar.classList.contains('sidebar-collapsed');

    if (shouldCollapse) {
        sidebar.classList.add('sidebar-collapsed');
    } else {
        sidebar.classList.remove('sidebar-collapsed');
    }

    // Only persist manual user toggle if window is wide enough (>= 1180px)
    if (typeof forcedState !== 'boolean' && window.innerWidth >= 1180) {
        try {
            localStorage.setItem('kg_sidebar_collapsed', shouldCollapse ? '1' : '0');
        } catch (e) {}
    }

    updateSidebarUI(shouldCollapse);
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

    // Mobile / Tablet drawer backdrop
    const backdrop = document.getElementById('sidebar-backdrop');
    if (backdrop) {
        if (!isCollapsed && window.innerWidth < 1024) {
            backdrop.classList.remove('hidden');
        } else {
            backdrop.classList.add('hidden');
        }
    }

    if (window.lucide) {
        lucide.createIcons();
    }
}

function initSidebarState() {
    const sidebar = document.getElementById('app-sidebar');
    if (!sidebar) return;

    function applyResponsiveState() {
        const w = window.innerWidth;
        let isCollapsed = false;
        if (w < 1180) {
            // Under 1180px (tablets, split-screen with DevTools, narrow laptops): auto-collapse
            isCollapsed = true;
        } else {
            try {
                const saved = localStorage.getItem('kg_sidebar_collapsed');
                if (saved !== null) {
                    isCollapsed = (saved === '1');
                }
            } catch (e) {}
        }
        if (isCollapsed) {
            sidebar.classList.add('sidebar-collapsed');
        } else {
            sidebar.classList.remove('sidebar-collapsed');
        }
        updateSidebarUI(isCollapsed);
    }

    applyResponsiveState();

    // Window resize listener with debounce
    let resizeTimer = null;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            applyResponsiveState();
        }, 120);
    });

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
    if (typeof clearAllToasts === "function") clearAllToasts();
    if (activeTab === 'rules' && tabId !== 'rules' && typeof hasUnsavedRuleChanges !== 'undefined' && hasUnsavedRuleChanges) {
        if (!confirm('У вас есть несохраненные изменения порядка правил. Покинуть вкладку без сохранения?')) {
            return;
        }
        if (typeof discardRuleChanges === 'function') {
            discardRuleChanges();
        }
    }

    activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');

    document.querySelectorAll('main > section').forEach(sec => sec.classList.add('hidden'));
    document.getElementById(`view-${tabId}`).classList.remove('hidden');
    updateAllDisplayModeButtons();
    initSourceFilterCheckboxes();

    // On mobile / tablet screens, automatically collapse sidebar drawer on navigation
    if (window.innerWidth < 1024) {
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar && !sidebar.classList.contains('sidebar-collapsed')) {
            toggleSidebar(true);
        }
    }

    if (tabId === 'devices') loadDevices();
    else if (tabId === 'rules') loadRules();
    else if (tabId === 'security') loadSecurity();
    else if (tabId === 'smarthome') loadSmartHome();
    else if (tabId === 'lan') {
        if (!devicesList || devicesList.length === 0) await loadDevices();
        loadLanTab();
    }
    else if (tabId === 'topology') {
        loadTopologyTab();
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
        loadL7TrafficSummary();
    }

    if (tabId !== 'settings') {
        const submenu = document.getElementById('settings-submenu');
        if (submenu) submenu.classList.add('hidden');
        const chev = document.getElementById('settings-chevron');
        if (chev) chev.classList.remove('rotate-180');
    }

    lucide.createIcons();
}

