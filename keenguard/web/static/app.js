// ============================================================================
// KeenGuard Application Orchestrator & Bootstrapper v5.0
// ============================================================================

// Global Data Refresh Pipeline
async function refreshAllData() {
    await Promise.allSettled([
        loadStatus(),
        loadDevices(),
        loadUpnp(),
        loadEvents()
    ]);
    if (activeTab === 'dashboard') {
        loadWifiAudit();
        checkRouterUpdates();
        updateLiveTrafficChart();
        loadSecurityScoreForDashboard();
        loadL7TrafficSummary();
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
    } else if (activeTab === 'rules') {
        if (typeof loadRules === 'function' && !hasUnsavedRuleChanges) loadRules();
    }

    if (typeof updateRulesBadgeOnly === 'function') {
        updateRulesBadgeOnly();
    }
}
window.refreshAllData = refreshAllData;

// Lifecycle Bootstrapping
document.addEventListener('DOMContentLoaded', async () => {
    // 0. Initialize authentication status
    await checkAuthStatus();

    // 1. Initialize modal dismiss event handlers
    initModalDismissHandlers();

    // 2. Establish live WebSocket stream
    connectWebSocket();

    // 3. Initial full data fetch
    await refreshAllData();

    // 4. Render Lucide icons
    if (window.lucide) {
        lucide.createIcons();
    }

    // 5. Setup periodic background refresh intervals
    setInterval(() => {
        refreshAllData();
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
