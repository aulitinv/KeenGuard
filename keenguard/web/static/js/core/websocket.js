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
            } else if (data.type === 'rules_updated') {
                if (typeof loadRules === 'function' && activeTab === 'rules' && !hasUnsavedRuleChanges) {
                    loadRules();
                } else if (typeof updateRulesBadgeOnly === 'function') {
                    updateRulesBadgeOnly();
                }
            } else if (data.type === 'error' && data.auth_required) {
                showLoginModal();
                return;
            }
        } catch (e) {
            console.error('WS parse error', e);
        }
    };

    ws.onclose = (event) => {
        if (event && event.code === 1008) {
            showLoginModal();
            return;
        }
        setTimeout(connectWebSocket, 3000);
    };
}

