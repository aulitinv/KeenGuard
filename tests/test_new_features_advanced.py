"""Unit tests for advanced KeenGuard features:
- Differentiated new device policies (category vs global)
- Whole-network audit session & Lateral Movement forensics
- Active Guard auto-ban / auto-quarantine of suspicious devices during audit
- Network audit API endpoints
"""
import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport

from keenguard.config import settings
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.core.audit import (
    NetworkAuditSession,
    TrafficAuditManager,
    AuditSession,
    identify_provider,
)
from keenguard.core.keenetic import keenetic_client
from keenguard.web.app import app, audit_manager

@pytest.mark.asyncio
async def test_category_policy_db_storage(tmp_path):
    """Verifies storing and retrieving differentiated category policies in SQLite."""
    test_db = Database(db_path=tmp_path / "test_pol.db")
    await test_db.init_db()

    # Initial state should have default mode and policies
    initial = await test_db.get_new_device_policies()
    assert initial["mode"] == "category"
    assert "trusted" in initial["policies"]

    custom_policies = {
        "trusted": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": False, "audit_duration": 300, "telegram_alert": True},
        "iot": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
        "camera": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
        "random_mac": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
        "unknown": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
    }

    await test_db.save_new_device_policies("category", custom_policies)
    saved = await test_db.get_new_device_policies()

    assert saved["mode"] == "category"
    assert saved["categories"]["camera"]["isolate_lan"] is True
    assert saved["categories"]["trusted"]["quarantine_wan"] is False
    assert saved["categories"]["iot"]["audit_duration"] == 900


def test_network_audit_session_aggregation(tmp_path):
    """Verifies that NetworkAuditSession processes NAT tables across multiple devices,
    detects Lateral Movement on critical ports, identifies cloud providers, and ranks devices."""
    net_session = NetworkAuditSession(
        scope="all",
        duration_seconds=60
    )

    sample_nat_table = [
        # 1. IoT device hitting external IoT cloud
        {
            "protocol": "TCP",
            "src": "192.168.1.55",
            "dst": "47.91.78.162",
            "sport": 40001,
            "dport": 443,
            "bytes": 5000,
            "packets": 20,
            "bytes-out": 12000,
            "packets-out": 30
        },
        # 2. PC device hitting Cloudflare DNS
        {
            "protocol": "UDP",
            "src": "192.168.1.100",
            "dst": "1.1.1.1",
            "sport": 52123,
            "dport": 53,
            "bytes": 200,
            "packets": 2,
            "bytes-out": 500,
            "packets-out": 2
        },
        # 3. Suspicious device probing internal LAN SMB port 445 (Lateral Movement!)
        {
            "protocol": "TCP",
            "src": "192.168.1.88",
            "dst": "192.168.1.150",
            "sport": 49120,
            "dport": 445,
            "bytes": 450,
            "packets": 4,
            "bytes-out": 0,
            "packets-out": 0
        },
        # 4. Suspicious device probing internal LAN SSH port 22
        {
            "protocol": "TCP",
            "src": "192.168.1.88",
            "dst": "192.168.1.150",
            "sport": 49121,
            "dport": 22,
            "bytes": 300,
            "packets": 3,
            "bytes-out": 0,
            "packets-out": 0
        },
        # 5. Normal router traffic to gateway 192.168.1.1 (should NOT be flagged as lateral movement)
        {
            "protocol": "TCP",
            "src": "192.168.1.100",
            "dst": "192.168.1.1",
            "sport": 55100,
            "dport": 80,
            "bytes": 1000,
            "packets": 5,
            "bytes-out": 2000,
            "packets-out": 8
        }
    ]

    net_session.update_nat_entries(sample_nat_table)

    assert net_session.total_flows == 5
    assert len(net_session.device_stats) == 3  # 192.168.1.55, 192.168.1.100, 192.168.1.88
    assert net_session.total_bytes > 20000

    # Lateral movement assertions
    assert len(net_session.lateral_movements) == 2
    lm_ports = {lm["dst_port"] for lm in net_session.lateral_movements}
    assert 445 in lm_ports
    assert 22 in lm_ports
    for lm in net_session.lateral_movements:
        assert lm["risk"] == "critical"

    # Report generation
    report = net_session.generate_report()
    assert report["is_network"] is True
    assert report["overall_risk"] == "critical"
    assert report["devices_analyzed"] == 3
    assert len(report["top_devices"]) == 3
    assert len(report["cloud_providers"]) >= 1
    # Cloud providers should include Alibaba or Cloudflare
    provider_names = [cp["name"] for cp in report["cloud_providers"]]
    assert any("Alibaba" in p or "Cloudflare" in p for p in provider_names)

    # PCAP generation
    pcap_name = net_session.save_pcap(pcap_dir=tmp_path)
    assert pcap_name is not None
    pcap_path = tmp_path / pcap_name
    assert pcap_path.exists()
    assert pcap_path.stat().st_size > 20  # Has PCAP global header


@pytest.mark.asyncio
async def test_audit_active_guard_suspicious_autoban(tmp_path, monkeypatch):
    """Verifies that if a device behaves suspiciously during an audit session,
    the active guard automatically triggers quarantine & ban."""
    test_db = Database(db_path=tmp_path / "test_audit_guard.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.core.audit.db", test_db)

    mgr = TrafficAuditManager(pcap_dir=tmp_path)
    banned_devices = []

    def mock_suspicious_cb(mac: str, ip: str, hostname: str, reason: str):
        banned_devices.append({"mac": mac, "ip": ip, "hostname": hostname, "reason": reason})

    mgr.set_suspicious_callback(mock_suspicious_cb)

    # 1. Test individual device audit with suspicious activity
    audit_res = await mgr.start_audit(
        mac="99:88:77:66:55:44",
        ip="192.168.1.99",
        hostname="malicious-iot",
        vendor="Shady Vendor",
        duration_seconds=60
    )
    assert audit_res["status"] == "started"

    # Feed suspicious LAN scan to port 445 (SMB)
    session = mgr.active_sessions.get("99:88:77:66:55:44")
    assert session is not None

    suspicious_flow = [
        {
            "protocol": "TCP",
            "src": "192.168.1.99",
            "dst": "192.168.1.200",
            "sport": 50123,
            "dport": 445,
            "bytes": 500,
            "packets": 5,
            "bytes-out": 0,
            "packets-out": 0
        }
    ]

    session.update_nat_entries(suspicious_flow, on_suspicious_callback=mock_suspicious_cb)

    # Verify callback fired
    assert len(banned_devices) == 1
    assert banned_devices[0]["mac"] == "99:88:77:66:55:44"
    assert "445" in banned_devices[0]["reason"]
    assert session.auto_quarantined is True

    # Report includes quarantined device
    report = await mgr.stop_audit("99:88:77:66:55:44")
    assert report is not None
    assert report["overall_risk"] == "critical"
    assert len(report["quarantined_devices"]) == 1
    assert report["quarantined_devices"][0]["mac"] == "99:88:77:66:55:44"


@pytest.mark.asyncio
async def test_network_audit_active_guard_autoban(tmp_path, monkeypatch):
    """Verifies that Active Guard catches and quarantines suspicious devices during a whole-network audit."""
    test_db = Database(db_path=tmp_path / "test_net_guard.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.core.audit.db", test_db)

    mgr = TrafficAuditManager(pcap_dir=tmp_path)
    banned_devices = []

    def mock_suspicious_cb(mac: str, ip: str, hostname: str, reason: str):
        banned_devices.append({"mac": mac, "ip": ip, "hostname": hostname, "reason": reason})

    mgr.set_suspicious_callback(mock_suspicious_cb)

    start_res = await mgr.start_network_audit(scope="all", duration_seconds=120)
    assert start_res["status"] == "started"

    net_session = mgr.network_session
    assert net_session is not None
    assert net_session.is_active is True

    # Feed a probe from an internal host to 3389 (RDP)
    nat_flow = [
        {
            "protocol": "TCP",
            "src": "192.168.1.77",
            "dst": "192.168.1.220",
            "sport": 41234,
            "dport": 3389,
            "bytes": 350,
            "packets": 3,
            "bytes-out": 0,
            "packets-out": 0
        }
    ]

    dev_map = {
        "192.168.1.77": DeviceRecord(mac="77:77:77:77:77:77", ip="192.168.1.77", hostname="suspicious-pc")
    }

    net_session.update_nat_table(nat_flow, devices_by_ip=dev_map, on_suspicious_callback=mock_suspicious_cb)

    # Callback must be invoked
    assert len(banned_devices) == 1
    assert banned_devices[0]["ip"] == "192.168.1.77"
    assert "3389" in banned_devices[0]["reason"]
    assert len(net_session.quarantined_devices) == 1

    status = mgr.get_network_audit_status()
    assert status["is_active"] is True
    assert status["quarantined_count"] == 1

    stop_report = await mgr.stop_network_audit()
    assert stop_report["is_network"] is True
    assert stop_report["overall_risk"] == "critical"
    assert len(stop_report["quarantined_devices"]) == 1
    assert stop_report["quarantined_devices"][0]["ip"] == "192.168.1.77"


@pytest.mark.asyncio
async def test_network_audit_and_policy_api_endpoints(tmp_path, monkeypatch):
    """Verifies FastAPI endpoints for network audit and new device policies."""
    test_db = Database(db_path=tmp_path / "test_api_adv.db")
    await test_db.init_db()

    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.core.audit.db", test_db)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET /api/settings/new_device_policy
        r_pol_get = await client.get("/api/settings/new_device_policy")
        assert r_pol_get.status_code == 200
        pol_data = r_pol_get.json()
        assert "mode" in pol_data
        assert "categories" in pol_data
        assert "trusted" in pol_data["categories"]
        assert "audit_auto_quarantine_suspicious" in pol_data

        # 2. POST /api/settings/new_device_policy
        new_pol_payload = {
            "mode": "category",
            "categories": {
                "trusted": {"quarantine_wan": False, "isolate_lan": False, "auto_audit": False, "audit_duration": 300, "telegram_alert": True},
                "iot": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 900, "telegram_alert": True},
                "camera": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
                "random_mac": {"quarantine_wan": True, "isolate_lan": True, "auto_audit": True, "audit_duration": 1800, "telegram_alert": True},
                "unknown": {"quarantine_wan": True, "isolate_lan": False, "auto_audit": True, "audit_duration": 600, "telegram_alert": True}
            },
            "global_policy": {
                "quarantine_wan": False,
                "isolate_lan": False,
                "auto_audit": False,
                "audit_duration": 3600
            },
            "audit_auto_quarantine_suspicious": True
        }
        r_pol_post = await client.post("/api/settings/new_device_policy", json=new_pol_payload)
        assert r_pol_post.status_code == 200
        assert r_pol_post.json()["status"] == "ok"
        assert settings.new_device_policy_mode == "category"
        assert settings.audit_auto_quarantine_suspicious is True

        # 3. POST /api/audit/network/start
        r_net_start = await client.post("/api/audit/network/start", json={"scope": "all", "duration_seconds": 60})
        assert r_net_start.status_code == 200
        assert r_net_start.json()["status"] == "started"

        # 4. GET /api/audit/network/status
        r_net_status = await client.get("/api/audit/network/status")
        assert r_net_status.status_code == 200
        st = r_net_status.json()
        assert st["is_active"] is True
        assert st["scope"] == "all"

        # 5. GET /api/audit/active includes NETWORK entry
        r_active = await client.get("/api/audit/active")
        assert r_active.status_code == 200
        act = r_active.json()
        assert any(item["mac"] == "NETWORK" for item in act)

        # 6. POST /api/audit/network/stop
        r_net_stop = await client.post("/api/audit/network/stop")
        assert r_net_stop.status_code == 200
        report = r_net_stop.json()
        assert report["is_network"] is True

        # 7. GET /api/audit/network/latest_report
        r_latest = await client.get("/api/audit/network/latest_report")
        assert r_latest.status_code == 200
        assert r_latest.json()["is_network"] is True

        # 8. Start via special alias: POST /api/audit/__ALL_NETWORK__/start
        r_alias_start = await client.post("/api/audit/__ALL_NETWORK__/start", json={"duration_seconds": 60})
        assert r_alias_start.status_code == 200
        # Stop via POST /api/audit/NETWORK/stop
        r_alias_stop = await client.post("/api/audit/NETWORK/stop")
        assert r_alias_stop.status_code == 200
        assert r_alias_stop.json()["is_network"] is True
