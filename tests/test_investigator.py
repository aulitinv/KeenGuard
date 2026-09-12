import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from keenguard.core.investigator import investigator, IncidentInvestigator
from keenguard.core.classifier import DeviceClassifier
from keenguard.web.app import app

def test_detect_device_os():
    """Verify accurate OS detection across major platforms."""
    assert IncidentInvestigator.detect_device_os("DESKTOP-TEST-PC", "Micro-Star INT'L", "pc") == "windows"
    assert IncidentInvestigator.detect_device_os("Laptop-ThinkPad", "Lenovo", "pc") == "windows"
    assert IncidentInvestigator.detect_device_os("spruthub-controller", "Raspberry Pi", "smart_home_hub") == "linux"
    assert IncidentInvestigator.detect_device_os("Ubuntu-Server", "", "server") == "linux"
    assert IncidentInvestigator.detect_device_os("MacBook-Air-Alex", "Apple, Inc.", "pc") == "macos"
    assert IncidentInvestigator.detect_device_os("iPhone-15-Pro", "Apple, Inc.", "mobile") == "ios"
    assert IncidentInvestigator.detect_device_os("SM-S928B-Galaxy", "Samsung Electronics", "mobile") == "android"
    assert IncidentInvestigator.detect_device_os("Pixel-8-Pro", "Google LLC", "mobile") == "android"
    assert IncidentInvestigator.detect_device_os("LGwebOSTV-usb", "LG Electronics", "smart_tv") == "webos"
    assert IncidentInvestigator.detect_device_os("Samsung-Tizen-OLED", "Samsung Visual Display", "smart_tv") == "tizen"
    assert IncidentInvestigator.detect_device_os("smart-vacuum-cleaner", "Xiaomi Communications", "iot") == "iot"

def test_generate_intel_links():
    """Verify threat intelligence link generation."""
    ip_links = IncidentInvestigator.generate_intel_links("198.51.100.25", is_ip=True)
    assert "virustotal.com/gui/ip-address/198.51.100.25" in ip_links["virustotal"]
    assert "abuseipdb.com/check/198.51.100.25" in ip_links["abuseipdb"]
    assert "ipinfo.io/198.51.100.25" in ip_links["ipinfo"]
    assert "shodan.io/host/198.51.100.25" in ip_links["shodan"]

    domain_links = IncidentInvestigator.generate_intel_links("bad-tracker.example.com", is_ip=False)
    assert "virustotal.com/gui/domain/bad-tracker.example.com" in domain_links["virustotal"]
    assert "who.is/whois/bad-tracker.example.com" in domain_links["whois"]
    assert "urlscan.io/search/#domain:bad-tracker.example.com" in domain_links["urlscan"]

def test_os_diagnostic_playbook_coverage():
    """Verify diagnostic playbooks for Windows, Linux, macOS, Android, iOS, and Smart TV."""
    # Windows
    win_pb = IncidentInvestigator.get_os_diagnostic_playbook("windows", "198.51.100.10", 80)
    assert win_pb["os_name"].startswith("Windows")
    assert any("Get-NetTCPConnection" in (step.get("command") or "") for step in win_pb["steps"])

    # Linux
    lin_pb = IncidentInvestigator.get_os_diagnostic_playbook("linux", "198.51.100.10", 80)
    assert "Linux" in lin_pb["os_name"]
    assert any("ss" in (step.get("command") or "") for step in lin_pb["steps"])

    # macOS
    mac_pb = IncidentInvestigator.get_os_diagnostic_playbook("macos", "198.51.100.10", 80)
    assert "macOS" in mac_pb["os_name"]
    assert any("lsof" in (step.get("command") or "") for step in mac_pb["steps"])

    # Android
    droid_pb = IncidentInvestigator.get_os_diagnostic_playbook("android", "198.51.100.10", 80)
    assert "Android" in droid_pb["os_name"]
    assert any("Private DNS" in step["title"] or "dumpsys netstats" in (step.get("command") or "") for step in droid_pb["steps"])

    # iOS
    ios_pb = IncidentInvestigator.get_os_diagnostic_playbook("ios", "198.51.100.10", 80)
    assert "iOS" in ios_pb["os_name"]
    assert any("конфиденциальности" in step["title"].lower() or "app privacy" in (step.get("tip") or "").lower() for step in ios_pb["steps"])

    # Smart TV (both 'smart_tv' and 'webos'/'tizen')
    tv_pb = IncidentInvestigator.get_os_diagnostic_playbook("webos", "198.51.100.10", 80)
    assert "Smart TV" in tv_pb["os_name"]
    assert any("ACR" in step["title"] or "Live Plus" in step["description"] for step in tv_pb["steps"])

    tv_generic_pb = IncidentInvestigator.get_os_diagnostic_playbook("smart_tv", "198.51.100.10", 80)
    assert "Smart TV" in tv_generic_pb["os_name"]
    assert len(tv_generic_pb["steps"]) == 4
    assert any("ACR" in step["title"] or "Live Plus" in step["description"] for step in tv_generic_pb["steps"])
    # Verify Standby / Quick Start+ rule 3 compliance
    assert any("Standby" in step["title"] or "Быстрый старт" in step["description"] or "режим ожидания" in step["description"] for step in tv_generic_pb["steps"])
    # Must NOT have IoT vacuum/sensor text
    for step in tv_generic_pb["steps"]:
        assert "Mi Home" not in step["description"]
        assert "CoAP" not in step["description"]
        # Router actions must not be in local client playbook (they belong to Step 4)
        assert "Сетевая защита на роутере Keenetic" not in step["title"]

@pytest.mark.asyncio
async def test_analyze_incident_dns_correlation_and_system_crl():
    """Verify DNS-to-IP correlation and OCSP/CRL false-positive recognition."""
    flows = [
        {
            "dst_ip": "198.51.100.50",
            "dst_port": 80,
            "protocol": "TCP",
            "is_lan": False,
            "is_encrypted": False,
            "provider": "Akamai Technologies",
            "bytes_up": 500,
            "bytes_down": 2500,
            "risk": "warning"
        },
        {
            "dst_ip": "198.51.100.100",
            "dst_port": 443,
            "protocol": "TCP",
            "is_lan": False,
            "is_encrypted": True,
            "provider": "Microsoft Azure",
            "bytes_up": 2000,
            "bytes_down": 8000,
            "risk": "safe"
        }
    ]

    res = await investigator.analyze_incident(
        target_mac="00:11:22:33:44:55",
        target_ip="192.168.1.101",
        target_host="DESKTOP-TEST",
        flows=flows,
        db_conn=None
    )

    assert res["target"]["os_type"] == "windows"
    assert "is_blocked_wan" in res["target"]
    assert res["flows_count"] == 2
    # Verify technical caveats for VPN and DoH/DoT are returned
    caveat_titles = [c["title"] for c in res["caveats"]]
    assert any("VPN" in t for t in caveat_titles)
    assert any("Private DNS" in t or "DoT" in t for t in caveat_titles)

def test_api_investigator_endpoints():
    """Verify /api/investigator endpoints integration."""
    client = TestClient(app)
    # 1. GET /api/investigator/incidents
    res = client.get("/api/investigator/incidents")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "incidents" in data
    assert "devices" in data

    # 2. POST /api/investigator/analyze (ad-hoc IP)
    analyze_res = client.post("/api/investigator/analyze", json={
        "target_ip": "198.51.100.77",
        "target_os": "linux"
    })
    assert analyze_res.status_code == 200
    adata = analyze_res.json()
    assert adata["status"] == "ok"
    assert adata["investigation"]["target"]["os_type"] == "linux"
    assert adata["investigation"]["playbook"]["os_name"].startswith("Linux")

    # 3. POST /api/investigator/block - valid domain succeeds
    with patch("keenguard.web.app.keenetic_client.add_dns_sinkhole", new_callable=AsyncMock) as mock_block:
        mock_block.return_value = True
        block_res = client.post("/api/investigator/block", json={"domain": "tracking.example.org"})
        assert block_res.status_code == 200
        bdata = block_res.json()
        assert bdata["status"] == "ok"
        assert bdata["target"] == "tracking.example.org"

    # 4. POST /api/investigator/block - IP address must be rejected with HTTP 400
    res_ip = client.post("/api/investigator/block", json={"domain": "192.168.1.1"})
    assert res_ip.status_code == 400
    assert "DNS Sinkhole предназначен для блокировки доменных имен" in res_ip.json()["detail"]

    res_ip_ext = client.post("/api/investigator/block", json={"domain": "8.8.8.8"})
    assert res_ip_ext.status_code == 400
    assert "DNS Sinkhole предназначен для блокировки доменных имен" in res_ip_ext.json()["detail"]

    # 5. POST /api/investigator/block - Keenetic router management domains must be rejected
    res_router = client.post("/api/investigator/block", json={"domain": "my.keenetic.net"})
    assert res_router.status_code == 400
    assert "Запрещено блокировать локальные или системные домены" in res_router.json()["detail"]

    res_keendns = client.post("/api/investigator/block", json={"domain": "myhome.keenetic.link"})
    assert res_keendns.status_code == 400
    assert "Запрещено блокировать локальные или системные домены" in res_keendns.json()["detail"]

    # 6. POST /api/investigator/block - Malformed domains without dot must be rejected
    res_malformed = client.post("/api/investigator/block", json={"domain": "notadomain"})
    assert res_malformed.status_code == 400
    assert "Укажите корректное доменное имя" in res_malformed.json()["detail"]

@pytest.mark.asyncio
async def test_investigator_empty_flows_and_playbook_no_router_fallback():
    """Verify that when no flows exist, commands do not point to router IP 192.168.1.1 and caveats have description."""
    db_mock = AsyncMock()
    cursor_mock = AsyncMock()
    cursor_mock.fetchone.return_value = None
    cursor_mock.fetchall.return_value = [
        ("telemetry.example.org", "198.51.100.5", "2026-09-13T12:00:00Z")
    ]
    db_mock.execute.return_value = cursor_mock

    res = await investigator.analyze_incident(
        target_mac="70:85:C2:00:00:01",
        target_ip=None,
        target_host="TEST-PC",
        flows=[],
        db_conn=db_mock
    )

    # 1. Verdict must be safe with informative message
    assert res["verdict"]["status"] == "safe"
    assert "Нет зафиксированных сессий" in res["verdict"]["summary"]
    # 2. Recent DNS queries must be present
    assert len(res["recent_dns"]) == 1
    assert res["recent_dns"][0]["domain"] == "telemetry.example.org"
    # 3. Playbook commands must NOT target 192.168.1.1
    win_playbook = res["playbook"]
    for step in win_playbook["steps"]:
        if step.get("command"):
            assert "192.168.1.1" not in step["command"]
    # 4. Caveats must contain both 'description' and 'text'
    for c in res["caveats"]:
        assert "description" in c and len(c["description"]) > 10
        assert "text" in c and len(c["text"]) > 10

def test_asrock_oui_classification():
    """Verify ASRock OUI is recognized as ASRock Incorporation."""
    vendor, profile, is_random = DeviceClassifier.classify("70:85:C2:11:22:33", "DESKTOP-TEST")
    assert vendor == "ASRock Incorporation"
    assert profile == "trusted"
    assert not is_random

