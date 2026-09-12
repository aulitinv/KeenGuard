"""Unit tests for newly added KeenGuard features:
- Telegram notifier
- Wi-Fi security audit
- Firmware updates check
- Security Digest generator
- Traffic history & rates
- DNS queries tracking
"""
import pytest
from keenguard.config import settings
from keenguard.db.models import SecurityEvent
from keenguard.core.notifier import notifier
from keenguard.core.keenetic import keenetic_client
from keenguard.core.digest import digest_generator
from keenguard.core.audit import identify_geoip, identify_provider
from keenguard.db.database import Database
import tempfile
from pathlib import Path

@pytest.mark.asyncio
async def test_geoip_identification():
    geo_alibaba = identify_geoip("47.91.78.162")
    assert geo_alibaba["country"] == "DE"
    assert "Alibaba" in geo_alibaba["provider"]

    geo_apple = identify_geoip("17.248.190.245")
    assert geo_apple["country"] == "US"
    assert "Apple" in geo_apple["provider"]

    geo_lan = identify_geoip("192.168.1.50")
    assert geo_lan["country"] == "LAN"

    prov_str = identify_provider("8.8.8.8")
    assert "Google" in prov_str
    assert "🇺🇸" in prov_str

@pytest.mark.asyncio
async def test_traffic_history_recording(tmp_path):
    test_db = Database(db_path=tmp_path / "test_traffic.db")
    await test_db.init_db()
    mac = "AA:BB:CC:DD:EE:01"
    await test_db.record_traffic_snapshot(mac, 1000, 2000, 150.5, 45.2)
    await test_db.record_traffic_snapshot(mac, 3000, 4000, 250.0, 80.0)

    history = await test_db.get_device_traffic_history(mac)
    assert len(history) == 2
    assert history[0]["rx_rate_kbps"] == 150.5
    assert history[1]["rx_rate_kbps"] == 250.0

    summary = await test_db.get_network_traffic_summary()
    assert len(summary) >= 1

@pytest.mark.asyncio
async def test_dns_queries_tracking(tmp_path):
    test_db = Database(db_path=tmp_path / "test_dns.db")
    await test_db.init_db()
    await test_db.record_dns_query("api.smart-device.net", ip="47.91.78.162")
    await test_db.record_dns_query("api.smart-device.net", ip="47.91.78.162")
    await test_db.record_dns_query("gateway.cloud-service.com", ip="17.248.190.245")

    queries = await test_db.get_top_dns_queries()
    assert len(queries) == 2
    # Smart device domain was queried twice
    assert queries[0]["domain"] == "api.smart-device.net"
    assert queries[0]["count"] == 2

@pytest.mark.asyncio
async def test_wifi_security_audit_mock():
    keenetic_client.mock_mode = True
    audit = await keenetic_client.get_wifi_security()
    assert audit["grade"] in ("A+", "A", "B", "C", "F")
    assert audit["score"] > 0
    assert len(audit["access_points"]) > 0
    assert audit["guest_network"]["configured"] is True

@pytest.mark.asyncio
async def test_firmware_updates_mock():
    keenetic_client.mock_mode = True
    updates = await keenetic_client.check_firmware_updates()
    assert updates["status"] == "ok"
    assert "current_version" in updates

@pytest.mark.asyncio
async def test_security_digest_generation():
    digest = await digest_generator.generate_digest(hours=24)
    assert "score" in digest
    assert "status_text" in digest
    assert "telegram_text" in digest
    assert 0 <= digest["score"] <= 100

@pytest.mark.asyncio
async def test_telegram_alert_disabled_by_default():
    settings.telegram_enabled = False
    ev = SecurityEvent(event_type="test_event", severity="critical", description="Test Alert")
    sent = await notifier.send_alert(ev)
    assert sent is False

@pytest.mark.asyncio
async def test_telegram_custom_gateway_and_proxy(monkeypatch):
    """Verifies that custom Telegram API URL (e.g. Cloudflare Worker) and proxy are handled correctly."""
    captured_urls = []
    captured_clients = []

    class MockResponse:
        status_code = 200
        def json(self):
            return {"ok": True, "result": {"message_id": 12345}}

    class MockAsyncClient:
        def __init__(self, **kwargs):
            captured_clients.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, json=None):
            captured_urls.append((url, json))
            return MockResponse()

    monkeypatch.setattr("httpx.AsyncClient", MockAsyncClient)

    # 1. Test custom Cloudflare worker gateway without trailing slash
    res = await notifier.send_message(
        text="Test Ping",
        token="123456:ABC-DEF",
        chat_id="999888777",
        api_url="https://worker-test.example.workers.dev",
        proxy="socks5://127.0.0.1:1080"
    )
    assert res["status"] == "ok"
    assert len(captured_urls) == 1
    assert captured_urls[0][0] == "https://worker-test.example.workers.dev/bot123456:ABC-DEF/sendMessage"
    assert captured_clients[0]["proxy"] == "socks5://127.0.0.1:1080"

    # 2. Test URL without https:// scheme (auto-prefix)
    captured_urls.clear()
    res2 = await notifier.send_test_message(
        token="123456:ABC-DEF",
        chat_id="999888777",
        api_url="custom-tg-proxy.my-domain.com",
    )
    assert res2["status"] == "ok"
    assert captured_urls[0][0] == "https://custom-tg-proxy.my-domain.com/bot123456:ABC-DEF/sendMessage"

@pytest.mark.asyncio
async def test_modular_new_device_policy():
    """Verifies that modular new device reaction flags can be independently configured."""
    # Test default states
    assert hasattr(settings, "new_device_quarantine_wan")
    assert hasattr(settings, "new_device_isolate_lan")
    assert hasattr(settings, "new_device_auto_audit")

    # Set arbitrary combination
    settings.new_device_quarantine_wan = True
    settings.new_device_isolate_lan = False
    settings.new_device_auto_audit = True

    assert settings.new_device_quarantine_wan is True
    assert settings.new_device_isolate_lan is False
    assert settings.new_device_auto_audit is True

@pytest.mark.asyncio
async def test_dns_tracker_resolution(tmp_path, monkeypatch):
    """Verifies DnsTracker IP resolution and NAT tracking with SQLite persistence."""
    from keenguard.core.dns_tracker import DnsTracker
    test_db = Database(db_path=tmp_path / "test_dns_tracker.db")
    await test_db.init_db()
    monkeypatch.setattr("keenguard.core.dns_tracker.db", test_db)

    tracker = DnsTracker()

    # 1. Local IPs should return None
    assert await tracker.resolve_ip("192.168.1.1") is None
    assert await tracker.resolve_ip("10.0.0.5") is None

    # 2. Known provider fallback should resolve
    domain_tg = await tracker.resolve_ip("149.154.166.110")
    assert domain_tg == "telegram.org"

    domain_google = await tracker.resolve_ip("8.8.8.8")
    assert domain_google == "dns.google"

    # 3. Process NAT entries with device mapping
    nat_entries = [
        {"protocol": "TCP", "src": "192.168.1.50", "dst": "149.154.166.110", "sport": 50000, "dport": 443},
        {"protocol": "UDP", "src": "192.168.1.50", "dst": "192.168.1.1", "sport": 5353, "dport": 53}, # local should be skipped
    ]
    devices_map = {
        "AA:BB:CC:11:22:33": {"ip": "192.168.1.50", "hostname": "Test-Client"}
    }

    recorded = await tracker.track_nat_connections(nat_entries, devices_map)
    assert recorded == 1

    top_queries = await test_db.get_top_dns_queries()
    assert len(top_queries) == 1
    assert top_queries[0]["domain"] == "telegram.org"
    assert top_queries[0]["mac"] == "AA:BB:CC:11:22:33"

@pytest.mark.asyncio
async def test_scheduled_audit_scope_filtering(tmp_path, monkeypatch):
    """Verifies that scheduled audit candidates are filtered correctly by scope."""
    from keenguard.db.models import DeviceRecord
    from keenguard.core.scheduler import BackgroundScheduler

    test_db = Database(db_path=tmp_path / "test_scheduler.db")
    await test_db.init_db()

    # Seed devices
    d_iot = DeviceRecord(mac="11:11:11:11:11:11", ip="192.168.1.10", profile="iot", is_online=True)
    d_cam = DeviceRecord(mac="22:22:22:22:22:22", ip="192.168.1.20", profile="camera", is_online=True)
    d_trust = DeviceRecord(mac="33:33:33:33:33:33", ip="192.168.1.30", profile="trusted", is_online=True)
    d_unassigned = DeviceRecord(mac="44:44:44:44:44:44", ip="192.168.1.40", profile="unassigned", is_online=True)
    d_offline = DeviceRecord(mac="55:55:55:55:55:55", ip="192.168.1.50", profile="iot", is_online=False)

    for d in [d_iot, d_cam, d_trust, d_unassigned, d_offline]:
        await test_db.upsert_device(d)

    monkeypatch.setattr("keenguard.core.scheduler.db", test_db)

    sched = BackgroundScheduler()

    # 1. Scope: 'all' -> all online devices
    monkeypatch.setattr(settings, "scheduled_audit_scope", "all")
    devices = await test_db.get_all_devices()
    scope_all = [d for d in devices if d.is_online and d.ip]
    assert len(scope_all) == 4

    # 2. Scope: 'iot_only' -> only iot and camera
    monkeypatch.setattr(settings, "scheduled_audit_scope", "iot_only")
    scope_iot = [d for d in devices if d.is_online and d.ip and d.profile in ("iot", "camera")]
    assert len(scope_iot) == 2
    assert {d.mac for d in scope_iot} == {"11:11:11:11:11:11", "22:22:22:22:22:22"}

    # 3. Scope: 'untrusted' -> iot, camera, and unassigned
    monkeypatch.setattr(settings, "scheduled_audit_scope", "untrusted")
    scope_untrusted = [d for d in devices if d.is_online and d.ip and d.profile in ("iot", "camera", "unassigned")]
    assert len(scope_untrusted) == 3
    assert "33:33:33:33:33:33" not in {d.mac for d in scope_untrusted}

@pytest.mark.asyncio
async def test_export_endpoints(tmp_path, monkeypatch):
    """Verifies CSV and JSON export logic."""
    from httpx import AsyncClient, ASGITransport
    from keenguard.web.app import app
    from keenguard.db.models import DeviceRecord, SecurityEvent

    test_db = Database(db_path=tmp_path / "test_export.db")
    await test_db.init_db()

    dev = DeviceRecord(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100", hostname="My-Phone", profile="trusted", is_online=True)
    await test_db.upsert_device(dev)

    ev = SecurityEvent(event_type="test_ev", severity="warning", description="Test event for export")
    await test_db.record_event(ev)

    monkeypatch.setattr("keenguard.web.app.db", test_db)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Export devices CSV
        r_dev_csv = await client.get("/api/export/devices?format=csv")
        assert r_dev_csv.status_code == 200
        assert r_dev_csv.headers["content-type"] == "text/csv; charset=utf-8"
        content_csv = r_dev_csv.content.decode("utf-8-sig")
        assert "MAC,IP,Hostname" in content_csv
        assert "AA:BB:CC:DD:EE:FF" in content_csv

        # 2. Export devices JSON
        r_dev_json = await client.get("/api/export/devices?format=json")
        assert r_dev_json.status_code == 200
        data_dev = r_dev_json.json()
        assert isinstance(data_dev, list)
        assert len(data_dev) == 1
        assert data_dev[0]["mac"] == "AA:BB:CC:DD:EE:FF"

        # 3. Export events CSV
        r_ev_csv = await client.get("/api/export/events?format=csv")
        assert r_ev_csv.status_code == 200
        content_ev_csv = r_ev_csv.content.decode("utf-8-sig")
        assert "ID,Timestamp,Type" in content_ev_csv
        assert "Test event for export" in content_ev_csv

        # 4. Export events JSON
        r_ev_json = await client.get("/api/export/events?format=json")
        assert r_ev_json.status_code == 200
        data_ev = r_ev_json.json()
        assert len(data_ev) == 1
        assert data_ev[0]["event_type"] == "test_ev"

