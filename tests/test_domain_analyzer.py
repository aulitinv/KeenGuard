"""Unit tests for DomainAnalyzer and DNS reputation inspection in KeenGuard."""
import pytest
from keenguard.core.domain_analyzer import DomainAnalyzer, domain_analyzer
from keenguard.db.database import Database
from keenguard.db.models import DeviceRecord
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app

@pytest.mark.asyncio
async def test_domain_classification_iot_clouds():
    analyzer = DomainAnalyzer()
    
    # Shelly
    res = analyzer.analyze_domain("api.shelly.cloud")
    assert res["category"] == "iot_cloud"
    assert "Shelly" in res["vendor"]
    assert res["risk_level"] == "safe"
    assert "shelly.cloud" in res["external_links"]["virustotal"]

    # Tuya
    res = analyzer.analyze_domain("tuya.iot.cloud")
    assert res["category"] == "iot_cloud"
    assert "Tuya" in res["vendor"]

    # Home Assistant
    res = analyzer.analyze_domain("hub.home-assistant.io")
    assert res["category"] == "iot_cloud"
    assert "Home Assistant" in res["vendor"]

    # Smart Life
    res = analyzer.analyze_domain("cloud.smartlife.me")
    assert res["category"] == "iot_cloud"
    assert "Smart Life" in res["vendor"]

    # Keenetic
    res = analyzer.analyze_domain("router.keenetic.cloud")
    assert res["category"] == "iot_cloud"
    assert "Keenetic" in res["vendor"]

@pytest.mark.asyncio
async def test_domain_classification_telemetry_and_ads():
    analyzer = DomainAnalyzer()

    # Firebase telemetry
    res = analyzer.analyze_domain("app-measurement.com")
    assert res["category"] == "telemetry"
    assert res["risk_level"] == "telemetry"
    assert "Firebase" in res["vendor"]

    # Sentry error tracking
    res = analyzer.analyze_domain("o123.ingest.sentry.io")
    assert res["category"] == "telemetry"

    # Google DoubleClick advertising
    res = analyzer.analyze_domain("ad.doubleclick.net")
    assert res["category"] == "advertising"
    assert res["risk_level"] == "ad"
    assert "Реклама" in res["badge_text"]

    # Yandex advertising
    res = analyzer.analyze_domain("an.yandex.ru")
    assert res["category"] == "advertising"

@pytest.mark.asyncio
async def test_domain_classification_system_and_tunnels():
    analyzer = DomainAnalyzer()

    # DNS
    res = analyzer.analyze_domain("dns.google")
    assert res["category"] == "system_dns"
    assert res["risk_level"] == "safe"

    res_cf = analyzer.analyze_domain("one.one.one.one")
    assert res_cf["category"] == "system_dns"

    # Tailscale tunnel
    res_ts = analyzer.analyze_domain("derp22b.tailscale.com")
    assert res_ts["category"] == "vpn_tunnel"
    assert res_ts["risk_level"] == "warning"

    # Dynamic DNS
    res_duck = analyzer.analyze_domain("myhome.duckdns.org")
    assert res_duck["category"] == "vpn_tunnel"

@pytest.mark.asyncio
async def test_multi_device_tracking_per_domain(tmp_path):
    test_db = Database(db_path=tmp_path / "test_dns_devices.db")
    await test_db.init_db()

    # Create 2 devices in DB
    dev1 = DeviceRecord(mac="11:22:33:44:55:66", ip="192.168.1.100", hostname="Smart-Media-TV", custom_name="Гостиная ТВ", profile="smart_tv")
    dev2 = DeviceRecord(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.150", hostname="Mobile-User-01", custom_name="Телефон Пользователя", profile="phone")
    await test_db.upsert_device(dev1)
    await test_db.upsert_device(dev2)

    # Both devices communicate with google.com
    await test_db.record_dns_query("google.com", mac=dev1.mac, ip="172.217.16.206")
    await test_db.record_dns_query("google.com", mac=dev1.mac, ip="172.217.16.206")
    await test_db.record_dns_query("google.com", mac=dev2.mac, ip="172.217.16.206")

    devices = await test_db.get_domain_devices("google.com")
    assert len(devices) == 2
    
    # TV has 2 queries, Phone has 1
    tv_entry = next(d for d in devices if d["mac"] == dev1.mac)
    phone_entry = next(d for d in devices if d["mac"] == dev2.mac)
    assert tv_entry["count"] == 2
    assert tv_entry["custom_name"] == "Гостиная ТВ"
    assert tv_entry["profile"] == "smart_tv"
    assert phone_entry["count"] == 1
    assert phone_entry["custom_name"] == "Телефон Пользователя"

    all_counts = await test_db.get_all_dns_device_counts()
    assert "google.com" in all_counts
    assert len(all_counts["google.com"]) == 2

@pytest.mark.asyncio
async def test_custom_domain_rules_and_learning(tmp_path):
    test_db = Database(db_path=tmp_path / "test_custom_rules.db")
    await test_db.init_db()

    analyzer = DomainAnalyzer()
    
    # Before custom rule, unknown domain is 'unknown'
    initial = analyzer.analyze_domain("my-custom-smart-device.net")
    assert initial["category"] == "unknown"

    # Set custom rule in DB
    await test_db.set_custom_domain_rule(
        domain="my-custom-smart-device.net",
        category="iot_cloud",
        description="Мой самодельный датчик температуры",
        risk_level="safe"
    )

    rules = await test_db.get_custom_domain_rules()
    assert "my-custom-smart-device.net" in rules
    assert rules["my-custom-smart-device.net"]["description"] == "Мой самодельный датчик температуры"

    # Inject into analyzer
    analyzer._custom_rules = rules
    custom_res = analyzer.analyze_domain("my-custom-smart-device.net")
    assert custom_res["category"] == "iot_cloud"
    assert custom_res["is_custom"] is True
    assert "Мой самодельный датчик" in custom_res["description"]

@pytest.mark.asyncio
async def test_dns_api_endpoints(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_api_dns.db")
    await test_db.init_db()

    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.core.domain_analyzer.db", test_db)

    # Record some queries
    await test_db.record_dns_query("api.shelly.cloud", mac="70:C9:32:57:FD:7F", ip="46.8.177.66")
    await test_db.record_dns_query("adservice.google.com", mac="11:22:33:44:55:66", ip="142.250.74.206")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. GET /api/dns/queries
        resp = await ac.get("/api/dns/queries")
        assert resp.status_code == 200
        queries = resp.json()
        assert len(queries) >= 2
        
        iot_q = next(q for q in queries if q["domain"] == "api.shelly.cloud")
        assert iot_q["analysis"]["category"] == "iot_cloud"
        assert iot_q["analysis"]["risk_level"] == "safe"
        assert "devices" in iot_q

        # 2. GET /api/dns/analyze?domain=...
        resp_an = await ac.get("/api/dns/analyze?domain=api.shelly.cloud")
        assert resp_an.status_code == 200
        an_data = resp_an.json()
        assert an_data["domain"] == "api.shelly.cloud"
        assert an_data["analysis"]["category"] == "iot_cloud"
        assert "devices" in an_data

        # 3. POST /api/dns/custom-rule
        resp_post = await ac.post("/api/dns/custom-rule", json={
            "domain": "api.shelly.cloud",
            "category": "vpn_tunnel",
            "description": "Переопределено пользователем как туннель",
            "risk_level": "warning"
        })
        assert resp_post.status_code == 200
        
        # Verify custom rule applied
        resp_an2 = await ac.get("/api/dns/analyze?domain=api.shelly.cloud")
        assert resp_an2.json()["analysis"]["category"] == "vpn_tunnel"
        assert resp_an2.json()["analysis"]["is_custom"] is True

@pytest.mark.asyncio
async def test_expanded_domain_rules_and_cyan_badges():
    analyzer = DomainAnalyzer()

    # CloudFront & Cloud services -> cdn_media with cyan badge
    res_cf = analyzer.analyze_domain("server-13-33-237-86.hel51.r.cloudfront.net")
    assert res_cf["category"] == "cdn_media"
    assert res_cf["badge_color"] == "cyan"
    assert res_cf["badge_text"] == "Медиа/CDN"
    assert "CloudFront" in res_cf["vendor"]

    # Huawei Cloud & GCP
    res_hw = analyzer.analyze_domain("ecs-159-138-203-215.compute.hwclouds-dns.com")
    assert res_hw["category"] == "cdn_media"
    assert "Huawei" in res_hw["vendor"]

    res_gcp = analyzer.analyze_domain("208.24.120.34.bc.googleusercontent.com")
    assert res_gcp["category"] == "cdn_media"
    assert "Google" in res_gcp["vendor"]

    # Home Connect CDN / AWS Global Accelerator
    res_bosch = analyzer.analyze_domain("a7bc97ea7e96c511a.awsglobalaccelerator.com")
    assert res_bosch["category"] == "cdn_media"
    assert res_bosch["risk_level"] == "safe"

    # Valve / Steam
    res_steam = analyzer.analyze_domain("162-254-198-69.valve.net")
    assert res_steam["category"] == "cdn_media"
    assert "Steam" in res_steam["vendor"]

    # Keenetic captive portal
    res_keen = analyzer.analyze_domain("captive113.keenetic.ru")
    assert res_keen["category"] == "system_dns"
    assert "Keenetic" in res_keen["vendor"]

    # Weather & Sensors
    res_meteo = analyzer.analyze_domain("air-quality-api-eu01.open-meteo.com")
    assert res_meteo["category"] == "iot_cloud"
    assert res_meteo["risk_level"] == "safe"

    # Advertising & Trackers
    res_ad = analyzer.analyze_domain("944.bm-nginx-loadbalancer.mgmt.ams3.adnexus.net")
    assert res_ad["category"] == "advertising"
    assert res_ad["risk_level"] == "ad"
    assert "AppNexus" in res_ad["vendor"]

    # Telemetry
    res_telem = analyzer.analyze_domain("v10.events.data.microsoft.com")
    assert res_telem["category"] == "telemetry"
    assert res_telem["risk_level"] == "telemetry"

@pytest.mark.asyncio
async def test_sinkhole_detection_and_blocking():
    analyzer = DomainAnalyzer()

    # 1. IP checks
    assert analyzer.is_sinkhole_ip("0.0.0.0") is True
    assert analyzer.is_sinkhole_ip("127.0.0.1") is True
    assert analyzer.is_sinkhole_ip("::") is True
    assert analyzer.is_sinkhole_ip("::1") is True
    assert analyzer.is_sinkhole_ip("8.8.8.8") is False
    assert analyzer.is_sinkhole_ip(None) is False

    # 2. analyze_domain with sinkhole IP
    res_blocked = analyzer.analyze_domain("ad.lgsmartad.com", ip="0.0.0.0")
    assert res_blocked["is_blocked"] is True
    assert "0.0.0.0" in res_blocked["blocked_badge"]
    assert "0.0.0.0" in res_blocked["keenetic_tip"]

    # 3. analyze_domain with normal IP
    res_normal = analyzer.analyze_domain("google.com", ip="142.250.74.206")
    assert res_normal["is_blocked"] is False
    assert res_normal["blocked_badge"] == ""

@pytest.mark.asyncio
async def test_api_dns_queries_sinkhole_enrichment(tmp_path, monkeypatch):
    test_db = Database(db_path=tmp_path / "test_api_dns_sinkhole.db")
    await test_db.init_db()

    monkeypatch.setattr("keenguard.web.app.db", test_db)
    monkeypatch.setattr("keenguard.core.domain_analyzer.db", test_db)

    # 1 blocked ad query (0.0.0.0), 1 normal query
    await test_db.record_dns_query("ad.lgsmartad.com", mac="11:22:33:44:55:66", ip="0.0.0.0")
    await test_db.record_dns_query("weather.open-meteo.com", mac="70:C9:32:57:FD:7F", ip="46.46.175.247")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/dns/queries")
        assert resp.status_code == 200
        queries = resp.json()
        assert len(queries) == 2

        ad_q = next(q for q in queries if q["domain"] == "ad.lgsmartad.com")
        assert ad_q["is_blocked"] is True
        assert "0.0.0.0" in ad_q["blocked_reason"]
        assert ad_q["analysis"]["is_blocked"] is True

        normal_q = next(q for q in queries if q["domain"] == "weather.open-meteo.com")
        assert normal_q["is_blocked"] is False

        # Single domain analyze endpoint
        resp_an = await ac.get("/api/dns/analyze?domain=ad.lgsmartad.com")
        assert resp_an.status_code == 200
        data = resp_an.json()
        assert data["is_blocked"] is True