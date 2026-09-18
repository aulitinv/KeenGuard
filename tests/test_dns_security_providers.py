import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from httpx import AsyncClient, ASGITransport, Response

from keenguard.core.dns_providers import (
    NextDnsProvider,
    ControlDProvider,
    AdGuardHomeProvider,
    PiHoleProvider,
    DnsSecurityManager,
    dns_security_manager,
    UnifiedBlockedDnsQuery,
    DnsProviderStatus,
)
from keenguard.db.models import DeviceRecord
from keenguard.db.database import db
from keenguard.web.app import app


# Synthetic network entities conforming to Zero-Leak policy
SYNTHETIC_IP = "192.168.1.105"
SYNTHETIC_MAC = "aa:bb:cc:dd:ee:55"
SYNTHETIC_HOSTNAME = "smart-tv-living-room"


@pytest.mark.asyncio
async def test_nextdns_provider_flow():
    """Test NextDNS connection check and log parsing."""
    provider = NextDnsProvider(profile_id="testprof123", api_key="test_api_key_xyz")

    # 1. Test connection
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json={"data": {"id": "testprof123", "name": "Home Profile"}})
        status = await provider.test_connection()
        assert status.is_connected is True
        assert "Home Profile" in status.profile_or_version

    # 2. Fetch blocked logs
    sample_logs = {
        "data": [
            {
                "timestamp": "2026-09-18T10:00:00Z",
                "domain": "adservice.google.com",
                "status": "blocked",
                "reasons": [{"id": "nextdns-recommended", "name": "NextDNS Ads & Trackers"}],
                "clientIp": SYNTHETIC_IP,
                "deviceName": SYNTHETIC_HOSTNAME,
                "tracker": {"category": "advertising"},
            },
            {
                "timestamp": "2026-09-18T10:01:00Z",
                "domain": "safe-domain.org",
                "status": "allowed",
                "clientIp": SYNTHETIC_IP,
            },
        ]
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json=sample_logs)
        queries = await provider.fetch_blocked_logs(limit=50)
        assert len(queries) == 1
        q = queries[0]
        assert q.domain == "adservice.google.com"
        assert q.provider == "nextdns"
        assert "NextDNS Ads & Trackers" in (q.filter_list or "")
        assert q.client_ip == SYNTHETIC_IP


@pytest.mark.asyncio
async def test_controld_provider_flow():
    """Test Control D connection check and activity log parsing."""
    provider = ControlDProvider(api_key="cd_token_secret", device_id="device_tv_01")

    # 1. Test connection
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json={"body": {"devices": [{"PK": "dev1", "name": "Router"}]}})
        status = await provider.test_connection()
        assert status.is_connected is True
        assert "Control D" in status.provider_name

    # 2. Fetch blocked logs
    sample_logs = {
        "body": {
            "activity": [
                {
                    "timestamp": 1789725600,
                    "domain": "analytics.tiktok.com",
                    "action": 0,  # Blocked in Control D
                    "rule": "Native Tracking Filter",
                    "ip": SYNTHETIC_IP,
                    "device_name": SYNTHETIC_HOSTNAME,
                },
                {
                    "timestamp": 1789725610,
                    "domain": "allowed-api.example.com",
                    "action": 1,  # Allowed
                    "ip": SYNTHETIC_IP,
                },
            ]
        }
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json=sample_logs)
        queries = await provider.fetch_blocked_logs(limit=50)
        assert len(queries) == 1
        q = queries[0]
        assert q.domain == "analytics.tiktok.com"
        assert q.provider == "controld"
        assert q.filter_list == "Native Tracking Filter"
        assert q.client_ip == SYNTHETIC_IP


@pytest.mark.asyncio
async def test_adguard_home_provider_flow():
    """Test AdGuard Home connection check and querylog parsing."""
    provider = AdGuardHomeProvider(url="http://192.168.1.1:3000", username="admin", password="password123")

    # 1. Test connection
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json={"version": "v0.107.43", "running": True})
        status = await provider.test_connection()
        assert status.is_connected is True
        assert "v0.107.43" in status.profile_or_version

    # 2. Fetch blocked logs
    sample_querylog = {
        "data": [
            {
                "time": "2026-09-18T10:05:00.000Z",
                "question": {"name": "metrics.icloud.com", "type": "A"},
                "reason": "FilteredBlacklist",
                "rule": "||metrics.icloud.com^",
                "filter_id": 1,
                "client": SYNTHETIC_IP,
                "client_proto": "doh",
            },
            {
                "time": "2026-09-18T10:06:00.000Z",
                "question": {"name": "apple.com", "type": "A"},
                "reason": "NotFilteredNotFound",
                "client": SYNTHETIC_IP,
            },
        ]
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json=sample_querylog)
        queries = await provider.fetch_blocked_logs(limit=50)
        assert len(queries) == 1
        q = queries[0]
        assert q.domain == "metrics.icloud.com"
        assert q.provider == "adguard_home"
        assert "||metrics.icloud.com^" in (q.filter_list or "")
        assert q.client_ip == SYNTHETIC_IP


@pytest.mark.asyncio
async def test_pihole_provider_flow():
    """Test Pi-hole connection check and query parsing."""
    provider = PiHoleProvider(url="http://192.168.1.1/admin", api_token="secret_pi_hash")

    # 1. Test connection (v5 FTL format)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json={"status": "enabled", "FTLnotrunning": False, "domains_being_blocked": 125000})
        status = await provider.test_connection()
        assert status.is_connected is True
        assert status.active_filters_count == 125000
        assert "Pi-hole v5" in status.profile_or_version

    # 2. Fetch blocked logs (v5 format)
    sample_queries = {
        "data": [
            [
                "1789725700",  # timestamp
                "A",           # type
                "telemetry.samsungcloudplatform.com",  # domain
                SYNTHETIC_IP,  # client
                "5",           # status 5 = Blocked (gravity)
                "0",           # dnssec
                "0",           # reply
                "0",           # response time
            ],
            [
                "1789725710",
                "A",
                "samsung.com",
                SYNTHETIC_IP,
                "2",           # status 2 = Forwarded (allowed)
                "0",
                "0",
                "0",
            ],
        ]
    }
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = Response(200, json=sample_queries)
        queries = await provider.fetch_blocked_logs(limit=50)
        assert len(queries) == 1
        q = queries[0]
        assert q.domain == "telemetry.samsungcloudplatform.com"
        assert q.provider == "pihole"
        assert "Gravity" in (q.filter_list or "")
        assert q.client_ip == SYNTHETIC_IP


@pytest.mark.asyncio
async def test_dns_security_manager_sync_and_attribution():
    """Test DnsSecurityManager synchronization, IP-to-device attribution, and SQLite persistence."""
    await db.upsert_device(
        DeviceRecord(
            mac=SYNTHETIC_MAC,
            ip=SYNTHETIC_IP,
            hostname=SYNTHETIC_HOSTNAME,
            vendor="LG Electronics",
            profile="smart_tv",
        )
    )
    manager = DnsSecurityManager()

    mock_provider = MagicMock()
    mock_provider.provider_id = "nextdns"
    mock_provider.name = "nextdns"
    mock_provider.test_connection = AsyncMock(return_value=DnsProviderStatus(
        is_connected=True,
        provider_name="NextDNS",
        profile_or_version="Connected"
    ))
    mock_provider.fetch_blocked_logs = AsyncMock(return_value=[
        UnifiedBlockedDnsQuery(
            timestamp="2026-09-18T10:10:00Z",
            domain="samsungacr.com",
            provider="nextdns",
            client_ip=SYNTHETIC_IP,
            client_device_name=SYNTHETIC_HOSTNAME,
            block_reason="NextDNS ACR Tracker Block",
            filter_list="Smart TV Tracking Protection",
            tracker_category="telemetry",
        )
    ])

    manager._active_provider_id = "nextdns"
    manager._providers["nextdns"] = mock_provider
    res = await manager.sync_blocked_logs()
    assert res["success"] is True
    assert res["count"] == 1

    # Verify query stored in database
    queries = await db.get_top_dns_queries(limit=10)
    matched = next((item for item in queries if item.get("domain") == "samsungacr.com"), None)
    assert matched is not None
    assert matched.get("is_blocked") == 1
    assert matched.get("blocked_by_provider") == "nextdns"
    assert matched.get("filter_list") == "Smart TV Tracking Protection"

    # Verify device attribution matched synthetic device MAC in dns_device_queries
    domain_devices = await db.get_domain_devices("samsungacr.com")
    assert any(d.get("mac", "").lower() == SYNTHETIC_MAC.lower() for d in domain_devices)

    # Verify sync metadata updated
    meta = await db.get_dns_provider_sync_meta("nextdns")
    assert meta["total_blocked_synced"] >= 1
    assert meta["last_status"] == "success"


@pytest.mark.asyncio
async def test_dns_provider_api_endpoints():
    """Test REST API endpoints for DNS security configuration, connection testing, and helper guides."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET Helpers
        res = await client.get("/api/dns/provider/helpers")
        assert res.status_code == 200
        data = res.json()
        assert "doh_dot_bypass" in data
        assert "streaming_ads" in data
        assert "device_attribution" in data

        # 2. GET Config
        res = await client.get("/api/dns/provider/config")
        assert res.status_code == 200
        cfg = res.json()
        assert "dns_security_provider" in cfg

        # 3. POST Config
        res = await client.post("/api/dns/provider/config", json={
            "dns_security_provider": "nextdns",
            "nextdns_profile_id": "test_api_profile",
            "dns_security_auto_sync": False,
            "dns_security_sync_interval": 120,
        })
        assert res.status_code == 200
        assert res.json()["status"] == "ok"

        # 4. POST Test with mock
        with patch.object(NextDnsProvider, "test_connection", new_callable=AsyncMock) as mock_test:
            mock_test.return_value = DnsProviderStatus(
                is_connected=True,
                provider_name="NextDNS",
                profile_or_version="Profile Active",
                active_filters_count=4,
            )
            res = await client.post("/api/dns/provider/test", json={
                "provider": "nextdns",
                "config_override": {"nextdns_profile_id": "test_api_profile"}
            })
            assert res.status_code == 200
            assert res.json()["ok"] is True

        # 5. POST Sync with mock
        with patch.object(dns_security_manager, "sync_blocked_logs", new_callable=AsyncMock) as mock_sync:
            mock_sync.return_value = {"success": True, "count": 5, "provider": "nextdns"}
            res = await client.post("/api/dns/provider/sync")
            assert res.status_code == 200
            assert res.json()["synced"] == 5

        # 6. GET Status
        res = await client.get("/api/dns/provider/status")
        assert res.status_code == 200
        status = res.json()
        assert "provider" in status
        assert "total_blocked_queries_synced" in status
