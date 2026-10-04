# -*- coding: utf-8 -*-
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from keenguard.core.dns.doh_catalog import (
    is_doh_domain,
    get_provider_for_domain,
    is_public_resolver_ip,
    get_provider_for_ip,
    DOH_DOMAINS,
    PUBLIC_RESOLVER_IPS,
)
from keenguard.core.dns.bypass_detector import DnsBypassDetector
from keenguard.core.keenetic import KeeneticClient
from keenguard.db.database import Database
from keenguard.web.app import app


def test_doh_catalog():
    """Verify DoH domain and Anycast IP lookups."""
    assert is_doh_domain("dns.google") is True
    assert is_doh_domain("sub.cloudflare-dns.com") is True
    assert is_doh_domain("use-application-dns.net") is True
    assert is_doh_domain("google.com") is False
    assert is_doh_domain("youtube.com") is False

    assert is_public_resolver_ip("8.8.8.8") is True
    assert is_public_resolver_ip("1.1.1.1") is True
    assert is_public_resolver_ip("9.9.9.9") is True
    assert is_public_resolver_ip("192.168.1.1") is False

    assert "Google" in get_provider_for_domain("dns.google")
    assert "Cloudflare" in get_provider_for_ip("1.1.1.1")


def test_dns_bypass_detector():
    """Verify detection of DoT (853), DoH (443), and unencrypted external DNS (53)."""
    detector = DnsBypassDetector(alert_cooldown_seconds=1)

    # 1. DoT on port 853
    res_dot = detector.inspect_flow(
        src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=853, proto="tcp", mac="00:11:22:33:44:55"
    )
    assert res_dot is not None
    assert res_dot["event_type"] == "dot_bypass"
    assert res_dot["severity"] == "warning"
    assert res_dot["should_alert"] is True

    # 2. DoH via SNI on port 443
    res_doh_sni = detector.inspect_flow(
        src_ip="192.168.1.60", dst_ip="104.16.249.249", dst_port=443, proto="tcp",
        sni="cloudflare-dns.com", mac="AA:BB:CC:DD:EE:01"
    )
    assert res_doh_sni is not None
    assert res_doh_sni["event_type"] == "doh_bypass"
    assert "Cloudflare" in res_doh_sni["provider"]

    # 3. DoH via known Anycast IP on port 443
    res_doh_ip = detector.inspect_flow(
        src_ip="192.168.1.70", dst_ip="1.1.1.1", dst_port=443, proto="tcp"
    )
    assert res_doh_ip is not None
    assert res_doh_ip["event_type"] == "doh_bypass"

    # 4. Standard HTTPS (e.g. github.com) must NOT trigger DoH bypass
    res_clean_https = detector.inspect_flow(
        src_ip="192.168.1.70", dst_ip="140.82.121.4", dst_port=443, proto="tcp", sni="github.com"
    )
    assert res_clean_https is None

    # 5. Direct external unencrypted DNS on port 53
    res_ext_dns = detector.inspect_flow(
        src_ip="192.168.1.80", dst_ip="8.8.4.4", dst_port=53, proto="udp"
    )
    assert res_ext_dns is not None
    assert res_ext_dns["event_type"] == "external_dns_bypass"


@pytest.mark.asyncio
async def test_keenetic_dot_and_sinkhole_methods():
    """Verify KeeneticClient mock methods for DoT blocking and DoH sinkholing."""
    client = KeeneticClient(host="192.168.1.1")
    client.mock_mode = True

    assert await client.is_dot_blocked() is False

    # Block DoT
    ok = await client.block_dot_traffic(True)
    assert ok is True
    assert await client.is_dot_blocked() is True

    # Unblock DoT
    ok = await client.block_dot_traffic(False)
    assert ok is True
    assert await client.is_dot_blocked() is False

    # Sinkhole DoH providers
    succeeded, failed = await client.sinkhole_doh_providers()
    assert len(succeeded) > 0
    assert "dns.google" in succeeded or "cloudflare-dns.com" in succeeded

    # Blackhole DoH IPs
    succeeded_ips, failed_ips = await client.blackhole_public_doh_resolvers()
    assert len(succeeded_ips) > 0
    assert "8.8.8.8" in succeeded_ips


def test_api_dns_security_endpoints(tmp_path):
    """Verify /api/dns/security endpoints."""
    mock_client = KeeneticClient(host="192.168.1.1")
    mock_client.mock_mode = True

    with patch("keenguard.web.state.get_keenetic_client", return_value=mock_client):
        client = TestClient(app)

        # GET bypass status
        resp = client.get("/api/dns/security/bypass-status")
        assert resp.status_code == 200
        data = resp.json()
        assert "dot_blocked" in data
        assert data["doh_catalog_total"] > 10

        # POST toggle-dot
        resp_toggle = client.post("/api/dns/security/toggle-dot", json={"block": True})
        assert resp_toggle.status_code == 200
        assert resp_toggle.json()["dot_blocked"] is True

        # POST sinkhole-doh
        resp_sinkhole = client.post("/api/dns/security/sinkhole-doh")
        assert resp_sinkhole.status_code == 200
        assert resp_sinkhole.json()["succeeded_count"] > 0
