"""Tests for Plan 08: Lightweight L7 Application Classification."""
import pytest
from keenguard.core.app_classifier import AppClassifier, APP_CATALOG
from keenguard.core.audit.session import AuditSession
from keenguard.core.audit.report import build_device_audit_report, build_network_audit_report


def test_app_classifier_sni_matching():
    classifier = AppClassifier()
    
    # 1. YouTube SNI matching
    res = classifier.classify_flow(
        src_ip="192.168.1.100",
        dst_ip="172.217.16.206",
        dst_port=443,
        proto="tcp",
        sni="rr3---sn-4g5ednks.googlevideo.com"
    )
    assert res["app_id"] == "youtube"
    assert res["category"] == "streaming"
    assert res["matched_by"] == "sni_or_domain"

    # 2. Netflix SNI matching
    res_netflix = classifier.classify_flow(
        src_ip="192.168.1.50",
        dst_ip="54.154.10.20",
        dst_port=443,
        proto="tcp",
        sni="assets.nflxext.com"
    )
    assert res_netflix["app_id"] == "netflix"
    assert res_netflix["category"] == "streaming"


def test_app_classifier_dns_context_correlation():
    classifier = AppClassifier()

    # Pre-cache DNS resolution for Telegram
    tg_ip = "149.154.167.99"
    classifier.cache_dns_resolution(tg_ip, "web.telegram.org")
    assert classifier.get_domain_for_ip(tg_ip) == "web.telegram.org"

    # Subsequent TCP flow to that IP without SNI should resolve via cached DNS
    res = classifier.classify_flow(
        src_ip="192.168.1.100",
        dst_ip=tg_ip,
        dst_port=443,
        proto="tcp",
        sni=None
    )
    assert res["app_id"] == "telegram"
    assert res["category"] == "communication"
    assert res["name"] == "Telegram"


def test_app_classifier_port_matching():
    classifier = AppClassifier()

    # Steam game port in range 27000-27100
    res_steam = classifier.classify_flow(
        src_ip="192.168.1.100",
        dst_ip="162.254.197.40",
        dst_port=27015,
        proto="udp"
    )
    assert res_steam["app_id"] == "steam"
    assert res_steam["category"] == "gaming"

    # BitTorrent standard port
    res_torrent = classifier.classify_flow(
        src_ip="192.168.1.100",
        dst_ip="85.200.10.5",
        dst_port=6881,
        proto="tcp"
    )
    assert res_torrent["app_id"] == "bittorrent"
    assert res_torrent["category"] == "p2p"

    # WireGuard port
    res_wg = classifier.classify_flow(
        src_ip="192.168.1.100",
        dst_ip="198.51.100.1",
        dst_port=51820,
        proto="udp"
    )
    assert res_wg["app_id"] == "wireguard"
    assert res_wg["category"] == "vpn"


def test_app_classifier_aggregation():
    classifier = AppClassifier()

    flows = [
        {"app_id": "youtube", "name": "YouTube", "category": "streaming", "icon": "video", "bytes": 70000},
        {"app_id": "telegram", "name": "Telegram", "category": "communication", "icon": "send", "bytes": 20000},
        {"app_id": "other", "name": "Other", "category": "other", "icon": "activity", "bytes": 10000},
    ]

    summary = classifier.aggregate_apps(flows)
    assert summary["total_bytes"] == 100000

    breakdown = summary["apps_breakdown"]
    assert len(breakdown) == 3
    assert breakdown[0]["app_id"] == "youtube"
    assert breakdown[0]["percentage"] == 70.0
    assert breakdown[1]["app_id"] == "telegram"
    assert breakdown[1]["percentage"] == 20.0
    assert breakdown[2]["app_id"] == "other"
    assert breakdown[2]["percentage"] == 10.0

    cats = summary["categories_breakdown"]
    cat_map = {c["category"]: c["percentage"] for c in cats}
    assert cat_map["streaming"] == 70.0
    assert cat_map["communication"] == 20.0
    assert cat_map["other"] == 10.0


def test_audit_report_with_app_breakdown():
    session = AuditSession(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.55", hostname="Smart-TV-LG")
    
    # Simulate NAT flows
    nat_entries = [
        {
            "dst": "142.250.180.14",
            "dport": 443,
            "protocol": "TCP",
            "bytes": 50000,
            "bytes-out": 150000,
            "packets": 50,
            "packets-out": 100,
        }
    ]
    # Cache DNS resolution for Google Video
    from keenguard.core.app_classifier import app_classifier
    app_classifier.cache_dns_resolution("142.250.180.14", "r1---sn-4g5ednks.googlevideo.com")

    session.update_nat_entries(nat_entries)

    report = session.generate_report()
    assert "apps_breakdown" in report
    assert "categories_breakdown" in report
    assert len(report["apps_breakdown"]) > 0
    assert report["apps_breakdown"][0]["app_id"] == "youtube"
    assert report["apps_breakdown"][0]["category"] == "streaming"
