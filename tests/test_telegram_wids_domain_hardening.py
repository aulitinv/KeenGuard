"""Unit tests for Telegram bot security, WIDS deduplication, domain reputation hardening, and in-memory bounds."""
import asyncio
from datetime import datetime, timezone
import socket
import struct
import time
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from keenguard.config import settings
from keenguard.core.domain_analyzer import (
    KNOWN_DOMAIN_RULES,
    FORBIDDEN_SINKHOLE_DOMAINS,
    is_ip_address_string,
    is_forbidden_or_local_domain,
    parse_dns_a_record,
    DomainAnalyzer,
)
from keenguard.core.notifier import TelegramNotifier
from keenguard.core.telegram_bot import TelegramBotWorker
from keenguard.core.wids import DeauthFloodDetector, WIDSService
from keenguard.core.lan_tracker import LanTrafficTracker
from keenguard.web.auth import BruteForceGuard, _failed_attempts
from keenguard.db.models import DeviceRecord, SecurityEvent


# ============================================================================
# 1. Domain Analyzer Tests (Deduplication, RFC 1035 Parser, Cache limit)
# ============================================================================

def test_known_domain_rules_no_duplicates():
    """Ensures KNOWN_DOMAIN_RULES has no duplicate domain patterns."""
    seen = set()
    duplicates = []
    for rule in KNOWN_DOMAIN_RULES:
        pattern = rule[0]
        if pattern in seen:
            duplicates.append(pattern)
        seen.add(pattern)
    assert not duplicates, f"Found duplicate domain rules in KNOWN_DOMAIN_RULES: {duplicates}"


def test_lgtvcommon_unique_and_telemetry():
    """Verifies that lgtvcommon.com is classified uniquely as telemetry."""
    matches = [r for r in KNOWN_DOMAIN_RULES if r[0] == "lgtvcommon.com"]
    assert len(matches) == 1, f"Expected 1 entry for lgtvcommon.com, found {len(matches)}"
    assert matches[0][1] == "telemetry", f"Expected category 'telemetry', got {matches[0][1]}"


def test_domain_validation_helpers():
    """Tests domain and IP validation functions."""
    assert is_ip_address_string("192.168.1.1") is True
    assert is_ip_address_string("2001:db8::1") is True
    assert is_ip_address_string("google.com") is False
    assert is_ip_address_string("192.168.1.300") is False

    assert is_forbidden_or_local_domain("localhost") is True
    assert is_forbidden_or_local_domain("my.keenetic.net") is True
    assert is_forbidden_or_local_domain("router.lan") is True
    assert is_forbidden_or_local_domain("device.local") is True
    assert is_forbidden_or_local_domain("device.home") is True
    assert is_forbidden_or_local_domain("mybox.keenetic.link") is True
    assert is_forbidden_or_local_domain("evil-tracker.com") is False


def test_parse_dns_a_record_direct_a():
    """Tests DNS parser on standard A record response."""
    qname = "example.com"
    q_bytes = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    q = q_bytes + struct.pack("!HH", 1, 1)
    ans = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("0.0.0.0")
    pkt = hdr + q + ans

    assert parse_dns_a_record(pkt) == "0.0.0.0"


def test_parse_dns_a_record_cname_followed_by_a():
    """Tests DNS parser when CNAME precedes A record."""
    qname = "ads.example.com"
    q_bytes = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
    q = q_bytes + struct.pack("!HH", 1, 1)

    cname_target = b"\x08sinkhole\x05local\x00"
    ans_cname = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 5, 1, 60, len(cname_target)) + cname_target
    ans_a = struct.pack("!H", 0xC00C) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
    pkt = hdr + q + ans_cname + ans_a

    assert parse_dns_a_record(pkt) == "127.0.0.1"


def test_parse_dns_a_record_invalid():
    """Tests DNS parser on malformed/short packets."""
    assert parse_dns_a_record(b"") is None
    assert parse_dns_a_record(b"shortpacket") is None
    hdr_no_ans = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 0, 0, 0)
    assert parse_dns_a_record(hdr_no_ans) is None


@pytest.mark.asyncio
async def test_domain_analyzer_cache_size_limit():
    """Tests that _sinkhole_cache does not grow unbounded beyond 2000 entries."""
    analyzer = DomainAnalyzer()
    now = time.time()
    # Pre-fill cache with 2005 entries
    for i in range(2005):
        analyzer._sinkhole_cache[f"domain{i}.com"] = (f"10.0.0.{i % 250}", now - (2005 - i))

    # Calling check_domain_sinkhole_async with a mock query
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        # Mock receiving empty or invalid
        mock_sock.recvfrom.return_value = (b"", ("127.0.0.1", 53))

        await analyzer.check_domain_sinkhole_async("newdomain.com")
        assert len(analyzer._sinkhole_cache) <= 2000


# ============================================================================
# 2. Telegram Notifier & Bot Security Tests (HTML Escaping, Auth, Sinkhole Check)
# ============================================================================

@pytest.mark.asyncio
async def test_telegram_notifier_html_escaping():
    """Tests that TelegramNotifier.send_alert escapes HTML entities in dynamic fields."""
    notifier = TelegramNotifier()
    notifier._client = MagicMock()
    captured_messages = []

    async def fake_send(text, **kwargs):
        captured_messages.append(text)
        return {"status": "ok"}

    notifier.send_message = AsyncMock(side_effect=fake_send)

    event = SecurityEvent(
        event_type="<script>alert(1)</script>",
        severity="high",
        target_mac="AA:BB:CC:DD:EE:FF",
        source_ip="192.168.1.50",
        description="Exploit attempt with <b style='color:red'>bold</b> & parameters",
        details={"raw": "<malicious>"}
    )

    with patch.object(settings, "telegram_enabled", True), \
         patch.object(settings, "telegram_bot_token", "test_token"), \
         patch.object(settings, "telegram_chat_id", "12345"):
        await notifier.send_alert(event)

    assert len(captured_messages) > 0
    msg = captured_messages[0]
    assert "<script>" not in msg
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in msg
    assert "&lt;b style=" in msg
    assert "&amp;" in msg


def test_telegram_bot_authorization():
    """Tests _is_authorized logic for direct user chats, groups, and allowed user ID list."""
    bot = TelegramBotWorker(notifier_instance=MagicMock())

    # Case A: Private chat (trusted_chat is user ID "12345")
    with patch.object(settings, "telegram_chat_id", "12345"), \
         patch.object(settings, "telegram_allowed_user_ids", []):
        assert bot._is_authorized("12345", chat_id=12345) is True
        assert bot._is_authorized("67890", chat_id=12345) is False
        assert bot._is_authorized("67890", chat_id=67890) is False

    # Case B: Group chat (trusted_chat is group ID "-100112233") without explicit allowed users
    with patch.object(settings, "telegram_chat_id", "-100112233"), \
         patch.object(settings, "telegram_allowed_user_ids", []):
        assert bot._is_authorized("555", chat_id="-100112233") is True
        assert bot._is_authorized("555", chat_id="999") is False

    # Case C: Group chat with explicit allowed user IDs ["555", "777"]
    with patch.object(settings, "telegram_chat_id", "-100112233"), \
         patch.object(settings, "telegram_allowed_user_ids", ["555", "777"]):
        assert bot._is_authorized("555", chat_id="-100112233") is True
        assert bot._is_authorized("888", chat_id="-100112233") is False
        # User 555 is also allowed directly in private chat because they are in allowed_users
        assert bot._is_authorized("555", chat_id="555") is True


@pytest.mark.asyncio
async def test_telegram_bot_block_dns_ip_and_forbidden_validation():
    """Tests that Telegram bot rejects IP addresses and protected router domains in block_dns callback."""
    notifier_mock = MagicMock()
    notifier_mock.answer_callback_query = AsyncMock()
    notifier_mock.edit_message_text = AsyncMock()
    notifier_mock.send_message = AsyncMock()

    bot = TelegramBotWorker(notifier_instance=notifier_mock)

    with patch.object(settings, "telegram_chat_id", "12345"), \
         patch.object(settings, "telegram_allowed_user_ids", []):

        # 1. Attempt to block an IP address
        query_ip = {
            "id": "q1",
            "from": {"id": 12345},
            "data": "block_dns:192.168.1.1",
            "message": {"chat": {"id": 12345}, "message_id": 10, "text": "DNS"}
        }
        await bot._handle_callback(query_ip)
        answer_text = notifier_mock.answer_callback_query.call_args[1]["text"]
        assert "является IP-адресом" in answer_text

        # 2. Attempt to block a forbidden domain
        query_forbidden = {
            "id": "q2",
            "from": {"id": 12345},
            "data": "block_dns:my.keenetic.net",
            "message": {"chat": {"id": 12345}, "message_id": 10, "text": "DNS"}
        }
        await bot._handle_callback(query_forbidden)
        answer_text = notifier_mock.answer_callback_query.call_args[1]["text"]
        assert "Запрещено блокировать" in answer_text


# ============================================================================
# 3. WIDS Tests (Deduplication & False-Positive Inactivity Filter)
# ============================================================================

def test_wids_deauth_detector_ignores_inactivity_disassociation():
    """Tests that 'disassociated due to inactivity' is ignored and does not trigger deauth alerts."""
    detector = DeauthFloodDetector()
    line = "Nov 22 10:00:00 Keenetic-Test wlan0: Station 00:11:22:33:44:55 disassociated due to inactivity"
    ev = detector.parse_log_line(line)
    assert ev is None

    # Normal deauth should parse
    active_line = "Nov 22 10:00:00 Keenetic-Test wlan0: Station 00:11:22:33:44:55 deauthenticated due to local deauth request"
    ev_active = detector.parse_log_line(active_line)
    assert ev_active is not None
    assert ev_active.mac == "00:11:22:33:44:55"


@pytest.mark.asyncio
async def test_wids_service_deduplicates_db_events():
    """Tests that repeating WIDS audit over identical logs does not spawn duplicate DB events."""
    service = WIDSService()
    mock_backend = MagicMock()
    mock_backend.get_wifi_security = AsyncMock(return_value={"networks": []})
    mock_backend.get_system_log = AsyncMock(return_value=[
        f"Nov 22 10:00:{i:02d} Keenetic wlan0: Station AA:BB:CC:DD:EE:FF deauthenticated due to local deauth request"
        for i in range(10)
    ])
    mock_backend.get_wlan_scan = AsyncMock(return_value=[])

    mock_db = MagicMock()
    mock_db.record_event = AsyncMock(return_value=101)

    # First run: incident detected, recorded in DB
    report1 = await service.run_wids_audit(mock_backend, db=mock_db, notify=False)
    assert len(report1["deauth_incidents"]) > 0
    assert mock_db.record_event.call_count == 1

    # Second run immediately with identical logs: should be deduplicated
    report2 = await service.run_wids_audit(mock_backend, db=mock_db, notify=False)
    assert len(report2["deauth_incidents"]) > 0
    # Still 1, not 2!
    assert mock_db.record_event.call_count == 1


# ============================================================================
# 4. In-Memory Limits Tests (LanTrafficTracker & BruteForceGuard)
# ============================================================================

def test_lan_tracker_memory_limits():
    """Tests size limits on flows, ping_matrix, arp_table, and pending_pings."""
    tracker = LanTrafficTracker()

    # 1. ARP Table limit (max 1000)
    with tracker._lock:
        for i in range(1050):
            if f"192.168.1.{i}" not in tracker.arp_table:
                tracker._prune_arp_table_locked()
            tracker.arp_table[f"192.168.1.{i}"] = f"AA:BB:CC:DD:{i//256:02X}:{i%256:02X}"
    assert len(tracker.arp_table) <= 1000

    # 2. Flows limit (max 2000)
    with tracker._lock:
        for i in range(2050):
            src = f"10.0.{i//256}.{i%256}"
            dst = "10.0.0.1"
            if (src, dst) not in tracker.flows:
                tracker._prune_flows_locked()
            tracker.flows[(src, dst)]["packet_count"] = 1
            tracker.flows[(src, dst)]["last_seen_epoch"] = time.time()
    assert len(tracker.flows) <= 2000

    # 3. Ping Matrix limit (max 1000)
    with tracker._lock:
        for i in range(1050):
            src = f"10.1.{i//256}.{i%256}"
            dst = "10.1.0.1"
            if (src, dst) not in tracker.ping_matrix:
                tracker._prune_ping_matrix_locked()
            tracker.ping_matrix[(src, dst)]["sent"] = 1
    assert len(tracker.ping_matrix) <= 1000

    # 4. Pending Pings TTL and limit (max 1000, TTL 5s)
    now = time.time()
    with tracker._lock:
        # Insert expired entries
        tracker.pending_pings[("192.168.1.10", "192.168.1.20", 1, 1)] = {
            "time": now - 10.0,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20"
        }
        # Insert fresh entries
        tracker.pending_pings[("192.168.1.10", "192.168.1.20", 1, 2)] = {
            "time": now,
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.20"
        }

    # Prune without incoming ICMP packet
    tracker.prune_pending_pings(now_time=now)
    assert ("192.168.1.10", "192.168.1.20", 1, 1) not in tracker.pending_pings
    assert ("192.168.1.10", "192.168.1.20", 1, 2) in tracker.pending_pings


def test_brute_force_guard_memory_limits():
    """Tests that BruteForceGuard._failed_attempts does not grow unbounded past 1000 IPs."""
    _failed_attempts.clear()
    now = time.time()

    # Simulate 1050 distinct IPs failing authentication
    for i in range(1050):
        ip = f"198.51.{i//256}.{i%256}"
        BruteForceGuard.record_failure(ip)

    assert len(_failed_attempts) <= 1000
    _failed_attempts.clear()
