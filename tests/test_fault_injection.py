"""Fault injection and robustness tests for Telegram, Sniffer, and WebSocket components."""
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
import httpx
from starlette.websockets import WebSocketDisconnect

from keenguard.core.notifier import TelegramNotifier
from keenguard.db.models import SecurityEvent
from keenguard.core.sniffer import NetworkSniffer, PacketRingBuffer
from keenguard.web.ws import ConnectionManager
from scapy.all import Ether, IP, TCP


@pytest.mark.asyncio
async def test_telegram_notifier_handles_http_errors():
    """TelegramNotifier should handle 502/429/timeouts gracefully without crashing the app."""
    notifier = TelegramNotifier()
    notifier.bot_token = "dummy_token"
    notifier.chat_id = "123456789"
    notifier.enabled = True

    ev = SecurityEvent(
        event_type="policy_violation",
        severity="critical",
        description="Test violation"
    )

    # 1. HTTP 502 Bad Gateway
    mock_resp_502 = httpx.Response(502, text="Bad Gateway", request=httpx.Request("POST", "http://test"))
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp_502)):
        # Should not raise exception
        success = await notifier.send_alert(ev)
        assert success is False

    # 2. HTTP 429 Too Many Requests / FloodWait
    mock_resp_429 = httpx.Response(429, text="Flood wait", request=httpx.Request("POST", "http://test"))
    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=mock_resp_429)):
        success = await notifier.send_alert(ev)
        assert success is False

    # 3. Connection timeout
    with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=httpx.ConnectTimeout("Telegram timeout"))):
        success = await notifier.send_alert(ev)
        assert success is False


def test_packet_ring_buffer_overflow_and_fifo_eviction():
    """Validates that PacketRingBuffer enforces max_packets limit with FIFO eviction under high packet pressure."""
    buf = PacketRingBuffer(max_packets=50, max_age_seconds=60)

    # Push 150 packets
    for i in range(150):
        pkt = Ether() / IP(src="192.168.1.10", dst=f"192.168.1.{i % 100}") / TCP(dport=80)
        buf.add(pkt, pid=f"pkt_{i}")

    # Buffer length must be exactly 50
    assert len(buf) == 50
    all_pkts = buf.get_packets()
    assert len(all_pkts) == 50

    # Earliest packets should be pkt_100 to pkt_149 (FIFO eviction)
    assert buf.find_by_id("pkt_0") is None
    assert buf.find_by_id("pkt_99") is None
    assert buf.find_by_id("pkt_100") is not None
    assert buf.find_by_id("pkt_149") is not None


@pytest.mark.asyncio
async def test_websocket_broadcast_resilience_to_dead_sockets():
    """Broadcast must remove broken sockets and continue delivering messages to healthy sockets."""
    manager = ConnectionManager()

    # Create mock WebSocket clients
    healthy_ws = AsyncMock()
    healthy_ws.accept = AsyncMock()
    healthy_ws.send_json = AsyncMock()

    broken_ws = AsyncMock()
    broken_ws.accept = AsyncMock()
    broken_ws.send_json = AsyncMock(side_effect=RuntimeError("Cannot call 'send' once a close message has been sent"))

    disconnecting_ws = AsyncMock()
    disconnecting_ws.accept = AsyncMock()
    disconnecting_ws.send_json = AsyncMock(side_effect=WebSocketDisconnect())

    await manager.connect(healthy_ws)
    await manager.connect(broken_ws)
    await manager.connect(disconnecting_ws)

    assert len(manager.active_connections) == 3

    # Broadcast message
    await manager.broadcast({"type": "ping", "data": "test"})

    # Healthy socket must have received the broadcast
    healthy_ws.send_json.assert_awaited_once_with({"type": "ping", "data": "test"})

    # Broken and disconnected sockets must have been purged from active_connections
    assert len(manager.active_connections) == 1
    assert healthy_ws in manager.active_connections
    assert broken_ws not in manager.active_connections
    assert disconnecting_ws not in manager.active_connections
