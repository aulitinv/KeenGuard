"""Tests for Camera WAN leak detection vs LAN streaming and NVR whitelisting."""
import pytest
import time
from unittest.mock import AsyncMock
from keenguard.core.anomaly import AnomalyDetector
from keenguard.db.models import DeviceRecord, SecurityEvent
from keenguard.config import settings

@pytest.mark.asyncio
async def test_camera_streaming_to_designated_nvr_is_silent():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    cam = DeviceRecord(
        mac="AA:11:22:33:44:55",
        ip="192.168.1.180",
        hostname="Yard-Camera",
        profile="camera",
        designated_nvr_ip="192.168.1.200"
    )

    # First counter entry
    detector.last_tx_counters[cam.mac] = (time.time() - 10.0, 100_000)

    # Stream to designated NVR (192.168.1.200)
    flows = [
        {"src_ip": "192.168.1.180", "dst_ip": "192.168.1.200", "bytes": 5_000_000}
    ]

    # Current tx: 5MB sent in 10s (~4000 kbps > threshold)
    await detector.check_camera_upload_leak(cam, current_tx_bytes=5_100_000, active_nat_flows=flows)

    # No security events recorded because destination was designated NVR
    mock_db.record_event.assert_not_called()

@pytest.mark.asyncio
async def test_camera_wan_upload_leak_triggers_alert():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    cam = DeviceRecord(
        mac="AA:11:22:33:44:55",
        ip="192.168.1.180",
        hostname="Yard-Camera",
        profile="camera",
        designated_nvr_ip="192.168.1.200"
    )

    # First counter entry
    detector.last_tx_counters[cam.mac] = (time.time() - 10.0, 100_000)

    # Stream to public external cloud IP (WAN)
    flows = [
        {"src_ip": "192.168.1.180", "dst_ip": "47.91.50.12", "bytes": 5_000_000}
    ]

    original_notify_wan = settings.camera_notify_wan_stream
    try:
        settings.camera_notify_wan_stream = True
        await detector.check_camera_upload_leak(cam, current_tx_bytes=5_100_000, active_nat_flows=flows)

        mock_db.record_event.assert_called_once()
        event = mock_db.record_event.call_args[0][0]
        assert isinstance(event, SecurityEvent)
        assert event.event_type == "camera_leak"
        assert event.target_mac == cam.mac
        assert event.details["stream_type"] == "wan"
        assert event.details["designated_nvr"] == "192.168.1.200"
    finally:
        settings.camera_notify_wan_stream = original_notify_wan

@pytest.mark.asyncio
async def test_camera_lan_stream_notification_toggle():
    mock_db = AsyncMock()
    detector = AnomalyDetector(db=mock_db)

    cam = DeviceRecord(
        mac="AA:11:22:33:44:55",
        ip="192.168.1.180",
        hostname="Yard-Camera",
        profile="camera",
        designated_nvr_ip="192.168.1.200"
    )

    # Stream to unauthorized local client (e.g. tablet at 192.168.1.55)
    flows = [
        {"src_ip": "192.168.1.180", "dst_ip": "192.168.1.55", "bytes": 5_000_000}
    ]

    original_lan_notify = settings.camera_notify_lan_stream
    original_wan_notify = settings.camera_notify_wan_stream
    try:
        # Case 1: LAN notify disabled (default)
        settings.camera_notify_lan_stream = False
        settings.camera_notify_wan_stream = True
        detector.last_tx_counters[cam.mac] = (time.time() - 10.0, 100_000)
        await detector.check_camera_upload_leak(cam, current_tx_bytes=5_100_000, active_nat_flows=flows)
        mock_db.record_event.assert_not_called()

        # Case 2: LAN notify enabled
        settings.camera_notify_lan_stream = True
        detector.last_tx_counters[cam.mac] = (time.time() - 10.0, 5_100_000)
        await detector.check_camera_upload_leak(cam, current_tx_bytes=10_100_000, active_nat_flows=flows)
        mock_db.record_event.assert_called_once()
        event = mock_db.record_event.call_args[0][0]
        assert event.event_type == "camera_lan_stream"
        assert event.details["stream_type"] == "lan"
    finally:
        settings.camera_notify_lan_stream = original_lan_notify
        settings.camera_notify_wan_stream = original_wan_notify
