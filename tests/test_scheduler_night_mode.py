import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from keenguard.core.sniffer import get_sniffer, sniffer, NetworkSniffer
from keenguard.core.scheduler import scheduler, BackgroundScheduler


def test_sniffer_accessor_exists():
    """Verify that get_sniffer() is cleanly exported from keenguard.core.sniffer and returns the singleton."""
    assert callable(get_sniffer)
    instance = get_sniffer()
    assert isinstance(instance, NetworkSniffer)
    assert instance is sniffer


@pytest.mark.asyncio
async def test_scheduler_is_device_active_runs_without_import_error():
    """Verify that _is_device_active imports sniffer and checks activity without raising ImportError."""
    mock_device = MagicMock()
    mock_device.mac = "00:11:22:33:44:55"
    mock_device.is_online = True
    mock_device.last_seen = datetime.now(timezone.utc).isoformat()

    with patch("keenguard.core.scheduler.db.get_device_traffic_history", new_callable=AsyncMock) as mock_hist:
        mock_hist.return_value = []
        is_active = await scheduler._is_device_active(mock_device, threshold_minutes=5)
        # Device is online and last_seen is right now (< 60s), so it should return True cleanly
        assert is_active is True


@pytest.mark.asyncio
async def test_scheduler_night_mode_transitions_loop_handles_devices():
    """Verify night mode transition check runs without uncaught exceptions."""
    mock_device = MagicMock()
    mock_device.mac = "00:11:22:33:44:55"
    mock_device.night_mode_enabled = True
    mock_device.is_online = False
    mock_device.last_seen = None
    mock_device.hostname = "Test Smart TV"
    mock_device.ip = "192.168.1.100"
    mock_device.is_blocked_wan = False

    with patch("keenguard.core.scheduler.db.get_all_devices", new_callable=AsyncMock) as mock_devices, \
         patch("keenguard.core.scheduler.forensics.is_night_time", return_value=True), \
         patch.object(scheduler, "_is_device_active", new_callable=AsyncMock, return_value=False):
        mock_devices.return_value = [mock_device]
        # Should execute cleanly without error
        await scheduler._check_night_mode_transitions(datetime(2026, 10, 6, 2, 0, 0))
        assert "00:11:22:33:44:55" in scheduler._tv_night_status
