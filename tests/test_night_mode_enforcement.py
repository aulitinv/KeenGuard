"""Unit tests for Smart TV night mode deferrals, WAN enforcement, and morning alerts."""
import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from keenguard.config import settings
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord
from keenguard.core.scheduler import BackgroundScheduler
from keenguard.core.enums import EventType, Severity


@pytest.mark.asyncio
async def test_smart_tv_night_mode_deferral_when_active():
    """If TV is active at night (e.g. streaming video), night mode must be deferred."""
    scheduler = BackgroundScheduler()
    tv_mac = "AA:BB:CC:11:22:33"
    tv_ip = "192.168.1.77"

    device = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="LivingRoom-TV",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=True
    )
    await db.upsert_device(device)

    # Simulated night time (01:00)
    night_dt = datetime(2026, 9, 20, 1, 0, 0)
    settings.night_mode_start_hour = 0
    settings.night_mode_end_hour = 7
    settings.night_mode_tv_inactivity_minutes = 5
    settings.night_mode_auto_block_wan = True

    # When TV is active, _is_device_active returns True
    with patch.object(scheduler, "_is_device_active", new=AsyncMock(return_value=True)):
        await scheduler._check_night_mode_transitions(night_dt)

    state = scheduler._tv_night_status.get(tv_mac)
    assert state is not None
    assert state["in_night_mode"] is False
    assert state["entered_night_mode_tonight"] is False
    assert state["wan_blocked_by_night_mode"] is False


@pytest.mark.asyncio
async def test_smart_tv_night_mode_activation_after_inactivity():
    """When TV has been inactive for >= N minutes, night mode activates and blocks WAN if configured."""
    scheduler = BackgroundScheduler()
    tv_mac = "AA:BB:CC:11:22:44"
    tv_ip = "192.168.1.78"

    device = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="Bedroom-TV",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=True
    )
    await db.upsert_device(device)

    night_dt = datetime(2026, 9, 20, 2, 0, 0)
    settings.night_mode_start_hour = 0
    settings.night_mode_end_hour = 7
    settings.night_mode_tv_inactivity_minutes = 5
    settings.night_mode_auto_block_wan = True

    # Pre-populate state with last_active_time = 10 minutes ago
    scheduler._tv_night_status[tv_mac] = {
        "entered_night_mode_tonight": False,
        "in_night_mode": False,
        "wan_blocked_by_night_mode": False,
        "morning_notified": False,
        "last_active_time": time.time() - 600.0  # 10 minutes ago
    }

    with patch.object(scheduler, "_is_device_active", new=AsyncMock(return_value=False)), \
         patch("keenguard.core.profiles.profile_manager.toggle_wan", new=AsyncMock(return_value=True)) as mock_toggle:
        await scheduler._check_night_mode_transitions(night_dt)
        mock_toggle.assert_awaited_once_with(tv_mac, block=True)

    state = scheduler._tv_night_status[tv_mac]
    assert state["in_night_mode"] is True
    assert state["entered_night_mode_tonight"] is True
    assert state["wan_blocked_by_night_mode"] is True


@pytest.mark.asyncio
async def test_morning_unblock_and_no_alert_when_tv_entered_night_mode():
    """In morning (07:00), if TV was in night mode, WAN is restored and no 'never slept' alert is fired."""
    scheduler = BackgroundScheduler()
    tv_mac = "AA:BB:CC:11:22:55"
    tv_ip = "192.168.1.79"

    device = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="Guest-TV",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=True
    )
    await db.upsert_device(device)

    morning_dt = datetime(2026, 9, 20, 7, 5, 0)
    settings.night_mode_start_hour = 0
    settings.night_mode_end_hour = 7

    scheduler._tv_night_status[tv_mac] = {
        "entered_night_mode_tonight": True,
        "in_night_mode": True,
        "wan_blocked_by_night_mode": True,
        "morning_notified": False,
        "last_active_time": time.time() - 3600.0
    }

    with patch("keenguard.core.profiles.profile_manager.toggle_wan", new=AsyncMock(return_value=True)) as mock_toggle, \
         patch("keenguard.db.database.db.record_event", new=AsyncMock()) as mock_record:
        await scheduler._check_night_mode_transitions(morning_dt)
        mock_toggle.assert_awaited_once_with(tv_mac, block=False)
        mock_record.assert_not_called()

    state = scheduler._tv_night_status[tv_mac]
    assert state["in_night_mode"] is False
    assert state["wan_blocked_by_night_mode"] is False
    assert state["entered_night_mode_tonight"] is False


@pytest.mark.asyncio
async def test_morning_alert_when_tv_never_slept_all_night():
    """In morning (07:00), if TV was active all night and never entered night mode, user is alerted."""
    scheduler = BackgroundScheduler()
    tv_mac = "AA:BB:CC:11:22:66"
    tv_ip = "192.168.1.80"

    device = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="Active-TV",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=True
    )
    await db.upsert_device(device)

    morning_dt = datetime(2026, 9, 20, 7, 10, 0)
    settings.night_mode_start_hour = 0
    settings.night_mode_end_hour = 7
    settings.night_mode_notify_tv_never_slept = True

    scheduler._tv_night_status[tv_mac] = {
        "entered_night_mode_tonight": False,
        "in_night_mode": False,
        "wan_blocked_by_night_mode": False,
        "morning_notified": False,
        "last_active_time": time.time()
    }

    recorded_events = []
    async def fake_record_event(ev):
        recorded_events.append(ev)
        return 1

    with patch("keenguard.db.database.db.record_event", side_effect=fake_record_event), \
         patch("keenguard.core.notifier.notifier.send_alert", new=AsyncMock()) as mock_alert:
        await scheduler._check_night_mode_transitions(morning_dt)

        assert len(recorded_events) == 1
        ev = recorded_events[0]
        assert ev.event_type == EventType.TV_STANDBY_WAKE.value
        assert ev.severity == Severity.WARNING.value
        assert "за всю ночь так и не перешёл в ночной режим" in ev.description
        mock_alert.assert_awaited_once()

    state = scheduler._tv_night_status[tv_mac]
    assert state["morning_notified"] is True


@pytest.mark.asyncio
async def test_no_false_morning_alert_on_daytime_startup():
    """When server starts during daytime/evening (outside night window), no false 'never slept' alert fires."""
    scheduler = BackgroundScheduler()
    tv_mac = "AA:BB:CC:11:22:77"
    tv_ip = "192.168.1.85"

    device = DeviceRecord(
        mac=tv_mac,
        ip=tv_ip,
        hostname="LGwebOSTV",
        profile="smart_tv",
        night_mode_enabled=True,
        is_online=False
    )
    await db.upsert_device(device)

    # Server starts in the evening at 22:35
    evening_dt = datetime(2026, 9, 20, 22, 35, 0)
    settings.night_mode_start_hour = 0
    settings.night_mode_end_hour = 7
    settings.night_mode_notify_tv_never_slept = True

    # Empty _tv_night_status as fresh startup
    assert tv_mac not in scheduler._tv_night_status

    with patch("keenguard.db.database.db.record_event", new=AsyncMock()) as mock_record, \
         patch("keenguard.core.notifier.notifier.send_alert", new=AsyncMock()) as mock_alert:
        await scheduler._check_night_mode_transitions(evening_dt)
        mock_record.assert_not_called()
        mock_alert.assert_not_called()

    # Verify state initialized correctly for daytime
    state = scheduler._tv_night_status[tv_mac]
    assert state["morning_notified"] is True
    assert state["was_in_night_window"] is False

