import pytest
from unittest.mock import MagicMock
from keenguard.config import settings
from keenguard.core.routers.manager import RouterManager
from keenguard.core.routers.keenetic import KeeneticBackend
from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.routers.base import BaseRouterBackend


def test_router_manager_default_keenetic():
    mgr = RouterManager()
    backend = mgr.get_backend()
    assert isinstance(backend, KeeneticBackend)
    assert mgr.get_active_type() == "keenetic"
    assert backend.platform_name == "KeeneticOS"


def test_router_manager_switch_to_openwrt():
    orig_type = settings.router_type
    try:
        settings.router_type = "openwrt"
        mgr = RouterManager()
        backend = mgr.get_backend()
        assert isinstance(backend, OpenWrtBackend)
        assert mgr.get_active_type() == "openwrt"
        assert backend.platform_name == "OpenWrt"
    finally:
        settings.router_type = orig_type


def test_router_manager_set_backend_mock():
    mgr = RouterManager()
    mock_backend = MagicMock(spec=BaseRouterBackend)
    mock_backend.platform_name = "MockPlatform"
    mgr.set_backend(mock_backend)
    assert mgr.get_backend() == mock_backend
    assert mgr.get_backend().platform_name == "MockPlatform"


@pytest.mark.asyncio
async def test_router_manager_facade_delegation():
    mgr = RouterManager()
    mock_backend = MagicMock(spec=BaseRouterBackend)
    from unittest.mock import AsyncMock

    mock_backend.get_active_sinkholes = AsyncMock(return_value=["bad.com"])
    mock_backend.add_dns_sinkhole = AsyncMock(return_value=True)
    mock_backend.remove_dns_sinkhole = AsyncMock(return_value=True)
    mock_backend.add_dns_sinkholes = AsyncMock(return_value=(["bad1.com"], []))
    mock_backend.remove_dns_sinkholes = AsyncMock(return_value=(["bad1.com"], []))
    mock_backend.get_active_ip_blackholes = AsyncMock(return_value=["198.51.100.1"])
    mock_backend.add_ip_blackholes = AsyncMock(return_value=(["198.51.100.1"], []))
    mock_backend.remove_ip_blackholes = AsyncMock(return_value=(["198.51.100.1"], []))
    mock_backend.get_nat_table = AsyncMock(return_value=[{"src": "192.168.1.10", "dst": "8.8.8.8"}])
    mock_backend.get_wifi_security = AsyncMock(return_value={"grade": "A"})
    mock_backend.check_firmware_updates = AsyncMock(return_value={"has_update": False})
    mock_backend.get_upnp_mappings = AsyncMock(return_value=[])
    mock_backend.delete_upnp_mapping = AsyncMock(return_value=True)
    mock_backend.evaluate_segment_risk = MagicMock(return_value={"risk_level": "low"})
    mock_backend.is_packet_capture_supported = AsyncMock(return_value=True)
    mock_backend.start_packet_capture = AsyncMock(return_value={"status": "running"})
    mock_backend.stop_packet_capture = AsyncMock(return_value="capture.pcap")
    mock_backend.download_capture_file = AsyncMock(return_value=True)
    mock_backend.reset_packet_capture = AsyncMock(return_value=True)
    mock_backend.set_dlna_access = AsyncMock(return_value=True)
    mock_backend.enable_mdns_relay = AsyncMock(return_value=True)
    mock_backend.is_router_entity = MagicMock(return_value=False)

    mgr.set_backend(mock_backend)

    assert await mgr.get_active_sinkholes() == ["bad.com"]
    assert await mgr.add_dns_sinkhole("bad.com") is True
    assert await mgr.remove_dns_sinkhole("bad.com") is True
    assert await mgr.add_dns_sinkholes(["bad1.com"]) == (["bad1.com"], [])
    assert await mgr.remove_dns_sinkholes(["bad1.com"]) == (["bad1.com"], [])
    assert await mgr.get_active_ip_blackholes() == ["198.51.100.1"]
    assert await mgr.add_ip_blackholes(["198.51.100.1"]) == (["198.51.100.1"], [])
    assert await mgr.remove_ip_blackholes(["198.51.100.1"]) == (["198.51.100.1"], [])
    assert len(await mgr.get_nat_table()) == 1
    assert (await mgr.get_wifi_security())["grade"] == "A"
    assert (await mgr.check_firmware_updates())["has_update"] is False
    assert await mgr.get_upnp_mappings() == []
    assert await mgr.delete_upnp_mapping("tcp", 8080) is True
    assert mgr.evaluate_segment_risk("camera", "Home", "192.168.1.50")["risk_level"] == "low"
    assert await mgr.is_packet_capture_supported() is True
    assert (await mgr.start_packet_capture())["status"] == "running"
    assert await mgr.stop_packet_capture() == "capture.pcap"
    assert await mgr.download_capture_file("capture.pcap", "/tmp/cap.pcap") is True
    assert await mgr.reset_packet_capture() is True
    assert await mgr.set_dlna_access("00:11:22:33:44:55", "192.168.1.10") is True
    assert await mgr.enable_mdns_relay() is True
    assert mgr.is_router_entity("192.168.1.1") is False
