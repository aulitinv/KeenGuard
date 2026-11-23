"""Unit tests for OpenWrt and Keenetic router backend integrity, error handling, and DB consistency."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock, PropertyMock
from fastapi.testclient import TestClient

from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.keenetic.models import is_rci_success, is_unsafe_ip_for_blackhole
from keenguard.core.keenetic.client import KeeneticClient
from keenguard.core.routers import router_manager
from keenguard.core.profiles import PolicyManager
from keenguard.db.database import db
from keenguard.db.models import DeviceRecord
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_openwrt_mock_mode_no_attribute_error():
    """Verify that OpenWrtBackend initializes mock_mode and does not raise AttributeError."""
    # Default instance
    default_backend = OpenWrtBackend()
    assert default_backend.mock_mode is False

    # Mock mode instance
    mock_backend = OpenWrtBackend(mock_mode=True)
    assert mock_backend.mock_mode is True

    # Call get_system_log and get_wlan_scan in mock mode
    logs = await mock_backend.get_system_log()
    assert isinstance(logs, list)
    assert len(logs) > 0
    assert any("netifd" in line for line in logs)

    scan = await mock_backend.get_wlan_scan()
    assert isinstance(scan, list)
    assert len(scan) > 0
    assert scan[0]["ssid"] == "Neighbor-Net"


@pytest.mark.asyncio
async def test_openwrt_start_packet_capture_validation():
    """Verify that start_packet_capture strictly validates all input parameters and prevents injection."""
    backend = OpenWrtBackend()

    # 1. Flag injection in target IP
    res_flag = await backend.start_packet_capture(ip="1.2.3.4 -z /tmp/x")
    assert res_flag["status"] == "error"
    assert "Invalid target IP address" in res_flag["message"]

    # 2. Invalid protocol
    res_proto = await backend.start_packet_capture(ip="198.51.100.10", proto="invalid_proto")
    assert res_proto["status"] == "error"
    assert "Invalid protocol" in res_proto["message"]

    # 3. Invalid port
    res_port = await backend.start_packet_capture(ip="198.51.100.10", port=99999)
    assert res_port["status"] == "error"
    assert "Port out of range" in res_port["message"]

    # 4. Invalid interface
    res_iface = await backend.start_packet_capture(interface="br-lan; rm -rf /")
    assert res_iface["status"] == "error"
    assert "Invalid interface name" in res_iface["message"]

    # 5. Valid parameters execution
    captured_calls = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        captured_calls.append((subsystem, method, params))
        if subsystem == "file" and method == "exec":
            return {"code": 0, "stdout": "/usr/sbin/tcpdump"}
        return {}

    backend._call_ubus = mock_call
    backend.is_packet_capture_supported = AsyncMock(return_value=True)

    res_ok = await backend.start_packet_capture(
        interface="Bridge0",  # Should be normalized to br-lan
        ip="198.51.100.10",
        proto="tcp",
        port=443
    )

    assert res_ok["status"] == "ok"
    assert res_ok["interface"] == "br-lan"
    assert res_ok["pcap_file"] == "/tmp/keenguard_capture.pcap"

    # Verify background execution without raw split vulnerability
    exec_call = next((p for s, m, p in captured_calls if s == "file" and m == "exec"), None)
    assert exec_call is not None
    assert exec_call["command"] == "/bin/sh"
    sh_cmd = exec_call["params"][1]
    assert "nohup" not in sh_cmd
    assert "timeout" in sh_cmd
    assert "/usr/sbin/tcpdump -i br-lan -c 50000 -C 10 -w /tmp/keenguard_capture.pcap -s 0 -U host 198.51.100.10 and tcp and port 443" in sh_cmd


@pytest.mark.asyncio
async def test_openwrt_add_ip_blackholes_rejects_unsafe():
    """Verify that OpenWrtBackend.add_ip_blackholes rejects unsafe or local IPs."""
    backend = OpenWrtBackend()
    backend._call_ubus = AsyncMock(return_value={})

    test_ips = ["192.168.1.1", "127.0.0.1", "10.0.0.1", "invalid_ip", "198.51.100.99"]
    succeeded, failed = await backend.add_ip_blackholes(test_ips)

    assert "192.168.1.1" in failed
    assert "127.0.0.1" in failed
    assert "10.0.0.1" in failed
    assert "invalid_ip" in failed
    assert "198.51.100.99" in succeeded


def test_is_rci_success_detection():
    """Verify is_rci_success detects errors even when HTTP status is 200."""
    # None check
    assert is_rci_success(None) is False

    # HTTP 500
    mock_500 = MagicMock()
    mock_500.status_code = 500
    assert is_rci_success(mock_500) is False

    # HTTP 200 with {"status": "error"}
    mock_err = MagicMock()
    mock_err.status_code = 200
    mock_err.json.return_value = [{"status": "error", "message": "Command syntax error"}]
    assert is_rci_success(mock_err) is False

    # HTTP 200 with nested {"status": "error"}
    mock_nested_err = MagicMock()
    mock_nested_err.status_code = 200
    mock_nested_err.json.return_value = [
        {"ip": {"hotspot": {"status": [{"status": "error", "message": "Unknown host"}]}}}
    ]
    assert is_rci_success(mock_nested_err) is False

    # HTTP 200 with {"status": "ok"}
    mock_ok = MagicMock()
    mock_ok.status_code = 200
    mock_ok.json.return_value = [{"status": "ok"}]
    assert is_rci_success(mock_ok) is True

    # HTTP 200 with empty list
    mock_empty = MagicMock()
    mock_empty.status_code = 200
    mock_empty.json.return_value = []
    assert is_rci_success(mock_empty) is True


@pytest.mark.asyncio
async def test_keenetic_remove_dns_sinkholes_dual_index():
    """Verify remove_dns_sinkholes parses dual IPv4+IPv6 response indices correctly."""
    client = KeeneticClient(host="192.168.1.1")
    client.mock_mode = False

    # 2 domains -> 4 commands (indices 0, 1 for domain1; 2, 3 for domain2) + 1 save command
    domains = ["malicious1.com", "malicious2.com"]

    # Mock response where malicious2.com IPv6 deletion fails with non-benign error
    mock_data = [
        {"ip": {"host": {"status": [{"status": "success"}]}}},     # domain 1 IPv4
        {"ipv6": {"host": {"status": [{"status": "success"}]}}},   # domain 1 IPv6
        {"ip": {"host": {"status": [{"status": "success"}]}}},     # domain 2 IPv4
        {"ipv6": {"host": {"status": [{"status": "error", "message": "Internal error", "code": "999"}]}}}, # domain 2 IPv6 error
        {"system": {"configuration": {"save": {}}}}
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_data

    with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_resp
        succeeded, failed = await client.remove_dns_sinkholes(domains)

        assert succeeded == ["malicious1.com"]
        assert failed == ["malicious2.com"]

    # Benign error code 22544392 ('no such record') should be treated as success
    mock_data_benign = [
        {"ip": {"host": {"status": [{"status": "success"}]}}},
        {"ipv6": {"host": {"status": [{"status": "success"}]}}},
        {"ip": {"host": {"status": [{"status": "success"}]}}},
        {"ipv6": {"host": {"status": [{"status": "error", "code": "22544392"}]}}},
        {"system": {"configuration": {"save": {}}}}
    ]
    mock_resp.json.return_value = mock_data_benign

    with patch.object(client, "_send_request", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = mock_resp
        succeeded, failed = await client.remove_dns_sinkholes(domains)

        assert succeeded == ["malicious1.com", "malicious2.com"]
        assert failed == []


@pytest.mark.asyncio
async def test_toggle_wan_db_consistency_on_failure():
    """Verify is_blocked_wan in DB is NOT updated if router backend fails."""
    test_mac = "AA:BB:CC:DD:EE:99"
    await db.upsert_device(DeviceRecord(
        mac=test_mac,
        ip="192.168.1.199",
        hostname="test-tv",
        is_blocked_wan=False
    ))

    dev_initial = await db.get_device(test_mac)
    assert dev_initial.is_blocked_wan is False

    backend = router_manager.get_backend()

    # 1. Backend fails: return False
    with patch.object(backend, "set_wan_access", new_callable=AsyncMock) as mock_set_wan:
        mock_set_wan.return_value = False

        res = await PolicyManager.toggle_wan(test_mac, block=True)
        # Real state returned
        assert res is False

        # Verify DB was NOT updated to True
        dev_after = await db.get_device(test_mac)
        assert dev_after.is_blocked_wan is False

    # 2. Backend succeeds: return True
    with patch.object(backend, "set_wan_access", new_callable=AsyncMock) as mock_set_wan:
        mock_set_wan.return_value = True

        res = await PolicyManager.toggle_wan(test_mac, block=True)
        assert res is True

        # Verify DB is now True
        dev_success = await db.get_device(test_mac)
        assert dev_success.is_blocked_wan is True


def test_speed_limit_openwrt_returns_501():
    """Verify /api/devices/{mac}/speed-limit returns 501 on OpenWrt."""
    with patch.object(router_manager.__class__, "platform_id", new_callable=PropertyMock) as mock_pid, \
         patch.object(router_manager.__class__, "platform_name", new_callable=PropertyMock) as mock_pname:
        mock_pid.return_value = "openwrt"
        mock_pname.return_value = "OpenWrt"

        client = TestClient(app)
        response = client.post("/api/devices/11:22:33:44:55:66/speed-limit", json={"speed_kbps": 2048})

        assert response.status_code == 501
        assert "не поддерживается на платформе OpenWrt" in response.json()["detail"]
