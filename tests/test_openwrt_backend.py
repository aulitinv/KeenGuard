"""Tests for OpenWrt router backend via /ubus JSON-RPC."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from keenguard.core.routers.openwrt import OpenWrtBackend
from keenguard.core.routers.models import RouterHost, RouterSystemInfo


@pytest.mark.asyncio
async def test_openwrt_connect_success():
    backend = OpenWrtBackend(host="10.0.0.1", port=80, username="root", password="testpassword")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": [0, {"ubus_rpc_session": "test_token_abc123", "expires": 300}]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        connected = await backend.connect()
        assert connected is True
        assert backend.session_token == "test_token_abc123"


@pytest.mark.asyncio
async def test_openwrt_connect_auth_failure():
    backend = OpenWrtBackend(host="10.0.0.1", port=80, username="root", password="wrongpassword")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # Code 6 = Permission denied
    mock_resp.json.return_value = {
        "jsonrpc": "2.0",
        "id": 1,
        "result": [6, {}]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        connected = await backend.connect()
        assert connected is False
        assert backend.session_token is None


@pytest.mark.asyncio
async def test_openwrt_get_system_info():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "system" and method == "info":
            return {
                "uptime": 86400,
                "load": [65536, 32768, 16384],  # 1.0, 0.5, 0.25
                "memory": {"total": 256000000, "free": 128000000},
                "release": {"description": "OpenWrt 23.05.2"}
            }
        elif subsystem == "system" and method == "board":
            return {
                "model": "TP-Link Archer AX23 v1",
                "board_name": "tplink,archer-ax23-v1",
                "release": {"description": "OpenWrt 23.05.2"}
            }
        return {}

    backend._call_ubus = mock_call
    info = await backend.get_system_info()
    assert isinstance(info, RouterSystemInfo)
    assert info.model == "TP-Link Archer AX23 v1"
    assert info.firmware_version == "OpenWrt 23.05.2"
    assert info.uptime == 86400
    assert info.cpu_load == 1.0
    assert info.memory_total == 256000000
    assert info.platform == "openwrt"


@pytest.mark.asyncio
async def test_openwrt_get_hosts():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "luci-rpc" and method == "getHostHints":
            return {
                "00:11:22:33:44:55": {"ip": "10.0.0.50", "name": "Work-PC"},
                "AA:BB:CC:DD:EE:FF": {"ipv4": ["10.0.0.60"], "hostname": "Smart-TV"}
            }
        elif subsystem == "dhcp" and method == "get_leases":
            return {
                "leases": [
                    {"macaddr": "00:11:22:33:44:55", "ipaddr": "10.0.0.50", "hostname": "Work-PC"},
                    {"macaddr": "12:34:56:78:9A:BC", "ipaddr": "10.0.0.70", "hostname": "Camera-IPC"}
                ]
            }
        elif subsystem == "uci" and method == "get":
            return {"values": {}}
        return {}

    backend._call_ubus = mock_call
    hosts = await backend.get_hosts()
    assert len(hosts) == 3

    macs = {h.mac for h in hosts}
    assert "00:11:22:33:44:55" in macs
    assert "AA:BB:CC:DD:EE:FF" in macs
    assert "12:34:56:78:9A:BC" in macs

    h_tv = next(h for h in hosts if h.mac == "AA:BB:CC:DD:EE:FF")
    assert h_tv.ip == "10.0.0.60"
    assert h_tv.hostname == "Smart-TV"
    assert h_tv.active is True
    assert h_tv.access == "permit"


@pytest.mark.asyncio
async def test_openwrt_set_wan_access_block_and_allow():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called_actions = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called_actions.append((subsystem, method, params))
        return {}

    backend._call_ubus = mock_call

    # 1. Block WAN
    res_block = await backend.set_wan_access("00:11:22:33:44:55", allow=False)
    assert res_block is True
    assert "00:11:22:33:44:55" in backend._blocked_macs_cache

    # Verify uci add was called with DROP target
    add_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "add"]
    assert len(add_calls) == 1
    assert add_calls[0][2]["values"]["target"] == "DROP"
    assert add_calls[0][2]["values"]["src_mac"] == "00:11:22:33:44:55"

    # 2. Allow WAN
    called_actions.clear()
    res_allow = await backend.set_wan_access("00:11:22:33:44:55", allow=True)
    assert res_allow is True
    assert "00:11:22:33:44:55" not in backend._blocked_macs_cache

    # Verify uci delete was called
    del_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "delete"]
    assert len(del_calls) == 1
    assert del_calls[0][2]["section"] == "keenguard_block_001122334455"


@pytest.mark.asyncio
async def test_openwrt_dns_sinkhole():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called_actions = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called_actions.append((subsystem, method, params))
        return {}

    backend._call_ubus = mock_call

    # Add sinkhole
    ok_add = await backend.add_dns_sinkhole("malware.badsite.test")
    assert ok_add is True
    add_list_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "add_list"]
    assert len(add_list_calls) == 1
    assert add_list_calls[0][2]["value"] == "/malware.badsite.test/0.0.0.0"

    # Remove sinkhole
    called_actions.clear()
    ok_rem = await backend.remove_dns_sinkhole("malware.badsite.test")
    assert ok_rem is True
    del_list_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "del_list"]
    assert len(del_list_calls) == 1
    assert del_list_calls[0][2]["value"] == "/malware.badsite.test/0.0.0.0"


@pytest.mark.asyncio
async def test_openwrt_reboot():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called.append((subsystem, method))
        return {}

    backend._call_ubus = mock_call
    ok_reboot = await backend.reboot()
    assert ok_reboot is True
    assert ("system", "reboot") in called


@pytest.mark.asyncio
async def test_openwrt_guest_wifi():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "network.interface" and method == "dump":
            return {
                "interface": [
                    {"interface": "lan", "up": True},
                    {"interface": "guest_wifi", "up": False}
                ]
            }
        elif subsystem == "network.interface" and method == "up":
            return {}
        return {}

    backend._call_ubus = mock_call
    status = await backend.get_guest_wifi_status()
    assert status["enabled"] is False
    assert status["interface"] == "guest_wifi"

    ok_toggle = await backend.toggle_guest_wifi(True)
    assert ok_toggle is True


@pytest.mark.asyncio
async def test_openwrt_conntrack_nat_table():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "luci-rpc" and method == "getConntrackList":
            return {
                "entries": [
                    {
                        "src": "192.168.1.100",
                        "dst": "1.1.1.1",
                        "sport": 54321,
                        "dport": 53,
                        "layer4": "udp",
                        "bytes": 240,
                        "packets": 2
                    },
                    {
                        "src": "192.168.1.105",
                        "dst": "198.51.100.2",
                        "sport": 44321,
                        "dport": 443,
                        "layer4": "tcp",
                        "bytes": 1024,
                        "packets": 8
                    }
                ]
            }
        return {}

    backend._call_ubus = mock_call
    table = await backend.get_nat_table()
    assert len(table) == 2
    assert table[0]["src"] == "192.168.1.100"
    assert table[0]["dst"] == "1.1.1.1"
    assert table[0]["dport"] == 53
    assert table[0]["protocol"] == "UDP"

    dev_conns = await backend.get_device_nat_connections("192.168.1.100")
    assert len(dev_conns) == 1
    assert dev_conns[0]["dst"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_openwrt_ip_blackholes():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called_actions = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called_actions.append((subsystem, method, params))
        if subsystem == "uci" and method == "get":
            return {
                "values": {
                    "keenguard_blackhole_198_51_100_1": {
                        ".type": "rule",
                        ".name": "keenguard_blackhole_198_51_100_1",
                        "dest_ip": "198.51.100.1",
                        "target": "REJECT"
                    }
                }
            }
        return {}

    backend._call_ubus = mock_call

    # 1. Get active blackholes
    active = await backend.get_active_ip_blackholes()
    assert "198.51.100.1" in active

    # 2. Add IP blackhole
    called_actions.clear()
    succeeded, failed = await backend.add_ip_blackholes(["198.51.100.2"])
    assert "198.51.100.2" in succeeded
    assert len(failed) == 0

    add_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "add"]
    assert len(add_calls) == 1
    assert add_calls[0][2]["values"]["dest_ip"] == "198.51.100.2"
    assert add_calls[0][2]["values"]["target"] == "REJECT"

    # 3. Remove IP blackhole
    called_actions.clear()
    removed, failed = await backend.remove_ip_blackholes(["198.51.100.1"])
    assert "198.51.100.1" in removed
    assert len(failed) == 0

    del_calls = [c for c in called_actions if c[0] == "uci" and c[1] == "delete"]
    assert len(del_calls) == 1
    assert del_calls[0][2]["section"] == "keenguard_blackhole_198_51_100_1"


@pytest.mark.asyncio
async def test_openwrt_dns_sinkholes_batch():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called_actions = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called_actions.append((subsystem, method, params))
        if subsystem == "uci" and method == "get":
            return {
                "values": {
                    "cfg01": {
                        ".type": "dnsmasq",
                        "address": [
                            "/bad1.test/0.0.0.0",
                            "/bad2.test/0.0.0.0"
                        ]
                    }
                }
            }
        return {}

    backend._call_ubus = mock_call

    # 1. Get active sinkholes
    active = await backend.get_active_sinkholes()
    assert "bad1.test" in active
    assert "bad2.test" in active

    # 2. Batch add sinkholes
    called_actions.clear()
    added, failed = await backend.add_dns_sinkholes(["ad3.test", "ad4.test"])
    assert len(added) == 2
    assert "ad3.test" in added
    assert len(failed) == 0

    # 3. Batch remove sinkholes
    called_actions.clear()
    removed, failed = await backend.remove_dns_sinkholes(["bad1.test"])
    assert "bad1.test" in removed
    assert len(failed) == 0


@pytest.mark.asyncio
async def test_openwrt_network_segments_and_risk():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "network.interface" and method == "dump":
            return {
                "interface": [
                    {
                        "interface": "lan",
                        "device": "br-lan",
                        "up": True,
                        "ipv4-address": [{"address": "192.168.1.1", "mask": 24}]
                    },
                    {
                        "interface": "guest",
                        "device": "br-guest",
                        "up": True,
                        "ipv4-address": [{"address": "192.168.2.1", "mask": 24}]
                    }
                ]
            }
        return {}

    backend._call_ubus = mock_call
    segments = await backend.get_network_segments()
    assert len(segments) == 2
    assert segments[0]["name"] == "lan"
    assert segments[0]["is_isolated"] is False
    assert segments[1]["is_isolated"] is True

    # Risk evaluation
    risk_lan = backend.evaluate_segment_risk("camera", "lan", "192.168.1.50")
    assert risk_lan["risk_level"] == "high"
    assert "L2" in risk_lan["warning"]

    risk_guest = backend.evaluate_segment_risk("camera", "guest", "192.168.2.50")
    assert risk_guest["risk_level"] == "low"


@pytest.mark.asyncio
async def test_openwrt_wifi_security():
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    async def mock_call(subsystem, method, params=None, require_auth=True):
        if subsystem == "uci" and method == "get":
            return {
                "values": {
                    "wifinet0": {
                        ".type": "wifi-iface",
                        "ssid": "Home_WiFi_5G",
                        "encryption": "sae-mixed",
                        "disabled": "0",
                        "wps": "0",
                        "isolate": "0"
                    },
                    "wifinet1": {
                        ".type": "wifi-iface",
                        "ssid": "IoT_Legacy",
                        "encryption": "none",
                        "disabled": "0"
                    }
                }
            }
        return {}

    backend._call_ubus = mock_call
    audit = await backend.get_wifi_security()
    assert "networks" in audit
    assert len(audit["networks"]) == 2
    assert audit["has_critical"] is True  # Open network 'none' triggers critical alert
    assert any(n["ssid"] == "IoT_Legacy" and n["risk_level"] == "critical" for n in audit["networks"])


@pytest.mark.asyncio
async def test_openwrt_packet_capture_lifecycle(tmp_path):
    import base64
    backend = OpenWrtBackend(host="10.0.0.1")
    backend.session_token = "valid_token"
    backend.session_expires = 9999999999.0

    called_actions = []

    async def mock_call(subsystem, method, params=None, require_auth=True):
        called_actions.append((subsystem, method, params))
        if subsystem == "file" and method == "exec":
            cmd = params.get("command") if params else ""
            if "which" in cmd:
                return {"code": 0, "stdout": "/usr/sbin/tcpdump\n"}
            return {"code": 0, "stdout": ""}
        elif subsystem == "file" and method == "read":
            # Return dummy base64 pcap
            fake_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 32
            return {"data": base64.b64encode(fake_pcap).decode("ascii")}
        elif subsystem == "file" and method == "remove":
            return {"code": 0}
        return {}

    backend._call_ubus = mock_call

    # 1. Packet capture capability check
    supported = await backend.is_packet_capture_supported()
    assert supported is True

    # 2. Start packet capture
    res_start = await backend.start_packet_capture(
        interface="br-lan",
        ip="192.168.1.100",
        duration_seconds=30
    )
    assert res_start["status"] == "running"
    assert backend._current_capture_file is not None

    # 3. Stop packet capture
    file_id = await backend.stop_packet_capture("br-lan")
    assert file_id is not None

    # 4. Download capture file
    target_pcap = tmp_path / "test.pcap"
    download_ok = await backend.download_capture_file(file_id, str(target_pcap))
    assert download_ok is True
    assert target_pcap.exists()
    assert target_pcap.stat().st_size > 0

    # 5. Reset packet capture
    reset_ok = await backend.reset_packet_capture("br-lan")
    assert reset_ok is True
