"""Unit tests for Mobile OUI recognition, LAA MAC randomization detection, and MAC rotation tracking mechanisms."""
import pytest
from typing import List
from keenguard.core.classifier import DeviceClassifier
from keenguard.db.models import DeviceRecord


def test_mobile_oui_recognition():
    """
    Test a): Check recognition of OUI 2C:DA:46 as mobile vendor (Mobile).
    
    Mobile smartphone synthetic hardware MAC:
    2C:DA:46:00:00:01 (IP: 192.168.1.101, hostname: Phone-Client-01)
    OUI prefix: 2C:DA:46 is officially registered in IEEE to mobile vendor.
    """
    mac = "2C:DA:46:00:00:01"
    hostname = "Phone-Client-01"

    # Hardware MAC must NOT be treated as randomized (LAA bit is 0)
    assert DeviceClassifier.is_randomized_mac(mac) is False

    # Classification must resolve profile to trusted
    vendor, profile, is_rand = DeviceClassifier.classify(mac, hostname=hostname)

    assert is_rand is False, "Hardware factory MAC must not be flagged as random"
    assert profile == "trusted", (
        f"Mobile smartphone must be assigned profile 'trusted'. Current profile: '{profile}'"
    )


def test_laa_randomized_mac_detection():
    """
    Test b): Check detection of randomized MAC addresses (IEEE LAA bit).
    
    In IEEE 802 MAC addresses:
    - First octet bit 0 (0x01): 0 = Unicast, 1 = Multicast.
    - First octet bit 1 (0x02): 0 = Universally Administered (UAA), 1 = Locally Administered (LAA).
    
    Synthetic test MACs:
    - EA:00:00:00:00:01 -> 0xEA = 0b11101010 (bit 1 is 1 -> LAA / Random MAC)
    - CA:00:00:00:00:02 -> 0xCA = 0b11001010 (bit 1 is 1 -> LAA / Random MAC)
    - 2C:DA:46:00:00:01 -> 0x2C = 0b00101100 (bit 1 is 0 -> UAA / Hardware MAC)
    """
    mac_ea = "EA:00:00:00:00:01"
    mac_ca = "CA:00:00:00:00:02"
    mac_hw = "2C:DA:46:00:00:01"

    # Bit-level LAA verification
    assert DeviceClassifier.is_randomized_mac(mac_ea) is True
    assert DeviceClassifier.is_randomized_mac(mac_ca) is True
    assert DeviceClassifier.is_randomized_mac(mac_hw) is False

    # Classification verification for randomized MAC 1
    v_ea, p_ea, r_ea = DeviceClassifier.classify(mac_ea, hostname="Phone-Client-01")
    assert r_ea is True
    assert "Locally Administered" in v_ea or "Random MAC" in v_ea

    # Classification verification for randomized MAC 2
    v_ca, p_ca, r_ca = DeviceClassifier.classify(mac_ca, hostname="Phone-Client-01")
    assert r_ca is True
    assert "Locally Administered" in v_ca or "Random MAC" in v_ca


def test_mac_rotation_detection_mechanism():
    """
    Test c): Check mechanism for detecting MAC rotation when multiple MACs
    share an identical hostname (e.g. 'Phone-Client-01').
    
    In modern mobile OSes, devices may rotate or switch
    between factory hardware MAC and randomized MACs, while DHCP Option 12
    continues sending the same device hostname.
    
    The system must have logic to:
    1. Detect correlation between MACs sharing the same hostname.
    2. Distinguish the physical/hardware MAC from rotated randomized MACs.
    3. Group them into a MAC rotation cluster / alias group.
    """
    devices = [
        DeviceRecord(
            mac="2C:DA:46:00:00:01",
            ip="192.168.1.101",
            hostname="Phone-Client-01",
            vendor="Mobile-Device-Vendor",
            profile="trusted",
            is_online=True
        ),
        DeviceRecord(
            mac="EA:00:00:00:00:01",
            ip="192.168.1.102",
            hostname="Phone-Client-01",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=True
        ),
        DeviceRecord(
            mac="CA:00:00:00:00:02",
            ip="0.0.0.0",
            hostname="Phone-Client-01",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=False
        ),
    ]

    # Verify that DeviceClassifier provides MAC rotation detection logic
    assert hasattr(DeviceClassifier, "detect_mac_rotations"), (
        "DeviceClassifier must implement 'detect_mac_rotations(devices: List[DeviceRecord])' "
        "to correlate multiple MAC entries of the same physical device."
    )

    rotation_groups = DeviceClassifier.detect_mac_rotations(devices)
    assert len(rotation_groups) == 1, "Expected 1 rotation cluster for 'Phone-Client-01'"
    
    group = rotation_groups[0]
    assert group["hostname"] == "Phone-Client-01"
    assert group["hardware_mac"] == "2C:DA:46:00:00:01"
    assert set(group["random_macs"]) == {"EA:00:00:00:00:01", "CA:00:00:00:00:02"}
    assert len(group["all_macs"]) == 3

def test_multiple_hardware_devices_with_same_hostname_not_rotation():
    # Two distinct physical Air Monitors sharing the same default factory hostname
    devices = [
        DeviceRecord(
            mac="58:2D:34:00:00:01",
            ip="192.168.1.104",
            hostname="Air-Quality-Sensor",
            vendor="Sensor-Device-Vendor",
            profile="iot",
            is_online=True
        ),
        DeviceRecord(
            mac="58:2D:34:00:00:02",
            ip="192.168.1.105",
            hostname="Air-Quality-Sensor",
            vendor="Sensor-Device-Vendor",
            profile="iot",
            is_online=True
        ),
    ]

    rotation_groups = DeviceClassifier.detect_mac_rotations(devices)
    # Neither device uses randomized MAC; both are distinct hardware devices
    assert len(rotation_groups) == 0, "Distinct hardware devices with same hostname must NOT be grouped as MAC rotation"


def test_generic_hostnames_excluded_from_rotation():
    """Generic/model hostnames (smart-tv, esp32, tasmota) must never cluster devices."""
    devices = [
        DeviceRecord(
            mac="DA:11:22:33:44:55",
            ip="192.168.1.50",
            hostname="smart-tv",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=True
        ),
        DeviceRecord(
            mac="EA:22:33:44:55:66",
            ip="192.168.1.103",
            hostname="smart-tv",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=True
        ),
    ]
    rotation_groups = DeviceClassifier.detect_mac_rotations(devices)
    assert len(rotation_groups) == 0, "Generic hostname 'smart-tv' must NOT form a rotation cluster"


def test_pure_random_mac_device_rotation():
    """Device that never connected with a factory hardware MAC (always used Private Wi-Fi)."""
    devices = [
        DeviceRecord(
            mac="DA:11:22:33:44:55",
            ip="0.0.0.0",
            hostname="Mobile-Work-User",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=False
        ),
        DeviceRecord(
            mac="EA:66:77:88:99:00",
            ip="192.168.1.115",
            hostname="Mobile-Work-User",
            vendor="Locally Administered (Random MAC)",
            profile="trusted",
            is_online=True
        ),
    ]
    rotation_groups = DeviceClassifier.detect_mac_rotations(devices)
    assert len(rotation_groups) == 1
    grp = rotation_groups[0]
    assert grp["hostname"] == "Mobile-Work-User"
    assert grp["hardware_mac"] is None, "Device without UAA MAC must have hardware_mac=None"
    assert grp["active_mac"] == "EA:66:77:88:99:00", "Online device must be selected as active_mac"
    assert len(grp["random_macs"]) == 2


def test_multiple_hardware_macs_with_random_not_rotation():
    """If candidate group contains multiple different hardware MACs, it is NOT a single client rotation."""
    devices = [
        DeviceRecord(
            mac="00:11:22:33:44:55", # Hardware MAC 1
            ip="192.168.1.10",
            hostname="MyGadget-Custom",
            vendor="VendorA",
            profile="iot",
            is_online=True
        ),
        DeviceRecord(
            mac="00:66:77:88:99:AA", # Hardware MAC 2
            ip="192.168.1.11",
            hostname="MyGadget-Custom",
            vendor="VendorB",
            profile="iot",
            is_online=True
        ),
        DeviceRecord(
            mac="DA:AA:BB:CC:DD:EE", # Random MAC
            ip="192.168.1.12",
            hostname="MyGadget-Custom",
            vendor="Locally Administered (Random MAC)",
            profile="iot",
            is_online=False
        ),
    ]
    rotation_groups = DeviceClassifier.detect_mac_rotations(devices)
    assert len(rotation_groups) == 0, "Multiple hardware MACs sharing a name must NOT be merged into a rotation group"


@pytest.mark.asyncio
async def test_api_devices_rotation_group_structure(tmp_path):
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    from keenguard.db.database import Database
    from keenguard.web.app import app

    test_db = Database(db_path=tmp_path / "test_rot_api.db")
    await test_db.init_db()

    d_hw = DeviceRecord(
        mac="2C:DA:46:00:00:01",
        ip="192.168.1.101",
        hostname="Phone-Client-01",
        vendor="Mobile-Device-Vendor",
        profile="trusted",
        is_online=False
    )
    d_rand1 = DeviceRecord(
        mac="EA:00:00:00:00:01",
        ip="192.168.1.102",
        hostname="Phone-Client-01",
        vendor="Locally Administered (Random MAC)",
        profile="trusted",
        is_online=True
    )
    d_rand2 = DeviceRecord(
        mac="CA:00:00:00:00:02",
        ip="0.0.0.0",
        hostname="Phone-Client-01",
        vendor="Locally Administered (Random MAC)",
        profile="trusted",
        is_online=False
    )
    await test_db.upsert_device(d_hw)
    await test_db.upsert_device(d_rand1)
    await test_db.upsert_device(d_rand2)

    with patch("keenguard.web.app.db", test_db):
        client = TestClient(app)
        resp = client.get("/api/devices")
        assert resp.status_code == 200
        data = resp.json()
        dev_map = {d["mac"]: d for d in data}

        # Verify d_hw
        item_hw = dev_map["2C:DA:46:00:00:01"]
        assert item_hw["rotation_group"] is not None
        assert item_hw["rotation_group"]["role"] == "hardware"
        assert item_hw["rotation_group"]["is_hardware"] is True
        assert item_hw["rotation_group"]["is_active"] is False
        assert item_hw["rotation_group"]["active_mac"] == "EA:00:00:00:00:01"

        # Verify d_rand1 (online active random)
        item_rand1 = dev_map["EA:00:00:00:00:01"]
        assert item_rand1["rotation_group"] is not None
        assert item_rand1["rotation_group"]["role"] == "active_random"
        assert item_rand1["rotation_group"]["is_hardware"] is False
        assert item_rand1["rotation_group"]["is_active"] is True

        # Verify d_rand2 (offline historical random)
        item_rand2 = dev_map["CA:00:00:00:00:02"]
        assert item_rand2["rotation_group"] is not None
        assert item_rand2["rotation_group"]["role"] == "historical_random"
        assert item_rand2["rotation_group"]["is_hardware"] is False
        assert item_rand2["rotation_group"]["is_active"] is False

