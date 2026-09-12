"""Tests for device classification and MAC randomization detection."""
import pytest
from keenguard.core.classifier import DeviceClassifier

def test_randomized_mac_detection():
    # Bit 1 of first byte is 1 -> LAA (randomized)
    # Examples of LAA: x2, x6, xA, xE
    assert DeviceClassifier.is_randomized_mac("02:1A:2B:3C:4D:5E") is True
    assert DeviceClassifier.is_randomized_mac("F6:22:33:44:55:66") is True
    assert DeviceClassifier.is_randomized_mac("DA:11:22:33:44:55") is True
    assert DeviceClassifier.is_randomized_mac("EE:AA:BB:CC:DD:EE") is True

    # Globally Unique Addresses (UAA - regular manufacturer MACs)
    assert DeviceClassifier.is_randomized_mac("00:1C:62:AA:BB:CC") is False
    assert DeviceClassifier.is_randomized_mac("24:0A:C4:11:22:33") is False
    assert DeviceClassifier.is_randomized_mac("C4:2F:90:77:88:99") is False

def test_smart_tv_classification():
    # Smart TV OUI
    vendor, profile, is_rand = DeviceClassifier.classify("00:1C:62:11:22:33")
    assert profile == "smart_tv"
    assert is_rand is False

    # Smart TV OUI 2
    vendor, profile, is_rand = DeviceClassifier.classify("00:12:47:AA:BB:CC")
    assert profile == "smart_tv"

    # Hostname heuristic
    vendor, profile, is_rand = DeviceClassifier.classify("12:34:56:78:90:AB", hostname="smart-tv-livingroom")
    assert profile == "smart_tv"

def test_camera_classification():
    # Camera OUI 1
    vendor, profile, is_rand = DeviceClassifier.classify("C4:2F:90:01:02:03")
    assert profile == "camera"

    # Camera OUI 2
    vendor, profile, is_rand = DeviceClassifier.classify("3C:EF:8C:11:22:33")
    assert profile == "camera"

    # Hostname heuristic
    vendor, profile, is_rand = DeviceClassifier.classify("FE:DC:BA:98:76:54", hostname="driveway-ipcamera-01")
    assert profile == "camera"

def test_iot_classification():
    # ESP32
    vendor, profile, is_rand = DeviceClassifier.classify("24:0A:C4:AB:CD:EF")
    assert profile == "iot"

    # IoT OUI
    vendor, profile, is_rand = DeviceClassifier.classify("10:5A:F7:12:34:56")
    assert profile == "iot"

    # Hostname heuristic for smart plug
    vendor, profile, is_rand = DeviceClassifier.classify("44:55:66:77:88:99", hostname="living-room-smart-plug")
    assert profile == "iot"

def test_smart_home_hub_classification():
    # Home Assistant
    vendor, profile, is_rand = DeviceClassifier.classify("B8:27:EB:12:34:56", hostname="homeassistant")
    assert profile == "smart_home_hub"

    # Hubitat / Zigbee2MQTT
    vendor, profile, is_rand = DeviceClassifier.classify("00:11:22:33:44:55", hostname="zigbee2mqtt-gateway")
    assert profile == "smart_home_hub"

def test_trusted_client_device_classification():
    # Trusted workstation/laptop
    vendor, profile, is_rand = DeviceClassifier.classify("00:1B:21:11:22:33", hostname="workstation-pc")
    assert profile == "trusted"
    assert is_rand is False

    # Mobile with randomized MAC
    vendor, profile, is_rand = DeviceClassifier.classify("EA:00:00:00:00:01", hostname="client-mobile-phone")
    assert is_rand is True

def test_unassigned_device_does_not_become_iot():
    # Completely generic/unknown device with unassigned profile
    generic_dev = {
        "mac": "12:34:56:78:90:AB",
        "hostname": "android-unknown-client",
        "profile": "unassigned",
        "vendor": "Locally Administered (Random MAC)"
    }
    trust = DeviceClassifier.classify_iot_trust_tier(generic_dev)
    # Must be 'unassigned', NEVER 'pure_local' or smart home IoT!
    assert trust["tier"] == "unassigned"
    assert "Неопознанное устройство" in trust["tier_title"]

    cat = DeviceClassifier.classify_smarthome_device(generic_dev)
    assert cat == "other"

    # But an unassigned device with an explicit IoT indicator (e.g. plug) should be recognized
    iot_unassigned_dev = {
        "mac": "24:0A:C4:00:11:22",
        "hostname": "smart-plug-livingroom",
        "profile": "unassigned",
        "vendor": "IoT Module Vendor"
    }
    trust_iot = DeviceClassifier.classify_iot_trust_tier(iot_unassigned_dev)
    assert trust_iot["tier"] in ("cloud_appliance", "pure_local")



