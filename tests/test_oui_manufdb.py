import pytest
from keenguard.core.classifier import DeviceClassifier


def test_infer_profile_from_vendor():
    assert DeviceClassifier.infer_profile_from_vendor("Espressif Inc.") == "iot"
    assert DeviceClassifier.infer_profile_from_vendor("Tuya Smart Inc.") == "iot"
    assert DeviceClassifier.infer_profile_from_vendor("Xiaomi Communications Co., Ltd.") == "trusted"
    assert DeviceClassifier.infer_profile_from_vendor("Sonoff Co.") == "iot"
    assert DeviceClassifier.infer_profile_from_vendor("Shelly Group AD") == "iot"
    assert DeviceClassifier.infer_profile_from_vendor("Hangzhou Hikvision Digital Technology") == "camera"
    assert DeviceClassifier.infer_profile_from_vendor("Zhejiang Dahua Technology") == "camera"
    assert DeviceClassifier.infer_profile_from_vendor("Apple, Inc.") == "trusted"
    assert DeviceClassifier.infer_profile_from_vendor("Meta Platforms Technologies, LLC") == "trusted"
    assert DeviceClassifier.infer_profile_from_vendor("Unknown Random Vendor XYZ") == "unassigned"


def test_manufdb_samsung_oui():
    # 2C:DA:46 is a registered IEEE OUI for Samsung Electronics
    vendor, profile, is_rand = DeviceClassifier.classify("2c:da:46:12:34:56", hostname="Galaxy-Device")
    assert "Samsung" in vendor
    assert profile == "trusted"
    assert is_rand is False


def test_manufdb_meta_vr_oui():
    # C0:DD:8A is Meta Platforms Technologies, LLC
    vendor, profile, is_rand = DeviceClassifier.classify("c0:dd:8a:aa:bb:cc", hostname="")
    assert "Meta" in vendor
    assert profile == "trusted"


def test_vr_headset_hostname_heuristic():
    vendor, profile, is_rand = DeviceClassifier.classify("00:11:22:33:44:55", hostname="quest-2-alex")
    assert profile == "trusted"
    assert "VR Headset" in vendor


