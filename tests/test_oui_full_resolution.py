import pytest
from keenguard.core.classifier import DeviceClassifier
from keenguard.db.models import DeviceRecord


def test_meta_platforms_oui_database():
    """Verify that Meta Platforms Technologies OUI prefix is classified as trusted."""
    # Prefix C0:DD:8A is Meta Platforms Technologies
    vendor, profile, is_rand = DeviceClassifier.classify("c0:dd:8a:11:22:33", hostname="")
    assert "Meta Platforms" in vendor
    assert profile == "trusted"
    assert is_rand is False


def test_manufdb_fallback_and_profile_inference():
    """Verify fallback to Scapy MANUFDB for various hardware vendors."""
    # 00:1A:80 is a registered hardware MAC for Samsung
    vendor, profile, is_rand = DeviceClassifier.classify("00:1a:80:55:66:77", hostname="")
    assert "Samsung" in vendor
    assert profile == "trusted"
    assert is_rand is False

    # Dahua camera OUI
    vendor, profile, is_rand = DeviceClassifier.classify("38:af:29:11:22:33", hostname="")
    assert "Dahua" in vendor
    assert profile == "camera"


def test_vr_headset_heuristic():
    """Verify VR headset heuristic for Quest / Oculus / Vive."""
    vendor, profile, is_rand = DeviceClassifier.classify("50:c7:bf:11:22:33", hostname="Oculus-Quest-2")
    assert profile == "trusted"
    assert "VR Headset" in vendor
