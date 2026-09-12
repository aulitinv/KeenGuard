"""Unit tests for Smart Home classification and API overview endpoint."""
import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.db.models import DeviceRecord
from keenguard.core.classifier import DeviceClassifier
from keenguard.web.app import app


def test_smarthome_device_classification():
    # 1. Controllers
    dev_hub = DeviceRecord(mac="00:11:22:33:44:01", hostname="smart-home-hub-01", profile="smart_home_hub")
    assert DeviceClassifier.classify_smarthome_device(dev_hub) == "controllers"

    # 2. Garden & Irrigation (outdoor, moisture, watering)
    dev_soil = DeviceRecord(mac="AA:BB:CC:11:22:01", hostname="soil-moisture-sensor-1", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_soil) == "garden"

    dev_water = DeviceRecord(mac="AA:BB:CC:11:22:02", custom_name="Автополив теплица", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_water) == "garden"

    dev_valve = DeviceRecord(mac="AA:BB:CC:11:22:03", hostname="garden-valve-solenoid", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_valve) == "garden"

    # 3. Climate & Air
    dev_ac = DeviceRecord(mac="AA:BB:CC:11:22:04", hostname="ac-bedroom", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_ac) == "climate"

    dev_airp = DeviceRecord(mac="AA:BB:CC:11:22:05", hostname="smart-airpurifier-01", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_airp) == "climate"

    # 4. Sensors
    dev_sensor = DeviceRecord(mac="AA:BB:CC:11:22:06", hostname="air-quality-sensor-01", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_sensor) == "sensors"

    # 5. Appliances
    dev_vacuum = DeviceRecord(mac="AA:BB:CC:11:22:07", hostname="smart-vacuum-cleaner", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_vacuum) == "appliances"

    dev_dishwasher = DeviceRecord(mac="AA:BB:CC:11:22:08", hostname="kitchen-dishwasher", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_dishwasher) == "appliances"

    dev_feeder = DeviceRecord(mac="AA:BB:CC:11:22:09", hostname="pet-feeder-kormushka", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_feeder) == "appliances"

    # 6. Security
    dev_cam = DeviceRecord(mac="AA:BB:CC:11:22:10", hostname="doorbell-camera-01", profile="camera")
    assert DeviceClassifier.classify_smarthome_device(dev_cam) == "security"

    # 7. Other IoT
    dev_other = DeviceRecord(mac="AA:BB:CC:11:22:11", hostname="esp-generic-relay", profile="iot")
    assert DeviceClassifier.classify_smarthome_device(dev_other) == "other"


@pytest.mark.asyncio
async def test_smarthome_overview_api():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/api/smarthome/overview")
        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "ok"
        assert "stats" in data
        assert "categories" in data
        assert "cloud_connections" in data
        assert "checklist" in data

        # Check all 7 expected categories are present
        categories = data["categories"]
        expected_keys = ["controllers", "garden", "climate", "sensors", "appliances", "security", "other"]
        for key in expected_keys:
            assert key in categories
            assert "title" in categories[key]
            assert "devices" in categories[key]

        # Verify garden category metadata
        assert categories["garden"]["title"] == "Сад и автополив"
        assert categories["controllers"]["title"] == "Хабы и контроллеры"

        # Verify checklist contains safe educational advice
        checklist = data["checklist"]
        assert len(checklist) >= 3
        hub_item = next((item for item in checklist if item["id"] == "hub_isolation"), None)
        assert hub_item is not None
        assert "KeeneticOS" in hub_item["guide"][0] or "KeeneticOS" in "".join(hub_item["guide"])
