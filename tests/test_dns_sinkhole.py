import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

from keenguard.core.keenetic import keenetic_client
from keenguard.core.domain_analyzer import domain_analyzer
from keenguard.db.database import db
from keenguard.web.app import app


@pytest.mark.asyncio
async def test_keenetic_sinkhole_mock_crud():
    """Test creating, listing, and removing static DNS sinkhole entries in KeeneticClient."""
    with patch.object(keenetic_client, "mock_mode", True):
        # Clean slate
        keenetic_client._mock_sinkholes = set()

        # Add
        ok = await keenetic_client.add_dns_sinkhole("adservice.google.com")
        assert ok is True

        ok = await keenetic_client.add_dns_sinkhole("tracking.miui.com")
        assert ok is True

        # List
        active = await keenetic_client.get_active_sinkholes()
        assert "adservice.google.com" in active
        assert "tracking.miui.com" in active
        assert len(active) == 2

        # Remove
        ok_rm = await keenetic_client.remove_dns_sinkhole("adservice.google.com")
        assert ok_rm is True

        active_after = await keenetic_client.get_active_sinkholes()
        assert "adservice.google.com" not in active_after
        assert "tracking.miui.com" in active_after


def test_domain_safety_rating_verdict():
    """Test that domain analyzer provides block safety labels and impact explanations."""
    # 1. Advertising -> Safe
    ad_verdict = domain_analyzer.analyze_domain("doubleclick.net")
    assert ad_verdict["block_safety"] == "safe"
    assert ad_verdict["safety_label"] == "Безопасно блокировать"
    assert "Рекламный сервис" in ad_verdict["impact_explanation"]

    # 2. TV Telemetry -> Telemetry safe
    tel_verdict = domain_analyzer.analyze_domain("samsungacr.com")
    assert tel_verdict["block_safety"] == "telemetry_safe"
    assert "телеметрии" in tel_verdict["impact_explanation"]

    # 3. IoT Cloud -> Dangerous to block
    iot_verdict = domain_analyzer.analyze_domain("tuyaeu.com")
    assert iot_verdict["block_safety"] == "dangerous"
    assert "Опасно блокировать" in iot_verdict["safety_label"]
    assert "умного дома" in iot_verdict["impact_explanation"]

    # 4. Threat / Suspicious -> Threat
    threat_verdict = domain_analyzer.analyze_domain("malware-c2-test.ru")
    # Even if unknown or heuristic, test dangerous/threat behavior
    assert "block_safety" in threat_verdict
    assert "impact_explanation" in threat_verdict


@pytest.mark.asyncio
async def test_dns_sinkhole_rest_endpoints():
    """Test DNS sinkhole REST endpoints end-to-end."""
    transport = ASGITransport(app=app)
    with patch.object(keenetic_client, "mock_mode", True):
        keenetic_client._mock_sinkholes = set()

        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # 1. Block single domain
            res_block = await ac.post("/api/dns/sinkhole/block", json={"domain": "an.yandex.ru"})
            assert res_block.status_code == 200
            assert res_block.json()["status"] == "ok"
            assert res_block.json()["domain"] == "an.yandex.ru"

            # 2. Get active sinkholes
            res_list = await ac.get("/api/dns/sinkholes")
            assert res_list.status_code == 200
            assert "an.yandex.ru" in res_list.json()["sinkholes"]

            # 3. Unblock domain
            res_unblock = await ac.post("/api/dns/sinkhole/unblock", json={"domain": "an.yandex.ru"})
            assert res_unblock.status_code == 200
            assert res_unblock.json()["action"] == "unblocked"

            # 4. Preset blocking (ads)
            await db.record_dns_query("doubleclick.net", ip="142.250.180.14", mac="00:11:22:33:44:55")
            res_preset = await ac.post("/api/dns/sinkhole/block_preset", json={"preset": "ads"})
            assert res_preset.status_code == 200
            data_preset = res_preset.json()
            assert data_preset["status"] == "ok"
            assert data_preset["preset"] == "ads"

            # 5. Unblock all
            res_clear = await ac.post("/api/dns/sinkhole/unblock_all")
            assert res_clear.status_code == 200
            assert res_clear.json()["status"] == "ok"

            res_final = await ac.get("/api/dns/sinkholes")
            assert len(res_final.json()["sinkholes"]) == 0


@pytest.mark.asyncio
async def test_dns_preset_preview_and_selective_blocking():
    """Test interactive preset preview, selective blocking, and enriched rules."""
    transport = ASGITransport(app=app)
    with patch.object(keenetic_client, "mock_mode", True):
        keenetic_client._mock_sinkholes = set()

        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Seed a DNS query in DB for ads
            await db.record_dns_query("adservice.google.com", ip="142.250.180.1", mac="aa:bb:cc:dd:ee:ff")

            # 1. Preview ads preset
            res_prev = await ac.get("/api/dns/sinkhole/preset_preview?preset=ads")
            assert res_prev.status_code == 200
            data_prev = res_prev.json()
            assert data_prev["preset"] == "ads"
            assert "curated" in data_prev
            assert len(data_prev["curated"]) > 0
            # Detected domains should include adservice.google.com
            det_doms = [d["domain"] for d in data_prev["detected"]]
            assert "adservice.google.com" in det_doms

            # 2. Block selected domains
            domains_to_block = ["adservice.google.com", "pagead2.googlesyndication.com"]
            res_block_sel = await ac.post("/api/dns/sinkhole/block_selected", json={"domains": domains_to_block})
            assert res_block_sel.status_code == 200
            data_bs = res_block_sel.json()
            assert data_bs["blocked_count"] == 2
            assert data_bs["failed_count"] == 0

            # 3. Check active sinkholes enriched rules
            res_active = await ac.get("/api/dns/sinkholes")
            assert res_active.status_code == 200
            data_active = res_active.json()
            assert data_active["count"] == 2
            assert "adservice.google.com" in data_active["sinkholes"]
            assert len(data_active["rules"]) == 2
            rule_doms = [r["domain"] for r in data_active["rules"]]
            assert "adservice.google.com" in rule_doms

            # 4. Preview tv_telemetry
            res_tv = await ac.get("/api/dns/sinkhole/preset_preview?preset=tv_telemetry")
            assert res_tv.status_code == 200
            data_tv = res_tv.json()
            assert data_tv["preset"] == "tv_telemetry"
            assert len(data_tv["curated"]) > 0

            # 5. Unblock selected
            res_unblock_sel = await ac.post("/api/dns/sinkhole/unblock_selected", json={"domains": ["adservice.google.com"]})
            assert res_unblock_sel.status_code == 200
            assert res_unblock_sel.json()["unblocked_count"] == 1

            # Final check
            res_final = await ac.get("/api/dns/sinkholes")
            assert res_final.json()["count"] == 1
            assert "pagead2.googlesyndication.com" in res_final.json()["sinkholes"]


@pytest.mark.asyncio
async def test_keenetic_sinkhole_batch_methods():
    """Test add_dns_sinkholes and remove_dns_sinkholes batch methods."""
    with patch.object(keenetic_client, "mock_mode", True):
        keenetic_client._mock_sinkholes = set()

        domains = ["tracking.yandex.ru", "samsungacr.com", "telemetry.lgappstv.com"]
        succeeded, failed = await keenetic_client.add_dns_sinkholes(domains)
        assert len(succeeded) == 3
        assert len(failed) == 0

        active = await keenetic_client.get_active_sinkholes()
        assert len(active) == 3
        for d in domains:
            assert d in active

        rm_succeeded, rm_failed = await keenetic_client.remove_dns_sinkholes(["tracking.yandex.ru", "samsungacr.com"])
        assert len(rm_succeeded) == 2
        assert len(rm_failed) == 0

        active_after = await keenetic_client.get_active_sinkholes()
        assert len(active_after) == 1
        assert "telemetry.lgappstv.com" in active_after


@pytest.mark.asyncio
async def test_rci_payload_schema_and_error_handling():
    """Verify that KeeneticClient generates exact RCI schema ('domain', not 'name', 'no': True) and handles router error responses."""
    from unittest.mock import AsyncMock, MagicMock

    with patch.object(keenetic_client, "mock_mode", False):
        mock_send = AsyncMock()

        # 1. Successful add response mock
        mock_resp_success = MagicMock()
        mock_resp_success.status_code = 200
        mock_resp_success.json.return_value = [
            {"ip": {"host": {"status": [{"status": "message", "code": "22544396", "message": "added"}]}}},
            {"system": {"configuration": {"save": {"status": [{"status": "message"}]}}}}
        ]
        mock_send.return_value = mock_resp_success

        with patch.object(keenetic_client, "_send_request", mock_send):
            ok = await keenetic_client.add_dns_sinkhole("test.adservice.com")
            assert ok is True

            # Verify RCI payload format: must be 'domain', not 'name'
            mock_send.assert_called_once()
            call_args = mock_send.call_args
            assert call_args[0][0] == "POST"
            assert call_args[0][1] == "/rci/"
            payload = call_args[1]["json_data"]
            assert payload[0] == {"ip": {"host": {"domain": "test.adservice.com", "address": "0.0.0.0"}}}
            assert payload[1] == {"system": {"configuration": {"save": {}}}}

        # 2. Router error response mock
        mock_send_err = AsyncMock()
        mock_resp_err = MagicMock()
        mock_resp_err.status_code = 200
        mock_resp_err.json.return_value = [
            {"ip": {"host": {"status": [{"status": "error", "code": "7471107", "message": "invalid argument"}]}}},
            {"system": {"configuration": {"save": {}}}}
        ]
        mock_send_err.return_value = mock_resp_err

        with patch.object(keenetic_client, "_send_request", mock_send_err):
            ok_err = await keenetic_client.add_dns_sinkhole("bad-domain.local")
            assert ok_err is False

        # 3. Successful remove payload format: must be 'domain' and 'no': True
        mock_send_rm = AsyncMock()
        mock_resp_rm = MagicMock()
        mock_resp_rm.status_code = 200
        mock_resp_rm.json.return_value = [
            {"ip": {"host": {"status": [{"status": "message", "code": "22544397", "message": "deleted"}]}}},
            {"system": {"configuration": {"save": {}}}}
        ]
        mock_send_rm.return_value = mock_resp_rm

        with patch.object(keenetic_client, "_send_request", mock_send_rm):
            ok_rm = await keenetic_client.remove_dns_sinkhole("test.adservice.com")
            assert ok_rm is True
            payload_rm = mock_send_rm.call_args[1]["json_data"]
            assert payload_rm[0] == {"ip": {"host": {"domain": "test.adservice.com", "address": "0.0.0.0", "no": True}}}
            assert payload_rm[1] == {"system": {"configuration": {"save": {}}}}


