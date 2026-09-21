import pytest
import asyncio
from pathlib import Path
from keenguard.config import settings
from keenguard.db.database import db
from keenguard.core.keenetic import keenetic_client

@pytest.fixture(autouse=True)
def isolate_keenetic_router():
    """
    Guarantees that ALL tests run with mock_mode=True, completely preventing
    any test from sending live HTTP or RCI requests to the physical Keenetic router.
    """
    orig_mock = keenetic_client.mock_mode
    keenetic_client.mock_mode = True
    yield
    keenetic_client.mock_mode = orig_mock

@pytest.fixture(autouse=True)
def isolate_test_env_file(tmp_path):
    """
    Guarantees that tests never write into or mutate the production .env file.
    Each test uses a temporary .env file in tmp_path.
    """
    import keenguard.config
    orig_env_file = keenguard.config.ENV_FILE
    test_env_file = tmp_path / ".env"
    keenguard.config.ENV_FILE = test_env_file

    prod_env = (Path(__file__).resolve().parent.parent / ".env").resolve()
    assert Path(keenguard.config.ENV_FILE).resolve() != prod_env, (
        "SECURITY VIOLATION: Test is configured to write to production .env file!"
    )
    yield
    keenguard.config.ENV_FILE = orig_env_file

@pytest.fixture(autouse=True)
def isolate_test_database(tmp_path):
    """
    Automatically isolates all pytest tests from the live production database.
    Each test receives a clean, isolated SQLite database in tmp_path.
    """
    test_db_path = tmp_path / "test_keenguard.db"
    orig_db_path = db.db_path
    orig_settings_db_path = settings.db_path

    db.db_path = test_db_path
    settings.db_path = test_db_path

    # Fail-closed security check: verify we are not pointing to production DB
    prod_path = (Path(__file__).resolve().parent.parent / "data" / "keenguard.db").resolve()
    assert Path(db.db_path).resolve() != prod_path, (
        "SECURITY VIOLATION: Test is configured to use production database path!"
    )

    async def init_and_seed():
        await db.init_db()
        from keenguard.db.models import DeviceRecord
        await db.upsert_device(DeviceRecord(
            mac="11:22:33:44:55:66",
            ip="192.168.1.50",
            hostname="test-host",
            profile="iot"
        ))
        await db.close()

    asyncio.run(init_and_seed())

    yield

    # Clean up any active audit sessions and background tasks between tests
    try:
        from keenguard.core.audit import audit_manager
        for mac in list(audit_manager.active_sessions.keys()):
            sess = audit_manager.active_sessions.pop(mac, None)
            if sess:
                sess.is_active = False
                if getattr(sess, "_poller_task", None) and not sess._poller_task.done():
                    sess._poller_task.cancel()
        if getattr(audit_manager, "active_network_session", None):
            net_sess = audit_manager.active_network_session
            net_sess.is_active = False
            if getattr(net_sess, "_poller_task", None) and not net_sess._poller_task.done():
                net_sess._poller_task.cancel()
            audit_manager.active_network_session = None

        from keenguard.web.ws import _background_tasks
        for t in list(_background_tasks):
            if hasattr(t, "cancel") and not t.done():
                t.cancel()
        _background_tasks.clear()

        from keenguard.core.scheduler import scheduler
        if getattr(scheduler, "_task", None) and not scheduler._task.done():
            scheduler._task.cancel()
    except Exception:
        pass

    async def cleanup():
        await db.close()

    try:
        asyncio.run(cleanup())
    except Exception:
        pass

    db.db_path = orig_db_path
    settings.db_path = orig_settings_db_path
