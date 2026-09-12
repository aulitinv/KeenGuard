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

    asyncio.run(init_and_seed())

    yield

    db.db_path = orig_db_path
    settings.db_path = orig_settings_db_path
