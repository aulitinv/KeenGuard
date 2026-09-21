import pytest
from httpx import AsyncClient, ASGITransport
from keenguard.web.app import app
from keenguard.config import settings
from keenguard.web.auth import (
    hash_password,
    verify_password,
    BruteForceGuard,
    create_session,
    validate_session,
    revoke_session,
    _failed_attempts,
    COOKIE_NAME,
)


@pytest.fixture(autouse=True)
def reset_auth_state():
    """Reset auth state and brute force counters before each test."""
    _failed_attempts.clear()
    orig_host = settings.web_host
    orig_auth_enabled = settings.web_auth_enabled
    orig_pw_hash = settings.web_password_hash
    orig_pw = settings.web_password
    orig_exempt = settings.web_auth_exempt_localhost

    yield

    _failed_attempts.clear()
    settings.web_host = orig_host
    settings.web_auth_enabled = orig_auth_enabled
    settings.web_password_hash = orig_pw_hash
    settings.web_password = orig_pw
    settings.web_auth_exempt_localhost = orig_exempt


@pytest.mark.asyncio
async def test_password_hashing_and_verification():
    """Verify PBKDF2 hashing and timing-safe comparison."""
    hashed = hash_password("MySecurePass123!")
    assert hashed.startswith("pbkdf2:sha256:100000$")
    assert verify_password("MySecurePass123!", hashed) is True
    assert verify_password("WrongPassword", hashed) is False
    assert verify_password("", hashed) is False


@pytest.mark.asyncio
async def test_localhost_exemption_allows_access():
    """Requests from localhost bypass authentication by default."""
    settings.web_host = "0.0.0.0"
    settings.web_auth_enabled = "true"
    settings.web_password_hash = hash_password("SuperSecret")
    settings.web_auth_exempt_localhost = True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # Default test client has localhost IP
        res = await ac.get("/api/settings/network_access")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["auth_required"] is True


@pytest.mark.asyncio
async def test_external_lan_request_blocked_when_unauthenticated():
    """Requests from LAN IP receive 401 when unauthenticated."""
    settings.web_host = "0.0.0.0"
    settings.web_auth_enabled = "true"
    settings.web_password_hash = hash_password("SuperSecret")
    settings.web_auth_exempt_localhost = True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://192.168.1.100") as ac:
        headers = {"X-Forwarded-For": "192.168.1.105"}
        res = await ac.get("/api/settings/network_access", headers=headers)
        assert res.status_code == 401
        data = res.json()
        assert data["auth_required"] is True


@pytest.mark.asyncio
async def test_login_flow_and_session_cookie():
    """Valid login generates session cookie and allows subsequent LAN requests."""
    pwd = "AdminNetworkPass99"
    settings.web_host = "0.0.0.0"
    settings.web_auth_enabled = "true"
    settings.web_password_hash = hash_password(pwd)

    transport = ASGITransport(app=app)
    lan_headers = {"X-Forwarded-For": "192.168.1.55"}

    async with AsyncClient(transport=transport, base_url="http://192.168.1.1") as ac:
        # 1. Wrong password attempt
        bad_res = await ac.post("/api/auth/login", json={"password": "wrong"}, headers=lan_headers)
        assert bad_res.status_code == 401
        assert "Неверный пароль" in bad_res.json()["detail"]

        # 2. Correct password attempt
        login_res = await ac.post("/api/auth/login", json={"password": pwd}, headers=lan_headers)
        assert login_res.status_code == 200
        data = login_res.json()
        assert data["authenticated"] is True
        token = data["token"]
        assert token is not None
        assert COOKIE_NAME in login_res.cookies

        # 3. Subsequent request with session cookie
        auth_cookie = {COOKIE_NAME: token}
        ok_res = await ac.get("/api/settings/network_access", headers=lan_headers, cookies=auth_cookie)
        assert ok_res.status_code == 200
        assert ok_res.json()["status"] == "ok"

        # 4. Subsequent request with Authorization Bearer header
        bearer_headers = {**lan_headers, "Authorization": f"Bearer {token}"}
        ok_bearer_res = await ac.get("/api/settings/network_access", headers=bearer_headers)
        assert ok_bearer_res.status_code == 200

        # 5. Logout revokes the session
        logout_res = await ac.post("/api/auth/logout", headers=lan_headers, cookies=auth_cookie)
        assert logout_res.status_code == 200

        # 6. Post-logout request is rejected
        rejected_res = await ac.get("/api/settings/network_access", headers=lan_headers, cookies=auth_cookie)
        assert rejected_res.status_code == 401


@pytest.mark.asyncio
async def test_brute_force_lockout():
    """Brute force guard locks out IP after 5 failed attempts with 429 status."""
    settings.web_host = "0.0.0.0"
    settings.web_auth_enabled = "true"
    settings.web_password_hash = hash_password("RealPassword123")

    transport = ASGITransport(app=app)
    attacker_headers = {"X-Forwarded-For": "192.168.1.250"}

    async with AsyncClient(transport=transport, base_url="http://192.168.1.1") as ac:
        # Attempts 1 to 4 should be 401
        for i in range(1, 5):
            res = await ac.post("/api/auth/login", json={"password": f"guess_{i}"}, headers=attacker_headers)
            assert res.status_code == 401

        # Attempt 5 should fail and trigger lockout
        res5 = await ac.post("/api/auth/login", json={"password": "guess_5"}, headers=attacker_headers)
        assert res5.status_code == 401

        # Attempt 6 should be rejected with 429 Too Many Requests
        res6 = await ac.post("/api/auth/login", json={"password": "RealPassword123"}, headers=attacker_headers)
        assert res6.status_code == 429
        assert "заблокирован" in res6.json()["detail"].lower()


@pytest.mark.asyncio
async def test_change_password():
    """Authorized user can change the admin password."""
    initial_pwd = "InitialPassword123"
    new_pwd = "BrandNewPassword456"
    settings.web_host = "127.0.0.1"
    settings.web_password_hash = hash_password(initial_pwd)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        # 1. Fail with invalid old password
        bad_change = await ac.post(
            "/api/auth/change_password",
            json={"old_password": "WrongOldPassword", "new_password": new_pwd}
        )
        assert bad_change.status_code == 400

        # 2. Fail with password too short (< 6 chars) via schema validation
        short_change = await ac.post(
            "/api/auth/change_password",
            json={"old_password": initial_pwd, "new_password": "123"}
        )
        assert short_change.status_code in (400, 422)

        # 3. Successful password change
        good_change = await ac.post(
            "/api/auth/change_password",
            json={"old_password": initial_pwd, "new_password": new_pwd}
        )
        assert good_change.status_code == 200
        assert verify_password(new_pwd, settings.web_password_hash) is True


@pytest.mark.asyncio
async def test_network_access_settings_update():
    """Update bind host, auth exemption, and password via settings endpoint."""
    settings.web_host = "127.0.0.1"
    settings.web_auth_exempt_localhost = True

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        payload = {
            "web_host": "0.0.0.0",
            "web_auth_enabled": "true",
            "web_auth_exempt_localhost": False,
            "new_password": "NewSecretForLAN99"
        }
        res = await ac.post("/api/settings/network_access", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["web_host"] == "0.0.0.0"
        assert data["web_auth_exempt_localhost"] is False
        assert data["has_web_password"] is True
        assert data["requires_restart"] is True
