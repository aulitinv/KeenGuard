"""Authentication and access control routes for KeenGuard Web UI."""
import logging
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from keenguard.config import settings, persist_web_auth_settings
from keenguard.web.auth import (
    COOKIE_NAME,
    DEFAULT_SESSION_LIFETIME,
    BruteForceGuard,
    create_session,
    get_client_ip,
    hash_password,
    is_auth_required,
    is_localhost_ip,
    revoke_session,
    validate_session,
    verify_password,
)

logger = logging.getLogger("keenguard.web.routes.auth")
router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Web UI admin password or PIN")


class ChangePasswordRequest(BaseModel):
    old_password: Optional[str] = Field(default="", description="Current password (if set)")
    new_password: str = Field(..., min_length=6, description="New admin password")


def get_current_session_token(request: Request) -> Optional[str]:
    """Extracts session token from cookie or Authorization header."""
    cookie_token = request.cookies.get(COOKIE_NAME)
    if cookie_token:
        return cookie_token
    auth_hdr = request.headers.get("authorization")
    if auth_hdr and auth_hdr.lower().startswith("bearer "):
        return auth_hdr[7:].strip()
    return None


def is_request_authorized(request: Request) -> bool:
    """Checks whether the incoming request is authorized to access protected resources."""
    if not is_auth_required():
        return True
    client_ip = get_client_ip(request)
    if settings.web_auth_exempt_localhost and is_localhost_ip(client_ip):
        return True
    token = get_current_session_token(request)
    return validate_session(token)


@router.get("/api/auth/status")
async def get_auth_status(request: Request):
    """Returns current authentication state, mode, and whether caller is authenticated."""
    client_ip = get_client_ip(request)
    is_local = is_localhost_ip(client_ip)
    token = get_current_session_token(request)
    has_valid_session = validate_session(token)
    required = is_auth_required()
    is_authed = (not required) or has_valid_session or (settings.web_auth_exempt_localhost and is_local)

    return {
        "status": "ok",
        "auth_required": required,
        "authenticated": is_authed,
        "is_localhost": is_local,
        "client_ip": client_ip,
        "web_host": settings.web_host,
        "exempt_localhost": settings.web_auth_exempt_localhost,
    }


@router.post("/api/auth/login")
async def login(body: LoginRequest, request: Request, response: Response):
    """Authenticates user with admin password and issues a secure session cookie."""
    client_ip = get_client_ip(request)

    # 1. Check brute force lockout
    is_locked, rem_seconds = BruteForceGuard.is_locked(client_ip)
    if is_locked:
        logger.warning("Rejected login attempt from locked-out IP: %s (%d sec left)", client_ip, rem_seconds)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Слишком много неверных попыток. Доступ временно заблокирован на {rem_seconds // 60 + 1} мин.",
        )

    # 2. Check password against hash or plaintext
    target_hash = settings.web_password_hash
    target_plain = settings.web_password

    is_valid = False
    if target_hash:
        is_valid = verify_password(body.password, target_hash)
    elif target_plain:
        is_valid = verify_password(body.password, target_plain)
    else:
        # No password has been set at all
        is_valid = True

    if not is_valid:
        rem_attempts = BruteForceGuard.record_failure(client_ip)
        logger.warning("Failed login attempt from IP: %s (attempts remaining: %d)", client_ip, rem_attempts)
        msg = f"Неверный пароль. Осталось попыток: {rem_attempts}" if rem_attempts > 0 else "Доступ заблокирован на 15 минут."
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=msg,
        )

    # 3. Successful login: reset brute-force counter and issue session
    BruteForceGuard.record_success(client_ip)
    token = create_session()
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=DEFAULT_SESSION_LIFETIME,
        httponly=True,
        samesite="lax",
        secure=False,  # Allow local LAN HTTP without SSL warnings
        path="/",
    )
    logger.info("Successful Web UI authentication from IP: %s", client_ip)
    return {"status": "ok", "authenticated": True, "token": token, "message": "Авторизация успешна"}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    """Revokes session and clears authentication cookie."""
    token = get_current_session_token(request)
    revoke_session(token)
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"status": "ok", "authenticated": False, "message": "Сессия завершена"}


@router.post("/api/auth/change_password")
async def change_password(body: ChangePasswordRequest, request: Request):
    """Changes the Web UI administrator password and persists it to .env."""
    if not is_request_authorized(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется авторизация")

    target_hash = settings.web_password_hash
    target_plain = settings.web_password

    # If an existing password was set, verify the old password first
    if target_hash or target_plain:
        old_pw = body.old_password or ""
        valid_old = False
        if target_hash:
            valid_old = verify_password(old_pw, target_hash)
        elif target_plain:
            valid_old = verify_password(old_pw, target_plain)
        if not valid_old:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Неверный старый пароль")

    if len(body.new_password.strip()) < 6:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Пароль должен содержать не менее 6 символов")

    new_hash = hash_password(body.new_password.strip())
    settings.web_password_hash = new_hash
    settings.web_password = ""
    persist_web_auth_settings(web_password_hash=new_hash)
    logger.info("Web UI password was successfully changed from IP %s", get_client_ip(request))
    return {"status": "ok", "message": "Пароль успешно обновлен"}
