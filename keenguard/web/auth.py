"""Web authentication, session management, and brute-force protection for KeenGuard."""
import hashlib
import hmac
import logging
import os
import secrets
import time
from typing import Dict, List, Optional, Tuple
from fastapi import Request

from keenguard.config import settings, persist_web_auth_settings

logger = logging.getLogger("keenguard.web.auth")

COOKIE_NAME = "keenguard_session"
DEFAULT_SESSION_LIFETIME = 30 * 86400  # 30 days

# In-memory session store: token -> expiry timestamp
_active_sessions: Dict[str, float] = {}

# Brute-force tracking: ip -> list of failure timestamps
_failed_attempts: Dict[str, List[float]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000,
    )
    return f"pbkdf2:sha256:100000${salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies password against stored PBKDF2 hash or plaintext fallback."""
    if not stored_hash or not password:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash.split("$")
            if len(parts) != 3:
                return False
            salt = parts[1]
            target_hash = parts[2]
            computed = hash_password(password, salt=salt).split("$")[2]
            return hmac.compare_digest(computed, target_hash)
        except Exception as e:
            logger.warning("Error verifying password hash: %s", e)
            return False
    # Plaintext fallback for convenience
    return hmac.compare_digest(password, stored_hash)


def is_auth_required() -> bool:
    """Determines whether authentication is required based on settings and bind host."""
    mode = (settings.web_auth_enabled or "auto").lower()
    if mode in ("false", "0", "no", "off"):
        return False
    if mode in ("true", "1", "yes", "on"):
        return True
    # "auto" mode: auth is required if server is exposed to LAN (not purely 127.0.0.1)
    # or if a password has been explicitly configured
    has_password = bool(settings.web_password_hash or settings.web_password)
    is_exposed = settings.web_host not in ("127.0.0.1", "localhost", "::1")
    return is_exposed or has_password


def is_localhost_ip(ip: str) -> bool:
    """Checks if client IP is a local loopback address."""
    clean_ip = (ip or "").strip().lower()
    return clean_ip in ("127.0.0.1", "::1", "localhost", "testclient")


def get_client_ip(request: Request) -> str:
    """Extracts client IP address safely from FastAPI request."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    if request.client and request.client.host:
        return request.client.host.strip()
    return "127.0.0.1"


# --- Session Management ---

def create_session() -> str:
    """Generates a secure cryptographically random session token and stores it."""
    clean_expired_sessions()
    token = secrets.token_urlsafe(32)
    _active_sessions[token] = time.time() + DEFAULT_SESSION_LIFETIME
    return token


def validate_session(token: Optional[str]) -> bool:
    """Validates if session token is active and not expired."""
    if not token:
        return False
    expiry = _active_sessions.get(token)
    if expiry is None:
        return False
    if time.time() > expiry:
        _active_sessions.pop(token, None)
        return False
    return True


def revoke_session(token: Optional[str]) -> None:
    """Revokes a session token upon logout."""
    if token:
        _active_sessions.pop(token, None)


def clean_expired_sessions() -> None:
    """Removes expired tokens to prevent memory growth."""
    now = time.time()
    expired = [t for t, exp in _active_sessions.items() if exp < now]
    for t in expired:
        _active_sessions.pop(t, None)


# --- Brute-force Guard ---

class BruteForceGuard:
    """Tracks failed login attempts per client IP and locks out attackers."""

    @classmethod
    def is_locked(cls, ip: str) -> Tuple[bool, int]:
        """Returns (is_locked, remaining_seconds)."""
        cls._prune(ip)
        attempts = _failed_attempts.get(ip, [])
        if len(attempts) >= MAX_FAILED_ATTEMPTS:
            elapsed = time.time() - attempts[-1]
            if elapsed < LOCKOUT_DURATION:
                return True, int(LOCKOUT_DURATION - elapsed)
        return False, 0

    @classmethod
    def record_failure(cls, ip: str) -> int:
        """Records a failed attempt for IP and returns remaining attempts allowed."""
        now = time.time()
        cls._prune(ip)
        if ip not in _failed_attempts:
            _failed_attempts[ip] = []
        _failed_attempts[ip].append(now)
        remaining = max(0, MAX_FAILED_ATTEMPTS - len(_failed_attempts[ip]))
        if len(_failed_attempts[ip]) >= MAX_FAILED_ATTEMPTS:
            cls._notify_lockout(ip)
        return remaining

    @classmethod
    def record_success(cls, ip: str) -> None:
        """Resets failed attempt counters for IP on successful authentication."""
        _failed_attempts.pop(ip, None)

    @classmethod
    def _prune(cls, ip: str) -> None:
        now = time.time()
        attempts = _failed_attempts.get(ip, [])
        valid = [t for t in attempts if now - t < LOCKOUT_DURATION]
        if valid:
            _failed_attempts[ip] = valid
        else:
            _failed_attempts.pop(ip, None)

    @classmethod
    def _notify_lockout(cls, ip: str) -> None:
        logger.warning("Brute-force lockout triggered for IP: %s", ip)
        try:
            from keenguard.core.notifier import telegram_notifier
            from keenguard.db.models import SecurityEvent
            from keenguard.core.enums import EventType, Severity
            from keenguard.web.ws import create_tracked_task

            evt = SecurityEvent(
                event_type=EventType.POLICY_VIOLATION,
                severity=Severity.WARNING,
                description=f"Несанкционированные попытки входа в веб-интерфейс с IP: {ip}. Доступ временно заблокирован на 15 минут.",
                source_ip=ip,
            )
            create_tracked_task(telegram_notifier.send_alert(evt))
        except Exception as e:
            logger.debug("Could not dispatch brute-force alert: %s", e)


# --- Startup Initializer ---

def ensure_initial_credentials() -> Optional[str]:
    """
    If authentication is required and no password has been configured yet,
    generates a secure 8-character passcode and persists it to .env.
    Returns generated password if one was created, else None.
    """
    if not is_auth_required():
        return None

    current_hash = settings.web_password_hash
    current_plain = settings.web_password
    if current_hash or current_plain:
        return None

    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    generated = "".join(secrets.choice(alphabet) for _ in range(8))
    new_hash = hash_password(generated)
    settings.web_password_hash = new_hash
    persist_web_auth_settings(web_password_hash=new_hash)
    logger.info("Generated initial Web UI password for LAN protection: %s", generated)
    return generated
