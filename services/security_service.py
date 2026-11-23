"""Administrator sessions, CSRF tokens, and single-process login throttling."""

from collections import deque
from hashlib import sha256
import hmac
import secrets
import threading
import time

from flask import current_app, session


def admin_is_configured() -> bool:
    return bool(
        current_app.config["ADMIN_USERNAME"]
        and current_app.config["ADMIN_PASSWORD_HASH"]
    )


def admin_fingerprint() -> str:
    return sha256(current_app.config["ADMIN_PASSWORD_HASH"].encode()).hexdigest()


def admin_is_authenticated() -> bool:
    return (
        admin_is_configured()
        and session.get("admin_user") == current_app.config["ADMIN_USERNAME"]
        and hmac.compare_digest(
            str(session.get("admin_fingerprint", "")).encode(), admin_fingerprint().encode()
        )
    )


def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def valid_csrf(candidate: str | None) -> bool:
    expected = session.get("csrf_token")
    return bool(
        isinstance(candidate, str)
        and isinstance(expected, str)
        and hmac.compare_digest(candidate.encode(), expected.encode())
    )


class LoginThrottle:
    """Bound password hashing attempts on the single active controller."""

    def __init__(self, attempts: int = 5, window_seconds: int = 300) -> None:
        self.attempts = attempts
        self.window_seconds = window_seconds
        self._attempts: deque[float] = deque()
        self._lock = threading.Lock()

    def allow_attempt(self) -> bool:
        with self._lock:
            now = time.monotonic()
            while self._attempts and now - self._attempts[0] >= self.window_seconds:
                self._attempts.popleft()
            if len(self._attempts) >= self.attempts:
                return False
            self._attempts.append(now)
            return True
