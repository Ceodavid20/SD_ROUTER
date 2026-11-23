"""Per-router HMAC verification, independent of RouterOS API diagnostics.

    Replay consumption and rate limiting belong to the polling transaction,
    not this stateless verifier. Secrets are read from environment references
    and never returned with the public JSON response.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
import hmac
import os
import re
from typing import Any

from services.json_storage import StorageService
from services.router_protocol import (
    KEY_ID, ProtocolError, parse_poll_request, parse_utc_timestamp, sign_request,
)


_REFERENCE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{64}\Z")


class AuthenticationError(ValueError):
    """A generic response message plus a safe, bounded audit reason code."""

    def __init__(self, *, code: str = "authentication_failed") -> None:
        super().__init__("Router authentication failed.")
        self.code = code


class RouterAuthService:
    """Verify a registered device without contacting it or changing storage."""

    def __init__(self, storage: StorageService, config: Mapping[str, Any]) -> None:
        self.storage = storage
        self.config = config

    def authenticate(
        self, payload: dict[str, Any], raw: bytes, key_id: str,
        signature: str, now: datetime,
    ) -> dict[str, Any]:
        """Authenticate exact signed bytes using current registry authorization.

        Multiple active key IDs allow an overlap during rotation. Disabling
        authentication or removing a key ID revokes it on the next request.
        This method never consumes a nonce; the caller must do that atomically
        before accepting a poll.
        """
        try:
            decoded = parse_poll_request(raw)
        except ProtocolError as exc:
            raise AuthenticationError() from exc
        if decoded != payload:
            raise AuthenticationError()
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            raise AuthenticationError()
        if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
            raise AuthenticationError()
        router = next((
            item for item in self.storage.read_json("routers.json")
            if item.get("router_id") == decoded["router_id"]
        ), None)
        if router is None or router.get("controller_auth_enabled") is not True:
            raise AuthenticationError()
        reference = router.get("controller_auth_ref")
        if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
            raise AuthenticationError()
        key_ids = router.get("controller_auth_key_ids")
        if (
            not isinstance(key_ids, list) or not key_ids
            or any(not isinstance(item, str) or not KEY_ID.fullmatch(item) for item in key_ids)
            or len(key_ids) != len(set(key_ids)) or key_id not in key_ids
        ):
            raise AuthenticationError()
        secret = os.environ.get(f"{reference}_{key_id}_SECRET", "")
        if not 32 <= len(secret) <= 4096:
            raise AuthenticationError()
        try:
            expected = sign_request(secret, raw, key_id)
        except ProtocolError as exc:
            raise AuthenticationError() from exc
        if not hmac.compare_digest(signature, expected):
            raise AuthenticationError()
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise AuthenticationError()
        max_age = self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120)
        clock_skew = self.config.get("ROUTER_CLOCK_SKEW_SECONDS", 30)
        if (
            type(max_age) is not int or not 1 <= max_age <= 86400
            or type(clock_skew) is not int or not 0 <= clock_skew <= 86400
        ):
            raise AuthenticationError()
        age = (now.astimezone(UTC) - parse_utc_timestamp(decoded["timestamp"])).total_seconds()
        if age > max_age:
            raise AuthenticationError(code="expired_request")
        if age < -clock_skew:
            raise AuthenticationError(code="future_request")
        return router
