"""Strict, versioned JSON for the first router-initiated polling stage.

This stage acknowledges authenticated polls only. It cannot describe or carry
an executable RouterOS command or an OSPF cost change.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import hmac
import json
import re
from typing import Any
from uuid import UUID


POLL_PATH = "/api/controller/v1/poll"
PROTOCOL_VERSION = "1.0"
MAX_REQUEST_BYTES = 8192
ROUTER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
KEY_ID = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_UTC_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z"
)
_REQUEST_FIELDS = {
    "protocol_version", "router_id", "request_id", "timestamp", "request_type",
}
_RESPONSE_FIELDS = {
    "protocol_version", "router_id", "request_id", "response_id", "status",
    "mode", "action", "configuration", "reason", "issued_at", "expires_at",
    "poll_after_seconds",
}


class ProtocolError(ValueError):
    """A credential-free validation error safe to return to a caller."""


def _fields(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProtocolError(f"Invalid {label} fields.")


def _uuid4(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 36:
        raise ProtocolError(f"{label} must be a canonical UUID4.")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ProtocolError(f"{label} must be a canonical UUID4.") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ProtocolError(f"{label} must be a canonical UUID4.")


def _router_id(value: Any) -> None:
    if not isinstance(value, str) or not ROUTER_ID.fullmatch(value):
        raise ProtocolError("Invalid router identity.")


def parse_utc_timestamp(value: Any) -> datetime:
    """Accept an explicit UTC timestamp; never assume the local timezone."""
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise ProtocolError("A UTC ISO 8601 timestamp ending in Z is required.")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(UTC)
    except ValueError as exc:
        raise ProtocolError("Invalid UTC timestamp.") from exc


def utc_text(value: datetime) -> str:
    """Serialize an aware server timestamp without losing its timezone."""
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ProtocolError("Server timestamps must include a timezone.")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON properties are not allowed.")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProtocolError("Non-finite JSON values are not allowed.")


def parse_poll_request(raw: bytes) -> dict[str, Any]:
    """Validate exact fields and types before any request is authenticated."""
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("Invalid polling request size.")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("Polling requests must contain valid UTF-8 JSON.") from exc
    _fields(payload, _REQUEST_FIELDS, "polling request")
    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported polling protocol version.")
    _router_id(payload["router_id"])
    _uuid4(payload["request_id"], "Request ID")
    parse_utc_timestamp(payload["timestamp"])
    if payload["request_type"] != "poll":
        raise ProtocolError("Unsupported router request type.")
    return payload


def sign_request(
    secret: str, raw: bytes, key_id: str,
    method: str = "POST", path: str = POLL_PATH,
) -> str:
    """Bind authentication to the exact body bytes, method, path, and key ID.

    ``timestamp`` and ``request_id`` live inside the signed body. This helper
    deliberately does not parse or reserialize JSON before signing it.
    """
    if not isinstance(secret, str) or not secret:
        raise ProtocolError("A signing secret is required.")
    if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("Invalid polling request size.")
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise ProtocolError("Invalid authentication key ID.")
    if not isinstance(method, str) or not re.fullmatch(r"[A-Z]{1,16}", method):
        raise ProtocolError("Invalid signed HTTP method.")
    if (
        not isinstance(path, str) or not path.startswith("/") or len(path) > 256
        or any(ord(c) < 33 or ord(c) > 126 for c in path)
    ):
        raise ProtocolError("Invalid signed HTTP path.")
    canonical = "\n".join((
        "SDR-POLL-V1", method, path, key_id, hashlib.sha256(raw).hexdigest(),
    )).encode("ascii")
    try:
        return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    except UnicodeError as exc:
        raise ProtocolError("Invalid signing secret encoding.") from exc


def validate_poll_response(payload: Any) -> None:
    """Validate the no-action response contract, including its short lifetime.

    The receiving client must additionally compare ``expires_at`` with its
    current clock. Structural validation cannot prove delivery or application.
    """
    _fields(payload, _RESPONSE_FIELDS, "polling response")
    if payload["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError("Unsupported polling protocol version.")
    _router_id(payload["router_id"])
    _uuid4(payload["request_id"], "Request ID")
    _uuid4(payload["response_id"], "Response ID")
    for field, expected in (
        ("status", "authenticated"), ("mode", "dry_run"), ("action", "none"),
        ("reason", "optimization_unavailable"),
    ):
        if payload[field] != expected:
            raise ProtocolError("Unsupported polling response state.")
    if not isinstance(payload["configuration"], dict) or payload["configuration"]:
        raise ProtocolError("This polling stage permits no configuration action.")
    issued = parse_utc_timestamp(payload["issued_at"])
    expires = parse_utc_timestamp(payload["expires_at"])
    if not 0 < (expires - issued).total_seconds() <= 300:
        raise ProtocolError("Invalid polling response lifetime.")
    interval = payload["poll_after_seconds"]
    if type(interval) is not int or not 1 <= interval <= 86400:
        raise ProtocolError("Invalid router polling interval.")
