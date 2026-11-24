"""RouterOS-compatible v2 polling: SHA-512 and integer UTC timestamps.

V1 remains unchanged. V2 uses the SHA-512 primitive documented by RouterOS
scripting, with standard HMAC construction performed by its restricted client.
Neither contract permits an executable command in a response.
"""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import hmac
import json
from typing import Any
from uuid import UUID

from services.router_protocol import (
    KEY_ID, MAX_REQUEST_BYTES, ROUTER_ID, ProtocolError, parse_utc_timestamp,
)


ROUTEROS_POLL_PATH = "/api/controller/v2/poll"
ROUTEROS_ACK_PATH = "/api/controller/v2/ack"
ROUTEROS_TRAFFIC_PATH = "/api/controller/v2/traffic"
_REQUEST_FIELDS = {"protocol_version", "router_id", "request_id", "timestamp", "request_type"}
_RESPONSE_FIELDS = {
    "protocol_version", "router_id", "request_id", "response_id", "status",
    "mode", "action", "configuration", "reason", "issued_at", "expires_at",
    "issued_at_unix", "expires_at_unix", "poll_after_seconds",
}


def _uuid4(value: Any) -> None:
    if not isinstance(value, str) or len(value) != 36:
        raise ProtocolError("A canonical UUID4 is required.")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ProtocolError("A canonical UUID4 is required.") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise ProtocolError("A canonical UUID4 is required.")


def _identity(value: Any) -> None:
    if not isinstance(value, str) or not ROUTER_ID.fullmatch(value):
        raise ProtocolError("Invalid router identity.")


def _unix(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= 2**53 - 1:
        raise ProtocolError("A positive whole UTC epoch timestamp is required.")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("Duplicate JSON properties are not permitted.")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ProtocolError("Non-finite JSON values are not permitted.")


def parse_routeros_request(raw: bytes, request_type: str = "poll") -> dict[str, Any]:
    if request_type not in ("poll", "ack"):
        raise ProtocolError("Unsupported router request type.")
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("Invalid router request size.")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("Router request must contain valid UTF-8 JSON.") from exc
    expected = _REQUEST_FIELDS | ({"response_id"} if request_type == "ack" else set())
    if not isinstance(payload, dict) or set(payload) != expected:
        raise ProtocolError("Invalid router request fields.")
    if payload["protocol_version"] != "2.0" or payload["request_type"] != request_type:
        raise ProtocolError("Unsupported router protocol version or request type.")
    _identity(payload["router_id"])
    _uuid4(payload["request_id"])
    _unix(payload["timestamp"])
    if request_type == "ack":
        _uuid4(payload["response_id"])
    return payload


def sign_routeros_request(
    secret: str, raw: bytes, key_id: str, path: str = ROUTEROS_POLL_PATH,
) -> str:
    if not isinstance(secret, str) or not secret:
        raise ProtocolError("A signing secret is required.")
    if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("Invalid router request size.")
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise ProtocolError("Invalid authentication key ID.")
    if path not in (ROUTEROS_POLL_PATH, ROUTEROS_ACK_PATH, ROUTEROS_TRAFFIC_PATH,
                    "/api/controller/v2/optimization", "/api/controller/v2/optimization/result"):
        raise ProtocolError("Unsupported signed endpoint.")
    canonical = "\n".join((
        "SDR-POLL-V2", "POST", path, key_id, hashlib.sha512(raw).hexdigest(),
    )).encode("ascii")
    try:
        return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha512).hexdigest()
    except UnicodeError as exc:
        raise ProtocolError("Invalid signing secret encoding.") from exc


def validate_routeros_response(payload: Any, request_type: str = "poll") -> None:
    if request_type not in ("poll", "ack"):
        raise ProtocolError("Unsupported router response type.")
    fields = _RESPONSE_FIELDS | ({"acknowledged_response_id"} if request_type == "ack" else set())
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ProtocolError("Invalid router response fields.")
    _identity(payload["router_id"])
    _uuid4(payload["request_id"])
    _uuid4(payload["response_id"])
    if request_type == "ack":
        _uuid4(payload["acknowledged_response_id"])
    expected_status = "authenticated" if request_type == "poll" else "receipt_recorded"
    expected_reason = "optimization_unavailable" if request_type == "poll" else "receipt_recorded"
    if (
        payload["protocol_version"] != "2.0" or payload["status"] != expected_status
        or payload["reason"] != expected_reason or payload["mode"] != "dry_run"
        or payload["action"] != "none" or not isinstance(payload["configuration"], dict)
        or payload["configuration"]
    ):
        raise ProtocolError("Unsupported router response action or state.")
    issued = parse_utc_timestamp(payload["issued_at"])
    expires = parse_utc_timestamp(payload["expires_at"])
    _unix(payload["issued_at_unix"])
    _unix(payload["expires_at_unix"])
    try:
        exact_issued = datetime.fromtimestamp(payload["issued_at_unix"], UTC)
        exact_expires = datetime.fromtimestamp(payload["expires_at_unix"], UTC)
    except (ValueError, OverflowError, OSError) as exc:
        raise ProtocolError("Invalid router response timestamps.") from exc
    if issued != exact_issued or expires != exact_expires or not 0 < (expires - issued).total_seconds() <= 300:
        raise ProtocolError("Invalid router response lifetime.")
    if type(payload["poll_after_seconds"]) is not int or not 1 <= payload["poll_after_seconds"] <= 86400:
        raise ProtocolError("Invalid router polling interval.")
