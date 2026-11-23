"""Strict V2 telemetry contract: one cumulative outbound counter, no RX."""

import json
from typing import Any

from services.router_protocol import MAX_REQUEST_BYTES, ProtocolError
from services.routeros_protocol import _constant, _identity, _object, _unix, _uuid4


TRAFFIC_FIELDS = {
    "protocol_version", "router_id", "request_id", "timestamp", "request_type",
    "interface", "tx_octets",
}


def validate_interface(value: Any) -> None:
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 128
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127
               or 0xD800 <= ord(character) <= 0xDFFF for character in value)
    ):
        raise ProtocolError("A single valid interface name is required.")


def parse_traffic_request(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError("Invalid traffic request size.")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ProtocolError("Invalid traffic JSON.") from exc
    if not isinstance(payload, dict) or set(payload) != TRAFFIC_FIELDS:
        raise ProtocolError("Invalid traffic request fields.")
    if payload["protocol_version"] != "2.0" or payload["request_type"] != "traffic":
        raise ProtocolError("Unsupported traffic protocol or request type.")
    _identity(payload["router_id"])
    _uuid4(payload["request_id"])
    _unix(payload["timestamp"])
    validate_interface(payload["interface"])
    if type(payload["tx_octets"]) is not int or not 0 <= payload["tx_octets"] < 2**64:
        raise ProtocolError("TX octets must be an unsigned 64-bit integer.")
    return payload
