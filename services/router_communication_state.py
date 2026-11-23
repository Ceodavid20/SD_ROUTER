"""Validation for bounded authentication/replay state on local JSON storage."""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from services.json_storage import ValidationError
from services.router_protocol import ProtocolError, ROUTER_ID, parse_utc_timestamp


INITIAL_COMMUNICATION_STATE = {
    "schema_version": 1, "routers": {}, "seen_requests": [], "rate_limits": {},
}
MAX_REPLAY_RECORDS = 10_000
MAX_RATE_BUCKETS = 1024
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _timestamp(value: Any) -> None:
    try:
        parse_utc_timestamp(value)
    except ProtocolError as exc:
        raise ValidationError("Invalid controller communication timestamp.") from exc


def _uuid(value: Any) -> None:
    try:
        parsed = UUID(value) if isinstance(value, str) else None
    except ValueError as exc:
        raise ValidationError("Invalid controller request identity.") from exc
    if parsed is None or parsed.version != 4 or str(parsed) != value:
        raise ValidationError("Invalid controller request identity.")


def validate_communication_state(state: Any) -> None:
    if (
        not isinstance(state, dict) or set(state) != set(INITIAL_COMMUNICATION_STATE)
        or type(state["schema_version"]) is not int or state["schema_version"] != 1
        or not isinstance(state["routers"], dict)
        or not isinstance(state["seen_requests"], list)
        or not isinstance(state["rate_limits"], dict)
    ):
        raise ValidationError("Invalid controller communication state.")
    if len(state["seen_requests"]) > MAX_REPLAY_RECORDS or len(state["rate_limits"]) > MAX_RATE_BUCKETS:
        raise ValidationError("Controller communication state exceeds its bounded capacity.")
    for router_id, record in state["routers"].items():
        if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
            raise ValidationError("Invalid controller router identity.")
        if not isinstance(record, dict) or set(record) != {
            "last_request_at", "last_authenticated_at", "last_response_id",
            "last_response_issued_at", "mode",
        } or record.get("mode") != "dry_run":
            raise ValidationError("Invalid controller check-in record.")
        for key in ("last_request_at", "last_authenticated_at", "last_response_issued_at"):
            _timestamp(record[key])
        _uuid(record["last_response_id"])
    seen = set()
    for item in state["seen_requests"]:
        if not isinstance(item, dict) or set(item) != {"router_id", "request_id", "expires_at"}:
            raise ValidationError("Invalid replay protection record.")
        if not isinstance(item["router_id"], str) or not ROUTER_ID.fullmatch(item["router_id"]):
            raise ValidationError("Invalid replay protection router.")
        _uuid(item["request_id"])
        _timestamp(item["expires_at"])
        pair = (item["router_id"], item["request_id"])
        if pair in seen:
            raise ValidationError("Duplicate replay protection record.")
        seen.add(pair)
    for key, bucket in state["rate_limits"].items():
        if not isinstance(key, str) or not _DIGEST.fullmatch(key):
            raise ValidationError("Invalid rate-limit identity.")
        if not isinstance(bucket, dict) or set(bucket) != {"window_started_at", "count"}:
            raise ValidationError("Invalid rate-limit bucket.")
        _timestamp(bucket["window_started_at"])
        if type(bucket["count"]) is not int or not 1 <= bucket["count"] <= 1_000_001:
            raise ValidationError("Invalid rate-limit request count.")
