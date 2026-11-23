"""V2 authenticated polling and receipt acknowledgements; no routing writes."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
import hmac
import os
import re
from typing import Any
from uuid import uuid4

from services.json_storage import StorageService, ValidationError
from services.api_credentials_service import APICredentialError, controller_secret
from services.router_poll_service import PollError, RouterPollService
from services.router_protocol import KEY_ID, ROUTER_ID, ProtocolError, parse_utc_timestamp
from services.routeros_protocol import (
    ROUTEROS_ACK_PATH, ROUTEROS_POLL_PATH, _uuid4, parse_routeros_request,
    sign_routeros_request, validate_routeros_response,
)


MAX_ROUTEROS_RECORDS = 10_000
_REFERENCE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_ROUTER_FIELDS = {
    "last_authenticated_at", "last_request_at", "last_response_id",
    "last_response_issued_at", "last_response_expires_at",
    "last_received_response_id", "last_received_at", "mode", "last_request_type",
}


def _time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_identity(value: Any) -> None:
    if not isinstance(value, str) or not ROUTER_ID.fullmatch(value):
        raise ValidationError("Invalid router communication identity.")


def _validate_time(value: Any) -> None:
    try:
        parse_utc_timestamp(value)
    except ProtocolError as exc:
        raise ValidationError("Invalid router communication timestamp.") from exc


def _validate_uuid(value: Any) -> None:
    try:
        _uuid4(value)
    except ProtocolError as exc:
        raise ValidationError("Invalid router communication request identity.") from exc


def validate_routeros_state(state: Any) -> None:
    if (
        not isinstance(state, dict)
        or set(state) != {"schema_version", "routers", "seen_requests", "issued_responses"}
        or type(state["schema_version"]) is not int or state["schema_version"] != 2
        or not isinstance(state["routers"], dict)
        or not isinstance(state["seen_requests"], list)
        or not isinstance(state["issued_responses"], list)
    ):
        raise ValidationError("Invalid RouterOS communication state.")
    if len(state["seen_requests"]) > MAX_ROUTEROS_RECORDS or len(state["issued_responses"]) > MAX_ROUTEROS_RECORDS:
        raise ValidationError("RouterOS communication state exceeds its bounded capacity.")
    for router_id, record in state["routers"].items():
        _validate_identity(router_id)
        if (
            not isinstance(record, dict) or set(record) != _ROUTER_FIELDS
            or record["mode"] != "dry_run" or record["last_request_type"] not in ("poll", "ack")
        ):
            raise ValidationError("Invalid RouterOS check-in record.")
        for key in ("last_authenticated_at", "last_request_at"):
            _validate_time(record[key])
        for key in ("last_response_id", "last_received_response_id"):
            if record[key] is not None:
                _validate_uuid(record[key])
        for key in ("last_response_issued_at", "last_response_expires_at", "last_received_at"):
            if record[key] is not None:
                _validate_time(record[key])
        if (record["last_response_id"] is None) != (record["last_response_issued_at"] is None):
            raise ValidationError("Inconsistent RouterOS response metadata.")
        if (record["last_response_id"] is None) != (record["last_response_expires_at"] is None):
            raise ValidationError("Inconsistent RouterOS response expiry.")
        if (record["last_received_response_id"] is None) != (record["last_received_at"] is None):
            raise ValidationError("Inconsistent RouterOS receipt metadata.")
    seen = set()
    for item in state["seen_requests"]:
        if not isinstance(item, dict) or set(item) != {"router_id", "request_id", "expires_at"}:
            raise ValidationError("Invalid RouterOS replay record.")
        _validate_identity(item["router_id"])
        _validate_uuid(item["request_id"])
        _validate_time(item["expires_at"])
        pair = (item["router_id"], item["request_id"])
        if pair in seen:
            raise ValidationError("Duplicate RouterOS replay record.")
        seen.add(pair)
    response_ids = set()
    for item in state["issued_responses"]:
        if not isinstance(item, dict) or set(item) != {
            "router_id", "request_id", "response_id", "issued_at", "expires_at", "received_at",
        }:
            raise ValidationError("Invalid RouterOS issued response record.")
        _validate_identity(item["router_id"])
        _validate_uuid(item["request_id"])
        _validate_uuid(item["response_id"])
        _validate_time(item["issued_at"])
        _validate_time(item["expires_at"])
        if not 0 < (parse_utc_timestamp(item["expires_at"]) - parse_utc_timestamp(item["issued_at"])).total_seconds() <= 300:
            raise ValidationError("Invalid RouterOS issued response lifetime.")
        if item["received_at"] is not None:
            _validate_time(item["received_at"])
        if item["response_id"] in response_ids:
            raise ValidationError("Duplicate RouterOS response identity.")
        response_ids.add(item["response_id"])


class RouterOSPollService:
    def __init__(self, storage: StorageService, config: Mapping[str, Any]) -> None:
        self.storage, self.config = storage, config

    def _authentication_failed(self, reason: str = "authentication_failed") -> None:
        self.storage.append_activity("security", "RouterOS authentication failed.", {"reason": reason})
        raise PollError("Router authentication failed.", 401, "authentication_failed")

    def _authenticate(self, payload, raw, key_id, signature, path, now):
        if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
            self._authentication_failed()
        if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
            self._authentication_failed()
        router = next((r for r in self.storage.read_json("routers.json") if r.get("router_id") == payload["router_id"]), None)
        if router is None or router.get("controller_auth_enabled") is not True:
            self._authentication_failed()
        reference, key_ids = router.get("controller_auth_ref"), router.get("controller_auth_key_ids")
        if (
            not isinstance(reference, str) or not _REFERENCE.fullmatch(reference)
            or not isinstance(key_ids, list) or not key_ids
            or any(not isinstance(k, str) or not KEY_ID.fullmatch(k) for k in key_ids)
            or len(set(key_ids)) != len(key_ids) or key_id not in key_ids
        ):
            self._authentication_failed()
        try:
            secret = controller_secret(router, key_id, self.config)
        except (APICredentialError, OSError, KeyError):
            self._authentication_failed()
        if not 32 <= len(secret) <= 4096:
            self._authentication_failed()
        try:
            expected = sign_routeros_request(secret, raw, key_id, path)
        except ProtocolError:
            self._authentication_failed()
        if not hmac.compare_digest(signature, expected):
            self._authentication_failed()
        age = now.timestamp() - payload["timestamp"]
        if age > self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120):
            self._authentication_failed("expired_request")
        if age < -self.config.get("ROUTER_CLOCK_SKEW_SECONDS", 30):
            self._authentication_failed("future_request")
        return router

    def authenticate(self, payload, raw, key_id, signature, path, now):
        """Verify V2 credentials/freshness without issuing a poll or receipt.

        The caller validates its own strict schema and consumes its nonce.
        """
        return self._authenticate(payload, raw, key_id, signature, path, now)

    def handle(
        self, raw: bytes, key_id: str, signature: str, source: str,
        request_type: str = "poll", now: datetime | None = None, count_attempt: bool = True,
    ) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise PollError("Controller time is unavailable.", 503, "clock_unavailable")
        now = now.astimezone(UTC)
        if count_attempt:
            RouterPollService(self.storage, self.config).check_rate_limit(source, now)
        try:
            payload = parse_routeros_request(raw, request_type)
        except ProtocolError as exc:
            self.storage.append_activity("security", "Invalid RouterOS request rejected.")
            raise PollError("Invalid router request.", 400, "invalid_request") from exc
        path = ROUTEROS_POLL_PATH if request_type == "poll" else ROUTEROS_ACK_PATH
        router = self._authenticate(payload, raw, key_id, signature, path, now)
        issued_unix = int(now.timestamp())
        expires_unix = issued_unix + self.config.get("ROUTER_RESPONSE_TTL_SECONDS", 60)
        issued_at = _time(datetime.fromtimestamp(issued_unix, UTC))
        response = {
            "protocol_version": "2.0", "router_id": router["router_id"],
            "request_id": payload["request_id"], "response_id": str(uuid4()),
            "status": "authenticated" if request_type == "poll" else "receipt_recorded",
            "mode": "dry_run", "action": "none", "configuration": {},
            "reason": "optimization_unavailable" if request_type == "poll" else "receipt_recorded",
            "issued_at": issued_at, "expires_at": _time(datetime.fromtimestamp(expires_unix, UTC)),
            "issued_at_unix": issued_unix, "expires_at_unix": expires_unix,
            "poll_after_seconds": self.config.get("ROUTER_POLL_INTERVAL", 60),
        }
        if request_type == "ack":
            response["acknowledged_response_id"] = payload["response_id"]
        validate_routeros_response(response, request_type)
        expiry = datetime.fromtimestamp(payload["timestamp"] + self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120), UTC)

        def accept(state):
            seen = [item for item in state["seen_requests"] if parse_utc_timestamp(item["expires_at"]) >= now]
            if any(item["router_id"] == router["router_id"] and item["request_id"] == payload["request_id"] for item in seen):
                raise PollError("This router request has already been accepted.", 409, "replayed_request")
            if len(seen) >= MAX_ROUTEROS_RECORDS:
                raise PollError("Router request capacity is temporarily unavailable.", 503, "request_capacity")
            issued = [item for item in state["issued_responses"] if parse_utc_timestamp(item["expires_at"]) > now]
            record = state["routers"].get(router["router_id"], {
                "last_response_id": None, "last_response_issued_at": None,
                "last_response_expires_at": None, "last_received_response_id": None,
                "last_received_at": None,
            })
            if request_type == "poll":
                if len(issued) >= MAX_ROUTEROS_RECORDS:
                    raise PollError("Router response capacity is temporarily unavailable.", 503, "response_capacity")
                issued.append({
                    "router_id": router["router_id"], "request_id": payload["request_id"],
                    "response_id": response["response_id"], "issued_at": response["issued_at"],
                    "expires_at": response["expires_at"], "received_at": None,
                })
                record.update(last_response_id=response["response_id"], last_response_issued_at=issued_at,
                              last_response_expires_at=response["expires_at"])
            else:
                acknowledged = next((item for item in issued if item["router_id"] == router["router_id"]
                                     and item["response_id"] == payload["response_id"]), None)
                if acknowledged is None:
                    raise PollError("The referenced response is unavailable for acknowledgement.", 409, "unknown_response")
                if acknowledged["received_at"] is None:
                    acknowledged["received_at"] = issued_at
                previous_id = record["last_received_response_id"]
                previous_index = next((index for index, item in enumerate(issued)
                                       if item["router_id"] == router["router_id"]
                                       and item["response_id"] == previous_id), None)
                acknowledged_index = issued.index(acknowledged)
                newer_known_receipt = previous_index is not None and acknowledged_index > previous_index
                if previous_id is not None and previous_index is None:
                    # After pruning, advance only when issue time proves this
                    # response is newer than the previously recorded receipt.
                    newer_known_receipt = (
                        parse_utc_timestamp(acknowledged["issued_at"])
                        > parse_utc_timestamp(record["last_received_at"])
                    )
                # Keep the newest issued response known to be received. An
                # out-of-order or fresh duplicate ACK still confirms its own
                # response, but must not rewind this per-router summary. List
                # order also distinguishes polls issued in the same second.
                if (
                    previous_id is None or payload["response_id"] == record["last_response_id"]
                    or (previous_id != record["last_response_id"] and newer_known_receipt)
                ):
                    record.update(last_received_response_id=payload["response_id"],
                                  last_received_at=acknowledged["received_at"])
            seen.append({"router_id": router["router_id"], "request_id": payload["request_id"], "expires_at": _time(expiry)})
            record.update(last_authenticated_at=issued_at, last_request_at=issued_at,
                          mode="dry_run", last_request_type=request_type)
            state["routers"][router["router_id"]] = record
            state["seen_requests"], state["issued_responses"] = seen, issued
            return state

        try:
            self.storage.update_json("router_communication_v2.json", accept)
        except PollError as exc:
            self.storage.append_activity("security", "RouterOS request rejected.", {
                "router_id": router["router_id"], "reason": exc.code,
            })
            raise
        message = "RouterOS no-action response issued." if request_type == "poll" else "RouterOS response receipt recorded."
        self.storage.append_activity("communication", message, {
            "router_id": router["router_id"], "request_type": request_type,
            "response_id": payload["response_id"] if request_type == "ack" else response["response_id"],
            "mode": "dry_run",
        })
        return response
