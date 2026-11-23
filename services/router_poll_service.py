"""Authenticated device polling, replay protection, and no-action responses.

This service never contacts routers, executes commands, or fabricates an
optimization result. The optimizer adapter is intentionally absent until the
actual existing optimization engine is available.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import uuid4

from services.json_storage import StorageService
from services.router_auth_service import AuthenticationError, RouterAuthService
from services.router_communication_state import MAX_RATE_BUCKETS, MAX_REPLAY_RECORDS
from services.router_protocol import parse_utc_timestamp, utc_text, validate_poll_response


class PollError(ValueError):
    def __init__(self, message: str, status: int, code: str) -> None:
        super().__init__(message)
        self.status, self.code = status, code


class RouterPollService:
    def __init__(self, storage: StorageService, config: Mapping[str, Any]) -> None:
        self.storage, self.config = storage, config

    def check_rate_limit(self, source: str, now: datetime | None = None) -> None:
        """Count attempts before auth. Persist limits across processes/restarts."""
        now = now or datetime.now(UTC)
        maximum = self.config.get("ROUTER_RATE_LIMIT_ATTEMPTS", 30)
        window = self.config.get("ROUTER_RATE_LIMIT_WINDOW_SECONDS", 60)
        digest = sha256(source.encode("utf-8")).hexdigest()
        result = {"allowed": False, "audit": False}

        def count(state: dict[str, Any]) -> dict[str, Any]:
            buckets = {
                key: value for key, value in state["rate_limits"].items()
                if (now - parse_utc_timestamp(value["window_started_at"])).total_seconds() < window
            }
            bucket = buckets.get(digest)
            if bucket is None:
                if len(buckets) >= MAX_RATE_BUCKETS:
                    state["rate_limits"] = buckets
                    return state
                bucket = {"window_started_at": utc_text(now), "count": 0}
                buckets[digest] = bucket
            previous = bucket["count"]
            bucket["count"] = min(previous + 1, maximum + 1)
            result["allowed"] = bucket["count"] <= maximum
            result["audit"] = previous == maximum
            state["rate_limits"] = buckets
            return state

        self.storage.update_json("router_communication.json", count)
        if not result["allowed"]:
            if result["audit"]:
                self.storage.append_activity("security", "Router polling rate limit reached.")
            raise PollError("Too many router requests. Try again later.", 429, "rate_limited")

    def poll(
        self, payload: dict[str, Any], raw: bytes, key_id: str,
        signature: str, source: str, *, now: datetime | None = None,
        count_attempt: bool = True,
    ) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        # HTTP controller counts before parsing, including malformed requests.
        # Direct service consumers count here by default.
        if count_attempt:
            self.check_rate_limit(source, now)
        try:
            router = RouterAuthService(self.storage, self.config).authenticate(
                payload, raw, key_id, signature, now,
            )
        except AuthenticationError as exc:
            # Never log raw bodies, headers, signatures, secret values, or
            # attacker-supplied identities. Bounded attempts limit audit volume.
            self.storage.append_activity(
                "security", "Router authentication failed.", {"reason": exc.code},
            )
            raise PollError("Router authentication failed.", 401, "authentication_failed") from exc
        issued = utc_text(now)
        response = {
            "protocol_version": "1.0", "router_id": router["router_id"],
            "request_id": payload["request_id"], "response_id": str(uuid4()),
            "status": "authenticated", "mode": "dry_run", "action": "none",
            "configuration": {}, "reason": "optimization_unavailable",
            "issued_at": issued,
            "expires_at": utc_text(now + timedelta(seconds=self.config.get("ROUTER_RESPONSE_TTL_SECONDS", 60))),
            "poll_after_seconds": self.config.get("ROUTER_POLL_INTERVAL", 60),
        }
        validate_poll_response(response)

        def accept(state: dict[str, Any]) -> dict[str, Any]:
            # Keep every accepted nonce until its signed timestamp is no longer
            # acceptable; using only time-since-receipt would permit future-date replay.
            seen = [entry for entry in state["seen_requests"]
                    if parse_utc_timestamp(entry["expires_at"]) >= now]
            if any(entry["router_id"] == router["router_id"]
                   and entry["request_id"] == payload["request_id"] for entry in seen):
                raise PollError("This router request has already been accepted.", 409, "replayed_request")
            if len(seen) >= MAX_REPLAY_RECORDS:
                raise PollError("Router request capacity is temporarily unavailable.", 503, "request_capacity")
            seen.append({
                "router_id": router["router_id"], "request_id": payload["request_id"],
                "expires_at": utc_text(parse_utc_timestamp(payload["timestamp"]) + timedelta(
                    seconds=self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120),
                )),
            })
            state["seen_requests"] = seen
            state["routers"][router["router_id"]] = {
                "last_request_at": issued, "last_authenticated_at": issued,
                "last_response_id": response["response_id"],
                "last_response_issued_at": issued, "mode": "dry_run",
            }
            return state

        # Nonce consumption and accepted check-in are one locked JSON update.
        try:
            self.storage.update_json("router_communication.json", accept)
        except PollError as exc:
            if exc.code == "replayed_request":
                self.storage.append_activity("security", "Replayed router polling request rejected.", {
                    "router_id": router["router_id"],
                })
            raise
        self.storage.append_activity("communication", "Router authenticated; no-action response issued.", {
            "router_id": router["router_id"], "response_id": response["response_id"], "mode": "dry_run",
        })
        return response
