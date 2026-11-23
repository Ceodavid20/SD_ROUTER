"""Read controller check-ins without contacting devices or altering their state."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
import re
from typing import Any

from services.json_storage import StorageService
from services.router_protocol import KEY_ID, parse_utc_timestamp


_REFERENCE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
MINIMUM_STALE_SECONDS = 180


def _authorization_enabled(router: Mapping[str, Any]) -> bool:
    reference, key_ids = router.get("controller_auth_ref"), router.get("controller_auth_key_ids")
    return (
        router.get("controller_auth_enabled") is True
        and isinstance(reference, str) and bool(_REFERENCE.fullmatch(reference))
        and isinstance(key_ids, list) and bool(key_ids)
        and all(isinstance(value, str) and KEY_ID.fullmatch(value) for value in key_ids)
        and len(set(key_ids)) == len(key_ids)
    )


def read_controller_status(
    storage: StorageService, config: Mapping[str, Any], routers: Sequence[Mapping[str, Any]],
    *, now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Project only known status fields from the storage service's validated JSON.

    A recent authenticated request proves a check-in. A receipt proves that a
    particular response was acknowledged; neither means routing was applied.
    Historical metadata remains visible after authorization is disabled.
    """
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("Controller status requires a timezone-aware clock.")
    current = current.astimezone(UTC)
    interval = config.get("ROUTER_POLL_INTERVAL", 60)
    if type(interval) is not int or not 1 <= interval <= 86400:
        interval = 60
    stale_after = max(3 * interval, MINIMUM_STALE_SECONDS)
    skew = config.get("ROUTER_CLOCK_SKEW_SECONDS", 30)
    if type(skew) is not int or not 0 <= skew <= 86400:
        skew = 30
    # read_json validates schemas and timestamps. Invalid storage fails closed;
    # it must never be presented as a successful or fabricated check-in.
    records_v1 = storage.read_json("router_communication.json")["routers"]
    state_v2 = storage.read_json("router_communication_v2.json")
    records_v2 = state_v2["routers"]
    confirmed_receipts = {
        (record["router_id"], record["response_id"]): record["received_at"]
        for record in state_v2["issued_responses"] if record["received_at"] is not None
    }
    summaries = {}
    for router in routers:
        router_id = router["router_id"]
        records = [
            (version, records[router_id])
            for version, records in (("1.0", records_v1), ("2.0", records_v2))
            if router_id in records
        ]
        latest = max(
            records, key=lambda item: (parse_utc_timestamp(item[1]["last_authenticated_at"]), item[0]),
            default=None,
        )
        issued = [(version, record) for version, record in records if record.get("last_response_id")]
        latest_response = max(
            issued, key=lambda item: (parse_utc_timestamp(item[1]["last_response_issued_at"]), item[0]),
            default=None,
        )
        last_auth = latest[1]["last_authenticated_at"] if latest else None
        if not _authorization_enabled(router):
            state = "disabled"
        elif last_auth is None:
            state = "awaiting"
        else:
            age = (current - parse_utc_timestamp(last_auth)).total_seconds()
            state = "authenticated" if -skew <= age <= stale_after else "stale"
        received = records_v2.get(router_id, {})
        response_id = latest_response[1]["last_response_id"] if latest_response else None
        response_version = latest_response[0] if latest_response else None
        receipt_id = received.get("last_received_response_id")
        matches_latest = bool(
            response_version == "2.0" and response_id
            and (response_id == receipt_id or (router_id, response_id) in confirmed_receipts)
        )
        if latest_response is None:
            receipt_state = "not_issued"
        elif response_version == "1.0":
            receipt_state = "not_supported"
        elif matches_latest:
            receipt_state = "received"
        elif receipt_id is not None:
            receipt_state = "previous_response"
        else:
            receipt_state = "awaiting"
        summaries[router_id] = {
            "state": state, "last_authenticated_at": last_auth,
            "protocol_version": latest[0] if latest else None,
            "last_response_id": response_id,
            "last_response_issued_at": latest_response[1]["last_response_issued_at"] if latest_response else None,
            "last_response_protocol_version": response_version,
            "last_received_response_id": receipt_id,
            "last_received_at": received.get("last_received_at"),
            "latest_response_received": matches_latest,
            "receipt_state": receipt_state, "stale_after_seconds": stale_after,
        }
    return summaries
