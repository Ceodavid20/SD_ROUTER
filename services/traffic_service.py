"""Authenticated, opt-in outbound telemetry. This service never contacts routers."""

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from services.json_storage import StorageService
from services.controller_status_service import _authorization_enabled
from services.router_communication_state import MAX_REPLAY_RECORDS
from services.router_poll_service import PollError, RouterPollService
from services.router_protocol import ProtocolError, parse_utc_timestamp, utc_text
from services.routeros_poll_service import RouterOSPollService
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, _uuid4
from services.traffic_protocol import parse_traffic_request, validate_interface
from services.traffic_state import TRAFFIC_DOCUMENT


_AUTHORIZATION_FIELDS = (
    "controller_auth_enabled", "controller_auth_ref", "controller_auth_key_ids",
    "monitoring_enabled", "interface_name", "monitoring_generation",
)


def stale_after_seconds(settings: Mapping[str, Any]) -> int:
    return max(180, 3 * settings["monitoring_interval_seconds"])


def read_traffic_status(
    storage: StorageService, config: Mapping[str, Any], routers, *, now: datetime | None = None,
) -> dict[str, dict[str, Any]]:
    """Project known fields only; a stale/disabled sample is never a live rate."""
    return project_traffic_status(
        storage.read_json(TRAFFIC_DOCUMENT), storage.read_json("automation_settings.json"),
        config, routers, now=now,
    )


def project_traffic_status(state, settings, config, routers, *, now=None):
    """Pure projection also used by a consistent workflow snapshot."""
    now = now or datetime.now(UTC)
    if now.utcoffset() is None:
        raise ValueError("Traffic status requires a timezone-aware clock.")
    stale_after = stale_after_seconds(settings)
    skew = config.get("ROUTER_CLOCK_SKEW_SECONDS", 30)
    if type(skew) is not int or not 0 <= skew <= 86400:
        skew = 30
    summaries = {}
    for router in routers:
        interface = router.get("interface_name")
        try:
            validate_interface(interface)
            generation = router.get("monitoring_generation")
            if generation is not None:
                _uuid4(generation)
            configured = True
        except ProtocolError:
            interface, configured = None, False
        record = state["routers"].get(router["router_id"])
        same_series = bool(record and configured and record["interface"] == interface
                           and record["generation"] == router.get("monitoring_generation"))
        enabled = router.get("monitoring_enabled") is True
        if not enabled:
            status = "disabled"
        elif not configured:
            status = "not_configured"
        elif not _authorization_enabled(router):
            status = "authentication_required"
        elif not same_series:
            status = "awaiting"
        elif not -skew <= now.timestamp() - record["timestamp"] <= stale_after:
            status = "stale"
        else:
            status = record["sample_state"]
        summaries[router["router_id"]] = {
            "enabled": enabled, "state": status, "interface": interface,
            "last_sample_at": utc_text(datetime.fromtimestamp(record["timestamp"], UTC)) if same_series else None,
            "last_received_at": record["last_received_at"] if same_series else None,
            "tx_mbps": record["tx_mbps"] if status == "measured" else None,
            "stale_after_seconds": stale_after,
        }
    return summaries


class TrafficService:
    def __init__(self, storage: StorageService, config: Mapping[str, Any]) -> None:
        self.storage, self.config = storage, config

    def check_rate_limit(self, source: str, now: datetime | None = None) -> None:
        # Independent budget: telemetry cannot spend polling/receipt quota.
        RouterPollService(self.storage, self.config).check_rate_limit(
            source, now, state_document=TRAFFIC_DOCUMENT,
        )

    def handle(
        self, raw: bytes, key_id: str, signature: str, source: str, *,
        now: datetime | None = None, count_attempt: bool = True,
    ) -> dict[str, Any]:
        now = now or datetime.now(UTC)
        if not isinstance(now, datetime) or now.utcoffset() is None:
            raise PollError("Controller time is unavailable.", 503, "clock_unavailable")
        now = now.astimezone(UTC)
        if count_attempt:
            self.check_rate_limit(source, now)
        try:
            payload = parse_traffic_request(raw)
        except ProtocolError as exc:
            self.storage.append_activity("security", "Invalid traffic request rejected.")
            raise PollError("Invalid traffic request.", 400, "invalid_request") from exc
        router = RouterOSPollService(self.storage, self.config).authenticate(
            payload, raw, key_id, signature, ROUTEROS_TRAFFIC_PATH, now,
        )
        result = {}

        def accept(state, routers, settings):
            current = next((item for item in routers if item["router_id"] == payload["router_id"]), None)
            if current is None or any(
                (type(current.get(key)), current.get(key)) != (type(router.get(key)), router.get(key))
                for key in _AUTHORIZATION_FIELDS
            ):
                raise PollError("Router monitoring authorization changed; retry with current settings.",
                                409, "authorization_changed")
            if current.get("monitoring_enabled") is not True:
                raise PollError("Traffic monitoring is disabled for this router.", 403, "monitoring_disabled")
            interface = current.get("interface_name")
            generation = current.get("monitoring_generation")
            try:
                validate_interface(interface)
                if generation is not None:
                    _uuid4(generation)
            except ProtocolError as exc:
                raise PollError("Router monitoring configuration is invalid.", 403, "monitoring_configuration") from exc
            if payload["interface"] != interface:
                raise PollError("Traffic must use the configured outbound interface.", 403, "interface_mismatch")
            seen = [entry for entry in state["seen_requests"]
                    if parse_utc_timestamp(entry["expires_at"]) >= now]
            if any(entry["router_id"] == payload["router_id"] and entry["request_id"] == payload["request_id"]
                   for entry in seen):
                raise PollError("This traffic request has already been accepted.", 409, "replayed_request")
            if len(seen) >= MAX_REPLAY_RECORDS:
                raise PollError("Traffic request capacity is temporarily unavailable.", 503, "request_capacity")
            previous = state["routers"].get(payload["router_id"])
            same_series = previous and previous["interface"] == interface and previous["generation"] == generation
            rate, interval, sample_state = None, None, "baseline"
            if same_series:
                interval = payload["timestamp"] - previous["timestamp"]
                if interval <= 0:
                    raise PollError("Traffic timestamps must increase.", 409, "out_of_order_sample")
                if payload["tx_octets"] < previous["tx_octets"]:
                    sample_state = "counter_reset"
                elif interval > stale_after_seconds(settings):
                    sample_state = "gap_reset"
                else:
                    rate = (payload["tx_octets"] - previous["tx_octets"]) * 8 / interval / 1_000_000
                    sample_state = "measured"
            sampled_at = datetime.fromtimestamp(payload["timestamp"], UTC)
            series_id = previous.get("series_id") if same_series else None
            if sample_state != "measured" or series_id is None:
                series_id = str(uuid4())
            state["routers"][payload["router_id"]] = {
                "interface": interface, "generation": generation,
                "timestamp": payload["timestamp"], "tx_octets": payload["tx_octets"],
                "last_received_at": utc_text(now), "tx_mbps": rate, "sample_state": sample_state,
                "series_id": series_id,
            }
            seen.append({
                "router_id": payload["router_id"], "request_id": payload["request_id"],
                "expires_at": utc_text(sampled_at + timedelta(
                    seconds=self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120))),
            })
            state["seen_requests"] = seen
            reading = None if rate is None else {
                "protocol_version": "2.0", "router_id": payload["router_id"],
                "request_id": payload["request_id"], "interface": interface,
                "timestamp": utc_text(sampled_at), "tx_octets": payload["tx_octets"],
                "tx_mbps": rate, "interval_seconds": interval,
                "series_id": series_id,
            }
            result.update(
                protocol_version="2.0", router_id=payload["router_id"], request_id=payload["request_id"],
                status="traffic_recorded", sample_state=sample_state, tx_mbps=rate,
                mode="dry_run", action="none", configuration={},
            )
            return state, reading

        self.storage.commit_traffic(accept)
        return result
