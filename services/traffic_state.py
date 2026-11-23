"""Validated counter baselines, bounded replay/rate state and history outbox."""

from typing import Any
from datetime import UTC, datetime

from services.json_storage import StorageService, ValidationError, _SEGMENT
from services.router_communication_state import validate_communication_state
from services.router_protocol import ProtocolError, parse_utc_timestamp
from services.routeros_protocol import _identity, _unix, _uuid4
from services.traffic_protocol import validate_interface


TRAFFIC_DOCUMENT = "router_traffic_v2.json"
SAMPLE_STATES = {"baseline", "measured", "counter_reset", "gap_reset"}
COUNTER_FIELDS = {
    "interface", "generation", "timestamp", "tx_octets",
    "last_received_at", "tx_mbps", "sample_state",
}
READING_FIELDS = {
    "protocol_version", "router_id", "request_id", "interface", "timestamp",
    "tx_octets", "tx_mbps", "interval_seconds",
}


def validate_traffic_state(state: Any) -> None:
    if (
        not isinstance(state, dict)
        or set(state) != {"schema_version", "routers", "seen_requests", "rate_limits", "pending_reading"}
        or type(state["schema_version"]) is not int or state["schema_version"] != 1
        or not isinstance(state["routers"], dict)
    ):
        raise ValidationError("Invalid traffic state.")
    validate_communication_state({
        "schema_version": 1, "routers": {},
        "seen_requests": state["seen_requests"], "rate_limits": state["rate_limits"],
    })
    try:
        for router_id, record in state["routers"].items():
            _identity(router_id)
            if not isinstance(record, dict) or set(record) not in (COUNTER_FIELDS, COUNTER_FIELDS | {"series_id"}):
                raise ValidationError("Invalid traffic counter record.")
            if "series_id" in record:
                _uuid4(record["series_id"])
            validate_interface(record["interface"])
            if record["generation"] is not None:
                _uuid4(record["generation"])
            _unix(record["timestamp"])
            try:
                datetime.fromtimestamp(record["timestamp"], UTC)
            except (ValueError, OverflowError, OSError) as exc:
                raise ValidationError("Invalid stored sample time.") from exc
            parse_utc_timestamp(record["last_received_at"])
            if type(record["tx_octets"]) is not int or not 0 <= record["tx_octets"] < 2**64:
                raise ValidationError("Invalid stored TX counter.")
            if not isinstance(record["sample_state"], str) or record["sample_state"] not in SAMPLE_STATES:
                raise ValidationError("Invalid traffic sample state.")
            if record["sample_state"] == "measured":
                StorageService._validate_traffic({
                    "router_id": router_id, "interface": record["interface"],
                    "timestamp": record["last_received_at"], "tx_mbps": record["tx_mbps"],
                })
            elif record["tx_mbps"] is not None:
                raise ValidationError("A counter baseline cannot have a measured rate.")
        pending = state["pending_reading"]
        if pending is not None:
            if not isinstance(pending, dict) or set(pending) != {"file", "offset", "reading"}:
                raise ValidationError("Invalid pending traffic write.")
            if not isinstance(pending["file"], str) or not _SEGMENT.fullmatch(pending["file"]):
                raise ValidationError("Invalid pending traffic segment.")
            if type(pending["offset"]) is not int or not 0 <= pending["offset"] <= 8 * 1024 * 1024:
                raise ValidationError("Invalid pending traffic offset.")
            reading = pending["reading"]
            if not isinstance(reading, dict) or set(reading) not in (READING_FIELDS, READING_FIELDS | {"series_id"}):
                raise ValidationError("Invalid pending traffic reading.")
            StorageService._validate_traffic(reading)
            _identity(reading["router_id"])
            _uuid4(reading["request_id"])
            if "series_id" in reading:
                _uuid4(reading["series_id"])
            validate_interface(reading["interface"])
            if (reading["protocol_version"] != "2.0" or "tx_octets" not in reading
                    or type(reading["interval_seconds"]) is not int
                    or not 1 <= reading["interval_seconds"] <= 3 * 86400):
                raise ValidationError("Invalid pending traffic interval.")
            if not pending["file"].startswith("traffic_segments/traffic-" + reading["timestamp"][:10] + "-"):
                raise ValidationError("Pending traffic date mismatch.")
            record = state["routers"].get(reading["router_id"])
            sampled_at = parse_utc_timestamp(reading["timestamp"])
            if (record is None or record["sample_state"] != "measured"
                    or sampled_at.timestamp() != record["timestamp"]
                    or record["interface"] != reading["interface"]
                    or record["tx_octets"] != reading["tx_octets"]
                    or record["tx_mbps"] != reading["tx_mbps"]
                    or record.get("series_id") != reading.get("series_id")
                    or not any(entry["router_id"] == reading["router_id"]
                               and entry["request_id"] == reading["request_id"]
                               for entry in state["seen_requests"])):
                raise ValidationError("Pending traffic is inconsistent with committed state.")
    except ProtocolError as exc:
        raise ValidationError("Invalid traffic metadata.") from exc
