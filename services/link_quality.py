"""Opt-in RTT delay variation, independent of TX counters and optimization.

Jitter here is mean absolute change of adjacent ping RTTs, in milliseconds.
It is explicitly RTT variation, not one-way IPDV or RTP inter-arrival jitter.
"""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
from ipaddress import ip_address, ip_network
import json
import math
import re
from uuid import UUID, uuid4

from services.json_storage import ValidationError
from services.router_protocol import ROUTER_ID, parse_utc_timestamp, utc_text
from services.routeros_api import RouterAPIError
from services.routeros_probe import RouterOSProbeClient, probe_address
from services.router_service import RouterService, RouterValidationError
from services.traffic_service import monitored_interfaces

DOCUMENT = "link_quality.json"
MAX_HISTORY = 500
MAX_TOTAL_SAMPLES = 10_000
STATUSES = {"measured", "partial", "insufficient_replies", "no_replies", "unavailable"}


def summarize(samples):
    if not isinstance(samples, list) or len(samples) != 8 or any(value is not None and
            (type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 60000) for value in samples):
        raise ValueError("Expected eight bounded RTT measurements or missing replies.")
    replies = [value for value in samples if value is not None]
    changes = [abs(right-left) for left, right in zip(samples, samples[1:]) if left is not None and right is not None]
    return {"jitter_ms": math.fsum(changes)/len(changes) if changes else None,
            "mean_rtt_ms": math.fsum(replies)/len(replies) if replies else None,
            "replies": len(replies), "probes_requested": 8, "adjacent_pairs": len(changes),
            "status": "measured" if len(replies) == 8 else "partial" if changes else "insufficient_replies" if replies else "no_replies"}


def _uuid(value):
    try:
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValidationError("Invalid jitter series identity.") from exc


def _validate_quality(state):
    def keys(item, names):
        if not isinstance(item, dict) or set(item) != set(names.split()):
            raise ValidationError("Invalid jitter storage fields.")
    keys(state, "schema_version links")
    if type(state["schema_version"]) is not int or state["schema_version"] != 1 or not isinstance(state["links"], dict) or len(state["links"]) > 2048:
        raise ValidationError("Invalid jitter document.")
    total = 0
    for path_id, entry in state["links"].items():
        if not isinstance(path_id, str) or not ROUTER_ID.fullmatch(path_id):
            raise ValidationError("Invalid jitter path.")
        keys(entry, "fingerprint series_id next_probe_at lease_id lease_until samples")
        if not isinstance(entry["fingerprint"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["fingerprint"]):
            raise ValidationError("Invalid jitter configuration fingerprint.")
        _uuid(entry["series_id"])
        parse_utc_timestamp(entry["next_probe_at"])
        if (entry["lease_id"] is None) != (entry["lease_until"] is None):
            raise ValidationError("Invalid jitter probe lease.")
        if entry["lease_id"] is not None:
            _uuid(entry["lease_id"]); parse_utc_timestamp(entry["lease_until"])
        if not isinstance(entry["samples"], list) or len(entry["samples"]) > MAX_HISTORY:
            raise ValidationError("Invalid jitter history size.")
        total += len(entry["samples"])
        previous = None
        for row in entry["samples"]:
            keys(row, "at series_id router_id interface target status jitter_ms mean_rtt_ms replies probes_requested adjacent_pairs")
            at = parse_utc_timestamp(row["at"])
            if previous is not None and at <= previous:
                raise ValidationError("Jitter timestamps must increase.")
            previous = at
            _uuid(row["series_id"])
            if not isinstance(row["router_id"], str) or not ROUTER_ID.fullmatch(row["router_id"]):
                raise ValidationError("Invalid jitter source identity.")
            from services.traffic_protocol import validate_interface
            validate_interface(row["interface"])
            if probe_address(row["target"]) != row["target"] or row["status"] not in STATUSES:
                raise ValidationError("Invalid jitter target or status.")
            if (type(row["replies"]) is not int or not 0 <= row["replies"] <= 8
                    or type(row["probes_requested"]) is not int or row["probes_requested"] != 8
                    or type(row["adjacent_pairs"]) is not int or not 0 <= row["adjacent_pairs"] <= max(0,row["replies"]-1)):
                raise ValidationError("Invalid jitter probe counts.")
            for key in ("jitter_ms", "mean_rtt_ms"):
                value = row[key]
                if value is not None and (type(value) not in (float,int) or not math.isfinite(value) or not 0 <= value <= 60000):
                    raise ValidationError("Invalid millisecond jitter value.")
            if ((row["jitter_ms"] is None) != (row["adjacent_pairs"] == 0)
                    or (row["mean_rtt_ms"] is None) != (row["replies"] == 0)
                    or (row["status"] == "measured" and (row["replies"] != 8 or row["adjacent_pairs"] != 7))
                    or (row["status"] == "partial" and (not row["adjacent_pairs"] or row["replies"] == 8))
                    or (row["status"] == "insufficient_replies" and (not row["replies"] or row["adjacent_pairs"]))
                    or (row["status"] in ("unavailable", "no_replies") and row["replies"])):
                raise ValidationError("Jitter values do not match their evidence.")
    if total > MAX_TOTAL_SAMPLES:
        raise ValidationError("Jitter retention capacity exceeded.")


def validate_quality(state):
    try:
        _validate_quality(state)
    except (ValueError, TypeError, KeyError) as exc:
        raise ValidationError("Invalid jitter monitoring state.") from exc


def _fingerprint(path, router, config):
    return hashlib.sha256(json.dumps({"path": {key: path.get(key) for key in (
        "path_id", "aggregation_router_id", "carrier_router_id", "aggregation_interface", "relationship_status", "jitter_enabled", "jitter_target")},
        "router": {key: router.get(key) for key in ("router_id", "active", "ip_address", "api_port", "api_tls",
            "api_ca_file", "credential_ref", "api_credentials_source", "monitoring_enabled", "monitoring_generation", "monitoring_interfaces", "interface_name")},
        "ca": str(config.get("ROUTER_CA_FILE") or ""), "environment": config.get("ENVIRONMENT", "development")},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _selected(inputs, path_id):
    path = next((p for p in inputs["routing_paths.json"]["paths"] if p["path_id"] == path_id), None)
    if not path or path.get("live_sampling_enabled") is True or path.get("jitter_enabled") is not True or path["relationship_status"] != "operator_selected":
        return None
    router = next((r for r in inputs["routers.json"] if r["router_id"] == path["aggregation_router_id"]), None)
    if not router or router.get("active", True) is not True or router.get("monitoring_enabled") is not True:
        return None
    try:
        if path["aggregation_interface"] not in monitored_interfaces(router):
            return None
    except ValueError:
        return None
    return path, router


class LinkQualityService:
    def __init__(self, storage, config):
        self.storage, self.config = storage, config

    def collect(self, path_id, *, now=None):
        """Reserve before I/O; discard an in-flight result after any relevant edit."""
        started = now or datetime.now(UTC)
        interval = self.config.get("JITTER_INTERVAL_SECONDS", 60)
        timeout = self.config.get("JITTER_API_TIMEOUT_SECONDS", 10)
        claimed = {}
        def claim(inputs, state):
            selected = _selected(inputs, path_id)
            if not selected:
                return
            path, router = selected
            fingerprint = _fingerprint(path, router, self.config)
            old = state["links"].get(path_id)
            if old and old["fingerprint"] == fingerprint and (started < parse_utc_timestamp(old["next_probe_at"])
                    or old["lease_until"] and started < parse_utc_timestamp(old["lease_until"])):
                return
            entry = {"fingerprint": fingerprint, "series_id": str(uuid4()), "samples": old["samples"] if old else []} if not old or old["fingerprint"] != fingerprint else old
            token = str(uuid4())
            entry.update(next_probe_at=utc_text(started+timedelta(seconds=interval)), lease_id=token,
                         lease_until=utc_text(started+timedelta(seconds=timeout+5)))
            state["links"][path_id] = entry
            claimed.update(path=deepcopy(path), router=deepcopy(router), fingerprint=fingerprint, token=token)
        self.storage.update_quality(claim)
        if not claimed:
            return None
        path, router = claimed["path"], claimed["router"]
        values = {**summarize([None]*8), "status": "unavailable"}
        try:
            target = probe_address(path["jitter_target"])
            if not any(ip_address(target) in ip_network(network) for network in self.config.get("ROUTER_ALLOWED_NETWORKS", [])):
                raise ValueError("Jitter target is outside the approved networks.")
            username, password, connection = RouterService(self.storage, self.config)._preflight(router)
            # Jitter never creates a new plaintext management exception.
            if connection["api_tls"] is not True:
                raise ValueError("Verified API-SSL is required for RTT probes.")
            samples = RouterOSProbeClient(connection["ip_address"], connection["api_port"], username, password,
                tls=True, timeout=timeout, ca_file=router.get("api_ca_file") or self.config.get("ROUTER_CA_FILE")).ping(target, path["aggregation_interface"])
            values = summarize(samples)
        except (RouterValidationError, RouterAPIError, OSError, ValueError):
            # No device traps, credentials, raw replies or destinations in logs.
            pass
        completed = started if now is not None else datetime.now(UTC)
        recorded = {}
        def commit(inputs, state):
            entry = state["links"].get(path_id)
            if not entry or entry["lease_id"] != claimed["token"]:
                return
            entry.update(lease_id=None, lease_until=None)
            selected = _selected(inputs, path_id)
            if (not selected or _fingerprint(*selected, self.config) != claimed["fingerprint"]
                    or entry["samples"] and completed <= parse_utc_timestamp(entry["samples"][-1]["at"])):
                return
            if values["status"] != "measured" or entry["samples"] and entry["samples"][-1]["status"] != "measured":
                entry["series_id"] = str(uuid4())
            sample = {"at": utc_text(completed), "series_id": entry["series_id"], "router_id": router["router_id"],
                "interface": path["aggregation_interface"], "target": path["jitter_target"], **values}
            entry["samples"] = [*entry["samples"][-(MAX_HISTORY-1):], sample]
            while sum(len(item["samples"]) for item in state["links"].values()) > MAX_TOTAL_SAMPLES:
                oldest = min((item for item in state["links"].values() if item["samples"]), key=lambda item: item["samples"][0]["at"])
                oldest["samples"].pop(0)
            recorded.update(sample)
        self.storage.update_quality(commit)
        return recorded or None


def quality_view(path, router, state, config, now):
    entry = state["links"].get(path["path_id"])
    enabled = path.get("jitter_enabled") is True
    active = enabled and router.get("active", True) is True and router.get("monitoring_enabled") is True
    matches = bool(entry and entry["fingerprint"] == _fingerprint(path, router, config))
    samples = entry["samples"] if entry else []
    latest = samples[-1] if samples and matches else None
    interval = config.get("JITTER_INTERVAL_SECONDS", 60)
    fresh = latest and 0 <= (now-parse_utc_timestamp(latest["at"])).total_seconds() <= interval*3
    status = ("disabled" if not active else "awaiting" if not latest else "stale" if not fresh else latest["status"])
    return {"enabled": enabled, "state": status, "target": path.get("jitter_target"),
        "interval_seconds": interval, "current_jitter_ms": latest["jitter_ms"] if fresh and active else None,
        "sampled_at": latest["at"] if latest else None,
        "points": [{key: row[key] for key in ("at", "jitter_ms", "series_id", "router_id", "interface", "target", "status", "replies", "probes_requested")}
                   for row in samples]}
