"""Opt-in, bounded high-resolution TX/RTT history; no routing or device writes.

The signed device history remains the optimizer's input. This independent live
cache never impersonates a device, consumes its nonce budget or alters baselines.
"""
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
from ipaddress import ip_address, ip_network
import json
import math
import re
from uuid import uuid4

from services.json_storage import ValidationError
from services.link_quality import _uuid, summarize, validate_quality
from services.router_protocol import ROUTER_ID, parse_utc_timestamp, utc_text
from services.router_service import RouterService, RouterValidationError
from services.routeros_api import RouterAPIError
from services.routeros_probe import RouterOSProbeClient, probe_address
from services.traffic_protocol import validate_interface
from services.traffic_service import monitored_interfaces

DOCUMENT = "live_samples.json"
MAX_POINTS = 600
MAX_TOTAL_POINTS = 12_000
STATES = {"baseline", "measured", "counter_reset", "gap_reset", "unavailable"}


class LiveSampleClient(RouterOSProbeClient):
    def read_live(self, channels):
        if not isinstance(channels, dict) or not 1 <= len(channels) <= 16:
            raise ValueError("Select one to sixteen authorized TX interfaces.")
        for interface, target in channels.items():
            validate_interface(interface)
            if target is not None:
                probe_address(target)
        def read():
            result = {}
            for interface in channels:
                rows = self._talk(["/interface/print", "=.proplist=.id,name,tx-byte", "?name=" + interface])
                if (len(rows) != 1 or rows[0].get("name") != interface
                        or not re.fullmatch(r"[0-9]{1,20}", rows[0].get("tx-byte", ""))
                        or int(rows[0]["tx-byte"]) >= 2**64):
                    raise RouterAPIError("Router did not return the selected TX counter.")
                result[interface] = {"at": utc_text(datetime.now(UTC)), "tx_octets": int(rows[0]["tx-byte"]), "quality": None}
            for interface, target in channels.items():
                if target is None:
                    continue
                try:
                    rows = self._talk(["/ping", "=address=" + target, "=interface=" + interface, "=count=8", "=interval=50ms"])
                    values = summarize(self.samples(rows))
                except RouterAPIError:
                    values = {**summarize([None] * 8), "status": "unavailable"}
                result[interface]["quality"] = {"at": utc_text(datetime.now(UTC)), "target": target, **values}
            return result
        return self._read(read)


def selected_paths(inputs, router_id):
    router = next((r for r in inputs["routers.json"] if r["router_id"] == router_id), None)
    if not router or router.get("active", True) is not True or router.get("monitoring_enabled") is not True:
        return [], router
    try:
        interfaces = monitored_interfaces(router)
    except ValueError:
        return [], router
    all_paths = inputs["routing_paths.json"]["paths"]
    counts = Counter((p["aggregation_router_id"], p["aggregation_interface"]) for p in all_paths if p["relationship_status"] == "operator_selected")
    paths = [p for p in all_paths if p["aggregation_router_id"] == router_id
        and p.get("monitor_router_id") == router_id and p.get("live_sampling_enabled") is True
        and p["relationship_status"] == "operator_selected" and p["aggregation_interface"] in interfaces
        and counts[(router_id, p["aggregation_interface"])] == 1]
    return sorted(paths, key=lambda p: p["path_id"]), router


def fingerprint(paths, router, config):
    values = {"router": {k: router.get(k) for k in ("router_id", "active", "ip_address", "api_port", "api_tls", "api_ca_file",
        "credential_ref", "api_credentials_source", "monitoring_enabled", "monitoring_generation", "monitoring_interfaces", "interface_name")},
        "paths": [{k: p.get(k) for k in ("path_id", "aggregation_interface", "carrier_router_id", "monitor_router_id", "jitter_enabled", "jitter_target", "live_sampling_enabled")} for p in paths],
        "ca": str(config.get("ROUTER_CA_FILE") or ""), "interval": config.get("LIVE_SAMPLE_INTERVAL_SECONDS", 1),
        "allowed_networks": config.get("ROUTER_ALLOWED_NETWORKS", []),
        "environment": config.get("ENVIRONMENT", "development")}
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_live_samples(state):
    try:
        def fields(value, names):
            if not isinstance(value, dict) or set(value) != set(names.split()):
                raise ValueError
        fields(state, "schema_version routers")
        if type(state["schema_version"]) is not int or state["schema_version"] != 1 or not isinstance(state["routers"], dict) or len(state["routers"]) > 256:
            raise ValueError
        total = 0
        for rid, entry in state["routers"].items():
            if not isinstance(rid, str) or not ROUTER_ID.fullmatch(rid):
                raise ValueError
            fields(entry, "fingerprint next_sample_at lease_id lease_until channels")
            if not isinstance(entry["fingerprint"], str) or not re.fullmatch(r"[a-f0-9]{64}", entry["fingerprint"]):
                raise ValueError
            parse_utc_timestamp(entry["next_sample_at"])
            if (entry["lease_id"] is None) != (entry["lease_until"] is None):
                raise ValueError
            if entry["lease_id"] is not None:
                _uuid(entry["lease_id"]); parse_utc_timestamp(entry["lease_until"])
            if not isinstance(entry["channels"], dict) or not 1 <= len(entry["channels"]) <= 16:
                raise ValueError
            for interface, channel in entry["channels"].items():
                validate_interface(interface)
                fields(channel, "series_id points")
                _uuid(channel["series_id"])
                if not isinstance(channel["points"], list) or len(channel["points"]) > MAX_POINTS:
                    raise ValueError
                total += len(channel["points"])
                previous = None
                quality_rows = []
                for row in channel["points"]:
                    fields(row, "at tx_octets mbps elapsed_seconds state series_id quality")
                    at = parse_utc_timestamp(row["at"])
                    if previous is not None and at <= previous:
                        raise ValueError
                    previous = at
                    _uuid(row["series_id"])
                    if row["state"] not in STATES or (row["tx_octets"] is None) != (row["state"] == "unavailable"):
                        raise ValueError
                    if row["tx_octets"] is not None and (type(row["tx_octets"]) is not int or not 0 <= row["tx_octets"] < 2**64):
                        raise ValueError
                    if row["state"] == "measured":
                        if any(type(row[k]) not in (float, int) or not math.isfinite(row[k]) for k in ("mbps", "elapsed_seconds")) or row["mbps"] < 0 or not 0 < row["elapsed_seconds"] <= 180:
                            raise ValueError
                    elif row["mbps"] is not None or row["elapsed_seconds"] is not None:
                        raise ValueError
                    if row["quality"] is not None:
                        q = row["quality"]
                        fields(q, "at target jitter_ms mean_rtt_ms replies probes_requested adjacent_pairs status")
                        if not 0 <= (parse_utc_timestamp(q["at"]) - at).total_seconds() <= 30:
                            raise ValueError
                        quality_rows.append({**q, "series_id": row["series_id"], "router_id": rid, "interface": interface})
                for offset in range(0, len(quality_rows), 500):
                    validate_quality({"schema_version": 1, "links": {"quality": {"fingerprint": entry["fingerprint"],
                        "series_id": channel["series_id"], "next_probe_at": entry["next_sample_at"], "lease_id": None,
                        "lease_until": None, "samples": quality_rows[offset:offset + 500]}}})
        if total > MAX_TOTAL_POINTS:
            raise ValueError
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise ValidationError("Invalid high-resolution monitoring state.") from exc


class LiveSampleService:
    def __init__(self, storage, config):
        self.storage, self.config = storage, config

    def collect(self, router_id, *, now=None):
        started = now or datetime.now(UTC)
        interval = self.config.get("LIVE_SAMPLE_INTERVAL_SECONDS", 1)
        timeout = self.config.get("LIVE_SAMPLE_TIMEOUT_SECONDS", 3)
        claimed = {}
        def claim(inputs, state):
            paths, router = selected_paths(inputs, router_id)
            if not paths:
                return
            digest = fingerprint(paths, router, self.config)
            old = state["routers"].get(router_id)
            if old and (old["lease_until"] and started < parse_utc_timestamp(old["lease_until"]) or
                    old["fingerprint"] == digest and started < parse_utc_timestamp(old["next_sample_at"])):
                return
            channels = {p["aggregation_interface"]: {"series_id": str(uuid4()), "points": []} for p in paths}
            if old and old["fingerprint"] == digest:
                channels = old["channels"]
            token = str(uuid4())
            # A small scheduling tolerance prevents millisecond wake-up jitter
            # from skipping alternate ticks. Leases still exclude overlapping I/O.
            state["routers"][router_id] = {"fingerprint": digest, "next_sample_at": utc_text(started + timedelta(seconds=interval - .05)),
                "lease_id": token, "lease_until": utc_text(started + timedelta(seconds=timeout + 2)), "channels": channels}
            claimed.update(paths=deepcopy(paths), router=deepcopy(router), digest=digest, token=token)
        self.storage.update_live_samples(claim)
        if not claimed:
            return None
        paths, router = claimed["paths"], claimed["router"]
        values = {}
        try:
            targets = {p["aggregation_interface"]: p.get("jitter_target") if p.get("jitter_enabled") is True else None for p in paths}
            for target in targets.values():
                if target is not None and not any(ip_address(probe_address(target)) in ip_network(network) for network in self.config.get("ROUTER_ALLOWED_NETWORKS", [])):
                    raise ValueError("Target is outside the approved networks.")
            username, password, connection = RouterService(self.storage, self.config)._preflight(router)
            if connection["api_tls"] is not True:
                raise ValueError("Verified API-SSL is required.")
            values = LiveSampleClient(connection["ip_address"], connection["api_port"], username, password,
                tls=True, timeout=timeout, ca_file=router.get("api_ca_file") or self.config.get("ROUTER_CA_FILE")).read_live(targets)
        except (RouterAPIError, RouterValidationError, OSError, ValueError):
            pass
        completed = now or datetime.now(UTC)
        saved = {}
        def commit(inputs, state):
            entry = state["routers"].get(router_id)
            if not entry or entry["lease_id"] != claimed["token"]:
                return
            entry.update(lease_id=None, lease_until=None)
            current_paths, current_router = selected_paths(inputs, router_id)
            if not current_paths or fingerprint(current_paths, current_router, self.config) != claimed["digest"]:
                return
            for path in paths:
                interface = path["aggregation_interface"]; channel = entry["channels"][interface]
                value = values.get(interface)
                at = parse_utc_timestamp(value["at"]) if value and now is None else completed
                previous = channel["points"][-1] if channel["points"] else None
                if previous and at <= parse_utc_timestamp(previous["at"]):
                    continue
                counter = value["tx_octets"] if value else None
                status, mbps, elapsed = "baseline" if value else "unavailable", None, None
                if value and previous and previous["tx_octets"] is not None:
                    delta = (at - parse_utc_timestamp(previous["at"])).total_seconds()
                    if counter < previous["tx_octets"]:
                        status = "counter_reset"
                    elif delta > interval * 3:
                        status = "gap_reset"
                    else:
                        status, elapsed = "measured", delta
                        mbps = (counter - previous["tx_octets"]) * 8 / delta / 1e6
                if status != "measured" or previous and previous["state"] == "unavailable":
                    channel["series_id"] = str(uuid4())
                q = deepcopy(value["quality"]) if value else None
                if q and now is not None:
                    q["at"] = utc_text(at)
                row = {"at": utc_text(at), "tx_octets": counter, "mbps": mbps, "elapsed_seconds": elapsed,
                    "state": status, "series_id": channel["series_id"], "quality": q}
                channel["points"] = [*channel["points"][-(MAX_POINTS - 1):], row]
                saved[interface] = row
            all_channels = [c for e in state["routers"].values() for c in e["channels"].values()]
            while sum(len(c["points"]) for c in all_channels) > MAX_TOTAL_POINTS:
                min((c for c in all_channels if c["points"]), key=lambda c: c["points"][0]["at"])["points"].pop(0)
        self.storage.update_live_samples(commit)
        return saved or None


def path_view(path, inputs, config, now, *, after=None):
    rid, interface = path["aggregation_router_id"], path["aggregation_interface"]
    paths, router = selected_paths(inputs, rid)
    entry = inputs[DOCUMENT]["routers"].get(rid)
    matches = bool(any(p["path_id"] == path["path_id"] for p in paths) and entry and entry["fingerprint"] == fingerprint(paths, router, config))
    rows = entry["channels"].get(interface, {}).get("points", []) if matches else []
    last = rows[-1] if rows else None
    interval = config.get("LIVE_SAMPLE_INTERVAL_SECONDS", 1)
    fresh = bool(last and 0 <= (now - parse_utc_timestamp(last["at"])).total_seconds() <= interval * 3)
    status = last["state"] if fresh else "stale" if last else "awaiting"
    quality = last["quality"] if fresh and last else None
    visible = [r for r in rows if after is None or parse_utc_timestamp(r["at"]) >= after]
    quality_points, last_break, previous_quality = [], "", None
    for row in rows:
        q = row["quality"]
        if not q or q["status"] != "measured" or previous_quality != "measured":
            last_break = row["at"]
        previous_quality = q["status"] if q else None
        if q and (after is None or parse_utc_timestamp(row["at"]) >= after):
            quality_points.append({"at": q["at"], "jitter_ms": q["jitter_ms"], "series_id": row["series_id"] + ":" + last_break,
                "router_id": rid, "interface": interface, "target": q["target"], "status": q["status"],
                "replies": q["replies"], "probes_requested": 8, "source": "api_ssl_live"})
    return {"id": path["path_id"], "sample_interval_seconds": interval, "state": status,
        "current_mbps": last["mbps"] if fresh else None, "sampled_at": last["at"] if last else None,
        "points": [{"at": r["at"], "mbps": r["mbps"], "series_id": r["series_id"], "source": "api_ssl_live"} for r in visible],
        "quality": {"enabled": path.get("jitter_enabled") is True, "state": "disabled" if not path.get("jitter_enabled") else quality["status"] if quality else status,
            "current_jitter_ms": quality["jitter_ms"] if quality else None, "sampled_at": quality["at"] if quality else None,
            "target": path.get("jitter_target"), "interval_seconds": interval, "points": quality_points}}


def live_delta(storage, config, *, after=None, now=None):
    now = now or datetime.now(UTC)
    inputs = storage.live_snapshot()
    paths = inputs["routing_paths.json"]["paths"]
    return {"updated_at": utc_text(now), "refresh_seconds": config.get("LIVE_SAMPLE_INTERVAL_SECONDS", 1),
        "series": [path_view(p, inputs, config, now, after=after) for p in paths if p.get("live_sampling_enabled") is True],
        "retention_points": MAX_POINTS}
