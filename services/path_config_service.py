"""Operator-defined paths and congestion limits, stored without router I/O."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import math
import re
from typing import Any
from uuid import uuid4

from services.json_storage import StorageService, ValidationError


DEFAULT_ROUTING_PATHS = {
    "schema_version": 1,
    "paths": [],
    "congestion_policy": {
        "status": "not_configured", "utilization_limit_percent": None,
        "minimum_hold_down_seconds": None, "overload_policy": None,
    },
    "automation": {"enabled": False, "routing_changes_enabled": False},
}

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_PATH_FIELDS = {
    "path_id", "aggregation_router_id", "carrier_router_id", "carrier",
    "aggregation_interface", "carrier_interface", "path_capacity_bps",
    "relationship_status", "route_role", "configuration_status",
}
_ROLES = {"not_set", "primary", "alternate", "standby"}
_STATES = {"operator_selected", "pending_confirmation", "disabled"}
_POLICIES = {"prefer_lower_utilization", "manual_only"}
QUALITY_FIELDS = {"jitter_enabled", "jitter_target", "live_sampling_enabled"}


def routing_policy_config(config):
    """Quality monitoring does not change routing decisions or their hold-down."""
    return {**config, "paths": [{key: value for key, value in path.items() if key not in QUALITY_FIELDS}
                                for path in config["paths"]]}


def _text(value: Any, label: str, *, maximum: int = 128, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError(f"Enter valid {label}.")
    value = value.strip()
    if len(value) > maximum or (required and not value):
        raise ValidationError(f"Enter valid {label}.")
    return value or None


def _keys(record: Any, expected: set[str], label: str) -> None:
    if not isinstance(record, dict) or set(record) != expected:
        raise ValidationError(f"Invalid {label} fields.")


def _configured(path: dict[str, Any]) -> str:
    return "configured" if all(path.get(key) for key in (
        "aggregation_interface", "carrier_interface", "path_capacity_bps"
    )) else "not_configured"


def analysis_path_ready(path: Mapping[str, Any]) -> bool:
    """Carrier-side analysis needs no invented aggregation interface mapping."""
    if path.get("configuration_status") == "configured":
        return True
    return bool(path.get("monitor_router_id") == path.get("carrier_router_id")
                and path.get("carrier_interface") and path.get("path_capacity_bps"))


def _policy_status(policy: dict[str, Any]) -> str:
    return "configured" if all(policy.get(key) is not None for key in (
        "utilization_limit_percent", "minimum_hold_down_seconds", "overload_policy"
    )) else "not_configured"


def validate_routing_paths(value: Any) -> None:
    """Validate stored contents as strictly as form input, without device access."""
    _keys(value, set(DEFAULT_ROUTING_PATHS), "routing settings")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValidationError("Unsupported routing settings version.")
    if not isinstance(value["paths"], list):
        raise ValidationError("Routing paths must be a list.")
    ids, links = set(), set()
    for path in value["paths"]:
        if (not isinstance(path, dict) or not _PATH_FIELDS <= set(path)
                or set(path) - _PATH_FIELDS - {"monitor_router_id", "carrier_availability"} - QUALITY_FIELDS):
            raise ValidationError("Invalid path fields.")
        if "jitter_enabled" in path and type(path["jitter_enabled"]) is not bool:
            raise ValidationError("Jitter enablement must be true or false.")
        if "live_sampling_enabled" in path and type(path["live_sampling_enabled"]) is not bool:
            raise ValidationError("Live sampling enablement must be true or false.")
        if path.get("live_sampling_enabled") is True and not path.get("aggregation_interface"):
            raise ValidationError("Configure the main-router TX interface before enabling live sampling.")
        target = path.get("jitter_target")
        if target is not None:
            from services.routeros_probe import probe_address
            try:
                if probe_address(target) != target:
                    raise ValueError
            except ValueError as exc:
                raise ValidationError("Enter a literal unicast jitter target.") from exc
        if path.get("jitter_enabled") is True and (not target or not path.get("aggregation_interface")):
            raise ValidationError("Configure a jitter target and main-router interface before enabling probes.")
        for key in ("path_id", "aggregation_router_id", "carrier_router_id"):
            if not isinstance(path[key], str) or not _ID.fullmatch(path[key]):
                raise ValidationError("Invalid path or router ID.")
        if path["path_id"] in ids:
            raise ValidationError("Path IDs must be unique.")
        ids.add(path["path_id"])
        if path["aggregation_router_id"] == path["carrier_router_id"]:
            raise ValidationError("Select two different routers.")
        if path.get("carrier_availability", "unknown") not in ("unknown", "available", "unavailable"):
            raise ValidationError("Select an explicitly confirmed carrier availability state.")
        monitor = path.get("monitor_router_id")
        if monitor is not None and (not isinstance(monitor, str) or monitor not in (
            path["aggregation_router_id"], path["carrier_router_id"],
        )):
            raise ValidationError("Select a path endpoint as its outbound measurement source.")
        if _text(path["carrier"], "carrier", maximum=64, required=True) != path["carrier"]:
            raise ValidationError("Enter a valid carrier label.")
        if not isinstance(path["route_role"], str) or path["route_role"] not in _ROLES:
            raise ValidationError("Select a valid route role.")
        if not isinstance(path["relationship_status"], str) or path["relationship_status"] not in _STATES:
            raise ValidationError("Select a valid path status.")
        for key in ("aggregation_interface", "carrier_interface"):
            if _text(path[key], "interface name") != path[key]:
                raise ValidationError("Interface names must be trimmed or unset.")
        capacity = path["path_capacity_bps"]
        if capacity is not None and (type(capacity) is not int or not 1 <= capacity <= 2**53 - 1):
            raise ValidationError("Capacity must be a positive whole number in bits per second.")
        if path["configuration_status"] != _configured(path):
            raise ValidationError("Path settings status does not match its fields.")
        # Allow parallel connections when their interface pairs differ.
        link = tuple(path[key] for key in ("aggregation_router_id", "carrier_router_id",
                                           "aggregation_interface", "carrier_interface"))
        if link in links:
            raise ValidationError("This router and interface pair already has a path.")
        links.add(link)
    policy = value["congestion_policy"]
    _keys(policy, set(DEFAULT_ROUTING_PATHS["congestion_policy"]), "congestion policy")
    limit = policy["utilization_limit_percent"]
    if limit is not None and (
        type(limit) not in (int, float) or not 0 < limit <= 100 or not math.isfinite(limit)
    ):
        raise ValidationError("Utilization limit must be greater than 0 and at most 100 percent.")
    hold = policy["minimum_hold_down_seconds"]
    if hold is not None and (type(hold) is not int or not 0 <= hold <= 2**31 - 1):
        raise ValidationError("Hold-down time must be a nonnegative whole number of seconds.")
    overload = policy["overload_policy"]
    if overload is not None and (not isinstance(overload, str) or overload not in _POLICIES):
        raise ValidationError("Select a valid congestion policy.")
    if policy["status"] != _policy_status(policy):
        raise ValidationError("Congestion policy status does not match its fields.")
    _keys(value["automation"], {"enabled", "routing_changes_enabled"}, "automation")
    if any(flag is not False for flag in value["automation"].values()):
        raise ValidationError("Path settings cannot enable automation or router changes.")


def _integer(form: Mapping[str, Any], key: str, *, minimum: int = 1) -> int | None:
    raw = _text(form.get(key), key.replace("_", " "), maximum=20)
    if raw is None:
        return None
    if not re.fullmatch(r"[0-9]+", raw):
        raise ValidationError(f"{key.replace('_', ' ').capitalize()} must be a whole number.")
    result = int(raw)
    if not minimum <= result <= 2**53 - 1:
        raise ValidationError(f"Enter a valid {key.replace('_', ' ')}.")
    return result


class PathConfigService:
    """Save intended paths; monitoring and route execution use separate services."""

    def __init__(self, storage: StorageService) -> None:
        self.storage = storage

    def read(self) -> dict[str, Any]:
        return self.storage.read_json("routing_paths.json")

    def list_paths(self) -> list[dict[str, Any]]:
        names = {
            router["router_id"]: router["name"]
            if isinstance(router.get("name"), str) and router["name"].strip()
            else router["router_id"]
            for router in self.storage.read_json("routers.json")
        }
        paths = self.read()["paths"]
        for path in paths:
            path["display_name"] = " → ".join(names.get(path[key], path[key]) for key in (
                "aggregation_router_id", "carrier_router_id"
            ))
            path["analysis_ready"] = analysis_path_ready(path)
        return paths

    def _path(self, path_id: str, form: Mapping[str, Any]) -> dict[str, Any]:
        path = {
            "path_id": path_id,
            "aggregation_router_id": _text(form.get("aggregation_router_id"), "aggregation router", required=True),
            "carrier_router_id": _text(form.get("carrier_router_id"), "carrier router", required=True),
            "carrier": _text(form.get("carrier"), "carrier", maximum=64),
            "aggregation_interface": _text(form.get("aggregation_interface"), "aggregation interface"),
            "carrier_interface": _text(form.get("carrier_interface"), "carrier interface"),
            "path_capacity_bps": _integer(form, "path_capacity_bps"),
            "route_role": _text(form.get("route_role", "not_set"), "route role", required=True),
            "relationship_status": _text(form.get("relationship_status", "operator_selected"), "path status", required=True),
            "monitor_router_id": _text(form.get("monitor_router_id"), "outbound measurement source"),
        }
        if "carrier_availability" in form:
            path["carrier_availability"] = form["carrier_availability"]
        inventory = {router["router_id"]: router for router in self.storage.read_json("routers.json")}
        for key in ("aggregation_router_id", "carrier_router_id"):
            if path[key] not in inventory:
                raise ValidationError("Select routers registered in the inventory.")
        assigned_carrier = inventory[path["carrier_router_id"]].get("carrier")
        if not path["carrier"]:
            path["carrier"] = assigned_carrier
        if assigned_carrier and assigned_carrier != path["carrier"]:
            raise ValidationError("Carrier must match the selected carrier router.")
        path["configuration_status"] = _configured(path)
        return path

    def add_path(self, form: Mapping[str, Any]) -> dict[str, Any]:
        path = self._path(str(uuid4()), form)

        def add(config: dict[str, Any]) -> dict[str, Any]:
            config["paths"].append(path)
            return config

        self.storage.update_json("routing_paths.json", add)
        self.storage.append_activity("routing", f"Routing path {path['path_id']} added.")
        return deepcopy(path)

    def save_path(self, path_id: str, form: Mapping[str, Any]) -> dict[str, Any]:
        path = self._path(path_id, form)

        def replace(config: dict[str, Any]) -> dict[str, Any]:
            for index, current in enumerate(config["paths"]):
                if current["path_id"] == path_id:
                    if "carrier_availability" not in form and "carrier_availability" in current:
                        path["carrier_availability"] = current["carrier_availability"]
                    if "monitor_router_id" not in form:
                        path["monitor_router_id"] = current.get("monitor_router_id")
                    # Jitter has a separate explicit opt-in form. Existing
                    # topology forms must not erase or silently enable it.
                    for field in QUALITY_FIELDS:
                        if field in current:
                            path[field] = current[field]
                    if any(path.get(key) != current.get(key) for key in (
                            "aggregation_router_id", "carrier_router_id", "aggregation_interface", "carrier_interface")):
                        for field in ("jitter_enabled", "live_sampling_enabled"):
                            if path.get(field):
                                path[field] = False
                    config["paths"][index] = path
                    return config
            raise ValidationError("Routing path was not found.")

        self.storage.update_json("routing_paths.json", replace)
        self.storage.append_activity("routing", f"Routing path {path_id} updated.")
        return deepcopy(path)

    def configure_jitter(self, path_id, target, enabled, config):
        from ipaddress import ip_address, ip_network
        from services.routeros_probe import probe_address
        if type(enabled) is not bool or not isinstance(target, str):
            raise ValidationError("Select a valid jitter monitoring setting.")
        try:
            target = probe_address(target.strip()) if target.strip() else None
            if enabled and (not target or not any(ip_address(target) in ip_network(network)
                    for network in config.get("ROUTER_ALLOWED_NETWORKS", []))):
                raise ValueError
        except ValueError as exc:
            raise ValidationError("Use a jitter target inside the controller's approved networks.") from exc
        def update(settings):
            path = next((path for path in settings["paths"] if path["path_id"] == path_id), None)
            if path is None:
                raise ValidationError("Routing path was not found.")
            path.update(jitter_enabled=enabled, jitter_target=target)
            return settings
        self.storage.update_json("routing_paths.json", update)
        self.storage.append_activity("monitoring", "RTT jitter enabled." if enabled else "RTT jitter disabled.", {"path_id": path_id})

    def configure_live_sampling(self, path_id, enabled):
        if type(enabled) is not bool:
            raise ValidationError("Select a valid live sampling setting.")
        def update(settings):
            path = next((p for p in settings["paths"] if p["path_id"] == path_id), None)
            if path is None:
                raise ValidationError("Routing path was not found.")
            path["live_sampling_enabled"] = enabled
            return settings
        self.storage.update_json("routing_paths.json", update)
        self.storage.append_activity("monitoring", "Second-by-second sampling enabled." if enabled else "Second-by-second sampling disabled.", {"path_id": path_id})

    def delete_path(self, path_id: str) -> None:
        def remove(config: dict[str, Any]) -> dict[str, Any]:
            if not any(path["path_id"] == path_id for path in config["paths"]):
                raise ValidationError("Routing path was not found.")
            config["paths"] = [path for path in config["paths"] if path["path_id"] != path_id]
            return config

        self.storage.update_json("routing_paths.json", remove)
        self.storage.append_activity("routing", f"Routing path {path_id} removed.")

    def save_congestion_policy(self, form: Mapping[str, Any]) -> dict[str, Any]:
        raw_limit = _text(form.get("utilization_limit_percent"), "utilization limit", maximum=32)
        try:
            limit = float(raw_limit) if raw_limit is not None else None
        except ValueError as exc:
            raise ValidationError("Utilization limit must be numeric.") from exc
        overload = _text(form.get("overload_policy"), "congestion policy")
        policy = {
            "utilization_limit_percent": limit,
            "minimum_hold_down_seconds": _integer(form, "minimum_hold_down_seconds", minimum=0),
            "overload_policy": None if overload == "not_set" else overload,
        }
        policy["status"] = _policy_status(policy)

        def replace(config: dict[str, Any]) -> dict[str, Any]:
            config["congestion_policy"] = policy
            return config

        self.storage.update_json("routing_paths.json", replace)
        self.storage.append_activity("routing", "Congestion limits updated.")
        return deepcopy(policy)
