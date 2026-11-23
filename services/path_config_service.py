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
        if not isinstance(path, dict) or set(path) not in (_PATH_FIELDS, _PATH_FIELDS | {"monitor_router_id"}):
            raise ValidationError("Invalid path fields.")
        for key in ("path_id", "aggregation_router_id", "carrier_router_id"):
            if not isinstance(path[key], str) or not _ID.fullmatch(path[key]):
                raise ValidationError("Invalid path or router ID.")
        if path["path_id"] in ids:
            raise ValidationError("Path IDs must be unique.")
        ids.add(path["path_id"])
        if path["aggregation_router_id"] == path["carrier_router_id"]:
            raise ValidationError("Select two different routers.")
        monitor = path.get("monitor_router_id")
        if monitor is not None and (not isinstance(monitor, str) or monitor not in (
            path["aggregation_router_id"], path["carrier_router_id"],
        )):
            raise ValidationError("Select a path endpoint as its outbound measurement source.")
        if path["carrier"] not in ("MTN", "GLO"):
            raise ValidationError("Select MTN or Glo.")
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
        return paths

    def _path(self, path_id: str, form: Mapping[str, Any]) -> dict[str, Any]:
        path = {
            "path_id": path_id,
            "aggregation_router_id": _text(form.get("aggregation_router_id"), "aggregation router", required=True),
            "carrier_router_id": _text(form.get("carrier_router_id"), "carrier router", required=True),
            "carrier": _text(form.get("carrier"), "carrier", required=True),
            "aggregation_interface": _text(form.get("aggregation_interface"), "aggregation interface"),
            "carrier_interface": _text(form.get("carrier_interface"), "carrier interface"),
            "path_capacity_bps": _integer(form, "path_capacity_bps"),
            "route_role": _text(form.get("route_role", "not_set"), "route role", required=True),
            "relationship_status": _text(form.get("relationship_status", "operator_selected"), "path status", required=True),
            "monitor_router_id": _text(form.get("monitor_router_id"), "outbound measurement source"),
        }
        inventory = {router["router_id"]: router for router in self.storage.read_json("routers.json")}
        for key in ("aggregation_router_id", "carrier_router_id"):
            if path[key] not in inventory:
                raise ValidationError("Select routers registered in the inventory.")
        assigned_carrier = inventory[path["carrier_router_id"]].get("carrier")
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
                    if "monitor_router_id" not in form:
                        path["monitor_router_id"] = current.get("monitor_router_id")
                    config["paths"][index] = path
                    return config
            raise ValidationError("Routing path was not found.")

        self.storage.update_json("routing_paths.json", replace)
        self.storage.append_activity("routing", f"Routing path {path_id} updated.")
        return deepcopy(path)

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
