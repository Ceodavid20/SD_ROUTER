"""Strict public calculation records, separate from executable router output."""

import math
import re

from services.json_storage import ValidationError
from services.router_protocol import ProtocolError, parse_utc_timestamp


ANALYSIS_FIELDS = {
    "router_id", "name", "interface", "state", "sample_count", "window_size", "sampled_at",
    "current_mbps", "average_mbps", "previous_average_mbps", "change_percent", "capacity_mbps",
    "utilization_percent", "traffic_share_percent", "cost_per_gb", "currency", "cost_per_hour", "observed_gb",
}
ALLOCATION_FIELDS = {
    "path_id", "aggregation_router_id", "carrier_router_id", "carrier", "monitor_router_id",
    "interface", "route_role", "capacity_mbps", "allowed_mbps", "current_mbps", "recommended_mbps",
    "change_mbps", "cost_per_gb", "currency", "current_cost_per_hour", "recommended_cost_per_hour",
}
RESULT_FIELDS = {
    "workflow_version", "evaluation_id", "timestamp", "source_fingerprint", "policy_fingerprint", "status",
    "objective", "mode", "action", "routing_changes_enabled", "analysis", "allocations", "groups", "issues",
    "hold_until", "currency", "current_cost_per_hour", "recommended_cost_per_hour", "estimated_savings_per_hour",
}
NUMERIC_FIELDS = {
    "current_mbps", "average_mbps", "previous_average_mbps", "change_percent", "capacity_mbps",
    "utilization_percent", "traffic_share_percent", "cost_per_gb", "cost_per_hour", "observed_gb",
    "allowed_mbps", "recommended_mbps", "change_mbps", "current_cost_per_hour",
    "recommended_cost_per_hour", "estimated_savings_per_hour", "demand_mbps", "available_mbps",
}


def _record(row, fields):
    if not isinstance(row, dict) or set(row) != fields:
        raise ValidationError("Invalid calculation record fields.")
    for key, value in row.items():
        if key in NUMERIC_FIELDS and value is not None:
            try:
                finite = type(value) in (int, float) and math.isfinite(value)
            except OverflowError:
                finite = False
            if not finite or (key not in {"change_percent", "change_mbps", "estimated_savings_per_hour"} and value < 0):
                raise ValidationError("Invalid calculation number.")
        elif key in {"sample_count", "window_size", "workflow_version"}:
            if type(value) is not int or value < 0:
                raise ValidationError("Invalid calculation count.")
        elif key == "routing_changes_enabled":
            if type(value) is not bool:
                raise ValidationError("Invalid calculation routing flag.")
        elif key in {"analysis", "allocations", "groups", "issues"}:
            if not isinstance(value, list):
                raise ValidationError("Invalid calculation section.")
        elif key not in NUMERIC_FIELDS:
            if value is None and key not in {"interface", "currency", "sampled_at", "hold_until"}:
                raise ValidationError("A calculation text field is required.")
            if value is not None and not isinstance(value, str):
                raise ValidationError("Invalid calculation text field.")


def validate_workflow_result(row):
    _record(row, RESULT_FIELDS)
    if (type(row["workflow_version"]) is not int or row["workflow_version"] != 1
            or row["mode"] != "dry_run" or row["action"] != "none"
            or row["routing_changes_enabled"] is not False
            or row["status"] not in ("blocked", "ready", "infeasible", "hold_down")
            or row["objective"] not in ("not_configured", "minimize_cost", "balance_utilization")):
        raise ValidationError("Invalid dry-run calculation state.")
    for key in ("evaluation_id", "source_fingerprint", "policy_fingerprint"):
        if not isinstance(row[key], str) or not re.fullmatch(r"[0-9a-f]{64}", row[key]):
            raise ValidationError("Invalid calculation identity.")
    try:
        parse_utc_timestamp(row["timestamp"])
        if row["hold_until"] is not None:
            parse_utc_timestamp(row["hold_until"])
        for key, fields in (("analysis", ANALYSIS_FIELDS), ("allocations", ALLOCATION_FIELDS),
                            ("groups", {"aggregation_router_id", "demand_mbps", "available_mbps", "state"}),
                            ("issues", {"code", "message"})):
            if not isinstance(row[key], list):
                raise ValidationError("Calculation sections must be lists.")
            for item in row[key]:
                _record(item, fields)
                if key == "analysis":
                    if item["sampled_at"] is not None:
                        parse_utc_timestamp(item["sampled_at"])
                    if not 0 <= item["sample_count"] <= item["window_size"] <= 86400 or item["window_size"] == 0:
                        raise ValidationError("Invalid calculation averaging window.")
                    if (type(item["sample_count"]) is not int or type(item["window_size"]) is not int
                            or not 1 <= item["window_size"] <= 86400
                            or not 0 <= item["sample_count"] <= item["window_size"]):
                        raise ValidationError("Invalid calculation sample count.")
                if key == "allocations" and row["status"] != "ready" and any(item[field] is not None for field in (
                    "recommended_mbps", "change_mbps", "recommended_cost_per_hour",
                )):
                    raise ValidationError("An unavailable recommendation cannot contain allocations.")
        if row["status"] == "ready":
            financial = row["current_cost_per_hour"] is not None
            if (not row["groups"] or not row["allocations"] or row["issues"]
                    or (row["objective"] == "minimize_cost" and not financial)
                    or (financial and (row["recommended_cost_per_hour"] is None
                        or not isinstance(row["currency"], str) or not re.fullmatch(r"[A-Z]{3}", row["currency"])))
                    or (not financial and (row["recommended_cost_per_hour"] is not None
                        or row["estimated_savings_per_hour"] is not None))):
                raise ValidationError("Incomplete ready recommendation.")
            for allocation in row["allocations"]:
                if (allocation["current_mbps"] is None or allocation["recommended_mbps"] is None
                        or allocation["allowed_mbps"] is None or allocation["capacity_mbps"] is None
                        or not 0 <= allocation["recommended_mbps"] <= allocation["allowed_mbps"] + 1e-7
                        or allocation["allowed_mbps"] > allocation["capacity_mbps"] + 1e-7
                        or (financial and allocation["currency"] != row["currency"])
                        or (not financial and (allocation["current_cost_per_hour"] is not None
                            or allocation["recommended_cost_per_hour"] is not None))):
                    raise ValidationError("Recommendation violates a path constraint.")
                if allocation["route_role"] == "standby" and allocation["recommended_mbps"] != 0:
                    raise ValidationError("A standby path cannot receive an allocation.")
            for group in row["groups"]:
                allocations = [item for item in row["allocations"]
                               if item["aggregation_router_id"] == group["aggregation_router_id"]]
                if (group["state"] != "ready" or not allocations
                        or not math.isclose(math.fsum(item["recommended_mbps"] for item in allocations),
                                            group["demand_mbps"], rel_tol=1e-9, abs_tol=1e-7)
                        or not math.isclose(math.fsum(item["current_mbps"] for item in allocations),
                                            group["demand_mbps"], rel_tol=1e-9, abs_tol=1e-7)):
                    raise ValidationError("Recommendation does not conserve group demand.")
        elif row["recommended_cost_per_hour"] is not None or row["estimated_savings_per_hour"] is not None:
            raise ValidationError("An unavailable plan cannot publish estimated savings.")
    except ProtocolError as exc:
        raise ValidationError("Invalid calculation timestamp.") from exc


def validate_workflow_projection(row, kind):
    fields = ANALYSIS_FIELDS if kind == "averages.json" else ALLOCATION_FIELDS
    _record(row, fields | {"workflow_version", "evaluation_id", "calculated_at"})
    if type(row["workflow_version"]) is not int or row["workflow_version"] != 1:
        raise ValidationError("Invalid calculation projection version.")
    if not isinstance(row["evaluation_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["evaluation_id"]):
        raise ValidationError("Invalid calculation projection identity.")
    try:
        parse_utc_timestamp(row["calculated_at"])
    except ProtocolError as exc:
        raise ValidationError("Invalid calculation projection time.") from exc
