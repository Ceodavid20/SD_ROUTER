"""Local TX analysis and constrained allocation previews; no router execution."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
import hashlib
import json
import math
import re
from typing import Any

from services.json_storage import StorageService
from services.router_protocol import parse_utc_timestamp, utc_text
from services.traffic_service import project_traffic_status, stale_after_seconds


OBJECTIVES = {"minimize_cost", "balance_utilization"}
_ROUTER_INPUTS = (
    "router_id", "name", "interface_name", "monitoring_enabled", "monitoring_generation",
    "capacity_mbps", "cost_per_gb", "currency", "controller_auth_enabled",
    "controller_auth_ref", "controller_auth_key_ids",
    "connection_status", "traffic_source_ip", "monitoring_interval_seconds",
    "traffic_source_ip", "connection_status",
)


class WorkflowError(ValueError):
    """A safe input/calculation error without private registry details."""


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _numeric(value: Any, *, positive: bool = False) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)
    except OverflowError:
        return False


def _currency(value: Any) -> str | None:
    return value if isinstance(value, str) and re.fullmatch(r"[A-Z]{3}", value) else None


def _cost(rate: float, price: float) -> float:
    # Decimal gigabytes: Mbps * 1e6 / 8 * 3600 / 1e9 = Mbps * 0.45 GB/hour.
    result = rate * 0.45 * price
    if not math.isfinite(result):
        raise WorkflowError("Traffic or pricing values exceed the safe calculation range.")
    return result


def policy_fingerprint(inputs: dict) -> str:
    settings = inputs["automation_settings.json"]
    return _digest({
        "routers": [{key: row.get(key) for key in _ROUTER_INPUTS} for row in inputs["routers.json"]],
        "paths": inputs["routing_paths.json"],
        "settings": {key: settings.get(key) for key in (
            "averaging_window", "monitoring_interval_seconds", "optimization_objective",
        )},
    })


def source_fingerprint(inputs: dict) -> str:
    return _digest({"policy": policy_fingerprint(inputs),
                    "counters": inputs["router_traffic_v2.json"]["routers"]})


def _analyze(inputs, windows, config, now):
    settings = inputs["automation_settings.json"]
    window = settings["averaging_window"]
    routers = inputs["routers.json"]
    state = inputs["router_traffic_v2.json"]
    summaries = project_traffic_status(state, settings, config, routers, now=now)
    analysis = []
    for router in routers:
        router_id = router["router_id"]
        summary = summaries[router_id]
        rows = windows.get(router_id, [])
        current_state = summary["state"]
        if current_state == "measured":
            current_state = "ready" if len(rows) >= window else "warming_up"
            record = state["routers"][router_id]
            if rows and (parse_utc_timestamp(rows[-1]["timestamp"]).timestamp() != record["timestamp"]
                         or rows[-1]["tx_octets"] != record["tx_octets"]):
                current_state = "history_unavailable"
            if any(parse_utc_timestamp(left["timestamp"]) >= parse_utc_timestamp(right["timestamp"])
                   for left, right in zip(rows, rows[1:])):
                current_state = "history_unavailable"
        average = math.fsum(row["tx_mbps"] for row in rows[-window:]) / window if current_state == "ready" else None
        previous = math.fsum(row["tx_mbps"] for row in rows[-window-1:-1]) / window if average is not None and len(rows) > window else None
        change = (average - previous) / previous * 100 if previous is not None and previous > 0 else None
        capacity = router.get("capacity_mbps") if _numeric(router.get("capacity_mbps"), positive=True) else None
        price = router.get("cost_per_gb") if _numeric(router.get("cost_per_gb")) else None
        currency = _currency(router.get("currency"))
        observed_gb = math.fsum(row["tx_mbps"] * row["interval_seconds"] / 8000
                                for row in rows[-window:]) if average is not None else None
        analysis.append({
            "router_id": router_id,
            "name": router.get("name") if isinstance(router.get("name"), str) else router_id,
            "interface": summary["interface"], "state": current_state,
            "sample_count": min(len(rows), window), "window_size": window,
            "sampled_at": summary["last_sample_at"], "current_mbps": summary["tx_mbps"],
            "average_mbps": average, "previous_average_mbps": previous, "change_percent": change,
            "capacity_mbps": capacity,
            "utilization_percent": average / capacity * 100 if average is not None and capacity else None,
            "traffic_share_percent": None,
            "cost_per_gb": price, "currency": currency,
            "cost_per_hour": _cost(average, price) if average is not None and price is not None and currency else None,
            "observed_gb": observed_gb,
        })
    return analysis


def allocate_parallel_paths(paths: list[dict], objective: str) -> list[float] | None:
    """Solve one parallel-path group under a fixed demand and upper bounds.

    Cost minimization fills cheaper paths first (the exact solution for this
    linear model). Utilization balance assigns capacity-proportional shares.
    No traffic is discarded when the constraints are infeasible.
    """
    if objective not in OBJECTIVES:
        raise WorkflowError("Select a dry-run optimization objective.")
    required = ("current_mbps", "allowed_mbps", "cost_per_gb") if objective == "minimize_cost" else ("current_mbps", "allowed_mbps")
    if any(not _numeric(path.get(key)) for path in paths for key in required):
        raise WorkflowError("Allocation inputs must be finite and nonnegative.")
    demand = math.fsum(path["current_mbps"] for path in paths)
    available = math.fsum(path["allowed_mbps"] for path in paths)
    tolerance = max(1, demand) * 1e-10
    if demand > available + tolerance:
        return None
    result = [0.0] * len(paths)
    if demand == 0:
        return result
    if objective == "balance_utilization":
        if available <= 0:
            return None
        return [demand * path["allowed_mbps"] / available for path in paths]
    remaining = demand
    for index in sorted(range(len(paths)), key=lambda i: (
        paths[i]["cost_per_gb"], -paths[i]["current_mbps"], paths[i]["path_id"],
    )):
        result[index] = min(remaining, paths[index]["allowed_mbps"])
        remaining = max(0.0, remaining - result[index])
    return result


def evaluate(inputs, windows, results, config, now):
    analysis = _analyze(inputs, windows, config, now)
    by_router = {row["router_id"]: row for row in analysis}
    inventory = {row["router_id"]: row for row in inputs["routers.json"]}
    settings = inputs["automation_settings.json"]
    routing = inputs["routing_paths.json"]
    policy = routing["congestion_policy"]
    objective = settings.get("optimization_objective", "not_configured")
    issues, allocations, groups = [], [], []

    def issue(code, message):
        if not any(row["code"] == code and row["message"] == message for row in issues):
            issues.append({"code": code, "message": message})

    if objective not in OBJECTIVES:
        issue("objective_required", "Choose an optimization objective in Settings.")
    if policy["status"] != "configured":
        issue("policy_required", "Configure the utilization limit, hold-down time and congestion policy in Routing paths.")
    active = [path for path in routing["paths"] if path["relationship_status"] == "operator_selected"]
    if not active:
        issue("paths_required", "Configure and confirm the paths included in the calculation.")
    selected = set()
    currencies = set()
    for path in active:
        path_id = path["path_id"]
        if path["configuration_status"] != "configured":
            issue("path_incomplete", f"Path {path_id}: enter both interfaces and confirmed capacity.")
            continue
        monitor_id = path.get("monitor_router_id")
        if monitor_id is None:
            issue("measurement_required", f"Path {path_id}: select its outbound TX measurement source.")
            continue
        if monitor_id in selected:
            issue("duplicate_measurement", "Each monitored router/interface can supply demand for only one path.")
            continue
        selected.add(monitor_id)
        monitor, carrier = inventory.get(monitor_id), inventory.get(path["carrier_router_id"])
        if monitor is None or carrier is None or path["aggregation_router_id"] not in inventory:
            issue("router_missing", f"Path {path_id}: an endpoint is absent from inventory.")
            continue
        interface = path["aggregation_interface"] if monitor_id == path["aggregation_router_id"] else path["carrier_interface"]
        row = by_router[monitor_id]
        if monitor.get("interface_name") != interface:
            issue("interface_mismatch", f"Path {path_id}: its measurement interface must match the router's configured outbound interface.")
        if row["state"] != "ready":
            issue("readings_required", f"Path {path_id}: measurement source is {row['state'].replace('_', ' ')} ({row['sample_count']}/{row['window_size']} readings).")
        if path["route_role"] == "not_set":
            issue("role_required", f"Path {path_id}: select its primary, alternate or standby role.")
        price, currency = carrier.get("cost_per_gb"), _currency(carrier.get("currency"))
        if objective == "minimize_cost" and (not _numeric(price) or currency is None):
            issue("price_required", f"Path {path_id}: enter the carrier router's confirmed price per decimal GB and currency.")
        if _numeric(price) and currency is not None:
            currencies.add(currency)
        if carrier.get("connection_status") in ("blocked", "disconnected"):
            issue("connection_unavailable", f"Path {path_id}: the carrier router's secure API connection needs verification.")
        capacity = path["path_capacity_bps"] / 1_000_000
        for endpoint in (monitor, carrier):
            configured_capacity = endpoint.get("capacity_mbps")
            if configured_capacity is not None:
                if not _numeric(configured_capacity, positive=True):
                    issue("capacity_invalid", f"Path {path_id}: correct the router interface capacity.")
                else:
                    capacity = min(capacity, configured_capacity)
        average = row["average_mbps"]
        row["capacity_mbps"] = capacity
        row["utilization_percent"] = average / capacity * 100 if average is not None else None
        row["cost_per_gb"], row["currency"] = price if _numeric(price) else None, currency
        row["cost_per_hour"] = _cost(average, price) if average is not None and _numeric(price) and currency else None
        allowed = capacity * policy["utilization_limit_percent"] / 100 if policy["status"] == "configured" else None
        allocations.append({
            "path_id": path_id, "aggregation_router_id": path["aggregation_router_id"],
            "carrier_router_id": path["carrier_router_id"], "carrier": path["carrier"],
            "monitor_router_id": monitor_id, "interface": interface, "route_role": path["route_role"],
            "capacity_mbps": capacity, "allowed_mbps": 0.0 if path["route_role"] == "standby" else allowed,
            "current_mbps": average, "recommended_mbps": None, "change_mbps": None,
            "cost_per_gb": price if _numeric(price) else None, "currency": currency,
            "current_cost_per_hour": row["cost_per_hour"], "recommended_cost_per_hour": None,
        })
    if objective == "minimize_cost" and len(currencies) > 1:
        issue("currency_mismatch", "Use one confirmed currency for all compared paths; currency conversion is not performed.")
    status = "blocked" if issues else "ready"
    grouped = defaultdict(list)
    for row in allocations:
        grouped[row["aggregation_router_id"]].append(row)
    if not issues:
        for aggregation_id, paths in grouped.items():
            demand = math.fsum(row["current_mbps"] for row in paths)
            available = math.fsum(row["allowed_mbps"] for row in paths)
            targets = allocate_parallel_paths(paths, objective)
            groups.append({"aggregation_router_id": aggregation_id, "demand_mbps": demand,
                           "available_mbps": available, "state": "ready" if targets is not None else "infeasible"})
            for index, row in enumerate(paths):
                by_router[row["monitor_router_id"]]["traffic_share_percent"] = row["current_mbps"] / demand * 100 if demand > 0 else 0.0
                if targets is not None:
                    row["recommended_mbps"] = targets[index]
                    row["change_mbps"] = targets[index] - row["current_mbps"]
                    row["recommended_cost_per_hour"] = _cost(targets[index], row["cost_per_gb"]) if row["cost_per_gb"] is not None and row["currency"] else None
            if targets is None:
                status = "infeasible"
                issue("insufficient_capacity", f"Aggregation router {aggregation_id}: demand exceeds the permitted capacity of eligible paths.")
    policy_id = policy_fingerprint(inputs)
    hold_until = None
    if status == "ready":
        previous = next((row for row in reversed(results) if row.get("workflow_version") == 1
                         and row["status"] == "ready" and row["policy_fingerprint"] == policy_id), None)
        if previous and previous["source_fingerprint"] != source_fingerprint(inputs):
            until = parse_utc_timestamp(previous["timestamp"]) + timedelta(seconds=policy["minimum_hold_down_seconds"])
            if now < until:
                status, hold_until = "hold_down", utc_text(until)
                issue("hold_down", "The hold-down interval has not elapsed. Calculate again after the displayed time.")
    # A partial/infeasible/held result cannot masquerade as an executable plan.
    if status != "ready":
        for row in allocations:
            row["recommended_mbps"] = row["change_mbps"] = row["recommended_cost_per_hour"] = None
    current_cost = math.fsum(row["current_cost_per_hour"] for row in allocations) if (
        allocations and len(allocations) == len(active) and len(currencies) == 1
        and all(row["current_cost_per_hour"] is not None for row in allocations)
    ) else None
    if current_cost is None:
        for row in allocations:
            row["current_cost_per_hour"] = row["recommended_cost_per_hour"] = None
    recommended_cost = math.fsum(row["recommended_cost_per_hour"] for row in allocations) if status == "ready" and current_cost is not None else None
    source_id = source_fingerprint(inputs)
    evaluation_id = _digest({"source": source_id, "status": status,
                             "analysis_states": [row["state"] for row in analysis], "hold_until": hold_until})
    return {
        "workflow_version": 1, "evaluation_id": evaluation_id, "timestamp": utc_text(now),
        "source_fingerprint": source_id, "policy_fingerprint": policy_id,
        "status": status, "objective": objective, "mode": "dry_run", "action": "none",
        "routing_changes_enabled": False, "analysis": analysis, "allocations": allocations,
        "groups": groups, "issues": issues, "hold_until": hold_until,
        "currency": next(iter(currencies)) if len(currencies) == 1 else None,
        "current_cost_per_hour": current_cost, "recommended_cost_per_hour": recommended_cost,
        "estimated_savings_per_hour": current_cost - recommended_cost if current_cost is not None and recommended_cost is not None else None,
    }


class WorkflowService:
    def __init__(self, storage: StorageService, config: Mapping[str, Any]):
        self.storage, self.config = storage, config

    def calculate(self, *, now: datetime | None = None) -> dict:
        current = now or datetime.now(UTC)
        if current.utcoffset() is None:
            raise WorkflowError("A timezone-aware calculation time is required.")
        return self.storage.calculate_workflow(
            lambda inputs, windows, results: evaluate(inputs, windows, results, self.config, current),
        )

    def preview(self, *, now: datetime | None = None) -> dict:
        """Current analysis and advisory conditions; no device I/O or JSON writes."""
        current = now or datetime.now(UTC)
        if current.utcoffset() is None:
            raise WorkflowError("A timezone-aware calculation time is required.")
        inputs, windows, results = self.storage.read_monitoring_snapshot()
        preview = evaluate(inputs, windows, results, self.config, current)
        inventory = {row["router_id"]: row for row in inputs["routers.json"]}
        recommendations = []
        for row in preview["analysis"]:
            router = inventory[row["router_id"]]
            if router.get("router_role") != "carrier" and not router.get("carrier"):
                continue
            allocation = next((p for p in preview["allocations"] if p["monitor_router_id"] == row["router_id"]), None)
            reasons = []
            if row["capacity_mbps"] is None:
                reasons.append("WAN capacity is unknown; configure a confirmed capacity before estimating utilization.")
            alternatives = [p for p in preview["allocations"] if allocation
                            and p["aggregation_router_id"] == allocation["aggregation_router_id"]
                            and p["carrier_router_id"] != allocation["carrier_router_id"]]
            if not alternatives:
                reasons.append("Traffic-switching eligibility between these links has not been confirmed in Routing paths.")
            if row["state"] != "ready":
                reasons.append(f"A fresh averaging window is required ({row['sample_count']}/{row['window_size']} readings; {row['state'].replace('_', ' ')}).")
            ready = preview["status"] == "ready" and not reasons and allocation is not None
            change = allocation["change_mbps"] if ready else None
            if change is None:
                action = "Continue monitoring; no traffic shift proposed."
                reasons.extend(item["message"] for item in preview["issues"] if item["message"] not in reasons)
            elif abs(change) < 1e-9:
                action = "Maintain the current eligible outbound allocation."
            elif change > 0:
                action = "Consider increasing eligible outbound allocation within the confirmed path group."
            else:
                action = "Consider shifting eligible outbound traffic to another confirmed path."
            recommendations.append({
                "router_id": row["router_id"], "interface": row["interface"],
                "status": "ready" if ready else "blocked", "mode": "dry_run",
                "execution_status": "Dry Run", "action": "none",
                "recommended_action": action,
                "reason": " ".join(reasons) if reasons else "The configured objective was evaluated against fresh TX measurements and confirmed path limits.",
                "current_mbps": row["current_mbps"], "average_mbps": row["average_mbps"],
                "capacity_mbps": row["capacity_mbps"], "utilization_percent": row["utilization_percent"],
                "api_connection_status": router.get("connection_status", "untested"),
                "monitoring_state": row["state"], "change_mbps": change,
                "expected_benefit": {
                    "is_estimate": True,
                    "description": "Estimated capacity allocation only; no routing has been executed." if ready else "Unavailable until capacity, measurements and switching eligibility are confirmed.",
                    "resulting_utilization_percent": allocation["recommended_mbps"] / row["capacity_mbps"] * 100 if ready else None,
                },
            })
        preview["recommendations"] = recommendations
        return preview

    def read_latest(self, *, now: datetime | None = None) -> dict | None:
        inputs, results = self.storage.read_workflow_snapshot()
        latest = next((row for row in reversed(results) if row.get("workflow_version") == 1), None)
        if latest is None:
            return None
        latest = dict(latest)
        current = now or datetime.now(UTC)
        if current.utcoffset() is None:
            raise WorkflowError("A timezone-aware calculation time is required.")
        inventory = {row["router_id"]: row for row in inputs["routers.json"]}
        times = [(row["router_id"], parse_utc_timestamp(row["sampled_at"])) for row in latest["analysis"]
                 if row["router_id"] in {path["monitor_router_id"] for path in latest["allocations"]}
                 and row["sampled_at"]]
        skew = self.config.get("ROUTER_CLOCK_SKEW_SECONDS", 30)
        if type(skew) is not int or not 0 <= skew <= 86400:
            skew = 30
        latest["is_current"] = (latest["source_fingerprint"] == source_fingerprint(inputs)
                                and bool(times) and all(-skew <= (current - at).total_seconds()
                                    <= stale_after_seconds(inputs["automation_settings.json"], inventory.get(router_id))
                                    for router_id, at in times))
        return latest

    def save_settings(self, form: Mapping[str, Any]) -> None:
        objective = form.get("optimization_objective")
        if objective not in OBJECTIVES | {"not_configured"}:
            raise WorkflowError("Select a supported dry-run objective.")
        values = {}
        for key in ("averaging_window", "monitoring_interval_seconds"):
            raw = form.get(key, "")
            if not isinstance(raw, str) or not re.fullmatch(r"[0-9]{1,5}", raw) or not 1 <= int(raw) <= 86400:
                raise WorkflowError("Collection interval and averaging window must be whole numbers from 1 to 86400.")
            values[key] = int(raw)
        self.storage.update_json("automation_settings.json", lambda settings: {
            **settings, **values, "optimization_objective": objective,
        })
