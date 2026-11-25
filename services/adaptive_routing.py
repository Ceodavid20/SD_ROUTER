"""Adaptive MLU mathematics used by the existing workflow. No device I/O.

A connection weight is a control input, never a measured bandwidth share.
Advisory decisions do not become the next cycle's applied control input.
"""
from collections import defaultdict
from datetime import timedelta
import math
from decimal import Decimal, ROUND_CEILING, localcontext

from services.router_protocol import ProtocolError, parse_utc_timestamp, utc_text
from services.traffic_service import monitored_interfaces, project_traffic_status, stale_after_seconds
from services.traffic_state import counter_record, stream_key

DEFAULT_SETTINGS = {
    "safe_utilization_percent": 80.0, "imbalance_tolerance_percent": 5.0,
    "hold_down_seconds": 120, "feedback_gain": 0.1,
    "max_weight_adjustment": 0.05, "reference_bandwidth_bps": 100_000_000_000,
    "congestion_alpha": 4.0, "pcc_buckets": 300,
}
STATES = {"balanced", "unbalanced", "congestion_risk", "insufficient_capacity",
          "physical_capacity_exceeded", "stale_measurements", "insufficient_samples",
          "carrier_unavailable", "optimization_on_hold", "configuration_required"}


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != set(DEFAULT_SETTINGS):
        raise ValueError("Invalid adaptive settings fields.")
    bounds = {
        "safe_utilization_percent": (0.01, 100), "imbalance_tolerance_percent": (0, 100),
        "hold_down_seconds": (0, 86400), "feedback_gain": (0, 1),
        "max_weight_adjustment": (0.000001, 0.05),
        "reference_bandwidth_bps": (1, 2**53 - 1), "congestion_alpha": (0, 1000),
        "pcc_buckets": (3, 10000),
    }
    for key, (lower, upper) in bounds.items():
        value = settings[key]
        if (type(value) not in (int, float) or not math.isfinite(value)
                or not lower <= value <= upper
                or (type(DEFAULT_SETTINGS[key]) is int and type(value) is not int)):
            raise ValueError("Invalid adaptive setting.")


def minmax_targets(demand, capacities):
    """Exact parallel-link MLU solution in bps; None means physically infeasible."""
    if (type(demand) not in (int, float) or not math.isfinite(demand) or demand < 0
            or not capacities or any(type(c) not in (int, float) or not math.isfinite(c) or c < 0
                                     for c in capacities)):
        raise ValueError("Invalid demand or capacities.")
    total = math.fsum(capacities)
    if demand > total or total <= 0:
        return None
    targets = [demand * (c / total) for c in capacities]
    # Reconcile floating arithmetic without discarding small measured rates.
    index = max(range(len(capacities)), key=capacities.__getitem__)
    targets[index] += demand - math.fsum(targets)
    return targets


def routing_cost(capacity_bps, utilization, settings=None):
    settings = settings or DEFAULT_SETTINGS
    if (type(capacity_bps) not in (int, float) or not math.isfinite(capacity_bps) or capacity_bps <= 0
            or type(utilization) not in (int, float) or not math.isfinite(utilization) or utilization < 0):
        raise ValueError("Invalid cost inputs.")
    # Decimal text avoids an extra metric at exact integer boundaries such
    # as 25 * (1 + 4 * 0.2**2) = 29, which binary floats can ceil to 30.
    with localcontext() as context:
        context.prec = 80
        value = (Decimal(str(settings["reference_bandwidth_bps"])) / Decimal(str(capacity_bps))) * (
            1 + Decimal(str(settings["congestion_alpha"])) * Decimal(str(utilization))**2)
        return int(value.to_integral_value(rounding=ROUND_CEILING))


def feedback_weights(previous, utilizations, settings=None):
    """Bounded proportional control; two links follow the specified equation exactly."""
    settings = settings or DEFAULT_SETTINGS
    if (len(previous) != len(utilizations) or not previous
            or any(type(x) not in (int, float) or not math.isfinite(x) or x < 0
                   for x in [*previous, *utilizations])
            or not math.isclose(sum(previous), 1, abs_tol=1e-9)):
        raise ValueError("Invalid feedback inputs.")
    if (max(utilizations) - min(utilizations)) * 100 <= settings["imbalance_tolerance_percent"]:
        return list(previous)
    step, gain = settings["max_weight_adjustment"], settings["feedback_gain"]
    if len(previous) == 2:
        delta = max(-step, min(step, gain * (utilizations[1] - utilizations[0])))
        first = min(1., max(0., previous[0] + delta))
        return [first, 1. - first]
    # Zero-sum feedback for larger operator-defined groups. Project onto a
    # bounded simplex so normalization never defeats the per-cycle step limit.
    mean = math.fsum(utilizations) / len(utilizations)
    desired = [w + gain * (mean - u) for w, u in zip(previous, utilizations)]
    lower = [max(0., w - step) for w in previous]
    upper = [min(1., w + step) for w in previous]
    lo, hi = -10., 10.
    for _ in range(80):
        mid = (lo + hi) / 2
        values = [max(a, min(b, d - mid)) for a, b, d in zip(lower, upper, desired)]
        if sum(values) > 1:
            lo = mid
        else:
            hi = mid
    return [max(a, min(b, d - hi)) for a, b, d in zip(lower, upper, desired)]


def pcc_distribution(weights, buckets):
    """Largest-remainder quantization; disjoint ranges cover every bucket once."""
    exact = [w * buckets for w in weights]
    counts = [math.floor(x) for x in exact]
    for index in sorted(range(len(weights)), key=lambda i: exact[i] - counts[i], reverse=True)[:buckets-sum(counts)]:
        counts[index] += 1
    cursor, result = 0, []
    for count in counts:
        result.append({"bucket_count": count, "first_bucket": cursor if count else None,
                       "last_bucket": cursor + count - 1 if count else None})
        cursor += count
    return result


def bounded_pcc_distribution(weights, baseline, buckets, max_step):
    """Quantize the actual classifier input without violating the control bound."""
    lower = [math.ceil(max(0, w - max_step) * buckets - 1e-9) for w in baseline]
    upper = [math.floor(min(1, w + max_step) * buckets + 1e-9) for w in baseline]
    if sum(lower) > buckets or sum(upper) < buckets or any(a > b for a, b in zip(lower, upper)):
        return None
    exact = [w * buckets for w in weights]
    counts = [max(a, min(b, math.floor(x))) for a, b, x in zip(lower, upper, exact)]
    while sum(counts) != buckets:
        increasing = sum(counts) < buckets
        candidates = [i for i in range(len(counts)) if counts[i] < upper[i]] if increasing else [i for i in range(len(counts)) if counts[i] > lower[i]]
        index = max(candidates, key=lambda i: exact[i] - counts[i]) if increasing else min(candidates, key=lambda i: exact[i] - counts[i])
        counts[index] += 1 if increasing else -1
    cursor, result = 0, []
    for count in counts:
        result.append({"bucket_count": count, "first_bucket": cursor if count else None,
                       "last_bucket": cursor + count - 1 if count else None})
        cursor += count
    return result

def source_measurement(router, interface, inputs, windows, config, now):
    settings = inputs["automation_settings.json"]
    count = settings["averaging_window"]
    state = inputs["router_traffic_v2.json"]
    try:
        authorized = interface in monitored_interfaces(router)
    except ProtocolError:
        authorized = False
    projected = project_traffic_status(state, settings, config,
        [{**router, "interface_name": interface}], now=now)[router["router_id"]]
    record = counter_record(state, router["router_id"], interface)
    key = router["router_id"] if interface == router.get("interface_name") else stream_key(router["router_id"], interface)
    rows = windows.get(key, [])[-count:]
    status = projected["state"] if authorized else "not_configured"
    if status == "measured":
        status = "ready" if len(rows) >= count else "warming_up"
        if (not rows or parse_utc_timestamp(rows[-1]["timestamp"]).timestamp() != record["timestamp"]
                or rows[-1]["tx_octets"] != record["tx_octets"]
                or any(parse_utc_timestamp(a["timestamp"]) >= parse_utc_timestamp(b["timestamp"])
                       or (parse_utc_timestamp(b["timestamp"]) - parse_utc_timestamp(a["timestamp"])).total_seconds()
                       > stale_after_seconds(settings, router) for a, b in zip(rows, rows[1:]))):
            status = "history_unavailable"
    average = math.fsum(row["tx_mbps"] for row in rows) / count * 1_000_000 if status == "ready" else None
    return {"state": status, "sample_count": len(rows), "sampled_at": projected["last_sample_at"],
            "average_bps": average, "current_bps": projected["tx_mbps"] * 1_000_000 if projected["tx_mbps"] is not None else None,
            "series_id": record.get("series_id") if record else None}


def evaluate_adaptive(inputs, windows, results, config, now, analysis):
    from services.workflow_service import _digest, policy_fingerprint, source_fingerprint
    saved = inputs["automation_settings.json"]
    settings = {**DEFAULT_SETTINGS, **saved.get("adaptive_optimization", {})}
    validate_settings(settings)
    inventory = {r["router_id"]: r for r in inputs["routers.json"]}
    policy_id = policy_fingerprint(inputs)
    active = [p for p in inputs["routing_paths.json"]["paths"] if p["relationship_status"] == "operator_selected"]
    grouped = defaultdict(list)
    for path in active:
        grouped[path["aggregation_router_id"]].append(path)
    issues, groups, allocations, basic_groups = [], [], [], []
    if not active:
        issues.append({"code": "paths_required", "message": "Confirm the carrier paths in Routing paths."})
    for aggregation_id, paths in grouped.items():
        links, reasons, selected = [], [], set()
        for path in paths:
            router, carrier = inventory.get(aggregation_id), inventory.get(path["carrier_router_id"])
            interface = path["aggregation_interface"]
            capacity = path["path_capacity_bps"]
            valid_capacity = type(capacity) is int and capacity > 0 and carrier and carrier.get("capacity_confirmed") is not False
            if not router or not carrier or not valid_capacity or not interface or path["route_role"] == "not_set":
                reasons.append(("configuration_required", f"Path {path['path_id']}: confirm endpoints, interface, capacity and role."))
            if ((router and router.get("active", True) is not True)
                    or (carrier and carrier.get("active", True) is not True)):
                reasons.append(("configuration_required", f"Path {path['path_id']}: an endpoint is deactivated."))
            if path.get("monitor_router_id") != aggregation_id:
                reasons.append(("configuration_required", f"Path {path['path_id']}: measure TX at its main-router outbound interface; carrier TX is health telemetry only."))
            if (aggregation_id, interface) in selected:
                reasons.append(("configuration_required", "Separate carrier paths require distinct main-router outbound TX interfaces. A shared interface cannot be split into measured carrier traffic."))
            selected.add((aggregation_id, interface))
            measurement = source_measurement(router, interface, inputs, windows, config, now) if router else {
                "state": "not_configured", "sample_count": 0, "sampled_at": None,
                "average_bps": None, "current_bps": None, "series_id": None}
            if measurement["state"] != "ready":
                code = "stale_measurements" if measurement["state"] == "stale" else "insufficient_samples"
                if measurement["state"] in ("not_configured", "disabled", "authentication_required"):
                    code = "configuration_required"
                reasons.append((code, f"Path {path['path_id']}: TX source {measurement['state']} ({measurement['sample_count']}/{saved['averaging_window']} samples)."))
            available = path.get("carrier_availability", "unknown")
            links.append({"path_id": path["path_id"], "carrier_router_id": path["carrier_router_id"],
                "carrier": path["carrier"], "monitor_router_id": aggregation_id, "interface": interface,
                "capacity_bps": capacity if valid_capacity else None,
                "availability": available, "eligible": available != "unavailable" and path["route_role"] != "standby",
                "measurement": measurement, "target_bps": None, "adjustment_bps": None,
                "utilization_percent": None, "target_utilization_percent": None,
                "calculated_cost": None, "actual_routing_metric": None,
                "applied_weight": None, "recommended_weight": None, "pcc": None})
        group = {"aggregation_router_id": aggregation_id, "status": "configuration_required",
            "total_capacity_bps": None, "healthy_capacity_bps": None, "safe_capacity_bps": None,
            "demand_bps": None, "available_bandwidth_bps": None, "excess_demand_bps": None,
            "unmet_demand_bps": None, "target_utilization_percent": None,
            "imbalance_percent": None, "predicted_imbalance_reduction_percent": None,
            "predicted_max_utilization_reduction_percent": None, "verified_improvement": None,
            "decision_id": None, "decision_version": None, "generated_at": None, "expires_at": None,
            "next_eligible_at": None, "decision_changed": False,
            "weight_basis": "capacity_initialization_unverified", "execution_authorized": False,
            "pcc_buckets": settings["pcc_buckets"], "links": links}
        groups.append(group)
        if links and all(link["capacity_bps"] is not None for link in links):
            healthy_capacity = math.fsum(link["capacity_bps"] for link in links if link["eligible"])
            group.update(total_capacity_bps=math.fsum(link["capacity_bps"] for link in links),
                healthy_capacity_bps=healthy_capacity,
                safe_capacity_bps=healthy_capacity * settings["safe_utilization_percent"] / 100)
        if reasons:
            codes = [c for c, _ in reasons]
            group["status"] = next(c for c in ("configuration_required", "stale_measurements", "insufficient_samples") if c in codes)
            issues.extend({"code": c, "message": m} for c, m in reasons)
            continue
        capacities = [link["capacity_bps"] for link in links]
        healthy = [c if link["eligible"] else 0 for c, link in zip(capacities, links)]
        measured = [link["measurement"]["average_bps"] for link in links]
        demand, total, available = math.fsum(measured), math.fsum(capacities), math.fsum(healthy)
        utilizations = [value / cap for value, cap in zip(measured, capacities)]
        imbalance = (max(utilizations) - min(utilizations)) * 100
        group.update(total_capacity_bps=total, healthy_capacity_bps=available,
            safe_capacity_bps=available * settings["safe_utilization_percent"] / 100,
            demand_bps=demand, available_bandwidth_bps=max(0, available - demand),
            excess_demand_bps=max(0, demand - total), unmet_demand_bps=max(0, demand - available),
            imbalance_percent=imbalance)
        targets = minmax_targets(demand, healthy)
        status = ("physical_capacity_exceeded" if demand > total else
                  "carrier_unavailable" if available == 0 else
                  "insufficient_capacity" if targets is None else
                  "congestion_risk" if demand > group["safe_capacity_bps"] else
                  "carrier_unavailable" if any(not x["eligible"] for x in links) else
                  "unbalanced" if imbalance > settings["imbalance_tolerance_percent"] else "balanced")
        group["status"] = status
        for link, utilization in zip(links, utilizations):
            link.update(utilization_percent=utilization * 100,
                        calculated_cost=routing_cost(link["capacity_bps"], utilization, settings))
        if targets is None:
            issues.append({"code": status, "message": f"Main router {aggregation_id}: remaining physical capacity cannot carry all measured demand; no partial allocation is published."})
            continue
        base = [c / available for c in healthy]
        # No recommendation is ever promoted to an applied weight. A future
        # execution-authorized adapter must supply verified applied state before
        # it can be used as the feedback controller's next control input.
        weights = feedback_weights(base, utilizations, settings) if all(link["eligible"] for link in links) else base
        bucket_count = settings["pcc_buckets"]
        distribution = bounded_pcc_distribution(weights, base, bucket_count, settings["max_weight_adjustment"])
        if distribution is None:
            group["status"] = "configuration_required"
            issues.append({"code": "pcc_granularity", "message": "Increase PCC bucket granularity so discrete weights respect the maximum adjustment."})
            continue
        for link, target, weight, pcc in zip(links, targets, weights, distribution):
            link.update(target_bps=target, adjustment_bps=target-link["measurement"]["average_bps"],
                target_utilization_percent=target / link["capacity_bps"] * 100,
                recommended_weight=pcc["bucket_count"] / bucket_count, pcc=pcc)
        target_max = max(t / c * 100 for t, c in zip(targets, capacities))
        target_imbalance = (max(t / c for t, c in zip(targets, capacities)) - min(t / c for t, c in zip(targets, capacities))) * 100
        group.update(target_utilization_percent=demand / available * 100,
            predicted_imbalance_reduction_percent=imbalance - target_imbalance,
            predicted_max_utilization_reduction_percent=max(utilizations) * 100 - target_max)
        signature = _digest({"policy": policy_id, "aggregation": aggregation_id,
            "links": [(x["path_id"], x["recommended_weight"], x["calculated_cost"], x["availability"]) for x in links]})
        previous = next((g for result in reversed(results) if result.get("workflow_version") == 2
            for g in result["adaptive"]["groups"] if g["aggregation_router_id"] == aggregation_id and g["decision_id"]), None)
        changed = previous is None or previous["decision_id"] != signature
        hold_until = parse_utc_timestamp(previous["generated_at"]) + timedelta(seconds=settings["hold_down_seconds"]) if previous else now
        if changed and previous and now < hold_until:
            group.update(status="optimization_on_hold", next_eligible_at=utc_text(hold_until))
            for link in links:
                link.update(recommended_weight=None, pcc=None)
        else:
            version = (previous["decision_version"] + 1 if changed else previous["decision_version"]) if previous else 1
            generated = utc_text(now) if changed else previous["generated_at"]
            # Validity is limited by the oldest source, never refreshed from a stale saved result.
            expiry = min(parse_utc_timestamp(link["measurement"]["sampled_at"]) + timedelta(
                seconds=stale_after_seconds(saved, inventory[aggregation_id])) for link in links)
            group.update(decision_id=signature, decision_version=version, generated_at=generated,
                expires_at=utc_text(expiry), decision_changed=changed,
                next_eligible_at=utc_text(parse_utc_timestamp(generated) + timedelta(seconds=settings["hold_down_seconds"])))
        for path, link in zip(paths, links):
            ready = bool(group["decision_id"])
            allocations.append({"path_id": path["path_id"], "aggregation_router_id": aggregation_id,
                "carrier_router_id": link["carrier_router_id"], "carrier": link["carrier"],
                "monitor_router_id": aggregation_id, "interface": link["interface"], "route_role": path["route_role"],
                "capacity_mbps": link["capacity_bps"]/1e6, "allowed_mbps": (link["capacity_bps"]/1e6 if link["eligible"] else 0.),
                "current_mbps": link["measurement"]["average_bps"]/1e6,
                "recommended_mbps": link["target_bps"]/1e6 if ready else None,
                "change_mbps": link["adjustment_bps"]/1e6 if ready else None,
                "cost_per_gb": None, "currency": None, "current_cost_per_hour": None, "recommended_cost_per_hour": None})
        basic_groups.append({"aggregation_router_id": aggregation_id, "demand_mbps": demand/1e6,
                             "available_mbps": available/1e6, "state": "ready"})
    ready = bool(groups) and all(g["decision_id"] for g in groups)
    held = any(g["status"] == "optimization_on_hold" for g in groups)
    infeasible = any(g["status"] in ("physical_capacity_exceeded", "insufficient_capacity", "carrier_unavailable")
                     and g["decision_id"] is None for g in groups)
    status = "ready" if ready else "hold_down" if held else "infeasible" if infeasible else "blocked"
    if not ready:
        for row in allocations:
            row["recommended_mbps"] = row["change_mbps"] = None
        # Never expose a partial network plan through the pull endpoint.
        for group in groups:
            group.update(decision_id=None, decision_version=None, generated_at=None, expires_at=None, decision_changed=False)
            for link in group["links"]:
                link.update(recommended_weight=None, pcc=None)
    source_id = source_fingerprint(inputs)
    evaluation_id = _digest({"policy": policy_id, "groups": [(g["aggregation_router_id"], g["status"], g["decision_id"], g["next_eligible_at"]) for g in groups], "issues": issues})
    return {"workflow_version": 2, "evaluation_id": evaluation_id, "timestamp": utc_text(now),
        "source_fingerprint": source_id, "policy_fingerprint": policy_id,
        "status": status, "objective": "adaptive_mlu", "mode": "dry_run", "action": "none",
        "routing_changes_enabled": False, "analysis": analysis, "allocations": allocations,
        "groups": basic_groups, "issues": issues, "hold_until": next((g["next_eligible_at"] for g in groups if g["status"] == "optimization_on_hold"), None),
        "currency": None, "current_cost_per_hour": None, "recommended_cost_per_hour": None,
        "estimated_savings_per_hour": None,
        "adaptive": {"algorithm": "adaptive_mlu", "mode": "advisory", "execution_authorized": False,
            "settings": settings, "groups": groups}}


def validate_adaptive(value):
    """Closed public schema. Reject injected fields, nonfinite math and executable state."""
    from services.json_storage import ValidationError
    import re
    def fail():
        raise ValidationError("Invalid advisory optimization record.")
    def keys(row, expected):
        if not isinstance(row, dict) or set(row) != set(expected.split()):
            fail()
    def number(value, nullable=True, signed=False):
        if value is None and nullable:
            return
        if type(value) not in (int, float) or not math.isfinite(value) or (not signed and value < 0):
            fail()
    keys(value, "algorithm mode execution_authorized settings groups")
    if value["algorithm"] != "adaptive_mlu" or value["mode"] != "advisory" or value["execution_authorized"] is not False:
        fail()
    try:
        validate_settings(value["settings"])
    except (ValueError, TypeError, OverflowError):
        fail()
    if not isinstance(value["groups"], list) or len(value["groups"]) > 4096:
        fail()
    for group in value["groups"]:
        keys(group, "aggregation_router_id status total_capacity_bps healthy_capacity_bps safe_capacity_bps demand_bps available_bandwidth_bps excess_demand_bps unmet_demand_bps target_utilization_percent imbalance_percent predicted_imbalance_reduction_percent predicted_max_utilization_reduction_percent verified_improvement decision_id decision_version generated_at expires_at next_eligible_at decision_changed weight_basis execution_authorized pcc_buckets links")
        if (not isinstance(group["status"], str) or group["status"] not in STATES or group["execution_authorized"] is not False
                or group["verified_improvement"] is not None or type(group["decision_changed"]) is not bool
                or group["weight_basis"] != "capacity_initialization_unverified"
                or not isinstance(group["aggregation_router_id"], str)
                or group["pcc_buckets"] != value["settings"]["pcc_buckets"]):
            fail()
        for key in ("total_capacity_bps", "healthy_capacity_bps", "safe_capacity_bps", "demand_bps",
                    "available_bandwidth_bps", "excess_demand_bps", "unmet_demand_bps",
                    "target_utilization_percent", "imbalance_percent"):
            number(group[key])
        for key in ("predicted_imbalance_reduction_percent", "predicted_max_utilization_reduction_percent"):
            number(group[key], signed=True)
        for key in ("generated_at", "expires_at", "next_eligible_at"):
            if group[key] is not None:
                try:
                    parse_utc_timestamp(group[key])
                except ProtocolError:
                    fail()
        if group["decision_id"] is not None:
            if (not isinstance(group["decision_id"], str) or not re.fullmatch(r"[a-f0-9]{64}", group["decision_id"])
                    or type(group["decision_version"]) is not int or group["decision_version"] < 1
                    or group["generated_at"] is None or group["expires_at"] is None
                    or parse_utc_timestamp(group["expires_at"]) <= parse_utc_timestamp(group["generated_at"])):
                fail()
        elif any(group[k] is not None for k in ("decision_version", "generated_at", "expires_at")):
            fail()
        if not isinstance(group["links"], list) or not 1 <= len(group["links"]) <= 256:
            fail()
        for link in group["links"]:
            keys(link, "path_id carrier_router_id carrier monitor_router_id interface capacity_bps availability eligible measurement target_bps adjustment_bps utilization_percent target_utilization_percent calculated_cost actual_routing_metric applied_weight recommended_weight pcc")
            if (link["actual_routing_metric"] is not None or link["applied_weight"] is not None
                    or link["availability"] not in ("unknown", "available", "unavailable")
                    or type(link["eligible"]) is not bool
                    or link["monitor_router_id"] != group["aggregation_router_id"]):
                fail()
            for key in ("path_id", "carrier_router_id", "carrier", "monitor_router_id"):
                if not isinstance(link[key], str) or not 1 <= len(link[key]) <= 128:
                    fail()
            if link["interface"] is not None:
                from services.traffic_protocol import validate_interface
                try:
                    validate_interface(link["interface"])
                except ProtocolError:
                    fail()
            for key in ("capacity_bps", "target_bps", "utilization_percent", "target_utilization_percent", "calculated_cost", "recommended_weight"):
                number(link[key])
            number(link["adjustment_bps"], signed=True)
            measurement = link["measurement"]
            keys(measurement, "state sample_count sampled_at average_bps current_bps series_id")
            if (type(measurement["sample_count"]) is not int or not 0 <= measurement["sample_count"] <= 86400
                    or measurement["state"] not in ("ready", "warming_up", "history_unavailable", "stale", "disabled", "not_configured", "authentication_required", "awaiting", "baseline", "counter_reset", "gap_reset")):
                fail()
            for key in ("average_bps", "current_bps"):
                number(measurement[key])
            if measurement["sampled_at"] is not None:
                try:
                    parse_utc_timestamp(measurement["sampled_at"])
                except ProtocolError:
                    fail()
            if measurement["series_id"] is not None:
                from services.routeros_protocol import _uuid4
                try:
                    _uuid4(measurement["series_id"])
                except ProtocolError:
                    fail()
            pcc = link["pcc"]
            if pcc is not None:
                keys(pcc, "bucket_count first_bucket last_bucket")
                if type(pcc["bucket_count"]) is not int or not 0 <= pcc["bucket_count"] <= group["pcc_buckets"]:
                    fail()
                if pcc["bucket_count"] == 0:
                    if pcc["first_bucket"] is not None or pcc["last_bucket"] is not None:
                        fail()
                elif (type(pcc["first_bucket"]) is not int or type(pcc["last_bucket"]) is not int
                      or not 0 <= pcc["first_bucket"] <= pcc["last_bucket"] < group["pcc_buckets"]
                      or pcc["last_bucket"] - pcc["first_bucket"] + 1 != pcc["bucket_count"]):
                    fail()
            if group["decision_id"]:
                if (measurement["state"] != "ready" or measurement["average_bps"] is None
                        or any(link[key] is None for key in ("utilization_percent", "target_utilization_percent", "adjustment_bps", "calculated_cost"))
                        or not link["capacity_bps"] or link["target_bps"] is None
                        or not 0 <= link["target_bps"] <= link["capacity_bps"] + 1e-5
                        or link["recommended_weight"] is None or not 0 <= link["recommended_weight"] <= 1
                        or pcc is None
                        or not math.isclose(link["recommended_weight"], pcc["bucket_count"]/group["pcc_buckets"], abs_tol=1e-12)
                        or not math.isclose(link["adjustment_bps"], link["target_bps"]-measurement["average_bps"], abs_tol=1e-5)
                        or link["calculated_cost"] != routing_cost(link["capacity_bps"], measurement["average_bps"]/link["capacity_bps"], value["settings"])
                        or not math.isclose(link["utilization_percent"], measurement["average_bps"]/link["capacity_bps"]*100, abs_tol=1e-9)
                        or not math.isclose(link["target_utilization_percent"], link["target_bps"]/link["capacity_bps"]*100, abs_tol=1e-9)
                        or (not link["eligible"] and (link["target_bps"] != 0 or link["recommended_weight"] != 0))):
                    fail()
        if group["decision_id"]:
            links = group["links"]
            if group["status"] not in ("balanced", "unbalanced", "congestion_risk", "carrier_unavailable"):
                fail()
            if any(group[key] is None for key in ("total_capacity_bps", "healthy_capacity_bps", "demand_bps", "unmet_demand_bps")):
                fail()
            capacity = math.fsum(link["capacity_bps"] for link in links)
            healthy = math.fsum(link["capacity_bps"] for link in links if link["eligible"])
            if (not healthy or not math.isclose(capacity, group["total_capacity_bps"], rel_tol=1e-9)
                    or not math.isclose(healthy, group["healthy_capacity_bps"], rel_tol=1e-9)
                    or group["demand_bps"] > healthy or group["unmet_demand_bps"] != 0
                    or any(not math.isclose(link["target_bps"], group["demand_bps"] * (link["capacity_bps"] / healthy if link["eligible"] else 0), rel_tol=1e-9, abs_tol=1e-5) for link in links)
                    or any(abs(link["recommended_weight"] - (link["capacity_bps"] / healthy if link["eligible"] else 0)) > value["settings"]["max_weight_adjustment"]+1e-9 for link in links)):
                fail()
            if (len({link["interface"] for link in links}) != len(links)
                    or not math.isclose(math.fsum(link["target_bps"] for link in links), group["demand_bps"], rel_tol=1e-9, abs_tol=1e-5)
                    or not math.isclose(math.fsum(link["measurement"]["average_bps"] for link in links), group["demand_bps"], rel_tol=1e-9, abs_tol=1e-5)
                    or not math.isclose(math.fsum(link["recommended_weight"] for link in links), 1, abs_tol=1e-9)
                    or sum(link["pcc"]["bucket_count"] for link in links) != group["pcc_buckets"]):
                fail()
            used = []
            for link in links:
                pcc = link["pcc"]
                if pcc["bucket_count"]:
                    used.extend(range(pcc["first_bucket"], pcc["last_bucket"]+1))
            if sorted(used) != list(range(group["pcc_buckets"])):
                fail()
