"""Build the same controller status for pages and the JSON API."""

from typing import Any
from collections.abc import Mapping

from services.json_storage import StorageService
from services.controller_status_service import read_controller_status
from services.traffic_service import read_traffic_status
from services.workflow_service import WorkflowService, optimization_enabled


def read_status(storage: StorageService, config: Mapping[str, Any]) -> dict[str, Any]:
    settings = storage.read_json("automation_settings.json")
    routers = storage.read_json("routers.json")
    polling = read_controller_status(storage, config, routers)
    controller_counts = {
        state: sum(summary["state"] == state for summary in polling.values())
        for state in ("disabled", "awaiting", "authenticated", "stale")
    }
    traffic = read_traffic_status(storage, config, routers)
    enabled = [summary for summary in traffic.values() if summary["enabled"]]
    measured = [summary for summary in enabled if summary["state"] == "measured"]
    calculation = WorkflowService(storage, config).read_latest()
    readiness = "not_configured"
    if routers:
        readiness = (
            "api_verified"
            if all(router.get("connection_status") == "connected" for router in routers)
            else "verification_required"
        )
    outbound = sum(summary["tx_mbps"] for summary in measured) if enabled and len(measured) == len(enabled) else None
    if settings.get("optimization_objective") == "adaptive_mlu":
        if optimization_enabled(settings):
            preview = WorkflowService(storage, config).preview()
            groups = preview["adaptive"]["groups"]
            outbound = sum(g["demand_bps"] for g in groups) / 1e6 if groups and all(g["demand_bps"] is not None for g in groups) else None
        else:
            from services.optimization_graphs import graph_data
            from services.traffic_service import project_traffic_status
            inventory = {row["router_id"]: row for row in routers}
            sources = graph_data(storage, include_context=False)["actual"]
            state = storage.read_json("router_traffic_v2.json")
            readings = [project_traffic_status(state, settings, config,
                [{**inventory[row["router_id"]], "interface_name": row["interface"]}])[row["router_id"]]
                for row in sources]
            outbound = sum(r["tx_mbps"] for r in readings) if readings and all(r["tx_mbps"] is not None for r in readings) else None
    return {
        "mode": settings["mode"],
        "company_name": config.get("COMPANY_NAME", "Network Operations"),
        "data_source": "router",
        "controller_access": "read_only",
        "router_count": len(routers),
        "readiness": readiness,
        # Retain the legacy API-diagnostic readiness field for compatibility.
        "controller_polling": controller_counts,
        "storage": "ready",
        "monitoring": "not_started" if not enabled else ("receiving" if measured else "awaiting_readings"),
        "traffic_monitoring": {"enabled": len(enabled), "measured": len(measured)},
        # Publish a network total only when every enabled router has a current rate.
        "outbound_mbps": outbound,
        "optimization_enabled": optimization_enabled(settings),
        "optimization": "off" if not optimization_enabled(settings) else "not_started" if calculation is None else (
            "recommendation_ready" if calculation["is_current"] and calculation["status"] == "ready"
            else "recalculation_required" if calculation["status"] == "ready" else calculation["status"]),
        "optimization_objective": settings.get("optimization_objective", "not_configured"),
        "last_calculation_at": calculation["timestamp"] if calculation else None,
        "automation": settings["automation"],
        "routing_changes_enabled": settings["routing_changes_enabled"],
        "monitoring_interval_seconds": settings["monitoring_interval_seconds"],
        "averaging_window": settings["averaging_window"],
    }
