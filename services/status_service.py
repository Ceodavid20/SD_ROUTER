"""Build the same controller status for pages and the JSON API."""

from typing import Any
from collections.abc import Mapping

from services.json_storage import StorageService
from services.controller_status_service import read_controller_status


def read_status(storage: StorageService, config: Mapping[str, Any]) -> dict[str, Any]:
    settings = storage.read_json("automation_settings.json")
    routers = storage.read_json("routers.json")
    polling = read_controller_status(storage, config, routers)
    controller_counts = {
        state: sum(summary["state"] == state for summary in polling.values())
        for state in ("disabled", "awaiting", "authenticated", "stale")
    }
    readiness = "not_configured"
    if routers:
        readiness = (
            "api_verified"
            if all(router.get("connection_status") == "connected" for router in routers)
            else "verification_required"
        )
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
        "monitoring": "not_started",
        "optimization": "not_started",
        "automation": settings["automation"],
        "routing_changes_enabled": settings["routing_changes_enabled"],
        "monitoring_interval_seconds": settings["monitoring_interval_seconds"],
        "averaging_window": settings["averaging_window"],
    }
