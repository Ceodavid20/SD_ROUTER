"""Read-only JSON endpoints for the controller."""

import hmac

from flask import Blueprint, Response, abort, current_app, jsonify, request

from services.json_storage import StorageError
from services.router_service import RouterService
from services.status_service import read_status
from services.workflow_service import WorkflowService


api = Blueprint("api", __name__, url_prefix="/api")
router_config = Blueprint("router_config", __name__)


@api.get("/routers")
def routers() -> Response:
    service = RouterService(current_app.extensions["json_storage"], current_app.config)
    return jsonify(routers=service.list_routers())


@api.get("/system/status")
def system_status() -> Response:
    try:
        response = jsonify(read_status(current_app.extensions["json_storage"], current_app.config))
    except (StorageError, OSError, ValueError):
        current_app.logger.error("Unable to read controller JSON storage.")
        response = jsonify(storage="unavailable", error="Storage is unavailable.")
        response.status_code = 503

    response.cache_control.no_store = True
    return response


@api.get("/workflow")
def current_workflow() -> Response:
    try:
        return jsonify(calculation=WorkflowService(
            current_app.extensions["json_storage"], current_app.config,
        ).read_latest())
    except StorageError:
        current_app.logger.error("Unable to read calculation storage.")
        return jsonify(error="Calculation storage is unavailable."), 503


@api.get("/monitoring")
def live_monitoring() -> Response:
    storage = current_app.extensions["json_storage"]
    routers = RouterService(storage, current_app.config).list_routers()
    selected = request.args.get("router_id") or None
    if selected and not any(r["router_id"] == selected for r in routers):
        abort(404)
    preview = WorkflowService(storage, current_app.config).preview()
    history = [{k:row[k] for k in ("router_id", "interface", "timestamp", "tx_mbps")}
               for row in storage.list_traffic(limit=100, router_id=selected)]
    return jsonify(mode="dry_run", action="none", routing_changes_enabled=False,
        routers=[r for r in routers if not selected or r["router_id"] == selected],
        analysis=[r for r in preview["analysis"] if not selected or r["router_id"] == selected],
        recommendations=[r for r in preview["recommendations"] if not selected or r["router_id"] == selected],
        history=history)


@api.get("/optimization")
def live_optimization() -> Response:
    response = jsonify(calculation=WorkflowService(
        current_app.extensions["json_storage"], current_app.config,
    ).preview())
    response.cache_control.no_store = True
    return response


@api.get("/optimization/live")
def live_tx_view() -> Response:
    from services.optimization_graphs import live_view
    try:
        response = jsonify(live_view(current_app.extensions["json_storage"], current_app.config))
    except (StorageError, OSError, ValueError):
        current_app.logger.error("Unable to read live TX dashboard data.")
        response = jsonify(error="Live readings are temporarily unavailable.")
        response.status_code = 503
    response.cache_control.no_store = True
    return response


@router_config.get("/router-config/<router_id>")
def current_router_config(router_id: str) -> Response:
    """Return only a validated router command, never an internal storage file."""
    token = current_app.config.get("ROUTER_CONFIG_TOKEN", "")
    if not token:
        response = jsonify(error="Router command delivery is not configured.")
        response.status_code = 503
    elif not hmac.compare_digest(
        request.headers.get("Authorization", "").encode(),
        f"Bearer {token}".encode(),
    ):
        response = jsonify(error="Router authentication is required.")
        response.status_code = 401
    else:
        # A stored proposal must never become a live command during commissioning.
        response = jsonify(error="Routing changes are disabled during commissioning.")
        response.status_code = 423
    response.cache_control.no_store = True
    return response
