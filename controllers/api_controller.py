"""Read-only JSON endpoints for the controller."""

import hmac

from flask import Blueprint, Response, current_app, jsonify, request

from services.json_storage import StorageError
from services.router_service import RouterService
from services.status_service import read_status


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
