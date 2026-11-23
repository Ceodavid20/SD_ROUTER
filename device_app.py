"""Create a device-only Flask application without browser/admin routes."""

from collections.abc import Mapping
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from config import load_config
from controllers.router_poll_controller import router_poll
from controllers.traffic_controller import router_traffic
from controllers.enrollment_controller import router_enrollment
from services.json_storage import StorageError, StorageService
from services.router_poll_service import PollError
from services.router_protocol import MAX_REQUEST_BYTES, ProtocolError


def _loopback(address: str | None) -> bool:
    try:
        return bool(address) and ip_address(address).is_loopback
    except ValueError:
        return False


def create_device_app(test_config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(load_config())
    if test_config is not None:
        app.config.update(test_config)
    if app.config.get("LIVE_ROUTING_ENABLED") is not False:
        raise ValueError("Live routing execution is not implemented; keep LIVE_ROUTING_ENABLED=false.")
    if type(app.config.get("SIMULATION_MODE")) is not bool:
        raise ValueError("SIMULATION_MODE must be true or false.")
    for key, minimum, maximum in (
        ("ROUTER_POLL_INTERVAL", 1, 86400),
        ("ROUTER_REQUEST_MAX_AGE_SECONDS", 1, 86400),
        ("ROUTER_CLOCK_SKEW_SECONDS", 0, 86400),
        ("ROUTER_RESPONSE_TTL_SECONDS", 1, 300),
        ("ROUTER_RATE_LIMIT_ATTEMPTS", 1, 1_000_000),
        ("ROUTER_RATE_LIMIT_WINDOW_SECONDS", 1, 86400),
    ):
        if type(app.config.get(key)) is not int or not minimum <= app.config[key] <= maximum:
            raise ValueError(f"Invalid {key} setting.")
    for key in ("DATA_DIR", "OUTPUT_DIR"):
        app.config[key] = Path(app.config[key]).expanduser().resolve()
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    storage = StorageService(app.config["DATA_DIR"], app.config["OUTPUT_DIR"])
    storage.initialize()
    app.extensions["json_storage"] = storage
    app.register_blueprint(router_poll)
    app.register_blueprint(router_traffic)
    app.register_blueprint(router_enrollment)

    @app.before_request
    def require_protected_transport():
        if request.blueprint not in ("router_poll", "router_traffic"):
            return None
        # Waitress clears forwarded headers by default. Only an explicitly
        # configured local TLS proxy may supply the verified scheme/source.
        host = urlsplit(request.url_root).hostname
        local_simulation = (
            app.config["SIMULATION_MODE"] and _loopback(request.remote_addr)
            and (host == "localhost" or _loopback(host))
        )
        if not request.is_secure and not local_simulation:
            return jsonify(error="Verified HTTPS is required for router communication."), 403
        return None

    @app.errorhandler(PollError)
    def polling_error(error):
        response = jsonify(error=str(error), code=error.code)
        response.status_code = error.status
        if error.status == 429:
            response.headers["Retry-After"] = str(app.config["ROUTER_RATE_LIMIT_WINDOW_SECONDS"])
        return response

    @app.errorhandler(StorageError)
    def storage_error(error):
        app.logger.error("Router communication storage is unavailable.")
        return jsonify(error="Controller storage is unavailable."), 503

    @app.errorhandler(ProtocolError)
    def protocol_error(error):
        app.logger.error("Controller polling response validation failed.")
        return jsonify(error="Controller response is unavailable."), 503

    @app.errorhandler(HTTPException)
    def http_error(error):
        response = error.get_response()
        response.data = app.json.dumps({"error": error.name})
        response.content_type = "application/json"
        return response

    @app.after_request
    def device_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app
