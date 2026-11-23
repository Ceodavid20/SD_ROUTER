"""Create the Flask application without starting a server or a scheduler."""

from collections.abc import Mapping
from pathlib import Path
import secrets
from typing import Any

from flask import Flask, Response, jsonify, redirect, request, url_for

from config import load_config
from controllers.api_controller import api, router_config
from controllers.auth_controller import auth
from controllers.page_controller import pages
from controllers.router_controller import router_management
from controllers.path_controller import routing_paths
from controllers.monitoring_controller import monitoring_management
from controllers.workflow_controller import workflow
from services.json_storage import StorageError, StorageService
from services.security_service import LoginThrottle, admin_is_authenticated, csrf_token, valid_csrf


def create_app(test_config: Mapping[str, Any] | None = None) -> Flask:
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    if test_config is not None:
        app.config.update(test_config)

    if not app.config.get("SECRET_KEY"):
        if app.config["AUTH_ENABLED"] and (
            app.config["ADMIN_USERNAME"] or app.config["ADMIN_PASSWORD_HASH"]
        ):
            raise ValueError("Set SDR_SECRET_KEY before configuring administrator access.")
        # Local functionality work still uses sessions for CSRF-protected forms.
        app.config["SECRET_KEY"] = secrets.token_hex(32)
    if not app.testing and len(app.config["SECRET_KEY"]) < 32:
        raise ValueError("SDR_SECRET_KEY must be at least 32 characters.")

    for setting in ("DATA_DIR", "OUTPUT_DIR"):
        app.config[setting] = Path(app.config[setting]).expanduser().resolve()

    storage = StorageService(app.config["DATA_DIR"], app.config["OUTPUT_DIR"])
    storage.initialize()
    app.extensions["json_storage"] = storage
    app.extensions["login_throttle"] = LoginThrottle()
    app.jinja_env.globals["csrf_token"] = csrf_token

    app.register_blueprint(auth)
    app.register_blueprint(pages)
    app.register_blueprint(api)
    app.register_blueprint(router_config)
    app.register_blueprint(router_management)
    app.register_blueprint(routing_paths)
    app.register_blueprint(monitoring_management)
    app.register_blueprint(workflow)

    @app.before_request
    def protect_company_operations() -> Response | tuple[Response, int] | None:
        if request.endpoint is None or request.endpoint == "static":
            return None
        # Device command delivery has its own Bearer authentication.
        if request.blueprint == "router_config":
            return None
        if request.blueprint == "auth" and not app.config["AUTH_ENABLED"]:
            return redirect(url_for("pages.dashboard"))
        if (
            app.config["AUTH_ENABLED"]
            and request.endpoint != "auth.login"
            and not admin_is_authenticated()
        ):
            if request.path.startswith("/api/"):
                return jsonify(error="Administrator authentication is required."), 401
            return redirect(url_for("auth.login"))
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not valid_csrf(request.form.get("csrf_token")):
                return app.response_class(
                    "The form expired or is invalid. Reload the page and try again.",
                    status=400, mimetype="text/plain",
                )
        return None

    @app.errorhandler(StorageError)
    def storage_unavailable(error: StorageError) -> Response:
        app.logger.error("Controller JSON storage is unavailable.")
        return app.response_class(
            "Controller storage is unavailable. Check the JSON files and backups.",
            status=503,
            mimetype="text/plain",
        )

    def handle_404(error: Exception) -> Response:
        app.logger.warning("404 Not Found: %s", error)
        return app.response_class(
            "The requested resource was not found on this server.",
            status=404,
            mimetype="text/plain",
        )
    app.errorhandler(404)(handle_404)   

    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    return app
