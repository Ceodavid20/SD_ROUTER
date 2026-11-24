"""Browser routes. All persistent state is read through JSON storage."""

from flask import Blueprint, abort, current_app, render_template, request, redirect, url_for

from services.status_service import read_status
from services.router_service import RouterService
from services.path_config_service import PathConfigService
from services.controller_connection_service import connection_details
from services.workflow_service import WorkflowService


pages = Blueprint("pages", __name__)


def _render(page: str, *, activity_limit: int = 0, **context: object) -> str:
    storage = current_app.extensions["json_storage"]
    activity = storage.list_activity(limit=activity_limit) if activity_limit else []
    return render_template(
        f"{page}.html", status=read_status(storage, current_app.config), activity=activity, **context
    )


@pages.get("/")
def dashboard() -> str:
    storage = current_app.extensions["json_storage"]
    routers = RouterService(storage, current_app.config).list_routers()
    from services.optimization_graphs import live_view
    return _render("dashboard", routers=routers,
                   live=live_view(storage, current_app.config))



@pages.get("/routers")
def routers() -> str:
    storage = current_app.extensions["json_storage"]
    return _render("routers", routers=RouterService(storage, current_app.config).list_routers())


@pages.get("/routers/connect")
def router_connection() -> str:
    return _render(
        "router_connection", connection=connection_details(current_app.config),
        registered_routers=RouterService(current_app.extensions["json_storage"], current_app.config).list_routers(),
    )


@pages.get("/monitoring")
def monitoring() -> str:
    storage = current_app.extensions["json_storage"]
    routers = RouterService(storage, current_app.config).list_routers()
    selected_router = request.args.get("router_id", "")
    if selected_router and not any(r["router_id"] == selected_router for r in routers):
        abort(404)
    unit = request.args.get("unit", current_app.config.get("TRAFFIC_DISPLAY_UNIT", "Mbps"))
    if unit not in ("Mbps", "Kbps"):
        abort(400)
    # A fixed projection prevents unknown legacy history fields reaching HTML.
    readings = [{key: row[key] for key in ("timestamp", "router_id", "interface", "tx_mbps")}
                for row in reversed(storage.list_traffic(limit=100, router_id=selected_router or None))]
    return _render(
        "monitoring", routers=routers, selected_router=selected_router, unit=unit,
        live_preview=WorkflowService(storage, current_app.config).preview(),
        readings=readings, connection=connection_details(current_app.config),
    )


@pages.get("/routing-paths")
def routing_paths() -> str:
    storage = current_app.extensions["json_storage"]
    service = PathConfigService(storage)
    return _render(
        "routing_paths", path_config=service.read(), paths=service.list_paths(),
        routers=RouterService(storage, current_app.config).list_routers(),
    )


@pages.get("/mathematics")
def mathematics() -> str:
    return redirect(url_for("pages.optimization"))


@pages.get("/optimization")
def optimization() -> str:
    from services.optimization_graphs import live_view
    return _render("optimization", live=live_view(
        current_app.extensions["json_storage"], current_app.config))



@pages.get("/json-output")
def json_output() -> str:
    return _render("json_output", calculation=WorkflowService(
        current_app.extensions["json_storage"], current_app.config,
    ).read_latest())


@pages.get("/automation")
def automation() -> str:
    return _render("automation")


@pages.get("/settings")
def settings() -> str:
    from services.adaptive_routing import DEFAULT_SETTINGS
    saved = current_app.extensions["json_storage"].read_json("automation_settings.json")
    return _render("settings", adaptive_settings={**DEFAULT_SETTINGS, **saved.get("adaptive_optimization", {})})


@pages.get("/logs")
def logs() -> str:
    return _render("logs", activity_limit=50)
