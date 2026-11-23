"""Browser routes. All persistent state is read through JSON storage."""

from flask import Blueprint, current_app, render_template

from services.status_service import read_status
from services.router_service import RouterService
from services.path_config_service import PathConfigService
from services.controller_connection_service import connection_details


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
    connected = sum(router.get("connection_status") == "connected" for router in routers)
    authenticated = sum(router["controller_polling"]["state"] == "authenticated" for router in routers)
    return _render(
        "dashboard",
        activity_limit=5,
        router_counts={
            "registered": len(routers),
            "connected": connected,
            "needs_check": len(routers) - connected,
            "authenticated": authenticated,
            "no_recent_checkin": len(routers) - authenticated,
        },
    )


@pages.get("/routers")
def routers() -> str:
    storage = current_app.extensions["json_storage"]
    return _render("routers", routers=RouterService(storage, current_app.config).list_routers())


@pages.get("/routers/connect")
def router_connection() -> str:
    return _render("router_connection", connection=connection_details(current_app.config))


@pages.get("/monitoring")
def monitoring() -> str:
    return _render("monitoring")


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
    return _render("mathematics")


@pages.get("/optimization")
def optimization() -> str:
    return _render("optimization")


@pages.get("/json-output")
def json_output() -> str:
    return _render("json_output")


@pages.get("/automation")
def automation() -> str:
    return _render("automation")


@pages.get("/settings")
def settings() -> str:
    return _render("settings")


@pages.get("/logs")
def logs() -> str:
    return _render("logs", activity_limit=50)
