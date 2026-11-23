"""Authenticated, CSRF-protected router inventory actions.

The application-wide security hook authenticates and validates CSRF before
these handlers run. A connection is attempted only by the explicit test POST.
"""

from flask import Blueprint, current_app, flash, redirect, request, url_for

from services.router_service import RouterService, RouterValidationError


router_management = Blueprint("router_management", __name__)


def _service() -> RouterService:
    return RouterService(current_app.extensions["json_storage"], current_app.config)


@router_management.post("/routers/<router_id>/edit")
def edit_router(router_id: str):
    try:
        _service().edit_router(router_id, request.form)
    except RouterValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Router settings saved. Previous connectivity status has been cleared.", "success")
    return redirect(url_for("pages.routers"))


@router_management.post("/routers/<router_id>/delete")
def delete_router(router_id: str):
    try:
        _service().delete_router(router_id)
    except RouterValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Router removed from inventory. Historical measurements were retained.", "success")
    return redirect(url_for("pages.routers"))


@router_management.post("/routers/<router_id>/test-api")
def test_api(router_id: str):
    try:
        router = _service().test_api(router_id)
    except RouterValidationError as exc:
        flash(str(exc), "danger")
    else:
        if router["connection_status"] == "connected":
            flash("Read-only API connection verified by a real router resource response.", "success")
        else:
            flash(router["last_error"], "warning")
    return redirect(url_for("pages.routers"))
