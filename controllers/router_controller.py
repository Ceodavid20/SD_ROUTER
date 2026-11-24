"""Authenticated, CSRF-protected router inventory actions.

The application-wide security hook authenticates and validates CSRF before
these handlers run. A connection is attempted only by the explicit test POST.
"""

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from services.router_service import RouterService, RouterValidationError
from services.router_onboarding_service import RouterOnboardingService
from services.api_credentials_service import configure_api_credentials, APICredentialError


router_management = Blueprint("router_management", __name__)


def _service() -> RouterService:
    return RouterService(current_app.extensions["json_storage"], current_app.config)


def _onboarding():
    return RouterOnboardingService(current_app.extensions["json_storage"], current_app.config)


@router_management.post("/routers/add")
def add_router():
    try:
        router = _service().add_router(request.form)
    except RouterValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("pages.routers"))
    flash("Router registered. Monitoring and routing changes are disabled.", "success")
    return redirect(url_for("router_management.setup_router", router_id=router["router_id"]))


@router_management.get("/routers/<router_id>/setup")
def setup_router(router_id):
    from services.status_service import read_status
    try:
        setup = _onboarding().view(router_id)
    except RouterValidationError:
        abort(404)
    return render_template("router_setup.html", setup=setup,
        status=read_status(current_app.extensions["json_storage"], current_app.config), activity=[])


@router_management.post("/routers/<router_id>/setup/<action>")
def setup_action(router_id, action):
    try:
        if action == "credentials":
            configure_api_credentials(current_app.extensions["json_storage"], current_app.config, router_id,
                                      request.form.get("username"), request.form.get("password"))
            message = "Read-only API credentials saved privately."
        elif action == "discover":
            _onboarding().discover(router_id)
            message = "Read-only discovery complete. No router configuration changed."
        elif action == "interfaces":
            names = request.form.getlist("interfaces")
            view = _onboarding().view(router_id)
            if not view["discovery_current"]:
                raise RouterValidationError("Run discovery for the current connection settings first.")
            available = {row.get("name") for row in view["discovery"]["snapshot"]["interfaces"]["rows"]}
            if not names or any(name not in available for name in names):
                raise RouterValidationError("Select discovered TX interfaces.")
            _service().configure_monitoring_interfaces(router_id, names)
            message = "TX interfaces saved. Enable monitoring explicitly after installing the matching collector."
        elif action == "active":
            if request.form.getlist("active") not in (["true"], ["false"]):
                raise RouterValidationError("Select an activation setting.")
            _service().set_active(router_id, request.form["active"] == "true")
            message = "Router activation saved; old monitoring and authorization were not re-enabled."
        elif action == "capture":
            selections = {key.removeprefix("scope_"): value for key, value in request.form.items() if key.startswith("scope_")}
            _onboarding().capture_baseline(router_id, selections)
            message = "Projected routing baseline captured. Review it before approval."
        elif action == "approve-baseline":
            _onboarding().approve_baseline(router_id, request.form.get("digest"))
            message = "Baseline approved. Routing changes remain disabled."
        elif action == "authorize":
            if request.form.get("confirm") != "true":
                raise RouterValidationError("Confirm the exact execution scope before approving it.")
            try:
                ttl = int(request.form.get("ttl_seconds", "3600"))
            except ValueError as exc:
                raise RouterValidationError("Enter a valid scope approval duration.") from exc
            _onboarding().authorize_scope(router_id, request.form.get("digest"), ttl_seconds=ttl)
            message = "Execution scope approved for review. The global routing executor remains blocked."
        elif action == "revoke":
            _onboarding().revoke(router_id)
            message = "Execution scope revoked."
        else:
            abort(404)
    except (RouterValidationError, APICredentialError) as exc:
        flash(str(exc), "danger")
    else:
        flash(message, "success")
    return redirect(url_for("router_management.setup_router", router_id=router_id))


@router_management.get("/routers/<router_id>/baseline.json")
def baseline_download(router_id):
    try:
        view = _onboarding().view(router_id)
        if not view["baseline"]:
            abort(404)
        response = jsonify(router_id=router_id, baseline=view["baseline"],
            limitation="Projected routing configuration only; not a complete RouterOS backup.")
    except RouterValidationError:
        abort(404)
    response.headers["Content-Disposition"] = 'attachment; filename="routing-baseline.json"'
    return response


@router_management.get("/routers/<router_id>/rollback.json")
def rollback_download(router_id):
    try:
        response = jsonify(_onboarding().rollback_reference(router_id))
    except RouterValidationError as exc:
        return jsonify(error=str(exc)), 409
    response.headers["Content-Disposition"] = 'attachment; filename="rollback-reference.json"'
    return response


@router_management.get("/routers/<router_id>/policy.json")
def policy_preview(router_id):
    try:
        return jsonify(_onboarding().policy_preview(router_id))
    except RouterValidationError:
        abort(404)


@router_management.post("/routers/<router_id>/bundle")
def private_bundle(router_id):
    # This download contains a router signing key. Never permit anonymous or
    # plaintext downloads, including development loopback convenience mode.
    if current_app.config.get("AUTH_ENABLED") is not True or not request.is_secure:
        return current_app.response_class("Administrator authentication over HTTPS is required for private bundles.", status=403)
    if request.form.get("confirm") != "true":
        return current_app.response_class("Confirm trusted delivery of the private bundle.", status=400)
    try:
        target = _onboarding().prepare_bundle(router_id)
    except (RouterValidationError, OSError, ValueError):
        flash("Private bundle unavailable. Verify current API-SSL discovery, profile CA, controller HTTPS origin and private storage.", "danger")
        return redirect(url_for("router_management.setup_router", router_id=router_id))
    from io import BytesIO
    from zipfile import ZipFile, ZIP_DEFLATED
    from flask import send_file
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for filename in sorted(target.rglob("*")):
            if filename.is_file() and not filename.is_symlink():
                archive.write(filename, str(filename.relative_to(target)))
    buffer.seek(0)
    return send_file(buffer, mimetype="application/zip", as_attachment=True, download_name="private-router-client.zip", max_age=0)


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
