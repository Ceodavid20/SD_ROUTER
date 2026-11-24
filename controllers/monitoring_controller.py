"""Explicit browser opt-in using the application's existing auth/CSRF guard."""

from flask import Blueprint, current_app, flash, redirect, request, url_for

from services.router_service import RouterService, RouterValidationError


monitoring_management = Blueprint("monitoring_management", __name__)


@monitoring_management.post("/routers/<router_id>/monitoring")
def configure_monitoring(router_id):
    try:
        if request.form.getlist("monitoring_enabled") not in (["true"], ["false"]):
            raise RouterValidationError("Select enable or disable monitoring.")
        RouterService(current_app.extensions["json_storage"], current_app.config).set_monitoring(
            router_id, request.form["monitoring_enabled"] == "true",
        )
    except RouterValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Outbound monitoring enabled." if request.form["monitoring_enabled"] == "true"
              else "Outbound monitoring disabled.", "success")
    return redirect(url_for("pages.monitoring"))


@monitoring_management.post('/routers/<router_id>/monitoring-interfaces')
def configure_interfaces(router_id):
    try:
        # One exact name per line; no comma splitting of legal interface names.
        raw = request.form.get('interfaces', '')
        if len(raw) > 2100:
            raise RouterValidationError('Enter at most sixteen TX interfaces.')
        interfaces = raw.splitlines()
        RouterService(current_app.extensions['json_storage'],current_app.config).configure_monitoring_interfaces(router_id, interfaces)
    except RouterValidationError as exc:
        flash(str(exc), 'danger')
    else:
        flash('TX interfaces saved. A changed interface list disables monitoring until explicitly re-enabled. Prepare and approve its matching collector before enabling.', 'success')
    return redirect(url_for('pages.monitoring'))
