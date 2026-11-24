"""Manual local calculations/settings using existing administrator/CSRF guards."""

from flask import Blueprint, current_app, flash, redirect, request, url_for, jsonify

from services.workflow_service import WorkflowError, WorkflowService


workflow = Blueprint("workflow", __name__)


def _service():
    return WorkflowService(current_app.extensions["json_storage"], current_app.config)


@workflow.post("/workflow/calculate")
def calculate():
    try:
        result = _service().calculate()
    except WorkflowError as exc:
        flash(str(exc), "danger")
    else:
        flash("Dry-run calculation completed. Routing changes remain off." if result["status"] == "ready"
              else "Optimization status saved. Review the requirements before a recommendation can be produced.",
              "success" if result["status"] == "ready" else "warning")
    return redirect(url_for("pages.optimization"))


@workflow.post("/workflow/settings")
def save_settings():
    try:
        _service().save_settings(request.form)
    except WorkflowError as exc:
        flash(str(exc), "danger")
    else:
        flash("Local calculation settings saved. Routing changes remain off.", "success")
    return redirect(url_for("pages.settings"))


@workflow.post("/workflow/optimization")
def set_optimization():
    values = request.form.getlist("optimization_enabled")
    if values not in (["true"], ["false"]):
        return jsonify(error="Select On or Off for optimization."), 400
    enabled = values == ["true"]
    service = _service()
    service.set_optimization_enabled(enabled)
    if enabled:
        # Start immediately; a simultaneous Off remains authoritative because
        # calculate rechecks the switch under the publication lock.
        try:
            service.calculate()
        except WorkflowError:
            pass
    actual = current_app.extensions["json_storage"].read_json("automation_settings.json").get("optimization_enabled", True)
    if request.accept_mimetypes.best == "application/json":
        response = jsonify(optimization_enabled=actual, routing_changes_enabled=False)
        response.cache_control.no_store = True
        return response
    flash("Optimization on." if actual else "Optimization off.", "success")
    return redirect(url_for("pages.optimization"))
