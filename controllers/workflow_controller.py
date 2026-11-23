"""Manual local calculations/settings using existing administrator/CSRF guards."""

from flask import Blueprint, current_app, flash, redirect, request, url_for

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
              else "Analysis saved. Review the requirements before a recommendation can be produced.",
              "success" if result["status"] == "ready" else "warning")
    destination = request.form.get("destination", "optimization")
    return redirect(url_for("pages.mathematics" if destination == "mathematics" else "pages.optimization"))


@workflow.post("/workflow/settings")
def save_settings():
    try:
        _service().save_settings(request.form)
    except WorkflowError as exc:
        flash(str(exc), "danger")
    else:
        flash("Local calculation settings saved. Routing changes remain off.", "success")
    return redirect(url_for("pages.settings"))
