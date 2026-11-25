"""CSRF-protected edits to local routing path settings; no device requests."""

from flask import Blueprint, current_app, flash, redirect, request, url_for

from services.json_storage import ValidationError
from services.path_config_service import PathConfigService


routing_paths = Blueprint("routing_paths", __name__)


def _service() -> PathConfigService:
    return PathConfigService(current_app.extensions["json_storage"])


@routing_paths.post("/routing-paths/add")
def add_path():
    try:
        _service().add_path(request.form)
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Routing path added.", "success")
    return redirect(url_for("pages.routing_paths"))


@routing_paths.post("/routing-paths/<path_id>/save")
def save_path(path_id: str):
    try:
        _service().save_path(path_id, request.form)
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Routing path saved.", "success")
    return redirect(url_for("pages.routing_paths"))


@routing_paths.post("/routing-paths/<path_id>/delete")
def delete_path(path_id: str):
    try:
        _service().delete_path(path_id)
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Routing path removed.", "success")
    return redirect(url_for("pages.routing_paths"))


@routing_paths.post("/routing-paths/policy")
def save_policy():
    try:
        _service().save_congestion_policy(request.form)
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Congestion limits saved.", "success")
    return redirect(url_for("pages.routing_paths"))


@routing_paths.post("/routing-paths/<path_id>/jitter")
def save_jitter(path_id):
    try:
        if request.form.getlist("jitter_enabled") not in (["true"], ["false"]):
            raise ValidationError("Select enable or disable jitter monitoring.")
        _service().configure_jitter(path_id, request.form.get("jitter_target", ""),
            request.form["jitter_enabled"] == "true", current_app.config)
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("RTT jitter monitoring saved.", "success")
    return redirect(url_for("pages.routing_paths"))


@routing_paths.post("/routing-paths/<path_id>/live-sampling")
def save_live_sampling(path_id):
    try:
        if request.form.getlist("live_sampling_enabled") not in (["true"], ["false"]):
            raise ValidationError("Select enable or disable live sampling.")
        _service().configure_live_sampling(path_id, request.form["live_sampling_enabled"] == "true")
    except ValidationError as exc:
        flash(str(exc), "danger")
    else:
        flash("Live sampling saved.", "success")
    return redirect(url_for("pages.routing_paths"))
