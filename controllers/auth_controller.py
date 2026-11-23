"""The local administrator signs in before opening company operations."""

import hmac

from flask import Blueprint, Response, current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from services.security_service import admin_fingerprint, admin_is_authenticated, admin_is_configured


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["GET", "POST"])
def login() -> Response | str | tuple[str, int]:
    if admin_is_authenticated():
        return redirect(url_for("pages.dashboard"))
    if not admin_is_configured():
        return render_template("login.html", setup_required=True, error=None), 503
    if request.method == "GET":
        return render_template("login.html", setup_required=False, error=None)

    throttle = current_app.extensions["login_throttle"]
    if not throttle.allow_attempt():
        return render_template(
            "login.html", setup_required=False,
            error="Too many sign-in attempts. Try again in five minutes.",
        ), 429

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_valid = len(password) <= 1024 and check_password_hash(
        current_app.config["ADMIN_PASSWORD_HASH"], password
    )
    if not (
        hmac.compare_digest(username.encode(), current_app.config["ADMIN_USERNAME"].encode())
        and password_valid
    ):
        return render_template(
            "login.html", setup_required=False,
            error="The username or password is incorrect.",
        ), 401

    session.clear()
    session["admin_user"] = username
    session["admin_fingerprint"] = admin_fingerprint()
    session.permanent = True
    current_app.extensions["json_storage"].append_activity(
        "security", "Administrator signed in."
    )
    return redirect(url_for("pages.dashboard"))


@auth.post("/logout")
def logout() -> Response:
    session.clear()
    return redirect(url_for("auth.login"))
