"""Private local API credentials; no router connections or credential output."""

from io import StringIO
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat

from dotenv import dotenv_values

from services.env_storage import update_private_environment
from services.router_protocol import ROUTER_ID


class APICredentialError(ValueError):
    """Credential-free error suitable for the local setup command and UI."""


def api_credentials(router, config):
    reference = router.get("credential_ref")
    if not isinstance(reference, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reference):
        return "", ""
    if router.get("api_credentials_source") != "private_env":
        return os.environ.get(reference + "_USERNAME", ""), os.environ.get(reference + "_PASSWORD", "")
    values = private_environment(config["API_CREDENTIALS_ENV_FILE"])
    return values.get(reference + "_USERNAME") or "", values.get(reference + "_PASSWORD") or ""


def private_environment(filename):
    """Read an owner-only credential snapshot without exposing its contents."""
    # Managed references deliberately read the atomically replaced private
    # file on demand, so configuring credentials needs no server restart.
    path = Path(filename)
    try:
        if path.is_symlink():
            raise APICredentialError("The private API credentials file must not be a symbolic link.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise APICredentialError("The private API credentials file is unavailable.")
            if os.name != "nt" and info.st_mode & 0o077:
                raise APICredentialError("The private API credentials file must have owner-only permissions.")
            values = dotenv_values(stream=StringIO(stream.read()), interpolate=False)
    except (OSError, UnicodeError) as exc:
        raise APICredentialError("Private API credentials are unavailable. Run the local credential setup command.") from exc
    return values


def controller_secret(router, key_id, config):
    name = f'{router["controller_auth_ref"]}_{key_id}_SECRET'
    if router.get("controller_credentials_source") == "private_env":
        return private_environment(config["CONTROLLER_CREDENTIALS_ENV_FILE"]).get(name) or ""
    return os.environ.get(name, "")


def registered_api_target(storage, router_id):
    if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
        raise APICredentialError("Enter a valid registered router ID.")
    router = next((row for row in storage.read_json("routers.json") if row["router_id"] == router_id), None)
    if router is None:
        raise APICredentialError("The router is not registered. This command cannot create a router.")
    return router


def configure_api_credentials(storage, config, router_id, username, password):
    """Store secrets first, then bind one existing router to a fresh reference.

    Existing transport/network policy, polling keys, TX configuration and
    routing locks are preserved. A concurrent endpoint/auth edit fails closed.
    """
    router = registered_api_target(storage, router_id)
    if (not isinstance(username, str) or not username.strip() or len(username) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in username)):
        raise APICredentialError("Enter a valid API username of at most 128 characters.")
    if (not isinstance(password, str) or not 1 <= len(password) <= 4096
            or any(c in password for c in ("\0", "\n", "\r"))):
        raise APICredentialError("Use a nonempty API password of at most 4096 characters without line breaks.")
    reference = "SDR_API_" + hashlib.sha256(router_id.encode()).hexdigest()[:16].upper() + "_" + secrets.token_hex(4).upper()
    username_key, password_key = reference + "_USERNAME", reference + "_PASSWORD"

    def save(values):
        if any(key in values or key in os.environ for key in (username_key, password_key)):
            raise APICredentialError("A credential reference collision occurred. Run setup again.")
        return {username_key: username.strip(), password_key: password}

    update_private_environment(config["API_CREDENTIALS_ENV_FILE"], save)
    fields = ("ip_address", "api_port", "api_tls", "credential_ref", "api_credentials_source")

    def bind(rows):
        current = next((row for row in rows if row["router_id"] == router_id), None)
        if current is None or any(current.get(key) != router.get(key) for key in fields):
            raise APICredentialError("Router API settings changed during setup. Run setup again.")
        current.update(credential_ref=reference, api_credentials_source="private_env",
                       connection_status="untested", last_checked_at=None, last_error=None)
        return rows

    storage.update_json("routers.json", bind)
    storage.append_activity("security", "Router API credentials configured privately.", {"router_id": router_id})
