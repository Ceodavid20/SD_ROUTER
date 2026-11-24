"""Deployment isolation and fail-closed production startup, before JSON I/O."""

from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit


def _path(value):
    path = Path(value).expanduser().absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Profile paths must not contain symbolic links.")
    return path


def profile_path(config, value):
    """Validate a private resource path without opening it or returning its data."""
    path = _path(value)
    if config.get("ENVIRONMENT", "development") != "development":
        root = _path(config["PROFILE_DIR"])
        if path == root or not path.is_relative_to(root):
            raise ValueError("Profile resources must be inside SDR_PROFILE_DIR.")
    return path


def _https_origin(value):
    try:
        url = urlsplit(value)
        return (url.scheme == "https" and bool(url.hostname) and bool(url.port or 443)
                and not url.username and not url.password and url.path in ("", "/")
                and not url.query and not url.fragment)
    except (ValueError, TypeError):
        return False


def loopback_proxy_options(host, proxy):
    """Both local backends trust forwarded headers from one explicit proxy only."""
    try:
        if host != "localhost" and not ip_address(host).is_loopback:
            raise ValueError
        if not proxy:
            return {}
        trusted = ip_address(proxy)
        if not trusted.is_loopback:
            raise ValueError
    except ValueError as exc:
        raise ValueError("Bind backends to loopback and configure one explicit loopback TLS proxy.") from exc
    return {"trusted_proxy": str(trusted), "trusted_proxy_count": 1,
            "trusted_proxy_headers": {"x-forwarded-for", "x-forwarded-proto"}}


def validate_deployment(config, *, setup=False):
    """No lab files are opened/created before production constraints are checked.

    An owner-only marker binds an isolated directory to exactly one environment.
    Existing unmarked data cannot be silently adopted as production data.
    setup permits creating administrator credentials before the first server run.
    """
    environment = config.get("ENVIRONMENT", "development")
    if environment not in ("development", "laboratory", "production"):
        raise ValueError("Invalid deployment environment.")
    isolated = environment != "development" or config.get("PROFILE_DIR") is not None
    if not isolated:
        return
    if not config.get("PROFILE_DIR"):
        raise ValueError("Set an isolated SDR_PROFILE_DIR.")
    root = _path(config["PROFILE_DIR"])
    from config import PROJECT_ROOT
    if root in (PROJECT_ROOT, Path(root.anchor)):
        raise ValueError("Use a dedicated profile directory, separate from the project root.")
    resources = [profile_path(config, config[key]) for key in (
        "DATA_DIR", "OUTPUT_DIR", "CONFIG_ENV_FILE", "API_CREDENTIALS_ENV_FILE",
        "CONTROLLER_CREDENTIALS_ENV_FILE",
    )]
    data, output = resources[:2]
    if data == output or data.is_relative_to(output) or output.is_relative_to(data):
        raise ValueError("DATA_DIR and OUTPUT_DIR must be separate directories.")
    for key in ("ROUTER_CA_FILE", "CONTROLLER_CA_FILE"):
        if config.get(key):
            profile_path(config, config[key])
    if config.get("PRIVATE_BUNDLE_DIR"):
        profile_path(config, config["PRIVATE_BUNDLE_DIR"])
    if environment == "production" and not setup:
        if (config.get("AUTH_ENABLED") is not True or not config.get("ADMIN_USERNAME")
                or not str(config.get("ADMIN_PASSWORD_HASH", "")).startswith(("scrypt:", "pbkdf2:"))
                or not isinstance(config.get("SECRET_KEY"), str) or len(config["SECRET_KEY"]) < 32
                or config.get("SESSION_COOKIE_SECURE") is not True):
            raise ValueError("Production requires administrator authentication, a persistent session key and secure cookies.")
        if (config.get("ALLOW_PLAINTEXT_API") is not False
                or config.get("LIVE_ROUTING_ENABLED") is not False
                or config.get("SIMULATION_MODE") is not True):
            raise ValueError("Production requires verified API TLS, SIMULATION_MODE=true and LIVE_ROUTING_ENABLED=false.")
        if not all(_https_origin(config.get(key, "")) for key in ("ADMIN_BASE_URL", "CONTROLLER_BASE_URL")):
            raise ValueError("Production requires HTTPS administrator and controller origins.")
        if not config.get("ROUTER_NETWORKS_EXPLICIT") or not config.get("ROUTER_ALLOWED_NETWORKS"):
            raise ValueError("Set explicit production router management networks.")
        try:
            for value in config["ROUTER_ALLOWED_NETWORKS"]:
                if ip_network(value).prefixlen == 0:
                    raise ValueError
        except ValueError as exc:
            raise ValueError("Configure bounded production router management networks.") from exc
        for key in ("ADMIN_HOST", "CONTROLLER_HOST"):
            loopback_proxy_options(config[key], config.get(key.replace("HOST", "TRUSTED_PROXY"), ""))
    if root.exists() and os.name != "nt" and root.stat().st_mode & 0o077:
        raise ValueError("Profile directories must have owner-only permissions.")
    for path in resources[2:]:
        if path.exists() and (not stat.S_ISREG(path.stat().st_mode)
                or (os.name != "nt" and path.stat().st_mode & 0o077)):
            raise ValueError("Profile configuration and credentials must be owner-only regular files.")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    # A separate lock avoids touching/recovering application data before isolation.
    descriptor = os.open(root / ".profile.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "r+b") as lock:
        import fcntl
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        marker = root / ".sdr-environment.json"
        if marker.is_symlink():
            raise ValueError("The environment marker must not be a symbolic link.")
        if marker.exists():
            if marker.stat().st_size > 1024:
                raise ValueError("Invalid environment marker.")
            try:
                saved = json.loads(marker.read_text())
            except (ValueError, UnicodeError) as exc:
                raise ValueError("Invalid environment marker.") from exc
            if saved != {"schema_version": 1, "environment": environment}:
                raise ValueError("This profile belongs to another environment. Use a separate profile directory.")
        else:
            if environment == "production" and any(path.exists() and any(path.iterdir()) for path in (data, output)):
                raise ValueError("Production cannot adopt unmarked existing data. Start with a new isolated profile.")
            with os.fdopen(os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600), "w") as stream:
                json.dump({"schema_version": 1, "environment": environment}, stream)
                stream.flush()
                os.fsync(stream.fileno())
