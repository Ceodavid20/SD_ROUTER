"""Read process configuration from the environment and the local .env file."""

import os
from datetime import timedelta
from pathlib import Path
from typing import Any
from dotenv import dotenv_values
PROJECT_ROOT = Path(__file__).resolve().parent
def _integer_env(values, name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(values.get(name, str(default)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a whole number.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its supported range.")
    return value
def load_config() -> dict[str, Any]:
    # Profile selection comes from the launch environment, never the lab .env.
    # Parsing locally prevents credentials leaking between app/profile instances.
    environment = os.environ.get("SDR_ENV", "development")
    if environment not in ("development", "laboratory", "production"):
        raise ValueError("SDR_ENV must be development, laboratory or production.")
    profile = os.environ.get("SDR_PROFILE_DIR", "")
    if environment != "development" and not profile:
        raise ValueError("Set an isolated SDR_PROFILE_DIR for laboratory or production.")
    root = Path(profile).expanduser().absolute() if profile else PROJECT_ROOT
    env_file = Path(os.environ.get("SDR_ENV_FILE", root / ".env")).expanduser().absolute()
    values = {**dotenv_values(env_file, interpolate=False), **os.environ}

    def boolean(name, default):
        value = values.get(name, str(default).lower())
        if value not in ("true", "false"):
            raise ValueError(f"{name} must be true or false.")
        return value == "true"

    def integer(name, default, minimum, maximum):
        return _integer_env(values, name, default, minimum, maximum)

    return {
        "ENVIRONMENT": environment,
        "PROFILE_DIR": root if profile else None,
        "CONFIG_ENV_FILE": env_file,
        "ADMIN_HOST": values.get("SDR_ADMIN_HOST", "127.0.0.1"),
        "ADMIN_PORT": integer("SDR_ADMIN_PORT", 8000, 1, 65535),
        "ADMIN_BASE_URL": values.get("SDR_ADMIN_BASE_URL", ""),
        "ADMIN_TRUSTED_PROXY": values.get("SDR_ADMIN_TRUSTED_PROXY", ""),
        # Device communication is a separate listener; the browser app stays local.
        "CONTROLLER_HOST": values.get("CONTROLLER_HOST", "127.0.0.1"),
        "CONTROLLER_PORT": integer("CONTROLLER_PORT", 8001, 1, 65535),
        "CONTROLLER_BASE_URL": values.get("CONTROLLER_BASE_URL", ""),
        "CONTROLLER_TRUSTED_PROXY": values.get("CONTROLLER_TRUSTED_PROXY", ""),
        "SIMULATION_MODE": boolean("SIMULATION_MODE", True),
        "LIVE_ROUTING_ENABLED": boolean("LIVE_ROUTING_ENABLED", False),
        "ROUTER_POLL_INTERVAL": integer("ROUTER_POLL_INTERVAL", 60, 1, 86400),
        "ROUTER_REQUEST_MAX_AGE_SECONDS": integer("ROUTER_REQUEST_MAX_AGE_SECONDS", 120, 1, 86400),
        "ROUTER_CLOCK_SKEW_SECONDS": integer("ROUTER_CLOCK_SKEW_SECONDS", 30, 0, 86400),
        "ROUTER_RESPONSE_TTL_SECONDS": integer("ROUTER_RESPONSE_TTL_SECONDS", 60, 1, 300),
        "ROUTER_RATE_LIMIT_ATTEMPTS": integer("ROUTER_RATE_LIMIT_ATTEMPTS", 30, 1, 1_000_000),
        "ROUTER_RATE_LIMIT_WINDOW_SECONDS": integer("ROUTER_RATE_LIMIT_WINDOW_SECONDS", 60, 1, 86400),
        "SECRET_KEY": values.get("SDR_SECRET_KEY") or None,
        "COMPANY_NAME": values.get("SDR_COMPANY_NAME", "Network Operations"),
        "AUTH_ENABLED": boolean("SDR_AUTH_ENABLED", False),
        "ADMIN_USERNAME": values.get("SDR_ADMIN_USERNAME", ""),
        "ADMIN_PASSWORD_HASH": values.get("SDR_ADMIN_PASSWORD_HASH", ""),
        "ROUTER_CONFIG_TOKEN": values.get("SDR_ROUTER_CONFIG_TOKEN", ""),
        "ALLOW_PLAINTEXT_API": boolean("SDR_ALLOW_PLAINTEXT_API", False),
        "ROUTER_ALLOWED_NETWORKS": [
            value.strip()
            for value in values.get(
                "SDR_ROUTER_ALLOWED_NETWORKS",
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",
            ).split(",")
            if value.strip()
        ],
        "ROUTER_NETWORKS_EXPLICIT": bool(values.get("SDR_ROUTER_ALLOWED_NETWORKS")),
        "ROUTER_CA_FILE": values.get("SDR_ROUTER_CA_FILE") or None,
        "CONTROLLER_CA_FILE": values.get("SDR_CONTROLLER_CA_FILE") or None,
        "PRIVATE_BUNDLE_DIR": Path(values.get("SDR_PRIVATE_BUNDLE_DIR") or root / "private" / "router-bundles"),
        "API_CREDENTIALS_ENV_FILE": Path(values.get("SDR_API_CREDENTIALS_FILE") or env_file),
        "CONTROLLER_CREDENTIALS_ENV_FILE": Path(values.get("SDR_CONTROLLER_CREDENTIALS_FILE") or env_file),
        "ENROLLMENT_ENABLED": boolean("SDR_ENROLLMENT_ENABLED", False),
        "TRAFFIC_DISPLAY_UNIT": values.get("SDR_TRAFFIC_DISPLAY_UNIT", "Mbps"),
        "API_TIMEOUT_SECONDS": integer("SDR_API_TIMEOUT_SECONDS", 3, 1, 60),
        "DISCOVERY_TIMEOUT_SECONDS": integer("SDR_DISCOVERY_TIMEOUT_SECONDS", 15, 1, 120),
        "ONBOARDING_DISCOVERY_MAX_AGE_SECONDS": integer("SDR_DISCOVERY_MAX_AGE_SECONDS", 900, 1, 86400),
        "ROUTER_FETCH_TIMEOUT_SECONDS": integer("SDR_ROUTER_FETCH_TIMEOUT_SECONDS", 10, 1, 60),
        "ROUTER_BOOTSTRAP_TIMEOUT_SECONDS": integer("SDR_BOOTSTRAP_TIMEOUT_SECONDS", 15, 1, 60),
        "DASHBOARD_REFRESH_SECONDS": integer("SDR_DASHBOARD_REFRESH_SECONDS", 5, 2, 300),
        "BROWSER_REQUEST_TIMEOUT_SECONDS": integer("SDR_BROWSER_TIMEOUT_SECONDS", 10, 1, 120),
        "MAX_CONTENT_LENGTH": 64 * 1024,
        "MAX_FORM_MEMORY_SIZE": 64 * 1024,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": boolean("SDR_COOKIE_SECURE", False),
        "PERMANENT_SESSION_LIFETIME": timedelta(minutes=integer("SDR_SESSION_MINUTES", 30, 1, 1440)),
        "DATA_DIR": Path(values.get("SDR_DATA_DIR", root / "data")),
        "OUTPUT_DIR": Path(
            values.get("SDR_OUTPUT_DIR", root / "output")
        ),
    }
