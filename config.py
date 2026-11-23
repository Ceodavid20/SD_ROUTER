"""Read process configuration from the environment and the local .env file."""

import os
from datetime import timedelta
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
PROJECT_ROOT = Path(__file__).resolve().parent
def _integer_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a whole number.") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its supported range.")
    return value
def load_config() -> dict[str, Any]:
    load_dotenv(PROJECT_ROOT / ".env", override=False)
    return {
        # Device communication is a separate listener; the browser app stays local.
        "CONTROLLER_HOST": os.environ.get("CONTROLLER_HOST", "127.0.0.1"),
        "CONTROLLER_PORT": _integer_env("CONTROLLER_PORT", 8001, 1, 65535),
        "CONTROLLER_BASE_URL": os.environ.get("CONTROLLER_BASE_URL", ""),
        "CONTROLLER_TRUSTED_PROXY": os.environ.get("CONTROLLER_TRUSTED_PROXY", ""),
        "SIMULATION_MODE": os.environ.get("SIMULATION_MODE", "true").lower() == "true",
        "LIVE_ROUTING_ENABLED": os.environ.get("LIVE_ROUTING_ENABLED", "false").lower() == "true",
        "ROUTER_POLL_INTERVAL": _integer_env("ROUTER_POLL_INTERVAL", 60, 1, 86400),
        "ROUTER_REQUEST_MAX_AGE_SECONDS": _integer_env("ROUTER_REQUEST_MAX_AGE_SECONDS", 120, 1, 86400),
        "ROUTER_CLOCK_SKEW_SECONDS": _integer_env("ROUTER_CLOCK_SKEW_SECONDS", 30, 0, 86400),
        "ROUTER_RESPONSE_TTL_SECONDS": _integer_env("ROUTER_RESPONSE_TTL_SECONDS", 60, 1, 300),
        "ROUTER_RATE_LIMIT_ATTEMPTS": _integer_env("ROUTER_RATE_LIMIT_ATTEMPTS", 30, 1, 1_000_000),
        "ROUTER_RATE_LIMIT_WINDOW_SECONDS": _integer_env("ROUTER_RATE_LIMIT_WINDOW_SECONDS", 60, 1, 86400),
        "SECRET_KEY": os.environ.get("SDR_SECRET_KEY") or None,
        "COMPANY_NAME": os.environ.get("SDR_COMPANY_NAME", "Network Operations"),
        "AUTH_ENABLED": os.environ.get("SDR_AUTH_ENABLED", "false").lower() == "true",
        "ADMIN_USERNAME": os.environ.get("SDR_ADMIN_USERNAME", ""),
        "ADMIN_PASSWORD_HASH": os.environ.get("SDR_ADMIN_PASSWORD_HASH", ""),
        "ROUTER_CONFIG_TOKEN": os.environ.get("SDR_ROUTER_CONFIG_TOKEN", ""),
        "ALLOW_PLAINTEXT_API": os.environ.get("SDR_ALLOW_PLAINTEXT_API", "false").lower() == "true",
        "ROUTER_ALLOWED_NETWORKS": [
            value.strip()
            for value in os.environ.get(
                "SDR_ROUTER_ALLOWED_NETWORKS",
                "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7",
            ).split(",")
            if value.strip()
        ],
        "ROUTER_CA_FILE": os.environ.get("SDR_ROUTER_CA_FILE") or None,
        "API_CREDENTIALS_ENV_FILE": PROJECT_ROOT / ".env",
        "API_TIMEOUT_SECONDS": 3,
        "MAX_CONTENT_LENGTH": 64 * 1024,
        "MAX_FORM_MEMORY_SIZE": 64 * 1024,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": os.environ.get("SDR_COOKIE_SECURE", "false").lower() == "true",
        "PERMANENT_SESSION_LIFETIME": timedelta(minutes=30),
        "DATA_DIR": Path(os.environ.get("SDR_DATA_DIR", PROJECT_ROOT / "data")),
        "OUTPUT_DIR": Path(
            os.environ.get("SDR_OUTPUT_DIR", PROJECT_ROOT / "output")
        ),
    }
