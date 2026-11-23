"""Describe the configured device endpoint without registering any router."""

from collections.abc import Mapping
from ipaddress import ip_address
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from services.routeros_protocol import ROUTEROS_ACK_PATH, ROUTEROS_POLL_PATH, ROUTEROS_TRAFFIC_PATH


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _valid_host(host: str) -> bool:
    try:
        address = ip_address(host)
        return not address.is_unspecified and not address.is_multicast
    except ValueError:
        return bool(
            len(host) <= 253
            and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in host.rstrip(".").split("."))
        )


def connection_details(config: Mapping[str, Any]) -> dict[str, Any]:
    """Use explicit configuration, never the browser's Host/forwarded headers.

    Advertising a URL is not a reachability/TLS test or device enrollment.
    Invalid configuration is not echoed: a URL might contain a leaked secret.
    """
    details = {
        "endpoint_url": None, "scope": "not_configured", "configuration_error": None,
        "poll_path": ROUTEROS_POLL_PATH, "ack_path": ROUTEROS_ACK_PATH,
        "ack_endpoint_url": None, "traffic_path": ROUTEROS_TRAFFIC_PATH,
        "traffic_endpoint_url": None, "method": "POST",
        "protocol_version": "2.0", "authentication": "HMAC-SHA512",
        "poll_interval": config.get("ROUTER_POLL_INTERVAL", 60),
    }
    configured = config.get("CONTROLLER_BASE_URL", "")
    if configured:
        try:
            if not isinstance(configured, str) or len(configured) > 2048:
                raise ValueError
            base = configured.strip()
            parts = urlsplit(base)
            host = parts.hostname
            port = parts.port
            if (
                parts.scheme not in ("http", "https") or not host or not _valid_host(host)
                or parts.username is not None or parts.password is not None
                or parts.path not in ("", "/") or "?" in base or "#" in base
                or any(ord(c) <= 32 or ord(c) >= 127 for c in base)
                or (port is not None and not 1 <= port <= 65535)
                or (parts.scheme == "http" and not _is_loopback(host))
            ):
                raise ValueError
            details["endpoint_url"] = urlunsplit((parts.scheme, parts.netloc, ROUTEROS_POLL_PATH, "", ""))
            details["ack_endpoint_url"] = urlunsplit((parts.scheme, parts.netloc, ROUTEROS_ACK_PATH, "", ""))
            details["traffic_endpoint_url"] = urlunsplit((parts.scheme, parts.netloc, ROUTEROS_TRAFFIC_PATH, "", ""))
            details["scope"] = "local" if _is_loopback(host) else "configured"
            return details
        except (ValueError, TypeError):
            details["configuration_error"] = (
                "Set CONTROLLER_BASE_URL to the approved HTTPS server origin, "
                "without credentials, a path, query parameters, or a fragment. "
                "HTTP is accepted only for a local loopback test."
            )
            return details
    host = config.get("CONTROLLER_HOST", "127.0.0.1")
    port = config.get("CONTROLLER_PORT", 8001)
    if isinstance(host, str) and _is_loopback(host) and type(port) is int and 1 <= port <= 65535:
        authority = f"[{host}]" if ":" in host else host
        details["endpoint_url"] = f"http://{authority}:{port}{ROUTEROS_POLL_PATH}"
        details["ack_endpoint_url"] = f"http://{authority}:{port}{ROUTEROS_ACK_PATH}"
        details["traffic_endpoint_url"] = f"http://{authority}:{port}{ROUTEROS_TRAFFIC_PATH}"
        details["scope"] = "local"
    else:
        details["configuration_error"] = "Set CONTROLLER_BASE_URL to the approved controller address before device setup."
    return details
