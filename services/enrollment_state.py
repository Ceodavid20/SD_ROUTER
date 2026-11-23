"""Bounded, hash-only enrollment grants and a recoverable registry commit."""

import re
from ipaddress import ip_address

from services.json_storage import ValidationError
from services.router_protocol import ROUTER_ID, ProtocolError, parse_utc_timestamp
from services.routeros_protocol import _uuid4
from services.traffic_protocol import validate_interface


ENROLLMENT_DOCUMENT = "router_enrollment.json"
MAX_GRANTS = 1024
GRANT_FIELDS = {
    "token_hash", "created_at", "expires_at", "used_at", "router_id", "name", "carrier",
    "outbound_interface", "management_interface", "management_ip", "chr_lab", "enable_monitoring",
    "interval_seconds", "bind_source", "replace_existing", "enrolled_router_id", "used_request_id",
}


def validate_enrollment_state(state):
    if (not isinstance(state, dict) or set(state) != {"schema_version", "grants", "rate_limits", "pending"}
            or type(state["schema_version"]) is not int or state["schema_version"] != 1
            or not isinstance(state["grants"], dict) or len(state["grants"]) > MAX_GRANTS):
        raise ValidationError("Invalid enrollment state.")
    from services.router_communication_state import validate_communication_state
    validate_communication_state({"schema_version": 1, "routers": {}, "seen_requests": [], "rate_limits": state["rate_limits"]})
    try:
        for grant_id, grant in state["grants"].items():
            if (not isinstance(grant_id, str) or not re.fullmatch(r"[0-9a-f]{32}", grant_id)
                    or not isinstance(grant, dict) or set(grant) != GRANT_FIELDS
                    or not isinstance(grant["token_hash"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", grant["token_hash"])):
                raise ValidationError("Invalid enrollment grant.")
            created = parse_utc_timestamp(grant["created_at"])
            expires = parse_utc_timestamp(grant["expires_at"])
            if not 60 <= (expires - created).total_seconds() <= 86400:
                raise ValidationError("Invalid enrollment expiry.")
            for key in ("router_id", "enrolled_router_id"):
                if grant[key] is not None and (not isinstance(grant[key], str) or not ROUTER_ID.fullmatch(grant[key])):
                    raise ValidationError("Invalid enrollment router identity.")
            for key in ("chr_lab", "enable_monitoring", "bind_source", "replace_existing"):
                if type(grant[key]) is not bool:
                    raise ValidationError("Invalid enrollment policy flag.")
            if type(grant["interval_seconds"]) is not int or not 1 <= grant["interval_seconds"] <= 86400:
                raise ValidationError("Invalid enrollment monitoring interval.")
            validate_interface(grant["outbound_interface"])
            if grant["management_interface"]:
                validate_interface(grant["management_interface"])
            for key in ("name", "carrier", "management_ip", "management_interface"):
                value = grant[key]
                if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise ValidationError("Invalid enrollment metadata.")
            if grant["management_ip"]:
                address = ip_address(grant["management_ip"])
                if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                    raise ValidationError("Invalid enrollment management address.")
            if grant["bind_source"] and not grant["management_ip"]:
                raise ValidationError("A source-bound enrollment needs its address.")
            if grant["used_at"] is None:
                if grant["used_request_id"] is not None or grant["enrolled_router_id"] is not None:
                    raise ValidationError("Inconsistent unused enrollment grant.")
            else:
                used = parse_utc_timestamp(grant["used_at"])
                if not created <= used < expires or grant["enrolled_router_id"] is None:
                    raise ValidationError("Invalid enrollment consumption.")
                _uuid4(grant["used_request_id"])
        pending = state["pending"]
        if pending is not None:
            if (not isinstance(pending, dict)
                    or set(pending) != {"grant_id", "router", "previous_router_digest"}
                    or pending["grant_id"] not in state["grants"]
                    or not isinstance(pending["router"], dict)):
                raise ValidationError("Invalid pending enrollment.")
            grant = state["grants"][pending["grant_id"]]
            row = pending["router"]
            if (grant["used_at"] is None or row.get("router_id") != grant["enrolled_router_id"]
                    or row.get("controller_credentials_source") != "private_env"
                    or row.get("controller_auth_enabled") is not True):
                raise ValidationError("Inconsistent pending enrollment identity.")
            digest = pending["previous_router_digest"]
            if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValidationError("Invalid pending enrollment comparison.")
    except (ProtocolError, ValueError, KeyError, TypeError) as exc:
        raise ValidationError("Invalid enrollment state.") from exc
