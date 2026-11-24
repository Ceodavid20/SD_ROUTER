"""Single-use enrollment over verified TLS; no device connection from Flask."""

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import ssl
from ipaddress import ip_address
from uuid import uuid4

from services.controller_setup_service import _https_origin, _new_private_directory, _private_file, _routeros_string
from services.enrollment_state import ENROLLMENT_DOCUMENT, MAX_GRANTS
from services.env_storage import update_private_environment
from services.json_storage import StorageError, StorageService
from services.router_protocol import ROUTER_ID, ProtocolError, parse_utc_timestamp, utc_text
from services.router_service import RouterService
from services.router_poll_service import PollError, RouterPollService
from services.routeros_protocol import _uuid4
from services.traffic_protocol import validate_interface
from services.traffic_setup_service import render_traffic_script


ENROLLMENT_PATH = "/api/controller/v2/enroll"
TOKEN = re.compile(r"([0-9a-f]{32})\.([A-Za-z0-9_-]{43})\Z")
REQUEST_FIELDS = {"protocol_version", "request_type", "request_id", "timestamp", "router_name", "device_id", "interface"}


def render_bootstrap(token, origin, interface, ca_name, *, fetch_timeout_seconds=15):
    if type(fetch_timeout_seconds) is not int or not 1 <= fetch_timeout_seconds <= 60:
        raise ValueError("Invalid bootstrap fetch timeout.")
    if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
        raise ValueError("Invalid private bootstrap authorization.")
    validate_interface(interface)
    if not isinstance(ca_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", ca_name):
        raise ValueError("Use a safe bootstrap CA file name.")
    template = (Path(__file__).resolve().parents[1] / "scripts/routeros/controller_bootstrap.rsc").read_text()
    values = {"__ENROLLMENT_TOKEN__": token, "__CONTROLLER_ORIGIN__": _https_origin(origin),
              "__OUTBOUND_INTERFACE__": interface, "__CA_FILENAME__": ca_name,
              "__FETCH_TIMEOUT_SECONDS__": str(fetch_timeout_seconds)}
    preflight = (Path(__file__).resolve().parents[1] / "scripts/routeros/controller_preflight.rsc").read_text()
    return preflight + "\n" + re.sub(r"__[A-Z_]+__", lambda m: _routeros_string(values[m.group()]), template)


def _request(raw):
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= 8192:
            raise ValueError
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=StorageService._unique_object,
                          parse_constant=StorageService._invalid_constant)
        if not isinstance(body, dict) or set(body) != REQUEST_FIELDS:
            raise ValueError
        if body["protocol_version"] != "1.0" or body["request_type"] != "enroll":
            raise ValueError
        _uuid4(body["request_id"])
        if type(body["timestamp"]) is not int or not 0 < body["timestamp"] < 2**53:
            raise ValueError
        name = body["router_name"]
        if not isinstance(name, str) or not name.strip() or len(name) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError
        if not isinstance(body["device_id"], str) or not re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", body["device_id"]):
            raise ValueError
        validate_interface(body["interface"])
        return body
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, ProtocolError) as exc:
        raise PollError("Invalid enrollment request.", 400, "invalid_enrollment") from exc


def create_enrollment_grant(storage, config, output_dir, ca_file, *, interface,
                            router_id=None, name="", carrier="", management_ip="",
                            management_interface="", chr_lab=False, enable_monitoring=False,
                            bind_source=False, replace_existing=False, interval_seconds=None,
                            ttl_seconds=900, now=None):
    """Prepare initial trust privately. This makes no router configuration changes."""
    from services.deployment_service import profile_path
    profile_path(config, output_dir)
    profile_path(config, ca_file)
    if config.get("ENVIRONMENT") == "production" and (chr_lab or enable_monitoring):
        raise ValueError("Production enrollment requires a non-lab identity and baseline review before monitoring opt-in.")
    current = now or datetime.now(UTC)
    if current.utcoffset() is None:
        raise ValueError("A timezone-aware enrollment time is required.")
    if router_id is not None and (not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id)):
        raise ValueError("Enter a valid optional router identity.")
    validate_interface(interface)
    if management_interface:
        validate_interface(management_interface)
    if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
        raise ValueError("Enrollment tokens must expire in 60 to 86400 seconds.")
    if any(type(value) is not bool for value in (chr_lab, enable_monitoring, bind_source, replace_existing)):
        raise ValueError("Enrollment policy flags must be booleans.")
    interval = interval_seconds if interval_seconds is not None else storage.read_json("automation_settings.json")["monitoring_interval_seconds"]
    if type(interval) is not int or not 1 <= interval <= 86400:
        raise ValueError("Choose a monitoring interval from 1 to 86400 seconds.")
    for value in (name, carrier, management_interface, management_ip):
        if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("Enter valid enrollment metadata.")
    RouterService(storage, config)._validated({"router_id": router_id or "PENDING", "name": name or "Pending router",
        "ip_address": management_ip, "interface_name": interface}, allow_pending_address=True)
    if bind_source and not management_ip:
        raise ValueError("A fixed source binding requires its configured address.")
    origin = _https_origin(config.get("CONTROLLER_BASE_URL", ""))
    ca = Path(ca_file).expanduser().resolve()
    ca_bytes = ca.read_bytes()
    if b"PRIVATE KEY" in ca_bytes:
        raise ValueError("Supply a public CA certificate, never a private key.")
    ssl.create_default_context(cafile=ca)
    token_id = secrets.token_hex(16)
    token = token_id + "." + secrets.token_urlsafe(32)
    expires = current + timedelta(seconds=ttl_seconds)
    grant = {"token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "created_at": utc_text(current), "expires_at": utc_text(expires), "used_at": None,
        "router_id": router_id, "name": name, "carrier": carrier, "outbound_interface": interface,
        "management_interface": management_interface, "management_ip": management_ip,
        "chr_lab": chr_lab, "enable_monitoring": enable_monitoring, "interval_seconds": interval,
        "bind_source": bind_source, "replace_existing": replace_existing,
        "enrolled_router_id": None, "used_request_id": None}
    target = _new_private_directory(output_dir)
    ca_name = "sdr-bootstrap-ca-" + token_id + ".pem"
    script = render_bootstrap(token, origin, interface, ca_name, fetch_timeout_seconds=config.get("ROUTER_BOOTSTRAP_TIMEOUT_SECONDS",15))
    _private_file(target / ca_name, ca_bytes)
    _private_file(target / "bootstrap.rsc", script)
    def save(state):
        state["grants"] = {key: value for key, value in state["grants"].items()
                           if parse_utc_timestamp(value["expires_at"]) >= current - timedelta(days=1)}
        if len(state["grants"]) >= MAX_GRANTS:
            raise ValueError("Enrollment grant capacity reached; review old authorizations.")
        state["grants"][token_id] = grant
        return state
    storage.update_json(ENROLLMENT_DOCUMENT, save)
    storage.append_activity("enrollment", "Single-use router bootstrap authorization created.")
    return {"output_dir": str(target), "enrollment_id": token_id, "expires_at": utc_text(expires),
            "bootstrap_script": str(target / "bootstrap.rsc"), "ca_certificate": str(target / ca_name)}


class EnrollmentService:
    def __init__(self, storage, config):
        self.storage, self.config = storage, config

    def check_rate_limit(self, source, now=None):
        RouterPollService(self.storage, self.config).check_rate_limit(source, now, state_document=ENROLLMENT_DOCUMENT)

    def enroll(self, raw, authorization, source, *, now=None, count_attempt=True):
        current = now or datetime.now(UTC)
        if not isinstance(current, datetime) or current.utcoffset() is None:
            raise PollError("Controller time is unavailable.", 503, "clock_unavailable")
        if count_attempt:
            self.check_rate_limit(source, current)
        if self.config.get("ENROLLMENT_ENABLED") is not True:
            raise PollError("Router enrollment is not enabled.", 503, "enrollment_disabled")
        body = _request(raw)
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise PollError("Enrollment authorization failed.", 401, "enrollment_unauthorized")
        token = authorization[7:]
        match = TOKEN.fullmatch(token) if len(token) <= 128 else None
        if match is None:
            raise PollError("Enrollment authorization failed.", 401, "enrollment_unauthorized")
        token_id = match[1]
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        age = current.timestamp() - body["timestamp"]
        if age > self.config.get("ROUTER_REQUEST_MAX_AGE_SECONDS", 120) or age < -self.config.get("ROUTER_CLOCK_SKEW_SECONDS", 30):
            raise PollError("Enrollment authorization failed.", 401, "enrollment_unauthorized")
        def prepare(state, routers):
            grant = state["grants"].get(token_id)
            if not hmac.compare_digest(token_hash, grant["token_hash"] if grant else "0" * 64) or grant is None:
                raise PollError("Enrollment authorization failed.", 401, "enrollment_unauthorized")
            if parse_utc_timestamp(grant["expires_at"]) <= current:
                raise PollError("Enrollment authorization failed.", 401, "enrollment_unauthorized")
            if grant["used_at"] is not None:
                raise PollError("This enrollment authorization has already been used.", 409, "enrollment_used")
            if body["interface"] != grant["outbound_interface"]:
                raise PollError("Enrollment request does not match its authorization.", 403, "enrollment_scope")
            if grant["bind_source"]:
                try:
                    matches_source = ip_address(source) == ip_address(grant["management_ip"])
                except (TypeError, ValueError):
                    matches_source = False
                if not matches_source:
                    raise PollError("Enrollment request does not match its authorization.", 403, "enrollment_scope")
            router_id = grant["router_id"] or "RTR-" + secrets.token_hex(10)
            existing = next((r for r in routers if r["router_id"] == router_id), None)
            if grant["management_ip"] and any(r.get("ip_address") == grant["management_ip"] and r["router_id"] != router_id for r in routers):
                raise PollError("This management address is already registered.", 409, "enrollment_existing")
            if existing and existing.get("controller_auth_enabled") is True and not grant["replace_existing"]:
                raise PollError("This router requires explicit re-enrollment authorization.", 409, "enrollment_existing")
            if existing and grant["management_ip"] and existing.get("ip_address") not in ("", grant["management_ip"]):
                raise PollError("Existing router configuration conflicts with enrollment.", 409, "enrollment_existing")
            record = RouterService(self.storage, self.config)._validated({
                "router_id": router_id, "name": grant["name"] or body["router_name"],
                "ip_address": grant["management_ip"], "interface_name": grant["outbound_interface"],
            }, allow_pending_address=True)
            router = {**record, **(existing or {})}
            router.setdefault("capacity_confirmed", existing is not None and existing.get("capacity_mbps") is not None)
            reference = "SDR_ENROLL_" + secrets.token_hex(10).upper()
            key_id, secret = "E" + secrets.token_hex(10).upper(), secrets.token_hex(32)
            collector = render_traffic_script(router_id, key_id, secret,
                _https_origin(self.config["CONTROLLER_BASE_URL"]), grant["outbound_interface"],
                fetch_timeout_seconds=self.config.get("ROUTER_FETCH_TIMEOUT_SECONDS",10))
            if grant["enable_monitoring"]:
                collector = collector.replace(":local sdrTrafficEnabled false;", ":local sdrTrafficEnabled true;", 1)
            router.update(name=grant["name"] or body["router_name"], interface_name=grant["outbound_interface"],
                management_interface=grant["management_interface"], carrier=grant["carrier"],
                router_role=(existing or {}).get("router_role") or ("carrier" if grant["carrier"] else "unassigned"),
                deployment_kind="chr_lab" if grant["chr_lab"] else (existing or {}).get("deployment_kind", "unspecified"),
                inventory_generation=(existing or {}).get("inventory_generation") or str(uuid4()),
                controller_auth_ref=reference, controller_auth_key_ids=[key_id], controller_auth_enabled=True,
                controller_credentials_source="private_env", monitoring_enabled=grant["enable_monitoring"],
                monitoring_generation=str(uuid4()), monitoring_interval_seconds=grant["interval_seconds"],
                enrollment_id=token_id, enrolled_at=utc_text(current), bootstrap_device_id=body["device_id"],
                integration_status="enrolled_awaiting_samples", traffic_origin="routeros_tx_counter")
            if grant["management_ip"]:
                router["ip_address"] = grant["management_ip"]
            if grant["bind_source"]:
                router["traffic_source_ip"] = grant["management_ip"]
            else:
                router.pop("traffic_source_ip", None)
            variable = f"{reference}_{key_id}_SECRET"
            def credential(values):
                if variable in values or variable in os.environ:
                    raise ValueError("Enrollment credential collision.")
                return {variable: secret}
            try:
                update_private_environment(self.config["CONTROLLER_CREDENTIALS_ENV_FILE"], credential)
            except (OSError, ValueError) as exc:
                raise StorageError("Private enrollment credentials could not be stored.") from exc
            grant.update(used_at=utc_text(current), enrolled_router_id=router_id, used_request_id=body["request_id"])
            response = {"protocol_version": "1.0", "status": "enrolled", "request_id": body["request_id"],
                "router_id": router_id, "interface": grant["outbound_interface"],
                "monitoring_enabled": grant["enable_monitoring"], "interval_seconds": grant["interval_seconds"],
                "collector_source": collector, "mode": "dry_run", "action": "monitoring_setup", "routing_changes_enabled": False}
            return token_id, router, response
        response = self.storage.consume_enrollment(prepare)
        self.storage.append_activity("enrollment", "Router enrolled with separate TX monitoring credentials.",
                                     {"router_id": response["router_id"]})
        return response
