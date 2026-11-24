"""Closed, credential-free schema for read-only discovery and scoped approvals."""
import re
from services.router_protocol import ROUTER_ID, parse_utc_timestamp, ProtocolError
from services.routeros_api import RouterOSReadOnlyClient
from services.json_storage import ValidationError

HASH = re.compile(r"[a-f0-9]{64}\Z")
RESOURCE = re.compile(r"\*[a-fA-F0-9]{1,16}\Z")
SCOPES = {"ospf_templates": "cost", "ospf_interfaces_v6": "cost", "mangle": "per-connection-classifier"}


def _keys(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValidationError("Invalid router onboarding fields.")


def _text(value, maximum=256):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError("Invalid discovery text.")


def _time(value):
    try:
        parse_utc_timestamp(value)
    except (ProtocolError, TypeError) as exc:
        raise ValidationError("Invalid onboarding timestamp.") from exc


def _hash(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValidationError("Invalid onboarding fingerprint.")


def validate_snapshot(value):
    if not isinstance(value, dict) or set(value) != set(RouterOSReadOnlyClient.READS):
        raise ValidationError("Invalid discovery menus.")
    def menu(key, result):
        _keys(result, "status rows")
        if result["status"] not in ("observed", "unavailable", "not_probed"):
            raise ValidationError("Invalid discovery status.")
        if not isinstance(result["rows"], list) or len(result["rows"]) > 126:
            raise ValidationError("Discovery exceeds the bounded read capacity.")
        if result["status"] != "observed" and result["rows"]:
            raise ValidationError("Unobserved menus cannot contain readings.")
        allowed = set(RouterOSReadOnlyClient.READS[key][1].split(","))
        for row in result["rows"]:
            if not isinstance(row, dict) or set(row) - allowed:
                raise ValidationError("Discovery contains an unexpected field.")
            for item in row.values():
                _text(item)
    for key, result in value.items():
        if key == "tx":
            if not isinstance(result, dict) or len(result) > 16:
                raise ValidationError("Invalid selected TX discovery.")
            for name, observed in result.items():
                from services.traffic_protocol import validate_interface
                try:
                    validate_interface(name)
                except ProtocolError as exc:
                    raise ValidationError("Invalid selected TX interface.") from exc
                menu(key, observed)
        else:
            menu(key, result)


def validate_onboarding(value):
    _keys(value, "schema_version routers")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or not isinstance(value["routers"], dict):
        raise ValidationError("Invalid onboarding state.")
    for router_id, entry in value["routers"].items():
        if not isinstance(router_id, str) or not ROUTER_ID.fullmatch(router_id):
            raise ValidationError("Invalid onboarding identity.")
        _keys(entry, "discovery baselines authorization")
        discovery = entry["discovery"]
        if discovery is not None:
            _keys(discovery, "captured_at binding snapshot")
            _time(discovery["captured_at"]); _hash(discovery["binding"])
            validate_snapshot(discovery["snapshot"])
        if not isinstance(entry["baselines"], list) or len(entry["baselines"]) > 8:
            raise ValidationError("Invalid baseline history.")
        for baseline in entry["baselines"]:
            _keys(baseline, "baseline_id captured_at binding topology_digest snapshot resources approved_at digest")
            for key in ("baseline_id", "binding", "topology_digest", "digest"):
                _hash(baseline[key])
            _time(baseline["captured_at"])
            if baseline["approved_at"] is not None:
                _time(baseline["approved_at"])
            validate_snapshot(baseline["snapshot"])
            if not isinstance(baseline["resources"], list) or len(baseline["resources"]) > 256:
                raise ValidationError("Invalid managed resource scope.")
            seen = set()
            for resource in baseline["resources"]:
                _keys(resource, "path_id menu resource_id field value")
                if (resource["menu"] not in SCOPES or resource["field"] != SCOPES[resource["menu"]]
                        or not isinstance(resource["path_id"], str) or not ROUTER_ID.fullmatch(resource["path_id"])
                        or not isinstance(resource["resource_id"], str) or not RESOURCE.fullmatch(resource["resource_id"])):
                    raise ValidationError("Invalid managed routing resource.")
                _text(resource["value"])
                identity = (resource["menu"], resource["resource_id"], resource["field"])
                if identity in seen:
                    raise ValidationError("Managed resources must be unique.")
                seen.add(identity)
        authorization = entry["authorization"]
        if authorization is not None:
            _keys(authorization, "baseline_id baseline_digest approved_at expires_at")
            _hash(authorization["baseline_id"]); _hash(authorization["baseline_digest"])
            _time(authorization["approved_at"]); _time(authorization["expires_at"])
            if parse_utc_timestamp(authorization["expires_at"]) <= parse_utc_timestamp(authorization["approved_at"]):
                raise ValidationError("Invalid authorization lifetime.")
