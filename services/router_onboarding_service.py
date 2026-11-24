"""Physical/virtual onboarding without any router configuration writes.

Discovery uses only the common read-only API. Baseline approval and execution
scope approval are separate; neither can bypass the disabled routing executor.
"""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import secrets

from services.deployment_service import profile_path
from services.onboarding_state import SCOPES, validate_snapshot
from services.router_service import RouterService, RouterValidationError
from services.routeros_api import RouterOSReadOnlyClient, RouterAPIError
from services.router_protocol import parse_utc_timestamp
from services.traffic_service import monitored_interfaces


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _time(now):
    return now.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _router(inputs, router_id):
    router = next((r for r in inputs["routers.json"] if r["router_id"] == router_id), None)
    if router is None:
        raise RouterValidationError("Router was not found.")
    return router


def _binding(router, config):
    keys = ("router_id", "ip_address", "api_port", "api_tls", "api_ca_file", "credential_ref",
            "api_credentials_source", "controller_auth_ref", "controller_auth_key_ids", "controller_auth_enabled",
            "router_role", "deployment_kind", "active", "interface_name", "monitoring_interfaces",
            "monitoring_generation", "traffic_source_ip", "capacity_mbps", "capacity_confirmed")
    return _hash({"router": {key: router.get(key) for key in keys},
                  "environment": config.get("ENVIRONMENT", "development"),
                  "controller": config.get("CONTROLLER_BASE_URL", ""),
                  "ca_file": router.get("api_ca_file") or str(config.get("ROUTER_CA_FILE") or "")})


def _topology(inputs, router_id):
    topology = inputs["routing_paths.json"]
    return _hash({"paths": [path for path in topology["paths"]
                            if router_id in (path["aggregation_router_id"], path["carrier_router_id"])],
                  "policy": topology["congestion_policy"], "settings": inputs["automation_settings.json"]})


def _baseline_digest(baseline):
    return _hash({key: value for key, value in baseline.items() if key not in ("digest", "approved_at")})


def capabilities(snapshot):
    """Report evidence, not a guessed feature matrix based on model/version."""
    observed = lambda key: snapshot[key]["status"] == "observed"
    resource = snapshot["resource"]["rows"]
    version = resource[0].get("version", "") if resource else ""
    major = version.split(".", 1)[0]
    feature = lambda value, detail: {"status": value, "detail": detail}
    unknown = "Not exercised by read-only API discovery; native client preflight is required."
    result = {
        "api": feature("observed", "Authenticated resource reply; TLS verification follows the saved API transport setting."),
        "interfaces": feature("observed" if observed("interfaces") else "unknown", "Projected interface names and states only."),
        "routing_tables": feature("observed" if observed("tables") else "unknown", "RouterOS 7 table menu is probed; absent or denied menus remain unknown."),
        "ospf": feature("observed" if observed("ospf_templates" if major == "7" else "ospf_interfaces_v6") else "unknown",
                        "Version-specific OSPF interface menu; an empty menu confirms access, not an active adjacency."),
        "pcc": feature("observed" if observed("mangle") else "unknown", "Existing classifiers are inspected; forwarding equivalence still requires operator verification."),
        "json_serialization": feature("unknown", unknown),
        "json_deserialization": feature("unknown", unknown),
        "sha512": feature("unknown", unknown),
        "scripting": feature("unknown", unknown),
        "https_polling": feature("unknown", "Verify trusted controller CA, clock, reachability and an authenticated native check-in."),
        "configuration_execution": feature("blocked", "No routing executor is implemented. Global routing changes remain disabled."),
        "fasttrack": feature("unknown", "Filter menu unavailable or not permitted."),
        "hardware_offload": feature("unknown", "Hardware counter visibility and forwarding effects need target-device validation."),
        "tx_monitoring": feature("unknown", "Select TX interfaces and run discovery; verify subsequent signed TX deltas."),
    }
    if major not in ("6", "7"):
        result["version_adapter"] = feature("unsupported", "No routing adapter for this RouterOS major version; read-only observations only.")
    else:
        result["version_adapter"] = feature("observed", "RouterOS " + major + " read-only discovery adapter; no routing execution adapter.")
    if major == "6":
        for key in ("json_serialization", "json_deserialization", "sha512"):
            result[key] = feature("unsupported", "The native V2 client targets RouterOS 7 scripting primitives. Upgrade and validate before installing it.")
    if observed("fasttrack"):
        fasttrack = any(row.get("action") == "fasttrack-connection" and row.get("disabled") not in ("true", "yes")
                        for row in snapshot["fasttrack"]["rows"])
        result["fasttrack"] = feature("review" if fasttrack else "observed",
            "Active FastTrack rule found. Verify policy routing and counter visibility on this device." if fasttrack else "No enabled FastTrack rule in the projected filter snapshot.")
    if observed("bridge_ports") or observed("switches"):
        result["hardware_offload"] = feature("review", "Offload configuration was inspected. Validate selected interface counters and policy routing on physical hardware.")
    selected = snapshot["tx"]
    if selected and all(item["status"] == "observed" and len(item["rows"]) == 1
            and item["rows"][0].get("name") == name and item["rows"][0].get("tx-byte", "").isdigit()
            and int(item["rows"][0]["tx-byte"]) <= 2**64 - 1 for name, item in selected.items()):
        result["tx_monitoring"] = feature("observed", "Selected TX octet counters were readable. Rate correctness still requires successive samples.")
    return result


class RouterOnboardingService:
    def __init__(self, storage, config):
        self.storage, self.config = storage, config

    def discover(self, router_id, *, now=None):
        now = now or datetime.now(UTC)
        inputs, _ = self.storage.read_onboarding_snapshot()
        router = _router(inputs, router_id)
        if router.get("active", True) is not True:
            raise RouterValidationError("Activate this router before discovery.")
        username, password, connection = RouterService(self.storage, self.config)._preflight(router)
        try:
            interfaces = monitored_interfaces(router) if router.get("interface_name") else []
            snapshot = RouterOSReadOnlyClient(connection["ip_address"], connection["api_port"], username, password,
                tls=connection["api_tls"], timeout=self.config.get("DISCOVERY_TIMEOUT_SECONDS", 15),
                ca_file=router.get("api_ca_file") or self.config.get("ROUTER_CA_FILE")).read_discovery(interfaces)
            validate_snapshot(snapshot)
        except RouterAPIError as exc:
            # API errors are fixed credential-free messages, never device traps.
            raise RouterValidationError(str(exc)) from exc
        discovery = {"captured_at": _time(now), "binding": _binding(router, self.config), "snapshot": snapshot}
        def save(current, entry):
            if _binding(_router(current, router_id), self.config) != discovery["binding"]:
                raise RouterValidationError("Router settings changed during discovery. Run it again.")
            entry["discovery"] = discovery
            # Any rediscovery requires review before renewing an authorization.
            entry["authorization"] = None
            return entry
        self.storage.update_onboarding(router_id, save)
        self.storage.append_activity("onboarding", "Read-only router discovery captured; routing unchanged.", {"router_id": router_id})
        return discovery

    def view(self, router_id, *, now=None):
        now = now or datetime.now(UTC)
        inputs, state = self.storage.read_onboarding_snapshot()
        router = _router(inputs, router_id)
        entry = state["routers"].get(router_id, {"discovery": None, "baselines": [], "authorization": None})
        discovery = entry["discovery"]
        discovery_current = bool(discovery and discovery["binding"] == _binding(router, self.config))
        baseline = entry["baselines"][-1] if entry["baselines"] else None
        baseline_current = bool(baseline and discovery_current and baseline["binding"] == discovery["binding"]
            and baseline["topology_digest"] == _topology(inputs, router_id)
            and baseline["digest"] == _baseline_digest(baseline)
            and self._configuration(baseline["snapshot"]) == self._configuration(discovery["snapshot"]))
        approval = entry["authorization"]
        approval_current = bool(approval and baseline_current and baseline["approved_at"]
            and approval["baseline_id"] == baseline["baseline_id"] and approval["baseline_digest"] == baseline["digest"]
            and now < parse_utc_timestamp(approval["expires_at"]) and router.get("active", True) is True)
        return {"router": RouterService._public(router), "discovery": discovery,
                "discovery_current": discovery_current,
                "capabilities": capabilities(discovery["snapshot"]) if discovery else {},
                "paths": [path for path in inputs["routing_paths.json"]["paths"] if path["aggregation_router_id"] == router_id],
                "baseline": baseline, "baseline_current": baseline_current,
                "authorization": approval, "scope_approved": approval_current,
                "execution_enabled": False, "execution_blocker": "Routing executor unavailable; LIVE_ROUTING_ENABLED remains false."}

    @staticmethod
    def _configuration(snapshot):
        # Runtime counters, uptime and running flags are not configuration drift.
        return {key: snapshot[key] for key in snapshot if key not in ("resource", "tx", "interfaces")}

    def capture_baseline(self, router_id, selections, *, now=None):
        """Copy the observed projection; each managed field needs an exact path binding."""
        now = now or datetime.now(UTC)
        def capture(inputs, entry):
            router = _router(inputs, router_id)
            discovery = entry["discovery"]
            if (not discovery or discovery["binding"] != _binding(router, self.config)
                    or not 0 <= (now - parse_utc_timestamp(discovery["captured_at"])).total_seconds()
                    <= self.config.get("ONBOARDING_DISCOVERY_MAX_AGE_SECONDS", 900)):
                raise RouterValidationError("Run fresh discovery before capturing a baseline.")
            paths = {path["path_id"]: path for path in inputs["routing_paths.json"]["paths"] if path["aggregation_router_id"] == router_id}
            resources, seen = [], set()
            for path_id, selection in selections.items():
                if not selection:
                    continue
                if path_id not in paths or not isinstance(selection, str) or selection.count(":") != 1:
                    raise RouterValidationError("Select a discovered resource for this router's path.")
                menu, resource_id = selection.split(":")
                if menu not in SCOPES:
                    raise RouterValidationError("Only discovered OSPF costs or existing PCC classifiers may be scoped.")
                observed = discovery["snapshot"][menu]
                row = next((row for row in observed["rows"] if row.get(".id") == resource_id), None)
                if observed["status"] != "observed" or not row or not row.get(SCOPES[menu]):
                    raise RouterValidationError("The selected routing field was not discovered.")
                interface = paths[path_id]["aggregation_interface"]
                matched = (interface and (interface in row.get("interfaces", "").split(",")
                    or interface == row.get("interface") or interface == row.get("out-interface")))
                if not matched or (menu, resource_id) in seen:
                    raise RouterValidationError("A managed resource must match one unique main-router TX interface.")
                if menu == "mangle" and not row.get("per-connection-classifier"):
                    raise RouterValidationError("Only an existing PCC classifier can be selected.")
                resources.append({"path_id": path_id, "menu": menu, "resource_id": resource_id,
                                  "field": SCOPES[menu], "value": row[SCOPES[menu]]})
                seen.add((menu, resource_id))
            baseline = {"baseline_id": secrets.token_hex(32), "captured_at": _time(now),
                "binding": discovery["binding"], "topology_digest": _topology(inputs, router_id),
                "snapshot": deepcopy(discovery["snapshot"]), "resources": resources, "approved_at": None}
            baseline["digest"] = _baseline_digest(baseline)
            entry["baselines"] = [*entry["baselines"][-7:], baseline]
            entry["authorization"] = None
            return entry
        entry = self.storage.update_onboarding(router_id, capture)
        self.storage.append_activity("onboarding", "Projected routing baseline captured for review.", {"router_id": router_id})
        return entry["baselines"][-1]

    def approve_baseline(self, router_id, digest, *, now=None):
        now = now or datetime.now(UTC)
        return self._approve(router_id, digest, now, authorize=False)

    def authorize_scope(self, router_id, digest, *, now=None, ttl_seconds=3600):
        if type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
            raise RouterValidationError("Scope approval must last between 60 and 86400 seconds.")
        return self._approve(router_id, digest, now or datetime.now(UTC), authorize=True, ttl_seconds=ttl_seconds)

    def _approve(self, router_id, digest, now, *, authorize, ttl_seconds=3600):
        def approve(inputs, entry):
            router = _router(inputs, router_id)
            baseline = entry["baselines"][-1] if entry["baselines"] else None
            discovery = entry["discovery"]
            if (not baseline or baseline["digest"] != digest or digest != _baseline_digest(baseline)
                    or baseline["binding"] != _binding(router, self.config)
                    or baseline["topology_digest"] != _topology(inputs, router_id)
                    or not discovery or self._configuration(baseline["snapshot"]) != self._configuration(discovery["snapshot"])):
                raise RouterValidationError("Baseline or settings changed. Capture and review a new baseline.")
            if router.get("active", True) is not True:
                raise RouterValidationError("Activate this router before approving a baseline.")
            if authorize:
                if not 0 <= (now - parse_utc_timestamp(discovery["captured_at"])).total_seconds() <= self.config.get("ONBOARDING_DISCOVERY_MAX_AGE_SECONDS", 900):
                    raise RouterValidationError("Run fresh discovery before approving an execution scope.")
                if (not baseline["approved_at"] or not baseline["resources"] or router.get("api_tls") is not True
                        or self.config.get("AUTH_ENABLED") is not True):
                    raise RouterValidationError("Approve a nonempty resource scope with administrator authentication and API-SSL first.")
                entry["authorization"] = {"baseline_id": baseline["baseline_id"], "baseline_digest": digest,
                    "approved_at": _time(now), "expires_at": _time(now + timedelta(seconds=ttl_seconds))}
            else:
                baseline["approved_at"] = _time(now)
                entry["authorization"] = None
            return entry
        result = self.storage.update_onboarding(router_id, approve)
        self.storage.append_activity("security", "Routing execution scope approved; execution remains blocked." if authorize
            else "Projected routing baseline approved; execution remains blocked.", {"router_id": router_id})
        return result

    def revoke(self, router_id):
        def revoke(inputs, entry):
            _router(inputs, router_id)
            entry["authorization"] = None
            return entry
        self.storage.update_onboarding(router_id, revoke)
        self.storage.append_activity("security", "Router routing execution scope revoked.", {"router_id": router_id})

    def rollback_reference(self, router_id):
        view = self.view(router_id)
        baseline = view["baseline"]
        if not baseline or not baseline["approved_at"]:
            raise RouterValidationError("Approve a captured baseline before exporting its rollback reference.")
        return {"schema_version": 1, "router_id": router_id, "baseline_id": baseline["baseline_id"],
                "baseline_digest": baseline["digest"], "execution_enabled": False,
                "action": "review_only", "resources": deepcopy(baseline["resources"]),
                "limitation": "Projected managed-field baseline, not a complete RouterOS backup. No automatic restore executor."}

    def policy_preview(self, router_id, *, now=None):
        """Review artifact bound to one router and exact approved resource IDs.

        This browser-only projection never changes legacy poll/ACK or sends
        executable commands. PCC bucket ranges require a future reviewed adapter.
        """
        from services.workflow_service import WorkflowService
        now = now or datetime.now(UTC)
        view = self.view(router_id, now=now)
        latest = WorkflowService(self.storage, self.config).read_latest(now=now)
        group = next((group for group in (latest or {}).get("adaptive", {}).get("groups", [])
                      if group["aggregation_router_id"] == router_id), None)
        baseline = view["baseline"]
        result = {"schema_version": 1, "router_id": router_id, "mode": "advisory", "action": "none",
            "execution_enabled": False, "scope_approved": view["scope_approved"],
            "baseline_digest": baseline["digest"] if baseline and view["baseline_current"] else None,
            "decision_id": None, "decision_version": None, "issued_at": _time(now),
            "expires_at": _time(now + timedelta(seconds=min(60, self.config.get("ROUTER_RESPONSE_TTL_SECONDS", 60)))),
            "managed_resources": [], "reason": "Current approved baseline and fresh advisory required."}
        if (not baseline or not view["baseline_current"] or not baseline["approved_at"]
                or not latest or not latest["is_current"] or not group or not group["decision_id"]):
            return result
        links = {link["path_id"]: link for link in group["links"]}
        result.update(decision_id=group["decision_id"], decision_version=group["decision_version"], reason="Review only; routing execution remains blocked.")
        for resource in baseline["resources"]:
            link = links.get(resource["path_id"])
            if not link:
                continue
            proposed = link["calculated_cost"] if resource["field"] == "cost" else None
            if proposed is not None and (type(proposed) is not int or not 1 <= proposed <= 65535):
                proposed = None
            result["managed_resources"].append({**resource, "observed_value": resource["value"],
                "proposed_value": proposed, "recommended_weight": link["recommended_weight"],
                "pcc_buckets": deepcopy(link["pcc"]), "execution_enabled": False})
        if group["expires_at"]:
            result["expires_at"] = min(result["expires_at"], group["expires_at"])
        return result

    def prepare_bundle(self, router_id):
        """Generate private local artifacts only, following explicit admin action."""
        from services.controller_setup_service import provision_router
        from services.traffic_setup_service import prepare_traffic_client, prepare_optimization_client
        if self.config.get("AUTH_ENABLED") is not True:
            raise RouterValidationError("Configure administrator authentication before preparing a browser-downloadable private bundle.")
        view = self.view(router_id)
        if (not view["discovery_current"] or not view["router"]["active"]
                or not view["discovery"]["snapshot"]["resource"]["rows"][0].get("version", "").startswith("7.")):
            raise RouterValidationError("Discover a capable RouterOS 7 device before preparing its native client bundle.")
        if not view["router"]["api_tls"]:
            raise RouterValidationError("Verify API-SSL before preparing the native client bundle.")
        ca = self.config.get("CONTROLLER_CA_FILE")
        if not ca:
            raise RouterValidationError("Configure the profile's trusted public controller CA file first.")
        import ssl
        ca_path = profile_path(self.config, ca)
        if ca_path.stat().st_size > 1024 * 1024 or b"PRIVATE KEY" in ca_path.read_bytes():
            raise RouterValidationError("Use a bounded public controller CA certificate file.")
        ssl.create_default_context(cafile=str(ca_path))
        parent = profile_path(self.config, self.config["PRIVATE_BUNDLE_DIR"])
        target = parent / (router_id + "-" + secrets.token_hex(8))
        result = provision_router(self.storage, self.config["CONTROLLER_CREDENTIALS_ENV_FILE"], router_id,
            self.config.get("CONTROLLER_BASE_URL", ""), target, ca_file=ca_path)
        prepare_traffic_client(self.storage, router_id, result["key_id"], result["controller_base_url"], target / "traffic", config=self.config)
        prepare_optimization_client(self.storage, router_id, result["key_id"], result["controller_base_url"], target / "advisory", config=self.config)
        # A provisioned key changes the binding: require fresh review before any
        # future execution approval. Existing polling/monitoring remains intact.
        self.revoke(router_id)
        return target
