"""Validated real router inventory and explicitly requested API discovery."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
import math
import os
import re
from typing import Any
from uuid import uuid4

from services.json_storage import StorageService
from services.controller_status_service import read_controller_status
from services.routeros_api import RouterAPIError, RouterOSReadOnlyClient
from services.traffic_service import read_traffic_status
from services.traffic_service import monitored_interfaces
from services.traffic_protocol import validate_interface
from services.router_protocol import ProtocolError
from services.controller_status_service import _authorization_enabled
from services.api_credentials_service import APICredentialError, api_credentials


class RouterValidationError(ValueError):
    """Router form input is invalid or the inventory target is missing."""


def _string(form: Mapping[str, Any], key: str, *, required: bool = False, limit: int = 128) -> str:
    value = form.get(key, "")
    if not isinstance(value, str):
        raise RouterValidationError(f"{key} must be text.")
    value = value.strip()
    if (required and not value) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise RouterValidationError(f"Enter a valid {key.replace('_', ' ')}.")
    return value


def _number(form: Mapping[str, Any], key: str, *, positive: bool) -> float | None:
    raw = _string(form, key, limit=32)
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise RouterValidationError(f"{key.replace('_', ' ')} must be numeric.") from exc
    if not math.isfinite(value) or (value <= 0 if positive else value < 0):
        raise RouterValidationError(f"Enter a valid {key.replace('_', ' ')}.")
    return value


def _port(form: Mapping[str, Any], key: str, default: int | None) -> int | None:
    try:
        raw = _string(form, key, limit=5)
        if not raw:
            return default
        value = int(raw)
    except ValueError as exc:
        raise RouterValidationError(f"{key.replace('_', ' ')} must be a port number.") from exc
    if not 1 <= value <= 65535:
        raise RouterValidationError(f"{key.replace('_', ' ')} must be between 1 and 65535.")
    return value


class RouterService:
    """Keep credentials outside JSON and never connect while listing inventory."""

    def __init__(self, storage: StorageService, config: Mapping[str, Any]) -> None:
        self.storage = storage
        self.config = config

    @staticmethod
    def _public(router: dict[str, Any]) -> dict[str, Any]:
        """Project an inventory record; never expose unknown legacy secret keys."""
        text_fields = (
            "router_id", "name", "carrier", "endpoint", "router_role",
            "ip_address", "model", "routeros_version",
            "interface_name", "ospf_target_id", "snmp_version",
            "snmp_credential_ref", "currency", "credential_ref", "last_checked_at",
            "last_error", "detected_model", "detected_routeros_version",
            "management_interface", "deployment_kind", "integration_status",
            "traffic_origin", "enrolled_at",
            "traffic_source_ip",
            "api_ca_file", "detected_architecture",
        )
        result = {key: router.get(key) if isinstance(router.get(key), str) else ""
                  for key in text_fields}
        result["name"] = result["name"] or result["router_id"]
        result["api_port"] = router.get("api_port") if type(router.get("api_port")) is int else None
        result["ssh_port"] = router.get("ssh_port") if type(router.get("ssh_port")) is int else None
        result["api_tls"] = router.get("api_tls") is True
        result["api_credentials_managed"] = router.get("api_credentials_source") == "private_env"
        controller_ref = router.get("controller_auth_ref", "")
        result["controller_auth_ref"] = (
            controller_ref if isinstance(controller_ref, str)
            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", controller_ref) else ""
        )
        key_ids = router.get("controller_auth_key_ids", [])
        result["controller_auth_key_ids"] = (
            list(dict.fromkeys(key_id for key_id in key_ids
                               if isinstance(key_id, str)
                               and re.fullmatch(r"[A-Z][A-Z0-9_]{0,31}", key_id)))
            if isinstance(key_ids, list) else []
        )
        result["controller_auth_enabled"] = router.get("controller_auth_enabled") is True
        result["snmp_ifindex"] = (
            router.get("snmp_ifindex")
            if type(router.get("snmp_ifindex")) is int
            and router["snmp_ifindex"] > 0
            else None
        )
        result["monitoring_enabled"] = router.get("monitoring_enabled") is True
        result["active"] = router.get("active", True) is True
        try:
            result["monitoring_interfaces"] = monitored_interfaces(router)
        except ProtocolError:
            result["monitoring_interfaces"] = []
        interval = router.get("monitoring_interval_seconds")
        result["monitoring_interval_seconds"] = interval if type(interval) is int and 1 <= interval <= 86400 else None
        for key in ("capacity_mbps", "cost_per_gb"):
            value = router.get(key)
            try:
                finite = type(value) in (float, int) and math.isfinite(value)
            except OverflowError:
                finite = False
            result[key] = value if finite else None
        result["capacity_confirmed"] = (
            router.get("capacity_confirmed", True) is True and result["capacity_mbps"] is not None
        )
        state = router.get("connection_status", "untested")
        result["connection_status"] = state if state in ("untested", "blocked", "connected", "disconnected") else "untested"
        return result

    def list_routers(self) -> list[dict[str, Any]]:
        records = self.storage.read_json("routers.json")
        # Authorization uses the exact registry metadata, as polling does.
        # Public projection must not repair malformed keys before this check.
        communication = read_controller_status(self.storage, self.config, records)
        monitoring = read_traffic_status(self.storage, self.config, records)
        discovered = self.storage.read_json("router_onboarding.json")["routers"]
        routers = [self._public(router) for router in records]
        for router, record in zip(routers, records):
            router["controller_polling"] = communication[router["router_id"]]
            router["traffic_monitoring"] = monitoring[router["router_id"]]
            router["api_diagnostics"] = self.api_diagnostic_readiness(record)
            discovery = discovered.get(router["router_id"], {}).get("discovery")
            if discovery:
                from services.router_onboarding_service import _binding
                if discovery["binding"] == _binding(record, self.config):
                    resources = discovery["snapshot"]["resource"]["rows"]
                    if resources:
                        router.update(detected_model=resources[0].get("board-name", ""),
                                      detected_routeros_version=resources[0].get("version", ""),
                                      detected_architecture=resources[0].get("architecture-name", ""))
        return routers

    def _revoke_execution_scope(self, router_id):
        entry = self.storage.read_json("router_onboarding.json")["routers"].get(router_id)
        if entry and entry["authorization"] is not None:
            from services.router_onboarding_service import RouterOnboardingService
            RouterOnboardingService(self.storage, self.config).revoke(router_id)

    def _validated(
        self, form: Mapping[str, Any], *, allow_pending_address: bool = False
    ) -> dict[str, Any]:
        router_id = _string(form, "router_id", required=True, limit=64)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id):
            raise RouterValidationError("Router ID must contain only letters, digits, hyphens, and underscores.")
        address_value = _string(
            form, "ip_address", required=not allow_pending_address, limit=64
        )
        if address_value:
            try:
                address = ip_address(address_value)
            except ValueError as exc:
                raise RouterValidationError("Enter a valid router IPv4 or IPv6 address.") from exc
            if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                raise RouterValidationError("Use a routable company management address.")
        else:
            address = None
        reference = _string(form, "credential_ref", limit=64)
        if reference and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", reference):
            raise RouterValidationError("Credential reference must be an uppercase environment variable prefix.")
        controller_reference = _string(form, "controller_auth_ref", limit=64)
        if controller_reference and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", controller_reference):
            raise RouterValidationError("Controller authentication reference must be an uppercase environment variable prefix.")
        snmp_reference = _string(form, "snmp_credential_ref", limit=64)
        if snmp_reference and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", snmp_reference):
            raise RouterValidationError("SNMP credential reference must be an uppercase environment variable prefix.")
        snmp_version = _string(form, "snmp_version", limit=4).lower()
        if snmp_version not in ("", "v1", "v2c", "v3"):
            raise RouterValidationError("Select a supported SNMP version.")
        currency = _string(form, "currency", limit=3).upper()
        if currency and not re.fullmatch(r"[A-Z]{3}", currency):
            raise RouterValidationError("Currency must be a three-letter code.")
        tls_input = form.get("api_tls", False)
        if tls_input not in (True, False, "", "on", "true", "false", "1", "0"):
            raise RouterValidationError("Invalid API TLS setting.")
        index_text = _string(form, "snmp_ifindex", limit=16)
        try:
            snmp_ifindex = int(index_text) if index_text else None
        except ValueError as exc:
            raise RouterValidationError("SNMP interface index must be a positive integer.") from exc
        if snmp_ifindex is not None and not 1 <= snmp_ifindex <= 2**31 - 1:
            raise RouterValidationError("SNMP interface index must be a positive integer.")
        role = _string(form, "router_role", limit=64) or "unassigned"
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", role):
            raise RouterValidationError("Use a lowercase role name containing letters, digits, hyphens or underscores.")
        kind = _string(form, "deployment_kind", limit=32) or "unspecified"
        if kind not in ("unspecified", "physical", "virtual", "chr_lab", "router"):
            raise RouterValidationError("Select physical, virtual or unspecified deployment.")
        if self.config.get("ENVIRONMENT") == "production" and kind == "chr_lab":
            raise RouterValidationError("Laboratory CHR records cannot be registered in production.")
        ca_file = _string(form, "api_ca_file", limit=1024)
        if ca_file:
            from services.deployment_service import profile_path
            try:
                ca_file = str(profile_path(self.config, ca_file))
            except ValueError as exc:
                raise RouterValidationError(str(exc)) from exc
        record = {
            "router_id": router_id,
            "name": _string(form, "name", required=True),
            "router_role": role,
            "deployment_kind": kind,
            "carrier": _string(form, "carrier", limit=64),
            "api_ca_file": ca_file or None,
            "ip_address": str(address) if address is not None else "",
            "model": _string(form, "model"),
            "routeros_version": _string(form, "routeros_version", limit=64),
            "interface_name": _string(form, "interface_name"),
            "snmp_ifindex": snmp_ifindex,
            "ospf_target_id": _string(form, "ospf_target_id", limit=128) or None,
            "snmp_version": snmp_version or None,
            "snmp_credential_ref": snmp_reference or None,
            "capacity_mbps": _number(form, "capacity_mbps", positive=True),
            "cost_per_gb": _number(form, "cost_per_gb", positive=False),
            "currency": currency,
            "api_port": _port(form, "api_port", None),
            "api_tls": tls_input in (True, "on", "true", "1"),
            "ssh_port": _port(form, "ssh_port", None),
            "credential_ref": reference,
            "controller_auth_ref": controller_reference,
            # Credential provisioning is a separate administrative operation.
            # Ordinary inventory forms cannot enable keys or select active keys.
            "controller_auth_enabled": False,
            "controller_auth_key_ids": [],
            "monitoring_enabled": False,
            "connection_status": "untested",
            "last_checked_at": None,
            "last_error": None,
        }
        if form.get("capacity_confirmation_present") == "true":
            confirmed = form.get("capacity_confirmed") in (True, "1", "on", "true")
            if confirmed and record["capacity_mbps"] is None:
                raise RouterValidationError("Enter a positive WAN capacity before confirming it.")
            record["capacity_confirmed"] = confirmed
        return record

    def add_router(self, form: Mapping[str, Any]) -> dict[str, Any]:
        record = self._validated(form, allow_pending_address=True)
        record["inventory_generation"] = str(uuid4())

        def append(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if any(item["router_id"] == record["router_id"] for item in routers):
                raise RouterValidationError("A router with this ID already exists.")
            return [*routers, record]

        self.storage.update_json("routers.json", append)
        self.storage.append_activity("routers", f"Router {record['router_id']} registered for read-only setup.")
        return record

    def register_monitoring_router(
        self, router_id: str, name: str, management_ip: str,
        outbound_interface: str, management_interface: str, carrier: str,
        *, chr_lab: bool = False, bind_source: bool = False, api_port: int = 8729,
    ) -> dict[str, Any]:
        """Explicit, idempotent local registration; no provisioning or router I/O."""
        carrier = _string({"carrier": carrier}, "carrier", required=True, limit=64)
        if type(chr_lab) is not bool or type(bind_source) is not bool:
            raise RouterValidationError("Lab and source-binding settings must be booleans.")
        if chr_lab and self.config.get("ENVIRONMENT") == "production":
            raise RouterValidationError("Laboratory CHR registration is blocked in production.")
        try:
            validate_interface(outbound_interface)
            validate_interface(management_interface)
        except ProtocolError as exc:
            raise RouterValidationError("Enter exact outbound and management interfaces.") from exc
        record = self._validated({
            "router_id": router_id, "name": name, "ip_address": management_ip,
            "interface_name": outbound_interface, "api_port": str(api_port),
            "api_tls": True, "ssh_port": "22",
        })
        record.update(carrier=carrier, router_role="carrier",
                      inventory_generation=str(uuid4()),
                      capacity_confirmed=False,
                      management_interface=management_interface,
                      deployment_kind="chr_lab" if chr_lab else "router",
                      integration_status="awaiting_router_setup")
        if bind_source:
            record["traffic_source_ip"] = record["ip_address"]

        def register(routers):
            current = next((r for r in routers if r["router_id"] == router_id), None)
            if current is not None:
                if (current.get("ip_address") != record["ip_address"]
                        or current.get("interface_name") != outbound_interface
                        or current.get("carrier") != carrier):
                    raise RouterValidationError("Existing router settings differ; review them before registration.")
                return routers
            if any(r.get("ip_address") == record["ip_address"] for r in routers):
                raise RouterValidationError("This management address is already registered to another router.")
            return [*routers, record]

        rows = self.storage.update_json("routers.json", register)
        self.storage.append_activity("routers", f"Router {router_id} registered for separate TX monitoring; no router configuration changed.")
        return self._public(next(r for r in rows if r["router_id"] == router_id))

    def edit_router(self, router_id: str, form: Mapping[str, Any]) -> dict[str, Any]:
        existing = next(
            (
                router for router in self.storage.read_json("routers.json")
                if router["router_id"] == router_id
            ),
            None,
        )
        if existing is None:
            raise RouterValidationError("Router was not found.")
        data = dict(form)
        data["router_id"] = router_id
        record = self._validated(data, allow_pending_address=True)
        record["monitoring_enabled"] = existing.get("monitoring_enabled") is True
        # Older editable records may contain fields not shown on this page.
        for key in ("capacity_mbps", "cost_per_gb", "currency"):
            if key in existing and key not in data:
                record[key] = existing[key]
        for key in ("carrier", "endpoint", "router_role", "deployment_kind", "api_ca_file"):
            if key in existing and key not in data:
                record[key] = existing[key]
        if "ospf_target_id" not in data:
            record["ospf_target_id"] = existing.get("ospf_target_id")
        if "snmp_version" not in data:
            record["snmp_version"] = existing.get("snmp_version")
        if "snmp_credential_ref" not in data:
            record["snmp_credential_ref"] = existing.get("snmp_credential_ref")

        def replace(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
            for index, current in enumerate(routers):
                if current["router_id"] != router_id:
                    continue
                # Preserve metadata not edited by this form, including check-in
                # and instruction history added by communication services.
                updated = {**current, **record}
                updated["monitoring_enabled"] = current.get("monitoring_enabled") is True
                source_changed = ("traffic_source_ip" in current
                                  and updated.get("ip_address") != current.get("ip_address"))
                if source_changed:
                    if not updated.get("ip_address"):
                        raise RouterValidationError("A source-bound router requires a management address.")
                    updated["traffic_source_ip"] = updated["ip_address"]
                # The private setup command owns managed references. An older
                # browser form must not clear or roll back a newly saved login.
                # Read the current reference inside the storage transaction so
                # a concurrent credential rotation is preserved as well.
                if (current.get("api_credentials_source") == "private_env"
                        or "credential_ref" not in data):
                    updated["credential_ref"] = current.get("credential_ref", "")
                for field in ("detected_model", "detected_routeros_version"):
                    updated.pop(field, None)
                current_auth = self._public(current)
                if "controller_auth_ref" not in data:
                    updated["controller_auth_ref"] = current_auth["controller_auth_ref"]
                if updated["controller_auth_ref"] == current_auth["controller_auth_ref"]:
                    updated["controller_auth_enabled"] = current_auth["controller_auth_enabled"]
                    updated["controller_auth_key_ids"] = current_auth["controller_auth_key_ids"]
                else:
                    # A different reference must be provisioned before use; do
                    # not silently reuse enablement from the previous key set.
                    updated["controller_auth_enabled"] = False
                    updated["controller_auth_key_ids"] = []
                if (updated.get("interface_name") != current.get("interface_name")
                        or updated.get("controller_auth_ref") != current.get("controller_auth_ref")
                        or source_changed):
                    updated["monitoring_generation"] = str(uuid4())
                    if updated.get("interface_name") != current.get("interface_name") and "monitoring_interfaces" in current:
                        updated["monitoring_interfaces"] = [updated["interface_name"]]
                        updated["monitoring_enabled"] = False
                routers[index] = updated
                return routers
            raise RouterValidationError("Router was not found.")

        updated_routers = self.storage.update_json("routers.json", replace)
        self._revoke_execution_scope(router_id)
        updated = next(item for item in updated_routers if item["router_id"] == router_id)
        self.storage.append_activity("routers", f"Router {router_id} settings updated; connectivity must be checked again.")
        public = self._public(updated)
        # Retain the existing edit result's optional-value contract without
        # returning private metadata carried forward in the stored record.
        for field in ("last_checked_at", "last_error", "ospf_target_id", "snmp_version", "snmp_credential_ref"):
            if updated.get(field) is None:
                public[field] = None
        return public

    def configure_monitoring_interface(self, router_id: str, interface: str) -> None:
        """Update only the selected router's TX interface, without contacting it."""
        if not isinstance(router_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id):
            raise RouterValidationError("Router ID is invalid.")
        try:
            validate_interface(interface)
        except ProtocolError as exc:
            raise RouterValidationError("Enter one valid outbound interface name.") from exc

        def configure(routers):
            router = next((item for item in routers if item["router_id"] == router_id), None)
            if router is None:
                raise RouterValidationError("Router was not found.")
            if router.get("interface_name") != interface:
                router.pop("monitoring_interfaces", None)
                router.update(interface_name=interface, monitoring_enabled=False,
                              monitoring_generation=str(uuid4()))
            return routers

        self.storage.update_json("routers.json", configure)
        self._revoke_execution_scope(router_id)
        self.storage.append_activity("monitoring", "Outbound TX monitoring interface configured.", {
            "router_id": router_id, "interface": interface,
        })

    def configure_monitoring_interfaces(self, router_id: str, interfaces: list[str]) -> None:
        """Authorize explicit independent TX channels; no router connection/write."""
        candidate = {"interface_name": interfaces[0] if isinstance(interfaces, list) and interfaces else None,
                     "monitoring_interfaces": interfaces}
        try:
            monitored_interfaces(candidate)
        except ProtocolError as exc:
            raise RouterValidationError(str(exc)) from exc
        def configure(rows):
            row = next((row for row in rows if row["router_id"] == router_id), None)
            if row is None:
                raise RouterValidationError("Router was not found.")
            if row.get("monitoring_interfaces", [row.get("interface_name")]) != interfaces:
                row.update(interface_name=interfaces[0], monitoring_interfaces=list(interfaces),
                           monitoring_generation=str(uuid4()), monitoring_enabled=False)
            return rows
        self.storage.update_json("routers.json", configure)
        self._revoke_execution_scope(router_id)

    def set_monitoring(self, router_id: str, enabled: bool) -> None:
        """Explicit local opt-in; changing this flag never installs a collector."""
        if (not isinstance(router_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id)
                or type(enabled) is not bool):
            raise RouterValidationError("Invalid monitoring setting.")
        baseline_binding = None
        if enabled and self.config.get("ENVIRONMENT") == "production":
            from services.router_onboarding_service import RouterOnboardingService
            view = RouterOnboardingService(self.storage, self.config).view(router_id)
            if not view["baseline_current"] or not view["baseline"]["approved_at"]:
                raise RouterValidationError("Capture and approve the current routing baseline before production monitoring opt-in.")
            baseline_binding = view["baseline"]["binding"]

        def configure(routers):
            router = next((item for item in routers if item["router_id"] == router_id), None)
            if router is None:
                raise RouterValidationError("Router was not found.")
            if enabled:
                if baseline_binding is not None:
                    from services.router_onboarding_service import _binding
                    if _binding(router, self.config) != baseline_binding:
                        raise RouterValidationError("Router settings changed after baseline review.")
                if router.get("active", True) is not True:
                    raise RouterValidationError("Activate this router before enabling monitoring.")
                try:
                    monitored_interfaces(router)
                except ProtocolError as exc:
                    raise RouterValidationError("Configure one outbound interface before enabling monitoring.") from exc
                if not _authorization_enabled(router):
                    raise RouterValidationError("Provision controller authentication before enabling monitoring.")
            if (router.get("monitoring_enabled") is True) != enabled:
                router["monitoring_generation"] = str(uuid4())
            router["monitoring_enabled"] = enabled
            return routers

        self.storage.update_json("routers.json", configure)
        self._revoke_execution_scope(router_id)
        self.storage.append_activity("monitoring", "Outbound traffic monitoring setting updated.", {
            "router_id": router_id, "enabled": enabled,
        })

    def set_active(self, router_id: str, active: bool) -> None:
        """Reactivation never re-enables monitoring or old key authorization."""
        if type(active) is not bool:
            raise RouterValidationError("Invalid router activation setting.")
        def update(rows):
            row = next((item for item in rows if item["router_id"] == router_id), None)
            if row is None:
                raise RouterValidationError("Router was not found.")
            if row.get("active", True) is not active:
                row.update(active=active, monitoring_enabled=False, controller_auth_enabled=False,
                           controller_auth_key_ids=[], monitoring_generation=str(uuid4()))
            return rows
        self.storage.update_json("routers.json", update)
        from services.router_onboarding_service import RouterOnboardingService
        RouterOnboardingService(self.storage, self.config).revoke(router_id)
        self.storage.append_activity("routers", "Router activated for setup." if active else "Router deactivated; monitoring and key authorization disabled.", {"router_id": router_id})

    def delete_router(self, router_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id):
            raise RouterValidationError("Router ID is invalid.")
        paths = self.storage.read_json("routing_paths.json")["paths"]
        if any(router_id in (path["aggregation_router_id"], path["carrier_router_id"])
               for path in paths):
            raise RouterValidationError("Remove this router's routing paths before deleting it.")

        def remove(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if not any(item["router_id"] == router_id for item in routers):
                raise RouterValidationError("Router was not found.")
            return [item for item in routers if item["router_id"] != router_id]

        self.storage.update_json("routers.json", remove)
        self.storage.append_activity("routers", f"Router {router_id} removed from inventory; history retained.")

    def _validated_saved(self, router: dict[str, Any]) -> dict[str, Any]:
        """Treat manually edited or legacy storage as untrusted configuration."""
        if any(key not in router for key in (
            "router_id", "name", "ip_address", "api_port", "api_tls", "credential_ref"
        )):
            raise RouterValidationError("Router configuration is incomplete. Edit and save it before testing.")
        if type(router["api_tls"]) is not bool:
            raise RouterValidationError("Router API TLS setting is invalid. Edit and save the router.")
        data = dict(router)
        for key in ("capacity_mbps", "cost_per_gb", "api_port", "ssh_port"):
            value = data.get(key)
            if value is None:
                data[key] = ""
            elif type(value) in (int, float) or isinstance(value, str):
                data[key] = str(value)
            else:
                raise RouterValidationError("Router numeric settings are invalid. Edit and save the router.")
        index = data.get("snmp_ifindex")
        if index is None:
            data["snmp_ifindex"] = ""
        elif type(index) is int:
            data["snmp_ifindex"] = str(index)
        elif not isinstance(index, str):
            raise RouterValidationError("SNMP interface index is invalid. Edit and save the router.")
        for key in ("ospf_target_id", "snmp_version", "snmp_credential_ref", "api_ca_file"):
            if data.get(key) is None:
                data[key] = ""
        return self._validated(data, allow_pending_address=True)

    def _api_setup(self, saved: dict[str, Any]):
        issues = []
        try:
            router = self._validated_saved(saved)
        except RouterValidationError as exc:
            return None, ("", ""), [str(exc)]
        if not router["ip_address"]:
            issues.append("Management IP address has not been entered for this router.")
        if router["api_port"] is None:
            issues.append("API port has not been entered for this router.")
        if saved.get("active", True) is not True:
            issues.append("Router is deactivated.")
        if not router["api_tls"] and not self.config.get("ALLOW_PLAINTEXT_API", False):
            issues.append("Unencrypted API connections are blocked. Configure API-SSL or explicitly authorize API access through a protected company network.")
        try:
            allowed = [ip_network(network) for network in self.config.get("ROUTER_ALLOWED_NETWORKS", [])]
        except ValueError as exc:
            allowed = []
            issues.append("The controller's router network allowlist needs correction.")
        if router["ip_address"] and not any(ip_address(router["ip_address"]) in network for network in allowed):
            issues.append("Router address is outside the configured company management networks.")
        reference = router["credential_ref"]
        username, password = "", ""
        if not reference:
            issues.append("Configure a credential reference for the read-only router account using the local setup command below.")
        else:
            try:
                username, password = api_credentials({**router, "api_credentials_source": saved.get("api_credentials_source")}, self.config)
            except APICredentialError as exc:
                issues.append(str(exc))
            else:
                if not username or not password:
                    issues.append("The referenced router credentials are not configured on this server.")
                elif len(username) > 128 or len(password) > 4096:
                    issues.append("The configured router credentials exceed the supported size.")
        return router, (username, password), issues

    def api_diagnostic_readiness(self, router: dict[str, Any]) -> dict[str, Any]:
        """Show every local prerequisite without contacting or logging in to a router."""
        _, _, issues = self._api_setup(router)
        return {"ready": not issues, "requirements": issues}

    def _preflight(self, saved: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        router, (username, password), issues = self._api_setup(saved)
        if issues:
            raise RouterValidationError(issues[0])
        return username, password, router

    def test_api(self, router_id: str) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id):
            raise RouterValidationError("Router ID is invalid.")
        # Keep the complete private record for the optimistic-concurrency check.
        router = next((item for item in self.storage.read_json("routers.json")
                       if item["router_id"] == router_id), None)
        if router is None:
            raise RouterValidationError("Router was not found.")
        tested = dict(router)
        tested["last_checked_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        try:
            username, password, connection_settings = self._preflight(router)
        except RouterValidationError as exc:
            tested.update(connection_status="blocked", last_error=str(exc))
        else:
            try:
                resource = RouterOSReadOnlyClient(
                    connection_settings["ip_address"], connection_settings["api_port"], username, password,
                    tls=connection_settings["api_tls"],
                    timeout=self.config.get("API_TIMEOUT_SECONDS", 3),
                    ca_file=router.get("api_ca_file") or self.config.get("ROUTER_CA_FILE"),
                ).read_resource()
            except RouterAPIError as exc:
                tested.update(connection_status="disconnected", last_error=str(exc))
            else:
                tested.update(connection_status="connected", last_error=None,
                              detected_model=resource.get("board-name"),
                              detected_routeros_version=resource.get("version"))

        def save(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
            # A concurrent edit invalidates this result rather than replacing it.
            current = next((item for item in routers if item["router_id"] == router_id), None)
            if current != router:
                raise RouterValidationError("Router settings changed during the connection check; run it again.")
            return [tested if item["router_id"] == router_id else item for item in routers]

        self.storage.update_json("routers.json", save)
        self.storage.append_activity("connectivity", f"Router {router_id} API check: {tested['connection_status']}.")
        return self._public(tested)
