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
from services.traffic_protocol import validate_interface
from services.router_protocol import ProtocolError
from services.controller_status_service import _authorization_enabled


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
        )
        result = {key: router.get(key) if isinstance(router.get(key), str) else ""
                  for key in text_fields}
        result["name"] = result["name"] or result["router_id"]
        result["api_port"] = router.get("api_port") if type(router.get("api_port")) is int else None
        result["ssh_port"] = router.get("ssh_port") if type(router.get("ssh_port")) is int else None
        result["api_tls"] = router.get("api_tls") is True
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
        for key in ("capacity_mbps", "cost_per_gb"):
            value = router.get(key)
            try:
                finite = type(value) in (float, int) and math.isfinite(value)
            except OverflowError:
                finite = False
            result[key] = value if finite else None
        state = router.get("connection_status", "untested")
        result["connection_status"] = state if state in ("untested", "blocked", "connected", "disconnected") else "untested"
        return result

    def list_routers(self) -> list[dict[str, Any]]:
        records = self.storage.read_json("routers.json")
        # Authorization uses the exact registry metadata, as polling does.
        # Public projection must not repair malformed keys before this check.
        communication = read_controller_status(self.storage, self.config, records)
        monitoring = read_traffic_status(self.storage, self.config, records)
        routers = [self._public(router) for router in records]
        for router in routers:
            router["controller_polling"] = communication[router["router_id"]]
            router["traffic_monitoring"] = monitoring[router["router_id"]]
        return routers

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
        return {
            "router_id": router_id,
            "name": _string(form, "name", required=True),
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

    def add_router(self, form: Mapping[str, Any]) -> dict[str, Any]:
        record = self._validated(form, allow_pending_address=True)

        def append(routers: list[dict[str, Any]]) -> list[dict[str, Any]]:
            if any(item["router_id"] == record["router_id"] for item in routers):
                raise RouterValidationError("A router with this ID already exists.")
            return [*routers, record]

        self.storage.update_json("routers.json", append)
        self.storage.append_activity("routers", f"Router {record['router_id']} registered for read-only setup.")
        return record

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
        for key in ("carrier", "endpoint", "router_role"):
            if key in existing:
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
                        or updated.get("controller_auth_ref") != current.get("controller_auth_ref")):
                    updated["monitoring_generation"] = str(uuid4())
                routers[index] = updated
                return routers
            raise RouterValidationError("Router was not found.")

        updated_routers = self.storage.update_json("routers.json", replace)
        updated = next(item for item in updated_routers if item["router_id"] == router_id)
        self.storage.append_activity("routers", f"Router {router_id} settings updated; connectivity must be checked again.")
        public = self._public(updated)
        # Retain the existing edit result's optional-value contract without
        # returning private metadata carried forward in the stored record.
        for field in ("last_checked_at", "last_error", "ospf_target_id", "snmp_version", "snmp_credential_ref"):
            if updated.get(field) is None:
                public[field] = None
        return public

    def set_monitoring(self, router_id: str, enabled: bool) -> None:
        """Explicit local opt-in; changing this flag never installs a collector."""
        if (not isinstance(router_id, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", router_id)
                or type(enabled) is not bool):
            raise RouterValidationError("Invalid monitoring setting.")

        def configure(routers):
            router = next((item for item in routers if item["router_id"] == router_id), None)
            if router is None:
                raise RouterValidationError("Router was not found.")
            if enabled:
                try:
                    validate_interface(router.get("interface_name"))
                except ProtocolError as exc:
                    raise RouterValidationError("Configure one outbound interface before enabling monitoring.") from exc
                if not _authorization_enabled(router):
                    raise RouterValidationError("Provision controller authentication before enabling monitoring.")
            if (router.get("monitoring_enabled") is True) != enabled:
                router["monitoring_generation"] = str(uuid4())
            router["monitoring_enabled"] = enabled
            return routers

        self.storage.update_json("routers.json", configure)
        self.storage.append_activity("monitoring", "Outbound traffic monitoring setting updated.", {
            "router_id": router_id, "enabled": enabled,
        })

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
        for key in ("ospf_target_id", "snmp_version", "snmp_credential_ref"):
            if data.get(key) is None:
                data[key] = ""
        return self._validated(data, allow_pending_address=True)

    def _preflight(self, router: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
        router = self._validated_saved(router)
        if not router["ip_address"]:
            raise RouterValidationError("Management IP address has not been entered for this router.")
        if router["api_port"] is None:
            raise RouterValidationError("API port has not been entered for this router.")
        if not router["api_tls"] and not self.config.get("ALLOW_PLAINTEXT_API", False):
            raise RouterValidationError("Unencrypted API connections are blocked. Configure API-SSL or explicitly authorize API access through a protected company network.")
        address = ip_address(router["ip_address"])
        try:
            allowed = [ip_network(network) for network in self.config.get("ROUTER_ALLOWED_NETWORKS", [])]
        except ValueError as exc:
            raise RouterValidationError("The controller's router network allowlist needs correction.") from exc
        if not any(address in network for network in allowed):
            raise RouterValidationError("Router address is outside the configured company management networks.")
        reference = router["credential_ref"]
        if not reference:
            raise RouterValidationError("Configure a credential reference for the read-only router account.")
        username = os.environ.get(reference + "_USERNAME", "")
        password = os.environ.get(reference + "_PASSWORD", "")
        if not username or not password:
            raise RouterValidationError("The referenced router credentials are not configured on this server.")
        if len(username) > 128 or len(password) > 4096:
            raise RouterValidationError("The configured router credentials exceed the supported size.")
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
                    ca_file=self.config.get("ROUTER_CA_FILE"),
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
