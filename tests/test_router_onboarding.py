"""Hardware behavior is mocked; every socket is blocked unless explicitly faked."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
from types import SimpleNamespace

import pytest

from app import create_app
from services.json_storage import ValidationError
from services.path_config_service import PathConfigService
from services.router_onboarding_service import RouterOnboardingService, capabilities
from services.router_service import RouterService, RouterValidationError
from services.routeros_api import RouterOSReadOnlyClient, RouterAPIError
from services.workflow_service import WorkflowService

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)


def snapshot(version="7.21.4"):
    data = {key: {"status": "observed", "rows": []} for key in RouterOSReadOnlyClient.READS if key != "tx"}
    data["resource"]["rows"] = [{"version": version, "board-name": "Synthetic physical model", "architecture-name": "arm64"}]
    data["interfaces"]["rows"] = [{".id": "*A", "name": "uplink-fibre.100", "type": "vlan", "running": "true"}]
    data["ospf_templates"]["rows"] = [{".id": "*B", "interfaces": "uplink-fibre.100", "cost": "25"}]
    data["fasttrack"]["rows"] = [{".id": "*C", "action": "fasttrack-connection", "disabled": "false"}]
    data["tx"] = {"uplink-fibre.100": {"status": "observed", "rows": [{".id": "*A", "name": "uplink-fibre.100", "tx-byte": "12000000000"}]}}
    return data


@pytest.fixture
def onboarding(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Unapproved router contact"))
    env = tmp_path / "credentials.env"
    env.write_text("READER_USERNAME=synthetic-reader\nREADER_PASSWORD=synthetic-hidden-password\n")
    env.chmod(0o600)
    app = create_app({"TESTING": True, "AUTH_ENABLED": False, "DATA_DIR": tmp_path / "data",
        "OUTPUT_DIR": tmp_path / "output", "API_CREDENTIALS_ENV_FILE": env,
        "ROUTER_ALLOWED_NETWORKS": ["10.73.0.0/24"], "ROUTER_CA_FILE": None,
        "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False})
    storage = app.extensions["json_storage"]
    routers = RouterService(storage, app.config)
    routers.add_router({"router_id": "DISTRIBUTION-EAST", "name": "Distribution East", "ip_address": "10.73.0.8",
        "api_tls": True, "api_port": "9876", "credential_ref": "READER", "router_role": "main",
        "deployment_kind": "physical", "interface_name": "uplink-fibre.100"})
    routers.add_router({"router_id": "FIBRE-EAST", "name": "Arbitrary carrier", "carrier": "Independent fibre",
        "router_role": "upstream", "capacity_mbps": "275.5", "deployment_kind": "physical"})
    path = PathConfigService(storage).add_path({"aggregation_router_id": "DISTRIBUTION-EAST", "carrier_router_id": "FIBRE-EAST",
        "aggregation_interface": "uplink-fibre.100", "carrier_interface": "sfp-sfpplus2", "path_capacity_bps": "275500000",
        "relationship_status": "operator_selected", "route_role": "primary", "monitor_router_id": "DISTRIBUTION-EAST"})
    calls = []
    def client(*args, **kwargs):
        calls.append((args[0], args[1], kwargs))
        return SimpleNamespace(read_discovery=lambda interfaces: snapshot())
    monkeypatch.setattr("services.router_onboarding_service.RouterOSReadOnlyClient", client)
    return app, storage, routers, RouterOnboardingService(storage, app.config), path, calls


def approved(onboarding):
    app, _, _, service, path, _ = onboarding
    service.discover("DISTRIBUTION-EAST", now=NOW)
    baseline = service.capture_baseline("DISTRIBUTION-EAST", {path["path_id"]: "ospf_templates:*B"}, now=NOW)
    service.approve_baseline("DISTRIBUTION-EAST", baseline["digest"], now=NOW)
    app.config["AUTH_ENABLED"] = True
    service.authorize_scope("DISTRIBUTION-EAST", baseline["digest"], now=NOW)
    return baseline


def test_dynamic_discovery_is_read_only_and_projects_model_architecture_interfaces(onboarding):
    app, storage, _, service, _, calls = onboarding
    before = storage.read_json("routers.json")
    discovery = service.discover("DISTRIBUTION-EAST", now=NOW)
    assert calls[0][0:2] == ("10.73.0.8", 9876)
    assert calls[0][2]["tls"] is True
    assert discovery["snapshot"]["resource"]["rows"][0]["architecture-name"] == "arm64"
    assert storage.read_json("routers.json") == before
    text = json.dumps(discovery)
    assert "synthetic-hidden-password" not in text and '"rx-byte"' not in text
    view = service.view("DISTRIBUTION-EAST", now=NOW)
    assert view["capabilities"]["fasttrack"]["status"] == "review"
    assert view["capabilities"]["json_serialization"]["status"] == "unknown"
    assert view["capabilities"]["tx_monitoring"]["status"] == "observed"
    assert view["execution_enabled"] is False
    response = app.test_client().get("/routers/DISTRIBUTION-EAST/setup")
    assert response.status_code == 200
    assert "arm64" in response.text and "synthetic-hidden-password" not in response.text


@pytest.mark.parametrize("version,status", [("6.49.18", "unsupported"), ("7.21.4", "unknown"), ("8.0rc1", "unknown"), ("unrecognized", "unknown")])
def test_native_capabilities_never_inferred_supported_from_version(version, status):
    evidence = capabilities(snapshot(version))
    assert evidence["json_serialization"]["status"] == status
    assert evidence["configuration_execution"]["status"] == "blocked"
    if version.startswith("8"):
        assert evidence["version_adapter"]["status"] == "unsupported"


def test_unavailable_menus_and_missing_tx_are_reported_unknown():
    data = snapshot()
    for key in ("interfaces", "mangle", "ospf_templates", "tables", "bridge_ports", "switches", "fasttrack"):
        data[key] = {"status": "unavailable", "rows": []}
    data["tx"] = {}
    evidence = capabilities(data)
    assert all(evidence[key]["status"] == "unknown" for key in ("interfaces", "pcc", "ospf", "tx_monitoring", "fasttrack", "hardware_offload"))


def test_baseline_review_scope_approval_and_rollback_never_enable_routing(onboarding):
    app, storage, _, service, path, _ = onboarding
    baseline = approved(onboarding)
    view = service.view("DISTRIBUTION-EAST", now=NOW)
    assert view["scope_approved"] is True and view["execution_enabled"] is False
    rollback = service.rollback_reference("DISTRIBUTION-EAST")
    assert rollback["resources"] == [{"path_id": path["path_id"], "menu": "ospf_templates", "resource_id": "*B", "field": "cost", "value": "25"}]
    assert rollback["action"] == "review_only" and rollback["execution_enabled"] is False
    assert app.config["LIVE_ROUTING_ENABLED"] is False and app.config["SIMULATION_MODE"] is True
    assert storage.read_json("router_config.json")["commands"] == []
    assert service.view("DISTRIBUTION-EAST", now=NOW + timedelta(hours=2))["scope_approved"] is False


@pytest.mark.parametrize("field,value", [("ip_address", "10.73.0.9"), ("interface_name", "new-tx-interface"),
    ("router_role", "branch"), ("capacity_mbps", 195.5), ("credential_ref", "ANOTHER_REF"), ("api_port", 12345)])
def test_configuration_changes_invalidate_discovery_baseline_and_authorization(onboarding, field, value):
    _, storage, _, service, _, _ = onboarding
    approved(onboarding)
    storage.update_json("routers.json", lambda rows: [{**row, field: value} if row["router_id"] == "DISTRIBUTION-EAST" else row for row in rows])
    view = service.view("DISTRIBUTION-EAST", now=NOW)
    assert view["discovery_current"] is False
    assert view["baseline_current"] is False and view["scope_approved"] is False


def test_topology_change_and_emergency_off_invalidate_scope(onboarding):
    app, storage, _, service, path, _ = onboarding
    approved(onboarding)
    storage.update_json("routing_paths.json", lambda cfg: {**cfg, "paths": [{**row, "path_capacity_bps": 150000000} for row in cfg["paths"]]})
    assert service.view("DISTRIBUTION-EAST", now=NOW)["scope_approved"] is False
    WorkflowService(storage, app.config).set_optimization_enabled(False)
    assert storage.read_json("router_onboarding.json")["routers"]["DISTRIBUTION-EAST"]["authorization"] is None


def test_invalid_or_foreign_scope_and_stale_discovery_fail_closed(onboarding):
    _, _, _, service, path, _ = onboarding
    service.discover("DISTRIBUTION-EAST", now=NOW)
    for selection in ("routes:*B", "ospf_templates:*FFFF", "ospf_templates:*B:extra"):
        with pytest.raises(RouterValidationError):
            service.capture_baseline("DISTRIBUTION-EAST", {path["path_id"]: selection}, now=NOW)
    with pytest.raises(RouterValidationError):
        service.capture_baseline("DISTRIBUTION-EAST", {"OTHER-ROUTERS-PATH": "ospf_templates:*B"}, now=NOW)
    with pytest.raises(RouterValidationError, match="fresh"):
        service.capture_baseline("DISTRIBUTION-EAST", {}, now=NOW + timedelta(minutes=16))


def test_deactivation_blocks_old_auth_and_reactivation_does_not_reenable_it(onboarding):
    _, storage, routers, service, _, _ = onboarding
    approved(onboarding)
    routers.set_active("DISTRIBUTION-EAST", False)
    row = storage.read_json("routers.json")[0]
    assert row["active"] is False and row["monitoring_enabled"] is False and row["controller_auth_enabled"] is False
    with pytest.raises(RouterValidationError, match="Activate"):
        service.discover("DISTRIBUTION-EAST", now=NOW)
    routers.set_active("DISTRIBUTION-EAST", True)
    assert storage.read_json("routers.json")[0]["controller_auth_enabled"] is False
    assert service.view("DISTRIBUTION-EAST", now=NOW)["scope_approved"] is False


def test_discovery_rejects_concurrent_endpoint_edit(onboarding, monkeypatch):
    _, storage, _, service, _, _ = onboarding
    def read(_):
        storage.update_json("routers.json", lambda rows: [{**row, "ip_address": "10.73.0.9"} if row["router_id"] == "DISTRIBUTION-EAST" else row for row in rows])
        return snapshot()
    monkeypatch.setattr("services.router_onboarding_service.RouterOSReadOnlyClient", lambda *a, **k: SimpleNamespace(read_discovery=read))
    with pytest.raises(RouterValidationError, match="changed"):
        service.discover("DISTRIBUTION-EAST", now=NOW)
    assert storage.read_json("router_onboarding.json")["routers"] == {}


def test_strict_storage_rejects_rx_secrets_and_unknown_fields(onboarding):
    _, storage, _, service, _, _ = onboarding
    service.discover("DISTRIBUTION-EAST", now=NOW)
    original = storage.read_json("router_onboarding.json")
    for key in ("rx-byte", "password", "source", "unknown-field"):
        state = deepcopy(original)
        state["routers"]["DISTRIBUTION-EAST"]["discovery"]["snapshot"]["resource"]["rows"][0][key] = "must-not-store"
        with pytest.raises(ValidationError):
            storage.write_json("router_onboarding.json", state)


def test_onboarding_actions_require_csrf_and_protect_admin_sessions(onboarding):
    app, storage, _, _, _, _ = onboarding
    client = app.test_client()
    before = storage.read_json("router_onboarding.json")
    assert client.post("/routers/DISTRIBUTION-EAST/setup/discover").status_code == 400
    assert storage.read_json("router_onboarding.json") == before
    app.config["AUTH_ENABLED"] = True
    assert client.get("/routers/DISTRIBUTION-EAST/setup").status_code == 302
    assert client.get("/routers/DISTRIBUTION-EAST/baseline.json").status_code == 302


@pytest.mark.parametrize("role", ["main", "distribution", "carrier", "upstream", "branch_42"])
def test_arbitrary_router_roles_and_carrier_names_need_no_source_edit(onboarding, role):
    _, storage, routers, _, _, _ = onboarding
    routers.edit_router("FIBRE-EAST", {"name": "Different carrier", "ip_address": "10.73.0.99", "router_role": role,
        "carrier": "Community upstream", "interface_name": "sfp28-12", "capacity_mbps": "1234.5"})
    row = storage.read_json("routers.json")[1]
    assert (row["router_role"], row["carrier"], row["capacity_mbps"], row["interface_name"]) == (role, "Community upstream", 1234.5, "sfp28-12")
