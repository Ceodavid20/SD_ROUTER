"""Real-data application behavior with isolated test-only registry fixtures."""

from copy import deepcopy
from pathlib import Path

import pytest

from app import create_app
from services.json_storage import StorageService
from services.router_service import RouterService, RouterValidationError


@pytest.fixture(autouse=True)
def no_router_commands(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Inventory setup contacted a router"))


@pytest.fixture
def config(tmp_path):
    return {"TESTING": True, "AUTH_ENABLED": False, "SIMULATION_MODE": True,
            "LIVE_ROUTING_ENABLED": False, "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output"}


def test_new_storage_does_not_create_sample_routers_or_paths(config):
    storage = StorageService(config["DATA_DIR"], config["OUTPUT_DIR"])
    storage.initialize()
    assert storage.read_json("routers.json") == []
    assert storage.read_json("routing_paths.json")["paths"] == []
    storage.initialize()
    assert storage.read_json("routers.json") == []


def test_registered_router_is_preserved_and_is_the_only_router_shown_after_restart(config):
    app = create_app(config)
    record = {"router_id": "REGISTERED-MIKROTIK", "name": "Existing MikroTik", "interface_name": "ether1",
              "controller_auth_enabled": True, "controller_auth_ref": "TEST_EXISTING_ROUTER",
              "controller_auth_key_ids": ["PRIMARY"], "monitoring_enabled": False,
              "private_legacy_secret": "test-only-hidden-value"}
    app.extensions["json_storage"].write_json("routers.json", [record])
    restarted = create_app(config)
    assert restarted.extensions["json_storage"].read_json("routers.json") == [record]
    client = restarted.test_client()
    routers = client.get("/api/routers").get_json()["routers"]
    assert [router["router_id"] for router in routers] == [record["router_id"]]
    assert client.get("/api/system/status").get_json()["data_source"] == "router"
    for path in ("/", "/routers", "/routers/connect", "/monitoring", "/optimization"):
        response = client.get(path)
        assert response.status_code == 200
        text = response.get_data(as_text=True)
        assert "test-only-hidden-value" not in text
        assert "Local synthetic demonstration" not in text and "SIM-MTN" not in text and "SIM-GLO" not in text
    connection = client.get("/routers/connect").get_data(as_text=True)
    assert record["router_id"] in connection and "ether1" in connection


def test_interface_configuration_updates_only_selected_router_and_preserves_authentication(config):
    app = create_app(config)
    storage = app.extensions["json_storage"]
    first = {"router_id": "REGISTERED-MIKROTIK", "name": "Existing MikroTik", "ip_address": "192.0.2.10",
             "interface_name": "", "monitoring_enabled": False,
             "controller_auth_enabled": True, "controller_auth_ref": "TEST_EXISTING_ROUTER",
             "controller_auth_key_ids": ["PRIMARY"], "ssh_port": 22,
             "private_legacy_secret": "test-only-private-value"}
    other = {"router_id": "OTHER-REGISTERED-ROUTER", "name": "Other router"}
    storage.write_json("routers.json", [first, other])
    protected = {name: deepcopy(storage.read_json(name)) for name in (
        "router_communication.json", "router_communication_v2.json", "router_config.json", "routing_paths.json")}
    RouterService(storage, app.config).configure_monitoring_interface(first["router_id"], "ether1")
    configured, unchanged = storage.read_json("routers.json")
    for key, value in first.items():
        if key != "interface_name":
            assert configured[key] == value
    assert configured["interface_name"] == "ether1" and configured["monitoring_enabled"] is False
    assert unchanged == other
    assert {name: storage.read_json(name) for name in protected} == protected


@pytest.mark.parametrize("interface", ["", " ether1", "ether1\n", ["ether1", "ether2"]])
def test_invalid_outbound_interface_cannot_change_the_registered_router(config, interface):
    app = create_app(config)
    storage = app.extensions["json_storage"]
    row = {"router_id": "REGISTERED-MIKROTIK", "name": "Existing MikroTik", "interface_name": "ether1"}
    storage.write_json("routers.json", [row])
    with pytest.raises((RouterValidationError, ValueError)):
        RouterService(storage, app.config).configure_monitoring_interface(row["router_id"], interface)
    assert storage.read_json("routers.json") == [row]


def test_demo_endpoints_and_runtime_launchers_are_removed(config):
    app = create_app(config)
    client = app.test_client()
    assert client.post("/demo/refresh").status_code == 404
    assert client.get("/api/demo").status_code == 404
    root = Path(__file__).resolve().parents[1]
    for relative in ("services/demo_service.py", "scripts/simulate_workflow.py", "scripts/simulate_router.py"):
        assert not (root / relative).exists()


def test_collector_url_uses_configured_origin_without_disclosing_credentials(config):
    config = {**config, "CONTROLLER_BASE_URL": "https://controller.example.test:18443"}
    client = create_app(config).test_client()
    response = client.get("/monitoring")
    assert response.status_code == 200
    assert "https://controller.example.test:18443/api/controller/v2/traffic" in response.get_data(as_text=True)
