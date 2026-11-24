"""Routing-path configuration stays in JSON until an operator applies it."""

from copy import deepcopy
from pathlib import Path

import pytest

from app import create_app
from services.json_storage import StorageService, ValidationError
from services.path_config_service import (
    DEFAULT_ROUTING_PATHS,
    PathConfigService,
)
from services.router_service import RouterService, RouterValidationError


def path_inventory(storage):
    storage.write_json("routers.json", [
        {"router_id": "TEST-AGG-1", "name": "Test aggregation"},
        {"router_id": "TEST-MTN", "name": "Test MTN", "carrier": "MTN"},
    ])


@pytest.fixture
def app(tmp_path: Path):
    application = create_app({
        "TESTING": True,
        "AUTH_ENABLED": False,
        "SECRET_KEY": None,
        "ADMIN_USERNAME": "",
        "ADMIN_PASSWORD_HASH": "",
        "ROUTER_CONFIG_TOKEN": "",
        "DATA_DIR": tmp_path / "data",
        "OUTPUT_DIR": tmp_path / "output",
    })
    path_inventory(application.extensions["json_storage"])
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def store(tmp_path: Path) -> StorageService:
    storage = StorageService(tmp_path / "data", tmp_path / "output")
    storage.initialize()
    path_inventory(storage)
    return storage


def test_default_paths_have_no_hardcoded_links_or_interfaces(store):
    config = PathConfigService(store).read()

    assert set(config) == {"schema_version", "paths", "congestion_policy", "automation"}
    assert config["paths"] == []
    assert config["congestion_policy"]["utilization_limit_percent"] is None
    assert config["automation"] == {
        "enabled": False,
        "routing_changes_enabled": False,
    }


def test_paths_accept_inventory_carrier_labels_without_provider_specific_code(store):
    store.update_json("routers.json", lambda rows: [
        {**row, "carrier":"Fiber West"} if row["router_id"] == "TEST-MTN" else row for row in rows])
    path = PathConfigService(store).add_path({
        "aggregation_router_id":"TEST-AGG-1", "carrier_router_id":"TEST-MTN",
        "carrier_interface":"uplink", "path_capacity_bps":"123000000",
        "monitor_router_id":"TEST-MTN", "route_role":"alternate"})
    assert path["carrier"] == "Fiber West" and path["aggregation_interface"] is None
    public = PathConfigService(store).list_paths()[0]
    assert public["analysis_ready"] is True and public["configuration_status"] == "not_configured"


def test_path_and_policy_settings_persist_after_restart_without_enabling_changes(store, tmp_path):
    service = PathConfigService(store)
    added = service.add_path({
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
        "aggregation_interface": "sfp-sfpplus1",
        "carrier_interface": "sfp-sfpplus2",
        "path_capacity_bps": "10000000000",
        "route_role": "primary",
    })
    saved_path = service.save_path(added["path_id"], {
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
        "aggregation_interface": "sfp-sfpplus3",
        "carrier_interface": "sfp-sfpplus4",
        "path_capacity_bps": "10000000000",
        "route_role": "primary",
    })
    policy = service.save_congestion_policy({
        "utilization_limit_percent": "80",
        "minimum_hold_down_seconds": "300",
        "overload_policy": "prefer_lower_utilization",
    })

    restarted = StorageService(tmp_path / "data", tmp_path / "output")
    restarted.initialize()
    persisted = PathConfigService(restarted).read()
    path = next(item for item in persisted["paths"] if item["path_id"] == added["path_id"])

    assert saved_path["configuration_status"] == "configured"
    assert path["aggregation_interface"] == "sfp-sfpplus3"
    assert path["carrier_interface"] == "sfp-sfpplus4"
    assert path["path_capacity_bps"] == 10_000_000_000
    assert path["route_role"] == "primary"
    assert policy["status"] == "configured"
    assert persisted["congestion_policy"]["utilization_limit_percent"] == 80
    assert persisted["automation"] == {
        "enabled": False,
        "routing_changes_enabled": False,
    }


@pytest.mark.parametrize(
    "form",
    [
        {"aggregation_interface": "bad\ninterface"},
        {"aggregation_router_id": "UNKNOWN-ROUTER"},
        {"carrier_router_id": "UNKNOWN-ROUTER"},
        {"carrier": "UNKNOWN-CARRIER"},
        {"path_capacity_bps": "0"},
    ],
)
def test_invalid_path_settings_leave_json_unchanged(store, form):
    before = deepcopy(store.read_json("routing_paths.json"))
    complete_form = {
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
        **form,
    }

    with pytest.raises(ValidationError):
        PathConfigService(store).add_path(complete_form)

    assert store.read_json("routing_paths.json") == before

    service = PathConfigService(store)
    added = service.add_path({
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
    })
    before_edit = deepcopy(service.read())
    with pytest.raises(ValidationError):
        service.save_path(added["path_id"], complete_form)
    assert service.read() == before_edit


def test_paths_accept_operator_registered_inventory_ids(store):
    store.write_json("routers.json", [
        {"router_id": "CORE-WEST", "name": "West aggregation"},
        {"router_id": "UPLINK-RED", "name": "MTN uplink"},
    ])

    path = PathConfigService(store).add_path({
        "aggregation_router_id": "CORE-WEST",
        "carrier_router_id": "UPLINK-RED",
        "carrier": "MTN",
    })

    assert path["path_id"]
    assert path["aggregation_router_id"] == "CORE-WEST"
    assert path["carrier_router_id"] == "UPLINK-RED"
    assert path["aggregation_interface"] is None
    assert path["carrier_interface"] is None
    assert path["path_capacity_bps"] is None


@pytest.mark.parametrize("stored_name", [None, [], "   "])
def test_path_display_falls_back_to_id_for_invalid_legacy_router_name(store, stored_name):
    service = PathConfigService(store)
    service.add_path({
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
    })
    routers = store.read_json("routers.json")
    for router in routers:
        if router["router_id"] == "TEST-AGG-1":
            router["name"] = stored_name
    store.write_json("routers.json", routers)

    assert service.list_paths()[0]["display_name"] == "TEST-AGG-1 → Test MTN"


def test_duplicate_and_self_link_paths_leave_json_unchanged(store):
    service = PathConfigService(store)
    form = {
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
    }
    service.add_path(form)
    before = deepcopy(service.read())

    with pytest.raises(ValidationError):
        service.add_path(form)
    with pytest.raises(ValidationError):
        service.add_path({
            **form,
            "carrier_router_id": "TEST-AGG-1",
        })

    assert service.read() == before


def test_parallel_links_between_the_same_routers_use_distinct_interfaces(store):
    service = PathConfigService(store)
    form = {
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
        "aggregation_interface": "ether1",
        "carrier_interface": "ether2",
        "path_capacity_bps": "1000000000",
    }
    first = service.add_path(form)
    second = service.add_path({
        **form,
        "aggregation_interface": "ether3",
        "carrier_interface": "ether4",
    })

    assert first["path_id"] != second["path_id"]
    assert len(service.read()["paths"]) == 2
    before_edit = deepcopy(service.read())
    with pytest.raises(ValidationError):
        service.save_path(second["path_id"], form)
    assert service.read() == before_edit


def test_path_can_be_deleted_without_changing_other_settings(store):
    service = PathConfigService(store)
    added = service.add_path({
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
    })
    service.delete_path(added["path_id"])

    assert service.read() == DEFAULT_ROUTING_PATHS
    with pytest.raises(ValidationError):
        service.delete_path(added["path_id"])


def test_router_cannot_be_deleted_until_its_paths_are_removed(store):
    service = PathConfigService(store)
    path = service.add_path({
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
    })
    inventory_before = deepcopy(store.read_json("routers.json"))
    router_service = RouterService(store, {})

    with pytest.raises(RouterValidationError, match="routing paths"):
        router_service.delete_router("TEST-MTN")
    assert store.read_json("routers.json") == inventory_before

    service.delete_path(path["path_id"])
    router_service.delete_router("TEST-MTN")
    assert all(router["router_id"] != "TEST-MTN" for router in store.read_json("routers.json"))


def test_invalid_policy_does_not_change_the_document(store):
    service = PathConfigService(store)
    before = deepcopy(service.read())

    with pytest.raises(ValidationError):
        service.save_congestion_policy({"utilization_limit_percent": "101"})
    assert service.read() == before


def test_invalid_stored_giant_utilization_is_rejected_without_replacing_json(store):
    before = deepcopy(store.read_json("routing_paths.json"))
    malformed = deepcopy(before)
    malformed["congestion_policy"]["utilization_limit_percent"] = 10**500

    with pytest.raises(ValidationError, match="Utilization limit"):
        store.write_json("routing_paths.json", malformed)

    assert store.read_json("routing_paths.json") == before


def test_storage_default_remains_detached_from_module_constant(store):
    """Mutating a read must not corrupt the template used by another app."""
    first = PathConfigService(store).read()
    first["paths"].append({"aggregation_router_id": "changed"})

    second = PathConfigService(store).read()
    assert second["paths"] == []
    assert DEFAULT_ROUTING_PATHS["paths"] == []


def test_path_page_forms_are_csrf_protected_and_only_save_json(
    app, client, monkeypatch
):
    import socket

    monkeypatch.setattr(
        socket, "create_connection",
        lambda *args, **kwargs: pytest.fail("Saving a path contacted a router"),
    )
    before = app.extensions["json_storage"].read_json("routing_paths.json")
    form = {
        "aggregation_router_id": "TEST-AGG-1",
        "carrier_router_id": "TEST-MTN",
        "carrier": "MTN",
        "aggregation_interface": "ether5",
        "carrier_interface": "sfp-sfpplus3",
        "path_capacity_bps": "1000000000",
        "route_role": "primary",
        "relationship_status": "operator_selected",
    }

    assert client.get("/routing-paths").status_code == 200
    assert client.post("/routing-paths/add", data=form).status_code == 400
    assert app.extensions["json_storage"].read_json("routing_paths.json") == before

    with client.session_transaction() as session:
        form["csrf_token"] = session["csrf_token"]
    response = client.post("/routing-paths/add", data=form)
    assert response.status_code == 302
    saved = PathConfigService(app.extensions["json_storage"]).read()
    assert len(saved["paths"]) == 1
    path = saved["paths"][0]
    assert path["aggregation_interface"] == "ether5"
    assert path["carrier_interface"] == "sfp-sfpplus3"
    assert path["path_capacity_bps"] == 1_000_000_000
    assert saved["automation"]["routing_changes_enabled"] is False

    updated = {
        **form,
        "aggregation_interface": "ether6",
        "route_role": "alternate",
    }
    save_url = f"/routing-paths/{path['path_id']}/save"
    assert client.post(save_url, data=updated).status_code == 302
    edited = PathConfigService(app.extensions["json_storage"]).read()["paths"][0]
    assert edited["aggregation_interface"] == "ether6"
    assert edited["route_role"] == "alternate"

    delete_url = f"/routing-paths/{path['path_id']}/delete"
    assert client.post(delete_url, data={}).status_code == 400
    assert client.post(delete_url, data={"csrf_token": form["csrf_token"]}).status_code == 302
    assert PathConfigService(app.extensions["json_storage"]).read()["paths"] == []
