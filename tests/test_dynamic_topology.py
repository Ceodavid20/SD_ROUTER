"""Signed real-counter fixtures for multiple independent, arbitrary link groups."""
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

import pytest

from device_app import create_device_app
from services.path_config_service import PathConfigService
from services.traffic_service import TrafficService
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request
from services.optimization_pull_service import OptimizationPullService
from services.optimization_protocol import PULL_PATH
from services.workflow_service import WorkflowService

NOW = datetime(2026, 11, 24, 15, tzinfo=UTC)
SECRET = "synthetic-dynamic-topology-key-0123456789012345"


@pytest.fixture
def topology(tmp_path, monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Topology tests contacted hardware"))
    app = create_device_app({"TESTING": True, "DATA_DIR": tmp_path / "data", "OUTPUT_DIR": tmp_path / "output",
        "ROUTER_RATE_LIMIT_ATTEMPTS": 1000, "SIMULATION_MODE": True, "LIVE_ROUTING_ENABLED": False})
    storage = app.extensions["json_storage"]
    routers, groups = [], {}
    for name, capacities, rates in (("BRANCH-NORTH", [125, 45, 80], [8, 6, 4]),
                                     ("CAMPUS-WEST", [60, 90, 30], [12, 20, 8])):
        reference = name.replace("-", "_")
        monkeypatch.setenv(reference + "_PRIMARY_SECRET", SECRET)
        interfaces = ["carrier." + str(index * 37 + 19) for index in range(3)]
        routers.append({"router_id": name, "name": name, "controller_auth_enabled": True,
            "controller_auth_ref": reference, "controller_auth_key_ids": ["PRIMARY"],
            "interface_name": interfaces[0], "monitoring_interfaces": interfaces, "monitoring_enabled": True})
        groups[name] = []
        for index, (capacity, rate, interface) in enumerate(zip(capacities, rates, interfaces)):
            carrier = name + "-PROVIDER-" + str(index)
            label = ["Independent fibre", "Regional wireless", "Community transit"][index]
            routers.append({"router_id": carrier, "name": label, "carrier": label, "capacity_confirmed": True})
            groups[name].append((carrier, label, capacity, rate, interface))
    storage.write_json("routers.json", routers)
    for name, links in groups.items():
        for carrier, label, capacity, rate, interface in links:
            PathConfigService(storage).add_path({"aggregation_router_id": name, "carrier_router_id": carrier,
                "carrier": label, "aggregation_interface": interface, "carrier_interface": "custom-physical-port",
                "path_capacity_bps": str(capacity * 1000000), "route_role": "primary", "monitor_router_id": name})
    service = WorkflowService(storage, app.config)
    service.save_settings({"optimization_objective": "adaptive_mlu", "monitoring_interval_seconds": "10", "averaging_window": "2"})
    for name, links in groups.items():
        for _, _, _, rate, interface in links:
            for step in range(3):
                payload = {"protocol_version": "2.0", "router_id": name, "request_id": str(uuid4()),
                    "timestamp": int((NOW - timedelta(seconds=20 - step * 10)).timestamp()),
                    "request_type": "traffic", "interface": interface, "tx_octets": 1234 + rate * 1250000 * step}
                raw = json.dumps(payload).encode()
                TrafficService(storage, app.config).handle(raw, "PRIMARY", sign_routeros_request(SECRET, raw, "PRIMARY", ROUTEROS_TRAFFIC_PATH), "127.0.0.1", now=datetime.fromtimestamp(payload["timestamp"], UTC))
    return app, storage, service, groups


def test_three_carriers_on_two_main_routers_use_only_their_own_demand(topology):
    _, _, service, expected = topology
    result = service.calculate(now=NOW)
    assert result["status"] == "ready"
    assert len(result["adaptive"]["groups"]) == 2
    for group in result["adaptive"]["groups"]:
        links = expected[group["aggregation_router_id"]]
        demand = sum(link[3] for link in links) * 1000000
        capacity = sum(link[2] for link in links) * 1000000
        assert len(group["links"]) == 3 and group["demand_bps"] == pytest.approx(demand)
        assert sum(link["target_bps"] for link in group["links"]) == pytest.approx(demand)
        for actual, expected_link in zip(group["links"], links):
            carrier, label, link_capacity, rate, interface = expected_link
            assert actual["carrier_router_id"] == carrier and actual["carrier"] == label
            assert actual["interface"] == interface
            assert actual["measurement"]["average_bps"] == pytest.approx(rate * 1000000)
            assert actual["target_bps"] == pytest.approx(demand * link_capacity * 1000000 / capacity)


def test_signed_dynamic_json_is_scoped_to_requesting_main_router(topology):
    app, storage, service, expected = topology
    service.calculate(now=NOW)
    for name, links in expected.items():
        raw = json.dumps({"protocol_version": "2.0", "router_id": name, "request_id": str(uuid4()),
            "timestamp": int(NOW.timestamp()), "request_type": "optimization"}).encode()
        signature = sign_routeros_request(SECRET, raw, "PRIMARY", PULL_PATH)
        response = OptimizationPullService(storage, app.config).handle(raw, "PRIMARY", signature, "127.0.0.1", now=NOW)
        assert response["status"] == "advisory_recommendation"
        assert response["router_id"] == name and response["recommendation"]["aggregation_router_id"] == name
        assert {row["carrier_router_id"] for row in response["recommendation"]["links"]} == {row[0] for row in links}
        assert response["execution_authorized"] is False and response["action"] == "none"
        serialized = json.dumps(response)
        assert SECRET not in serialized
        assert all(other == name or other not in serialized for other in expected)


def test_capacity_changes_and_deactivated_carriers_fail_closed(topology):
    _, storage, service, _ = topology
    first = service.calculate(now=NOW)
    storage.update_json("routing_paths.json", lambda cfg: {**cfg, "paths": [
        {**path, "path_capacity_bps": 250000000} if index == 0 else path for index, path in enumerate(cfg["paths"])]})
    assert service.read_latest(now=NOW)["is_current"] is False
    updated = service.calculate(now=NOW + timedelta(seconds=1))
    assert updated["adaptive"]["groups"][0]["total_capacity_bps"] != first["adaptive"]["groups"][0]["total_capacity_bps"]
    storage.update_json("routers.json", lambda rows: [{**row, "active": False} if row["router_id"] == "BRANCH-NORTH-PROVIDER-0" else row for row in rows])
    blocked = service.calculate(now=NOW + timedelta(seconds=2))
    group = next(group for group in blocked["adaptive"]["groups"] if group["aggregation_router_id"] == "BRANCH-NORTH")
    assert group["status"] == "configuration_required" and group["decision_id"] is None
