"""Carrier integration uses isolated test storage and never contacts a device."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

import pytest

from app import create_app
from services.router_service import RouterService, RouterValidationError
from services.router_poll_service import PollError
from services.routeros_protocol import ROUTEROS_TRAFFIC_PATH, sign_routeros_request
from services.traffic_service import TrafficService
from services.workflow_service import WorkflowService


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr("socket.create_connection", lambda *a, **k: pytest.fail("Integration test contacted a router"))


@pytest.fixture
def fleet(tmp_path, monkeypatch):
    app = create_app({"TESTING": True, "AUTH_ENABLED": False, "SIMULATION_MODE": True,
                      "LIVE_ROUTING_ENABLED": False, "DATA_DIR": tmp_path / "data",
                      "OUTPUT_DIR": tmp_path / "output"})
    storage = app.extensions["json_storage"]
    service = RouterService(storage, app.config)
    original = service.add_router({"router_id": "SDR-CHR-LAB-01", "name": "Original test router",
                                   "ip_address": "192.0.2.10", "interface_name": "ether1"})
    for router_id, address, carrier in (("SDR-MTN-01", "192.0.2.11", "MTN"),
                                        ("SDR-GLO-01", "192.0.2.12", "GLO")):
        service.register_monitoring_router(router_id, carrier + " CHR lab", address,
                                           "ether1", "ether3", carrier, chr_lab=True, bind_source=True)
    return app, storage, service


def sample(fleet, router_id, source, at, counter=1000):
    app, storage, _ = fleet
    secret = "test-only-" + router_id + "-private-hmac-value"
    body = {"protocol_version": "2.0", "router_id": router_id, "request_id": str(uuid4()),
            "request_type": "traffic", "timestamp": int(at.timestamp()),
            "interface": "ether1", "tx_octets": counter}
    raw = json.dumps(body, separators=(",", ":")).encode()
    return TrafficService(storage, app.config).handle(
        raw, "PRIMARY", sign_routeros_request(secret, raw, "PRIMARY", ROUTEROS_TRAFFIC_PATH), source, now=at,
    )


def enable(fleet, monkeypatch):
    _, storage, _ = fleet
    def authorize(rows):
        for row in rows:
            reference = row["router_id"].replace("-", "_")
            monkeypatch.setenv(reference + "_PRIMARY_SECRET", "test-only-" + row["router_id"] + "-private-hmac-value")
            row.update(controller_auth_ref=reference, controller_auth_enabled=True,
                       controller_auth_key_ids=["PRIMARY"], monitoring_enabled=True)
        return rows
    storage.update_json("routers.json", authorize)


def test_explicit_registration_is_idempotent_and_keeps_unknown_capacity_and_monitoring_off(fleet):
    _, storage, service = fleet
    before = deepcopy(storage.read_json("routers.json"))
    service.register_monitoring_router("SDR-MTN-01", "MTN CHR lab", "192.0.2.11", "ether1", "ether3", "MTN", chr_lab=True)
    assert storage.read_json("routers.json") == before
    assert len(before) == 3
    for row in before[1:]:
        assert row["capacity_mbps"] is None and row["cost_per_gb"] is None
        assert row["monitoring_enabled"] is False and row["controller_auth_enabled"] is False
        assert row["management_interface"] == "ether3" and row["interface_name"] == "ether1"
        assert row["traffic_source_ip"] == row["ip_address"] and row["deployment_kind"] == "chr_lab"
    assert storage.read_json("routing_paths.json")["paths"] == []


def test_duplicate_address_or_changed_existing_target_cannot_replace_a_router(fleet):
    _, storage, service = fleet
    before = storage.read_json("routers.json")
    with pytest.raises(RouterValidationError):
        service.register_monitoring_router("DIFFERENT-ID", "Duplicate", "192.0.2.11", "ether1", "ether3", "MTN")
    with pytest.raises(RouterValidationError):
        service.register_monitoring_router("SDR-MTN-01", "MTN", "192.0.2.99", "ether1", "ether3", "MTN")
    assert storage.read_json("routers.json") == before


def test_cloned_hmac_identity_cannot_replace_a_source_bound_routers_baseline(fleet, monkeypatch):
    enable(fleet, monkeypatch)
    _, storage, _ = fleet
    now = datetime.now(UTC)
    sample(fleet, "SDR-MTN-01", "192.0.2.11", now)
    before = storage.read_json("router_traffic_v2.json")
    with pytest.raises(PollError) as caught:
        sample(fleet, "SDR-MTN-01", "192.0.2.12", now + timedelta(seconds=60), 999_999)
    assert caught.value.code == "source_mismatch"
    after = storage.read_json("router_traffic_v2.json")
    assert after["routers"] == before["routers"] and after["seen_requests"] == before["seen_requests"]
    assert storage.list_traffic() == []


def test_each_carrier_has_independent_real_counter_history_and_resets(fleet, monkeypatch):
    enable(fleet, monkeypatch)
    _, storage, _ = fleet
    now = datetime.now(UTC)
    for router_id, ip in (("SDR-MTN-01", "192.0.2.11"), ("SDR-GLO-01", "192.0.2.12")):
        assert sample(fleet, router_id, ip, now)["sample_state"] == "baseline"
    assert sample(fleet, "SDR-MTN-01", "192.0.2.11", now + timedelta(seconds=60), 7_501_000)["tx_mbps"] == 1
    assert sample(fleet, "SDR-GLO-01", "192.0.2.12", now + timedelta(seconds=60), 15_001_000)["tx_mbps"] == 2
    assert sample(fleet, "SDR-MTN-01", "192.0.2.11", now + timedelta(seconds=120), 1)["sample_state"] == "counter_reset"
    assert sample(fleet, "SDR-GLO-01", "192.0.2.12", now + timedelta(seconds=120), 30_001_000)["tx_mbps"] == 2
    rows = storage.list_traffic()
    assert [r["tx_mbps"] for r in rows if r["router_id"] == "SDR-MTN-01"] == [1]
    assert [r["tx_mbps"] for r in rows if r["router_id"] == "SDR-GLO-01"] == [2, 2]
    assert all(not any(key.startswith("rx") for key in r) for r in rows)


@pytest.mark.parametrize("source", [None, "", "bad-address", 123])
def test_invalid_source_binding_fails_closed(fleet, monkeypatch, source):
    enable(fleet, monkeypatch)
    _, storage, _ = fleet
    storage.update_json("routers.json", lambda rows: [
        {**r, "traffic_source_ip": source} if r["router_id"] == "SDR-MTN-01" else r for r in rows])
    with pytest.raises(PollError):
        sample(fleet, "SDR-MTN-01", "192.0.2.11", datetime.now(UTC))
    assert storage.read_json("router_traffic_v2.json")["routers"] == {}


def test_preview_reports_unknown_capacity_and_unconfirmed_switching_without_writes(fleet, monkeypatch):
    enable(fleet, monkeypatch)
    app, storage, _ = fleet
    now = datetime.now(UTC).replace(microsecond=0)
    for router_id, ip in (("SDR-MTN-01", "192.0.2.11"), ("SDR-GLO-01", "192.0.2.12")):
        for i in range(6):
            sample(fleet, router_id, ip, now - timedelta(seconds=(5-i)*60), 1000+i*7_500_000)
    protected = {name:storage.read_json(name) for name in storage.DEFAULTS}
    preview = WorkflowService(storage, app.config).preview(now=now)
    assert len(preview["recommendations"]) == 2
    for recommendation in preview["recommendations"]:
        assert recommendation["status"] == "blocked"
        assert "capacity is unknown" in recommendation["reason"]
        assert "has not been confirmed" in recommendation["reason"]
        assert recommendation["execution_status"] == "Dry Run" and recommendation["action"] == "none"
        assert recommendation["change_mbps"] is None
        assert recommendation["expected_benefit"]["resulting_utilization_percent"] is None
    assert {name:storage.read_json(name) for name in storage.DEFAULTS} == protected


def test_live_frontend_separates_carriers_and_supports_units_and_history_filter(fleet, monkeypatch):
    enable(fleet, monkeypatch)
    app, storage, _ = fleet
    now = datetime.now(UTC).replace(microsecond=0)
    for router_id, ip in (("SDR-MTN-01", "192.0.2.11"), ("SDR-GLO-01", "192.0.2.12")):
        sample(fleet, router_id, ip, now - timedelta(seconds=60))
        sample(fleet, router_id, ip, now, 7_501_000)
    client = app.test_client()
    dashboard = client.get("/").get_data(as_text=True)
    assert "Router TX connections" in dashboard and "SDR-MTN-01" in dashboard and "SDR-GLO-01" in dashboard
    assert "Current TX (Mbps)" in dashboard and "Unknown capacity" in dashboard
    page = client.get("/monitoring?unit=Mbps&router_id=SDR-MTN-01").get_data(as_text=True)
    assert "Current outbound (Mbps)" in page and "Average TX (Mbps)" in page
    data = client.get("/api/monitoring?router_id=SDR-MTN-01").get_json()
    assert len(data["routers"]) == 1 and len(data["history"]) == 1
    assert data["history"][0]["router_id"] == "SDR-MTN-01" and data["history"][0]["tx_mbps"] == 1
    assert data["action"] == "none" and data["routing_changes_enabled"] is False
    assert client.get("/monitoring?unit=bad").status_code == 400
    assert client.get("/api/monitoring?router_id=UNKNOWN").status_code == 404
    assert client.get("/api/monitoring?router_id=").status_code == 200


def test_generic_registration_supports_other_names_ports_and_dynamic_sources(fleet):
    _, storage, service = fleet
    result = service.register_monitoring_router("OTHER-RTR", "Other transit", "198.51.100.20", "pppoe-wan", "vlan-mgmt", "Other carrier", api_port=18729)
    row = next(r for r in storage.read_json("routers.json") if r["router_id"] == "OTHER-RTR")
    assert row["api_port"] == 18729 and row["interface_name"] == "pppoe-wan"
    assert "traffic_source_ip" not in row and row["deployment_kind"] == "router"
